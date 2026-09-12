/*
 * nvme.c — NVMe block-storage driver: modern PCIe storage over MMIO doorbells.
 *
 * An NVMe controller is a PCI device whose registers are memory-mapped (a 64-bit
 * BAR0). Unlike AHCI (where we build a SATA FIS) or virtio (a paravirtual
 * virtqueue), NVMe is driven entirely through *queue pairs* living in RAM: a
 * Submission Queue (SQ) of 64-byte command entries and a Completion Queue (CQ) of
 * 16-byte completion entries. To run a command we write a Submission Queue Entry
 * (SQE) into the SQ at its tail, advance the tail, and ring the SQ's "doorbell"
 * register (in the controller's MMIO at offset 0x1000+). The controller fetches
 * the SQE, DMAs the data buffer (named by Physical Region Pages — PRP1/PRP2), and
 * posts a Completion Queue Entry (CQE) in the CQ. We poll the CQ: each CQE carries
 * a *phase bit* that the controller toggles each time the queue wraps, so a CQE is
 * "ours" when its phase matches the phase we expect; its status field tells us OK
 * or error. We then advance the CQ head and ring the CQ doorbell.
 *
 * Bring-up (NVMe 1.x §7.6.1):
 *   1. disable the controller (CC.EN=0), wait CSTS.RDY==0;
 *   2. allocate a zeroed admin SQ + admin CQ (one page frame each), program
 *      AQA (their sizes), ASQ/ACQ (their physical bases);
 *   3. set CC (64-byte SQEs, 16-byte CQEs, NVM command set, MPS=0, EN=1) and
 *      wait CSTS.RDY==1;
 *   4. via the admin queue: IDENTIFY controller + namespace 1 (to learn the
 *      capacity + LBA size), then CREATE IO COMPLETION QUEUE + CREATE IO
 *      SUBMISSION QUEUE for a single IO queue pair (qid 1).
 * IO then uses the IO queue pair: NVM READ (0x02) / WRITE (0x01) SQEs.
 *
 * SAFE SCOPE: this is an *additional* block device. The OS still BOOTS from, and
 * runs FAT32/VFS on, the legacy ATA disk (kernel/ata.c). nvme_init() probes PCI
 * for an NVMe controller; if there's none (or bring-up fails) it is a clean no-op
 * that leaves the system unchanged, so a machine without one boots fine. Once
 * proven, the boot volume could be migrated onto NVMe by pointing fat32/vfs at
 * nvme_read.
 *
 * DMA + alignment: every queue/PRP-list/bounce buffer comes from pmm_alloc_frame()
 * — the PMM only returns low physical RAM that the boot page tables identity-map
 * (phys == virt), so a frame address is BOTH a CPU-usable pointer AND the physical
 * address the controller needs (exactly how ahci.c/virtio_blk.c/e1000.c do it). A
 * 4 KiB frame is naturally page-aligned, which satisfies NVMe's queue alignment
 * and the PRP entry alignment. We DMA every transfer through a page-aligned BOUNCE
 * frame and memcpy to/from the caller's buffer: this both removes any alignment
 * requirement on the caller's pointer and cleanly bounds every transfer to the
 * fixed bounce size, so two PRP entries (PRP1 + PRP2) always describe it.
 */
#include "nvme.h"
#include "pci.h"
#include "pmm.h"
#include "vmm.h"
#include "string.h"
#include "console.h"

/* ---- controller registers (BAR0-relative, NVMe 1.x §3.1) ----------------- */
#define NVME_REG_CAP    0x00   /* controller capabilities (64-bit)            */
#define NVME_REG_VS     0x08   /* version                                     */
#define NVME_REG_CC     0x14   /* controller configuration                    */
#define NVME_REG_CSTS   0x1C   /* controller status                           */
#define NVME_REG_AQA    0x24   /* admin queue attributes (SQ/CQ sizes)        */
#define NVME_REG_ASQ    0x28   /* admin SQ base address (64-bit)              */
#define NVME_REG_ACQ    0x30   /* admin CQ base address (64-bit)              */
#define NVME_REG_DBS    0x1000 /* start of the doorbell registers            */

/* CAP field accessors (CAP is 64-bit). */
#define CAP_MQES(cap)   (((cap) & 0xFFFFull) + 1)         /* max queue entries */
#define CAP_DSTRD(cap)  (((cap) >> 32) & 0xF)             /* doorbell stride   */
#define CAP_MPSMIN(cap) (((cap) >> 48) & 0xF)             /* min page size     */

/* CC (controller configuration) fields. */
#define CC_EN       (1u << 0)        /* enable                                */
#define CC_CSS_NVM  (0u << 4)        /* command set: NVM                      */
#define CC_MPS_4K   (0u << 7)        /* memory page size = 2^(12+MPS) = 4 KiB */
#define CC_AMS_RR   (0u << 11)       /* arbitration: round robin              */
#define CC_IOSQES   (6u << 16)       /* IO SQ entry size = 2^6 = 64 bytes     */
#define CC_IOCQES   (4u << 20)       /* IO CQ entry size = 2^4 = 16 bytes     */

/* CSTS (controller status) fields. */
#define CSTS_RDY    (1u << 0)        /* ready                                 */
#define CSTS_CFS    (1u << 1)        /* controller fatal status               */

/* Admin opcodes (NVMe 1.x §5). */
#define NVM_ADMIN_CREATE_IO_SQ  0x01
#define NVM_ADMIN_CREATE_IO_CQ  0x05
#define NVM_ADMIN_IDENTIFY      0x06

/* NVM IO opcodes (NVMe 1.x §6). */
#define NVM_CMD_WRITE  0x01
#define NVM_CMD_READ   0x02

/* IDENTIFY CNS values. */
#define IDENTIFY_CNS_NS    0x00      /* identify namespace                    */
#define IDENTIFY_CNS_CTRL  0x01      /* identify controller                   */

/* Queue geometry: small fixed depths keep each queue inside one page frame.
 * Admin SQ entries are 64 B (so 4096/64 = 64 fit); CQ entries are 16 B. We use a
 * shallow depth — one command in flight is all this blocking driver needs. */
#define ADMIN_Q_DEPTH  8
#define IO_Q_DEPTH     8
#define IO_QID         1            /* the single IO queue pair's id          */

/* A 64-byte NVMe Submission Queue Entry (the generic command layout, NVMe 1.x
 * Figure 11). Command-set-specific fields reuse cdw10..cdw15. */
struct nvme_sqe {
    uint8_t  opc;          /* opcode                                          */
    uint8_t  fuse;         /* fused operation + PSDT (we use 0)               */
    uint16_t cid;          /* command identifier (we echo it in the CQE)      */
    uint32_t nsid;         /* namespace id                                    */
    uint64_t rsvd2;        /* (cdw2/cdw3)                                     */
    uint64_t mptr;         /* metadata pointer (unused)                       */
    uint64_t prp1;         /* data pointer 1 (physical)                       */
    uint64_t prp2;         /* data pointer 2 / PRP-list pointer (physical)    */
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} __attribute__((packed));

/* A 16-byte NVMe Completion Queue Entry (NVMe 1.x Figure 27). */
struct nvme_cqe {
    uint32_t result;       /* command-specific result (cdw0)                  */
    uint32_t rsvd;         /* (cdw1)                                          */
    uint16_t sq_head;      /* SQ head pointer the controller has consumed to  */
    uint16_t sq_id;        /* the SQ this completion is for                   */
    uint16_t cid;          /* command identifier being completed              */
    uint16_t status;       /* bit 0 = phase tag; bits 15..1 = status field    */
} __attribute__((packed));

/* One submission/completion queue pair we manage. */
struct nvme_queue {
    struct nvme_sqe *sq;       /* submission queue ring (page frame)           */
    struct nvme_cqe *cq;       /* completion queue ring (page frame)           */
    volatile uint32_t *sq_db;  /* this queue's SQ tail doorbell (MMIO)         */
    volatile uint32_t *cq_db;  /* this queue's CQ head doorbell (MMIO)         */
    uint16_t depth;            /* number of entries in each ring               */
    uint16_t sq_tail;          /* next SQ slot we'll write                     */
    uint16_t cq_head;          /* next CQ slot we'll read                      */
    uint8_t  phase;            /* phase bit we currently expect (starts 1)     */
};

static struct {
    int present;
    volatile uint8_t *regs;    /* mapped BAR0 register block                   */
    uint32_t dstrd;            /* doorbell stride from CAP                      */
    uint16_t cid_next;         /* rolling command identifier                   */

    struct nvme_queue admin;   /* admin queue pair (qid 0)                      */
    struct nvme_queue io;       /* the one IO queue pair (qid IO_QID)           */

    uint64_t nsze;             /* namespace size, in LBAs                       */
    uint32_t lba_bytes;        /* the namespace's LBA data size, in bytes       */
    uint64_t capacity;         /* capacity in NVME_SECTOR_SIZE units (for API)  */

    uint64_t bounce_phys;      /* page-aligned DMA bounce frame (phys == virt)  */
    uint8_t *bounce;
    uint32_t bounce_pages;     /* how many contiguous pages the bounce spans    */
} nv;

/* ---- small MMIO helpers -------------------------------------------------- */
static uint32_t reg_rd32(uint32_t off)            { return *(volatile uint32_t *)(nv.regs + off); }
static void     reg_wr32(uint32_t off, uint32_t v){ *(volatile uint32_t *)(nv.regs + off) = v; }
static uint64_t reg_rd64(uint32_t off)            { return *(volatile uint64_t *)(nv.regs + off); }
static void     reg_wr64(uint32_t off, uint64_t v){ *(volatile uint64_t *)(nv.regs + off) = v; }

/* Physical address of a kernel pointer, for handing buffers to the controller's
 * DMA engine. Our queues/PRP buffers live in identity-mapped low RAM (phys ==
 * virt), but translating is the correct general way — exactly as ahci.c does. */
static uint64_t phys_of(const void *p) {
    uint64_t t = vmm_translate((uint64_t)(uintptr_t)p);
    return t ? t : hhdm_phys(p);   /* no translation: it is an HHDM pointer, so subtract the base (M1970) */
}

/* The doorbell registers march at a stride of (4 << CAP.DSTRD) bytes; for queue
 * y, SQyTDBL is at 0x1000 + (2y)*stride and CQyHDBL at 0x1000 + (2y+1)*stride. */
static volatile uint32_t *sq_doorbell(uint16_t qid) {
    uint32_t stride = 4u << nv.dstrd;
    return (volatile uint32_t *)(nv.regs + NVME_REG_DBS + (2u * qid) * stride);
}
static volatile uint32_t *cq_doorbell(uint16_t qid) {
    uint32_t stride = 4u << nv.dstrd;
    return (volatile uint32_t *)(nv.regs + NVME_REG_DBS + (2u * qid + 1u) * stride);
}

/* Submit one already-filled SQE on `q` and poll its CQ for the matching
 * completion. Returns the 15-bit status field (0 == success) or 0xFFFF on
 * timeout. Single command in flight at a time (this is a blocking driver), so we
 * write at sq_tail, ring the SQ doorbell, then wait for a CQE whose phase matches
 * what we expect — advancing head + phase and ringing the CQ doorbell when seen. */
static uint16_t nvme_submit(struct nvme_queue *q, struct nvme_sqe *cmd) {
    cmd->cid = nv.cid_next++;

    /* Place the command at the SQ tail and advance the tail (wrapping). */
    q->sq[q->sq_tail] = *cmd;
    q->sq_tail = (uint16_t)((q->sq_tail + 1) % q->depth);

    /* A store barrier so the SQE lands in RAM before the doorbell write tells the
     * controller to fetch it (x86's strong ordering only needs a compiler fence). */
    __asm__ volatile("" ::: "memory");
    *q->sq_db = q->sq_tail;

    /* Poll the CQ head slot until its phase bit flips to the phase we expect. */
    volatile struct nvme_cqe *cqe = (volatile struct nvme_cqe *)&q->cq[q->cq_head];
    uint16_t status = 0xFFFF;
    for (uint64_t i = 0; i < 200000000ull; i++) {
        uint16_t s = cqe->status;
        if ((s & 1) == q->phase) {
            status = (uint16_t)(s >> 1);     /* the 15-bit status field */
            break;
        }
        __asm__ volatile("pause");
    }
    if (status == 0xFFFF)
        return 0xFFFF;                       /* timeout: never saw our completion */

    /* Advance the CQ head; the phase bit toggles each time the ring wraps. */
    q->cq_head = (uint16_t)((q->cq_head + 1) % q->depth);
    if (q->cq_head == 0)
        q->phase ^= 1;
    __asm__ volatile("" ::: "memory");
    *q->cq_db = q->cq_head;

    return status;
}

/* Allocate + zero one page frame for an SQ and one for a CQ, fill in `q`'s
 * pointers/doorbells/depth, and reset its head/tail/phase. Returns 0 on success
 * (frames allocated), -1 on OOM (and frees any partial allocation). */
static int queue_alloc(struct nvme_queue *q, uint16_t qid, uint16_t depth) {
    uint64_t sqf = pmm_alloc_frame();
    uint64_t cqf = pmm_alloc_frame();
    if (!sqf || !cqf) {
        if (sqf) pmm_free_frame(sqf);
        if (cqf) pmm_free_frame(cqf);
        return -1;
    }
    memset(hhdm(sqf), 0, PAGE_SIZE);
    memset(hhdm(cqf), 0, PAGE_SIZE);

    q->sq    = (struct nvme_sqe *)hhdm(sqf);
    q->cq    = (struct nvme_cqe *)hhdm(cqf);
    q->sq_db = sq_doorbell(qid);
    q->cq_db = cq_doorbell(qid);
    q->depth = depth;
    q->sq_tail = 0;
    q->cq_head = 0;
    q->phase = 1;            /* CQ memory starts zeroed; first valid CQE has phase 1 */
    return 0;
}

/* Run IDENTIFY (CNS picks controller vs namespace) into a freshly-allocated page
 * frame, returning the frame's pointer (caller frees), or NULL on failure. */
static void *nvme_identify(uint32_t cns, uint32_t nsid) {
    uint64_t f = pmm_alloc_frame();
    if (!f)
        return NULL;
    memset(hhdm(f), 0, PAGE_SIZE);

    struct nvme_sqe cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.opc   = NVM_ADMIN_IDENTIFY;
    cmd.nsid  = nsid;
    cmd.prp1  = f;                 /* identity-mapped frame: phys == virt */
    cmd.cdw10 = cns;               /* CNS in the low byte of CDW10 */

    if (nvme_submit(&nv.admin, &cmd) != 0) {
        pmm_free_frame(f);
        return NULL;
    }
    return hhdm(f);
}

/* Identify namespace 1 and compute its capacity. The identify-namespace struct
 * (NVMe 1.x Figure 114): NSZE is the u64 at byte 0; FLBAS (byte 26) low 4 bits
 * select which LBA Format (the LBAF array of u32 starts at byte 128) is in use;
 * each LBAF's bits 16..23 are LBADS (LBA data size = 2^LBADS bytes). */
static int nvme_setup_namespace(void) {
    uint8_t *ns = (uint8_t *)nvme_identify(IDENTIFY_CNS_NS, 1);
    if (!ns)
        return -1;

    uint64_t nsze;
    memcpy(&nsze, ns + 0, sizeof(nsze));

    uint8_t flbas = ns[26] & 0x0F;
    uint32_t lbaf;
    memcpy(&lbaf, ns + 128 + (uint32_t)flbas * 4, sizeof(lbaf));
    uint32_t lbads = (lbaf >> 16) & 0xFF;

    pmm_free_frame(hhdm_phys(ns));   /* ns is an HHDM pointer now -- freeing the pointer itself would release the wrong frame (M1970) */

    if (nsze == 0 || lbads < 9 || lbads > 16)   /* sane LBA size: 512 B .. 64 KiB */
        return -1;

    nv.nsze      = nsze;
    nv.lba_bytes = 1u << lbads;

    /* The public API speaks 512-byte sectors. Express the capacity in those units
     * so nvme_read/write and the self-test reason in a single unit. We only
     * actually run IO when the native LBA size is 512 (the common QEMU case);
     * a non-512 device is reported but treated as unsupported for IO. */
    nv.capacity = (uint64_t)nv.nsze * ((uint64_t)nv.lba_bytes / NVME_SECTOR_SIZE);
    return 0;
}

/* Create the single IO queue pair (qid IO_QID): the IO completion queue first
 * (commands reference it), then the IO submission queue pointed at it. Both are
 * physically contiguous (one page each, PC=1) and the CQ takes no interrupts (we
 * poll, IEN=0). Returns 0 on success. */
static int nvme_create_io_queues(void) {
    if (queue_alloc(&nv.io, IO_QID, IO_Q_DEPTH) != 0)
        return -1;

    /* CREATE IO COMPLETION QUEUE: CDW10 = (size-1)<<16 | qid; CDW11 = PC(bit0). */
    struct nvme_sqe c;
    memset(&c, 0, sizeof(c));
    c.opc   = NVM_ADMIN_CREATE_IO_CQ;
    c.prp1  = phys_of(nv.io.cq);
    c.cdw10 = ((uint32_t)(IO_Q_DEPTH - 1) << 16) | IO_QID;
    c.cdw11 = 1u;                              /* PC=1 (physically contiguous), IEN=0 */
    if (nvme_submit(&nv.admin, &c) != 0)
        return -1;

    /* CREATE IO SUBMISSION QUEUE: CDW10 = (size-1)<<16 | qid;
     * CDW11 = CQID<<16 | PC(bit0) (this SQ posts completions to CQID). */
    memset(&c, 0, sizeof(c));
    c.opc   = NVM_ADMIN_CREATE_IO_SQ;
    c.prp1  = phys_of(nv.io.sq);
    c.cdw10 = ((uint32_t)(IO_Q_DEPTH - 1) << 16) | IO_QID;
    c.cdw11 = ((uint32_t)IO_QID << 16) | 1u;   /* CQID=IO_QID, PC=1 */
    if (nvme_submit(&nv.admin, &c) != 0)
        return -1;

    return 0;
}

int nvme_init(void) {
    memset(&nv, 0, sizeof(nv));

    /* Locate an NVMe controller by PCI class (0x01 mass-storage, 0x08 NVM,
     * 0x02 NVMe). Fall back to QEMU's nvme vendor:device (0x1B36:0x0010). */
    pci_device_t dev = pci_find_class(0x01, 0x08, 0x02);
    if (!dev.valid)
        dev = pci_find(0x1B36, 0x0010);
    if (!dev.valid)
        return -1;

    /* Enable PCI memory-space decode + bus mastering so the controller can DMA. */
    pci_enable_bus_master(&dev);

    /* BAR0 is the 64-bit MMIO register block; the high 32 bits live in BAR1.
     * Map it cache-disabled (it sits in the PCI hole, above the boot identity
     * map). The register block is at 0x0000 and the doorbells start at 0x1000;
     * a couple of pages cover both with room to spare. */
    uint64_t bar0 = (uint64_t)pci_bar(&dev, 0);
    uint64_t bar1 = (uint64_t)pci_read32(dev.bus, dev.slot, dev.func, 0x14);
    uint64_t mmio = bar0 | (bar1 << 32);
    if (!mmio)
        return -1;
    for (uint64_t off = 0; off < 0x4000; off += PAGE_SIZE)
        vmm_map(mmio + off, mmio + off, PTE_WRITABLE | PTE_PCD);
    nv.regs = (volatile uint8_t *)(uintptr_t)mmio;

    uint64_t cap = reg_rd64(NVME_REG_CAP);
    nv.dstrd = (uint32_t)CAP_DSTRD(cap);

    /* The controller must support our memory page size (4 KiB). CAP.MPSMIN is the
     * minimum page size as 2^(12+MPSMIN); MPSMIN==0 means 4 KiB is allowed. */
    if (CAP_MPSMIN(cap) != 0)
        return -1;

    /* --- bring-up (NVMe 1.x §7.6.1) ----------------------------------------- */

    /* Disable the controller, then wait for it to report not-ready. */
    uint32_t cc = reg_rd32(NVME_REG_CC);
    cc &= ~CC_EN;
    reg_wr32(NVME_REG_CC, cc);
    {
        int ready = 1;
        for (int i = 0; i < 5000000; i++) {
            if (!(reg_rd32(NVME_REG_CSTS) & CSTS_RDY)) { ready = 0; break; }
        }
        if (ready)                       /* never went not-ready: bail clean */
            return -1;
    }

    /* Allocate the admin queue pair (its doorbells are qid 0). */
    if (queue_alloc(&nv.admin, 0, ADMIN_Q_DEPTH) != 0)
        return -1;

    /* AQA: admin CQ size in bits 27..16, admin SQ size in bits 11..0 (each as
     * size-1). ASQ/ACQ: the queues' physical base addresses (64-bit, page-aligned). */
    reg_wr32(NVME_REG_AQA, ((uint32_t)(ADMIN_Q_DEPTH - 1) << 16) | (ADMIN_Q_DEPTH - 1));
    reg_wr64(NVME_REG_ASQ, phys_of(nv.admin.sq));
    reg_wr64(NVME_REG_ACQ, phys_of(nv.admin.cq));

    /* Configure + enable: 64-byte IO SQEs, 16-byte IO CQEs, NVM command set,
     * 4 KiB pages, round-robin arbitration, EN=1. */
    cc = CC_EN | CC_CSS_NVM | CC_MPS_4K | CC_AMS_RR | CC_IOSQES | CC_IOCQES;
    reg_wr32(NVME_REG_CC, cc);

    /* Wait for ready; a controller-fatal-status (CFS) along the way is terminal. */
    {
        int ok = 0;
        for (int i = 0; i < 5000000; i++) {
            uint32_t csts = reg_rd32(NVME_REG_CSTS);
            if (csts & CSTS_CFS) return -1;     /* fatal */
            if (csts & CSTS_RDY) { ok = 1; break; }
        }
        if (!ok)
            return -1;                          /* timeout */
    }

    /* Learn the namespace geometry (capacity + LBA size). */
    if (nvme_setup_namespace() != 0)
        return -1;

    /* Bring up the single IO queue pair we use for reads/writes. */
    if (nvme_create_io_queues() != 0)
        return -1;

    /* A page-aligned DMA bounce frame: we copy every transfer through it so the
     * caller's buffer needs no alignment and a transfer is always describable by
     * PRP1 (+ PRP2 for a 2nd page). Two contiguous pages let one call move up to
     * 8 KiB (16 sectors). The PMM bump/bitmap allocator returns contiguous frames
     * for a fresh run; we verify rather than assume. */
    nv.bounce_pages = 2;
    uint64_t b0 = pmm_alloc_frame();
    if (!b0)
        return -1;
    uint64_t prev = b0;
    int contig = 1;
    for (uint32_t i = 1; i < nv.bounce_pages; i++) {
        uint64_t f = pmm_alloc_frame();
        if (!f || f != prev + PAGE_SIZE) { contig = 0; break; }
        prev = f;
    }
    if (!contig) {
        /* Fall back to a single-page bounce (still valid: PRP1 alone covers it). */
        nv.bounce_pages = 1;
    }
    nv.bounce_phys = b0;
    nv.bounce = (uint8_t *)hhdm(b0);

    nv.present = 1;
    return 0;
}

int      nvme_present(void)  { return nv.present; }
uint64_t nvme_capacity(void) { return nv.present ? nv.capacity : 0; }

/* The shared core of read and write: bounce one transfer (<= the bounce size)
 * through the page-aligned bounce frame and run an NVM READ/WRITE on the IO
 * queue. `write` picks WRITE (and copies the caller's data into the bounce first);
 * a read copies the bounce back into the caller's buffer after completion.
 * Returns 0 on success, -1 on bad-arg / device error / timeout. */
static int nvme_xfer(uint64_t lba, uint32_t count, void *buf, int write) {
    if (!nv.present || !buf || count == 0)
        return -1;
    /* We only do IO on a 512-byte-LBA namespace (the public API + bounce math are
     * expressed in 512-byte sectors). A differently-formatted namespace is brought
     * up + reported but not read/written here. */
    if (nv.lba_bytes != NVME_SECTOR_SIZE)
        return -1;
    /* Bound the transfer to what the bounce frame (and thus PRP1+PRP2) can hold. */
    uint32_t max_sectors = (nv.bounce_pages * PAGE_SIZE) / NVME_SECTOR_SIZE;
    if (count > max_sectors)
        return -1;
    /* Refuse reads/writes past the end of the namespace. */
    if (lba >= nv.capacity || count > nv.capacity - lba)
        return -1;

    uint32_t bytes = count * NVME_SECTOR_SIZE;

    if (write)
        memcpy(nv.bounce, buf, bytes);

    /* PRP1 names the first page of the bounce; if the transfer spills past the
     * first page boundary, PRP2 names the second page (the bounce is page-aligned,
     * so there is no intra-page offset to account for). For <= one page, PRP2 is
     * unused (0). This is the exact case the NVMe PRP rules allow with two PRPs. */
    uint64_t prp1 = nv.bounce_phys;
    uint64_t prp2 = 0;
    if (bytes > PAGE_SIZE)
        prp2 = nv.bounce_phys + PAGE_SIZE;

    struct nvme_sqe cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.opc   = write ? NVM_CMD_WRITE : NVM_CMD_READ;
    cmd.nsid  = 1;
    cmd.prp1  = prp1;
    cmd.prp2  = prp2;
    cmd.cdw10 = (uint32_t)(lba & 0xFFFFFFFF);          /* SLBA low 32  */
    cmd.cdw11 = (uint32_t)(lba >> 32);                 /* SLBA high 32 */
    cmd.cdw12 = (count - 1) & 0xFFFF;                  /* NLB is 0-based */

    uint16_t status = nvme_submit(&nv.io, &cmd);
    if (status != 0)
        return -1;                                     /* error or timeout */

    if (!write)
        memcpy(buf, nv.bounce, bytes);
    return 0;
}

int nvme_read(uint64_t lba, uint32_t count, void *buf) {
    return nvme_xfer(lba, count, buf, 0);
}

int nvme_write(uint64_t lba, uint32_t count, const void *buf) {
    return nvme_xfer(lba, count, (void *)buf, 1);
}

/* ---- boot-time verification --------------------------------------------- */

/* A static buffer for the self-test (we DMA through the internal bounce frame, so
 * this is just where we land the bytes to checksum/print). */
static uint8_t selftest_buf[NVME_SECTOR_SIZE];
static uint8_t st_saved[NVME_SECTOR_SIZE];
static uint8_t st_scratch[NVME_SECTOR_SIZE];
static uint8_t st_readback[NVME_SECTOR_SIZE];

/* Read a few sectors off the NVMe namespace and log the first bytes + a simple
 * additive checksum, so the read can be matched against known on-disk content;
 * then a write round-trip on the last sector. This is the boot verification hook;
 * a no-op (logs "none found") if no NVMe controller is attached. Mirrors
 * ahci_selftest / virtio_blk_selftest. */
void nvme_selftest(void) {
    if (!nv.present) {
        kprintf("[nvme] no NVMe controller found "
                "(none attached; legacy ATA boot intact).\n\n");
        return;
    }

    kprintf("[ ok ] NVMe up: namespace 1 = %lu LBAs of %u bytes "
            "(%lu MiB) (boot stays on legacy ATA).\n",
            nv.nsze, nv.lba_bytes,
            (nv.nsze * (uint64_t)nv.lba_bytes) / (1024 * 1024));
    kprintf("[nvme] capacity in 512B sectors = %lu (LBA size = %u)\n",
            nv.capacity, nv.lba_bytes);

    if (nv.lba_bytes != NVME_SECTOR_SIZE) {
        kprintf("[nvme] LBA size %u != 512: IO self-test skipped (device up, "
                "identify OK).\n\n", nv.lba_bytes);
        return;
    }

    for (uint64_t lba = 0; lba < 3; lba++) {
        if (nvme_read(lba, 1, selftest_buf) != 0) {
            kprintf("[nvme] sector %lu: READ FAILED\n", lba);
            continue;
        }
        /* Additive checksum over the whole sector + the first 16 bytes shown as
         * hex and (printable) ASCII, so a known pattern is recognizable. */
        uint32_t sum = 0;
        for (int i = 0; i < NVME_SECTOR_SIZE; i++)
            sum += selftest_buf[i];
        kprintf("[nvme] sector %lu sum=%08x first16=", lba, sum);
        for (int i = 0; i < 16; i++)
            kprintf("%02x ", selftest_buf[i]);
        kprintf(" |");
        for (int i = 0; i < 16; i++) {
            uint8_t c = selftest_buf[i];
            kprintf("%c", (c >= 0x20 && c < 0x7F) ? (char)c : '.');
        }
        kprintf("|\n");
    }

    /* Write round-trip on the last sector: save it, write a marker, read it back,
     * verify, then restore the original so we don't corrupt the test image. Done
     * only if the device has room (>=8 sectors). A failure here is reported but
     * not fatal to boot. */
    if (nv.capacity >= 8) {
        uint64_t test_lba = nv.capacity - 1;
        if (nvme_read(test_lba, 1, st_saved) == 0) {
            for (int i = 0; i < NVME_SECTOR_SIZE; i++)
                st_scratch[i] = (uint8_t)(0x5A ^ (i & 0xFF));
            int ok = (nvme_write(test_lba, 1, st_scratch) == 0);
            memset(st_readback, 0, sizeof(st_readback));
            ok = ok && (nvme_read(test_lba, 1, st_readback) == 0);
            ok = ok && (memcmp(st_readback, st_scratch, NVME_SECTOR_SIZE) == 0);
            nvme_write(test_lba, 1, st_saved);     /* restore original content */
            kprintf("[nvme] write round-trip on sector %lu: %s\n",
                    test_lba, ok ? "OK (wrote+read back+restored)" : "MISMATCH");
        }
    }

    kprintf("[ ok ] NVMe read self-test complete "
            "(bytes above are the real disk content).\n\n");
}
