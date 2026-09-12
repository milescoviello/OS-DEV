/*
 * hda.c — Intel High Definition Audio (HDA) controller driver (QEMU `intel-hda`).
 *
 * HDA is the modern PCI audio controller that superseded AC'97. Unlike AC'97's
 * two fixed port-I/O windows, an HDA controller is a single MMIO register block
 * (BAR0) that talks to one or more *codecs* over a serial link. Each codec is a
 * graph of "widgets" — Audio Output converters (DACs), Pin complexes (the jacks),
 * mixers, selectors — that you discover and wire together by sending the codec
 * "verbs" (command words). Once an output converter is fed by a stream and routed
 * to an output pin, the controller DMAs PCM out via a stream descriptor whose
 * Buffer Descriptor List (BDL) points at the sample buffers.
 *
 * Bring-up sequence (HDA spec rev 1.0a):
 *   1. Reset the controller: clear then set GCTL.CRST, wait for it to read 1.
 *   2. Codec enumeration: read STATESTS — a bit per codec address that responded
 *      to the wake. Pick the lowest set bit.
 *   3. Codec verbs (sent synchronously via the Immediate Command registers
 *      ICOI/IRII/ICIS — the spec's documented alternative to a CORB/RIRB ring,
 *      and far less code for a bring-up driver): from the codec root, find the
 *      Audio Function Group, then within it an output converter (DAC) and an
 *      output-capable Pin. Set the DAC's stream format (48 kHz/16-bit/2ch),
 *      assign it stream tag 1 / channel 0, unmute + max-gain its output amp and
 *      the pin's output amp, enable the pin's output (+ EAPD), and (if the pin
 *      has a selector/mixer in front of the DAC) leave the default connection.
 *   4. Output stream: build a BDL pointing at a cyclic ring of RAM frames, point
 *      the first output stream descriptor (at 0x80 + ISS*0x20) at it, program the
 *      format + cyclic-buffer-length + last-valid-index + stream number, and set
 *      RUN. The controller then DMAs the ring out forever; hda_pump() (timer IRQ)
 *      refills the consumed half from the software ring, exactly like ac97.c.
 *
 * The public API mirrors ac97.c so audio.c can bind either behind one seam.
 */
#include "hda.h"
#include "pci.h"
#include "vmm.h"
#include "pmm.h"
#include "timer.h"
#include "console.h"
#include "kheap.h"
#include "string.h"
#include <stdint.h>
#include <stddef.h>

/* ---- controller (MMIO) registers, offsets from BAR0 ---------------------- */
#define REG_GCAP        0x00    /* 16: global capabilities (OSS/ISS/BSS counts) */
#define REG_GCTL        0x08    /* 32: global control; bit0 CRST# (0=reset)     */
#define REG_WAKEEN      0x0C    /* 16: wake enable                              */
#define REG_STATESTS    0x0E    /* 16: state change status (codec-present bits) */
#define REG_INTCTL      0x20    /* 32: interrupt control                        */
#define REG_INTSTS      0x24    /* 32: interrupt status                         */

/* Immediate Command interface (synchronous single-verb path). */
#define REG_ICOI        0x60    /* 32: immediate command output (the verb)      */
#define REG_IRII        0x64    /* 32: immediate response input (the reply)     */
#define REG_ICIS        0x68    /* 16: immediate command status                 */
#define ICIS_ICB        0x0001  /*  command busy (write 1 to issue)             */
#define ICIS_IRV        0x0002  /*  response valid                             */

#define GCTL_CRST       0x00000001u   /* 0 = hold in reset, 1 = run */

/* ---- stream (output) descriptor, the first OSD at OSD_BASE ----------------
 * Input stream descriptors come first (ISS of them), then the output ones; the
 * first output descriptor lives at 0x80 + ISS*0x20. Offsets below are relative
 * to that descriptor's base. */
#define SD_CTL          0x00    /* 24-ish: stream control (RUN=bit1, RST=bit0, low byte; stream# in bits 20-23 of the dword) */
#define SD_STS          0x03    /*  8: stream status                            */
#define SD_LPIB         0x04    /* 32: link position in buffer (DMA progress)   */
#define SD_CBL          0x08    /* 32: cyclic buffer length (bytes)             */
#define SD_LVI          0x0C    /* 16: last valid index (BDL entries - 1)       */
#define SD_FMT          0x12    /* 16: stream format                            */
#define SD_BDLPL        0x18    /* 32: BDL pointer, low                         */
#define SD_BDLPU        0x1C    /* 32: BDL pointer, high                        */

#define SDCTL_RST       0x01    /* stream reset            */
#define SDCTL_RUN       0x02    /* stream run (DMA)        */
#define SDCTL_IOC       0x04    /* interrupt on completion */

/* ---- codec verbs ----------------------------------------------------------
 * A command word's verb+payload field (bits 0-19) comes in two shapes:
 *   - a 12-bit verb (bits 8-19) with an 8-bit payload (bits 0-7),
 *   - a 4-bit verb (bits 16-19) with a 16-bit payload (bits 0-15).
 * We store every verb LEFT-ALIGNED in its 20-bit field (i.e. already shifted so
 * an OR with the payload lays it out correctly), so the same packing works for
 * both: 12-bit verbs as 0xNNN00, 4-bit verbs as 0xN0000. codec_cmd just ORs in
 * the payload — no per-verb branching. */
#define VERB_GET_PARAM      0xF0000   /* GetParameter (8-bit param id)            */
#define VERB_GET_CONN_LIST  0xF0200   /* GetConnectionListEntry                   */
#define VERB_SET_CONN_SEL   0x70100   /* SetConnectionSelect                      */
#define VERB_SET_STREAM_CHAN 0x70600  /* SetConverterStreamChannel                */
#define VERB_SET_PIN_CTL    0x70700   /* SetPinWidgetControl                      */
#define VERB_SET_EAPD       0x70C00   /* SetEAPD/BTL enable                       */
#define VERB_SET_POWER      0x70500   /* SetPowerState                            */
#define VERB_SET_STREAM_FMT 0x20000   /* SetConverterFormat (16-bit payload)      */
#define VERB_SET_AMP_GAIN   0x30000   /* SetAmplifierGainMute (16-bit payload)    */

/* GetParameter parameter ids. */
#define PARAM_VENDOR_ID     0x00
#define PARAM_NODE_COUNT    0x04   /* subordinate node count: [16:23]=start, [0:7]=count */
#define PARAM_FN_GROUP_TYPE 0x05   /* function group type; low byte 0x01 = Audio */
#define PARAM_AUDIO_CAP     0x09   /* audio widget capabilities                  */
#define PARAM_PIN_CAP       0x0C   /* pin capabilities                           */

/* Widget type, from bits [20:23] of the audio-widget-capabilities param. */
#define WTYPE_OUT_DAC       0x0    /* Audio Output (converter / DAC) */
#define WTYPE_IN_ADC        0x1
#define WTYPE_MIXER         0x2
#define WTYPE_SELECTOR      0x3
#define WTYPE_PIN           0x4

/* Pin-capabilities bit: this pin can drive an output. */
#define PINCAP_OUTPUT       (1u << 4)
/* Pin-capabilities bit: pin has EAPD (external amplifier power-down). */
#define PINCAP_EAPD         (1u << 16)

/* Pin-control bits we set to enable analog output on a jack. */
#define PINCTL_OUT_EN       (1u << 6)   /* output enable        */
#define PINCTL_HP_EN        (1u << 7)   /* headphone-amp enable */

/* Stream tag + channel we use for the single output stream. */
#define STREAM_TAG          1
#define OUT_CHANNEL         0

/* Cyclic ring geometry: a BDL of NUM_BDL entries, each one PAGE_SIZE of PCM.
 * 16-bit stereo = 4 bytes/frame, so each buffer holds PAGE_SIZE/4 frames. The
 * spec requires >= 2 BDL entries and the CBL be a multiple of 128 bytes; both
 * hold here (PAGE_SIZE = 4096). */
#define NUM_BDL         32
#define BUF_BYTES       PAGE_SIZE
#define BUF_FRAMES      (BUF_BYTES / 4)            /* 1024 stereo frames per buffer */
#define RING_BYTES      (NUM_BDL * BUF_BYTES)      /* 128 KiB cyclic ring           */

typedef struct {
    uint32_t addr_lo;   /* buffer physical address, low 32 bits  */
    uint32_t addr_hi;   /* buffer physical address, high 32 bits */
    uint32_t len;       /* buffer length in bytes                */
    uint32_t flags;     /* bit0 = interrupt-on-completion        */
} __attribute__((packed)) bdl_entry_t;

static volatile uint8_t *mmio;          /* BAR0 register block                 */
static volatile uint8_t *osd;           /* the first output stream descriptor  */
static int          codec;              /* the chosen codec address            */
static int          afg;                /* the Audio Function Group node       */
static int          dac_nid;            /* output converter node               */
static int          pin_nid;            /* output pin node                     */
static bdl_entry_t *bdl;                /* NUM_BDL entries (one frame)          */
static uint64_t     bdl_phys;
static uint64_t     buf_phys[NUM_BDL];  /* the cyclic sample buffers           */
static int          inited;

/* ---- small MMIO helpers --------------------------------------------------- */
static inline uint16_t r16(uint32_t off)            { return *(volatile uint16_t *)(mmio + off); }
static inline uint32_t r32(uint32_t off)            { return *(volatile uint32_t *)(mmio + off); }
static inline void     w16(uint32_t off, uint16_t v){ *(volatile uint16_t *)(mmio + off) = v; }
static inline void     w32(uint32_t off, uint32_t v){ *(volatile uint32_t *)(mmio + off) = v; }
static inline uint8_t  sd_r8(uint32_t off)             { return *(volatile uint8_t  *)(osd + off); }
static inline uint32_t sd_r32(uint32_t off)            { return *(volatile uint32_t *)(osd + off); }
static inline void     sd_w8(uint32_t off, uint8_t v)  { *(volatile uint8_t  *)(osd + off) = v; }
static inline void     sd_w16(uint32_t off, uint16_t v){ *(volatile uint16_t *)(osd + off) = v; }
static inline void     sd_w32(uint32_t off, uint32_t v){ *(volatile uint32_t *)(osd + off) = v; }

int hda_ready(void) { return inited; }

/* ---- codec command transport: the Immediate Command registers -------------
 * Pack {codec addr, node id, verb, payload} into a 32-bit command word and
 * issue it synchronously: write the verb, set ICB, poll until IRV (response
 * valid). Returns the codec's 32-bit response, or 0 on timeout. This is the
 * spec's sanctioned alternative to the CORB/RIRB DMA rings — perfect for a
 * configure-once bring-up where we never need streamed command throughput. */
static uint32_t codec_cmd(int cad, int nid, uint32_t verb, uint32_t payload) {
    /* verb is pre-shifted into the 20-bit verb+payload field; OR in the payload
     * (8 or 16 bits depending on the verb shape — the spare bits are zero in
     * both the verb and a well-formed payload, so a single OR is exact). */
    uint32_t cmd = ((uint32_t)(cad & 0xF) << 28) |
                   ((uint32_t)(nid & 0xFF) << 20) |
                   ((verb | payload) & 0xFFFFF);

    /* wait for any previous immediate command to drain */
    for (int i = 0; i < 1000 && (r16(REG_ICIS) & ICIS_ICB); i++) { }

    w16(REG_ICIS, r16(REG_ICIS) & ~ICIS_IRV);   /* clear stale response-valid */
    w32(REG_ICOI, cmd);
    w16(REG_ICIS, ICIS_ICB);                     /* issue */

    for (int i = 0; i < 100000; i++) {
        uint16_t s = r16(REG_ICIS);
        if ((s & ICIS_IRV) && !(s & ICIS_ICB))
            return r32(REG_IRII);
    }
    return 0;
}

/* Convenience: GetParameter on a node. */
static uint32_t get_param(int nid, uint32_t param) {
    return codec_cmd(codec, nid, VERB_GET_PARAM, param);
}

/* The 16-bit HDA stream-format word for 48 kHz, 16-bit, 2 channels:
 *   base 48 kHz (bit14=0), mult=1, div=1 (bits 8-13 = 0),
 *   bits-per-sample 16 -> 0b001 (bits 4-6), channels-1 = 1 (bits 0-3).
 * = 0x0011. This is exactly what AC'97 plays, so the resample path is shared. */
#define FMT_48K_16_2  0x0011

/* ---- widget-graph walk: find a DAC + an output pin under the AFG ---------- */
static void enumerate_codec(void) {
    afg = dac_nid = pin_nid = 0;

    /* Root node (nid 0): how many function groups, and where they start. */
    uint32_t root_nc = get_param(0, PARAM_NODE_COUNT);
    int fg_start = (root_nc >> 16) & 0xFF;
    int fg_count =  root_nc        & 0xFF;

    for (int fg = fg_start; fg < fg_start + fg_count && !afg; fg++) {
        uint32_t t = get_param(fg, PARAM_FN_GROUP_TYPE);
        if ((t & 0x7F) == 0x01)            /* 0x01 = Audio Function Group */
            afg = fg;
    }
    if (!afg) return;

    /* Wake the function group (D0). */
    codec_cmd(codec, afg, VERB_SET_POWER, 0x0);

    /* Walk every widget under the AFG: remember the first output DAC and the
     * first output-capable pin. (QEMU's hda-output codec has exactly one of
     * each, but we scan generally.) */
    uint32_t afg_nc = get_param(afg, PARAM_NODE_COUNT);
    int w_start = (afg_nc >> 16) & 0xFF;
    int w_count =  afg_nc        & 0xFF;

    for (int w = w_start; w < w_start + w_count; w++) {
        uint32_t cap  = get_param(w, PARAM_AUDIO_CAP);
        int type = (cap >> 20) & 0xF;
        if (type == WTYPE_OUT_DAC && !dac_nid)
            dac_nid = w;
        if (type == WTYPE_PIN && !pin_nid) {
            uint32_t pc = get_param(w, PARAM_PIN_CAP);
            if (pc & PINCAP_OUTPUT)
                pin_nid = w;
        }
    }
}

/* Wire DAC -> pin and unmute/enable both. */
static void configure_output(void) {
    /* DAC: stream format, then assign stream tag 1 / channel 0. */
    codec_cmd(codec, dac_nid, VERB_SET_STREAM_FMT, FMT_48K_16_2);
    codec_cmd(codec, dac_nid, VERB_SET_STREAM_CHAN,
              (STREAM_TAG << 4) | OUT_CHANNEL);

    /* Unmute + max gain on the DAC's OUTPUT amp.
     * SetAmpGain payload: bit15 output-amp, bit13 left, bit12 right,
     * bit7 mute(0=unmute), bits0-6 gain. 0xB000 | gain sets out+L+R, unmuted. */
    codec_cmd(codec, dac_nid, VERB_SET_AMP_GAIN, 0xB000 | 0x7F);

    /* If the pin sits behind a selector/mixer with the DAC as one input, the
     * default connection (entry 0) is usually the DAC; leave it. (QEMU wires
     * the pin straight to the DAC.) Unmute the pin's output amp too. */
    codec_cmd(codec, pin_nid, VERB_SET_AMP_GAIN, 0xB000 | 0x7F);

    /* Pin: power up, enable output (+ headphone amp), then EAPD if present. */
    codec_cmd(codec, pin_nid, VERB_SET_POWER, 0x0);
    codec_cmd(codec, pin_nid, VERB_SET_PIN_CTL, PINCTL_OUT_EN | PINCTL_HP_EN);

    uint32_t pc = get_param(pin_nid, PARAM_PIN_CAP);
    if (pc & PINCAP_EAPD)
        codec_cmd(codec, pin_nid, VERB_SET_EAPD, 0x2);   /* bit1 = EAPD enable */
}

/* ---- output stream descriptor programming -------------------------------- */

/* Reset the output stream: clear RUN, pulse RST (set, wait read-1, clear,
 * wait read-0), per the spec's stream-reset handshake. */
static void stream_reset(void) {
    sd_w8(SD_CTL, 0);                                  /* RUN=0 */
    for (int i = 0; i < 10000 && (sd_r8(SD_CTL) & SDCTL_RUN); i++) { }
    sd_w8(SD_CTL, SDCTL_RST);                          /* enter reset */
    for (int i = 0; i < 10000 && !(sd_r8(SD_CTL) & SDCTL_RST); i++) { }
    sd_w8(SD_CTL, 0);                                  /* leave reset */
    for (int i = 0; i < 10000 && (sd_r8(SD_CTL) & SDCTL_RST); i++) { }
}

/* Point the stream descriptor at the BDL/ring and set format + stream number,
 * but leave RUN clear (the caller sets it). */
static void stream_setup(void) {
    stream_reset();
    sd_w32(SD_BDLPL, (uint32_t)bdl_phys);
    sd_w32(SD_BDLPU, (uint32_t)(bdl_phys >> 32));
    sd_w32(SD_CBL,   RING_BYTES);
    sd_w16(SD_LVI,   NUM_BDL - 1);
    sd_w16(SD_FMT,   FMT_48K_16_2);

    /* Stream number lives in bits 20-23 of the 32-bit control register; write
     * the whole dword so it lands together with the (currently clear) low-byte
     * RUN/RST bits. The controller matches this against the converter's tag. */
    sd_w32(SD_CTL, (uint32_t)STREAM_TAG << 20);
}

/* ---- public: blocking + streaming playback (mirrors ac97.c) --------------- */

/* streaming ring (software producer -> the 32 BDL buffers), identical model to
 * ac97.c so audio.c's pump path and DOOM's mixer are driver-agnostic. */
#define STREAM_FRAMES 48000          /* 1 second of stereo ring */
static int16_t        *sbuf;
static volatile uint32_t s_head, s_tail;   /* producer / consumer, in frames */
static volatile int    stream_on;
static uint32_t        last_buf;           /* last buffer index we refilled    */

/* Which BDL buffer is the DMA engine currently inside? Derived from LPIB. */
static uint32_t cur_buf(void) {
    uint32_t pos = sd_r32(SD_LPIB) % RING_BYTES;
    return pos / BUF_BYTES;
}

void hda_stream_start(void) {
    if (!inited || stream_on) return;
    if (!sbuf) { sbuf = kmalloc(STREAM_FRAMES * 4); if (!sbuf) return; }
    s_head = s_tail = 0;

    /* all buffers silent + linked into the BDL */
    for (int i = 0; i < NUM_BDL; i++) {
        memset(hhdm(buf_phys[i]), 0, BUF_BYTES);
        bdl[i].addr_lo = (uint32_t)buf_phys[i];
        bdl[i].addr_hi = (uint32_t)(buf_phys[i] >> 32);
        bdl[i].len     = BUF_BYTES;
        bdl[i].flags   = 0;
    }
    stream_setup();
    last_buf = 0;
    sd_w32(SD_CTL, ((uint32_t)STREAM_TAG << 20) | SDCTL_RUN);   /* run continuously */
    stream_on = 1;
}

void hda_stream_stop(void) {
    if (!stream_on) return;
    stream_on = 0;
    sd_w8(SD_CTL, 0);          /* clear RUN (keep stream number in upper bits irrelevant once stopped) */
}

int hda_stream_write(const int16_t *frames, int nframes) {
    if (!inited) return 0;
    if (!stream_on) hda_stream_start();
    if (!stream_on) return 0;
    int wrote = 0;
    for (int i = 0; i < nframes; i++) {
        uint32_t next = (s_head + 1) % STREAM_FRAMES;
        if (next == s_tail) break;                      /* ring full */
        sbuf[s_head * 2]     = frames[i * 2];
        sbuf[s_head * 2 + 1] = frames[i * 2 + 1];
        s_head = next;
        wrote++;
    }
    return wrote;
}

int hda_stream_avail(void) {
    if (!sbuf) return STREAM_FRAMES - 1;
    uint32_t used = (s_head - s_tail + STREAM_FRAMES) % STREAM_FRAMES;
    return (int)(STREAM_FRAMES - 1 - used);
}

/* Timer-IRQ hook: refill the buffers the DMA engine has passed from the
 * software ring, underrunning to silence — same shape as ac97_pump. */
void hda_pump(void) {
    if (!stream_on) return;
    uint32_t cur = cur_buf();
    while (last_buf != cur) {                            /* buffers the engine finished */
        int16_t *dst = (int16_t *)hhdm(buf_phys[last_buf]);
        for (int f = 0; f < (int)BUF_FRAMES; f++) {
            if (s_tail != s_head) {
                dst[f * 2]     = sbuf[s_tail * 2];
                dst[f * 2 + 1] = sbuf[s_tail * 2 + 1];
                s_tail = (s_tail + 1) % STREAM_FRAMES;
            } else { dst[f * 2] = dst[f * 2 + 1] = 0; }  /* underrun: silence */
        }
        last_buf = (last_buf + 1) % NUM_BDL;
    }
}

/* Blocking playback of a finite buffer: stream it through the ring and wait for
 * it to drain. The syscall path sets IF=1 so timer_wait's hlt can wake. */
void hda_play(const int16_t *frames, int nframes) {
    if (!inited || nframes <= 0) return;
    hda_stream_start();
    int pos = 0;
    while (pos < nframes) {
        /* push as much as fits, then sleep a little for the DMA to drain */
        pos += hda_stream_write(frames + (size_t)pos * 2, nframes - pos);
        if (pos < nframes)
            timer_wait(1);              /* ~10 ms; pump runs in the IRQ */
    }
    /* wait for the ring to empty (consumer catches the producer) */
    for (int i = 0; i < 500 && s_tail != s_head; i++)
        timer_wait(1);
    timer_wait(3);                      /* let the last queued buffers play out */
}

/* ---- bring-up ------------------------------------------------------------- */
int hda_init(void) {
    /* QEMU's `intel-hda` is an Intel ICH6 HDA controller (8086:2668); the real
     * ICH9 variant is 0x293E. Match by class first (0x04 multimedia, 0x03 HDA)
     * so any HDA controller is found, then fall back to the known ids. */
    pci_device_t d = pci_find_class(0x04, 0x03, 0x00);
    if (!d.valid) d = pci_find(0x8086, 0x2668);
    if (!d.valid) d = pci_find(0x8086, 0x293E);
    if (!d.valid) { return -1; }              /* no HDA controller — caller no-ops */

    /* Enable PCI memory-space decode + bus mastering so the controller can DMA. */
    pci_enable_bus_master(&d);

    /* BAR0 is the MMIO register block. Map it cache-disabled, like AHCI's ABAR:
     * it sits in the PCI hole above the boot identity map, so it must be mapped
     * before we touch it. The register window (controller globals + per-stream
     * descriptors) fits comfortably in two pages. */
    uint64_t bar0 = pci_bar(&d, 0);
    if (!bar0) { kprintf("[hda] BAR0 not assigned\n"); return -1; }
    for (uint64_t off = 0; off < 0x4000; off += PAGE_SIZE)
        vmm_map(bar0 + off, bar0 + off, PTE_WRITABLE | PTE_PCD);
    mmio = (volatile uint8_t *)(uintptr_t)bar0;

    /* 1. Reset the controller: drive CRST# low, then high, and wait for it to
     *    report it has come out of reset (GCTL.CRST reads back 1). */
    w32(REG_GCTL, r32(REG_GCTL) & ~GCTL_CRST);
    for (int i = 0; i < 100000 && (r32(REG_GCTL) & GCTL_CRST); i++) { }
    w32(REG_GCTL, r32(REG_GCTL) | GCTL_CRST);
    int up = 0;
    for (int i = 0; i < 1000000; i++)
        if (r32(REG_GCTL) & GCTL_CRST) { up = 1; break; }
    if (!up) { kprintf("[hda] controller reset timeout\n"); return -1; }

    /* Codecs need a moment after CRST to assert their STATESTS bit. */
    timer_wait(1);

    /* The number of in/out/bidir stream descriptors (from GCAP) tells us where
     * the first OUTPUT stream descriptor lives: after the ISS input ones. */
    uint16_t gcap = r16(REG_GCAP);
    int iss = (gcap >> 8) & 0x0F;     /* input stream count   */
    int oss = (gcap >> 12) & 0x0F;    /* output stream count  */
    osd = mmio + 0x80 + (uint32_t)iss * 0x20;   /* first output stream descriptor */

    /* 2. Codec enumeration: STATESTS has a bit per codec slot that woke up. */
    uint16_t statests = r16(REG_STATESTS);
    if (!statests) { kprintf("[hda] no codec responded (STATESTS=0)\n"); return -1; }
    codec = -1;
    for (int i = 0; i < 15; i++)
        if (statests & (1u << i)) { codec = i; break; }
    if (codec < 0) { kprintf("[hda] STATESTS=%x but no codec bit?\n", statests); return -1; }

    uint32_t vid = get_param(0, PARAM_VENDOR_ID);
    kprintf("[hda] STATESTS=%x codec=%d vendor=%04x:%04x iss=%d oss=%d\n",
            statests, codec, vid >> 16, vid & 0xFFFF, iss, oss);

    /* 3. Find + configure the output path (DAC -> pin). */
    enumerate_codec();
    if (!afg || !dac_nid || !pin_nid) {
        kprintf("[hda] no output path (afg=%d dac=%d pin=%d)\n", afg, dac_nid, pin_nid);
        return -1;
    }
    configure_output();

    /* 4. Allocate the BDL + cyclic ring (plain RAM frames; identity-mapped, so
     *    their physical address is also a usable virtual one). */
    bdl_phys = pmm_alloc_frame();
    if (!bdl_phys) { kprintf("[hda] OOM (BDL)\n"); return -1; }
    bdl = (bdl_entry_t *)hhdm(bdl_phys);
    memset(bdl, 0, NUM_BDL * sizeof(bdl_entry_t));
    for (int i = 0; i < NUM_BDL; i++) {
        buf_phys[i] = pmm_alloc_frame();
        if (!buf_phys[i]) { kprintf("[hda] OOM (ring)\n"); return -1; }
    }
    stream_setup();    /* program the descriptor now; RUN flips on first play */

    inited = 1;
    kprintf("[ ok ] HDA audio: BAR0=%lx codec=%d dac=%d pin=%d (stream tag %d)\n",
            (unsigned long)bar0, codec, dac_nid, pin_nid, STREAM_TAG);
    return 0;
}

/* Bring-up self-test: queue a short tone and confirm the stream's DMA position
 * register (LPIB) advances — the headless proof that the controller is actually
 * streaming (audio is inaudible without a host sound server). Generates a ~440 Hz
 * triangle wave (no FP — the kernel builds with -mgeneral-regs-only), streams it
 * through the ring, samples LPIB before/after a short wait, and logs both. */
void hda_selftest(void) {
    if (!inited) return;

    /* ~0.2 s of a 440 Hz triangle wave at 48 kHz stereo. period ~= 109 frames. */
    enum { N = 9600, PERIOD = 109 };
    static int16_t tone[N * 2];
    for (int i = 0; i < N; i++) {
        int p = i % PERIOD;
        /* triangle: ramp up for the first half-period, down for the second */
        int v = (p < PERIOD / 2) ? p : (PERIOD - p);
        int16_t s = (int16_t)((v - PERIOD / 4) * 400);   /* center + scale */
        tone[i * 2] = tone[i * 2 + 1] = s;
    }

    hda_stream_start();
    int queued = hda_stream_write(tone, N);

    uint32_t lpib0 = sd_r32(SD_LPIB);
    uint32_t ctl   = sd_r32(SD_CTL);
    timer_wait(5);                    /* ~50 ms — the pump feeds the ring meanwhile */
    uint32_t lpib1 = sd_r32(SD_LPIB);

    kprintf("[hda] selftest: queued=%d CTL=%x RUN=%d LPIB %u -> %u : %s\n",
            queued, ctl, (ctl >> 1) & 1, lpib0, lpib1,
            (lpib1 != lpib0) ? "DMA ADVANCING" : "STALLED");

    /* drain + stop so the test tone doesn't keep looping behind the desktop */
    timer_wait(15);
    hda_stream_stop();
}
