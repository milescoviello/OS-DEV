/*
 * ac97.c — Intel 82801AA AC'97 audio (the QEMU `-device AC97`).
 *
 * The chip exposes two port-I/O register windows via PCI BARs: NAM (BAR0, the
 * AC'97 mixer/codec) and NABM (BAR1, the bus-master DMA engine). PCM output is
 * driven by a Buffer Descriptor List (BDL): an array of up to 32 entries, each
 * { physical buffer address, sample count, control }. We hand the engine a list
 * of plain RAM frames (whose physical address doubles as a virtual one via the
 * identity map, like the e1000 rings), point it at the codec, and it DMAs the
 * 16-bit-stereo-48 kHz samples out.
 *
 * This first cut plays a finite buffer and blocks until it has drained — enough
 * for a `tone` command and a building block for the DOOM mixer (which will stream
 * a ring instead).
 */
#include "ac97.h"
#include "pci.h"
#include "io.h"
#include "pmm.h"
#include "vmm.h"   /* hhdm(): CPU access to DMA memory (M1970) */
#include "timer.h"
#include "console.h"
#include "kheap.h"
#include "wav.h"
#include "string.h"
#include <stdint.h>
#include <stddef.h>

/* NAM (mixer) registers — 16-bit, relative to BAR0 */
#define NAM_RESET    0x00
#define NAM_MASTER   0x02      /* master volume     */
#define NAM_PCM_OUT  0x18      /* PCM-out volume     */

/* NABM (bus master) registers — the PCM-Out box lives at offset 0x10 of BAR1 */
#define PO_BDBAR     0x10      /* 32-bit: BDL physical base        */
#define PO_CIV       0x14      /*  8-bit: current buffer index (RO) */
#define PO_LVI       0x15      /*  8-bit: last valid buffer index   */
#define PO_SR        0x16      /* 16-bit: status                    */
#define PO_PICB      0x18      /* 16-bit: samples left in cur buffer*/
#define PO_CR        0x1B      /*  8-bit: control                   */

#define CR_RPBM      0x01      /* run (1) / pause (0) bus master    */
#define CR_RR        0x02      /* reset this DMA engine             */
#define SR_DCH       0x01      /* DMA controller halted             */

#define NUM_BUF      32                 /* BDL entries */
#define BUF_FRAMES   (PAGE_SIZE / 4)    /* 16-bit stereo frames per 4 KiB buffer = 1024 */

typedef struct {
    uint32_t addr;     /* physical address of the sample buffer */
    uint16_t samples;  /* number of 16-bit samples (= frames * 2) */
    uint16_t ctrl;     /* bit15 IOC, bit14 BUP */
} __attribute__((packed)) bdl_entry_t;

static uint16_t     nam, nabm;             /* I/O port bases */
static bdl_entry_t *bdl;                   /* 32 entries (one frame) */
static uint64_t     bdl_phys;
static uint64_t     buf_phys[NUM_BUF];     /* the sample-buffer pool */
static int          inited;

int ac97_ready(void) { return inited; }

int ac97_init(void) {
    pci_device_t d = pci_find(0x8086, 0x2415);   /* 82801AA AC'97 */
    if (!d.valid) { kprintf("[ac97] no device\n"); return -1; }

    /* enable I/O space (bit0) + bus master (bit2) in the PCI command register */
    uint32_t cmd = pci_read32(d.bus, d.slot, d.func, 0x04);
    pci_write32(d.bus, d.slot, d.func, 0x04, cmd | 0x05);

    nam  = (uint16_t)pci_bar(&d, 0);
    nabm = (uint16_t)pci_bar(&d, 1);

    outw(nam + NAM_RESET, 1);          /* reset the mixer */
    outw(nam + NAM_MASTER, 0x0000);    /* 0x0000 = full volume, unmuted */
    outw(nam + NAM_PCM_OUT, 0x0000);

    outb(nabm + PO_CR, CR_RR);                       /* reset the PCM-out engine */
    for (int i = 0; i < 100000 && (inb(nabm + PO_CR) & CR_RR); i++) { }

    bdl_phys = pmm_alloc_frame();
    bdl = (bdl_entry_t *)(uintptr_t)bdl_phys;
    memset(bdl, 0, NUM_BUF * sizeof(bdl_entry_t));
    for (int i = 0; i < NUM_BUF; i++) buf_phys[i] = pmm_alloc_frame();   /* 128 KiB pool */
    outl(nabm + PO_BDBAR, (uint32_t)bdl_phys);

    inited = 1;
    kprintf("[ ok ] AC'97 audio: NAM=%x NABM=%x\n", nam, nabm);
    return 0;
}

void ac97_play(const int16_t *frames, int nframes) {
    if (!inited || nframes <= 0) return;
    ac97_stream_stop();    /* blocking playback and streaming both own PCM-out */

    /* Fill the buffer pool + BDL, at most NUM_BUF * BUF_FRAMES frames per batch. */
    int total = nframes, pos = 0;
    while (pos < total) {
        int batch_start = pos, n = 0;
        for (; n < NUM_BUF && pos < total; n++) {
            int chunk = total - pos;
            if (chunk > (int)BUF_FRAMES) chunk = BUF_FRAMES;
            memcpy((int16_t *)(uintptr_t)buf_phys[n], frames + (size_t)pos * 2, (size_t)chunk * 4);
            bdl[n].addr    = (uint32_t)buf_phys[n];
            bdl[n].samples = (uint16_t)(chunk * 2);   /* 2 samples per stereo frame */
            bdl[n].ctrl    = 0;
            pos += chunk;
        }

        outl(nabm + PO_BDBAR, (uint32_t)bdl_phys);
        outb(nabm + PO_LVI, (uint8_t)(n - 1));        /* play entries 0..n-1 */
        outb(nabm + PO_CR, CR_RPBM);                  /* run */

        /* Block for this batch's duration at 48 kHz, then confirm it halted.
         * The syscall path sets IF=1 so timer_wait's hlt can wake. */
        int ms = (pos - batch_start) * 1000 / 48000 + 30;   /* + margin */
        timer_wait((uint64_t)ms / 10 + 1);

        for (int i = 0; i < 200000 && !(inb(nabm + PO_SR) & SR_DCH); i++) { }
        outb(nabm + PO_CR, 0);                        /* stop */
    }
}

/* Decode a 16-bit PCM WAV into a fresh kmalloc'd 48 kHz-stereo buffer (caller
 * frees). Sets *nframes; returns NULL on a bad/unsupported WAV or OOM. */
static int16_t *wav_decode(const uint8_t *d, int len, long *nframes) {
    int channels, rate, bits;
    long pcm_off, pcm_len;
    if (wav_parse(d, len, &channels, &rate, &bits, &pcm_off, &pcm_len) < 0) return 0;
    long in_frames = pcm_len / (2 * channels);
    const int16_t *in = (const int16_t *)(d + pcm_off);
    long out_frames = in_frames * 48000 / rate;       /* resample to the AC'97's 48 kHz */
    if (out_frames <= 0) return 0;
    int16_t *out = kmalloc((size_t)out_frames * 4);
    if (!out) return 0;
    for (long i = 0; i < out_frames; i++) {
        long si = i * rate / 48000;                   /* nearest-neighbour */
        if (si >= in_frames) si = in_frames - 1;
        if (channels == 2) { out[i*2] = in[si*2]; out[i*2+1] = in[si*2+1]; }
        else               { out[i*2] = out[i*2+1] = in[si]; }
    }
    *nframes = out_frames;
    return out;
}

int ac97_play_wav(const uint8_t *d, int len) {        /* blocking */
    if (!inited) return -1;
    long n; int16_t *pcm = wav_decode(d, len, &n);
    if (!pcm) return -1;
    ac97_play(pcm, (int)n);
    kfree(pcm);
    return 0;
}

/* ---- streaming: a non-blocking PCM ring kept fed from the timer IRQ --------
 * The 32 BDL buffers are run as a continuous loop; ac97_pump() (called each
 * timer tick) refills the buffers the device just finished from a software ring
 * the producer writes via ac97_stream_write(), and keeps LVI one buffer behind
 * CIV so the engine never halts. Underruns play silence. This is what DOOM's
 * sound mixer feeds. */
#define STREAM_FRAMES 48000          /* 1 second of stereo ring */
static int16_t        *sbuf;
static volatile uint32_t s_head, s_tail;   /* producer / consumer, in frames */
static volatile int    stream_on;
static int             last_civ;

/* Background music: a decoded 48 kHz-stereo song the pump streams on its own
 * (non-blocking), so playback continues while other apps run. Mutually exclusive
 * with app streaming (ac97_stream_write) — whichever starts last wins. */
static int16_t        *bg_buf;
static long            bg_frames, bg_pos;
static volatile int    bg_active;

void ac97_stream_start(void) {
    if (!inited || stream_on) return;
    if (!sbuf) { sbuf = kmalloc(STREAM_FRAMES * 4); if (!sbuf) return; }
    s_head = s_tail = 0;
    outb(nabm + PO_CR, CR_RR);
    for (int i = 0; i < 100000 && (inb(nabm + PO_CR) & CR_RR); i++) { }
    for (int i = 0; i < NUM_BUF; i++) {                 /* all buffers silent + full */
        memset(hhdm(buf_phys[i]), 0, BUF_FRAMES * 4);
        bdl[i].addr = (uint32_t)buf_phys[i];
        bdl[i].samples = BUF_FRAMES * 2;
        bdl[i].ctrl = 0;
    }
    outl(nabm + PO_BDBAR, (uint32_t)bdl_phys);
    last_civ = 0;
    outb(nabm + PO_LVI, NUM_BUF - 1);
    outb(nabm + PO_CR, CR_RPBM);                        /* run continuously */
    stream_on = 1;
}

void ac97_stream_stop(void) {
    if (!stream_on) return;
    stream_on = 0;
    outb(nabm + PO_CR, 0);
}

/* Queue interleaved stereo frames; returns how many were accepted (drops the
 * rest if the ring is full). Non-blocking. Starts the stream on first use. */
int ac97_stream_write(const int16_t *frames, int nframes) {
    if (!inited) return 0;
    if (!stream_on) ac97_stream_start();
    if (!stream_on) return 0;
    bg_active = 0;                  /* app streaming (e.g. DOOM) preempts background music */
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

int ac97_stream_avail(void) {                           /* free frames in the ring */
    if (!sbuf) return STREAM_FRAMES - 1;
    uint32_t used = (s_head - s_tail + STREAM_FRAMES) % STREAM_FRAMES;
    return (int)(STREAM_FRAMES - 1 - used);
}

/* Background playback: take ownership of `pcm` (nframes of 48 kHz stereo) and
 * stream it from the pump. Non-blocking; replaces any current song. */
void ac97_play_bg(int16_t *pcm, long nframes) {
    if (!inited || !pcm || nframes <= 0) return;
    ac97_stream_start();                 /* ensure the engine is running */
    uint64_t fl; __asm__ volatile("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    int16_t *old = bg_buf;               /* swap under cli — the pump runs in the IRQ */
    bg_active = 0;
    bg_buf = pcm; bg_frames = nframes; bg_pos = 0;
    s_head = s_tail;                     /* drop any stale app-stream data */
    bg_active = 1;
    __asm__ volatile("push %0; popfq" : : "r"(fl) : "memory", "cc");
    if (old) kfree(old);                 /* now unreferenced — safe to free */
}

void ac97_stop_bg(void) {
    uint64_t fl; __asm__ volatile("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    int16_t *old = bg_buf;
    bg_active = 0; bg_buf = 0;
    __asm__ volatile("push %0; popfq" : : "r"(fl) : "memory", "cc");
    if (old) kfree(old);
}

/* Decode a WAV and play it in the background (non-blocking). 0/-1. */
int ac97_play_wav_bg(const uint8_t *d, int len) {
    if (!inited) return -1;
    long n; int16_t *pcm = wav_decode(d, len, &n);
    if (!pcm) return -1;
    ac97_play_bg(pcm, n);                /* transfers ownership */
    return 0;
}

/* Timer-IRQ hook: refill finished buffers from the software ring, advance LVI. */
void ac97_pump(void) {
    if (!stream_on) return;

    /* background music: top up the software ring from the decoded song */
    if (bg_active && bg_buf) {
        while (bg_pos < bg_frames) {
            uint32_t next = (s_head + 1) % STREAM_FRAMES;
            if (next == s_tail) break;                   /* ring full */
            sbuf[s_head * 2]     = bg_buf[bg_pos * 2];
            sbuf[s_head * 2 + 1] = bg_buf[bg_pos * 2 + 1];
            s_head = next; bg_pos++;
        }
        if (bg_pos >= bg_frames) bg_active = 0;          /* finished (buffer freed on next play/stop) */
    }

    int civ = inb(nabm + PO_CIV);
    while (last_civ != civ) {                           /* buffers the device finished */
        int16_t *dst = (int16_t *)(uintptr_t)buf_phys[last_civ];
        for (int f = 0; f < (int)BUF_FRAMES; f++) {
            if (s_tail != s_head) {
                dst[f * 2]     = sbuf[s_tail * 2];
                dst[f * 2 + 1] = sbuf[s_tail * 2 + 1];
                s_tail = (s_tail + 1) % STREAM_FRAMES;
            } else { dst[f * 2] = dst[f * 2 + 1] = 0; }  /* underrun: silence */
        }
        last_civ = (last_civ + 1) % NUM_BUF;
    }
    outb(nabm + PO_LVI, (uint8_t)((civ + NUM_BUF - 1) % NUM_BUF));   /* stay one behind CIV */
}
