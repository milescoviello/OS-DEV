# North-star goals — an honest difficulty breakdown

You named three end goals: **(1) a web browser, (2) play music from the NAS,
(3) run Claude Code.** They are all reachable in *some* form, but they differ
enormously in difficulty, and one of them is genuinely a multi-year stretch.
Here's the honest picture so expectations match reality.

All three sit on top of the same **foundation** (interrupts → memory →
scheduler → userspace → libc → filesystem). That foundation is the achievable,
fun, well-documented part — months of work for a determined hobbyist. The goals
below are what comes *after* it, and each adds large subsystems.

---

## Update (2026-06-02): where we actually landed

- **🌐 Web browser — achieved, far beyond the original bar** (updated ~M215).
  OS-DEV browses the **real HTTPS web** with a from-scratch **TLS 1.3 client** +
  full X.509 chain validation to baked-in roots (the once-"remaining gate" is
  done — example.com/NPR/gnu.org/google.com all validate, `TLS*`), its own HTML
  renderer (headings, bold/italic, links, lists, tables, `<pre>`, inline
  PNG/GIF/JPEG, colour, entities), and a **comprehensive from-scratch JavaScript
  engine** (OOP + ES6 + regex + Map/Set/Date) that runs in pages. It is
  **interactive**: a minimal DOM (`getElementById`/`querySelector` →
  `textContent`/`innerHTML`/`.value`/`getAttribute`/`setAttribute`),
  `window.location`, inline `onclick`, the full form-input set, **GET form
  submission + live web search (DuckDuckGo, from a form or the address bar)**,
  and reactive `onchange`/`oninput`. Fully keyboard-driven. The honest ceiling
  (real web apps / Chromium) still stands — see below — but "a browser somehow"
  is comprehensively met.
- **🎵 Music — audio SHIPPED; the "from the NAS" part is what's still missing.**
  Miles deprioritized this goal ("idc about music i want a good DE"), and the
  note here used to say "an audio driver + decoder were never built" — that is
  **false and was corrected 2026-07-28**. What actually exists: **two audio
  drivers** (`kernel/ac97.c` AC'97 and `kernel/hda.c` Intel HD Audio, selected at
  boot, `audio_name()` reports which), a **from-scratch WAV decoder**
  (`kernel/wav.c`), a mixing/streaming layer (`kernel/audio.c`:
  `audio_play_wav`, `audio_play_wav_bg`, `audio_stream_write` + a timer-IRQ
  pump), and a **`jukebox` player app** (`user/jukebox.c`) that scans the disk
  for WAVs and plays them. DOOM and Quake play their sound through it.
  What is genuinely NOT built: **compressed-format decoders** (no MP3/FLAC/Vorbis)
  and **any NAS filesystem protocol** (no SMB/CIFS, no NFS, no DLNA). HTTP is the
  only transport, so the closest thing to the original goal today is
  `wget <url> <file>` followed by `jukebox` — i.e. fetch-then-play a WAV over
  HTTP, not stream from an SMB share.
- **🤖 Run Claude Code — still a multi-year stretch.** Unchanged: needs a Linux
  syscall ABI + a JS runtime. Not attempted.

## Update (2026-09): the minimal DOM landed, and a stylesheet can now lay out a page

Two corrections to the 2026-06 note below, which has gone stale in one direction
and been confirmed in the other:

- **The "next big build" it names is done.** A minimal DOM shipped: pages get
  `getElementById`-style access (`browser_dom_get`/`browser_dom_set`,
  text *and* HTML), element `onclick` handlers, and a canvas bridge. In-page JS
  is no longer only `document.write` + `javascript:` links.
- **CSS got the missing half (M1928-M1931).** Until recently the cascade carried
  **no box geometry at all** — width, margins, padding and height could only come
  from an inline `style=` attribute, so a *stylesheet* could not lay out a page,
  which is how essentially every real page is built. That is fixed, along with
  viewport units (`vw`/`vh`), `float`/`clear`, and `max-height`/`overflow:hidden`.
  example.com now renders as the centred column its stylesheet asks for, and
  danluu.com and `text.npr.org` render close to a real browser.

**The honest ceiling below is unchanged.** None of this moves Chromium, Google Docs
or a modern SPA into reach — those need a full layout engine, an event loop and a
Linux ABI. What changed is that *text-oriented real pages* now render largely
correctly, which is exactly the "best little from-scratch browser" target. Still
genuinely out of reach in the renderer: `position`, `z-index`, and floated block
containers, all of which need real out-of-flow boxes.

---

## Update (later 2026-06): HTTPS + a JavaScript engine landed

Two big things changed since the note above:

- **🔒 HTTPS/TLS is done.** A from-scratch **TLS 1.3 client** (X25519 + HKDF,
  AES-GCM/ChaCha20-Poly1305, from-scratch RSA + ECDSA P-256/P-384 + SHA-256/384)
  with **X.509 certificate-chain validation to baked-in trusted roots** browses
  the real HTTPS web (example.com, NPR, gnu.org, danluu.com, google.com → `TLS*`).
  The browser is no longer HTTP-only.
- **🧩 A from-scratch JavaScript engine** (`kernel/js.c`) — closures, arrow
  functions, template literals, `switch`/`for-of`, `try/catch/finally/throw`,
  `JSON.parse/stringify`, and a Math/String/Array standard library. It runs from
  the shell (`js`) **and inside the browser**: pages execute their `<script>` at
  load (`document.write`) and `javascript:` links run JS on click.

**The honest ceiling (decided with Miles):** running **Chromium / Google Docs /
Blackbaud** is **not achievable** here. Those need a complete modern engine — a
full JS+DOM+CSS layout engine, an event loop, `fetch`/WebSocket, plus (to run the
*real* browser binary) a Linux ABI, libc, dynamic loader, threads, and a graphics
stack. That's a multi-year "build a Linux clone" effort, not a feature. The
realistic direction is **"the best little from-scratch browser"**, not real-web-app
compatibility. The browser is currently a *token-stream renderer* (no DOM tree);
the next big build toward interactivity is a **minimal DOM**
(`getElementById`/`textContent`/element `onclick`) plus a persistent per-page JS
context — until then, in-page JS is `document.write` + `javascript:` links.

The detailed original analysis follows.

---

## 🎵 Play music from the NAS — **the most achievable goal**

What it needs:
- **NIC driver** — QEMU emulates `e1000` / `virtio-net`. Moderate.
- **TCP/IP stack** — ARP, IPv4, ICMP, UDP, TCP, DNS. Big but well-trodden; we
  can write it or port **lwIP**.
- **A way to reach the NAS:**
  - If the NAS exposes **HTTP/DLNA** → just an HTTP client. *Much* easier.
  - **SMB/CIFS** or **NFS** client → considerably more work.
- **Audio driver** — QEMU emulates Intel HD Audio (`intel-hda`) or `AC'97`.
  Push PCM samples to the codec. Moderate.
- **Decoding** — WAV is raw PCM (trivial). MP3/FLAC = port a small decoder
  (`minimp3`, `dr_flac`).

**Realistic milestone:** stream a WAV (or MP3 via a ported decoder) over HTTP
from the NAS and play it through the AC'97/HDA codec. This is genuinely
attainable and a fantastic mid-term target.

> **Status (2026-07-28): mostly reached.** The NIC driver, TCP/IP stack, HTTP
> client, AC'97 *and* HDA drivers, and a WAV decoder + player app all shipped —
> see the corrected bullet in the update section above. The two pieces of this
> paragraph still outstanding are the **MP3/FLAC decoder** and an **SMB/NFS
> client**; over HTTP it is `wget` + `jukebox` today.

---

## 🌐 A web browser — **achievable in a limited form**

Two routes:

- **(a) Write your own engine.** A minimal HTML/CSS renderer (little or no
  JavaScript) drawing to a framebuffer with a font rasterizer. Large but
  bounded — you can render simple pages. This is the SerenityOS path; they
  spent *years* building their engine (Ladybird).
- **(b) Port an existing engine.** The realistic target is **NetSurf** — a
  lightweight browser with its own engine and few dependencies, designed to be
  portable. Porting **Firefox/Chromium is effectively infeasible solo**:
  millions of lines, needs a near-complete Linux userland, GPU, threads, and
  sandboxing.

Either route also needs: **framebuffer graphics** (VBE or QEMU virtio-gpu),
**fonts** (port FreeType or a bitmap font), **TLS** (port BearSSL/mbedTLS), and
the TCP stack from the music goal.

**Realistic milestone:** a simple browser (your own renderer, or a NetSurf
port) that loads basic HTTPS pages. Not "modern Chrome."

---

## 🤖 Run Claude Code — **the hardest by far; a long-horizon stretch goal**

Claude Code is a **Node.js** application. Running it natively means running
Node (V8 + libuv) on this OS, which requires:

- A substantial **POSIX libc** (port **musl** or **newlib**), **threads**
  (pthreads/futexes), `mmap`, signals, a **PTY/terminal**, a real process model.
- A **TCP/IP stack with working TLS 1.2/1.3** (it calls the Anthropic API over
  HTTPS).
- Then either:
  - **(a) compile Node for the OS** — Node's build is enormous and assumes a
    lot of POSIX; very hard, or
  - **(b) implement enough of the Linux syscall ABI to run a *prebuilt* Linux
    Node binary** (a "Linux compatibility layer") — the pragmatic route, and how
    some hobby OSes run real software. Still means implementing dozens of
    syscalls precisely (`clone`, `futex`, `epoll`, `mmap`…) plus a dynamic
    linker, or running a static build.

**Honest assessment:** this is essentially *"make the OS Linux-compatible
enough to run Node and do TLS networking."* It's a multi-year goal and may stay
aspirational — but it's the single best reason to make one **early
architectural decision** (below).

---

## The one early decision these goals force

Most of the foundation is identical no matter what. But around the
**userspace/libc** stage we choose a philosophy:

- **Pure from-scratch** ("SerenityOS style"): write your own libc, your own
  browser, your own everything. Music ✅, your own simple browser ✅, but you'd
  build your *own* tools rather than run Node — so **Claude Code wouldn't run
  natively** this way.
- **Compatibility-oriented** ("run real software"): aim early for a **musl
  libc + Linux-compatible syscall ABI**, so the long-term payoff is running
  unmodified third-party binaries — eventually Node (→ Claude Code) and a
  ported browser. More constraining, lots of unglamorous syscall work, but the
  only realistic path to literally running Claude Code.

**We do not need to decide today.** Milestones 1–7 are the same either way.
We pick the fork when we reach userspace (milestone 8).
