<div align="center">

# OS-DEV

**A from-scratch x86_64 operating system** — kernel, TLS 1.3, a JavaScript
engine, and a sandboxed web browser — written in C and a little assembly.
Developed under QEMU; boots on real hardware through GRUB.

[![Milestones](https://img.shields.io/badge/milestones-1952-blue)](WHATS-NEXT.md)
[![Tests](https://img.shields.io/badge/tests-136%20suites-brightgreen)](tests/README.md)
[![host tests](https://github.com/kitslayer/OS-DEV/actions/workflows/ci.yml/badge.svg)](https://github.com/kitslayer/OS-DEV/actions/workflows/ci.yml)
[![From scratch](https://img.shields.io/badge/from--scratch-~101k%20lines-orange)](#status)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

![Demo: the desktop, the Apps menu, DOOM running as a windowed ring-3 process, and the from-scratch browser fetching a page over real HTTPS](docs/osdev-demo.gif)

</div>

## Status

A mature hobby OS that goes from power-on to a graphical, mouse- and
keyboard-driven **desktop** and hosts real **ring-3 programs as windows**. It is
developed and run under QEMU; it also boots via GRUB / Multiboot2 (see the honest
caveats below).

### What's genuinely here — from scratch

- **Kernel:** x86_64 long mode; physical + virtual memory managers; a kernel
  heap; **preemptive** multitasking with a CFS-style weighted scheduler,
  sleep/wake, and **fork + copy-on-write**; per-process address-space isolation;
  ring-3 userspace over a ~280-call syscall layer; an ELF loader (incl. PIE /
  load-time dynamic relocation); and **SMP bring-up** (LAPIC + the ACPI MADT;
  every core trampolines up into long mode).
- **Storage + filesystems:** a read-write **FAT32** driver over ATA / AHCI /
  NVMe / virtio-blk, now with a from-scratch **write-ahead journal** so a file /
  directory create is **crash-atomic** (ext3-style ordered-mode metadata
  journaling with replay-on-mount — survives a power cut); ext2 + ISO-9660
  readers; a VFS with `/proc` and `/dev`; a **unified block cache** shared by
  every device (one LRU pool, write-through); and software **RAID-0/1/5 + a
  linear (LVM-lite) volume manager**.
- **Networking:** ARP / IPv4 / ICMP / UDP / **TCP**, DNS, DHCP, and a
  **TLS 1.3 client** built on from-scratch X25519 / RSA / ECDSA / AES-GCM /
  ChaCha20-Poly1305 / SHA-2, with **X.509 chain validation to ~13 baked-in root
  CAs** (hostname + validity enforced — the core anti-MITM checks). A real HTTPS
  handshake to example.com is exercised and asserted on every boot. There is also
  a small from-scratch HTTP server, a WebSocket client + server, and a **network
  debug console** (`-append netcon`) that serves a remote inspection shell
  (`dmesg`/`ps`/`mem`/`pci`/`ls`/`cat`/`reboot`) over TCP — the bring-up lifeline
  for a physical machine whose framebuffer may not light up.
- **Graphics + desktop:** a framebuffer compositor; a window manager
  (drag / resize / tile / start-menu); PS/2 and USB-tablet pointers; AC'97 / Intel
  HD-Audio sound; a **web browser** with a **from-scratch JavaScript engine**
  (ES6-flavoured: classes, closures, arrow functions, destructuring, Map/Set, a
  Math/JSON/String/Array standard library) that renders real pages and runs page
  `<script>` against a minimal live DOM; and from-scratch **PNG / GIF / JPEG /
  SVG / BMP** decoders.
- **Security hardening:** every syscall pointer argument is validated by a
  PTE_USER page-table walk; the kernel image is **W^X** (`.text` read-only +
  executable, `.rodata` / `.data` / `.bss` / heap / stacks **non-executable**);
  both the kernel **and** user stacks have unmapped **guard pages** (an overflow
  faults cleanly rather than corrupting a neighbour), backed by a stack-overflow
  canary; and **SMEP + UMIP** are enabled when the CPU exposes them. These aren't
  just claimed: end-to-end tests in `make check` deliberately overflow a kernel
  stack, overflow a user stack, execute a no-execute page, and execute a user page
  from ring 0 — and assert each one faults. The untrusted-input parsers are
  continuously fuzzed under ASan/UBSan.
- **Userspace:** a real scripting **shell** (pipes, redirects, globbing,
  functions, control flow, quoting); a **text editor** with syntax highlighting; a
  **hex editor**; a **file manager**; a **spreadsheet** (live formulas — arithmetic,
  logic, stats — CSV import/export, and in-cell bar charts) and a **graphing
  calculator** (plots y=f(x)); developer tools — a **JSON** validator/pretty-printer,
  an interactive **regex** tester (over the JS engine's own regex), a visual **diff**
  viewer, a zip/tar **archive** browser, and a SHA-256/512/CRC-32 **checksum** tool; a
  mouse-driven **paint** program (shapes, flood-fill, PNG/BMP export); ~50 more small
  graphical tools (clocks, converters, a scientific calculator, a system monitor, a
  task manager, …); and ~40 games. **Bundled third-party software** runs as ring-3
  windows on the syscall layer: id Software's **DOOM** and **Quake**, a **Game Boy**
  emulator (Peanut-GB), and a **NES** emulator (libxnes).

### Honest caveats — this is a learning project, not a production OS

- **Development happens under QEMU, but it does boot on real hardware.** A
  physical laptop boots it through GRUB and is driven over ethernet by the
  **network debug console** (`netcon`) on TCP 2323 — `make efi-bringup` /
  `make iso-bringup` build that image, and the GRUB→Multiboot2 handoff is also
  verified under OVMF (`make efitest`). Getting there took a real bug hunt: a page
  walk through the low-1 GiB identity map faulted on any table frame above 1 GiB
  (M1875), and the laptop's Intel I218 LOM needed an actual driver (M1876). QEMU
  remains the day-to-day target, and hardware coverage is narrow — one machine,
  and some laptops' xHCI input is not wired up yet. See
  [BAREMETAL.md](BAREMETAL.md).
- **The browser now runs mostly in ring 3.** The default **Browser** (`webview`)
  runs its whole HTML/CSS/JS/image-decode engine as a pledge-sandboxed ring-3
  program, so a parser bug there can no longer compromise the kernel. This was the
  project's main architectural weakness (a parser bug was a kernel bug) and is now
  largely resolved — also helped by the W^X / guard-page hardening above and
  extensive parser fuzzing. As of **M1863 the browser's HTTPS fetch also runs in
  ring 3**: `webview` links the same from-scratch TLS 1.3 + crypto + X.509 stack
  the standalone `httpget` uses, so its **entire TLS/crypto/certificate-validation
  path is out of the kernel** (plain `http://` still uses the kernel `sys_http`,
  which carries no crypto/X.509 — verified end-to-end: the ring-3 browser fetches
  `https://example.com` over a full in-process TLS 1.3 handshake). One honest caveat
  remains: the old in-kernel renderer is kept as an opt-in **"Browser (kernel)"**
  fallback, so that ring-0 parsing code still exists in the tree. The hardest parsers are also out
  of ring 0 as standalone programs: the **JavaScript engine** (`jsrun`), the
  **image decoders** (PNG/GIF/JPEG/SVG/BMP, `imgdec`), and the **TLS 1.3 client +
  crypto + X.509 validation** (`httpget`). See [WHATS-NEXT.md](WHATS-NEXT.md).
- **SMP is real, and used.** The kernel brings every core online at boot (local
  APIC + ACPI MADT + a real→long-mode AP trampoline), and the **general CFS
  scheduler genuinely runs ordinary tasks — the `pin_core=-1` kind that every
  kernel thread and every ring-3 process is — concurrently across all cores**:
  each AP takes its own local-APIC-timer tick and pulls runnable work from the
  shared ready ring, so a busy user app migrates onto an idle core (and
  `sched_setaffinity` can pin/evict it, enforced per-core). This is covered by
  an automated test — `make smpschedtest` spreads 8 compute tasks across 4 cores
  with an **exact** shared counter (no lost updates under real concurrency),
  alongside the existing `smpthreadtest` for the separate kernel-thread pool. At
  **idle** the APs correctly `hlt` (power-friendly — an idle core is halted, not
  spinning). The one piece with no steady-state driver is the short-lived
  **compute job pool** (`smp_parallel_for`), used at boot for parallel TLS
  chain-link verification and a self-test but not called afterwards.
- **Lines of code:** roughly **71k** of from-scratch kernel C and **~31k** of
  from-scratch userspace C. The bundled DOOM / Quake / emulators add **~133k**
  lines of vendored third-party code — most of the raw line count is theirs, not
  this project's. This project's own code is MIT-licensed (**[LICENSE](LICENSE)**);
  the vendored code keeps its own license unchanged — see **[NOTICE](NOTICE)**.

For the running change log see **[WHATS-NEXT.md](WHATS-NEXT.md)**; for an honest
difficulty breakdown of the long-term goals, **[GOALS.md](GOALS.md)**; for
booting on real hardware, **[BAREMETAL.md](BAREMETAL.md)**; for the test suites
(host ASan/UBSan parser fuzzers + in-guest QEMU boot/driver tests),
**[tests/README.md](tests/README.md)** (`make check`).

![The ring-3 Browser (webview) rendering its start page, including live HTTPS links, over real TLS](docs/osdev-browser-ring3.png)

<table>
<tr>
<td width="33%"><img src="docs/osdev-doom-themed.png" alt="DOOM running as a windowed ring-3 process"></td>
<td width="33%"><img src="docs/osdev-sysinfo-themed.png" alt="The System Info panel: live memory/task/network/disk stats"></td>
<td width="33%"><img src="docs/osdev-terminal-themed.png" alt="The shell: neofetch + ps, from-scratch"></td>
</tr>
<tr>
<td align="center"><sub>id Software's DOOM, windowed</sub></td>
<td align="center"><sub>live system stats</sub></td>
<td align="center"><sub>the scriptable shell</sub></td>
</tr>
</table>

**Productivity & developer tools** — all from scratch, running in ring 3:

<table>
<tr>
<td width="33%"><img src="docs/osdev-app-sheet.png" alt="The spreadsheet: live formulas, an IF-driven Pass? column, and STDEV"></td>
<td width="33%"><img src="docs/osdev-app-plot.png" alt="The graphing calculator plotting y = 5*sin(x)"></td>
<td width="33%"><img src="docs/osdev-app-paint.png" alt="The paint program: line, rectangle, filled box, ellipse and flood-fill"></td>
</tr>
<tr>
<td align="center"><sub>spreadsheet — formulas + charts</sub></td>
<td align="center"><sub>graphing calculator</sub></td>
<td align="center"><sub>paint — shapes + fill</sub></td>
</tr>
<tr>
<td width="33%"><img src="docs/osdev-app-gjson.png" alt="The JSON viewer: validate + pretty-print with syntax colouring"></td>
<td width="33%"><img src="docs/osdev-app-gregex.png" alt="The regex tester: matches highlighted, over the JS engine's own regex"></td>
<td width="33%"><img src="docs/osdev-app-garc.png" alt="The archive browser: list a zip/tar's contents without extracting"></td>
</tr>
<tr>
<td align="center"><sub>JSON pretty-printer</sub></td>
<td align="center"><sub>regex tester</sub></td>
<td align="center"><sub>archive browser</sub></td>
</tr>
</table>

Where to go next: **[WHATS-NEXT.md](WHATS-NEXT.md)**. The honest take on the
long-term goals (browser, music, Claude Code): **[GOALS.md](GOALS.md)**.

## Quick start

```sh
make          # build the kernel + userspace shell + FAT32 disk image
make run      # boot in a QEMU window (VGA output)
make test     # boot headless, capture serial output, exit after 5s
make clean
```

Don't want to build from source? Grab the pre-built kernel + disk image from
the [latest release](https://github.com/kitslayer/OS-DEV/releases/latest) and
boot it straight in QEMU — see the bundled `RUN_ME.md` for the one-liner.

Drive the shell over the serial line (so it works headlessly):

```sh
(sleep 1; printf 'help\nls\ncat hello.txt\nexit\n') | \
  qemu-system-x86_64 -no-reboot -kernel build/kernel32.elf \
    -drive file=build/fat.img,format=raw,if=ide -display none -serial stdio
```

## How it boots

1. QEMU's built-in Multiboot loader (`-kernel`) finds the multiboot header in
   `boot/boot.asm`, loads the kernel at physical 1 MiB, and jumps to `_start`
   in **32-bit protected mode**.
2. `_start` (32-bit) verifies multiboot + long-mode support, builds page tables
   that identity-map the low 1 GiB, enables PAE + long mode + paging, loads a
   64-bit GDT, and far-jumps into 64-bit code.
3. The 64-bit entry sets up segments + stack and calls `kmain()` (C).

**The 32-bit-container trick:** QEMU's multiboot loader refuses an ELF64
("give a 32bit one"). So we link as a real **ELF64** (`build/kernel.elf`, keep
for `gdb`), then `objcopy` it into a **32-bit ELF container**
(`build/kernel32.elf`) the loader accepts — the 64-bit code inside is untouched.
No GRUB, no ISO, no `xorriso`.

**Booting through a real bootloader instead:** the steps above are QEMU's
`-kernel` shortcut. `boot/boot.asm` also carries a real Multiboot2 header, so
`make efi` (UEFI, no extra tools) or `make iso` (BIOS, needs `xorriso`) build an
image that a **real GRUB** loads through the standard Multiboot2 handoff —
verified end-to-end under QEMU + OVMF. See [BAREMETAL.md](BAREMETAL.md) for the
details and exactly what still needs a physical machine to confirm.

## Layout

```
boot/boot.asm        multiboot header + 32->64-bit long-mode trampoline
kernel/              the kernel
  kmain.c            entry; wires every subsystem together
  console.c vga.c serial.c     text output + kprintf
  gdt.c idt.c interrupts.c pic.c   descriptor tables + interrupts
  timer.c keyboard.c           PIT + PS/2 (and the input queue)
  pmm.c vmm.c kheap.c          physical / virtual memory + heap
  task.c                       kernel threads + scheduler
  elf.c syscall.c              ELF loader + syscall dispatch
  ata.c fat32.c vfs.c          disk driver + filesystem + VFS
  asm/                         context switch, ISR stubs, usermode, user blob
  include/                     kernel headers
user/                ring-3 programs: ulib (libc), the shell, ~90 apps/games,
                     and the pledge-sandboxed parsers (webview/jsrun/imgdec/httpget)
tools/mkfatfs.c      host-side FAT32 image builder
linker.ld            kernel ELF layout (loaded at 1 MiB)
Makefile             build / run / test / iso / efi
docs/                standalone write-ups for the foundational milestones (189 of them)
```

## Documentation

A standalone write-up for a foundational milestone at a time — read them in
order to learn how the whole thing works, from boot to a real HTTPS browser:

| # | Topic | Doc |
|---|-------|-----|
| 0 | Booting to 64-bit long mode        | [docs/00](docs/00-boot-and-long-mode.md) |
| 1 | Terminal driver + `kprintf`        | [docs/01](docs/01-terminal-and-kprintf.md) |
| 2 | Interrupts (GDT/TSS, IDT, PIC)     | [docs/02](docs/02-interrupts.md) |
| 3 | Timer + keyboard                   | [docs/03](docs/03-timer-and-keyboard.md) |
| 4 | Physical memory manager            | [docs/04](docs/04-physical-memory.md) |
| 5 | Virtual memory + higher-half       | [docs/05](docs/05-virtual-memory.md) |
| 6 | Kernel heap                        | [docs/06](docs/06-kernel-heap.md) |
| 7 | Multitasking + scheduler           | [docs/07](docs/07-multitasking.md) |
| 8 | Userspace, syscalls, ELF loader    | [docs/08](docs/08-userspace.md) |
| 9 | libc + shell                       | [docs/09](docs/09-libc-and-shell.md) |
| 10| VFS + FAT32 filesystem             | [docs/10](docs/10-vfs-and-fat32.md) |
| 11| Preemptive scheduling              | [docs/11](docs/11-preemptive-scheduling.md) |
| 13| NIC driver + ARP + ping            | [docs/13](docs/13-networking.md) |
| 14| Framebuffer graphics + font        | [docs/14](docs/14-framebuffer.md) |
| 17| Window manager / compositor        | [docs/17](docs/17-window-manager.md) |
| 21| Per-process address spaces         | [docs/21](docs/21-process-isolation.md) |
| 33| TCP + HTTP GET (fetch real web pages)  | [docs/33](docs/33-tcp-http.md) |
| 34| **Graphical web browser** (HTML render) | [docs/34](docs/34-browser.md) |
| 92| PNG image rendering (DEFLATE + PNG) | [docs/92](docs/92-png-images.md) |
| 112| **From-scratch baseline JPEG decoder** (integer IDCT, fuzzed) | [docs/112](docs/112-jpeg-decoder.md) |
| 119| X25519 (Curve25519 ECDH) — first step toward HTTPS/TLS | [docs/119](docs/119-x25519.md) |
| 124| Bignum + RSA PKCS#1 & PSS signature verify (vs Python + OpenSSL) | [docs/124](docs/124-bignum-rsa.md) |
| 127| **TLS 1.3 client — the browser fetches real HTTPS pages** | [docs/127](docs/127-tls-https.md) |
| 144| **From-scratch JavaScript interpreter** — lexer, parser, tree-walking evaluator | [docs/144](docs/144-js-interpreter.md) |
| 166| **JS `class` / `extends`** — inheritance, method-copy model | [docs/166](docs/166-class-syntax.md) |
| 178| **JS regular expressions** — from-scratch `RegExp`, ReDoS-safe | [docs/178](docs/178-regex.md) |
| 192| **Minimal DOM** — `getElementById(id).textContent`/`innerHTML` mutate the page | [docs/192](docs/192-dom.md) |
| 281| **`querySelector` / `querySelectorAll`** by CSS selector | [docs/281](docs/281-queryselector.md) |
| 304| **CSS `<style>` blocks** — the first real stylesheet support | [docs/304](docs/304-css.md) |
| 422| Untrusted-input security audit (images, HTML, net, fs, crypto) | [docs/422](docs/422-untrusted-input-security-audit.md) |
| 434| Browser HTML/CSS parser security audit | [docs/434](docs/434-browser-parser-security-audit.md) |
| 438| Security + test posture — the consolidated trust-boundary map | [docs/438](docs/438-security-and-test-posture.md) |

That's a tour of the foundational arc, not the full history: `docs/` holds
**189 standalone write-ups** in total — browse the directory for the rest
(individual JS/DOM/CSS features, driver bring-up, security reviews, …). Every
milestone, including the ~1000 shipped after this table's last dedicated doc
(the ring-3 browser migration, kernel-stack/user-stack hardening, RAID, SMP,
and everything else below), is logged chronologically, newest first, in
**[WHATS-NEXT.md](WHATS-NEXT.md)**.

## Roadmap

**Foundation — complete:**
- [x] 0. Boot to 64-bit long mode, print to screen + serial
- [x] 1. Terminal driver (scrolling VGA text + formatted `kprintf`)
- [x] 2. Interrupts: GDT/TSS, IDT, CPU exceptions, PIC remap
- [x] 3. Timer (PIT) + PS/2 keyboard input
- [x] 4. Physical memory manager (multiboot memory map, frame allocator)
- [x] 5. Virtual memory: 4-level paging, higher-half direct map (see docs/05)
- [x] 6. Kernel heap (`kmalloc`/`kfree`)
- [x] 7. Multitasking: kernel threads + round-robin scheduler
- [x] 8. Userspace: ring 3, syscalls, ELF program loader
- [x] 9. A libc + a basic shell
- [x] 10. VFS + FAT32 filesystem + ATA driver + shell `ls`/`cat`

**Hardware + extras:**
- [x] 11. Preemptive scheduling (timer-driven context switches)
- [x] 12. PCI bus enumeration
- [x] 13. e1000 NIC driver + ARP + ICMP ping
- [x] 14. Framebuffer graphics + 8×8 font

**Desktop environment:**
- [x] 15. Graphical console + real 8×16 font
- [x] 16. PS/2 mouse + cursor
- [x] 17. Window manager / compositor (drag, focus, z-order)
- [x] 18. Desktop apps: terminal, file browser, taskbar clock + button
- [x] 19. USB (UHCI) + usb-tablet absolute pointer (cursor tracks 1:1)
- [x] 20. Resizable windows + start menu + Clock/About apps
- [x] 21. Per-process address spaces (real memory isolation)
- [x] 22. Userspace apps as windows (the ring-3 shell, in a window)

**System polish & apps:**
- [x] 23. Sleep/wake (blocking) — the CPU idles instead of busy-spinning
- [x] 24. Visual polish: gradients, shadows, rounded windows, themed taskbar
- [x] 25. Real-time clock (RTC) — real time in the taskbar + `date`
- [x] 26. PC speaker sound + `beep` + a boot chime
- [x] 27. System commands: `mem`, `clear`, `reboot`
- [x] 28. FAT32 **write** — create/save files on disk
- [x] 29. Networking from the shell: `ping` + DNS `resolve`
- [x] 30. A userspace **text editor** (`edit`)
- [x] 31. File delete (`rm`) — full file toolkit: ls/cat/edit/write/rm
- [x] 32. Process spawning + multiple programs (`run`, a 2nd live "clock" app)
- [x] 33. **TCP + HTTP GET** — fetches real web pages over the internet (`get`)
- [x] 34. **Graphical web browser** — parses + renders live HTML in a window
- [x] 35. **Clickable links** — follow links + resolve relative/absolute URLs
- [x] 36. **Non-blocking page loads** — fetch on a worker task, desktop stays live
- [x] 37. **Richer rendering** — page title in the bar, list/definition layout, `<hr>`
- [x] 38. **Browser history / Back** — back stack, `<` button + Backspace
- [x] 39. **`browse <url>`** — open the browser from the shell
- [x] 40. **Concurrency hardening** — atomic WM↔worker hand-offs (review-driven)
- [x] 41. **Browser start page** — built-in bookmarks home, rendered locally
- [x] 42. **Save a page to disk** — browser → FAT32 → shell reads it back
- [x] 43. **FAT32 subdirectories** — `mkdir`/`cd`/`pwd` + path resolution
- [x] 44. **Calculator app** — a third interactive userspace program
- [x] 45. **Browser opens local files** — `file:…` reads the disk (offline reading)
- [x] 46. **FS write hardening** — overwrite no longer duplicates/leaks (review fix)
- [x] 47. **`cp` / `mv`** — file toolkit complete (ls cat edit write rm cp mv mkdir cd pwd)
- [x] 48. **`tree`** — recursive directory listing (first recursive FS op)
- [x] 49. **Taskbar window list** — a chip per window, click to focus
- [x] 50. **`ps`** — list running tasks (id / state / name) from the run queue
- [x] 51. **Bold & italic** — inline emphasis in the browser
- [x] 52. **Compositor scene-cache** — mouse moves no longer re-render the desktop
- [x] 53. **Arrow keys** — extended-scancode decoding (browser scroll, more to come)
- [x] 54. **Command history** — ↑/↓ recall previous commands (responsive typing)
- [x] 55. **Snake** — a real-time game (non-blocking input, prompt repaint)
- [x] 56. **`df`** + review fixes (history erase clamp, lost-wakeup)
- [x] 57. **Text editor** — full-screen editor with cursor, saves to FAT32
- [x] 58. **`find`** — recursive filesystem search
- [x] 59. **HTTP redirects** — the browser follows 3xx `Location:` hops
- [x] 60. **2048** — a second arrow-key game (six userspace apps now)
- [x] 61. **`hexdump`** — inspect a file's raw bytes
- [x] 62. **`wc`** + FAT chain cycle-guard (review fix — no hang on corrupt FAT)
- [x] 63. **`cal`** — month calendar from the RTC
- [x] 64. **`grep`** — search inside files (companion to `find`)
- [x] 65. **System Monitor** — a graphical app with live memory/task bars
- [x] 66. **SHA-256** — verified hash + `sha256` checksums (first step toward TLS)
- [x] 67. **Bookmarks** — customize the browser start page from a `SITES` file
- [x] 68. **AES-128 + `crypt`** — verified cipher, passphrase file encryption
- [x] 69. **`base64`** — encode files to text (rounds out crypto/encoding tools)

**Where next:** TLS/HTTPS with enforced certificate validation, the graphical
web browser, a from-scratch JavaScript engine + interactive DOM, and live web
search all shipped long ago. Since then the work has pushed hard on the
**POSIX / systems axis**: an in-guest C compiler (`cc`), pipes + a per-process
file-descriptor table with the full event-loop toolkit (`poll(2)`,
`splice`/`tee`, `eventfd`, `timerfd`, `memfd`+file-seals), real async signals +
`sigreturn` + masking (`sigprocmask`/`sigpending`), `mmap`/demand-paging/COW-
`fork`/`waitpid`, a `/proc` + `/dev` control-file fabric (incl.
`/proc/<pid>/{maps,smaps,limits,auxv}` and a writable `/dev/kmsg`), ext2/ext4
(extents) read **and** write (incl. hard links + `rename`), swap + a buffer
cache, seccomp-BPF + pledge/unveil sandboxing, resource limits (`prlimit`),
kernel threads + futexes + TLS, a full debug/trace suite (`ptrace`, a **GDB
remote-serial stub**, eBPF syscall tracepoints, a KASAN-lite heap sanitizer),
and **SMP: the kernel brings every CPU core online at boot** (local APIC +
ACPI MADT + a real→long-mode AP trampoline) **and actually schedules across
them** — the general CFS scheduler migrates ordinary tasks (every kernel thread
and ring-3 process) onto any core via each AP's own local-APIC-timer tick, with
`sched_setaffinity` enforced per-core (`make smpschedtest` proves 8 tasks spread
across 4 cores with an exact shared counter). Idle APs `hlt` (power-friendly);
the only thing with no steady-state caller is the boot-time compute job pool.

More recently the work turned to **dismantling the kernel's biggest attack
surface: untrusted-input parsing.** The JS engine, the image decoders
(PNG/GIF/JPEG/SVG/BMP), the TLS 1.3 + X.509 stack, and finally the browser's
own HTML/CSS/JS engine were each pulled out into a ring-3 program (`jsrun` /
`imgdec` / `httpget` / `webview`) and locked down with `pledge()` to only the
syscall classes each one needs. Alongside that, both the kernel **and** user
stacks gained unmapped guard pages backed by a stack-overflow canary, proven
with end-to-end tests that deliberately trigger a kernel-stack overflow, a
user-stack overflow, an NX violation, and a SMEP violation and assert each one
faults — protections that are tested, not just claimed. (See "Honest caveats"
above for exactly what's still ring-0.)

### The current frontier: self-hosting (M1933-)

The active campaign is the long-term goal in `GOALS.md` taken seriously:
**develop OS-DEV inside OS-DEV.** The end state is an in-guest toolchain running
under a **Linux ABI compatibility layer**, so that unmodified static Linux
binaries — busybox, a real GCC, eventually Node — run here.

**To be unambiguous about what this does and does not change:** the OS is, and
stays, overwhelmingly **self-made**. The kernel, every driver, the TLS 1.3 stack
and all its crypto, the JavaScript engine, the browser, the window manager and
~31k lines of userspace apps are written from scratch and none of that is
affected. The compatibility layer is a **bolt-on whose entire purpose is to run
*other people's* binaries** — which is what every real operating system does,
and precisely what an ABI is for. Borrowing a C compiler is not the same as
borrowing an operating system; writing a from-scratch GCC and a from-scratch
Node is not a credible path, and pretending otherwise would just mean the goal
never happens.

Landed so far, all on the from-scratch ext2 driver:
- **M1933** — an ext2 directory can grow past its first block. It was capped at
  **49 entries**; now inode-limited (600 in one directory, `e2fsck`-clean).
- **M1934** — streaming writes. A file no longer has to fit in memory to be
  written; reaches double-indirect (4 GiB at a 4 KiB block), and an
  extent-mapped file is rebuilt as indirect in place so appends work.
- **M1935** — `pwrite` wired through the VFS, plus a 512 MiB ext2 volume. A
  4 MiB file written from inside the OS in 64 KiB chunks, then verified from
  outside it: `e2fsck` clean, and all 4 MiB byte-compared.
- **M1936** — the caps a real userland needs: 8 → 32 processes, 24 → 128 fds,
  16 → 64 VMAs. `fd_set` was a single 64-bit word, so any fd ≥ 64 was
  undefined behaviour waiting to happen.
- **M1937** — paths **fail closed** instead of truncating. A truncated path
  names a *different file*, and that was measurably happening: `openat()` on a
  105-char path used to succeed and then read the wrong file.

- **M1938** — the **`syscall` instruction now works and speaks Linux**: a second,
  independent entry path on an instruction that was previously unused here, so
  it cannot collide with the native `int 0x80` ABI. Proven from ring 3.

- **M1939** — **a real Linux binary runs inside OS-DEV.** A host-compiled
  `-static-pie` ELF, loaded off the ext2 volume, printing through Linux
  `write(2)` and exiting with the right status. Asserted headlessly by
  `make linuxabitest`.

- **M1940** — a real **SysV initial stack** (argc/argv/envp/auxv, 16-byte
  aligned, with `AT_RANDOM`), which a libc reads before `main`. Hit an honest
  wall: a *glibc* static-PIE binary carries ifunc (`IRELATIVE`) relocations it
  resolves itself before its first syscall, and dies there. **musl** is the
  right first libc target.

- **M1941** — a pre-existing deadlock: fault handlers run with interrupts off
  and spun *unbounded* on the console lock, so a same-core holder wedged the
  machine **and swallowed the fault report**. Bounded now; a boot that died at
  78 log lines completes at 306.
- **M1942** — **AVX, via XSAVE.** Real Linux binaries contain AVX (glibc's
  `_dl_aux_init` opens with `vpxor`), which needs `CR4.OSXSAVE` + `XCR0` *and*
  an XSAVE-based context switch, since FXSAVE does not preserve YMM. glibc now
  parses the auxv and reaches its first syscall, `brk`.

- **M1943** — a **double fault in the new syscall entry stub**, caught by a
  flaky test: `swapgs` is only self-restoring if every entry is paired with an
  exit, and `exit_group` never returns. Deterministic now.
- **M1944** — **a real glibc binary runs, prints and exits.** It reports the
  `argc`/`argv[0]` our SysV stack built, proving the frame, alignment and auxv
  are right.
- **M1945** — ring 3 was starting with the **kernel's leftover registers**: an
  ABI violation (`%rdx` must be zero — glibc registers it as an `atexit`
  handler and *calls* it) and an **information leak** that affected OS-DEV's
  own apps too. glibc now returns from `main` normally.

- **M1946/M1947** — **a glibc program does real file I/O and lists a
  directory** on ext2: `openat`/`read`/`lseek`/`newfstatat`/`fstat`/
  `getdents64`. It writes and re-reads a 200-line file, stats it, lists the
  directory, and exits 0. `opendir` needed three chained fixes, each of which
  had been failing *silently* with zero entries.

- **M1948-M1950** — **`fork`/`execve`/`wait4`/`pipe`/`dup2`**, demonstrated by a
  busybox-shaped multi-call binary that re-execs *itself* to build
  `echo | wc` — the reader counts all 4 lines and `wait4` collects both
  statuses. Chasing it root-caused a long-standing intermittent **Double
  Fault** (`swapgs` is unsound if a syscall blocks, because nothing saves
  `GS_BASE` across a context switch — it is gone now), two pre-existing `fork`
  TLS bugs, and a concurrency bug in the new `execve` (static argv buffers
  shared across processes).

Still ahead: a toolchain. busybox itself is not obtainable on this host, so the
ABI surface is driven by purpose-built glibc programs exercising the same
syscalls. The honest scale is months, and the memory
subsystem needs real work before Node (today's `mmap` has no `addr`, `prot` or
`flags` argument at all, so V8's address-space reservation cannot even be
expressed).

Also still open: a **unified inode/page cache** (the block buffer cache is the
seed), and extending the crash-consistency journal to the rest of the
filesystem write path. (Several items once listed here are done:
**cross-core scheduling** works and is now tested — M1862; the **browser's HTTPS
fetch now runs in ring 3** — M1863, so no TLS/crypto/X.509 runs in the kernel for
the default browser; and a from-scratch **write-ahead journal** now makes a real
FAT32 file create **crash-atomic** — M1864-M1866, ext3-style ordered-mode metadata
journaling with replay-on-mount, proven under host fault-injection *and* in-guest
on real hardware. Extending the journal to `rm`/`mkdir`/`rename`/overwrite is
mechanical follow-on. The one remaining SMP loose end is that the boot-time
compute job pool has no steady-state caller — a narrow cosmetic gap.)
