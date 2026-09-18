<div align="center">

# OS-DEV

**A from-scratch x86_64 operating system** — kernel, TLS 1.3, a JavaScript
engine, and a sandboxed web browser — written in C and a little assembly.
Developed under QEMU; boots on real hardware through GRUB.

[![Milestones](https://img.shields.io/badge/milestones-2223-blue)](WHATS-NEXT.md)
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

- **M1952-M1953** — a real **`mmap`**: `MAP_FIXED` (an address the caller
  chooses) and **file-backed at an offset** — the two shapes a dynamic linker
  needs for every `PT_LOAD` of a shared object. Chasing them also found an ABI
  bug (reading an `int` argument as `long`, so `fd = -1` read as 4 billion) and
  a concurrency bug in `execve` (per-process now, not globals).

- **M1954** — **`PT_INTERP`: dynamically-linked Linux binaries run.** The kernel
  now reads a program's interpreter, maps `ld-linux-x86-64.so.2` alongside it and
  enters *that*, with `AT_BASE` describing the interpreter and `AT_PHDR`/`AT_ENTRY`
  still describing the executable. Linux processes get a **chroot-style root**
  (`/disk2` prefixed onto every absolute path) so `/lib64/...` resolves without
  re-rooting the whole OS. The unlock was `MAP_FIXED` learning to **replace**
  rather than refuse: `ld.so` reserves a library's whole span with one mapping
  and then `MAP_FIXED`s each segment *into its own reservation*, so "refuse on
  overlap" rejected the second segment of every library. VMA carving (split /
  trim / punch, with the file offset following the new start) also turned
  `munmap` into a real range operation — it used to ignore its `len`.

- **M1955** — **real GNU binutils assembles, links and runs a program, inside
  OS-DEV.** `as` and `ld` are unmodified host binaries with five shared
  libraries each; the demo assembles a `.s`, links the object, and then *runs
  the result*, which exits with its own status. Two bugs stood between: the VMA's
  backing-path buffer was **64 bytes** and binutils' `libbfd` lives 98 characters
  down `/usr/lib64/binutils/<triplet>/<version>/`, so every demand-fault on that
  mapping read a nonexistent path, got zeros, and handed `ld.so` a library whose
  entire dynamic section was `NULL`; and `fstat` reported **`st_ino = 1` for every
  file**, so `ld.so` — which decides "already loaded?" by comparing
  `(st_dev, st_ino)` — mapped `libbfd` and then skipped `libz`, `libzstd` and
  `libc` as duplicates of it. ext2 inodes are now reported for real. Neither
  failure named its cause: the first was a page fault at `CR2=0x8` inside
  `_dl_check_map_versions`, the second `undefined symbol: free, version
  GLIBC_2.2.5`.

- **M1956** — **`mmap` was never actually lazy.** A file-backed mapping with any
  protection other than read-write faulted its *whole range* in at `mmap` time,
  because `app_mprotect` validated with `vmm_user_ok` and `vmm_user_ok`
  **materialises** a lazily-resolvable page. A VMA now records its `prot` and the
  fault handler honours it. Four bugs fell out: a permission fault on a present
  page was an **infinite retry loop** (a hang with no diagnostic); recycled VMA
  slots let a `MAP_FIXED` read-write segment **inherit `prot=1`** from the
  read-only reservation it replaced; a partial-range `mprotect` would have
  restricted the whole mapping; and a process killed by a fault reported
  **success** to anything that waited on it (139 now).

- **M1957** — **PHASE 4 COMPLETE: OS-DEV compiled a C program with a real GCC,
  inside itself, and ran it.** `cc1` is a 42 MB dynamically-linked PIE and could
  not previously be *loaded* — the spawn path read whole images into the kernel
  heap with a 16 MB ceiling. Executables are now **demand-paged from the file**:
  the kernel reads 8 KiB of headers, maps each `PT_LOAD` as a file-backed VMA,
  and pages arrive as the compiler executes them. The demo compiles a
  freestanding `.c` with `cc1`, assembles it with `as`, links it with `ld` and
  runs the result, which exits with its own status.

- **M1958** — **GNU make builds a program inside OS-DEV.** It forks a child per
  recipe line, `execve`s a dynamically-linked binary in it, and `wait4`s — and
  all three were gaps. `execve` could not load a dynamically-linked image at all
  (the `PT_INTERP` work was spawn-only), `posix_spawn`'s
  `clone(CLONE_VM|CLONE_VFORK, stack)` was refused, and then `make` **hung in
  `wait4`** because `app_reap` is driven only by the desktop's window loop —
  which had not started yet. `cc1` → `as` → `ld` → `echo` now runs in dependency
  order and make exits 0.

- **M1959** — **real threads: glibc's own NPTL runs.** `pthread_create`, a mutex,
  a condition variable, `pthread_join` and per-thread TLS, across four threads
  sharing one address space. The thread machinery mostly existed (M1138/M1226);
  what was missing was the *entry convention* — Linux's `clone` **returns in the
  child** rather than starting it at `fn(arg)` — plus `futex`(202), `gettid`,
  `madvise`, and `exit(2)` ending one thread instead of the process. Real threads
  then exposed **two lost-wakeup races that predate them**: `task_wake` silently
  dropped a wake aimed at a task that had decided to block but not yet blocked,
  and a woken futex waiter cleared its slot *unconditionally* — erasing the
  registration of whichever thread had claimed that slot in the meantime, which
  then slept forever. It hung in three runs of four; it now passes four of four.
  This is the shared prerequisite for everything still ahead.

- **M1960** — **OS-DEV compiled its own kernel source, in-guest.** The real gcc
  *driver* (which forks and execs `cc1` and `as` itself) built `kernel/elf.c` —
  the actual ELF loader this kernel runs on — freestanding, with the exact
  `CFLAGS` the host Makefile uses, and `nm` read `elf_load` back out of the
  object. The blocker was a **silent truncation**: `execve` copied at most 16
  argv entries and the driver passes `cc1` about twenty-five, so
  **`-ffreestanding` was dropped**, which surfaced as `cc1` failing on an
  `#include_next` inside GCC's own `stdint.h`. Truncated vectors are reported
  now, not silently accepted. Underneath it, **relative paths** were resolved
  against the *kernel's* directory rather than the process's — a Linux process
  now starts inside its own root, relative paths resolve against its own cwd,
  and `fork` inherits `cwd_path` (it previously did not, so every forked child's
  `getcwd` said `/`).

- **M1961** — **`make` drives the in-guest toolchain over OS-DEV's own kernel
  source**, compiling file after file correctly (the assembler handles a 497 KB
  real input). Two serious bugs fell out. The ring-3 **address map overlapped
  itself** — the heap ran through `0x48000000`, where the dynamic linker was
  mapped, so any program whose heap passed 64 MiB paged over `ld.so`. And task
  reaping was a **use-after-free**: `task_exit` sets `TASK_DEAD` before its final
  `context_switch`, which still writes to its own `task_t`, so a reaper on
  another core could free a live kernel stack. **Not yet a complete kernel
  build:** `kernel/app.c`, the largest file, hangs in a userspace loop inside a
  shared library — measured (no syscalls, frozen fault counters, RIP sampled via
  the QEMU monitor), not guessed. Everything smaller builds.

- **M1962** — **PHASE 5 DONE: OS-DEV built its own kernel, inside itself, and
  that kernel boots.** GNU make drove the in-guest `gcc`/`as`/`ld` over all 136
  kernel sources, linked them with OS-DEV's own linker script, and produced an
  8.7 MB `kernel32.elf`; booted under QEMU it brings up ACPI and the HPET, puts
  4 of 4 CPUs online and reaches the desktop launch. The loop is closed. Five
  silent-wrong-answer bugs stood in the way, the worst being that **`brk` handed
  out frames without zeroing them** — an information leak, *and* corruption,
  because glibc's `calloc` skips its `memset` for memory fresh from the kernel,
  so GCC read a previous process's **instruction bytes** as hash-table pointers.
  The rest were caps that truncated in silence: `execve`'s argv at 16, the
  initial-stack builder's at 64 (so `ld` got 57 of its 146 objects), and
  directory listings at 64 entries (so `$(wildcard)` saw 62 of 136 sources).
  `make selfhosttest` proves it end to end — not part of `make check`, since
  compiling 136 real files under emulation takes fifteen minutes.

- **M1963** — **TLB shootdown.** `invlpg` only invalidates the local core, so
  once an address space could be live on several cores at once (M1959's
  threads), unmapping or write-protecting a page left other cores using stale
  translations — writing through a mapping that had just been revoked. A
  dedicated IPI now flushes them, for multi-task address spaces only, with a
  **bounded** wait (an unbounded one deadlocks against a core spinning on a lock
  with interrupts off). A boot-time self-test caught the first version waiting
  **15.9 seconds** for acks that were never coming; it now acks in 0 ms.

- **M1964** — **real Node.js runs JavaScript inside OS-DEV.** `node --version`
  prints `v26.3.0`; `node -e` prints `LXNODE: 2 linux x64` (V8 parsing,
  compiling and JIT-ing); and the `fs` module writes, re-reads, stats and lists
  files **through the from-scratch ext2 driver**. An unmodified 102 MB binary
  with 21 shared libraries — we don't port Node, we run it. The blocker was
  V8's pointer-compression cage: it reserves gigabytes of address space, and
  our mmap window was 1 GiB, so Node died with `Fatal process out of memory:
  SegmentedTable::InitializeTable`. The window moved **above 4 GiB and grew to
  256 GiB** — free, since reserving address space costs one VMA and only
  touched pages cost memory. Plus `epoll`/`poll`/`eventfd2`/`uname` and friends.

- **M1965** — **Node opened a socket, and something answered.** A Node `net`
  server and client, over a real AF_UNIX socket, inside OS-DEV: listen,
  connect, accept, `echo:ping` back, half-close, clean exit 0. `unixsock.c` has
  been a complete AF_UNIX implementation since M1169, but its endpoints were
  bare integers **outside the fd table** — they could not be read, written,
  closed or polled like anything else, which is precisely what a program
  expects of a socket. They are fd types now, and libuv's event loop drives
  them. Four bugs, each of which lied about itself: `getsockopt`'s **`optval`
  and `optlen` arguments were swapped**, so the length `4` was written into the
  value buffer and libuv read `SO_ERROR = 4` — reporting `connect EINTR` on a
  connection that had succeeded. `epoll_ctl` answered `EINVAL` where Linux
  answers **`EEXIST`**, and libuv `abort()`s on anything else — it now returns
  real errnos. `write` on a socket fd fell through to the pipe path and
  returned **`EBADF`** on a perfectly valid descriptor, because the byte path
  did not exist. And `shutdown(SHUT_WR)` was **accepted and ignored**, so
  `socket.end()` did nothing, the server never saw its client finish, and a
  completed exchange hung forever with no error anywhere — AF_UNIX has a real
  half-close now. Also: `/proc` and `/dev` were being rewritten into the disk
  root by the compat layer and then reported missing, so Node's probes of
  `/proc/meminfo` and `/dev/null` failed against files this kernel has
  generated since M1216 — they resolve to the kernel's own synthetic
  filesystems again, and are stat-able and readable through the VFS
  (a character device streams; it does not hit EOF at an offset).
  And the crash that came *after* the success: `app_mmap` found a free gap and
  then rounded the address up to 2 MiB, walking the mapping past the gap it had
  just verified and onto the next VMA — **two VMAs owning the same pages**, so
  the first `munmap` freed the frames out from under the other. Only mappings
  ≥ 2 MiB, only when a VMA sat right after the gap; V8 allocates many, so Node
  hit it about one run in three.

- **M1967** — **PHASE 6 DONE: Node reached the internet from inside OS-DEV.**
  `node -e "http.get('http://example.com/')"` printed `LXNODEHTTP: 200 559` — a
  DNS lookup and an HTTP request, from JavaScript, over sockets libuv polls, on
  a from-scratch kernel, TCP stack and NIC driver. The blocker: `tcp_read` pulls
  frames straight off the NIC, so nothing could answer "is there data?" without
  **consuming the answer**, and `poll()` reported `POLLNVAL` for every socket
  fd. Each socket now has a receive ring filled by a non-blocking pump.
  `net_udp_recv` had the same shape of bug with a worse consequence — it
  **dropped TCP segments belonging to live connections**, so a resolver running
  beside a fetch silently ate that fetch's data. Then: glibc's resolver sends
  both queries in one `sendmmsg` (`ENOSYS` → every hostname `EAI_AGAIN`);
  `/etc/resolv.conf` is now written at boot from the **DHCP lease**;
  `libnss_dns.so.2` is `dlopen`'d so `ldd` cannot see it and it was never
  staged; and `getsockname` hardcoded `AF_UNIX`, which aborted glibc outright
  once AF_INET existed. Plus a bug of mine from M1965: the `statx` handler had
  every field **eight bytes too far**, so Node read `stx_ino` as the file size.

- **M1968-M1969** — **PHASE 7 BEGINS: HTTPS from Node, and the kernel moved to
  the higher half.** `https.get` printed `LXNODETLS: 200 559` — Node's bundled
  OpenSSL doing a TLS 1.3 handshake over this project's own TCP stack (the only
  thing missing was a CA bundle on disk). Then Phase 7 hit the wall the plan
  predicted: Claude Code is a single **214 MB non-PIE `ET_EXEC`** linked at
  `0x200000`, and the low 1 GiB was identity-mapped as *supervisor* pages shared
  into every address space — with the kernel's own code inside exactly that
  range. The kernel is now linked at `0xFFFFFFFF80100000` (still loaded at
  physical 1 MiB). Boots with zero faults through SMP, the I/O APIC, W^X,
  preemption and ring-3 isolation; full suite green. Freeing the low 1 GiB for
  user space is the next step.

- **M1970** — **the low 1 GiB now belongs to the process, and a non-PIE Linux
  binary runs.** `LXNOPIE: ET_EXEC ran below 1 GiB — main=402800, 2048 KiB of
  .data verified`. With the kernel out of the way (M1968), address spaces stop
  inheriting the boot identity map, so a binary linked at a fixed low address
  loads where it was linked. The cost was real: every DMA driver had been using
  a PMM frame's **physical address directly as a pointer**, which only worked
  because the two were the same number. The first user program to send a DNS
  query panicked the kernel in `memcpy ← arp_resolve ← net_udp_send ←
  app_sendto`, writing an ARP frame into a buffer that existed only in the
  kernel's own address space. Fifteen drivers moved their CPU-side access to
  the HHDM; the devices still get physical addresses. Also: `ET_EXEC` images
  now get the right auxv (`AT_PHDR` resolved through the `PT_LOAD` that
  contains the headers, as Linux does), `/proc/self/exe`, `open`/`sigaltstack`/
  `close_range`, nested `/proc/sys` and `/sys` nodes, and a **syscall ring +
  user backtrace** dumped when a process aborts. And the PMM was reporting the
  address *span* as RAM — 5120 MiB on a 4 GiB machine, a number `sysinfo`
  passed straight to every Linux program.

- **M1975** — **PHASE 7: CLAUDE CODE RUNS INSIDE OS-DEV.** `2.1.270 (Claude
  Code)`, exit 0 — a 214 MB **non-PIE `ET_EXEC`** image, loaded at its
  link-time address in the first gigabyte, printing a string produced by its
  own JavaScript. It is built with **Bun**, so the engine inside it is
  **JavaScriptCore**, not V8. The last blocker was our `/proc/self/maps`: the
  stack line printed a bare address with **no `start-end` range**, so glibc's
  `pthread_getattr_np` could never find the entry containing
  `__libc_stack_end` — and JSC asks the system for its stack bounds before it
  will run a line of code, then aborts *silently* when the answer is an error.
  Also: the user stack went 512 KiB → **16 MiB** demand-paged (Claude Code's
  `PT_GNU_STACK` asks for 12.2 MiB; Linux's default is 8), and `RLIMIT_STACK`
  now reports what we actually give instead of "unlimited".

- **M1977** — **PHASE 8 BEGINS: the `wl_shm` foundation.** `LXSCM: memfd +
  SCM_RIGHTS + MAP_SHARED — fd 5 passed as 6, 64 KiB shared both ways`. A
  Wayland client hands the compositor its pixels by putting them in a memfd and
  passing the **descriptor** over the socket they already share — no pixel is
  ever copied. Both halves existed natively (`app_memfd_create` M1212,
  `app_scm_send/recv` M1265) and neither had a Linux syscall number, so:
  `memfd_create`, `ftruncate`, and SCM_RIGHTS control messages through
  `sendmsg`/`recvmsg`. memfd storage became page-aligned and page-granular so it
  can actually be aliased into a process, and is frozen once mapped (growing
  would leave every existing mapping pointing at freed memory).

- **M1978** — **a real Wayland client talks to OS-DEV's own compositor.**
  `LXWL: connected, 4 globals, wl_compositor bound, 2 roundtrips OK` — from a
  client built against **libwayland-client, the same library Firefox and GTK
  use**, staged unmodified. Not a ported X server: the protocol is a Unix socket
  plus shared memory, both of which we now have, and a Wayland compositor *is* a
  window manager, so this stays additive to `kernel/desktop.c` rather than
  putting a foreign server in charge of windows. The blocker was ours and
  invisible from outside the process: libwayland reads with **`MSG_DONTWAIT`**
  on a *blocking* socket and loops until it gets `EAGAIN`, and we ignored the
  flag — so `wl_display_read_events` stopped dead with every byte already
  delivered. A raw client that used `read()` instead never hit it, which is what
  made the bytes look innocent.

- **M1979** — **the compositor reads a client's pixels.**
  `[wl] commit: 64x32 stride 256 format 0 -> first pixel 0xff3366cc`. The client
  writes into a memfd, passes the **descriptor** over the protocol socket with
  SCM_RIGHTS, and commits a surface; the compositor maps that same memory and
  reads the exact value back. Nothing is copied — the pool *is* the client's
  memory. `wl_compositor.create_surface`, `wl_shm.create_pool`,
  `wl_shm_pool.create_buffer`, `wl_surface.attach/damage/commit`, `wl_buffer.release`,
  and the `wl_shm.format` advertisement a client needs before it will build a
  buffer at all.

- **M1980** — **a Wayland client's surface is drawn in an OS-DEV window.** The
  desktop gained a window kind that blits the committed surface straight from
  the client's shared memory to the framebuffer — one copy in the entire path,
  and it is the one that puts pixels on screen. Asserted by **screenshot**: the
  client paints `0x3366CC`, a colour the theme never uses, and the check
  requires **exactly** its 64×32 pixels in one contiguous block — a scaled,
  clipped, torn or wrongly-strided blit all produce blue pixels and all produce
  the wrong shape.

- **M1981** — **`xdg_shell`: a Wayland client owns a real window.**
  `[wl] toplevel title: "OS-DEV Wayland demo"` — the client names its own
  window and the compositor's titlebar shows it. This is the protocol GTK and
  Firefox actually use, and the part that is easy to get silently wrong: a
  compositor must send the **initial `configure` unprompted**, because a
  toplevel is not mapped until the client acknowledges one — a client that
  never receives it waits forever having done nothing wrong.

- **M1982** — **Firefox runs inside OS-DEV.** `Mozilla Firefox 153.0.4`, exit 0
  — a 268 MB install whose `libxul.so` pulls an **83-library closure** (GTK,
  cairo, pango, fontconfig, dbus), staged unmodified and resolved by the real
  `ld.so`. It asked for exactly two things we lacked: `readahead(2)` (a hint
  Linux is free to ignore, so `ENOSYS` made it look like a failure) and
  `/proc/self/task/<tid>/stat`, the per-thread view. It now runs with **zero
  ENOSYS and zero missing files**. As with `claude --version`, this is the
  load-bearing first step and not the finish line: rendering a page into a
  window is the goal.

- **M1983** — **`wl_seat`: a Wayland window takes real input.** The desktop
  already owned the keyboard and the mouse; it now forwards them to the focused
  client as `wl_pointer` and `wl_keyboard` events, in **surface-relative**
  coordinates it computes from the window's own position. The test is driven by
  real QEMU input: it *screendumps to find where the surface landed*, aims the
  pointer at a known offset inside it, and asserts the client reports that same
  offset back — so the whole chain of arithmetic (screen → window → surface) is
  checked, not merely that an event arrived. Pointer focus follows the cursor
  (`enter` → `leave` → a second `enter`), keyboard focus follows the window, and
  a press of `a` arrives as **evdev keycode 30** — a keycode, not a character.

  Two failures worth recording, both of the same shape: **a well-formed-looking
  message that is the wrong length kills the connection, not the feature.**
  `wl_keyboard.keymap` carries its `fd` out-of-band in an `SCM_RIGHTS` control
  message, so the descriptor occupies *no space in the body* — writing a
  placeholder word for it made libwayland reject the message and drop the
  client, which presents as a keyboard that receives nothing at all.
  `wl_keyboard.modifiers` is **five** words (serial, depressed, latched, locked,
  **group**); sending four is not a missing field, it is a malformed message,
  and libwayland failed the whole connection with `EINVAL`. In both cases the
  visible symptom was "input does not work", several layers away from the cause.

- **M1984** — **our own XKB keymap, handed to a client over `SCM_RIGHTS`.**
  Wayland does not carry key labels; it carries a **file descriptor** to a
  keymap the client compiles with libxkbcommon, and a client that never gets one
  turns no keycode into a character — GTK, and therefore Firefox, does no text
  input without it. `kernel/include/xkbmap.h` is a hand-written US layout,
  deliberately **self-contained** (no `include "complete"`) so it compiles with
  `XKB_CONTEXT_NO_DEFAULT_INCLUDES` and needs no `/usr/share/X11/xkb` tree in the
  guest. The kernel builds a memfd from it and queues it for the client's next
  `recvmsg` — the **first descriptor this system passes in that direction**, the
  kernel giving a process a file rather than taking one. End to end in-guest:
  `[wl] sent xkb keymap (7138 bytes) as a memfd` →
  `LXWL-XKB: compiled the compositor's keymap` →
  `LXWL-XKB-KEY: evdev 30 -> keysym a, text "a"`.

  It also fixed a real bug it would otherwise have hit: the `SCM_RIGHTS` mailbox
  was **one slot per connection, shared by both directions**, so a process could
  receive back the descriptor it had just sent, and only one could ever be in
  flight. It is now a per-direction FIFO — order matters, because libwayland
  matches descriptors to messages by the order it pops them.

- **M1985** — **who owns the pages behind a `memfd` mapping.** A memfd's buffer
  is **kernel heap**, so mapping it aliases the heap into a process — and
  `munmap`, process exit and `close()` all treated those pages as the process's
  own. The first `munmap` handed live kernel memory back to the physical
  allocator; the next allocation anywhere in the kernel got memory the heap was
  still using. It surfaced as something else entirely: `ld.so` was read into a
  buffer whose frames had been re-handed out, so **one page of its text came up
  zero-filled**, and Firefox died on `add %al,(%rax)` at the first instruction
  of whatever function happened to live there. A mapping now reference-counts
  both the frames and the object, so `mmap()`-then-`close()` — the documented
  way to use a memfd, and what every toolkit does — is finally safe. The two
  `pmm_addref` calls in `app_ringbuf`/`app_shm_open` that were unguarded by
  `pmm_refcountable` are guarded too: above the refcount ceiling `pmm_addref`
  silently does nothing, so those mappings did not hold the reference they
  claimed to.

  **The diagnostic that cracked it is the lasting part.** A ring-3 fault now
  prints the **bytes at `rip`**, the last 16 Linux syscalls with their return
  values, and a user backtrace. `bytes at rip: 00 00 00 ...` said in one line
  what two hours of reasoning about relocation had not: the instruction was not
  ld.so's code, because ld.so's code was not there. (`00 00` is
  `add %al,(%rax)` — which is exactly the write the fault reported.)

- **M1986** — **the globals a real toolkit needs, and our own XKB data tree.**
  Firefox now gets GTK up and **connects to our compositor**. Getting there took
  three findings, none of which the protocol documents:

  - **GDK will not create a seat until `wl_data_device_manager` has been
    advertised**, and **order matters**: it postpones seat creation until both
    `wl_compositor` and the manager have arrived, so a compositor announcing
    `wl_seat` first creates its seat a round trip late. Anything asking for the
    keyboard before then — GTK asks almost immediately — finds none. Added
    `wl_output` (a real monitor, from the framebuffer's geometry),
    `wl_data_device_manager` and `wl_subcompositor`, and **reordered** so the
    manager precedes the seat.
  - **libxkbcommon resolves a keymap from RMLVO *names*** when a toolkit asks
    before the compositor has sent one, reading `/usr/share/X11/xkb` — and GDK
    treats failure as `g_error`, so it aborts. This host has no
    xkeyboard-config installed either, so `tools/xkb/` is **our own** rules and
    component files, split out of the same layout `kernel/include/xkbmap.h`
    carries, and checked by the same suite.
  - A GTK program **writes before it draws**: fonts, a compiled GSettings
    schema, a cursor theme, `/etc/machine-id`, an `XDG_CACHE_HOME` that exists.
    Each missing one fails in a way that does not name itself.

  Plus the syscalls it asked for and we lacked: `getresuid`/`getresgid` (which
  must *write* their three outputs), `getpeername`, `statfs`/`fstatfs`,
  `fallocate` (`EOPNOTSUPP`, not `ENOSYS` — every caller has a fallback for the
  first and none for the second) and `inotify_init1`.

  **Honest status: Firefox does not paint yet.** It now reaches GTK's display
  open and dies later, in a heavier phase, with what looks like kernel memory
  corruption under real thread and mmap load — the same shape as the
  long-standing intermittent `cc1` crash. That is the next thing to fix, and it
  is a kernel bug, not a missing feature.

- **M1987** — **naming the corruption, and a reproducer that takes a minute.**
  Firefox died with a page fault whose error code said *instruction fetch, from
  a user address, in supervisor mode* — SMEP catching the kernel jumping into
  userspace. `tools/lx/lxstress.c` does what a browser does, deliberately and
  densely, from six threads: mmap/touch/mprotect/munmap churn at sizes that
  straddle the page and hugepage boundaries, threads created and joined
  repeatedly, futex ping-pong, and signals delivered mid-syscall. It reproduces
  in about **sixty seconds** instead of ten minutes, and it names the phase.

  It found a real bug and named a bigger one.

  **Fixed:** an anonymous mapping never recorded its own protection. `VMA_NEW`
  zeroed the field and `app_mmap` never set it, so every ordinary `mmap` carried
  `prot == 0`, which *means* `PROT_NONE`. Two places papered over it —
  `/proc/self/maps` and `vma_pte_flags` both had a "zero means read-write"
  fallback — and the one place that read the field literally, the fault
  handler's permission branch, killed processes for writing to their own
  read-write memory. Both fallbacks are gone and the field is load-bearing;
  reverting the default now fails `LXMMAP-PROT` loudly.

  **Named, not yet fixed:** the VMA table is shared by every thread and raced.
  `app_vma_carve` fills the hole it makes by **moving the last entry down**, so
  a concurrent `munmap` relocates an unrelated mapping to an index a scan has
  already walked past — and the scan concludes the address is unmapped. The
  fault log now proves it: *"no VMA"* for an address that the table dump
  printed one line later as `vma[22] 108a00000-108c00000`. A per-process
  spinlock was tried and **removed**: several of these operations block while
  holding it (`app_msync` writes to disk from inside `app_vma_carve`), and a
  spinlock held across a blocking call, spun on by cores with interrupts off,
  hangs the machine instead. The fix is a blocking-call audit plus tombstoned
  removal so entries never move, and it is the next milestone.

  Diagnostics that made all of this visible, and stay: a ring-3 fault now prints
  the **bytes at `rip`**, the last 16 Linux syscalls with return values, a user
  backtrace, and — on an unmapped fault — **the whole VMA table and the thread
  id**. Plus a recursion guard, because a kernel-stack overflow presents as the
  kernel executing its own stack, which looks exactly like random corruption.

- **M1988** — **`linux <path>` — you can now run a Linux binary by typing it.**
  Until now the compatibility layer could only run what a *kernel boot flag*
  told it to, which makes it a demo rather than a property of the system. A new
  syscall and a shell command close that:

  ```
  osdev:/$ linux /usr/bin/claude --version
  linux: started /usr/bin/claude as pid 101
  osdev:/$ 2.1.270 (Claude Code)
  ```

  That last line is Claude Code's own JavaScript, printed into an OS-DEV shell
  window, from a command someone typed. Getting it *into the window* was the
  other half: a Linux process writes to fd 1, which went to the kernel console
  — and the desktop covers the console, so the first real use of this rendered
  five hundred lines of `claude --help` somewhere nobody could see and looked,
  from the shell, like nothing had happened. A Linux child launched from a shell
  now writes into **that shell's window**.

  **The desktop got a legibility pass, which it badly needed.** The wallpaper
  was drawn at *full theme intensity* — the same `THEME_MAGENTA` and
  `THEME_CYAN` the titlebars and accents use — so the sun and grid were exactly
  as loud as the windows in front of them and nothing read as being nearer than
  anything else. The identity is unchanged; the background now sits at 20–44% so
  the foreground can be heard over it. And the boot layout was three fixed
  rectangles sized for a smaller screen: on 1280×960 they landed in the top-left
  third, overlapping, with Files clipped by the shell while 60% of the desktop
  sat empty. Placement is derived from the actual framebuffer now, and app
  windows cascade in the space the boot column leaves instead of on top of it.

- **M1989** — **the VMA table is thread-safe now.** `lxstress` went from **0/4
  to 5/6** clean runs. Three distinct races, each found by making the previous
  fix expose the next:

  1. **Removal MOVED entries.** `app_vma_carve` filled the hole it made with the
     last entry, so a concurrent `munmap` relocated a live mapping to an index a
     scan had already walked past. Entries are **tombstoned** now and never
     move; a racing scan sees the mapping or nothing, never a *different* one.
  2. **Two threads could reserve the same address.** Searching for a free gap
     and recording the mapping were separate unsynchronised acts, so both
     threads found the same gap and both recorded a mapping there — in
     *different slots*, so the table looked perfectly consistent and the overlap
     audit stayed clean. Then one `munmap`'d and took the other's memory.
     `vma_reserve` now does both under one lock.
  3. **Splits claimed slots outside that lock**, so a split and an `mmap` could
     take the same index and one mapping ceased to exist.

  The lock is safe where the M1987 attempt was not: it covers only table work —
  no I/O, no user memory — so nothing inside it can block or fault.

  Also: `app_join` freed a thread's task as soon as it was `TASK_DEAD`, but a
  task sets that flag and only *then* performs its final context switch. glibc
  unmaps a joined thread's stack the moment `join` returns, so the thread
  faulted on memory that no longer belonged to anyone. It waits for `off_cpu`
  now, exactly as the reaper has since M1961.

- **M1990** — **a futex waiter could resurrect a dead thread.** `lxstress` is
  now **7/8**. A waiter records `task_self()` in the futex table and
  `FUTEX_WAKE` later calls `task_wake()` on that stored pointer — and *nothing
  cleared the slot when the task died*. A thread that exited while parked on a
  futex left a dangling pointer, and a later wake on the same key put a **freed
  task on the run queue**; the next schedule restored a context whose saved
  `rip` was whatever the reused memory happened to hold. The futex key is a
  **physical** address, which makes it worse rather than better: once the dead
  thread's pages are recycled, an unrelated process can hash to the same key and
  fire the stale entry without ever having touched that futex. Every path a task
  can end on — thread exit, process exit, join, the reaper — now drops its
  slots, and the wake loop refuses to queue a `TASK_DEAD` task.

- **M1991** — **two cores could run the same task's stack.** The scheduler's own
  `switch_to_next` carries a CRITICAL note: never make a still-executing task
  pickable, because that "is exactly what let two cores end up running the same
  task's stack". The timer's sleeper scan was doing precisely that. A task
  blocking *with a deadline* sets `TASK_BLOCKED`, releases the run-queue lock,
  and only then calls `switch_to_next` — so for a window it is BLOCKED and still
  running on its own stack, and `task_wake_sleepers` would see `wake_at <= now`
  and mark it `READY` for another core to pick. `core_prev` did not cover it:
  that is deliberately zeroed when the outgoing task *blocked* rather than being
  preempted, because `finish_switch` has nothing to complete for it. A new
  `core_leaving` tracks the outgoing task whatever its state, cleared by whoever
  runs next on that core — which is proof the stack has been left. **Eight
  stress runs, zero kernel panics**, where this used to halt the machine.

  Also: the fault-path diagnostics were re-entering the fault handler.
  `vmm_user_ok` *materialises* a lazily-mappable page — right for a syscall
  argument, exactly wrong when walking a half-mapped user stack from inside
  `app_fault_handle`. They use `vmm_translate` now, which answers the same
  question and changes nothing.

- **M1992** — **every syscall Claude Code makes is now implemented.** Driving it
  past `--version` turned into the mechanical loop the plan describes: run it,
  read the numbers, implement, repeat. It asked for and got `sched_yield` (39
  times in one startup — `ENOSYS` had turned a scheduler point into a
  busy-wait), `stat`/`lstat` (the old by-path spellings glibc still emits — a
  program that gets `ENOSYS` for `stat` cannot look at a file at all),
  `fchmod`/`fchmodat`, `fsync`/`fdatasync`, `rename`, and `epoll_pwait2` (which
  takes a `timespec *`, not a millisecond count — reading the pointer as an
  integer gives either an instant return or a nonsense deadline).

  Two real bugs behind them. **A trailing slash was not a character the path
  walker forgave**: `lx_xlate("/")` produced `/disk2/`, so the root — the path a
  program is most likely to hand us — resolved to nothing. And **stdin on a
  process nobody is typing at now returns EOF**: `claude -p` checks whether its
  prompt was piped in before using the one on the command line, and blocked on
  the console keyboard for a full fifteen-minute budget with zero page faults
  and no error. A process launched with `linux` from a shell still gets the
  keyboard.

  `--version` and `--help` are now **reliably 0**, where `--help` used to fail
  about half the time. `-p` gets as far as loading its config, resolving its
  managed settings, and **creating and deleting a session file under
  `~/.claude/sessions/`** — then fails, intermittently, in one of two ways. It
  makes **zero unimplemented syscalls**, so what remains is not a missing
  feature.

- **M1993** — **a TLB-shootdown deadlock, found by RIP-sampling.** Extending
  `lxstress` toward what a dynamic runtime actually does — **file-backed**
  mappings, hundreds held live at once, closed-then-kept as every toolkit does
  — hung the guest 4/4. Sampling the cores through the QEMU monitor showed all
  four pinned at the same two instructions across every sample, which is the
  signature of a spin loop: one core held the shootdown lock waiting for acks
  while the other three spun *for that lock* with interrupts off, so they never
  took the IPI and never acked. Every shootdown then ran to its 200 000-spin
  timeout and the machine stopped making progress.

  The design flaw was that the pending **count** is global, so a core spinning
  for the lock cannot tell whether it still owes a flush. It is a per-core
  obligation now, and a spinner discharges its own while it waits — which is
  the only arrangement that composes.

  And `app_mmap_file_at` got the same atomic reserve `app_mmap` did in M1989:
  finding a gap and recording the mapping were two acts there too, and that is
  the path a runtime uses for **every shared object it loads, from several
  threads at once**.

- **M1994** — **`lxstress` is 8/8 on the full file-backed, threaded suite.** Two
  more real bugs, and one instructive non-bug.

  **`task_wake` had the hole M1991 fixed in the timer's sleeper scan and no
  other.** A task blocking with a deadline sets `TASK_BLOCKED`, releases the
  run-queue lock, and only *then* switches — so for a window it is BLOCKED and
  still on its own stack. `task_wake` flipped it to `READY` there, and another
  core resumed a context from a stack still in use. `wake_pending` already
  existed for the neighbouring case and is the right answer.

  **`app_reap` freed the main task with no `off_cpu` check** — while the thread
  loop directly below it says "same rule as the main task above", describing a
  check that was not there.

  And the instructive one: `kstack_free`'s comment claimed "only the BSP runs
  tasks, so no shootdown", which stopped being true at M1531. Adding the
  shootdown it implied **made things worse** — `smpthreadtest` went from passing
  to a kernel stack overflow inside the IPI handler, because that path runs from
  `task_free` with the run-queue lock held. The conclusion was right for the
  wrong reason: kernel-stack **virtual** addresses are bump-allocated and never
  reused, so a stale translation names an address nothing will ever reference
  again. The comment now says that, because the next person to read it will
  otherwise "fix" it the same way I did.

- **M1995** — **`claude --help` went from 1-in-3 to 4-in-4**, and the reason is a
  bug that had nothing to do with Claude Code.

  **Two cores could fault on the same page and both map it.** Interrupts off
  stops preemption on *this* core and nothing else, so two threads of one
  process can be inside the fault handler for the same address at once: both see
  it absent, both allocate, both fill, and the second `vmm_map` **replaces the
  first** — discarding everything the first thread's faulting instruction went
  on to write. In a garbage-collected runtime that is objects turning into small
  integers, which is exactly how it presented: near-NULL dereferences at a
  *different* address every run, deep inside JavaScriptCore. The page is now
  published under the same short lock the check is made under; the loser frees
  its frame and re-executes.

  **And a lost wakeup, visible in the run-time dump.** M1994 correctly stopped
  `task_wake` from making a still-switching task runnable — but remembering the
  wake is not enough, because `wake_pending` is consumed by the *next*
  `task_block`, and a task that is already blocked will never make one. It slept
  forever:

  ```
  [runsync]   thread 27 state=2 wchan=... wake_pending=1
  ```

  A deferred wake is handed to the timer now: the sleeper scan already skips
  tasks still on a core, so it takes it up the moment the switch completes —
  one tick late and correct, rather than immediate and unsafe.

  `-p` now runs for the full fifteen-minute budget doing real work (two million
  disk reads) instead of erroring out, and `lxstress` is 7/8 with file-backed
  mappings across eight threads.

- **M1996** — **Firefox binds every global we advertise.** It reaches our
  compositor and takes `wl_compositor`, `wl_subcompositor`,
  `wl_data_device_manager`, `wl_shm`, `wl_output` and `wl_seat` — the whole set
  — then goes on to scan fonts and open its profile. Getting there needed
  `inotify_add_watch`/`inotify_rm_watch`: M1986 added `inotify_init1` and not
  these, which is the worst half to implement. A program gets a working inotify
  fd, cannot put a single watch on it, and — because a file watcher has nothing
  else to do — **retries forever**. Firefox sat in a three-syscall loop burning
  a core with its window never opening. The native watch mechanism has existed
  since M1266; only the ABI spelling was missing.

  Plus `/etc/hosts`, `/etc/host.conf` and the profile directories it writes
  before it will open a window.

  **The diagnostic that made this findable is the lasting part.** "Blocked, zero
  syscalls" is ambiguous between *working silently*, *stuck*, and *dead* — and
  with several threads the syscall ring cannot disambiguate either, because a
  thread blocked *inside* a call makes no new entries. There is now a heartbeat
  that prints the process state, the global syscall delta, and **where every
  thread is parked** by symbolising its wait channel. That turned "Firefox is
  silent" into: main and two workers in `app_futex`, one in `pipe_read`, and one
  `READY` and spinning — which is a lost wakeup or a deadlock, and is the next
  thing.

- **M1997** — **the futex layer is not the problem, and now there is evidence.**
  Firefox stalls with three threads in `app_futex`, so the obvious theory was a
  lost wakeup: the waiter key is a *physical* address, and Firefox forks, so a
  copy-on-write between the wait and the wake would rename the futex and lose it
  forever. I rewrote the key as `(process, virtual address)` the way Linux does
  for private futexes — and it **broke `lxstress` outright**, because the
  kernel's own `clear_child_tid` wake goes through the native entry point and
  the two spellings stopped matching. Reverted.

  The A/B that "cleared" the change first was also invalid: the edit that was
  supposed to disable it silently matched nothing, so both builds were the same
  binary. **Assert that a patch applied before trusting the experiment.**

  So the question got answered with measurement instead. `-append futextrace`
  logs every wait and wake with its address, and under Firefox: 237 wakes, 235
  of which woke nobody — all for addresses no thread was parked on, which is
  what uncontended `pthread_mutex_unlock` looks like — and **no wake was ever
  issued for the address the blocked thread is waiting on**. Nothing is lost.
  Those threads are waiting for work that never arrives, which moves the
  question up a layer.

  Also fixed: `/etc/hosts` was written before `/disk2/etc` existed.

Still ahead: Firefox actually painting. The honest scale is still months.

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

- **M1998** — **Claude Code runs, and says what it actually wants: "Not logged
  in · Please run /login".** Not `--version`, not `--help` — the real program,
  through config, settings, plugins, rules, git detection, MCP, session files
  and TLS certificates, to its own authentication check, exiting 1 like it
  would anywhere. Three separate bugs stood between it and that line, and none
  of them were in Claude Code.

  **A blocked thread survived `task_stop`, and woke up in a freed address
  space.** `app_reap`'s own comment says it stops live threads so "they must
  never run once we free the shared address space just below" — and `task_stop`
  checked for `TASK_READY` or `TASK_RUNNING`, which a thread parked in `poll()`,
  `nanosleep()` or a timed futex is neither. It was left BLOCKED with a
  deadline, the process was torn down, and the timer's sleeper scan made it
  `READY` again right on schedule. It then executed user code whose pages no
  longer existed:

      [fault] UNMAPPED 103085000 err=6: no VMA (... 0 vmas, tid 15)

  A fault in a process with **zero mappings**, at the same instruction in both
  runs, long after that process had exited — and, the first time, in a slot
  already reused by the *next* process, which is what killed it. Deterministic
  on one core (2/2), which is what made it findable: a sleeping thread wakes
  reliably. `exit_group` now also ends its siblings itself rather than leaving
  them running until the window manager gets round to reaping.

  **`readlink` answered one question out of three.** `/proc/self/exe` worked
  since M1970; `/proc/self/cwd` and `/proc/self/fd/<n>` returned ENOENT, and so
  did every real symlink on the filesystem — `vfs_readlink` has existed since
  M1233 and this entry point never called it. That is not a cosmetic gap:
  **Zig, and therefore Bun, and therefore Claude Code, does not call
  `realpath(3)`.** It opens a path `O_PATH` and reads back the descriptor's
  magic link. So Claude Code concluded its own working directory did not exist:

      Error: Can't access working directory /: Path "/" does not exist

  while stat, lstat, statx, access, `open(O_DIRECTORY)`, opendir, realpath and
  chdir on `/` all worked perfectly. A probe written in C would have passed.

  **`stat` on a mount root returned inode 0, and every `st_nlink` was 1.** Zero
  is not an inode, it is "this file has no identity" — anything keyed on
  `(dev, ino)` collides across every such directory. And a directory has at
  least two links; `find(1)` subtracts 2 from `st_nlink` and walks a negative
  number of subdirectories.

  `tools/lx/lxcwd.c` is the tool that found all of it, and it runs on every
  Linux-ABI boot now: it asks about the root directory **every way a runtime
  knows how**, both the glibc routes and the Zig ones, and builds a nested
  directory tree one component at a time. The glibc half passed from the start.
  That is the whole lesson — a probe that only asks the way *you* would ask
  tells you the gap is somewhere else.

  Also here: the compositor now refuses to send an event newer than the version
  a client bound (`wl_output.name` is version 4, `wl_pointer.frame` is 5,
  `wl_keyboard.repeat_info` is 4) and **says so when a request has no handler**,
  because silently ignoring one is indistinguishable from a hang; and `poll`/
  `epoll_wait` print the whole fd set, with each descriptor's type and
  readiness, when they sit for seconds with nothing ready. That is what
  identified Firefox's stall as an event loop waiting on an eventfd and an
  inotify watch rather than on the display.

- **M1999** — **four syscalls that were already implemented, and a struct that
  never carried the time.** Firefox and Claude Code were both asking for things
  this kernel has been able to do for hundreds of milestones, through entry
  points that did not exist.

  `symlink`(88), `link`(86), `utimensat`(280) and `pidfd_open`(434) all returned
  **ENOSYS** while `vfs_symlink` (M1146), `vfs_link` (M1207), `app_utimens`
  (M1230) and `app_pidfd_open` (M1222) sat behind the native entry point doing
  exactly that work. Firefox links a temporary into place to make a profile
  write atomic; Claude Code stamps every file it writes.

  And the one that matters most: **`struct stat` never carried a timestamp.**
  `LXST_O_ATIME`/`MTIME`/`CTIME` were not defined, so the fields kept the zeroes
  the buffer was cleared to and every file a Linux program stat'd reported 1
  January 1970. Underneath, `ext2_stat_path` *read the whole inode* and threw
  away `i_mtime`, `i_links_count` and `i_mode` — it had been writing the
  timestamps since M1175 and nothing could read one back. That is the
  self-hosting path: **`make` decides what to rebuild by comparing mtimes**, and
  with every file equally ancient it cannot order anything. `chmod` looked
  broken for the same reason — the mode was synthesised as 0755/0644 from
  "is it a directory".

  The other half of the milestone is **`tools/lx/lxcage.c`**, which reproduces
  the memory shape a JS engine actually needs: reserve twice the address space
  you want, round up to a large alignment, `munmap` the head and the tail, and
  then *use* what is left. That is JavaScriptCore's pointer cage, taken verbatim
  from this kernel's own trace of Bun doing it — an 8 GiB reservation trimmed
  down to 4 GiB at a 4 GiB boundary. Both trims return 0 whatever they actually
  removed, so the assertion is on writing and reading back 65 points across the
  kept region rather than on a return value. **Mutation-proven**: making a head
  trim drop the whole VMA turns the probe into a SIGSEGV — the same exit status
  Claude Code was giving. The path itself is clean; the probe is what makes that
  a fact rather than a belief.

  Also: `app_fault_current` now ends a dying process's **other threads**, which
  M1998 fixed only for `exit_group`. A process killed by SIGSEGV has to stop its
  siblings for exactly the reason a clean exit does — the same
  `[fault] UNMAPPED ... 4 vmas` came back through the second doorway.

- **M2000** — **Claude Code works, and a 401 came back from the server.** With a
  deliberately fake key in its environment it resolves `api.anthropic.com` over
  our DNS, opens a TCP connection on our own stack, completes a TLS handshake,
  sends a real POST and reads a real reply:

      Failed to authenticate. API Error: 401 API key is invalid.

  That 401 is the whole pipeline, proven from the outside. Without a key it
  prints its real answer instead — `Not logged in · Please run /login` — and
  exits 1, three times out of three on four cores. The developer's own
  credentials are never staged into a guest image, so that is exactly as far as
  this can honestly be taken.

  Two bugs stood between here and there, and the split that found them was
  **one core versus four**: single-core runs were correct and four-core runs
  died dereferencing NULL in a process with a perfectly healthy VMA table.

  **`madvise(MADV_DONTNEED)` freed the frame without telling the other cores.**
  Every other place that takes a mapping away calls `app_tlb_sync` — `munmap`
  does, `mprotect` does, M1963 added both for this exact reason — and `madvise`
  did not. It is the one a JavaScript engine calls constantly: JSC decommits its
  GC blocks 64 KiB at a time, and the syscall ring is full of it. So core A
  dropped the PTE and handed the frame back to the allocator while core B still
  held a cached translation; the frame was reissued immediately and B kept
  writing to it. **The order matters as much as the shootdown**: unmap a bounded
  chunk, drop the lock, make every core forget, and only *then* return the
  frames — anything else leaves a window where the frame belongs to someone
  else and is still reachable. `MADV_PAGEOUT` came out from under the VMA
  spinlock at the same time; it writes every page to **disk**, and holding a
  spinlock across that is the failure M1912 and M1993 both were.

  **`mmap`'s address hint was ignored, and the window was too small to honour
  it.** mimalloc — which is what Bun allocates with — picks an address in
  [2 TiB, 30 TiB) and passes it as a hint; Linux honours a free hint, so on
  Linux its arenas land where it chose. Every such request fell outside our 256
  GiB window, so everything was packed into the low few gigabytes on top of the
  region JavaScriptCore had reserved for its pointer cage. The window is now 32
  TiB — this is 4-level paging with a 48-bit user half, and the PML4 entry for
  30 TiB is index 61 whose PDPT is allocated on demand exactly like index 0.

  The instructive part is what I got wrong in between: I honoured the hint by
  calling `app_mmap_fixed`, and **`MAP_FIXED` REPLACES what is already mapped**
  — that is its defining behaviour and ld.so depends on it. A hint is advice.
  Routing one through `MAP_FIXED` hands a caller that merely had a preference
  the power to destroy a mapping it knows nothing about, and the owner dies
  later with a SIGSEGV that names nothing. `app_mmap_hint` refuses on any
  overlap and lets the caller fall back, which is what Linux does.

  **And the compositor was dropping messages.** `wl_send` handed a whole message
  to `unix_send`, which writes what fits in the peer's ring and reports how
  much — so a busy client got *half a message*, read a header claiming 44 bytes,
  got 20, and interpreted every byte after that at the wrong offset. Firefox
  says so out loud: `Wayland protocol error: message too short, object (2),
  message global(usu)`. Each client now has a real output queue: append the
  whole message, flush what the ring takes, resume at the exact byte. The stream
  stays byte-exact however slow the client is.

- **M2001** — **one 2 KiB buffer, shared by every task on every core, in the
  middle of `recvmsg`.** `static uint8_t sbuf[2048]` — and the same on the send
  side — with no lock, in a syscall two tasks can be executing at once. Two
  concurrent `recvmsg` calls overwrite each other's bytes, and for a **stream**
  socket those bytes are already gone from the ring, so a client gets someone
  else's data spliced into its own and its message framing is permanently
  offset. libwayland reports the wreckage as

      Wayland protocol error: message too short, object (2), message global(usu)

  — a `wl_registry.global` 24 bytes long, which is shorter than any global this
  compositor can emit. The syscall trace is what named it: `recvmsg(fd 10) = 24`
  where the message that should have been there is 28 bytes at minimum.
  Intermittent, because it needs two readers to overlap: Firefox has several
  threads and several processes on the socket, and the demo client has one,
  which is why the test suite never saw it. **3 of 4 Firefox runs errored
  before; 0 of 4 after.**

  I had also reasoned my way to two wrong answers first — that a partial
  `unix_send` was truncating messages (real, fixed in M2000, not this), and that
  the output queue's two writers were racing (also real, also fixed, also not
  this). Both were true bugs and neither was the one. The thing that settled it
  was **dumping the bytes we actually put on the wire** and finding every one of
  them correct, which moves the question to who else is writing to that buffer.

  **And the cursor theme, which was four candidate causes behind one warning.**
  `Failed to load cursor theme Adwaita` is GDK's report for the whole of
  libwayland-cursor's `memfd_create` → `F_ADD_SEALS` → `posix_fallocate` →
  `mmap` chain. Two links were broken: `fstat` had no memfd case, so a memfd
  fell into the catch-all that reports **S_IFIFO** — and glibc's
  `posix_fallocate` starts by `fstat`-ing and returns ESPIPE for a FIFO *without
  attempting anything*, so the pool was never sized and the mmap after it
  failed; and `F_ADD_SEALS`/`F_GET_SEALS` answered EBADF although
  `app_memfd_seal` has enforced seals since M1212. A memfd is a regular file on
  Linux — an unlinked tmpfs one — and saying so is both correct and what unblocks
  it. `tools/lx/lxanon.c` now walks that chain step by step, so the next time it
  breaks the log says which link.

  Firefox now binds every global, **creates a `wl_shm` pool from its own memfd**
  and receives its keymap without a single protocol error. It still does not
  paint. `libEGL.so.1` is staged too — it is `dlopen`'d, so `ldd` cannot see it
  and the closure staging had no way to know.

- **M2002** — **a file descriptor is a reference, and AF_UNIX never got the
  memo.** `app_fd_fork` takes a reference for every shared object a child
  inherits — pipes since M1187, memfds since M1212, epoll since M1220, inotify
  and TCP sockets since M1603 — and AF_UNIX endpoints were simply never added to
  that list. So a forked child's socket *was* the parent's socket, and the first
  `close()` in either process hung up both ends. Every child closes its
  inherited descriptors after `exec`, and `posix_spawn` does it explicitly.

  Firefox forks its content processes. Its display connection died moments after
  it had bound every global, created a `wl_shm` pool and taken its keymap — and
  from the compositor's side it looked like a clean, voluntary hangup by a
  client that had not gone anywhere:

      [wl] client disconnected (ep 3, recv -> 0, 0 byte(s) still queued to send)

  That line is itself part of the fix: "client disconnected" used to be printed
  for both a peer that hung up and a receive that errored, which are different
  problems with different causes. Saying *which*, and how much was still queued,
  is what pointed at the peer rather than at us. `app_fd_release` (process exit)
  had the same omission in the other direction — with references it would have
  leaked the connection forever instead of closing it early.

  Also: the compositor could ask `recv` for **zero bytes** whenever its input
  buffer held a partial message, and a zero-length read returns zero, which that
  loop read as EOF — dropping a healthy client precisely when it was busiest.

  Firefox now keeps its connection across its forks, binds a second registry,
  and a third client connects. It still creates no `wl_surface`.

- **M2003** — **`getpid()` returned the calling thread's id.** On Linux every
  thread of a process reports the same `getpid()` — that is the whole difference
  between it and `gettid()`, and it is load-bearing. This returned
  `task_current_id()`, so each thread got a different answer. A program that
  records its pid at startup and re-checks it later to find out whether it has
  been forked concludes that it **has** been, on every thread, and takes its
  post-fork teardown path. It was also inconsistent with its own neighbours:
  `fork()` hands the parent the child's **app** pid, `getppid()` returns an app
  pid, and `/proc/<pid>` is keyed on app pids — `getpid()` was the one answering
  in a different namespace. It went unnoticed for as long as nothing threaded
  got far enough to care.

  Firefox died 30 seconds into startup, every run, writing through a null
  pointer. With this fixed it does not crash at all.

  **And a diagnostic that was lying.** The syscall-history ring kept a single
  global "current entry" pointer, set on entry and patched with the result on
  exit. With two threads in the syscall path — the normal state of any threaded
  program — the second overwrites it and the first patches the *second's* slot
  with its own return value. The ring then reports one thread's answer against
  another thread's call, and I spent a while looking for a bug in the futex code
  because the dump showed `FUTEX_WAIT_BITSET` returning **ENOENT**, which it
  cannot. The slot is a local now, claimed atomically, and every entry records
  the **tid** that made the call — which is what finally made the faulting
  thread's own history readable among five busy ones. Same shared-mutable-global
  class as M2001's `recvmsg` buffer; it is worth grepping for.

  Supporting work, all of it earning its keep in the same hunt: a ring-3 fault
  now prints **which library `rip` is in and the offset inside it**
  (`libxul.so + 2caf323`), because the VMA table printed with it is capped and a
  browser's hundreds of mappings put the relevant one past the cap;
  `getpriority`/`setpriority` are implemented (note the encoding — the raw
  syscall returns `20 - nice`, so 0 would claim the *lowest* priority rather
  than "normal"); and `-append ffshot` runs Firefox **headless**, rendering to a
  PNG with no compositor at all — as a demo it is the whole browser, and as a
  diagnostic it proved the crash had nothing to do with the display by
  reproducing at the identical offset without one.

  Firefox no longer crashes. It now sits idle instead — zero page faults for
  thirteen minutes — so it is blocked on something rather than dying of
  something. That is a better problem.

- **M2004** — **you type `claude` and Claude Code takes over the terminal.** Its
  interface renders in the OS-DEV shell window — the theme picker, the
  `console.log("Hello, World!")` preview, colours, box layout — and
  `claude --version` prints `2.1.270 (Claude Code)` at the prompt like any other
  command. Eight things had to be true at once, and none of them were.

  **`claude` was not a command.** You had to type `linux /usr/bin/claude`, which
  is not a compatibility layer, it is a confession. An unrecognised command now
  gets looked up on a PATH and, if it is a Linux binary, run — **in the
  foreground**, with the shell waiting for it. The old spawn returned instantly,
  so the prompt came back while the program was still starting and an
  interactive program had a shell competing with it for the keyboard.

  **Its output went nowhere.** fd 0/1/2 were "the console" only by virtue of
  *not* being in the fd table, which works right up until a program dups one —
  and Claude Code writes to a dup. They are real descriptors now (a console
  alias bound to the window), so dup, dup2 and fork all do the right thing, and
  the child's output lands in the window that launched it. `out_to` is also
  armed *before* the spawn rather than after, because the old order was a race
  the child won whenever it printed early, and it left the child parentless so
  nothing could wait for it.

  **It got its own window.** A foreground job of a shell must not open a second,
  empty window somewhere the person who typed the command is not looking.

  **It could not tell it was on a terminal.** `ioctl` answered ENOTTY to
  everything. Two traps: modern glibc's `tcgetattr` uses **TCGETS2**
  (`_IOR('T',0x2A,44)`), not TCGETS — implementing only the old one answers a
  question nobody asks; and a descriptor is a terminal because of **what it
  refers to**, not its number, so a dup of stdio must answer yes too. Plus
  `TIOCGWINSZ` from the real grid (80x24), and `/dev/tty`, which did not exist.

  **`readv` did not exist** — unnoticed because glibc's stdio uses `read(2)`.
  Bun reads stdin with **`preadv2`**, so an interactive program could never
  receive a keystroke.

  **Our console was always "readable".** An event loop polled stdin, was told it
  was ready, called read — and the read blocked until somebody typed. The loop
  was then stuck inside a read it had been promised would not block, so nothing
  else could happen, *including drawing the interface that would tell you to
  type*. Claude Code sat on a blank window having written not one byte.

  **Escape sequences printed as literal text**, because `app_write_to` — the
  path a Linux child's output takes — called `grid_putc` directly and bypassed
  the terminal's own state machine. The terminal existed; one of its two entry
  points did not use it. Added `CSI G`/`d` (absolute column/row, the single most
  common thing a TUI emits) and 256-colour SGR, folded onto our palette.

  **And `TERM=osdev` is in no terminfo database**, so a TUI concludes it is
  driving something with no cursor addressing and renders nothing at all — which
  is the correct thing for it to do.

  Also here: a **stall watchdog** that reports any Linux process which stops
  making syscalls, and which had to be rate-based rather than
  change-based — a program parked on a long timer ticks over one syscall every
  fifteen seconds, which resets an equality test forever while it does precisely
  nothing.

  **What still does not work, and why:** the interactive login. Claude Code runs
  a connectivity preflight against `platform.claude.com` and exits if it does
  not like the answer. A packet capture shows our stack is not the problem — the
  TLS handshake completes in **0.3 s**, the server sends its response, and the
  application reads every byte of it (3870 then 807). It then abandons the
  connection and retries three times. What it dislikes is the answer, not the
  transport.

- **M2005** — **a write fault on a writable page, which we treated as fatal.**
  x86 does not require the TLB to be updated when a PTE is made **more**
  permissive, so a stale entry can fault on an access the page tables already
  allow. The only correct response is to invalidate that entry and retry —
  Linux has a function for exactly this case. We fell through to the bottom of
  the fault handler and killed the process.

  It is the long-standing *"`cc1` crashes intermittently"* that has blocked
  self-hosting since M1962, and the report that finally named it is one this
  milestone added: the fault handler now describes **the faulting page**, not
  just the address:

      [fault] err=0x7 (present+write+user) at 0x103163ff8
      [fault] the faulting page 100e5f000: pte=...007 (present=1 write=1 user=1 cow=0)
      [fault]   inside vma[16] 100e57000-100e60000 prot=3

  A write fault on a page that is present, writable and user-accessible is
  unreachable by any other route, and the existing report only dumped the VMA
  table for *not-present* faults — so the one fact that identifies the bug was
  the one fact never printed. The COW handler immediately above had just made
  that page writable; this core's TLB had not caught up.

  With it fixed, the in-guest build of OS-DEV's own kernel gets from `kheap.o`
  to `virtio_blk.o` — dozens of translation units further.

  Also: a ring-3 fault resolves `rip` to **its library and offset**
  (`libc.so.6 + 11548a` → `clone + 0x21a` against the host's symbol table), and
  `run-selfhost-test.sh` no longer deletes the failing boot's serial log —
  the same harness defect the Linux-ABI suite had, and an in-guest build takes
  fifteen minutes to reproduce.

  **Still failing, and now precisely located:** self-hosting dies in glibc's
  `posix_spawn`. Both faults land there — `clone + 0x21a` and the child helper
  — and it is the one place we *fake* `CLONE_VM|CLONE_VFORK`, serving it with a
  copy-on-write fork and an overridden child stack instead of a shared address
  space and a suspended parent. glibc is written against the real semantics.
  That is the next milestone, and it is the one the campaign plan named from the
  start.

- **M2006** — **a child could run before it had a TLS base, and that was the
  intermittent `cc1` crash.** `task_create_stack` publishes a task as
  `TASK_READY` and links it into the run queue — and then its callers go on to
  copy the things that make it a working thread:

      a->task = task_create_stack(...);
      task_copy_fpu(a->task, p->task);
      task_copy_tls(a->task, p->task);     <- too late if it already ran

  A child that wins that race runs glibc with **`%fs` = 0**, and the first
  function compiled with a stack protector reads its canary from `%fs:0x28` —
  which, with a zero base, is the linear address `0x28`:

      err=0x4 in a ring-3 task (CR2=0x0000000000000028)
      posix_spawnattr_setsigmask + 0x57d

  A fault at exactly 0x28 is not a null pointer with an offset, it is a canary
  read, and it says the thread has no TLS. Children and `pthread_create`
  threads are now born `TASK_STOPPED` and released once their context is
  complete.

  **And real vfork ordering.** `CLONE_VM|CLONE_VFORK` promises two things — a
  shared address space and a *suspended parent* — and they are separable. The
  suspension is the half that mattered: the capture showed the parent running
  on after `clone` and `munmap`ing the stack the child was still executing on
  (`clone + 0x21a`, faulting at `rsp-8`). A suspended parent cannot do that.

  I did implement the sharing too, and backed it out: the child exec'ing into a
  fresh space while the parent keeps the old one is correct on paper, and in
  practice produced corrupted control flow in freshly-exec'd processes
  (instruction fetches at `0x50fff001`, `0x237d8`, a write to gcc's read-only
  text) that I could not account for. A copy-on-write child loses only the
  ability to hand its exec errno back through shared memory, and glibc's
  fallback for that is exiting 127, which the parent already learns from
  `wait4`.

  The result is the goal this campaign was named for:

      ok: GNU make drove the in-guest gcc/as/ld over the whole kernel tree and exited 0
      ok: it produced a kernel (built in-guest: 8836744 bytes)
      ok: self-built kernel reached 'full bring-up complete'
      ok: self-built kernel reached 'launching the desktop environment'

  **OS-DEV builds its own kernel inside itself, and that kernel boots.** Not
  once by luck — `make selfhosttest` passes, and the one failure along the way
  left its serial log behind because this milestone also stopped that harness
  deleting it.
