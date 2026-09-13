# OS-DEV — build a from-scratch x86_64 kernel and run it under QEMU.
#
#   make          build build/kernel.elf
#   make run      boot it in QEMU with a graphical window
#   make test     boot it headless and confirm via serial output (no window)
#   make clean    remove build artifacts

# --- tools ------------------------------------------------------------------
CC      := gcc
AS      := nasm
LD      := ld
OBJCOPY := objcopy
QEMU    := qemu-system-x86_64

# --- flags ------------------------------------------------------------------
# Freestanding kernel C: no host runtime, no PIC, no red zone (interrupts would
# clobber it), and no SSE/MMX/x87 (we haven't enabled the FPU yet).
# NOTE: -fstack-protector* is silently a no-op under this toolchain's freestanding
# build (Gentoo GCC strips SSP when -ffreestanding/-nostdlib are set, and
# -mstack-protector-guard=global no-ops too — verified by disassembly). So
# stack-overflow protection is provided structurally instead: kernel stacks get an
# unmapped GUARD PAGE below them (task.c / boot.asm), and W^X marks every stack NX
# (vmm_harden_kernel). Keep -fno-stack-protector explicit so the intent is clear.
# -mcmodel=kernel (M1968): the kernel is LINKED into the top 2 GiB
# (0xFFFFFFFF80000000), and the default `small` model assumes every symbol fits
# in the low 2 GiB -- it would emit 32-bit displacements that truncate every
# kernel address. `kernel` is the model for exactly this layout: symbols in the
# top 2 GiB, still reachable with cheap sign-extended 32-bit operands.
CFLAGS  := -std=gnu11 -ffreestanding -nostdlib \
           -fno-stack-protector -fno-pic -fno-pie -mcmodel=kernel \
           -mno-red-zone -mgeneral-regs-only -fwrapv \
           -fno-omit-frame-pointer \
           -Wall -Wextra -Ikernel/include -O2 -g -MMD -MP

ASFLAGS := -f elf64
LDFLAGS := -n -T linker.ld

# -m 256M: QEMU's ~128M default starves the heaviest app — Quake needs its 18 MB
# PAK + a multi-MB hunk on top of the kernel (incl. the 40 MB JS arena), so it
# silently fails to launch at 128M but runs fine at 256M (DOOM, lighter, works at
# either). 256M comfortably fits the whole app suite, even DOOM+Quake at once.
QEMUFLAGS := -no-reboot -no-shutdown -m 256M -smp 4

# Hardware acceleration for the INTERACTIVE run targets: use KVM (native-speed
# guest — typing / window drags / app launches feel instant, ~10x faster than
# pure emulation) when /dev/kvm is present and writable (the invoking user is in
# the kvm group), else fall back to plain TCG emulation so the build stays
# portable. The headless make-check suites keep their own (TCG) QEMU invocations
# for CI determinism and to run on hosts without KVM.
ACCEL := $(shell test -w /dev/kvm && echo -enable-kvm -cpu host)

# --- sources ----------------------------------------------------------------
BUILD   := build
# kernel.elf: real ELF64 with symbols (use this for gdb).
# kernel32.elf: same code repackaged in a 32-bit ELF container so QEMU's
#               multiboot loader will accept it (it refuses ELF64).
KERNEL64 := $(BUILD)/kernel.elf
KERNEL   := $(BUILD)/kernel32.elf
DISK      := $(BUILD)/fat.img

# --- ext2 data volume (M1935) ------------------------------------------------
# The self-hosting campaign needs a filesystem that can hold a real toolchain,
# and the boot FAT32 volume cannot: this driver is 8.3-UPPERCASE-only with
# SILENT truncation (package.json -> PACKAGE.JSO), and it has no symlinks, no
# permissions and no case preservation. ext2 is the only filesystem here with
# real POSIX metadata, so a second, larger ext2 drive is attached as /disk1.
#
# Deliberately built as CLASSIC ext2, with the ext4 `extent` feature OFF: with
# extents on, mke2fs makes DIRECTORIES extent-mapped too, and dir_add grows a
# directory through bmap_alloc, which cannot grow an extent tree (M1933/M1934).
# dir_index (HTree) is off for the same reason -- the driver reads linear
# directories. Sparse file, so the nominal size costs almost nothing on disk.
#
# Built only when host e2fsprogs is present; without it the guest simply has no
# /disk1 and everything else behaves exactly as before.
MKE2FS    := $(shell command -v mke2fs 2>/dev/null)
# Where Claude Code lives on the host. It ships as a versioned binary under
# ~/.local/share/claude/versions/, with ~/.local/bin/claude a launcher, so
# `command -v` finds the launcher rather than the image -- resolve it. (M1968)
CLAUDE_BIN ?= $(shell readlink -f "$$(command -v claude 2>/dev/null)" 2>/dev/null)
# Firefox's install directory. Staged whole -- see the rule below for why.
FIREFOX_DIR ?= $(firstword $(wildcard /usr/lib64/firefox /usr/lib/firefox))
EXT2SIZE  := 2200M   # 512M -> 1500M (M1964): Node is 102 MB plus 21 shared libraries, on top of the 195 MB toolchain+source tree
ifneq ($(MKE2FS),)
EXT2IMG   := $(BUILD)/ext2.img
EXT2FLAGS := -drive file=$(BUILD)/ext2.img,format=raw,if=ide
else
EXT2IMG   :=
EXT2FLAGS :=
endif

DISKFLAGS := -drive file=$(BUILD)/fat.img,format=raw,if=ide $(EXT2FLAGS)
# An e1000 NIC on user-mode (SLIRP) networking: the gateway 10.0.2.2 answers
# ARP and ICMP, which is how we test the network stack.
NICFLAGS  := -netdev user,id=net0 -device e1000,netdev=net0
# Same SLIRP network, but presenting a Realtek RTL8139 instead of the e1000 — to
# exercise the second NIC driver (kernel/rtl8139.c). Used by `make run-rtl8139`.
RTLNICFLAGS := -netdev user,id=net0 -device rtl8139,netdev=net0
# Same SLIRP network, but presenting a LEGACY virtio-net NIC instead of the e1000
# — to exercise the paravirtual NIC driver (kernel/virtio_net.c). disable-modern
# forces the legacy I/O-port transport the driver speaks. Used by `make run-virtio-net`.
VIRTIONICFLAGS := -netdev user,id=net0 -device virtio-net-pci,netdev=net0,disable-modern=on,disable-legacy=off
# A UHCI USB controller + an absolute pointing device (tablet).
USBFLAGS  := -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0
# An Intel AC'97 audio codec. Override the host backend if needed:
#   make run AUDIODEV=sdl   (or alsa, pa, none)
AUDIODEV  ?= pa
AUDIOFLAGS := -device AC97,audiodev=snd0 -audiodev $(AUDIODEV),id=snd0
# Same AC'97 codec, but with the null backend so the headless smoke test can
# exercise the audio bring-up without depending on a host sound server.
TESTAUDIOFLAGS := -device AC97,audiodev=snd0 -audiodev none,id=snd0
# An Intel HD Audio controller (`intel-hda`) with an output codec (`hda-output`)
# instead of AC'97 — drives kernel/hda.c. The audiodev attaches to the codec
# (hda-output), not the controller bus. Override the host backend like AUDIODEV.
HDAAUDIOFLAGS := -device intel-hda -device hda-output,audiodev=snd0 -audiodev $(AUDIODEV),id=snd0
# Same HDA pair on the null backend, for the headless hdatest (no host sound server).
TESTHDAFLAGS := -device intel-hda -device hda-output,audiodev=snd0 -audiodev none,id=snd0

# kernel/testmod.c is a LOADABLE MODULE (M1261): compiled to an ET_REL .ko and
# incbin'd into the kernel image (kernel/asm/mod_blob.asm), NOT linked in — so
# exclude it from the normal C object list (it would otherwise define mod_init in
# the kernel itself, defeating the point).
C_SRCS  := $(filter-out kernel/testmod.c,$(shell find kernel -name '*.c'))
# ap_trampoline.asm is a FLAT 16-bit real-mode binary (the AP bring-up trampoline,
# M1197) — assembled with `nasm -f bin` and incbin'd by ap_blob.asm, NOT linked
# as an elf64 object — so exclude it from the normal asm object list.
ASM_SRCS:= $(filter-out kernel/asm/ap_trampoline.asm,$(shell find boot kernel -name '*.asm'))
OBJS    := $(patsubst %.c,$(BUILD)/%.o,$(C_SRCS)) \
           $(patsubst %.asm,$(BUILD)/%.o,$(ASM_SRCS))

# --- rules ------------------------------------------------------------------
.PHONY: all nodetest selfhosttest linuxabitest run run-rtl8139 run-virtio-net run-hda test rtl8139test virtionettest virtioblktest virtiorngtest virtioconsoletest nvmetest floppytest parttest blockdevtest raidtest ahcitest atapitest atalba48test idedmatest virtiogputest svgatest usbstoragetest usbkbdtest ehcitest xhcitest usbbottest layouttest layoutrendertest desktoptest ipctest hdatest httpdtest jstest lxinettest claudetest waylandtest firefoxtest check check-all clean

all: $(KERNEL) $(DISK)

# --- FAT32 disk image (built by our host-side tool) --------------------------
$(BUILD)/mkfatfs: tools/mkfatfs.c
	@mkdir -p $(BUILD)
	$(CC) -O2 -Wall -o $@ $<

# A shared library placed on the FAT disk for the userspace dynamic linker
# (M1263): built as a freestanding PIC ET_DYN, loaded at runtime by ulib's
# dlopen()/dlsym(). mkfatfs reads build/dltest.so via its hostfiles[] table, so
# the disk depends on it.
$(BUILD)/dltest.so: user/dltest_lib.c Makefile
	@mkdir -p $(BUILD)
	$(CC) -shared -fPIC -nostdlib -ffreestanding -fno-stack-protector -mno-red-zone -fno-pie -O2 $< -o $@

# Two more shared libraries proving cross-object dynamic linking (M1539):
# dlext.so imports base_mul as an undefined symbol that only dlbase.so
# exports, so dlopen() must resolve it against an EARLIER-loaded object
# (dl_resolve_import() in ulib.c) rather than silently misresolving it to its
# own base. Same freestanding PIC ET_DYN recipe as dltest.so.
$(BUILD)/dlbase.so: user/dlbase_lib.c Makefile
	@mkdir -p $(BUILD)
	$(CC) -shared -fPIC -nostdlib -ffreestanding -fno-stack-protector -mno-red-zone -fno-pie -O2 $< -o $@

$(BUILD)/dlext.so: user/dlext_lib.c Makefile
	@mkdir -p $(BUILD)
	$(CC) -shared -fPIC -nostdlib -ffreestanding -fno-stack-protector -mno-red-zone -fno-pie -O2 $< -o $@

$(DISK): $(BUILD)/mkfatfs $(BUILD)/dltest.so $(BUILD)/dlbase.so $(BUILD)/dlext.so $(BUILD)/testmod.ko
	$(BUILD)/mkfatfs $@

# --- the Linux-ABI guest root (M1939) ---------------------------------------
# Binaries for the Linux compatibility layer are built with the HOST compiler
# as ordinary static-PIE Linux executables -- that is the whole point: they are
# not built for OS-DEV, and OS-DEV runs them anyway. Staged into a directory
# that mke2fs -d copies into the ext2 volume, so the toolchain can later be
# dropped into the same place.
#
# -static-pie is mandatory: boot maps the low 1 GiB as SUPERVISOR pages shared
# into every address space, so no user page can exist below 1 GiB and a normal
# non-PIE static binary (linked at 0x400000) cannot be loaded at all.
# -nostdlib keeps this one freestanding so it tests the ABI and the loader in
# isolation, with none of libc's auxv/TLS startup in the way.
LXROOT  := $(BUILD)/lxroot
LXFLAGS := -static-pie -nostdlib -nostartfiles -fno-stack-protector \
           -fno-asynchronous-unwind-tables -O2
$(LXROOT)/hellofree: tools/lx/hellofree.c
	@mkdir -p $(LXROOT)
	$(CC) $(LXFLAGS) -o $@ $<
	@echo "  HOSTCC  $@ (a real Linux static-PIE binary)"

# A real LIBC binary, to exercise what the freestanding one deliberately does
# not: a libc reads argc/argv/envp/auxv off the stack before main, and musl/glibc
# both read AT_RANDOM there for the stack canary. Built with the host's default
# libc, statically and position-independent.
$(LXROOT)/hellolibc: tools/lx/hellolibc.c
	@mkdir -p $(LXROOT)
	$(CC) -static-pie -O2 -o $@ $<
	@echo "  HOSTCC  $@ (a real static-PIE LIBC binary)"

$(LXROOT)/lxfileio: tools/lx/lxfileio.c
	@mkdir -p $(LXROOT)
	$(CC) -static-pie -O2 -o $@ $<
	@echo "  HOSTCC  $@ (glibc file I/O + directory listing)"

$(LXROOT)/lxbox: tools/lx/lxbox.c
	@mkdir -p $(LXROOT)
	$(CC) -static-pie -O2 -o $@ $<
	@echo "  HOSTCC  $@ (busybox-shaped multi-call binary: fork/execve/pipe)"

$(LXROOT)/lxmmap: tools/lx/lxmmap.c
	@mkdir -p $(LXROOT)
	$(CC) -static-pie -O2 -o $@ $<
	@echo "  HOSTCC  $@ (MAP_FIXED mmap)"

$(LXROOT)/lxwlraw: tools/lx/lxwlraw.c
	@mkdir -p $(LXROOT)
	$(CC) -static-pie -O2 -o $@ $<
	@echo "  HOSTCC  $@ (the Wayland handshake by hand, with a hexdump)"

# xdg-shell is a PROTOCOL EXTENSION, not part of libwayland: its marshalling
# code is generated from the XML by wayland-scanner and compiled in. Generated
# into tools/lx/gen/ at build time so the checked-in tree carries the XML's
# meaning rather than a stale copy of its output. (M1981)
tools/lx/gen/xdg-shell-client-protocol.h tools/lx/gen/xdg-shell-protocol.c:
	@mkdir -p tools/lx/gen
	@if command -v wayland-scanner >/dev/null 2>&1 && [ -f $(XDG_SHELL_XML) ]; then 	    wayland-scanner client-header $(XDG_SHELL_XML) tools/lx/gen/xdg-shell-client-protocol.h && 	    wayland-scanner private-code  $(XDG_SHELL_XML) tools/lx/gen/xdg-shell-protocol.c && 	    echo "  SCANNER tools/lx/gen/xdg-shell-*  (from $(XDG_SHELL_XML))"; 	 else echo "  SKIP    xdg-shell bindings (wayland-scanner or the XML is missing)"; fi

XDG_SHELL_XML ?= /usr/share/wayland-protocols/stable/xdg-shell/xdg-shell.xml

$(LXROOT)/lxwl: tools/lx/lxwl.c tools/lx/gen/xdg-shell-client-protocol.h tools/lx/gen/xdg-shell-protocol.c
	@mkdir -p $(LXROOT)
	@if [ -f tools/lx/gen/xdg-shell-protocol.c ]; then 	    $(CC) -O2 -Itools/lx/gen -o $@ $< tools/lx/gen/xdg-shell-protocol.c -lwayland-client && 	    echo "  HOSTCC  $@ (a REAL libwayland client + xdg-shell -- the same path Firefox uses)"; 	 else echo "  SKIP    $@ (no xdg-shell bindings)"; fi

$(LXROOT)/lxscm: tools/lx/lxscm.c
	@mkdir -p $(LXROOT)
	$(CC) -static-pie -O2 -o $@ $<
	@echo "  HOSTCC  $@ (memfd + SCM_RIGHTS + MAP_SHARED: the wl_shm foundation)"

$(LXROOT)/lxnopiedyn: tools/lx/lxnopiedyn.c
	@mkdir -p $(LXROOT)
	$(CC) -no-pie -O2 -o $@ $<
	@echo "  HOSTCC  $@ (NON-PIE + DYNAMIC: Claude Code's exact ELF shape)"

$(LXROOT)/lxnopie: tools/lx/lxnopie.c
	@mkdir -p $(LXROOT)
	$(CC) -no-pie -static -O2 -o $@ $<
	@echo "  HOSTCC  $@ (NON-PIE ET_EXEC: needs the low 1 GiB to belong to the process)"

$(LXROOT)/lxinet: tools/lx/lxinet.c
	@mkdir -p $(LXROOT)
	$(CC) -static-pie -O2 -o $@ $<
	@echo "  HOSTCC  $@ (AF_INET sockets: DNS over UDP + HTTP over TCP, poll-driven)"

$(LXROOT)/lxvmagap: tools/lx/lxvmagap.c
	@mkdir -p $(LXROOT)
	$(CC) -static-pie -O2 -o $@ $<
	@echo "  HOSTCC  $@ (big-mmap VMA overlap regression)"

$(LXROOT)/lxfmap: tools/lx/lxfmap.c
	@mkdir -p $(LXROOT)
	$(CC) -static-pie -O2 -o $@ $<
	@echo "  HOSTCC  $@ (file-backed mmap at an offset)"

# Dynamically linked ON PURPOSE (no -static-pie): needs PT_INTERP + ld.so.
# The interpreter and libc are copied in beside it, because the guest has no
# /lib64 of its own -- that is the point of the exercise.
# Real POSIX threads, dynamically linked so it uses glibc's actual NPTL (M1959).
$(LXROOT)/lxthread: tools/lx/lxthread.c
	@mkdir -p $(LXROOT)
	$(CC) -O2 -o $@ $< -lpthread
	@for so in $$(ldd $@ 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do \
	   d=$(LXROOT)$$(dirname $$so); mkdir -p $$d; cp -f $$so $$d/ 2>/dev/null || true; \
	 done
	@echo "  HOSTCC  $@ (REAL pthreads: clone/futex/TLS)"

$(LXROOT)/lxdyn: tools/lx/lxdyn.c
	@mkdir -p $(LXROOT)/lib64 $(LXROOT)/usr/lib64
	$(CC) -O2 -o $@ $<
	@for so in $$(ldd $@ 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do \
	   d=$(LXROOT)$$(dirname $$so); mkdir -p $$d; cp -f $$so $$d/ 2>/dev/null || true; \
	 done
	@echo "  HOSTCC  $@ (DYNAMICALLY linked, + its ld.so/libc staged)"

LXBINS := $(LXROOT)/lxthread $(LXROOT)/lxdyn $(LXROOT)/hellofree $(LXROOT)/hellolibc $(LXROOT)/lxfileio $(LXROOT)/lxbox $(LXROOT)/lxmmap $(LXROOT)/lxfmap $(LXROOT)/lxvmagap $(LXROOT)/lxinet $(LXROOT)/lxnopie $(LXROOT)/lxnopiedyn $(LXROOT)/lxscm $(LXROOT)/lxwl $(LXROOT)/lxwlraw

# --- the borrowed Linux toolchain (M1955) ---------------------------------
# THE overwhelming majority of what runs on OS-DEV is written from scratch in
# this repo. This is the exception, and it is bolted on rather than ported:
# unmodified host binutils/nasm/make binaries, copied in whole, run through
# the Linux ABI shim. We do not port GCC -- we run it.
#
# Order-only against ext2.img via a stamp, because the tools are not built
# here and their mtimes are the host package manager's.
LXTOOLS := as ld objcopy nasm

# The source the in-guest toolchain assembles. Staged as a plain file, at the
# path a Linux process inside OS-DEV sees as /hello.s.
$(LXROOT)/hello.s: tools/lx/hello.s
	@mkdir -p $(LXROOT)
	@cp -f $< $@
	@echo "  STAGE   $@ (source for the in-guest assemble+link demo)"

$(LXROOT)/hello.c: tools/lx/hello.c
	@mkdir -p $(LXROOT)
	@cp -f $< $@
	@echo "  STAGE   $@ (source for the in-guest COMPILE demo)"

# OS-DEV's OWN SOURCE, staged into the volume so the in-guest toolchain can
# compile it. This is Phase 5: the OS building itself. Copied rather than
# generated -- these are the same files this host Makefile compiles.
$(LXROOT)/.src-staged: $(wildcard kernel/*.c kernel/include/*.h boot/*.asm kernel/asm/*.asm) tools/lx/Makefile.kernel
	@mkdir -p $(LXROOT)/src/build
	@cp -r kernel boot linker.ld $(LXROOT)/src/ 2>/dev/null || true
	@rm -f $(LXROOT)/src/kernel/testmod.c
	@cp -f tools/lx/Makefile.kernel $(LXROOT)/src/Makefile
	@# The 128 prebuilt userspace ELFs kernel/asm/user_blob.asm incbin's, plus
	@# the AP trampoline. This milestone rebuilds the KERNEL from source; the
	@# applications are reused as blobs, which is stated plainly in the docs.
	@cp -f build/*.elf build/*.bin build/*.ko $(LXROOT)/src/build/ 2>/dev/null || true
	@printf '#include "ksyms.h"\nconst struct ksym ksyms[]={{0,0}};\nconst int ksyms_count=0;\n' > $(LXROOT)/src/ksyms_stub.c
	@touch $@
	@echo "  STAGE   $(LXROOT)/src (OS-DEV's own kernel source + Makefile, for the in-guest build)"

# A LARGE real assembly file (OS-DEV's own biggest source, compiled to .s on
# the host) for the in-guest assembler to chew on. Half a megabyte of real
# input catches size-dependent bugs a hello-world never would.
$(LXROOT)/big.s: kernel/app.c
	@mkdir -p $(LXROOT)
	@$(CC) $(filter-out -MMD -MP -g,$(CFLAGS)) -S $< -o $@ 2>/dev/null || true
	@echo "  STAGE   $@ ($$(wc -c < $@) bytes of real assembly for the in-guest assembler)"

$(LXROOT)/Makefile.guest: tools/lx/Makefile.guest
	@mkdir -p $(LXROOT)
	@cp -f $< $@
	@echo "  STAGE   $@ (the Makefile GNU make runs INSIDE OS-DEV)"

# Depends on lxwl as well: the libwayland-client closure is staged FROM that
# binary, so it has to exist first. Without the dependency the staging step ran
# before the client was built and silently skipped it. (M1978)
$(LXROOT)/.tools-staged: tools/stage-linux-tool.sh $(LXROOT)/lxwl
	@mkdir -p $(LXROOT)
	@for t in $(LXTOOLS); do tools/stage-linux-tool.sh $(LXROOT) $$t; done
	@tools/stage-linux-tool.sh $(LXROOT) make "$$(command -v gmake || command -v make)"
	@tools/stage-linux-tool.sh $(LXROOT) cc1  "$$(gcc -print-prog-name=cc1 2>/dev/null)"
	@tools/stage-linux-tool.sh $(LXROOT) collect2 "$$(gcc -print-prog-name=collect2 2>/dev/null)"
	@tools/stage-linux-tool.sh $(LXROOT) gcc
	@# GCC's own FREESTANDING headers (stdint.h, stddef.h, stdarg.h, the
	@# intrinsics). -ffreestanding still needs these -- they are part of the
	@# compiler, not of libc -- and cc1 finds them via a path relative to the
	@# driver, so they have to land at exactly the host's absolute path.
	@gi="$$(gcc -print-file-name=include 2>/dev/null)"; \
	 if [ -d "$$gi" ]; then mkdir -p $(LXROOT)$$gi && cp -r "$$gi/." $(LXROOT)$$gi/ && \
	   echo "  STAGE   gcc freestanding headers <- $$gi"; fi
	@# ...and AGAIN at /lib/gcc/..., because cc1's include prefix is computed
	@# from the DRIVER'S argv[0]: exec'd as /usr/bin/gcc it looks in
	@# /usr/bin/../../../lib/gcc/... which normalises to /lib/gcc/..., not
	@# /usr/lib/gcc/.... On the host that resolves correctly only because the
	@# real binary lives three levels deeper.
	@gi="$$(gcc -print-file-name=include 2>/dev/null)"; \
	 if [ -d "$$gi" ]; then mkdir -p $(LXROOT)/lib/gcc/x86_64-pc-linux-gnu/15 && \
	   cp -r "$$gi" $(LXROOT)/lib/gcc/x86_64-pc-linux-gnu/15/ && \
	   echo "  STAGE   gcc freestanding headers (also at /lib/gcc/...)"; fi
	@for t in mkdir rm cp touch printf nm; do tools/stage-linux-tool.sh $(LXROOT) $$t; done
	@mkdir -p $(LXROOT)/bin && for t in mkdir rm cp touch printf; do cp -f $(LXROOT)/usr/bin/$$t $(LXROOT)/bin/$$t 2>/dev/null || true; done
	@tools/stage-linux-tool.sh $(LXROOT) bash
	@# PHASE 6: Node. 102 MB and 21 shared libraries (libuv, c-ares, OpenSSL,
	@# ICU, nghttp2, simdjson) -- staged whole and unmodified, exactly like the
	@# toolchain. We do not port Node; we run it.
	@tools/stage-linux-tool.sh $(LXROOT) node
	@# PHASE 8: libwayland-client and its closure, so a real Wayland client can
	@# run in-guest. Staged from the lxwl binary we just built against it.
	@# ABSPATH, not a relative one: the staging script only accepts an absolute
	@# binary path (a relative one looks like a bare command name and it goes
	@# looking in /usr/bin, then skips). (M1978)
	@if [ -f $(LXROOT)/lxwl ]; then tools/stage-linux-tool.sh $(LXROOT) lxwl $(abspath $(LXROOT)/lxwl); fi
	@for t in echo cat ls; do tools/stage-linux-tool.sh $(LXROOT) $$t; done
	@mkdir -p $(LXROOT)/bin && for t in echo cat ls; do cp -f $(LXROOT)/usr/bin/$$t $(LXROOT)/bin/$$t 2>/dev/null || true; done
	@# PHASE 7: Claude Code. A single 214 MB dynamically-linked ELF (a Node
	@# single-executable app -- the runtime and the JS are bundled into one
	@# image), so it stages exactly like node did and needs no npm tree. Only
	@# FIVE shared libraries, all glibc core; everything else is inside it.
	@# Staged from wherever the host has it, and SKIPPED if it is not
	@# installed -- the build must not depend on the developer's own tooling
	@# being present.
	@if [ -n "$(CLAUDE_BIN)" ] && [ -f "$(CLAUDE_BIN)" ]; then 	    tools/stage-linux-tool.sh $(LXROOT) claude "$(CLAUDE_BIN)"; 	 else echo "  SKIP    claude (not installed; set CLAUDE_BIN=/path to stage it)"; fi
	@# PHASE 8: Firefox. Its own directory goes in WHOLESALE -- libxul.so,
	@# omni.ja, the .so plugins and the resource tree -- because Firefox
	@# resolves those relative to its own install path, not through ld.so. The
	@# shared-library closure comes from libxul rather than the launcher: the
	@# launcher is a 600 KB stub with six dependencies, and everything real
	@# (GTK, cairo, pango, fontconfig, dbus) is libxul's. (M1982)
	@if [ -d "$(FIREFOX_DIR)" ]; then 	    mkdir -p $(LXROOT)$(FIREFOX_DIR) && cp -a "$(FIREFOX_DIR)/." $(LXROOT)$(FIREFOX_DIR)/ && 	    echo "  STAGE   firefox <- $(FIREFOX_DIR) ($$(du -sh $(FIREFOX_DIR) | cut -f1))"; 	    tools/stage-linux-tool.sh $(LXROOT) libxul "$(FIREFOX_DIR)/libxul.so" >/dev/null 2>&1 || true; 	    n=0; for so in $$(ldd "$(FIREFOX_DIR)/libxul.so" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*' | sort -u); do 	        r=$$(readlink -f "$$so" 2>/dev/null) || continue; [ -f "$$r" ] || continue; 	        mkdir -p $(LXROOT)$$(dirname "$$so") $(LXROOT)/usr/lib64; 	        cp -f "$$r" $(LXROOT)$$so; cp -f "$$r" $(LXROOT)/usr/lib64/$$(basename "$$so") 2>/dev/null || true; 	        n=$$((n+1)); done; 	    echo "  STAGE   libxul closure (+ $$n shared libs)"; 	 else echo "  SKIP    firefox (not installed; set FIREFOX_DIR=)"; fi
	@mkdir -p $(LXROOT)/bin && cp -f $(LXROOT)/usr/bin/bash $(LXROOT)/bin/sh
	@touch $@


# The ext2 data volume (see the EXT2IMG block near the top). Sparse: `truncate`
# reserves the size without writing it, and mke2fs only touches metadata, so a
# 512M volume costs a few MB on the host until it is actually filled.
$(BUILD)/ext2.img: $(LXBINS) $(LXROOT)/.tools-staged $(LXROOT)/hello.s $(LXROOT)/hello.c $(LXROOT)/Makefile.guest $(LXROOT)/big.s $(LXROOT)/.src-staged
	@mkdir -p $(BUILD)
	@rm -f $@ && truncate -s $(EXT2SIZE) $@
	@mke2fs -F -q -b 4096 -O ^resize_inode,^dir_index,^ext_attr,^has_journal,^extent \
	        -d $(LXROOT) $@ >/dev/null 2>&1
	@echo "  MKE2FS  $@ ($(EXT2SIZE), 4K blocks, classic ext2, Linux binaries staged in)"

$(BUILD)/%.o: %.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# js.o uses real IEEE-754 doubles (M906), which need SSE — so drop -mgeneral-regs-only
# and add SSE for this one translation unit (an exact-target rule overrides the %.o rule).
# Safe in the kernel: fpu_init() enables x87+SSE at boot, and the scheduler saves/restores
# FP/SSE state for EVERY task (task.c fx_alloc in sched_init + task_create_stack), so the
# JS engine's xmm use survives context switches. No libm/libcall (js_sqrt/js_pow are local).
$(BUILD)/kernel/js.o: kernel/js.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(filter-out -mgeneral-regs-only,$(CFLAGS)) -msse2 -mfpmath=sse -c $< -o $@

# A loadable kernel module (M1261): kernel/testmod.c -> an ET_REL object
# build/testmod.ko (same code model as the kernel, so its relocations match what
# kernel/module.c applies). It is NOT linked into the kernel; instead
# kernel/asm/mod_blob.asm incbin's it into .rodata, and insmod loads + relocates
# + runs it. The blob object must be (re)assembled after the .ko exists.
$(BUILD)/testmod.ko: kernel/testmod.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/kernel/asm/mod_blob.o: $(BUILD)/testmod.ko

# -fwrapv is in CFLAGS above (global): the kernel parses untrusted input (network,
# disk, images, TLS, HTML, JS) with signed arithmetic, so signed overflow must be
# defined (wrapping) rather than UB under -O2 across the whole kernel.

$(BUILD)/%.o: %.asm
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $< -o $@

# --- userspace ---------------------------------------------------------------
# Each user program (shell, clock, ...) is linked with the shared ulib into its
# own ELF; the kernel embeds them all (see kernel/asm/user_blob.asm).
# -fwrapv: the OS-authored apps (shell $((...)) / calc evaluators, etc.) do signed
# arithmetic on user input, so overflow must wrap (defined) rather than be UB under
# -O2 — same rationale as the kernel CFLAGS. (Ported games keep their own CFLAGS.)
USER_CFLAGS := -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone \
               -mgeneral-regs-only -std=gnu11 -O2 -fwrapv -Wall -Ikernel/include -MMD -MP
USER_ELFS := $(BUILD)/shell.elf $(BUILD)/clock.elf $(BUILD)/calc.elf $(BUILD)/snake.elf $(BUILD)/editor.elf $(BUILD)/g2048.elf $(BUILD)/life.elf $(BUILD)/tetris.elf $(BUILD)/breakout.elf $(BUILD)/mines.elf $(BUILD)/sudoku.elf $(BUILD)/calendar.elf $(BUILD)/timer.elf $(BUILD)/mandel.elf $(BUILD)/piano.elf $(BUILD)/maze.elf $(BUILD)/adv.elf $(BUILD)/matrix.elf $(BUILD)/paint.elf $(BUILD)/hangman.elf $(BUILD)/jukebox.elf $(BUILD)/ttt.elf $(BUILD)/bj.elf $(BUILD)/typing.elf $(BUILD)/simon.elf $(BUILD)/c4.elf $(BUILD)/wordle.elf $(BUILD)/gfxdemo.elf $(BUILD)/scene3d.elf $(BUILD)/terrain.elf $(BUILD)/demoscene.elf $(BUILD)/doom.elf $(BUILD)/quake.elf $(BUILD)/nes.elf $(BUILD)/reversi.elf $(BUILD)/lights.elf $(BUILD)/fifteen.elf $(BUILD)/mastermind.elf $(BUILD)/pong.elf $(BUILD)/halflife.elf $(BUILD)/memory.elf $(BUILD)/sokoban.elf $(BUILD)/battleship.elf $(BUILD)/pig.elf $(BUILD)/raycast.elf $(BUILD)/tron.elf $(BUILD)/spaceinv.elf $(BUILD)/asteroids.elf $(BUILD)/flappy.elf $(BUILD)/gb.elf $(BUILD)/lander.elf $(BUILD)/yahtzee.elf $(BUILD)/checkers.elf $(BUILD)/gomoku.elf $(BUILD)/frogger.elf $(BUILD)/chess.elf $(BUILD)/vpoker.elf $(BUILD)/mancala.elf $(BUILD)/dotsbox.elf $(BUILD)/missile.elf $(BUILD)/pacman.elf $(BUILD)/solitaire.elf $(BUILD)/gems.elf $(BUILD)/columns.elf $(BUILD)/freecell.elf $(BUILD)/spider.elf $(BUILD)/sandbox.elf $(BUILD)/forth.elf $(BUILD)/cc.elf $(BUILD)/crash.elf $(BUILD)/futex.elf $(BUILD)/nettcp.elf $(BUILD)/crashinfo.elf $(BUILD)/forktest.elf $(BUILD)/execdemo.elf $(BUILD)/nstest.elf $(BUILD)/steptest.elf $(BUILD)/scnotify.elf $(BUILD)/fswaittest.elf $(BUILD)/sigfdtest.elf $(BUILD)/bpftest.elf $(BUILD)/fantest.elf $(BUILD)/iouringtest.elf $(BUILD)/msealtest.elf $(BUILD)/httpd.elf $(BUILD)/uffdtest.elf $(BUILD)/mmapfile.elf $(BUILD)/threads.elf $(BUILD)/robustfutex.elf $(BUILD)/overlay.elf $(BUILD)/pcwd.elf $(BUILD)/hexedit.elf $(BUILD)/aclock.elf $(BUILD)/sysgraph.elf $(BUILD)/taskman.elf $(BUILD)/gcal.elf $(BUILD)/gauges.elf $(BUILD)/gsw.elf $(BUILD)/bclock.elf $(BUILD)/gfont.elf $(BUILD)/gtimer.elf $(BUILD)/imgview.elf $(BUILD)/gcalc.elf $(BUILD)/gcolor.elf $(BUILD)/gfire.elf $(BUILD)/gmetro.elf $(BUILD)/gconv.elf $(BUILD)/gbase.elf $(BUILD)/gpass.elf $(BUILD)/gclip.elf $(BUILD)/gtodo.elf $(BUILD)/gseq.elf $(BUILD)/pietest.elf $(BUILD)/jsrun.elf $(BUILD)/imgdec.elf $(BUILD)/httpget.elf $(BUILD)/webview.elf $(BUILD)/sheet.elf $(BUILD)/plot.elf $(BUILD)/gpaint.elf $(BUILD)/gjson.elf $(BUILD)/gregex.elf $(BUILD)/gdiff.elf $(BUILD)/garc.elf $(BUILD)/ghash.elf

$(BUILD)/user_%.o: user/%.c Makefile
	@mkdir -p $(BUILD)
	$(CC) $(USER_CFLAGS) -c $< -o $@

# cc.c is the vendored c4 C compiler — terse C that's noisy under -Wall; -w it.
$(BUILD)/user_cc.o: user/cc.c Makefile
	@mkdir -p $(BUILD)
	$(CC) $(USER_CFLAGS) -w -c user/cc.c -o $@

# crash.c keeps frame pointers so its core dump (M1104) has a walkable saved-rbp
# chain — i.e. so `crashinfo` (M1112) can produce a real frame-pointer backtrace.
$(BUILD)/user_crash.o: user/crash.c Makefile
	@mkdir -p $(BUILD)
	$(CC) $(USER_CFLAGS) -fno-omit-frame-pointer -c user/crash.c -o $@

$(BUILD)/%.elf: $(BUILD)/user_%.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld
	$(LD) -T user/user.ld -o $@ $(BUILD)/user_$*.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (userspace program)"

# pietest.elf — a POSITION-INDEPENDENT executable (M1465): built -fPIE -pie so it
# is an ET_DYN carrying R_X86_64_RELATIVE relocs, the test for the kernel's new
# elf_load_dyn path. This SPECIFIC rule overrides the %.elf pattern above; the
# program is self-contained (its own _start + inline syscalls, no ulib) so its
# only reloc is RELATIVE — exactly what the loader handles.
$(BUILD)/pietest.elf: user/pietest.c Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fPIE -pie -mno-red-zone -mcmodel=small -std=gnu11 -O2 -w -e _start -o $@ user/pietest.c
	@echo "Built $@ (PIE test executable)"

# --- DOOM (vendored doomgeneric) ---------------------------------------------
# Same shape as USER_CFLAGS but WITH floating point (DOOM uses double): drop
# -mgeneral-regs-only, add SSE. -w silences DOOM's many legacy warnings;
# -fcommon tolerates its tentative-definition globals. The shim headers in
# user/doom/include stand in for libc.
DOOM_CFLAGS := -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone \
               -std=gnu11 -O2 -w -fcommon -msse2 -mfpmath=sse \
               -Iuser/doom/include -Ikernel/include \
               -DDOOMGENERIC_RESX=320 -DDOOMGENERIC_RESY=200 -DNORMALUNIX

DOOM_SRCS := $(wildcard user/doom/*.c)
DOOM_OBJS := $(patsubst user/doom/%.c,$(BUILD)/doom/%.o,$(DOOM_SRCS))

$(BUILD)/doom/%.o: user/doom/%.c Makefile
	@mkdir -p $(BUILD)/doom
	$(CC) $(DOOM_CFLAGS) -c $< -o $@

$(BUILD)/doom.elf: $(DOOM_OBJS) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld
	$(LD) -T user/user.ld -o $@ $(DOOM_OBJS) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (DOOM)"

# --- Quake (vendored quakegeneric) -------------------------------------------
# Same shape as DOOM_CFLAGS: floating point on (Quake is FP-heavy) so drop
# -mgeneral-regs-only and add SSE; -w silences the legacy warnings; -fcommon
# tolerates the engine's tentative-definition globals. The shim headers in
# user/quake/include stand in for libc; -Iuser/quake lets the engine .c files
# resolve their own cross-included headers. The engine renders at vid_null.c's
# 320x240, which is what quakegeneric.h's RES_X/RES_Y default to.
QUAKE_CFLAGS := -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone \
                -std=gnu11 -O2 -w -fcommon -msse2 -mfpmath=sse \
                -Iuser/quake/include -Iuser/quake -Ikernel/include \
                -DQUAKEGENERIC_RESX=320 -DQUAKEGENERIC_RESY=240 -DNORMALUNIX

QUAKE_SRCS := $(wildcard user/quake/*.c)
QUAKE_OBJS := $(patsubst user/quake/%.c,$(BUILD)/quake/%.o,$(QUAKE_SRCS))

$(BUILD)/quake/%.o: user/quake/%.c Makefile
	@mkdir -p $(BUILD)/quake
	$(CC) $(QUAKE_CFLAGS) -c $< -o $@

$(BUILD)/quake.elf: $(QUAKE_OBJS) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld
	$(LD) -T user/user.ld -o $@ $(QUAKE_OBJS) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (Quake)"

# --- NES (vendored libxnes + a platform shim) --------------------------------
# Same shape as DOOM_CFLAGS: floating point on (libxnes's audio sample path is
# float) so drop -mgeneral-regs-only and add SSE; -w silences the vendored
# core's legacy warnings; -fcommon tolerates its tentative-definition globals.
# -Iuser/nes lets the core's <xnes.h>/<cpu.h>/... resolve; -Iuser/nes/include
# supplies the libc shim headers (GCC provides <stdint.h>/<stdarg.h>/<limits.h>
# freestanding). The emulator renders a 256x240 XRGB framebuffer.
NES_CFLAGS := -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone \
              -std=gnu11 -O2 -w -fcommon -msse2 -mfpmath=sse \
              -Iuser/nes -Iuser/nes/include -Ikernel/include

NES_SRCS := $(wildcard user/nes/*.c)
NES_OBJS := $(patsubst user/nes/%.c,$(BUILD)/nes/%.o,$(NES_SRCS))

$(BUILD)/nes/%.o: user/nes/%.c Makefile
	@mkdir -p $(BUILD)/nes
	$(CC) $(NES_CFLAGS) -c $< -o $@

$(BUILD)/nes.elf: $(NES_OBJS) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld
	$(LD) -T user/user.ld -o $@ $(NES_OBJS) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (NES)"

# --- Game Boy (vendored Peanut-GB, single header + a platform shim) ----------
# Same shape as the NES stanza; -Iuser/gb resolves <peanut_gb.h>, -Iuser/gb/include
# the libc shim headers. SSE on (harmless) for consistency with the other ports.
GB_CFLAGS := -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone \
             -std=gnu11 -O2 -w -fcommon -msse2 -mfpmath=sse \
             -Iuser/gb -Iuser/gb/include -Ikernel/include

GB_SRCS := $(wildcard user/gb/*.c)
GB_OBJS := $(patsubst user/gb/%.c,$(BUILD)/gb/%.o,$(GB_SRCS))

$(BUILD)/gb/%.o: user/gb/%.c Makefile
	@mkdir -p $(BUILD)/gb
	$(CC) $(GB_CFLAGS) -c $< -o $@

$(BUILD)/gb.elf: $(GB_OBJS) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld
	$(LD) -T user/user.ld -o $@ $(GB_OBJS) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (Game Boy)"

# --- Raycaster (a from-scratch pseudo-3D maze) -------------------------------
# Built with SSE (like DOOM/Quake) so it can use float for the ray geometry; the
# generic user rule uses -mgeneral-regs-only (no float), so give it its own rule.
$(BUILD)/raycast.elf: user/raycast.c $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -w \
	      -msse2 -mfpmath=sse -Ikernel/include -c user/raycast.c -o $(BUILD)/raycast_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/raycast_app.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (Raycaster)"

# --- jsrun (the from-scratch JavaScript engine, running in RING 3) ------------
# First step of moving the browser/parser stack out of ring 0: kernel/js.c is pure
# compute (arena + libc + callback I/O), so it links into a userspace program built
# with SSE (the engine uses IEEE-754 doubles), -DJS_RING3 (drops the privileged
# cli/sti single-flight guard, which would #GP in ring 3) and a 16 MB arena. A bug
# in the 4600-line interpreter now crashes only this ring-3 process, not the kernel.
$(BUILD)/jsrun.elf: user/jsrun.c kernel/js.c $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -w \
	      -msse2 -mfpmath=sse -Ikernel/include -DJS_RING3 -DJS_ARENA=16777216 \
	      -c kernel/js.c -o $(BUILD)/jsrun_js.o
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -Wall \
	      -msse2 -mfpmath=sse -Ikernel/include -c user/jsrun.c -o $(BUILD)/jsrun_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/jsrun_app.o $(BUILD)/jsrun_js.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (ring-3 JavaScript engine)"

# gregex — the regex tester. It REUSES the ring-3 JS engine (kernel/js.c) rather
# than reimplement a matcher, so it links js.c exactly like jsrun (SSE, JS_RING3,
# a big arena for the interpreter).
$(BUILD)/gregex.elf: user/gregex.c kernel/js.c $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -w \
	      -msse2 -mfpmath=sse -Ikernel/include -DJS_RING3 -DJS_ARENA=16777216 \
	      -c kernel/js.c -o $(BUILD)/gregex_js.o
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -Wall \
	      -msse2 -mfpmath=sse -Ikernel/include -c user/gregex.c -o $(BUILD)/gregex_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/gregex_app.o $(BUILD)/gregex_js.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (regex tester)"

# --- imgdec (the from-scratch image decoders, running in RING 3) --------------
# Second step of the ring-0->ring-3 move (after jsrun): PNG/GIF/JPEG/SVG/BMP +
# inflate are pure compute over caller-provided buffers (already host-fuzzed in
# tests/), so they link straight into a ring-3 program. A malformed-image bug now
# crashes only this process, not the kernel. SSE on in case a decoder uses float.
IMGDEC_CC = $(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -msse2 -mfpmath=sse -Ikernel/include -Iuser
$(BUILD)/imgdec.elf: user/imgdec.c kernel/png.c kernel/gif.c kernel/jpeg.c kernel/bmp.c kernel/svg.c kernel/webp.c kernel/inflate.c $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(IMGDEC_CC) -w -DPNG_THREADED -c kernel/png.c     -o $(BUILD)/imgdec_png.o
	$(IMGDEC_CC) -w -DGIF_THREADED -c kernel/gif.c     -o $(BUILD)/imgdec_gif.o
	$(IMGDEC_CC) -w -DJPEG_THREADED -c kernel/jpeg.c    -o $(BUILD)/imgdec_jpeg.o
	$(IMGDEC_CC) -w -c kernel/bmp.c     -o $(BUILD)/imgdec_bmp.o
	$(IMGDEC_CC) -w -c kernel/svg.c     -o $(BUILD)/imgdec_svg.o
	$(IMGDEC_CC) -w -c kernel/webp.c    -o $(BUILD)/imgdec_webp.o
	$(IMGDEC_CC) -w -c kernel/inflate.c -o $(BUILD)/imgdec_inflate.o
	$(IMGDEC_CC) -w -c kernel/font.c    -o $(BUILD)/imgdec_font.o
	$(IMGDEC_CC) -Wall -c user/imgdec.c -o $(BUILD)/imgdec_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/imgdec_app.o $(BUILD)/imgdec_png.o $(BUILD)/imgdec_gif.o $(BUILD)/imgdec_jpeg.o $(BUILD)/imgdec_bmp.o $(BUILD)/imgdec_svg.o $(BUILD)/imgdec_webp.o $(BUILD)/imgdec_inflate.o $(BUILD)/imgdec_font.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (ring-3 image decoders)"

# gpaint links the from-scratch PNG encoder (kernel/png_encode.c + its DEFLATE)
# so it can export the canvas as a PNG in ring 3 — same IMGDEC_CC pattern as
# imgview/imgdec. gpaint itself is integer-only; the SSE in IMGDEC_CC is harmless.
$(BUILD)/gpaint.elf: user/gpaint.c kernel/png_encode.c kernel/deflate.c $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(IMGDEC_CC) -w -c kernel/png_encode.c -o $(BUILD)/gpaint_pngenc.o
	$(IMGDEC_CC) -w -DDEFLATE_HOST -c kernel/deflate.c -o $(BUILD)/gpaint_deflate.o   # DEFLATE_HOST = ring-3 build: no privileged cli in the lock
	$(IMGDEC_CC) -Wall -c user/gpaint.c    -o $(BUILD)/gpaint_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/gpaint_app.o $(BUILD)/gpaint_pngenc.o $(BUILD)/gpaint_deflate.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (paint, with PNG export)"

# --- imgview now DECODES IN RING 3: the graphical image viewer links the
# from-scratch decoders directly (like imgdec) and fit-scales in-process, instead
# of the in-kernel sys_loadimg — so a malformed image opened in the viewer crashes
# only imgview, not the kernel. Overrides the generic %.elf rule. ---
$(BUILD)/imgview.elf: user/imgview.c kernel/png.c kernel/gif.c kernel/jpeg.c kernel/bmp.c kernel/svg.c kernel/webp.c kernel/inflate.c kernel/font.c $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(IMGDEC_CC) -w -DPNG_THREADED -c kernel/png.c     -o $(BUILD)/imgview_png.o
	$(IMGDEC_CC) -w -DGIF_THREADED -c kernel/gif.c     -o $(BUILD)/imgview_gif.o
	$(IMGDEC_CC) -w -DJPEG_THREADED -c kernel/jpeg.c    -o $(BUILD)/imgview_jpeg.o
	$(IMGDEC_CC) -w -c kernel/bmp.c     -o $(BUILD)/imgview_bmp.o
	$(IMGDEC_CC) -w -c kernel/svg.c     -o $(BUILD)/imgview_svg.o
	$(IMGDEC_CC) -w -c kernel/webp.c    -o $(BUILD)/imgview_webp.o
	$(IMGDEC_CC) -w -c kernel/inflate.c -o $(BUILD)/imgview_inflate.o
	$(IMGDEC_CC) -w -c kernel/font.c    -o $(BUILD)/imgview_font.o
	$(IMGDEC_CC) -Wall -c user/imgview.c -o $(BUILD)/imgview_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/imgview_app.o $(BUILD)/imgview_png.o $(BUILD)/imgview_gif.o $(BUILD)/imgview_jpeg.o $(BUILD)/imgview_bmp.o $(BUILD)/imgview_svg.o $(BUILD)/imgview_webp.o $(BUILD)/imgview_inflate.o $(BUILD)/imgview_font.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (ring-3 image viewer)"

# --- webview (the from-scratch web browser, running in RING 3) -----------------
# Headline ring-0 -> ring-3 migration: browser.c + js.c + image decoders + HTML/
# CSS/URL parsers built for ring 3 (-DBROWSER_RING3 / -DJS_RING3), so the untrusted
# HTML/CSS/JS/image parsing runs OUTSIDE the kernel. A parser bug now crashes only
# this ring-3 process. As of M1863 the HTTPS fetch path is ALSO ring 3: tls.c + the
# crypto/X.509 stack (the same proven objects httpget links) are compiled in, so the
# browser no longer calls the kernel's SYS_https (its TLS/crypto/cert-validation runs
# here, in ring 3). Plain http:// still uses SYS_http (no crypto/X.509 there). SSE:
# js.c uses IEEE-754 doubles; the integer-only crypto is built -mgeneral-regs-only.
WEBVIEW_CC = $(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -msse2 -mfpmath=sse -Ikernel/include -Iuser -w
WEBVIEW_PARSERS = png gif jpeg bmp svg webp inflate font http cssprop color url htmlentity htmlattr reader
# Ring-3 TLS 1.3 + crypto + X.509 for the browser's HTTPS fetch (M1863). Same set +
# flags httpget uses (integer-only -> -mgeneral-regs-only). url.c is already linked
# via WEBVIEW_PARSERS, so tls.c's url_host_port() resolves without adding it here.
WEBVIEW_TLS_CC = $(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -mgeneral-regs-only -std=gnu11 -O2 -Ikernel/include -w
WEBVIEW_CRYPTO = aes aesgcm bignum chachapoly ecdsa hkdf rsa sha256 sha512 x25519 x509 rootca
$(BUILD)/webview.elf: user/webview.c kernel/browser.c kernel/js.c $(patsubst %,kernel/%.c,$(WEBVIEW_PARSERS)) kernel/tls.c $(patsubst %,kernel/%.c,$(WEBVIEW_CRYPTO)) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(WEBVIEW_CC) -DBROWSER_RING3 -c kernel/browser.c -o $(BUILD)/webview_browser.o
	$(WEBVIEW_CC) -DJS_RING3 -DJS_ARENA=16777216 -c kernel/js.c -o $(BUILD)/webview_js.o
	@for m in $(WEBVIEW_PARSERS); do echo "  CC kernel/$$m.c (ring-3 browser)"; extra=""; [ "$$m" = "jpeg" ] && extra="-DJPEG_THREADED"; [ "$$m" = "png" ] && extra="-DPNG_THREADED"; [ "$$m" = "gif" ] && extra="-DGIF_THREADED"; $(WEBVIEW_CC) $$extra -c kernel/$$m.c -o $(BUILD)/webview_$$m.o || exit 1; done
	$(WEBVIEW_TLS_CC) -DTLS_RING3 -c kernel/tls.c -o $(BUILD)/webview_tls.o
	@for m in $(WEBVIEW_CRYPTO); do echo "  CC kernel/$$m.c (ring-3 browser TLS/crypto)"; extra=""; [ "$$m" = "aes" ] && extra="-DAES_RING3"; [ "$$m" = "ecdsa" ] && extra="-DECDSA_RING3"; $(WEBVIEW_TLS_CC) $$extra -c kernel/$$m.c -o $(BUILD)/webview_$$m.o || exit 1; done
	$(WEBVIEW_CC) -c user/webview.c -o $(BUILD)/webview_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/webview_app.o $(BUILD)/webview_browser.o $(BUILD)/webview_js.o $(patsubst %,$(BUILD)/webview_%.o,$(WEBVIEW_PARSERS)) $(BUILD)/webview_tls.o $(patsubst %,$(BUILD)/webview_%.o,$(WEBVIEW_CRYPTO)) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (ring-3 web browser + ring-3 TLS)"

# --- httpget (the from-scratch TLS 1.3 client, running in RING 3) -------------
# Third step of the ring-0->ring-3 move: tls.c + its crypto (X25519/ECDSA/RSA/
# AES-GCM/ChaCha20-Poly1305/SHA-2/X.509) are static-buffer pure compute (host-
# fuzzed in tests/), so they link into a ring-3 program; httpget.c shims kernel
# tcp_*/DNS/clock onto the socket/resolve/time syscalls. -DTLS_RING3 drops tls.c's
# privileged cli/sti. Integer-only crypto -> -mgeneral-regs-only (as the kernel).
HTTPGET_CC = $(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -mgeneral-regs-only -std=gnu11 -O2 -Ikernel/include
HTTPGET_CRYPTO = aes aesgcm bignum chachapoly ecdsa hkdf rsa sha256 sha512 x25519 x509 rootca
$(BUILD)/httpget.elf: user/httpget.c kernel/tls.c kernel/url.c $(patsubst %,kernel/%.c,$(HTTPGET_CRYPTO)) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(HTTPGET_CC) -w -DTLS_RING3 -c kernel/tls.c -o $(BUILD)/httpget_tls.o
	$(HTTPGET_CC) -w -c kernel/url.c -o $(BUILD)/httpget_url.o    # url_host_port() for tls_get_inner (M1773)
	@for m in $(HTTPGET_CRYPTO); do echo "  CC kernel/$$m.c (ring-3 crypto)"; extra=""; [ "$$m" = "aes" ] && extra="-DAES_RING3"; [ "$$m" = "ecdsa" ] && extra="-DECDSA_RING3"; $(HTTPGET_CC) -w $$extra -c kernel/$$m.c -o $(BUILD)/httpget_$$m.o || exit 1; done
	$(HTTPGET_CC) -Wall -c user/httpget.c -o $(BUILD)/httpget_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/httpget_app.o $(BUILD)/httpget_tls.o $(BUILD)/httpget_url.o $(patsubst %,$(BUILD)/httpget_%.o,$(HTTPGET_CRYPTO)) $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (ring-3 TLS 1.3 client)"

# --- scene3d (software 3D engine: z-buffer + Gouraud, float math, so SSE) -----
$(BUILD)/scene3d.elf: user/scene3d.c $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -w \
	      -msse2 -mfpmath=sse -Ikernel/include -c user/scene3d.c -o $(BUILD)/scene3d_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/scene3d_app.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (3D Engine)"

# --- terrain (procedural heightmap flythrough: z-buffer + fog, float, so SSE) -
$(BUILD)/terrain.elf: user/terrain.c $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -w \
	      -msse2 -mfpmath=sse -Ikernel/include -c user/terrain.c -o $(BUILD)/terrain_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/terrain_app.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (Terrain)"

# --- Asteroids (vector arcade; float physics, so SSE like the raycaster) ------
$(BUILD)/asteroids.elf: user/asteroids.c $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -w \
	      -msse2 -mfpmath=sse -Ikernel/include -c user/asteroids.c -o $(BUILD)/asteroids_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/asteroids_app.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (Asteroids)"

# --- Lunar Lander (float physics, so SSE like the raycaster/asteroids) -------
$(BUILD)/lander.elf: user/lander.c $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -w \
	      -msse2 -mfpmath=sse -Ikernel/include -c user/lander.c -o $(BUILD)/lander_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/lander_app.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (Lunar Lander)"

$(BUILD)/missile.elf: user/missile.c $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -w \
	      -msse2 -mfpmath=sse -Ikernel/include -c user/missile.c -o $(BUILD)/missile_app.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/missile_app.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (Missile Command)"

# --- calc (scientific calculator: now floating point, so SSE like the games) --
# The generic user rule uses -mgeneral-regs-only (no float); the float evaluator
# (user/calceval.h + user/dmath.h) needs SSE, so give calc its own rule. Keep
# -fwrapv + -Wall so the OS-authored evaluator (calceval.h/calc.c) stays under
# full warnings. The two -Wno- flags target ONLY user/dmath.h, which is copied
# verbatim from kernel/js.c (already-tested math): -Wmisleading-indentation
# fires on its one-line i64_to_str (js.c is itself non-clean under -Wextra), and
# -Wstringop-overflow is a known GCC false positive on num_to_str's digit loop
# (provably tn<=15<=sizeof tmp) seen only after inlining. calceval.h/calc.c are
# warning-clean on their own. Object name (user_calc.o) matches the build.
$(BUILD)/calc.elf: user/calc.c user/calceval.h user/dmath.h $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -fwrapv -Wall \
	      -Wno-misleading-indentation -Wno-stringop-overflow \
	      -msse2 -mfpmath=sse -Ikernel/include -c user/calc.c -o $(BUILD)/user_calc.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/user_calc.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (scientific calculator)"

# --- sheet (spreadsheet) -----------------------------------------------------
# Same shape as calc: its formula engine (user/sheeteval.h + user/dmath.h) uses
# IEEE-754 doubles, so drop -mgeneral-regs-only and add SSE. The -Wno- flags
# target ONLY dmath.h (copied verbatim from js.c; see the calc rule above for the
# first two) — the spreadsheet uses only some of dmath's math, so the unused trig
# helpers (js_tan/js_acos/...) trip -Wunused-function. sheet.c/sheeteval.h are
# warning-clean on their own.
$(BUILD)/sheet.elf: user/sheet.c user/sheeteval.h user/dmath.h $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -fwrapv -Wall \
	      -Wno-misleading-indentation -Wno-stringop-overflow -Wno-unused-function \
	      -msse2 -mfpmath=sse -Ikernel/include -c user/sheet.c -o $(BUILD)/user_sheet.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/user_sheet.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (spreadsheet)"

# --- plot (graphing calculator) ----------------------------------------------
# Same shape as sheet/calc: ploteval.h + dmath.h use IEEE-754 doubles (so SSE,
# not -mgeneral-regs-only), and being a gfx app it mallocs its pixel canvas. The
# -Wno- flags target dmath.h's unused trig helpers, exactly as in the sheet rule.
$(BUILD)/plot.elf: user/plot.c user/ploteval.h user/dmath.h $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o user/user.ld Makefile
	@mkdir -p $(BUILD)
	$(CC) -ffreestanding -nostdlib -fno-pic -fno-pie -mno-red-zone -std=gnu11 -O2 -fwrapv -Wall \
	      -Wno-misleading-indentation -Wno-stringop-overflow -Wno-unused-function \
	      -msse2 -mfpmath=sse -Ikernel/include -c user/plot.c -o $(BUILD)/user_plot.o
	$(LD) -T user/user.ld -o $@ $(BUILD)/user_plot.o $(BUILD)/user_ulib.o $(BUILD)/user_umalloc.o
	@echo "Built $@ (graphing calculator)"

# the embedded blob depends on every program ELF
$(BUILD)/kernel/asm/user_blob.o: $(USER_ELFS)

# AP bring-up trampoline (M1197): assemble the real-mode trampoline as a flat
# binary, then make the embedding blob (ap_blob.asm incbin's build/ap_trampoline.bin)
# depend on it so it's built first.
$(BUILD)/ap_trampoline.bin: kernel/asm/ap_trampoline.asm
	@mkdir -p $(BUILD)
	$(AS) -f bin $< -o $@
$(BUILD)/kernel/asm/ap_blob.o: $(BUILD)/ap_trampoline.bin

# kernel.elf is built in TWO link passes so the embedded symbol table (for panic
# backtraces — kernel/ksyms.c) holds the FINAL function addresses:
#   pass 1 links with a zero-entry stub table to learn the addresses; we then run
#   `nm` + tools/gen_ksyms.sh to emit the real table and relink. The table lands
#   in .rodata (after .text), so adding it never shifts a function address —
#   making the pass-1 addresses exact for pass 2.
KSYMSC  := $(BUILD)/ksyms_table.c
KSYMSO  := $(BUILD)/ksyms_table.o
$(KERNEL64): $(OBJS) linker.ld tools/gen_ksyms.sh
	@mkdir -p $(dir $@)
	@printf '#include "ksyms.h"\nconst struct ksym ksyms[]={{0,0}};\nconst int ksyms_count=0;\n' > $(KSYMSC)
	$(CC) $(filter-out -MMD -MP,$(CFLAGS)) -c $(KSYMSC) -o $(KSYMSO)
	$(LD) $(LDFLAGS) -o $(BUILD)/kernel_pass1.elf $(OBJS) $(KSYMSO)
	@nm -n $(BUILD)/kernel_pass1.elf | sh tools/gen_ksyms.sh > $(KSYMSC)
	$(CC) $(filter-out -MMD -MP,$(CFLAGS)) -c $(KSYMSC) -o $(KSYMSO)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(KSYMSO)

$(KERNEL): $(KERNEL64)
	$(OBJCOPY) -I elf64-x86-64 -O elf32-i386 $< $@
	@echo "Built $@ (64-bit kernel in a multiboot-loadable 32-bit container)"

# Interactive: opens a QEMU window so you can see the VGA output.
run: $(KERNEL) $(DISK) $(EXT2IMG)
	$(QEMU) $(QEMUFLAGS) $(ACCEL) -kernel $(KERNEL) $(DISKFLAGS) $(NICFLAGS) $(USBFLAGS) $(AUDIOFLAGS) -serial stdio

# --- bare metal (see BAREMETAL.md) ------------------------------------------
# Boot the Multiboot kernel via REAL GRUB (not QEMU's -kernel shortcut) — the
# path a physical machine uses. The kernel requests + consumes a Multiboot
# framebuffer (boot.asm + fb_init_mb), falling back to Bochs std-VGA under QEMU.

# BIOS GRUB rescue ISO. Needs xorriso (Gentoo: emerge dev-libs/libisoburn).
# Verify the GRUB->Multiboot handoff: qemu-system-x86_64 -cdrom build/os.iso
# (no -kernel). Deploy to a USB stick: dd if=build/os.iso of=/dev/sdX bs=4M.
iso: $(KERNEL)
	@command -v xorriso >/dev/null || { echo "iso: needs xorriso — emerge dev-libs/libisoburn"; exit 1; }
	@mkdir -p $(BUILD)/isodir/boot/grub
	cp $(KERNEL) $(BUILD)/isodir/boot/kernel32.elf
	printf 'set timeout=0\nset default=0\nmenuentry "OS-DEV" {\n\tmultiboot2 /boot/kernel32.elf\n\tboot\n}\n' > $(BUILD)/isodir/boot/grub/grub.cfg
	grub-mkrescue -d /usr/lib/grub/i386-pc -o $(BUILD)/os.iso $(BUILD)/isodir
	@echo "Built $(BUILD)/os.iso — verify: qemu-system-x86_64 -cdrom $(BUILD)/os.iso -serial stdio"

# UEFI standalone GRUB image (no xorriso needed — VERIFIED to boot under OVMF).
# Embeds the kernel in GRUB's memdisk. Deploy: copy build/BOOTX64.EFI to
# <USB>/EFI/BOOT/BOOTX64.EFI on a FAT-formatted stick and boot a UEFI machine.
efi: $(KERNEL)
	printf 'set timeout=0\nset default=0\ninsmod all_video\nmenuentry "OS-DEV" {\n\tmultiboot2 /boot/kernel32.elf\n\tboot\n}\n' > $(BUILD)/grub-efi.cfg
	grub-mkstandalone -O x86_64-efi -o $(BUILD)/BOOTX64.EFI \
	    --modules="multiboot2 normal all_video efi_gop efi_uga part_gpt fat" \
	    "boot/grub/grub.cfg=$(BUILD)/grub-efi.cfg" "boot/kernel32.elf=$(KERNEL)"
	@echo "Built $(BUILD)/BOOTX64.EFI — copy to <USB>/EFI/BOOT/BOOTX64.EFI on a FAT ESP"

# --- Real-hardware BRING-UP images (M1870) ------------------------------------
# Same as `iso`/`efi` but the kernel cmdline carries `netcon`, so the machine
# comes up with the network debug console listening on TCP 2323 even if the
# framebuffer never lights up (a known MB2/GOP risk on bare metal). Find the box
# on the LAN by its NIC's MAC in the router's DHCP table, then connect:
#   nc <ip> 2323          (type `help`)
# See docs/BAREMETAL-BRINGUP.md for the full checklist.
iso-bringup: $(KERNEL)
	@command -v xorriso >/dev/null || { echo "iso-bringup: needs xorriso — emerge dev-libs/libisoburn"; exit 1; }
	@mkdir -p $(BUILD)/isodir-bringup/boot/grub
	cp $(KERNEL) $(BUILD)/isodir-bringup/boot/kernel32.elf
	printf 'set timeout=0\nset default=0\nmenuentry "OS-DEV (netcon bring-up)" {\n\tmultiboot2 /boot/kernel32.elf netcon nodisk watchdog\n\tboot\n}\n' > $(BUILD)/isodir-bringup/boot/grub/grub.cfg
	grub-mkrescue -d /usr/lib/grub/i386-pc -o $(BUILD)/os-bringup.iso $(BUILD)/isodir-bringup
	@echo "Built $(BUILD)/os-bringup.iso (cmdline: netcon) — dd to USB: dd if=$(BUILD)/os-bringup.iso of=/dev/sdX bs=4M"

efi-bringup: $(KERNEL)
	printf 'set timeout=0\nset default=0\ninsmod all_video\nmenuentry "OS-DEV (netcon bring-up)" {\n\tmultiboot2 /boot/kernel32.elf netcon nodisk watchdog\n\tboot\n}\n' > $(BUILD)/grub-efi-bringup.cfg
	grub-mkstandalone -O x86_64-efi -o $(BUILD)/BOOTX64-bringup.EFI \
	    --modules="multiboot2 normal all_video efi_gop efi_uga part_gpt fat" \
	    "boot/grub/grub.cfg=$(BUILD)/grub-efi-bringup.cfg" "boot/kernel32.elf=$(KERNEL)"
	@echo "Built $(BUILD)/BOOTX64-bringup.EFI (cmdline: netcon) — copy to <USB>/EFI/BOOT/BOOTX64.EFI on a FAT ESP"

# Same as `run`, but with a Realtek RTL8139 NIC instead of the e1000 — boots the
# whole stack over the second card driver (kernel/rtl8139.c) so you can watch the
# serial log say "rtl8139 up" and ARP/ping/HTTP the SLIRP gateway over it.
run-rtl8139: $(KERNEL) $(DISK)
	$(QEMU) $(QEMUFLAGS) $(ACCEL) -kernel $(KERNEL) $(DISKFLAGS) $(RTLNICFLAGS) $(USBFLAGS) $(AUDIOFLAGS) -serial stdio

# Same as `run`, but with a LEGACY virtio-net NIC instead of the e1000 — boots the
# whole stack over the paravirtual NIC driver (kernel/virtio_net.c) so you can
# watch the serial log say "virtio-net up" and ARP/ping/HTTP the SLIRP gateway over it.
run-virtio-net: $(KERNEL) $(DISK)
	$(QEMU) $(QEMUFLAGS) $(ACCEL) -kernel $(KERNEL) $(DISKFLAGS) $(VIRTIONICFLAGS) $(USBFLAGS) $(AUDIOFLAGS) -serial stdio

# Headless in-guest assertion that the RTL8139 driver brings up the full stack:
# boots with -device rtl8139 (no e1000) and asserts the network markers print
# over it. SKIPs cleanly if QEMU is absent. (Companion to `boottest`, which
# covers the e1000 path.)
rtl8139test: $(KERNEL) $(DISK)
	@tests/run-rtl8139-tests.sh

# Headless in-guest assertion that the virtio-net driver brings up the full stack:
# boots with a LEGACY virtio-net-pci NIC (no e1000) and asserts the network markers
# print over it — the driver bound + read its MAC, ARP resolved the gateway, ICMP
# echo succeeded. SKIPs cleanly if QEMU is absent. (Companion to `boottest`, the
# e1000 path; and to `rtl8139test`, the other concrete NIC.)
virtionettest: $(KERNEL) $(DISK)
	@tests/run-virtio-net-tests.sh

# Headless in-guest assertion for the virtio-blk driver (kernel/virtio_blk.c):
# attaches a SECOND disk over legacy virtio (-device virtio-blk-pci,disable-
# modern=on), boots, and asserts the driver read that disk's KNOWN per-sector
# content back (host-computed checksums + marker) and the write round-trip. The
# boot disk stays on legacy ATA. SKIPs cleanly if QEMU/python3 absent. (Companion
# to `boottest`, which has no virtio disk -> the driver must cleanly no-op there.)
virtioblktest: $(KERNEL) $(DISK)
	@tests/run-virtio-blk-tests.sh

# Headless in-guest assertion for the virtio-rng driver (kernel/virtio_rng.c):
# attaches a virtio entropy device (-device virtio-rng-pci), boots, and asserts
# the driver brought it up and DMA'd real entropy in — the boot self-test draws
# two batches over the virtqueue and proves them nonzero + differing. The boot
# disk stays on legacy ATA. SKIPs cleanly if QEMU absent. (Companion to
# `boottest`, which has no virtio-rng device -> the driver must cleanly no-op.)
virtiorngtest: $(KERNEL) $(DISK)
	@tests/run-virtio-rng-tests.sh

# Headless in-guest assertion for the virtio-console driver (kernel/virtio_console.c):
# attaches a virtio-serial bus + a console port whose host end is a FILE, boots,
# and asserts the boot self-test's transmit-queue write actually reached that
# host file (guest->host data path), with the desktop reached and no fault. SKIPs
# cleanly if QEMU absent. (Companion to `boottest`, which has no virtio-console
# -> the driver must cleanly no-op.)
virtioconsoletest: $(KERNEL) $(DISK)
	@tests/run-virtio-console-tests.sh

# Headless in-guest assertion for the NVMe driver (kernel/nvme.c): attaches a
# SECOND disk over NVMe (-device nvme + -drive ...,if=none), boots, and asserts
# the driver brought the controller up, IDENTIFYd namespace 1, read that disk's
# KNOWN per-sector content back (host-computed checksums + marker), and the write
# round-trip. The boot disk stays on legacy ATA. SKIPs cleanly if QEMU/python3
# absent. (Companion to `boottest`, which has no NVMe disk -> the driver cleanly
# no-ops there.)
nvmetest: $(KERNEL) $(DISK)
	@tests/run-nvme-tests.sh

# Headless in-guest assertion for the floppy controller driver (kernel/floppy.c):
# attaches a 1.44 MB floppy image (-drive ...,if=floppy), boots, and asserts the
# 82077AA driver RESET + RECALIBRATEd the controller and read that diskette's
# KNOWN per-sector content back over ISA DMA (host-computed checksums + marker),
# including a multi-sector read. Unlike the other DMA drivers (PCI bus-master),
# the floppy moves data through the legacy 8237 ISA DMA controller (channel 2 +
# a low-RAM, 64-KiB-bounded bounce buffer). The boot disk stays on legacy ATA.
# SKIPs cleanly if QEMU/python3 absent. (Companion to `boottest`, which has no
# floppy -> the driver must cleanly no-op there.)
floppytest: $(KERNEL) $(DISK)
	@tests/run-floppy-tests.sh

# Headless in-guest assertion for ATA multi-drive enumeration + MBR/GPT partition
# parsing (kernel/ata.c + kernel/partition.c): attaches a SECOND IDE disk with an
# MBR + a FAT32 partition (primary slave) and a THIRD with a GPT + a FAT32
# partition (secondary master), boots, and asserts the kernel enumerated all four
# legacy ATA slots, parsed BOTH partition tables correctly (host-computed
# scheme/type/start-LBA/sectors), and read a known file (HELLO.TXT) back from
# each partition's FAT32 at its offset. The boot disk stays on legacy ATA (index
# 0, bare FAT32, no table). SKIPs cleanly if QEMU/python3 absent. (Companion to
# `boottest`, which has no extra disks -> only drive 0 present, no table -> no-op.)
parttest: $(KERNEL) $(DISK)
	@tests/run-partition-tests.sh

# Headless in-guest assertion for the generic block-device layer + read-only
# multi-volume FAT32 browsing over ALL storage drivers (kernel/blockdev.c + the
# device-agnostic fatvol_list/fatvol_find in kernel/partition.c): attaches a
# SECOND disk over LEGACY virtio-blk whose content is a bare FAT32 filesystem with
# KNOWN root files (GREET.TXT, NUMBERS.DAT) + a subdir, boots, and asserts
# blockdev_enumerate() registered the virtio-blk device, MOUNTED its FAT32 volume
# read-only, and LISTED those known entries (names + sizes) -> proving the disk is
# browsable over a non-ATA driver, not just self-tested. The boot disk stays on
# legacy ATA (bare FAT32) and the boot mount + fat32.c/vfs.c are untouched (this
# layer is additive + read-only). SKIPs cleanly if QEMU/python3 absent. (Companion
# to `boottest`, which has only the ATA boot disk -> it alone is registered + its
# bare FAT32 listed, a clean no-fault path.)
blockdevtest: $(KERNEL) $(DISK)
	@tests/run-blockdev-tests.sh

# Headless in-guest assertion for software RAID (device-mapper, kernel/dm.c):
# attaches 3 non-boot SATA disks on an AHCI HBA so dm_selftest builds RAID-1/0/5
# volumes and proves mirror redundancy, stripe distribution, and RAID-5 parity
# reconstruction (single-disk fault tolerance). Boot stays on legacy ATA; the
# self-test is a no-op without extra disks, so boottest is unaffected.
raidtest: $(KERNEL) $(DISK)
	@tests/run-raid-tests.sh

# In-guest assertion for the AHCI/SATA IDENTIFY-DEVICE capacity query (M1715):
# attaches ONE known-size (16384-sector) SATA disk on an AHCI HBA and asserts the
# driver reports that exact capacity and the block layer sizes + I/Os it at the
# true last sector. Boot stays on legacy ATA; the SATA disk is scratch.
ahcitest: $(KERNEL) $(DISK)
	@tests/run-ahci-tests.sh

# In-guest test of the ATAPI CD-ROM read driver (kernel/atapi.c, M1852): boots with
# a minimal ISO on -cdrom and asserts the PACKET READ(10) of the PVD.
atapitest: $(KERNEL) $(DISK)
	@tests/run-atapi-tests.sh

# In-guest assertion for the ATA driver's LBA48 path (M1721): attaches a 160 GiB
# sparse ATA disk (primary slave) and asserts a write+read-back at a sector past
# the 128 GiB LBA28 boundary round-trips. Boot stays on the LBA28 disk 0.
atalba48test: $(KERNEL) $(DISK)
	@tests/run-ata-lba48-tests.sh

# In-guest HTTP SERVER test (M1304): boots with a host->guest TCP port forward,
# runs the `httpd` shell command (net_tcp_serve), then curls the forwarded port
# from the HOST and asserts the served page comes back -- the inbound-connection
# counterpart of boottest's outbound client. Needs socat + curl on the host.
httpdtest: $(KERNEL) $(DISK)
	@tests/run-httpd-tests.sh

# Headless in-guest assertion for the bus-master IDE DMA path (kernel/ata.c):
# boots with the NORMAL IDE boot disk (-drive ...,if=ide, on the bus-master-capable
# PIIX3 IDE controller) and asserts the kernel's DMA read path returned BYTE-
# IDENTICAL data to the trusted PIO path -- ata_dma_selftest() DMA-reads a few of
# the boot disk's sectors, PIO-reads the same, and logs "DMA==PIO OK" per sector
# (plus a DMA write round-trip). The boot path (PIO ata_read/ata_write) is
# untouched: FAT32 still mounts on legacy ATA via PIO. SKIPs cleanly if QEMU is
# absent. (Companion to `boottest`, which uses the same disk but doesn't assert
# the DMA==PIO comparison.)
idedmatest: $(KERNEL) $(DISK)
	@tests/run-ide-dma-tests.sh

# Headless in-guest assertion for the virtio-gpu driver (kernel/virtio_gpu.c):
# attaches a virtio-gpu device (-device virtio-gpu-pci) ALONGSIDE the std-VGA
# display, boots, and asserts the driver brought the modern paravirtual 2D GPU
# up (modern PCI handshake + control virtqueue), read scanout 0's resolution,
# created+attached+scanned-out a backing resource, and ran the full present
# cycle (TRANSFER_TO_HOST_2D + RESOURCE_FLUSH each returned OK) with no fault —
# while the std-VGA boot display path (gfxtest) stays unaffected. SKIPs cleanly
# if QEMU absent. (Companion to boottest/gfxtest, which have no virtio-gpu ->
# the driver must cleanly no-op and the std-VGA desktop must still render.)
virtiogputest: $(KERNEL) $(DISK)
	@tests/run-virtio-gpu-tests.sh

# Headless in-guest assertion for the VMware SVGA-II driver (kernel/svga.c):
# attaches a VMware SVGA-II device (-device vmware-svga) ALONGSIDE the std-VGA
# display, boots, and asserts the driver confirmed SVGA_ID_2 over the I/O-port
# index/value register file, read the linear framebuffer (BAR1) + command FIFO
# (BAR2) addresses+sizes, set a mode, wrote a colour-band test pattern to the
# framebuffer, emitted an SVGA_CMD_UPDATE into the FIFO + synced, and read the
# registers back OK with no fault -- while the std-VGA boot display path
# (gfxtest) stays unaffected. SKIPs cleanly if QEMU (or the vmware-svga device)
# is absent. NOTE: distinct from `svgtest` (the SVG image rasterizer fuzz test).
svgatest: $(KERNEL) $(DISK)
	@tests/run-svga-tests.sh

# Headless in-guest assertion for the USB mass-storage driver (kernel/usb_storage.c):
# attaches a USB flash disk as a usb-storage device ON THE SAME UHCI BUS as the
# existing usb-tablet (-device usb-storage,bus=uhci.0,port=2 + -drive ...,if=none),
# boots, and asserts the driver enumerated the Bulk-Only-Transport / SCSI device
# (class 08 / subclass 06 / proto 50 + its bulk endpoints), READ CAPACITYd it,
# read that disk's KNOWN per-sector content back over BOT (host-computed checksums
# + marker), and the WRITE(10) round-trip. The boot disk stays on legacy ATA and
# the USB tablet stays up (shared controller). SKIPs cleanly if QEMU/python3
# absent. (Companion to `boottest`, which has no usb-storage -> the driver must
# cleanly no-op there and the tablet must still come up.)
usbstoragetest: $(KERNEL) $(DISK)
	@tests/run-usb-storage-tests.sh

# Headless in-guest assertion for the USB HID boot-keyboard driver (kernel/usb_kbd.c):
# attaches a usb-kbd ON THE SAME UHCI BUS as the existing usb-tablet (-device
# usb-kbd,bus=uhci.0,port=2), boots, and asserts the driver enumerated the HID
# boot keyboard (class 03 / subclass 01 = Boot / proto 01 = Keyboard + its
# interrupt-IN endpoint), selected boot protocol (HID SET_PROTOCOL(0) ok), and
# DECODED keystrokes injected via QEMU's `sendkey` monitor command over the
# interrupt endpoint. The PS/2 keyboard stays the primary input and the USB tablet
# stays up (shared controller). SKIPs cleanly if QEMU/socat absent. (Companion to
# `boottest`, which has no usb-kbd -> the driver must cleanly no-op there and the
# tablet + PS/2 keyboard must still come up.)
usbkbdtest: $(KERNEL) $(DISK)
	@tests/run-usb-kbd-tests.sh

# Headless in-guest assertion for the EHCI (USB 2.0) host-controller driver
# (kernel/ehci.c): attaches an EHCI controller (-device usb-ehci) WITH a usb-storage
# flash disk on ITS bus (-device usb-storage,bus=ehci.0) — a SEPARATE, additional
# USB host alongside the existing UHCI controller + tablet — boots, and asserts the
# driver brought the USB 2.0 controller up (PCI class 0C/03/20 probe + HC reset +
# async QH/qTD schedule running), reset+enabled a high-speed root port, ENUMERATED
# the device over EHCI control transfers (device/config descriptors read, address
# assigned, SET_CONFIGURATION), and — the stretch bulk path — read SECTOR 0 over
# EHCI bulk (BOT/SCSI READ(10)) returning that disk's KNOWN content (host-computed
# checksum + marker). The UHCI tablet stays up and boot stays on legacy ATA. SKIPs
# cleanly if QEMU/python3 absent. (Companion to `boottest`, which has no EHCI
# controller -> the driver must cleanly no-op there and UHCI + the tablet stay up.)
ehcitest: $(KERNEL) $(DISK)
	@tests/run-ehci-tests.sh

# Headless in-guest assertion for the xHCI (USB 3.0) host-controller driver
# (kernel/xhci.c): attaches an xHCI controller (-device qemu-xhci) WITH a usb-storage
# flash disk on ITS bus (-device usb-storage,bus=xhci.0) — a SEPARATE, additional
# USB host alongside the existing UHCI controller + tablet AND the EHCI controller —
# boots, and asserts the driver brought the USB 3.0 controller up (PCI class 0C/03/30
# probe + HC reset + command/event TRB rings running), that the rings work end to end
# (ENABLE SLOT returned a slot id), reset+detected a root port, ENUMERATED the device
# over xHCI control transfers (ENABLE SLOT + ADDRESS DEVICE, device/config descriptors
# read over the EP0 TRB ring, SET_CONFIGURATION), and — the stretch bulk path — read
# SECTOR 0 over xHCI bulk (BOT/SCSI READ(10)) returning that disk's KNOWN content
# (host-computed checksum + marker). The UHCI tablet + EHCI stay up and boot stays on
# legacy ATA. SKIPs cleanly if QEMU/python3 absent (or the qemu-xhci device is missing).
# (Companion to `boottest`, which has no xHCI controller -> the driver must cleanly
# no-op there and UHCI + EHCI + the tablet stay up.)
xhcitest: $(KERNEL) $(DISK)
	@tests/run-xhci-tests.sh

# Same as `run`, but with an Intel HD Audio controller (`intel-hda` + `hda-output`)
# instead of AC'97 — boots the whole desktop over the HDA driver (kernel/hda.c).
# Watch the serial log say "HDA audio: ..." and "audio output: hda"; the jukebox /
# tone / DOOM all play through it.
run-hda: $(KERNEL) $(DISK)
	$(QEMU) $(QEMUFLAGS) $(ACCEL) -kernel $(KERNEL) $(DISKFLAGS) $(NICFLAGS) $(USBFLAGS) $(HDAAUDIOFLAGS) -serial stdio

# Headless in-guest assertion that the HDA driver brings up an audio output path
# AND its stream DMA actually advances: boots with -device intel-hda + hda-output
# (no AC'97), asserts the controller reset + codec enum + output verbs succeeded
# and the stream's DMA position register advances while a tone plays — with no
# fault. SKIPs cleanly if QEMU is absent. (Companion to `boottest`, the AC'97 path.)
hdatest: $(KERNEL) $(DISK)
	@tests/run-hda-tests.sh

# Headless smoke test: no window, capture serial, kill after a few seconds.
# Used to confirm the kernel boots without needing a display.
test: $(KERNEL) $(DISK)
	@echo "--- booting headless, capturing COM1 (5s) ---"
	@timeout 5 $(QEMU) $(QEMUFLAGS) -kernel $(KERNEL) $(DISKFLAGS) $(NICFLAGS) $(USBFLAGS) $(TESTAUDIOFLAGS) \
	    -display none -serial stdio ; \
	    echo "--- qemu exited ---"

# Host-side regression test of the from-scratch JavaScript engine (ASan+UBSan).
jstest:
	@tests/run-js-tests.sh

# Host-side regression + fuzz test of the image decoders (ASan+UBSan).
imgtest:
	@tests/run-img-tests.sh

# Host-side fuzz test of the X.509 certificate parser (ASan+UBSan).
x509test:
	@tests/run-x509-tests.sh

# Host-side fuzz test of kernel/tls.c's UNTRUSTED record + Certificate-message
# framing parsers, against the real crypto (ASan+UBSan).
tlsfuzztest:
	@tests/run-tls-tests.sh

# Host-side fuzz test of the TCP/IP packet parser + reassembly (ASan+UBSan).
nettest:
	@tests/run-net-tests.sh

# Host-side proof of the reliable TCP sender (retransmit/RTO/fast-rtx/flow control, M1886).
tcpreliabletest:
	@tests/run-tcp-reliable-test.sh

# Host-side fuzz test of the FAT32 read path over corrupt/cyclic on-disk structures (ASan+UBSan).
fstest:
	@tests/run-fs-tests.sh

# PHASE 5: OS-DEV builds its OWN kernel inside itself, and that kernel boots.
# NOT in `check`: stage 1 compiles 136 real source files with a real compiler
# under TCG and takes ~15 minutes. Run it when the self-hosting claim needs
# re-proving.
# PHASE 6: real Node.js in-guest. NOT in `check` -- V8 under TCG is minutes per
# start and this runs Node three times.
nodetest: $(KERNEL) $(DISK) $(EXT2IMG)
	@sh tests/run-node-test.sh

selfhosttest: $(KERNEL) $(DISK) $(EXT2IMG)
	@sh tests/run-selfhost-test.sh

linuxabitest: $(KERNEL) $(DISK) $(EXT2IMG)
	@tests/run-linuxabi-tests.sh

ext2test:
	@tests/run-ext2-tests.sh

xattrtest:
	@tests/run-xattr-tests.sh

iso9660test:
	@tests/run-iso9660-tests.sh

# Host-side known-answer test of the crypto primitives vs published RFC/FIPS vectors (ASan+UBSan).
kattest:
	@tests/run-crypto-tests.sh

# Host-side property fuzz of bn_mod vs Python's arbitrary-precision integers, 1..8320-bit (ASan+UBSan).
bignumfuzztest:
	@tests/run-bignum-fuzz-tests.sh

# Host-side property fuzz of Barrett reduction + bn_modexp (M1536) vs Python's
# arbitrary-precision integers (ASan+UBSan).
barrettfuzztest:
	@tests/run-barrett-fuzz-tests.sh

# Host-side differential fuzz of memcpy/memset/memmove vs a naive reference (every overlap shape, ASan+UBSan).
stringtest:
	@tests/run-string-tests.sh

# Host-side fuzz test of the SVG rasterizer over adversarial/truncated XML (ASan+UBSan).
svgtest:
	@tests/run-svg-tests.sh

# Host-side round-trip test of the DEFLATE/gzip compressor vs the decoder (ASan+UBSan).
deflatetest:
	@tests/run-deflate-tests.sh

# Host-side round-trip test of the PNG encoder vs the decoder (ASan+UBSan).
pngenctest:
	@tests/run-pngenc-tests.sh

# Host-side extraction + corrupt-input fuzz of the ZIP extractor (ASan+UBSan).
ziptest:
	@tests/run-zip-tests.sh

# Host-side extraction + corrupt-input fuzz of the tar (ustar) extractor (ASan+UBSan).
tartest:
	@tests/run-tar-tests.sh

# Host-side regression test of the userspace malloc/free allocator (ASan+UBSan).
heaptest:
	@tests/run-heap-tests.sh

# Host-side crash-consistency proof of the write-ahead journal (kernel/journal.c,
# M1864): power-loss injected at every write; recovered state is never torn.
journaltest:
	@tests/run-journal-tests.sh

# Host-side regression + fuzz test of the WAV header parser (ASan+UBSan).
wavtest:
	@tests/run-wav-tests.sh

# Host-side regression + fuzz test of the AML namespace parser (ASan+UBSan):
# AliasOp/FieldOp namespace correctness + truncated/random DSDT bytes.
acpiamltest:
	@tests/run-acpiaml-tests.sh

# Host-side regression + fuzz test of the VP8L (WebP Lossless) decoder (ASan+UBSan):
# real cwebp round-trips (gradient/palette/noise/photo shapes) + malformed-input fuzz.
webptest:
	@tests/run-webp-tests.sh

# Host-side regression + fuzz test of the ELF64 loader (ASan+UBSan): the ring-3
# trust boundary — a malformed program must never OOB-read or escape its range.
elftest:
	@tests/run-elf-tests.sh

# Host-side regression + fuzz test of the HTTP/1.x response parsers (ASan+UBSan):
# chunked-transfer decode + header scans over untrusted/truncated server bytes.
httptest:
	@tests/run-http-tests.sh

# Host-side torture + invariant test of the KERNEL heap kmalloc/kfree (ASan+UBSan).
kheaptest:
	@tests/run-kheap-tests.sh

# Host-side fuzz of the engine's JSON.parse over untrusted/malformed/deep input (ASan+UBSan).
jsonfuzztest:
	@tests/run-jsonfuzz-tests.sh

# Host-side fuzz of the engine's regex (compile + backtracking search) over ReDoS/malformed input (ASan+UBSan).
regexfuzztest:
	@tests/run-regexfuzz-tests.sh

# Host-side fuzz of the full JS parse+run pipeline on untrusted/malformed source (ASan+UBSan).
jssrcfuzztest:
	@tests/run-jssrcfuzz-tests.sh

# Host-side fuzz of the HTML entity decoder over untrusted/malformed page bytes (ASan+UBSan).
htmlentfuzztest:
	@tests/run-htmlentfuzz-tests.sh

# Host-side fuzz of the HTML attribute scanners over untrusted/malformed tag bytes (ASan+UBSan).
htmlattrtest:
	@tests/run-htmlattr-tests.sh

# Host-side fuzz of the URL splitter/resolver over untrusted/malformed URLs (ASan+UBSan).
urltest:
	@tests/run-url-tests.sh

# Host-side fuzz of the CSS colour parser over untrusted/malformed colour tokens (ASan+UBSan).
colortest:
	@tests/run-color-tests.sh

# Host-side fuzz of the inline-style property scanner over untrusted style="" bytes (ASan+UBSan).
csstest:
	@tests/run-css-tests.sh

# Host-side regression + fuzz of the CSS simple-selector parser (kernel/include/cssel.h, ASan+UBSan).
csseltest:
	@tests/run-cssel-tests.sh

# Host-side regression + fuzz of the reader-mode content extractor (kernel/reader.c, ASan+UBSan).
readertest:
	@tests/run-reader-tests.sh

# Host-side regression + fuzz of the shell's grep regex matcher (user/shgrep.h, ASan+UBSan).
shgreptest:
	@tests/run-shgrep-tests.sh

# Host-side regression + fuzz of the shell's sed substitution engine (user/shsed.h, ASan+UBSan).
shsedtest:
	@tests/run-shsed-tests.sh

# Host-side regression + fuzz of the shell's $((expr)) integer evaluator (user/shmath.h, ASan+UBSan).
shmathtest:
	@tests/run-shmath-tests.sh

# Host-side regression + fuzz of the shell's ';' statement splitter (user/shsplit.h, ASan+UBSan).
shsplittest:
	@tests/run-shsplit-tests.sh

# Host-side regression + fuzz of the shell's brace expansion (user/shbrace.h, ASan+UBSan).
shbracetest:
	@tests/run-shbrace-tests.sh

# Host-side regression + fuzz of the shell's parameter/variable expander (user/shexpand.h, ASan+UBSan).
shexpandtest:
	@tests/run-shexpand-tests.sh

# Host-side regression + fuzz of the shell's quoting pass (user/shquote.h, ASan+UBSan).
shquotetest:
	@tests/run-shquote-tests.sh

# Host-side regression of the shell's test / [ ] conditional evaluator (user/shtest.h, ASan+UBSan).
shtesttest:
	@tests/run-shtest-tests.sh

# Host-side regression of the `ls -l` formatting helpers (user/lsfmt.h, ASan+UBSan).
lsfmttest:
	@tests/run-lsfmt-tests.sh

# Host-side regression of the shell's `sort` key helpers (user/shsort.h, ASan+UBSan).
shsorttest:
	@tests/run-shsort-tests.sh

# Host-side regression of the shell tr/cut text helpers (user/shtxt.h, ASan+UBSan).
shtxttest:
	@tests/run-shtxt-tests.sh

# Host-side regression + fuzz of the WebSocket RFC 6455 frame codec (kernel/wsframe.h, ASan+UBSan).
wsframetest:
	@tests/run-wsframe-tests.sh

# Host-side regression of the shared USB Mass-Storage Bulk-Only-Transport + SCSI
# layer (kernel/usbbot.h, ASan+UBSan) against a mock BOT device: CBW/CSW wire
# format, tag echo-checking, the IN/OUT residue trust rules, READ/WRITE(10)
# round-trips, chunking, capacity bounds, and injected device faults. This is the
# code every USB host controller (UHCI/EHCI/xHCI) now shares.
usbbottest:
	@tests/run-usbbot-tests.sh

# Host-side known-answer tests for the CSS box-layout engine (kernel/layout.h,
# ASan+UBSan): the CSS 2.1 §10.3.3 width constraint incl. auto margins/centring,
# border/padding, nested block stacking, §8.3.1 margin collapsing (siblings,
# parent<->first-child, parent<->last-child), auto vs explicit height,
# display:none, greedy inline wrapping, and hostile input. Pure, so the layout
# rules are unit-testable off-target before any of it is wired into browser.c.
layouttest:
	@tests/run-layout-tests.sh

# In-guest regression for the browser's SOLVED box-model geometry: opens
# LAYCHK.HTM (each case in a unique background colour), dumps the framebuffer, and
# asserts the geometry by bounding box — §10.3.3 used widths including padding,
# auto-margin centring and left/right alignment, a nested background staying inset
# within its padded parent, and the border enclosing the padding box. The layout
# RULES are covered by layouttest; this covers the browser-side WIRING, which had
# no automated coverage until M1902 (three real bugs coexisted in a green tree).
layoutrendertest: $(KERNEL) $(DISK)
	@tests/run-layout-render-tests.sh

# Headless assertion for the DESKTOP / window manager (M1925). The desktop had no
# automated coverage at all: window management and virtual desktops were each
# verified once by a human looking at a screenshot. Drives the real WM through the
# QEMU monitor and asserts relative properties between framebuffer dumps -- the
# strongest being that switching workspaces away and back restores the screen
# byte-identically.
desktoptest: $(KERNEL) $(DISK)
	@tests/run-desktop-tests.sh

# Headless assertion for the POSIX IPC surface (M1906): mqueue priority ordering,
# named-semaphore O_CREAT/O_EXCL + non-blocking trywait, shm frame sharing + size
# cap, the pty master->slave data path, flock exclusion/sharing/pid-release,
# inotify filtering, and eventfd accumulate+drain. ~2,700 lines that had no
# automated assertions at all before this. Kernel-side because ring-3 app output
# is not mirrored to COM1.
ipctest: $(KERNEL) $(DISK)
	@tests/run-ipc-tests.sh

# Host-side regression of the WebSocket client handshake helpers (kernel/wsclient.h, ASan+UBSan).
wsclienttest:
	@tests/run-wsclient-tests.sh

# Host-side regression of SHA-1 (kernel/sha1.h, added for the WebSocket server handshake, ASan+UBSan).
sha1test:
	@tests/run-sha1-tests.sh

# Host-side regression + fuzz of the calculator app's expression evaluator (user/calceval.h, ASan+UBSan+-fwrapv).
calctest:
	@tests/run-calc-tests.sh

sheettest:
	@tests/run-sheet-tests.sh

# Host-side regression of the graphing calculator's expression evaluator (user/ploteval.h, ASan+UBSan+-fwrapv).
plottest:
	@tests/run-plot-tests.sh

# Host-side regression of the JSON viewer's validator/pretty-printer (user/jsoncore.h, ASan+UBSan+-fwrapv).
jsoncoretest:
	@tests/run-json-tests.sh

# Host-side regression of the diff viewer's line-diff engine (user/diffcore.h, ASan+UBSan+-fwrapv).
difftest:
	@tests/run-diff-tests.sh

# Host-side regression + fuzz of the browser's Markdown/CSV -> HTML converters (kernel/mdconv.h, ASan+UBSan+-fwrapv).
mdtest:
	@tests/run-md-tests.sh

# Host-side regression of the editor's undo grouping (user/editor.c, ASan+UBSan+-fwrapv).
editortest:
	@tests/run-editor-tests.sh

# Host-side regression of the archive browser's listing engine (user/arccore.h, ASan+UBSan+-fwrapv).
arctest:
	@tests/run-arc-tests.sh

# Host-side regression of the hash tool's CRC-32 + Base64 core (user/hashcore.h, ASan+UBSan+-fwrapv).
hashtest:
	@tests/run-hash-tests.sh

# Host-side regression + fuzz of the shell's cd path resolver (user/normpath.h, ASan+UBSan).
normpathtest:
	@tests/run-normpath-tests.sh

# Host-side regression of the terminal's Tab-completion core (kernel/complete.h, ASan+UBSan).
completetest:
	@tests/run-complete-tests.sh

# In-guest boot assertion: boots the real kernel headless and asserts every
# bring-up marker is present with no crash (exercises the whole driver stack,
# not one .c in isolation). SKIPs cleanly if QEMU is absent.
boottest: $(KERNEL) $(DISK)
	@tests/run-boot-tests.sh

# In-guest assertion that a kernel stack overflow is caught + diagnosed by the
# guard page (M1495), with a working high-VA backtrace (M1496) -- not the silent
# heap corruption it used to be (M1491). Boots `-append kstackover` (M1498); the
# companion boottest boots WITHOUT the flag, so the deliberate overflow never
# fires there. The only suite that triggers a real kernel fault end-to-end.
kstacktest: $(KERNEL) $(DISK)
	@tests/run-kstack-test.sh

# In-guest assertion that a RING-3 user-stack overflow is caught by the M1499
# guard page -- it faults cleanly on the guard (CR2 ~ USTACK_BASE 0x50000000) and
# kills only the app, leaving the kernel running. Boots `-append ustackover`
# (M1500), which spawns `crash stack` (user/crash.c).
ustacktest: $(KERNEL) $(DISK)
	@tests/run-ustack-test.sh

# In-guest assertion that W^X/NX is enforced (not just configured): booting
# `-append wxtest` (M1501) makes the kernel try to execute a byte in a .bss
# buffer; it must take an instruction-fetch #PF instead of running -- the headline
# anti-code-injection guarantee. Proves vmm_harden_kernel's NX is real.
wxtest: $(KERNEL) $(DISK)
	@tests/run-wx-test.sh

# In-guest assertion that SMEP is enforced: booting `-append smeptest` (M1502, on
# a SMEP-capable `-cpu qemu64,+smep` model) makes the kernel try to execute a user
# (PTE_USER) page; it must fault instead of running -- the ret2user defence.
smeptest: $(KERNEL) $(DISK)
	@tests/run-smep-test.sh

# In-guest assertion that smp_thread (M1530) runs real independent kernel
# threads across MULTIPLE cores concurrently: booting `-append smpthreadtest`
# spawns 4 threads racing on a shared counter, each recording its own core.
smpthreadtest: $(KERNEL) $(DISK)
	@tests/run-smpthread-test.sh

# In-guest assertion that the GENERAL (M1531) scheduler runs ordinary
# (pin_core=-1) tasks -- the kind every kernel thread AND every ring-3 process
# is -- concurrently across MULTIPLE cores, correctly. Distinct from
# smpthreadtest (which covers the separate M1530 smp_thread mechanism): this is
# the cross-core migration that actually lets a user app run on an AP (M1862).
smpschedtest: $(KERNEL) $(DISK)
	@tests/run-smpsched-test.sh

# In-guest crash-recovery proof for the write-ahead journal (kernel/journal.c)
# on REAL ata hardware: commit+checkpoint, then a simulated power loss right
# after the commit point, then journal_recover() replays the committed txn (M1865).
journalguesttest: $(KERNEL) $(DISK)
	@tests/run-journal-guest-test.sh

# In-guest proof that a REAL file create on the LIVE FAT32 boot filesystem is
# crash-atomic: journaled metadata (ordered mode) + a simulated power loss after
# the commit point, then journal_recover() replays it so the file appears with
# the exact content, atomically (M1866). Runs on a copy of the disk image.
fatjournaltest: $(KERNEL) $(DISK)
	@tests/run-fatjournal-test.sh

# netcontest (M1870): boot `-append netcon`, forward host:12323 -> guest:2323,
# then a host TCP client drives a persistent multi-command session (echo/mem/cpu/
# uptime/ip/ps/help) against the in-kernel network debug console and asserts the
# responses -- proving the real-hardware remote-console lifeline works end to end.
netcontest: $(KERNEL) $(DISK)
	@tests/run-netcon-test.sh

# efitest (M1871): the REAL bare-metal boot path — build the netcon bring-up EFI
# image and boot it through GRUB's multiboot2 handoff under QEMU + OVMF (UEFI),
# then drive netcon over a forwarded port. Regression guard for the mb2_to_mb1
# cmdline-tag fix (a GRUB-booted kernel now actually receives its cmdline). NOT in
# `make check` (needs OVMF firmware + is slow); skips cleanly if OVMF is absent.
efitest: $(KERNEL) $(DISK)
	@tests/run-efi-netcon-test.sh

# gdbstubtest (M1204): boot `-append gdbstub`, attach real host gdb over COM2,
# assert it reads + symbolizes registers. Skips if gdb/qemu are unavailable.
gdbstubtest: $(KERNEL)
	@tests/run-gdbstub-test.sh

# In-guest GRAPHICAL assertion: boots, lets the desktop paint, captures the VGA
# framebuffer via the QEMU monitor and asserts it rendered (compositor / fb /
# font / vga.c -- no other in-guest coverage). SKIPs if QEMU/socat/python3 absent.
gfxtest: $(KERNEL) $(DISK)
	@tests/run-gfx-tests.sh

# In-guest BROWSER assertion: launch the Browser from the Apps menu and assert
# its (network-free) home page rendered -- the end-to-end guard for parse_html,
# which is too coupled to fuzz in isolation. SKIPs if QEMU/socat/python3 absent.
browsertest: $(KERNEL) $(DISK)
	@tests/run-browser-tests.sh

# PHASE 8: Firefox in-guest. A 268 MB install with an 83-library closure. NOT
# in `make check`: minutes per start under TCG. SKIPs when it was never staged.
firefoxtest: $(KERNEL) $(DISK) $(EXT2IMG)
	@tests/run-firefox-test.sh

# PHASE 8: OS-DEV's own Wayland compositor, exercised by a REAL libwayland
# client (the same library Firefox uses). In `make check`: one 2 GiB boot.
waylandtest: $(KERNEL) $(DISK) $(EXT2IMG)
	@tests/run-wayland-tests.sh

# PHASE 7: Claude Code in-guest. A 214 MB non-PIE ET_EXEC built with Bun, so
# the engine is JavaScriptCore. NOT in `make check`: every start is minutes
# under TCG. SKIPs cleanly when it was never staged.
claudetest: $(KERNEL) $(DISK) $(EXT2IMG)
	@tests/run-claude-test.sh

# AF_INET sockets through the Linux ABI (M1967): a DNS lookup over UDP and an
# HTTP request over TCP, both driven by poll(). The same path Node uses, run as
# a plain static-PIE binary so a failure is diagnosable in three minutes rather
# than inside a V8 run. Needs the real internet; SKIPs without it.
lxinettest: $(KERNEL) $(DISK) $(EXT2IMG)
	@tests/run-lxinet-tests.sh

# Run every host-side regression/fuzz/KAT suite, then the in-guest boot assertions.
# ('test' above is the human-readable headless boot; 'boottest'/'gfxtest' are asserted.)
#
# PARALLEL (M1965). There is no KVM on the usual host -- no nested virt -- so
# every guest suite is TCG, ~75x slower than native, and the suite was running
# them one at a time on a 24-core machine. The whole cost is QEMU: a full
# rebuild of the kernel, the FAT volume and the 1.5 GB ext2 image together take
# about two seconds.
#
# What made serialisation necessary was that all 37 guest suites open the SAME
# build/fat.img read-write, so any suite that wrote to it could corrupt another
# suite's disk mid-read. They now boot with QEMU's -snapshot, which sends guest
# writes to a throwaway overlay and leaves the backing image untouched -- a
# correctness improvement on its own, and what makes concurrency safe. Scratch
# images, monitor sockets and forwarded host ports were already per-suite.
# (run-selfhost-test.sh is deliberately NOT snapshotted: it builds a kernel
# INSIDE the guest and debugfs pulls it back out of the image afterwards, so
# discarding the guest's writes would discard the artefact under test.)
#
# -Otarget keeps each suite's output together instead of interleaving it, so a
# failure is still readable. Override the width with CHECKJOBS=1 to serialise.
#
# SIX suites stay SERIAL, and not out of caution: gfxtest, browsertest,
# layoutrendertest, desktoptest, httpdtest and usbkbdtest drive the guest
# through the QEMU monitor (screendump / sendkey / mouse) and wait with FIXED
# `sleep`s rather than by polling for a condition. A fixed sleep is an
# assumption about how fast the host is, and under six concurrent TCG guests
# that assumption is simply wrong -- layoutrendertest failed with "no
# framebuffer dump produced" at -j6 and passes alone. The honest fix is to make
# those suites wait on a condition; until then they run after the pool drains,
# which costs a couple of minutes and keeps them meaningful.
CHECKJOBS ?= 6
CHECK_SERIAL := gfxtest browsertest layoutrendertest desktoptest httpdtest usbkbdtest
check:
	@$(MAKE) --no-print-directory -j$(CHECKJOBS) -Otarget check-all
	@$(MAKE) --no-print-directory $(CHECK_SERIAL)
	@echo "ALL TESTS PASSED (parallel pool + $(CHECK_SERIAL) serially)"

check-all: waylandtest lxinettest jstest imgtest x509test tlsfuzztest nettest tcpreliabletest fstest ext2test xattrtest iso9660test kattest bignumfuzztest barrettfuzztest stringtest svgtest deflatetest pngenctest ziptest tartest heaptest journaltest wavtest acpiamltest webptest elftest httptest kheaptest jsonfuzztest regexfuzztest jssrcfuzztest htmlentfuzztest htmlattrtest urltest colortest csstest csseltest readertest shgreptest shsedtest shmathtest shsplittest shbracetest shexpandtest shquotetest shtesttest lsfmttest shsorttest shtxttest wsframetest wsclienttest usbbottest layouttest sha1test calctest sheettest plottest jsoncoretest difftest mdtest editortest arctest hashtest normpathtest completetest boottest kstacktest ustacktest wxtest smeptest smpthreadtest smpschedtest journalguesttest fatjournaltest netcontest gdbstubtest rtl8139test virtionettest virtioblktest virtiorngtest virtioconsoletest nvmetest floppytest parttest blockdevtest raidtest ahcitest atapitest atalba48test idedmatest virtiogputest svgatest usbstoragetest ehcitest xhcitest hdatest ipctest linuxabitest
	@echo "ALL TESTS PASSED (jstest + imgtest + x509test + tlsfuzztest + nettest + tcpreliabletest + fstest + ext2test + xattrtest + iso9660test + kattest + bignumfuzztest + barrettfuzztest + stringtest + svgtest + deflatetest + pngenctest + ziptest + tartest + heaptest + journaltest + wavtest + acpiamltest + webptest + elftest + httptest + kheaptest + jsonfuzztest + regexfuzztest + jssrcfuzztest + htmlentfuzztest + htmlattrtest + urltest + colortest + csstest + csseltest + readertest + shgreptest + shsedtest + shmathtest + shsplittest + shbracetest + shexpandtest + shquotetest + shtesttest + lsfmttest + shsorttest + shtxttest + wsframetest + wsclienttest + usbbottest + layouttest + sha1test + calctest + sheettest + plottest + jsoncoretest + difftest + mdtest + editortest + arctest + hashtest + normpathtest + completetest + boottest + kstacktest + ustacktest + wxtest + smeptest + smpthreadtest + smpschedtest + journalguesttest + fatjournaltest + netcontest + gdbstubtest + rtl8139test + virtionettest + virtioblktest + virtiorngtest + virtioconsoletest + nvmetest + floppytest + parttest + blockdevtest + raidtest + ahcitest + atapitest + atalba48test + idedmatest + virtiogputest + svgatest + usbstoragetest + usbkbdtest + ehcitest + xhcitest + hdatest + httpdtest + gfxtest + browsertest + layoutrendertest + ipctest + linuxabitest)"

clean:
	rm -rf $(BUILD)

# Header-dependency tracking: -MMD (in the *CFLAGS) drops a .d next to each .o
# listing every header it included; pulling those in here means editing a header
# rebuilds exactly the objects that include it. Without this, a header edit
# silently shipped a stale .o — e.g. extending shmath.h didn't rebuild shell.o
# until a manual `touch` (M780). Placed last so the included .d rules can't
# hijack the default goal; missing on a clean tree -> ignored.
-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)
