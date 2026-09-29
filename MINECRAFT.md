# Minecraft on OS-DEV: the route, and an honest account of what is in the way

**The question:** how could real Minecraft run here? That means Minecraft
Java Edition, the actual game, not a clone.

**The short answer:** the same way Firefox and Claude Code got here. We don't
port anything. We *run* the unmodified Linux build through the Linux ABI layer.

Minecraft Java Edition is a Java program, and every piece of the chain it
needs is either already running in OS-DEV or has a named, bounded gap:

    HotSpot JVM  ->  LWJGL natives  ->  SDL3 (Wayland)  ->  our compositor
                                    ->  EGL + desktop GL 3.3 core  ->  Mesa
                                    ->  OpenAL (sound; optional)

Nothing here needs an X server, a from-scratch GPU driver, or a line of
Minecraft's code changed.

## Which Minecraft: 26.3

These facts were checked against Mojang's own version JSONs, the client jars'
bytecode and the bundled native libraries, on 2026-09-28:

| | 1.21.11 | 26.1 / 26.2 | **26.3 (current)** |
|---|---|---|---|
| Java | 21 | 25 | **25** |
| Windowing | GLFW, tries X11 then Wayland | GLFW, **forces X11** | **SDL3, ends up on Wayland** |
| GL | 3.3 core | 3.3 core | **3.3 core** (Vulkan optional, falls back to GL) |
| LWJGL | 3.3.3 | 3.4.1 | 3.4.3 (FFM downcalls on JDK 25) |

- **26.1 and 26.2 are the worst choice.** They call
  `glfwInitHint(GLFW_PLATFORM, GLFW_PLATFORM_X11)` whenever the bundled GLFW
  supports both platforms. With no X server, `glfwInit` then fails, and there
  is no fallback.
- **26.3 needs no workaround.** It moved to SDL3. SDL tries Wayland first only
  if the compositor offers `wp_fifo_manager_v1`, but with no X server it falls
  through to Wayland anyway, and `SDL_VIDEO_DRIVER=wayland` forces it.
- **Vulkan is not required yet.** 26.4-snapshot-1 makes Vulkan the default but
  still falls back to OpenGL. Mojang has said OpenGL will eventually be
  removed, but has given no date.

## The chain, link by link

### 1. The JVM (HotSpot, JDK 25): done in M2392-M2394, see Status

HotSpot uses signals the way no program here had before. It does not test
for null, for a zero divisor or for a pending safepoint. It lets the hardware
fault, and its handler:

1. reads the fault from `siginfo_t` and `ucontext_t`,
2. writes a new program counter into the ucontext,
3. returns, and expects the kernel to resume *there*.

At startup it also faults on purpose to check that YMM registers survive a
signal. It exits outright if `getcpu(2)` is missing.

What the Linux ABI layer did before M2392, measured against a probe that
passes 27/27 on real Linux 7.0:

- **`getcpu` returned ENOSYS.** HotSpot aborts with "getcpu(2) system call not
  supported by kernel".
- **The signal frame was OS-DEV's own, not Linux's.** siginfo had `si_code` at
  +4 and `si_addr` at +8, where Linux has them at +8 and +16. The ucontext was
  the interrupt frame.
- **`rt_sigreturn` restored a kernel-side copy.** The handler's PC edit was
  discarded, so the faulting instruction ran again, forever.
- **No FP state was saved in the frame.** A handler's `memcpy` changed the
  interrupted code's XMM registers.
- **Every ring-3 exception became SIGSEGV.** HotSpot needs SIGFPE for integer
  division by zero.
- **Fault info was stored per process, not per thread.** Two threads hitting a
  safepoint page at the same moment could swap `si_addr`.
- **Fork dropped `sa_flags`.** A child's SA_SIGINFO handler was called with
  garbage pointers.
- **`sigaltstack` was a stub.**

**M2392 fixes all of these.** Linux processes get the real Linux frame:
`rt_sigframe`, `ucontext_t`, `siginfo_t` and the XSAVE image, and `rt_sigreturn`
restores from it. Native apps keep their documented frame. `tools/lx/lxsigctx.c`
is the probe; `tools/lx/LxJava.java` is the same checks done from Java.

**Still open, not yet shown to matter:**
- the 4096-VMA cap (`APP_MAXVMA`), with no VMA merging;
- `/proc/self/maps` reads are cut off at 64 KiB;
- per-thread CPU clocks report wall time;
- `membarrier` is missing (only used with a non-default flag).

### 2. The game files: not in the image, ever

The repository is **public**, and Mojang's EULA forbids redistributing the
jar or assets. So nothing Mojang-made is ever committed, and nothing
Mojang-made goes into the image by default.

The files come from Mojang's own servers:
- Fetch them on a Linux host with [portablemc](https://github.com/theorzr/portablemc):
  `portablemc start --dry -u <name> 26.3`. That downloads everything and
  launches nothing.
- Total size: a 41 MB client jar, about 83 MB of libraries, and about 484 MB
  of assets.

From there:
- They get staged from a path *outside* the repo, the way `FIREFOX_DIR` is.
- The main class is `net.minecraft.client.main.Main`.
- The classpath goes in an `@argfile`, because `app_run_linux_sync` allows 28
  arguments.
- Singleplayer runs offline with a chosen username. Online servers need a
  Microsoft login, which is out of scope. The user should own the game.

### 3. LWJGL's natives

LWJGL natives ship as ordinary `natives-linux` jars on the classpath. LWJGL
extracts them to `-Dorg.lwjgl.system.SharedLibraryExtractPath` and loads them
with `dlopen`. Firefox already exercises `dlopen` from a writable directory.
Expect this link to work, or to fail with a clear message.

### 4. SDL3 on our Wayland compositor: works in part

SDL3 needs `wl_compositor`, `wl_shm`, `xdg_wm_base` and `wl_seat`, all of
which `kernel/wayland.c` already serves to Firefox. SDL loads
`libwayland-client`/`-cursor`/`-egl` and `libxkbcommon` at run time; all four
are already staged.

**Missing:**
- **Held keys.** `desktop.c:2808` forwards the *cooked* character as an instant
  press and release. A held W arrives as a string of taps, and Shift or Ctrl
  on their own are never sent. The raw press/release ring exists
  (`keyboard.c:92`) and would be forwarded instead.
- `wl_keyboard.leave`.
- The middle mouse button.
- `xdg_toplevel.set_fullscreen`.
- A configure sent when the window manager resizes a window.
- **Mouse-look.** SDL refuses relative mouse mode unless the compositor has
  **both** `zwp_relative_pointer_manager_v1` and `zwp_pointer_constraints_v1`.
  The VM's usb-tablet gives only absolute positions, so deltas have to be
  synthesised from absolute motion or come from a relative device. Without
  this the game runs, but the camera does not turn.

### 5. OpenGL 3.3 core in a Wayland window: the biggest gap

The staged Mesa is virgl + nouveau only (`tools/build-mesa-virgl.sh`): no
LLVM, no software rasterizer, no GLX, no glvnd. No EGL client has ever put a
*window* on screen here. `lxgl` passes only with a pbuffer on the surfaceless
platform, and the compositor composites `wl_shm` buffers only. Two routes:

- **(a) llvmpipe. Recommended first; it gets pixels.**
  - Mesa's software EGL-on-Wayland path presents through `wl_shm`, which the
    compositor already composites for Firefox, so there is no compositor work.
  - llvmpipe is GL 4.5 core conformant, so a 3.3 core context is fine.
  - Cost: rebuild Mesa with `llvmpipe` and LLVM. The LLVM closure is about
    130 MB, which the image and the disk path have to carry.
  - Speed is the open question. There is no rigorous published benchmark; the
    anecdotes range from 3 to 30 fps. We have 8 KVM cores of a 5.2 GHz Core
    Ultra 7 at a small window size.
- **(b) virgl, for speed.**
  - Rendering happens on the host's Intel GPU. virgl exposes GL 4.3+, and the
    render-node chain is already proven by `lxgl`.
  - Missing: a way to show a GPU-rendered buffer. That means serving
    `zwp_linux_dmabuf_v1`, or `wl_drm`'s `create_prime_buffer`, and having the
    compositor read the virgl resource back (`TRANSFER_FROM_HOST_3D`) into
    guest memory, since the display is a separate std-VGA framebuffer. At
    854x480 that is 1.6 MB per frame, which is affordable.

**Also needed: the same GL entry points for LWJGL and SDL.**
- LWJGL loads `libGLX.so.0`/`libGL.so.1`. SDL's EGL path loads
  `libGL.so.1`/`libOpenGL.so.0`.
- 26.3 checks that LWJGL's `glGetError` *is* `SDL_GL_GetProcAddress("glGetError")`
  and rejects the GL backend if not.
- Mesa built with `-Dglvnd=enabled`, plus libglvnd staged, gives a
  `libOpenGL.so.0`/`libGL.so.1` that dispatches into the current EGL context.
  Alternatively, point `-Dorg.lwjgl.opengl.libname` and `SDL_OPENGL_LIBRARY`
  at one library.

### 6. Sound: optional

No Linux program can reach audio today: there is no `/dev/snd`, no `/dev/dsp`
and no PulseAudio socket, even though HDA and AC'97 have native drivers. Set
`ALSOFT_DRIVERS=null` and the game runs silent; it already disables sound by
itself if OpenAL cannot open a device. Real audio is an OSS `/dev/dsp` or a
minimal ALSA PCM shim over the existing `audio.c`. That is a separate,
contained milestone.

### 7. The load itself

The official launcher's 26.x defaults are more than this kernel should be
asked for up front:
- ZGC,
- a 4 GB heap,
- `-XX:+AlwaysPreTouch`.

The plan is to launch by hand with `-XX:+UseSerialGC` or G1, `-Xmx2G`, and no
pre-touch. Those choose which kernel paths get exercised, and can be widened
once each one is proven.

Startup is also a disk-read problem. It means class-loading a 41 MB jar and
reading about 484 MB of assets. Firefox's first paint read 803 MB through
8-sector DMA, the known lever. Expect minutes on the first boot.

## Milestones, each "done" by a measurement

1. **The JVM runs.** `-append lxjava` shows `java -version` and LxJava with
   `RESULT PASS`, under both Serial and G1. **Done (M2392-M2394).**
2. **The game's own JVM work runs headless:** a dedicated server
   (`server.jar`) generates a world. This tests the collector, threads and
   world generation under a real workload before any window exists. It uses
   the same staging path as the client, from outside the repo.
3. **A GL 3.3 core context in a Wayland window.** A small EGL + SDL3 probe
   (`lxsdlgl`) draws a known colour, and a screenshot check asserts it the way
   `tests/wl/shot_check.py` does. This needs route (a), llvmpipe.
4. **Game input:** raw key press/release (held keys, modifiers on their own),
   `wl_keyboard.leave`, the middle button, and relative pointer plus pointer
   constraints.
5. **Minecraft 26.3 reaches the title screen,** from a screenshot.
6. **A singleplayer world:** create one, walk, look around, place a block.
7. **Faster:** virgl route (b), then the disk path, then sound.

## Risks, stated plainly

- **Unknown unknowns in link 5.** No EGL window has ever been shown here. The
  M2351-M2356 GL campaign needed eight separate kernel facts before Mesa would
  even initialise. Expect the Wayland-EGL-swrast path to need its own list.
- **Frame rate on llvmpipe** is genuinely unknown until measured. The first
  number may well be single digits at a small window size. Route (b) is the
  answer if it is.
- **Scale.** Minecraft starts about 50-100 threads and allocates heavily. The
  VMA table (4096, no merging), the 192-thread cap and the disk path have each
  been fine for Firefox. None has been shown fine for this.
- **The target moves.** Mojang intends to remove OpenGL. When it does, the
  route becomes Vulkan: lavapipe (software) or Venus (virtio-gpu). Pin the
  version that works.

## Status

### 2026-09-29: link 1 is done, and HotSpot runs

Measured under KVM on pve-ultra, VM 122, 8 cores, `-append "lxsigctx lxjava
noprobes nonetdemo"`:

| | M2391 kernel (before) | M2394 kernel (after) | real Linux 7.0 |
|---|---|---|---|
| `lxsigctx` | 1 check ok, then died | **27/27 PASS** | 27/27 PASS |
| cost per caught fault | n/a | 2.57 us | 1.08 us |
| `java -version` | exit 139 | **exit 0**, Temurin 25.0.4 | exit 0 |
| LxJava, Serial GC | not reached | **14/14 PASS**, 2.28 s | 14/14, 1.00 s |
| LxJava, G1 | not reached | **14/14 PASS**, 2.14 s | 14/14 |

The whole boot plus four programs finishes inside ~14 s of serial capture.

Why the M2391 JVM died: `getcpu` was ENOSYS. HotSpot's fallback then *calls*
the legacy vsyscall `vgetcpu` at `0xffffffffff600800`, which is unmapped here,
and gets SIGSEGV. With `getcpu` implemented, that path is never taken.
Emulating the vsyscall page, as Linux's `vsyscall=xonly` does, would only
matter for binaries older than glibc 2.14.

Three defects outside the signal path turned up along the way:

- **The UNMAPPED fault report was unbounded.** It was written for a fault that
  kills the process, so it was expected once. A JVM takes one for every caught
  null check. One LxJava run printed 40,528 reports, each with a 54-line VMA
  table, and the serial console turned 288 ms of work into 580 s. It is now
  capped for processes that catch SIGSEGV (M2392).
- **`-append noprobes` had never worked.** `probes` is a substring of
  `noprobes` (M2394).
- **`build-mesa-virgl.sh` built mesa-demos.** It also left the host's libEGL
  stub in the image (M2391).

Regression check. The new frame changes signals for *every* Linux process,
so the heaviest existing users were re-run:
- **Firefox renders** (`PAGE ON SCREEN` at 29.3 s). That needed M2395 first,
  because Firefox 156, newer than any build tested here before, crashed every
  content process on the M2391 kernel too. `open("/proc/self/fd/N")` did not
  re-open the memfd, as Linux's magic link does.
- **Claude Code works.** `claude -p` answered "OS-DEV" and exited 0. It runs
  on Bun/JavaScriptCore, which suspends threads with signals and reads their
  registers out of the ucontext.
- **The other 30 probes of the Linux ABI suite pass** on both kernels.

### Next: milestone 2

Next is a headless dedicated server: Mojang's `server.jar`, fetched on a
host, never committed. It is pure Java with no LWJGL and no GL, so it tests
the JVM at Minecraft's own scale:
- world generation on every core,
- a few hundred MB of heap under G1,
- region files on ext2,
- a TCP listener on 25565.

It is also the cheapest way to find out whether the VMA cap or the
192-thread cap bites before there is a window to debug through.
