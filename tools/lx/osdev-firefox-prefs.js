// OS-DEV default preferences for Firefox (M2106).
//
// WHY THIS FILE EXISTS. Firefox's GPU process was starting, failing to create
// an EGL display, and exiting with status 1 -- over and over, a new pid every
// second or two:
//
//   [GFX1-]: Failed[3] to create EGL library  display: FEATURE_FAILURE_NO_DISPLAY
//   [GFX1-]: Failed GL context creation for hardware WebRender: true
//
// There is no OpenGL, no EGL and no Mesa in this image, and there is not going
// to be: OS-DEV's compositor takes a shared-memory buffer of pixels. So asking
// for hardware WebRender can only ever fail here, and the retry loop is what
// kept the content area blank while the chrome rendered perfectly -- the window
// was real, and nothing was ever drawing a page into it.
//
// Gecko ships a complete software rasteriser for exactly this case (SWGL, the
// "software WebRender" backend). It is not a degraded mode bolted on; it is the
// same WebRender pipeline with a CPU backend, and it needs no driver at all.
//
// A default-preferences file rather than an environment variable because prefs
// are the documented mechanism and are read on every startup regardless of
// whether a profile exists yet -- and on the first boot of a fresh image, it
// does not.
pref("gfx.webrender.software",       true);   // SWGL: rasterise on the CPU
pref("gfx.webrender.all",            true);   // ...and use WebRender for everything
pref("gfx.x11-egl.force-disabled",   true);   // never probe EGL; there is none
pref("webgl.disabled",               true);   // a page asking for WebGL must fail fast, not hang
pref("layers.gpu-process.enabled",   false);  // the process that was dying in a loop
pref("media.rdd-process.enabled",    false);  // no audio/video decode here either

// FEWER PROCESSES, because every one of them costs a full fork of a 120 MB
// image plus its own copy of the library closure. The target is a page on
// screen in seconds, and content isolation buys nothing when the whole machine
// is one trust domain running one test page.
pref("fission.autostart",            false);
pref("dom.ipc.processCount",         1);
// NO FORK SERVER. It adds a whole second mechanism to child startup -- a
// process that receives descriptors over SCM_RIGHTS and forks on request --
// and descriptor passing is the most fragile surface in this kernel's Linux
// layer (M2083, M2084, M2104 were all in it). One way for a child to start is
// enough while children are still dying silently.
pref("dom.ipc.forkserver.enable",    false);
// NO PRELAUNCHED CONTENT PROCESS. Firefox starts a spare content process
// early and parks it so that opening a tab feels instant. Two of them turned
// up here -- pids 166 and 167, seventeen threads each, every thread BLOCKED,
// nothing running -- which is exactly what a process with no document assigned
// to it looks like, and it made "the content process is alive but idle" read
// as a bug when it is the design. Worse, it puts a process-assignment step
// between the URL and the renderer, and that step is what has to work for a
// page to appear at all. On demand is one less moving part.
pref("dom.ipc.processPrelaunch.enabled", false);
// NOTE: `browser.tabs.remote.autostart` is NOT a pref in this build -- the
// string does not appear in libxul at all, so setting it did nothing. Checked
// rather than assumed, because a pref that does not exist fails silently and
// looks exactly like a pref that did not help.

// THE FIRST TAB LOADS OUR PAGE, AND NOT BECAUSE OF argv (M2110).
//
// The content area has been 84% #f9f9fb through this entire campaign, and that
// colour is not "blank" -- it is the background of about:home. Firefox's
// packaged prefs say so outright:
//
//     pref("browser.startup.page",     1);            // 1 = load the homepage
//     pref("browser.startup.homepage", "about:home");
//
// So the browser was loading its home page, correctly, and every conclusion
// drawn from "the content area is blank" was drawn about a page that had
// rendered exactly as configured. A URL on the command line is supposed to
// override this, and it did not do so reliably -- the document was opened on
// some runs and not on others. Setting the homepage removes argv from the
// question entirely: the initial tab loads this and there is no handler,
// no remote-command path and no process-assignment step in between.
pref("browser.startup.page",         1);
pref("browser.startup.homepage",     "file:///ffpage.html");
pref("browser.newtabpage.enabled",   false);

// A SOFTWARE VSYNC TIMER, NOT THE WAYLAND ONE (M2110).
//
// Gecko's refresh driver is what paints page content, and it is driven by
// vsync. On Wayland that vsync comes from wl_surface.frame callbacks -- the
// client requests one, commits, and the compositor answers `done`. Our
// compositor answers `done` only on a commit of the SAME surface the callback
// was requested on, and Firefox commits its content subsurface 127 times per
// startup while committing its toplevel twice. If the vsync callback is on the
// toplevel, the refresh driver gets two ticks and then stops -- and a browser
// whose refresh driver has stopped paints its chrome once and never paints a
// page, which is exactly what the framebuffer shows.
//
// layout.frame_rate >= 0 makes Gecko use its own timer instead, so this
// separates "the compositor's vsync is wrong" from "the content never renders"
// without changing a line of kernel code. 60 rather than something lower
// because the target is a fast first paint, not a light one.
pref("layout.frame_rate",            60);

// Nothing may open a second tab, phone home, or replace the URL we asked for.
pref("browser.shell.checkDefaultBrowser", false);
pref("browser.aboutwelcome.enabled",      false);
pref("datareporting.policy.dataSubmissionEnabled", false);
pref("toolkit.telemetry.enabled",         false);
pref("app.update.enabled",                false);
pref("extensions.autoDisableScopes",      0);
