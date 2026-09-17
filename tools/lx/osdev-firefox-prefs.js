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
// THE GPU PROCESS IS BACK ON (M2115). It was disabled because it died in a
// respawn loop trying to create an EGL display -- but that was the EGL, and
// software WebRender above removes EGL from the path entirely. It matters
// because the GPU process is where the COMPOSITOR lives, and the compositor is
// what receives an out-of-process document's display list. With it disabled
// the parent hosts the compositor, and remote content has never once appeared
// that way here. `-append ffnogpu` puts it back off for the A/B.
// THE GPU PROCESS IS ON (M2117). It was disabled in M2107 because it died in a
// respawn loop trying to create an EGL display -- but that was the EGL, and
// software WebRender removes EGL from the path entirely. WebRender's own HUD
// now draws into the window, so compositing works; what is missing is the
// REMOTE DOCUMENT's pipeline, and the GPU process is where the cross-process
// compositor normally lives. With it disabled the parent hosts the compositor,
// and a remote document has never once appeared that way here.
pref("layers.gpu-process.enabled",   false);  // it was never actually spawned with software WR, so this changes nothing either way
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
// VSYNC COMES FROM THE COMPOSITOR AGAIN (M2115).
//
// Setting layout.frame_rate to 60 made Gecko use its own timer, and the
// compositor's counters then said what that cost:
//
//     [page] vsync: 892 tick(s) offered, 0 frame callback(s) answered, 52 commit(s)
//
// Zero. Firefox never requested a wl_surface.frame callback even once, because
// it had been told not to need one -- so the periodic tick M2111 built had
// nothing to answer, and the browser committed 52 frames in six minutes. -1 is
// the default and means "use the display's vsync", which on Wayland is the
// frame callback, which this compositor now delivers on a real 60 Hz tick
// rather than only in reply to a commit of the same surface.
pref("layout.frame_rate",            -1);

// WEBRENDER'S OWN HUD, DRAWN INTO THE WINDOW (M2115).
//
// The content area is blank while the chrome paints, the document is loaded
// and active, and Gecko renders the same page correctly headless. What is left
// is whether WebRender is compositing the window at all, and no MOZ_LOG module
// name tried so far reports anything about it (`webrender` and `ipcmessages`
// both produced nothing). The profiler overlay is WebRender describing itself
// in pixels: if it appears in the framebuffer dump, WebRender is live and the
// missing thing is the content pipeline specifically; if it does not, the
// chrome is arriving by some other route and WebRender is not running.
// ...AND IT ANSWERED, SO IT IS OFF AGAIN (M2116). With the HUD on, the content
// area came back 57% #343434 with green and yellow pixels in it -- WebRender's
// own overlay and its graphs, drawn into the window. That is WebRender saying
// "I am compositing this window", which is the fact three runs were spent
// trying to establish. It also covers the content, so it cannot stay on while
// the question is what the content looks like.
pref("gfx.webrender.debug.profiler", false);

// Nothing may open a second tab, phone home, or replace the URL we asked for.
pref("browser.shell.checkDefaultBrowser", false);
pref("browser.aboutwelcome.enabled",      false);
pref("datareporting.policy.dataSubmissionEnabled", false);
pref("toolkit.telemetry.enabled",         false);
pref("app.update.enabled",                false);
pref("extensions.autoDisableScopes",      0);

// WHY IS THE FIRST TAB NEVER NAVIGATED? (M2133)
//
// M2132 established that Gecko opens a document channel for browser.xhtml, for
// six extension background pages, and for NOTHING ELSE -- the initial
// browsing context gets `about:blank` and is never navigated, neither from
// argv nor from browser.startup.homepage above. Creating and navigating that
// first tab is chrome JavaScript (gBrowserInit), so an exception partway
// through startup would leave exactly this: some chrome painted, no tab strip,
// no document, and the default window title.
//
// Chrome console messages -- including uncaught errors -- do not reach stderr
// by default; they go to the Browser Console, which there is no way to open
// here. This pref routes them to stdout, which is our serial console. The pref
// name is checked against libxul rather than assumed, because a pref that does
// not exist fails silently and looks exactly like a pref that did not help.
pref("devtools.console.stdout.chrome", true);
pref("browser.dom.window.dump.enabled", true);

// TRIED AND MADE NO DIFFERENCE, RECORDED SO IT IS NOT RETRIED (M2135)
//
// browser.region.update.enabled, browser.region.network.url,
// browser.backup.scheduled.enabled, toolkit.telemetry.enabled and
// datareporting.healthreport.uploadEnabled were all turned off together on the
// theory that one of them was aborting chrome startup before the first tab was
// created. The page did start rendering in that run -- and it renders just the
// same with all five put back, so they were not the reason. Removing them
// again rather than shipping prefs that do nothing: a setting kept "just in
// case" is a setting someone later has to disprove.

// THE THREE MINUTES BEFORE THE PAGE APPEARS (M2136)
//
// M2135 got the page on screen; it arrived about 150 seconds after Firefox's
// first paint, and the log says exactly what those 150 seconds were:
//
//   sample 9  (135s)  -- still only the chrome
//   console.error: Region.sys.mjs: "Failed to fetch region" NO_RESULT
//   sample 10 (150s)  -- THE PAGE IS ON SCREEN
//
// The page appears the instant Mozilla's region lookup gives up. Region.init()
// builds a promise list, and with no region known it pushes
// `#idleDispatch(() => this._fetchRegion())` onto it -- a network request
// dispatched at the next MAIN-THREAD IDLE MOMENT, which a browser starting up
// on an emulated machine does not offer for a long time. Startup waits on that
// promise before the first tab is created and navigated.
//
// Region.init() reads the answer straight out of this pref and skips the fetch
// entirely when it is set:
//
//     this.#home = Services.prefs.getCharPref(REGION_PREF, null);
//     if (this.#home) { ...no network... } else { ...fetch... }
//
// So the region is stated rather than discovered. That is also honest: the
// service being queried is Mozilla's geolocation endpoint, this machine has no
// business asking it, and the value only selects a default search engine.
pref("browser.search.region",        "US");
pref("browser.region.network.url",   "");
pref("browser.region.update.enabled", false);

// THE CAPTIVE-PORTAL PROBE IS THE 140 SECONDS (M2136)
//
// Measured, not guessed. Per-sample syscall counts show Firefox doing real
// work for the first 15s after first paint, then going almost completely
// quiet for a hundred seconds, then bursting:
//
//   sample 1  (15s):  +366595 syscalls, +59327 faults   <- working
//   samples 2-9:      +12000 syscalls, ~270 faults      <- a poll loop idling
//   sample 10 (150s): +898253 syscalls, +9161 faults    <- and the page appears
//
// A flat plateau is a WAIT, not slow work. The connect log says what it is
// waiting for:
//
//   t= 54690ms connect -> 151.101.129.91:80 = 0     <- Fastly, over HTTP
//   ...142 seconds with no network activity at all...
//   t=196740ms connect -> 1.1.1.1:53 = 0
//
// 151.101.x is Fastly, port 80 is plain HTTP, and the thing Firefox fetches
// over plain HTTP at startup is detectportal.firefox.com -- captive-portal
// detection, asking whether a hotel wifi is intercepting traffic. This machine
// has no business asking that, the answer cannot matter to it, and waiting on
// it costs the entire time-to-page.
//
// The stall itself is ALSO a bug in this OS's HTTP path -- a small GET to a
// real server should not take 140 seconds -- and it is recorded as such rather
// than papered over: see WHATS-NEXT. Disabling the probe removes it from
// startup; it does not fix the stall, and the stall will bite any guest that
// fetches over HTTP.
pref("network.captive-portal-service.enabled", false);
pref("network.connectivity-service.enabled",   false);
