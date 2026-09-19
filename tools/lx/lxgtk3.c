/*
 * lxgtk3.c -- the GTK3 control, and the one that was missing (M2272).
 *
 * M2250 used zenity as "a real GTK client" and concluded from its working
 * click that this compositor's input path is correct and Firefox's failure
 * must be Gecko's. That was wrong for a reason nobody checked for a whole
 * day: zenity here links libgtk-4.so.1 and Firefox links libgtk-3.so.0.
 * They are DIFFERENT TOOLKITS with different Wayland backends, so the
 * control proved GTK4 works and said nothing at all about GTK3.
 *
 * This is the missing arm: the same experiment, in GTK3. A window, a button,
 * and a line on stdout for every input event that arrives. If the button
 * responds, GTK3 input works here too and Firefox really is doing something
 * of its own. If it does not, the bug is OURS and it reproduces in eighty
 * lines instead of thirty million.
 *
 * Everything it prints is prefixed LXGTK3- so a boot log can be grepped the
 * same way the other probes are.
 */
#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <gdk/gdkwayland.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <wayland-client.h>

static int n_motion, n_press, n_key, n_enter;

static gboolean on_motion(GtkWidget *w, GdkEventMotion *e, gpointer u) {
    (void)w; (void)u;
    if (++n_motion <= 3)
        printf("LXGTK3-MOTION: %.0f,%.0f\n", e->x, e->y), fflush(stdout);
    return FALSE;
}
static gboolean on_enter(GtkWidget *w, GdkEventCrossing *e, gpointer u) {
    (void)w; (void)u; n_enter++;
    printf("LXGTK3-ENTER: pointer entered at %.0f,%.0f\n", e->x, e->y);
    fflush(stdout);
    return FALSE;
}
static gboolean on_press(GtkWidget *w, GdkEventButton *e, gpointer u) {
    (void)w; (void)u; n_press++;
    printf("LXGTK3-BUTTON: press %u at %.0f,%.0f\n", e->button, e->x, e->y);
    fflush(stdout);
    return FALSE;
}
static gboolean on_key(GtkWidget *w, GdkEventKey *e, gpointer u) {
    (void)w; (void)u; n_key++;
    printf("LXGTK3-KEY: keyval %u\n", e->keyval);
    fflush(stdout);
    return FALSE;
}
static void on_click(GtkButton *b, gpointer u) {
    (void)b; (void)u;
    printf("LXGTK3-CLICKED: the button was activated -- GTK3 INPUT WORKS\n");
    fflush(stdout);
    gtk_main_quit();
}
/* A bound, so the probe always ends and always reports. A run that hangs
 * tells the harness nothing and holds the VM. */
static gboolean bail(gpointer u) {
    (void)u;
    printf("LXGTK3-RESULT: %d enter, %d motion, %d button, %d key\n",
           n_enter, n_motion, n_press, n_key);
    fflush(stdout);
    gtk_main_quit();
    return FALSE;
}

/* ---- GECKO'S SHAPE: a subsurface with an EMPTY input region (M2297) ----
 *
 * lxgtk3 responds to a click and Firefox does not, on the same compositor and
 * the same libgtk-3.so.0. The structural difference, from the compositor's
 * own log, is that Gecko paints into a SUBSURFACE it creates outside GDK --
 *
 *   [wl] surface 18 is a subsurface (role object 30)
 *   [wl] subsurface 30: surface 18 is now a child of surface 33
 *   [wl] set_input_region on surface 18 -> an EMPTY region -- takes no input
 *   [wl] commit: 1280x960 ... (surface 18, subsurface)
 *
 * -- while lxgtk3 paints straight into its toplevel. Eliminating flags one
 * ten-minute boot at a time has produced nothing; building the smaller
 * program that has the same shape is the method that has actually worked in
 * this project. If the button stops responding once this subsurface is in
 * front of it, Firefox's bug is reproduced in a hundred lines.
 *
 * Enabled with --subsurface, so the same binary is its own control. */
static struct wl_compositor *g_comp;
static struct wl_subcompositor *g_subcomp;
static struct wl_shm *g_shm;
static void reg_global(void *d, struct wl_registry *r, uint32_t name,
                       const char *iface, uint32_t ver) {
    (void)d; (void)ver;
    if (!strcmp(iface, "wl_compositor"))
        g_comp = wl_registry_bind(r, name, &wl_compositor_interface, 1);
    else if (!strcmp(iface, "wl_subcompositor"))
        g_subcomp = wl_registry_bind(r, name, &wl_subcompositor_interface, 1);
    else if (!strcmp(iface, "wl_shm"))
        g_shm = wl_registry_bind(r, name, &wl_shm_interface, 1);
}
static void reg_remove(void *d, struct wl_registry *r, uint32_t name) { (void)d; (void)r; (void)name; }
static const struct wl_registry_listener reg_l = { reg_global, reg_remove };

static void add_gecko_subsurface(GtkWidget *win, int w, int h) {
    GdkWindow *gw = gtk_widget_get_window(win);
    if (!gw || !GDK_IS_WAYLAND_WINDOW(gw)) { printf("LXGTK3-SUB: no wayland window\n"); return; }
    struct wl_display *dpy = gdk_wayland_display_get_wl_display(gdk_display_get_default());
    struct wl_surface *parent = gdk_wayland_window_get_wl_surface(gw);
    struct wl_registry *reg = wl_display_get_registry(dpy);
    wl_registry_add_listener(reg, &reg_l, NULL);
    wl_display_roundtrip(dpy);
    if (!g_comp || !g_subcomp || !g_shm) {
        printf("LXGTK3-SUB: missing globals comp=%p subcomp=%p shm=%p\n",
               (void*)g_comp, (void*)g_subcomp, (void*)g_shm);
        fflush(stdout); return;
    }
    int stride = w * 4, size = stride * h;
    int fd = memfd_create("lxgtk3-sub", 0);
    if (fd < 0 || ftruncate(fd, size) < 0) { printf("LXGTK3-SUB: memfd failed\n"); return; }
    unsigned char *px = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (px == MAP_FAILED) { printf("LXGTK3-SUB: mmap failed\n"); return; }
    for (int i = 0; i < size; i += 4) {           /* 50% alpha so the button stays visible */
        px[i+0] = 0x40; px[i+1] = 0x00; px[i+2] = 0x40; px[i+3] = 0x80;
    }
    struct wl_shm_pool *pool = wl_shm_create_pool(g_shm, fd, size);
    struct wl_buffer *buf = wl_shm_pool_create_buffer(pool, 0, w, h, stride, WL_SHM_FORMAT_ARGB8888);
    struct wl_surface *sub = wl_compositor_create_surface(g_comp);
    struct wl_subsurface *ss = wl_subcompositor_get_subsurface(g_subcomp, sub, parent);
    wl_subsurface_set_position(ss, 0, 0);
    wl_subsurface_set_desync(ss);
    /* THE POINT OF THE EXPERIMENT: this surface takes no input, so every
     * event must fall through to the parent -- which is what Gecko asks for
     * and what this compositor claims to implement. */
    struct wl_region *empty = wl_compositor_create_region(g_comp);
    wl_surface_set_input_region(sub, empty);
    wl_region_destroy(empty);
    wl_surface_attach(sub, buf, 0, 0);
    wl_surface_damage(sub, 0, 0, w, h);
    wl_surface_commit(sub);
    wl_surface_commit(parent);
    wl_display_flush(dpy);
    printf("LXGTK3-SUB: a %dx%d subsurface with an EMPTY input region is now "
           "in front of the button -- Gecko's shape\n", w, h);
    fflush(stdout);
}

int main(int argc, char **argv) {
    int want_sub = 0;
    for (int i = 1; i < argc; i++) if (!strcmp(argv[i], "--subsurface")) want_sub = 1;
    gtk_init(&argc, &argv);
    printf("LXGTK3: gtk %d.%d.%d, backend %s\n",
           gtk_get_major_version(), gtk_get_minor_version(), gtk_get_micro_version(),
           GDK_IS_WAYLAND_DISPLAY(gdk_display_get_default()) ? "wayland" : "other");
    fflush(stdout);

    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "OSDEV-GTK3");
    gtk_window_set_default_size(GTK_WINDOW(win), 360, 200);
    GtkWidget *btn = gtk_button_new_with_label("OSDEV-GTK3-CLICK-ME");
    gtk_container_add(GTK_CONTAINER(win), btn);

    g_signal_connect(btn, "clicked", G_CALLBACK(on_click), NULL);
    gtk_widget_add_events(win, GDK_POINTER_MOTION_MASK | GDK_BUTTON_PRESS_MASK |
                               GDK_KEY_PRESS_MASK | GDK_ENTER_NOTIFY_MASK);
    g_signal_connect(win, "motion-notify-event",  G_CALLBACK(on_motion), NULL);
    g_signal_connect(win, "enter-notify-event",   G_CALLBACK(on_enter),  NULL);
    g_signal_connect(win, "button-press-event",   G_CALLBACK(on_press),  NULL);
    g_signal_connect(win, "key-press-event",      G_CALLBACK(on_key),    NULL);
    g_signal_connect(win, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    gtk_widget_show_all(win);
    printf("LXGTK3: window shown, waiting for input\n"); fflush(stdout);
    if (want_sub) {
        /* After show_all, so the GdkWindow and its wl_surface exist. */
        while (gtk_events_pending()) gtk_main_iteration();
        add_gecko_subsurface(win, 360, 200);
    }
    g_timeout_add_seconds(60, bail, NULL);
    gtk_main();
    printf("LXGTK3-RESULT: %d enter, %d motion, %d button, %d key\n",
           n_enter, n_motion, n_press, n_key);
    fflush(stdout);
    return 0;
}
