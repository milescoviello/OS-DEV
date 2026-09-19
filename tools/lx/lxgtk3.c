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
#include <gtk/gtk.h>
#include <gdk/gdkwayland.h>
#include <stdio.h>

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

int main(int argc, char **argv) {
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
    g_timeout_add_seconds(60, bail, NULL);
    gtk_main();
    printf("LXGTK3-RESULT: %d enter, %d motion, %d button, %d key\n",
           n_enter, n_motion, n_press, n_key);
    fflush(stdout);
    return 0;
}
