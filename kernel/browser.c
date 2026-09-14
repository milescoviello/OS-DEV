/*
 * browser.c — a tiny graphical web browser.
 *
 * The pipeline, end to end:
 *   1. parse the address bar URL into host + path
 *   2. fetch it with http_get() (real TCP/HTTP over the internet)
 *   3. strip the HTML into a flat list of "tokens": words (each tagged with a
 *      style — normal / heading / link, and a link id if it sits in an <a>)
 *      and breaks (line / paragraph)
 *   4. render that token stream word-wrapped into the window, recording the
 *      on-screen rectangle of every link word so clicks can follow it
 *
 * It is deliberately NOT a real layout engine: no CSS, no tables, no images.
 * But it turns live HTML from the internet into readable, styled, scrollable,
 * clickable pages — the first real step toward a browser.
 */
#include "font.h"   /* font_row: the extended TUI glyphs (M2015) */
#include "browser.h"
#include "net.h"
#include "fb.h"
#include "png.h"
#include "gif.h"
#include "jpeg.h"
#include "layout.h"   /* shared CSS box-layout engine: the §10.3.3 width solver (M1896) */
#include "svg.h"
#include "bmp.h"
#include "webp.h"
#include "image.h"   /* decode_image() — defined below; shared with desktop.c wallpaper */
#include "tls.h"
#include "js.h"
#include "console.h"
#include "kheap.h"
#include "string.h"
#include "task.h"
#include "timer.h"
#include "vfs.h"
#include "http.h"
#include "htmlentity.h"
#include "htmlattr.h"
#include "url.h"
#include "cssel.h"   /* sel_t + sel_parse (CSS simple-selector parser; host-fuzzed) — M688 */
#include "color.h"
#include "cssprop.h"
#include "cssborder.h"   /* parse_style_border — CSS `border` shorthand value parser, host-tested via tests/css (M1777) */
#include "reader.h"   /* reader_main_region() — article-first content extraction (host-fuzzed) */
#include <stdint.h>
#include <stddef.h>

#define RAW_MAX   1048576       /* response/image fetch buffer (1 MB; M1436 — many modern pages exceed 512 KB) */
#define TEXT_MAX  196608        /* token text pool (192 KB; tok_t.off is uint32 now, so no 64KB ceiling) */
#define TOK_MAX   22000         /* rendered tokens; sized to fill TEXT_MAX (~8 bytes of text/token) */
#define SCRIPT_MAX 16384        /* concatenated inline <script> text run per page */
#define HREF_MAX  32768         /* href URL pool (< 65536: href_t.off is uint16); was 8KB — large pages' body links exceeded it */
#define LINK_MAX  2000          /* max clickable links/page; large real pages (Wikipedia) have hundreds */
#define LREC_MAX  1024
#define URL_MAX   160
#define ADDR_H    30
#define GW        8                 /* glyph width (8x16 font) */
#define NO_LINK   0xFFFF
#define IMG_SLOTS 6                 /* inline images decoded per page */
#define IMG_READ_MAX 131072         /* scratch to read a local image file */
#define LOCAL_IMG_MAX (1024*1024)   /* transient buffer for a full-page local image (a 24-bit BMP screenshot is ~576 KB > RAW_MAX) */
#define DATA_URI_B64_MAX 262144     /* max base64 length of an inline data: image URI we'll decode */
#define IMG_MAX_H 360               /* cap an inline image's on-screen height */
#define REMOTE_IMG_MAX 6            /* remote <img> URLs prefetched per page (best-effort; was 3 — too few to reach real content images past leading nav/icon <img>s) */
#define IN_MAX    16                /* distinct form-field values stored per page (id-keyed: inputs/textareas/selects). was 8 -> a >8-field form silently dropped the extras from render + GET submit */
#define IN_VLEN   256               /* bytes per stored field value -> 255 chars (was 96/95): a real textarea / long input is no longer truncated. EVERY edit buffer below must be IN_VLEN with caps IN_VLEN-1 (plain copy) / IN_VLEN-2 (before an insert) so they never overflow */

enum { STY_NORMAL, STY_H1, STY_H2, STY_LINK, STY_BOLD, STY_EM, STY_CODE, STY_STRIKE, STY_MARK, STY_SUB, STY_SUP };
enum { TK_WORD, TK_BREAK, TK_PARA, TK_HR, TK_IMG,     /* TK_IMG: link field = image slot */
       TK_BORDER_OPEN, TK_BORDER_CLOSE,               /* CSS border: OPEN carries off=color(24b), style=width; bracket a block's tokens, drawn as one rect at render (M910) */
       TK_FLEX_OPEN, TK_FLEX_CLOSE,                   /* display:flex: bracket a container; inside, child block-breaks become horizontal gaps (row layout) (M927) */
       TK_MAXW_OPEN, TK_MAXW_CLOSE,                   /* max-width: OPEN off=px; narrows+centres cl..cr for the block (readable column) (M933) */
       TK_BG_OPEN, TK_BG_CLOSE };                     /* block background-color: OPEN off=rgb(24b); a forward-scan at OPEN fills ONE contiguous rect behind the whole block before its content paints (M993) */
#define BORDER_PAD 6                                   /* px of padding between a full border box and its text (both axes, M916) */

typedef struct { uint32_t off; uint16_t len, link; uint8_t style, type; } tok_t;  /* off is uint32 so TEXT_MAX can exceed 64KB (len<=word, link<LINK_MAX stay uint16) */
typedef struct { uint16_t off, len; } href_t;            /* slice into hrefs[] */
typedef struct { int16_t x, y, w, h; uint16_t link; } lrec_t;  /* a clickable rect */
/* sel_t (one simple CSS selector: tag/.class/#id/[attr]) now lives in cssel.h (M688). */

#define CSS_MAX 160                 /* simple style rules captured from <style> blocks per page (raised from 24 in M1432 — real sites have many rules) */
#define SC_MAX  16                  /* max nesting depth of active style scopes (color/weight) */

struct browser {
    char    url[URL_MAX];
    int     editing;
    int     edit_fresh;                                  /* just entered the address bar: first keystroke replaces the URL */
    int     url_cur;                                     /* caret index in the address bar (for left/right editing) */
    int     viewsource;                                  /* 'u': show raw HTML instead of rendering */
    char   *raw;  int rawlen;
    char   *text; int textlen;
    tok_t  *toks; int ntok;
    char   *hrefs; int hreflen;
    href_t *links; int nlink;
    lrec_t *lrec;  int nlrec;                            /* rebuilt each render */
    lrec_t *wrec;  int nwrec;                            /* per-visible-word rects (.link = token idx) for text selection */
    int     tsel0, tsel1;                                /* selected token range (-1 = none); set by mouse drag */
    int     sel;                                         /* keyboard-selected link id (NO_LINK = none) */
    int     linky[LINK_MAX];                             /* content-space y of each link (for scroll-into-view) */
    int     scroll, content_h, view_h;
    uint16_t pending_vmargin;   /* CSS vertical margin (px) to add before the next block break */
    char    status[40];
    char    title[64];                                   /* <title> -> window bar */
    char    title_js[64]; int title_js_set;              /* document.title override (persists across re-renders like input values; reset on navigate) */
    volatile int loading;                                /* fetch in flight     */
    volatile int need_parse;                             /* worker -> WM: parse  */
    volatile int closed;                                 /* window closed mid-fetch */
    volatile int http_n;                                 /* http_get result      */
    int     cert_status;                                 /* TLS CertVerify: -2 n/a, 0 ok, -1 fail */
    int     chain_ok;                                    /* 1 = chain anchored to a trusted root */
    int     host_match;                                  /* TLS hostname match: -2 n/a, 1 ok, 0 mismatch */
    char    cert_cn[48], cert_expiry[16];                /* leaf cert identity, for the 'i' cert-info display */
    int     zoom;                                        /* content zoom multiplier (1..4), persists across navigation */
    int     reader;                                      /* reader mode: render the page's main-content region only (article-first), skipping nav/header/footer chrome. On by default; 'm' toggles. Persists across navigation */
    volatile int want;                                   /* load queued (worker busy) */
    char    cur[URL_MAX];                                /* currently shown URL */
    char    hist[16][URL_MAX]; int histn;                /* back stack          */
    char    fwd[16][URL_MAX];  int fwdn;                 /* forward stack (pages backed out of) */
    int     is_back;                                     /* this nav is a Back/Forward (skip hist push + fwd clear) */
    int     redirects;                                   /* HTTP 3xx hop count  */
    int     listdepth;                                   /* nested <ul>/<ol> depth */
    char    listtype[8];                                 /* 'u' or 'o' per level */
    int     listnum[8];                                  /* <ol> item counter per level */
    char    listfmt[8];                                  /* <ol type>: '1'/'a'/'A'/'i'/'I' per level */
    char    listmark[8];                                  /* list-style-type per level: 0=default, 'N'=none, '-'/'*'/'+' bullet, '1'=decimal */
    int     tdcount;                                     /* cells emitted in the current <tr> */
    int     finding;                                     /* in-page find: typing a query */
    char    findq[40];                                   /* the find query */
    int     find_tok;                                    /* highlighted match token (-1 none) */
    int     help_on;                                     /* '?' key-reference overlay shown */
    int     toky[TOK_MAX];                               /* content-space y of every token (scroll-to) */
    char    anc_id[32][32]; uint16_t anc_tok[32]; int anc_n;   /* id -> token index, for #fragment scroll-to */
    uint8_t det_open[16];                                      /* <details> open state by index (0xFF=unseeded), persists across re-renders */
    uint8_t *img; int imgw, imgh;                        /* current full-page frame (RGBA), or NULL */
    uint8_t *framebuf; int nframes, curframe;            /* animated GIF: all frames + current */
    int      framedelay[64];                             /* per-frame delay (centiseconds) */
    uint64_t frametick;                                  /* tick at which curframe was shown */
    uint8_t *imgs[IMG_SLOTS]; int imgsw[IMG_SLOTS], imgsh[IMG_SLOTS]; int nimg;  /* inline images */
    char canv_id[IMG_SLOTS][32]; int canv_slot[IMG_SLOTS]; int n_canv;           /* M1796: <canvas> id -> image-slot registry (a canvas is a writable image slot) */
    char     rimg_src[REMOTE_IMG_MAX][96];   /* the RAW src string as it appears in the <img> (for matching) */
    uint8_t *rimg_data[REMOTE_IMG_MAX];      /* the fetched COMPRESSED image bytes (kmalloc'd), or NULL */
    int      rimg_len[REMOTE_IMG_MAX];       /* byte length of rimg_data[i] */
    int      n_rimg;                         /* how many remote images prefetched (0..REMOTE_IMG_MAX) */
    uint32_t curcolor;                                   /* <font color> in effect (0=none, else 0x01000000|rgb) */
    uint32_t tokcolor[TOK_MAX];                          /* per-token colour override */
    int      curul;                                      /* underline in effect (text-decoration:underline / <u>/<ins>); independent of style, so it composes */
    uint8_t  tokul[TOK_MAX];                             /* per-token underline flag */
    int      curtransform;                               /* text-transform in effect: 0=none, 1=uppercase, 2=lowercase (applied emit-time to b->text, so .textContent — read from b->raw — stays original) */
    uint32_t curbg;                                      /* CSS background-color in effect (0=none, else 0x01000000|rgb) */
    uint32_t tokbg[TOK_MAX];                             /* per-token background colour (drawn as an inline highlight behind the text) */
    int      curalign;                                   /* text-align in effect: 0=left, 1=center, 2=right */
    uint8_t  tokalign[TOK_MAX];                          /* per-token text-align (a line takes its first token's value) */
    int      curscale;                                   /* CSS font-size scale override in effect (0=none/use style default, else 2 or 3) */
    uint8_t  tokscale[TOK_MAX];                           /* per-token glyph-scale override (0=none; enlarges only — the bitmap font has no sub-1x) */
    int      curlh_css;                                  /* CSS line-height override in effect (0=none/use style default, else px value) */
    uint8_t  toklh[TOK_MAX];                              /* per-token CSS line-height in px (0=none/use style default) */
    int      curindent;                                  /* left-indent in px (from <blockquote> nesting), applied at every line start */
    int      curprews;                                   /* CSS white-space: preserve spaces+newlines like <pre> when >0 (M1818) */
    uint8_t  tokindent[TOK_MAX];                          /* per-token left-indent in px, capped at 255 (a line takes its first token's value) */
    char    *scripts; int scriptlen;                     /* inline <script> text captured this parse */
    int     bodyoff, bodylen;                            /* current page's body region in raw (for click-time JS re-render) */
    char    ls_keys[16][32]; char ls_vals[16][160]; int ls_n;   /* per-page localStorage (survives per-run JS arena resets) */
    char    oc_tag[16]; int oc_depth, oc_link, oc_style;        /* active inline-onclick scope (0 depth = none) */
    struct { char tag[16]; char cls[32]; int depth; uint32_t savecolor, savebg; int savestyle, setstyle, saveul, savetransform, savealign, savescale, savelh, hidden, saveindent, saveprews; uint8_t hasborder; uint8_t hasflex; uint8_t hasmaxw; uint8_t hasbg; uint8_t padb; uint8_t margb; uint16_t boxh; uint16_t boxminh; uint16_t boxmaxh; uint8_t bordbox; uint8_t ovhidden; } sc[SC_MAX];  /* nested style scopes (color/bg/font-weight/font-style/underline/transform/align/font-size/line-height/display:none/border/flex/block-bg + the element's class, for descendant-selector matching), a stack so nested styled elements compose */
    int     sc_sp;                                              /* number of active style frames (0 = none) */
    int     n_hidden;                                          /* >0 while inside a display:none element: suppress all emission */
    sel_t   css_sel[CSS_MAX]; uint32_t css_color[CSS_MAX]; int16_t css_style[CSS_MAX]; uint8_t css_ul[CSS_MAX]; uint8_t css_transform[CSS_MAX]; uint32_t css_bg[CSS_MAX]; uint8_t css_align[CSS_MAX]; uint8_t css_size[CSS_MAX]; uint8_t css_disp[CSS_MAX]; uint8_t css_margin[CSS_MAX]; uint8_t css_indent[CSS_MAX]; uint32_t css_border[CSS_MAX]; uint8_t css_list[CSS_MAX]; uint8_t css_lineheight[CSS_MAX]; uint8_t css_ws[CSS_MAX]; uint16_t css_spec[CSS_MAX]; uint16_t css_imp[CSS_MAX];
    /* Box geometry from a STYLESHEET rule (M1929). Until now width and auto
     * margins could only come from an inline style= attribute, so a rule like
     * `body{width:60vw;margin:15vh auto}` -- exactly how real pages, example.com
     * included, centre their content -- did nothing at all. */
    uint16_t css_w[CSS_MAX]; uint8_t css_mauto[CSS_MAX];
    /* Padding + height from a rule too (M1930): `.card{padding:20px}` is one of
     * the most common declarations there is, and it was inline-only. */
    uint8_t css_padl[CSS_MAX], css_padr[CSS_MAX], css_padt[CSS_MAX], css_padb[CSS_MAX];
    uint16_t css_h[CSS_MAX];
    int n_css;  /* <style> rules: selector -> color / text-style / underline / text-transform / background / text-align / font-size / line-height / display:none / border / list-style-type / specificity */
    char    in_id[IN_MAX][32]; char in_val[IN_MAX][IN_VLEN]; int in_n;   /* <input> field values, by id (the typed/scripted text) */
    char    in_name[IN_MAX][32];                                /* each field's name= attr (parallel to in_id), for GET submit */
    char    ta_ids[8][32]; int ta_n;                            /* ids that are <textarea>s (so Enter inserts a newline, not submit) */
    char    sel_ids[8][32]; char sel_vals[8][512]; int sel_n;   /* <select>s: id + its option values ('\n'-joined), so a click cycles to the next.
                                                                 * 512 holds the worst case: 16 options x 31 chars + 15 '\n' = 511 + NUL (was 256 -> truncated long lists, breaking selcyc round-trip) */
    char    focus_id[32];                                       /* id of the focused input field (empty = none) */
    int     field_cur;                                          /* caret index within the focused field's value */
    char    form_action[URL_MAX];                               /* current <form action>; empty = submit to the current page */
};

static void drop_image(browser_t *b);        /* fwd: free any decoded image */
static void drop_image_slots(browser_t *b);  /* fwd: free inline images */
static void drop_remote_imgs(browser_t *b);  /* fwd: free prefetched remote-image bytes */
static int  decode_local_to_slot(browser_t *b, const char *path);  /* fwd */
static int  decode_bytes_to_slot(browser_t *b, const uint8_t *data, int len);  /* fwd: decode an in-memory image blob into an inline slot */
static int  b64_decode(const char *in, int inlen, uint8_t *out, int cap);       /* fwd: base64 -> bytes (for data: image URIs) */

/* ---- small helpers ---- */
/* lc() + the attribute scanners (find_attr/has_attr/attr_int/find_href) now live
 * in htmlattr.c so they can be fuzzed in isolation (M566). */
static int tageq(const char *t, const char *lit) {
    int i = 0; while (t[i] && lit[i]) { if (t[i] != lit[i]) return 0; i++; }
    return t[i] == lit[i];
}
static int startsw(const char *s, const char *p) {
    while (*p) { if (*s != *p) return 0; s++; p++; } return 1;
}
static int streqs(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; } return *a == *b;
}
static void copy_url(char *dst, const char *src) {
    int i = 0; while (src[i] && i < URL_MAX - 1) { dst[i] = src[i]; i++; } dst[i] = 0;
}
static uint32_t color_for(int style) {
    switch (style) {
    case STY_H1:   return 0x10306E;
    case STY_H2:   return 0x243B70;
    case STY_LINK: return 0x1560C0;
    case STY_BOLD: return 0x101015;
    case STY_EM:   return 0x6A4A1A;
    case STY_CODE: return 0xA83254;          /* inline <code>/<tt>: crimson */
    case STY_STRIKE: return 0x808890;        /* <s>/<del>: muted grey, drawn with a strike-line */
    case STY_MARK: return 0x101015;          /* <mark>: dark text on a yellow highlight (set in the draw) */
    default:       return 0x202024;
    }
}
static int lineh_for(int style) { return style == STY_H1 ? 34 : style == STY_H2 ? 24 : 18; }
static int scale_for(int style) { return style == STY_H1 ? 2 : 1; }

/* ---- token emission ---- */
static void emit_word(browser_t *b, int start, int style, int link) {
    int len = b->textlen - start;
    if (len <= 0 || b->ntok >= TOK_MAX || b->n_hidden > 0) return;   /* display:none -> emit nothing */
    b->tokcolor[b->ntok] = b->curcolor;                  /* <font color> override (0 = none) */
    b->tokul[b->ntok] = (uint8_t)b->curul;               /* underline (text-decoration / <u>) */
    b->tokbg[b->ntok] = b->curbg;                        /* background-color highlight (0 = none) */
    b->tokalign[b->ntok] = (uint8_t)b->curalign;         /* text-align (0=left/1=center/2=right) */
    b->tokscale[b->ntok] = (uint8_t)b->curscale;         /* font-size scale override (0=none) */
    b->toklh[b->ntok]    = (uint8_t)(b->curlh_css > 255 ? 255 : b->curlh_css);   /* CSS line-height in px (0=none) */
    b->tokindent[b->ntok] = (uint8_t)(b->curindent > 255 ? 255 : b->curindent);   /* left-indent px */
    b->toks[b->ntok++] = (tok_t){ (uint32_t)start, (uint16_t)len,
                                  (uint16_t)link, (uint8_t)style, TK_WORD };
}
static void emit_break(browser_t *b, int type) {
    uint16_t m = b->pending_vmargin; b->pending_vmargin = 0;   /* CSS margin for this block, if any (consume once) */
    if (b->ntok == 0 || b->n_hidden > 0) return;         /* no leading blank lines / display:none */
    tok_t *last = &b->toks[b->ntok - 1];
    /* A block-bg / border CLOSE marker terminates a block's content but, unlike
     * FLEX/MAXW close, does NOT advance the render cursor (it only strokes/decrements).
     * So a block that follows one needs its OWN break appended AFTER the marker, else
     * the next block's first words collapse onto the styled block's last line — inside
     * its fill/box (M994). The break must stay after the marker so the block's height
     * scan (which ends at its CLOSE) still measures only the block's own content. */
    if (last->type == TK_WORD || last->type == TK_BORDER_CLOSE || last->type == TK_BG_CLOSE) {
        if (b->ntok >= TOK_MAX) return;
        b->toks[b->ntok++] = (tok_t){ m, 0, NO_LINK, STY_NORMAL, (uint8_t)type };   /* off = extra vertical px */
    } else {                                             /* consecutive break: merge, don't stack */
        if (last->type == TK_BREAK && type == TK_PARA) last->type = TK_PARA;   /* upgrade BREAK->PARA */
        if (m > last->off) last->off = m;                /* carry the larger CSS margin onto the merged break */
    }
}
/* Emit a literal word (e.g. a list bullet) by appending it to the text pool. */
static void emit_literal(browser_t *b, const char *s, int style) {
    int start = b->textlen;
    for (int i = 0; s[i] && b->textlen < TEXT_MAX - 1; i++) b->text[b->textlen++] = s[i];
    emit_word(b, start, style, NO_LINK);
}
/* Emit a literal word as a clickable/selectable link (used for <input> fields). */
static void emit_literal_link(browser_t *b, const char *s, int link) {
    int start = b->textlen;
    for (int i = 0; s[i] && b->textlen < TEXT_MAX - 1; i++) b->text[b->textlen++] = s[i];
    emit_word(b, start, STY_LINK, link);
}
static const char *in_get(browser_t *b, const char *id);   /* fwd: <input> field value lookup */
static void in_set(browser_t *b, const char *id, const char *val);          /* fwd */
static void in_name_set(browser_t *b, const char *id, const char *name);    /* fwd */
static int dom_attr_region_at(browser_t *b, int off, int *as, int *ae);     /* fwd: position-handle id resolution */
static int browser_dom_get(const char *id, char *out, int max, int html);   /* fwd */
static int canvas_new_slot(browser_t *b, int cw, int ch);   /* M1796: fwd — allocate a blank writable image slot for a <canvas> */
static void browser_canvas_op(const char *id, int op, int a, int by, int c, int d, const char *color, const char *text, int lw);   /* M1796-M1801: fwd (registered via js_set_canvas) */
static void browser_dom_set(const char *id, const char *value, int html);   /* fwd */


/* Copy up to `dstmax` chars of src[0..srclen) into dst, decoding HTML entities as
 * it goes. Returns chars written. Used for attribute text (e.g. img alt) which the
 * main text loop — the only other place entities are decoded — never sees. */
static int copy_decoded(char *dst, int dstmax, const char *src, int srclen) {
    int p = 0;
    for (int i = 0; i < srclen && p < dstmax; i++) {
        char c = src[i];
        if (c == '&') {
            char dec; int adv = decode_entity(src + i, srclen - i, &dec);
            if (adv) { c = dec; i += adv - 1; }
        }
        dst[p++] = c;
    }
    return p;
}


/* Format an <ol> item number n in the given type into out[<max]: '1' decimal,
 * 'a'/'A' alphabetic (a,b,…,z,aa,…), 'i'/'I' roman (1–3999). */
static void fmt_li_num(int n, char fmt, char *out, int max) {
    int p = 0; if (n < 1) n = 1; if (max < 2) { if (max > 0) out[0] = 0; return; }
    if (fmt == 'a' || fmt == 'A') {
        char base = (fmt == 'A') ? 'A' : 'a'; char tmp[8]; int k = 0;
        while (n > 0 && k < 7) { n--; tmp[k++] = (char)(base + n % 26); n /= 26; }
        while (k && p < max - 1) out[p++] = tmp[--k];
    } else if (fmt == 'i' || fmt == 'I') {
        static const int vals[] = {1000,900,500,400,100,90,50,40,10,9,5,4,1};
        static const char *syms[] = {"m","cm","d","cd","c","xc","l","xl","x","ix","v","iv","i"};
        if (n > 3999) n = 3999;
        for (int i = 0; i < 13 && p < max - 1; i++)
            while (n >= vals[i] && p < max - 1) { for (const char *s = syms[i]; *s && p < max - 1; s++) out[p++] = (fmt == 'I') ? (char)(*s - 32) : *s; n -= vals[i]; }
    } else {
        char tmp[12]; int k = 0; int t = n; while (t && k < 11) { tmp[k++] = (char)('0' + t % 10); t /= 10; }
        while (k && p < max - 1) out[p++] = tmp[--k];
    }
    out[p] = 0;
}

/* Store an href slice, returning its link id (or NO_LINK if full/empty). */
static int add_href(browser_t *b, const char *v, int vlen) {
    if (vlen <= 0 || b->nlink >= LINK_MAX || b->hreflen + vlen >= HREF_MAX) return NO_LINK;
    int off = b->hreflen;
    for (int i = 0; i < vlen; i++) b->hrefs[b->hreflen++] = v[i];
    b->links[b->nlink] = (href_t){ (uint16_t)off, (uint16_t)vlen };
    return b->nlink++;
}
/* Store an "input:ID" link so following it focuses that field for typing. */
static int add_input_link(browser_t *b, const char *id) {
    const char *pfx = "input:"; int pl = 6; int il = 0; while (id[il]) il++;
    if (il <= 0 || b->nlink >= LINK_MAX || b->hreflen + pl + il >= HREF_MAX) return NO_LINK;
    int off = b->hreflen;
    for (int i = 0; i < pl; i++) b->hrefs[b->hreflen++] = pfx[i];
    for (int i = 0; i < il; i++) b->hrefs[b->hreflen++] = id[i];
    b->links[b->nlink] = (href_t){ (uint16_t)off, (uint16_t)(pl + il) };
    return b->nlink++;
}
/* Store a "check:ID" link so following it toggles that checkbox/radio. */
static int add_check_link(browser_t *b, const char *id) {
    const char *pfx = "check:"; int pl = 6; int il = 0; while (id[il]) il++;
    if (il <= 0 || b->nlink >= LINK_MAX || b->hreflen + pl + il >= HREF_MAX) return NO_LINK;
    int off = b->hreflen;
    for (int i = 0; i < pl; i++) b->hrefs[b->hreflen++] = pfx[i];
    for (int i = 0; i < il; i++) b->hrefs[b->hreflen++] = id[i];
    b->links[b->nlink] = (href_t){ (uint16_t)off, (uint16_t)(pl + il) };
    return b->nlink++;
}
/* Store a "selcyc:ID" link so following it cycles a <select> to its next option. */
static int add_select_link(browser_t *b, const char *id) {
    const char *pfx = "selcyc:"; int pl = 7; int il = 0; while (id[il]) il++;
    if (il <= 0 || b->nlink >= LINK_MAX || b->hreflen + pl + il >= HREF_MAX) return NO_LINK;
    int off = b->hreflen;
    for (int i = 0; i < pl; i++) b->hrefs[b->hreflen++] = pfx[i];
    for (int i = 0; i < il; i++) b->hrefs[b->hreflen++] = id[i];
    b->links[b->nlink] = (href_t){ (uint16_t)off, (uint16_t)(pl + il) };
    return b->nlink++;
}
/* Store a "det:N" link so following it toggles <details> index N open/closed. */
static int add_det_link(browser_t *b, int idx) {
    char buf[8]; int p = 0; const char *pfx = "det:"; while (pfx[p]) { buf[p] = pfx[p]; p++; }
    if (idx >= 10) buf[p++] = (char)('0' + idx / 10);
    buf[p++] = (char)('0' + idx % 10); buf[p] = 0;
    if (b->nlink >= LINK_MAX || b->hreflen + p >= HREF_MAX) return NO_LINK;
    int off = b->hreflen;
    for (int i = 0; i < p; i++) b->hrefs[b->hreflen++] = buf[i];
    b->links[b->nlink] = (href_t){ (uint16_t)off, (uint16_t)p };
    return b->nlink++;
}
/* Store an onclick handler as a "javascript:CODE" link so the existing click path
 * (goto_href -> run_js_handler) runs the code; returns the link id. */
static int add_onclick(browser_t *b, const char *code, int codelen) {
    const char *pfx = "javascript:"; int pl = 11;
    if (codelen <= 0 || b->nlink >= LINK_MAX || b->hreflen + pl + codelen >= HREF_MAX) return NO_LINK;
    int off = b->hreflen;
    for (int i = 0; i < pl; i++) b->hrefs[b->hreflen++] = pfx[i];
    for (int i = 0; i < codelen; i++) b->hrefs[b->hreflen++] = code[i];
    b->links[b->nlink] = (href_t){ (uint16_t)off, (uint16_t)(pl + codelen) };
    return b->nlink++;
}
/* Byte offset of the innermost <form>'s own '<' still open at raw position `pos`
 * (the last <form seen before pos with no </form> between it and pos), or -1 if
 * none. A field/submit-link's enclosing form identity, computed on demand from the
 * raw HTML rather than cached at parse time -- a field with no default value/state
 * (so never touched until the user actually clicks it) only gets its in_id/in_name
 * slot allocated at CLICK time, by which point any parse-time "current form" flag
 * is long stale (parsing finished before the click happened at all). Forms don't
 * nest in real HTML, so no depth counting is needed, unlike table_has_field's
 * <table> nesting scan. */
static int enclosing_form_start(browser_t *b, int pos) {
    const char *r = b->raw; int lo = b->bodyoff, hi = b->bodyoff + b->bodylen;
    if (pos < lo) pos = lo; if (pos > hi) pos = hi;
    int form_at = -1;
    for (int i = lo; i < pos; i++) {
        if (r[i] != '<') continue;
        if (i + 5 < hi && lc(r[i+1])=='f' && lc(r[i+2])=='o' && lc(r[i+3])=='r' && lc(r[i+4])=='m'
            && (r[i+5]==' '||r[i+5]=='>'||r[i+5]=='\t'||r[i+5]=='\n'||r[i+5]=='\r')) form_at = i;
        else if (i + 5 < hi && r[i+1]=='/' && lc(r[i+2])=='f' && lc(r[i+3])=='o' && lc(r[i+4])=='r' && lc(r[i+5])=='m') form_at = -1;
    }
    return form_at;
}
/* Decimal-encode a (possibly negative) small int into out, returning the length
 * written (no NUL). Used to smuggle a form's identity through a "submit:" href's text. */
static int fmt_int(char *out, int v) {
    int n = 0; unsigned int u; if (v < 0) { out[n++] = '-'; u = (unsigned int)(-v); } else u = (unsigned int)v;
    char rev[12]; int rn = 0; if (u == 0) rev[rn++] = '0'; else while (u) { rev[rn++] = (char)('0' + u % 10); u /= 10; }
    while (rn > 0) out[n++] = rev[--rn];
    return n;
}
/* Decode the FORM index add_submit_link/fmt_int encoded at the front of a
 * "submit:FORM:ACTION" href (caller must have already confirmed the "submit:"
 * prefix). If skip is non-NULL, *skip gets the byte offset (from href start) where
 * the FORM: prefix ends and ACTION begins. */
static int submit_link_form(const char *hp, int len, int *skip) {
    int k = 7, neg = 0; if (k < len && hp[k] == '-') { neg = 1; k++; }
    int v = 0; while (k < len && hp[k] >= '0' && hp[k] <= '9') { v = v * 10 + (hp[k] - '0'); k++; }
    if (k < len && hp[k] == ':') k++;
    if (skip) *skip = k;
    return neg ? -v : v;
}
/* Store a "submit:FORM:ACTION" link (FORM = enclosing_form_start at raw position
 * `pos`, i.e. the submit element's own <form>, or -1 outside any form); following
 * it (browser_follow) builds a GET query from ONLY that form's fields and
 * navigates. The action is snapshotted at render time because the parse-time
 * form_action is cleared by the </form> close tag. */
static int add_submit_link(browser_t *b, const char *action, int pos) {
    char pfx[24]; int pl = 0; const char *p0 = "submit:"; while (p0[pl]) { pfx[pl] = p0[pl]; pl++; }
    pl += fmt_int(pfx + pl, enclosing_form_start(b, pos)); pfx[pl++] = ':';
    int al = 0; while (action[al]) al++;
    if (b->nlink >= LINK_MAX || b->hreflen + pl + al >= HREF_MAX) return NO_LINK;
    int off = b->hreflen;
    for (int i = 0; i < pl; i++) b->hrefs[b->hreflen++] = pfx[i];
    for (int i = 0; i < al; i++) b->hrefs[b->hreflen++] = action[i];
    b->links[b->nlink] = (href_t){ (uint16_t)off, (uint16_t)(pl + al) };
    return b->nlink++;
}
/* Store an "event:ID" link; activating it (browser_follow) calls js_fire_event(ID,
 * "click") to run a JS-assigned handler (el.onclick=fn / addEventListener). The
 * element gets one via a synthetic data-jsh attribute the handler-registration wrote. */
static int add_event_link(browser_t *b, const char *id, int idlen) {
    const char *pfx = "event:"; int pl = 6;
    if (idlen <= 0 || b->nlink >= LINK_MAX || b->hreflen + pl + idlen >= HREF_MAX) return NO_LINK;
    int off = b->hreflen;
    for (int i = 0; i < pl; i++) b->hrefs[b->hreflen++] = pfx[i];
    for (int i = 0; i < idlen; i++) b->hrefs[b->hreflen++] = id[i];
    b->links[b->nlink] = (href_t){ (uint16_t)off, (uint16_t)(pl + idlen) };
    return b->nlink++;
}
/* Percent-encode s into out (cap = bytes available incl. NUL slot); returns bytes
 * written (no NUL). Unreserved chars pass through, space -> '+', else %XX. */
static int url_encode(char *out, int cap, const char *s) {
    int o = 0;
    for (int i = 0; s[i] && o < cap - 3; i++) {          /* -3: room for a worst-case %XX */
        char c = s[i];
        if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~') out[o++] = c;
        else if (c == ' ') out[o++] = '+';
        else { const char *h = "0123456789ABCDEF"; out[o++]='%'; out[o++]=h[(c>>4)&0xF]; out[o++]=h[c&0xF]; }
    }
    return o;
}
/* Case-insensitive compare of an attribute value (v,vl) against a literal. */
static int attr_eq(const char *v, int vl, const char *lit) {
    int i = 0; for (; i < vl; i++) { if (!lit[i] || lc(v[i]) != lc(lit[i])) return 0; } return lit[i] == 0;
}

/* hexd / hsl_to_rgb / parse_color now live in color.c so the untrusted colour
 * parser can be fuzzed in isolation (M581). */
/* Extract the `color:` value from an inline style="..." string and parse it (a tiny
 * CSS subset). Skips `background-color:` by requiring a property boundary before `color`. */
static uint32_t parse_style_color(const char *s, int n) {
    for (int i = 0; i + 6 <= n; i++) {
        if (lc(s[i])=='c' && lc(s[i+1])=='o' && lc(s[i+2])=='l' && lc(s[i+3])=='o' && lc(s[i+4])=='r' && s[i+5]==':') {
            char before = (i > 0) ? s[i-1] : ' ';   /* must start a property, not be the tail of e.g. background-color */
            if (before==' ' || before==';' || before=='\t' || before=='\n' || before=='"' || before=='\'') {
                int k = i + 6; while (k < n && (s[k]==' '||s[k]=='\t')) k++;     /* skip ws after ':' */
                int vs = k; while (k < n && s[k] != ';' && s[k] != '}') k++;     /* value to ';' or end */
                int ve = k; while (ve > vs && (s[ve-1]==' '||s[ve-1]=='\t')) ve--;  /* trim trailing ws */
                return parse_color(s + vs, ve - vs);
            }
        }
    }
    return 0;
}
/* style_prop (the inline-style property scanner) now lives in cssprop.c so it can
 * be fuzzed in isolation (M583). */
/* Map an inline style's font-weight/font-style to the renderer's text-style enum:
 * font-weight bold/bolder/600..900 -> STY_BOLD; font-style italic/oblique -> STY_EM; else -1.
 * (The renderer's style is a single enum, so bold takes precedence when both are set.) */
static int parse_style_textstyle(const char *s, int n) {
    int vs, ve;
    if (style_prop(s, n, "font-weight", 11, &vs, &ve)) {
        const char *v = s + vs; int vl = ve - vs;
        if (attr_eq(v, vl, "bold") || attr_eq(v, vl, "bolder") ||
            (vl >= 3 && v[0] >= '6' && v[0] <= '9'))         /* 600/700/800/900 */
            return STY_BOLD;
    }
    if (style_prop(s, n, "font-style", 10, &vs, &ve)) {
        const char *v = s + vs; int vl = ve - vs;
        if (attr_eq(v, vl, "italic") || attr_eq(v, vl, "oblique")) return STY_EM;
    }
    /* `font:` shorthand (when the explicit properties above aren't set): a "bold"
     * or "italic" token in the value. Substring (font families rarely contain
     * them); bold wins, mirroring the single-enum precedence above. */
    if (style_prop(s, n, "font", 4, &vs, &ve)) {
        const char *v = s + vs; int vl = ve - vs;
        for (int i = 0; i + 4 <= vl; i++)
            if ((v[i]|32)=='b'&&(v[i+1]|32)=='o'&&(v[i+2]|32)=='l'&&(v[i+3]|32)=='d') return STY_BOLD;
        for (int i = 0; i + 6 <= vl; i++)
            if ((v[i]|32)=='i'&&(v[i+1]|32)=='t'&&(v[i+2]|32)=='a'&&(v[i+3]|32)=='l'&&(v[i+4]|32)=='i'&&(v[i+5]|32)=='c') return STY_EM;
    }
    /* text-decoration:line-through -> strikethrough (the renderer draws a strike line) */
    if (style_prop(s, n, "text-decoration", 15, &vs, &ve) ||
        style_prop(s, n, "text-decoration-line", 20, &vs, &ve)) {
        const char *v = s + vs; int vl = ve - vs;
        for (int i = 0; i + 12 <= vl; i++)               /* "line-through" is 12 chars */
            if (lc(v[i])=='l'&&lc(v[i+1])=='i'&&lc(v[i+2])=='n'&&lc(v[i+3])=='e'&&v[i+4]=='-'&&
                lc(v[i+5])=='t'&&lc(v[i+6])=='h'&&lc(v[i+7])=='r'&&lc(v[i+8])=='o'&&lc(v[i+9])=='u'&&lc(v[i+10])=='g'&&lc(v[i+11])=='h')
                return STY_STRIKE;
    }
    return -1;
}
/* text-decoration / text-decoration-line: underlined if its value contains "underline". */
static int parse_style_underline(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "text-decoration", 15, &vs, &ve) &&
        !style_prop(s, n, "text-decoration-line", 20, &vs, &ve)) return 0;
    for (int i = vs; i + 9 <= ve; i++)                     /* "underline" is 9 chars; i+8 < ve <= n */
        if (lc(s[i])=='u'&&lc(s[i+1])=='n'&&lc(s[i+2])=='d'&&lc(s[i+3])=='e'&&lc(s[i+4])=='r'&&
            lc(s[i+5])=='l'&&lc(s[i+6])=='i'&&lc(s[i+7])=='n'&&lc(s[i+8])=='e') return 1;
    for (int i = vs; i + 4 <= ve; i++)                     /* "none" -> 2 = suppress (e.g. a link's text-decoration:none) */
        if (lc(s[i])=='n'&&lc(s[i+1])=='o'&&lc(s[i+2])=='n'&&lc(s[i+3])=='e') return 2;
    return 0;
}
/* text-transform: 1 = uppercase, 2 = lowercase, 0 = none/unsupported (capitalize is left as-is). */
static int parse_style_transform(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "text-transform", 14, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs;
    if (attr_eq(v, vl, "uppercase")) return 1;
    if (attr_eq(v, vl, "lowercase")) return 2;
    return 0;
}
/* background-color / background (shorthand): the colour drawn behind the text (0 = none).
 * `background` (10) matches only the shorthand (`background:` — the `:` boundary means it
 * never matches `background-color`), and parse_color reads the leading colour token, so a
 * `background: #fff url(..)` shorthand still yields #fff. */
static uint32_t parse_style_bg(const char *s, int n) {
    int vs, ve;
    if (style_prop(s, n, "background-color", 16, &vs, &ve) ||
        style_prop(s, n, "background", 10, &vs, &ve))
        return parse_color(s + vs, ve - vs);
    return 0;
}
/* parse_style_border now lives in cssborder.h so the untrusted CSS `border` value can
 * be host-tested for conformance (border:none/0) + bounds in tests/css (M1777). */
/* text-align: 1 = center, 2 = right, 0 = left/justify/other (the default flow). */
static int parse_style_align(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "text-align", 10, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs;
    if (attr_eq(v, vl, "center")) return 1;
    if (attr_eq(v, vl, "right"))  return 2;
    return 0;
}
/* white-space (M1818): 1 = preserve (pre / pre-wrap / pre-line), 2 = normal
 * (collapse — an explicit reset inside a preformatted ancestor), 0 = unspecified.
 * `nowrap` collapses like normal here (this word-wrapping renderer has no true no-wrap). */
static int parse_style_whitespace(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "white-space", 11, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs;
    if (attr_eq(v, vl, "pre") || attr_eq(v, vl, "pre-wrap") || attr_eq(v, vl, "pre-line")) return 1;
    if (attr_eq(v, vl, "normal") || attr_eq(v, vl, "nowrap")) return 2;
    return 0;
}
/* font-size -> a glyph-scale bucket: 3 (≈ ≥28px / ≥175% / ≥1.8em), 2 (≈ ≥19px / ≥119% /
 * ≥1.2em), else 0 (no override). The bitmap font has no sub-1x, so this only enlarges;
 * small sizes just fall through to the default 1x. Reads the leading integer of the value. */
/* A single CSS <size> token (e.g. "16px", "1.5em", "120%", "large") -> a glyph-
 * scale bucket: 3 (large), 2 (medium), 0 (default 1x). */
static int size_bucket(const char *v, int vl) {
    int i = 0, num = 0, seen = 0;
    while (i < vl && v[i] >= '0' && v[i] <= '9') { num = num*10 + (v[i]-'0'); i++; seen = 1; }
    if (!seen) {                                            /* keywords: large/x-large/… */
        if (attr_eq(v, vl, "large") || attr_eq(v, vl, "larger")) return 2;
        if (attr_eq(v, vl, "x-large") || attr_eq(v, vl, "xx-large")) return 3;
        return 0;
    }
    if (i < vl && v[i] == '.') { i++; while (i < vl && v[i] >= '0' && v[i] <= '9') i++; }  /* skip any fraction */
    /* unit: % / em / rem / px / pt (default ~px). em/rem are relative to 1; % to 100. */
    const char *u = v + i; int ul = vl - i;
    if (ul >= 1 && u[0] == '%')                                          return num >= 175 ? 3 : num >= 119 ? 2 : 0;
    if (ul >= 2 && (u[0]|32)=='e' && (u[1]|32)=='m')                     return num >= 2 ? 3 : num >= 1 ? 2 : 0;
    if (ul >= 3 && (u[0]|32)=='r' && (u[1]|32)=='e' && (u[2]|32)=='m')   return num >= 2 ? 3 : num >= 1 ? 2 : 0;
    return num >= 28 ? 3 : num >= 19 ? 2 : 0;                            /* px / pt / unitless */
}
/* In a `font:` shorthand value, find the offset of the <size> token — a digit run
 * with a unit (a '%' or a letter immediately after), which distinguishes the size
 * (16px) from a unitless numeric weight (600). -1 if none. */
static int font_size_off(const char *v, int vl) {
    for (int i = 0; i < vl; i++) {
        if (v[i] < '0' || v[i] > '9') continue;
        if (i > 0 && v[i-1] >= '0' && v[i-1] <= '9') continue;       /* mid-number */
        int j = i; while (j < vl && v[j] >= '0' && v[j] <= '9') j++;
        if (j < vl && v[j] == '.') { j++; while (j < vl && v[j] >= '0' && v[j] <= '9') j++; }
        char c = (j < vl) ? v[j] : 0;
        if (c == '%' || ((c|32) >= 'a' && (c|32) <= 'z')) return i;   /* has a unit -> it's the size */
    }
    return -1;
}
static int parse_style_fontsize(const char *s, int n) {
    int vs, ve;
    if (style_prop(s, n, "font-size", 9, &vs, &ve)) return size_bucket(s + vs, ve - vs);
    if (style_prop(s, n, "font", 4, &vs, &ve)) {              /* `font:` shorthand -> find its size token */
        int off = font_size_off(s + vs, ve - vs);
        if (off >= 0) return size_bucket(s + vs + off, ve - vs - off);
    }
    return 0;
}
/* line-height -> px value (0 = not set / use default).
 * Handles: Npx -> N; unitless N or N.M -> round(N*16); Nem -> round(N*16); normal -> 0.
 * Clamps to 8..120 so a stray large value can't blow up layout. */
static int parse_style_lineheight(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "line-height", 11, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs;
    /* skip leading whitespace */
    int i = 0; while (i < vl && (v[i]==' '||v[i]=='\t')) i++;
    /* "normal" keyword -> not set */
    if (vl - i >= 6 && (v[i]|32)=='n' && (v[i+1]|32)=='o' && (v[i+2]|32)=='r' && (v[i+3]|32)=='m' && (v[i+4]|32)=='a' && (v[i+5]|32)=='l') return 0;
    /* read integer part */
    int num = 0, seen = 0;
    while (i < vl && v[i] >= '0' && v[i] <= '9') { num = num*10 + (v[i]-'0'); i++; seen = 1; }
    if (!seen) return 0;
    /* optional fractional part: e.g. "1.5" -> num=1, frac=5 (tenths) */
    int frac = 0; /* in tenths */
    if (i < vl && v[i] == '.') {
        i++;
        if (i < vl && v[i] >= '0' && v[i] <= '9') { frac = v[i] - '0'; i++; }
        while (i < vl && v[i] >= '0' && v[i] <= '9') i++; /* skip rest */
    }
    /* unit: px / em / rem / unitless */
    const char *u = v + i; int ul = vl - i;
    /* skip trailing whitespace in unit */
    while (ul > 0 && (u[ul-1]==' '||u[ul-1]=='\t')) ul--;
    int px;
    int is_px  = (ul >= 2 && (u[0]|32)=='p' && (u[1]|32)=='x');
    int is_em  = (ul >= 2 && (u[0]|32)=='e' && (u[1]|32)=='m');
    int is_rem = (ul >= 3 && (u[0]|32)=='r' && (u[1]|32)=='e' && (u[2]|32)=='m');
    int is_pct = (ul >= 1 && u[0] == '%');
    if (is_px) {
        px = num;
    } else if (is_em || is_rem || ul == 0) {
        /* unitless or em: multiply by 16 (1 em = 16px baseline) */
        px = num * 16 + (frac * 16 + 5) / 10;  /* round(frac/10 * 16) */
    } else if (is_pct) {
        px = (num * 16 + 50) / 100;             /* percentage of 16px base */
    } else {
        /* unknown unit: treat as px */
        px = num;
    }
    if (px < 8)  return 8;
    if (px > 120) return 120;
    return px;
}
/* Vertical margin (margin-top, or the `margin` shorthand's first/top value) in px,
 * so the otherwise box-model-less renderer can honour author spacing between blocks.
 * Only px and em (~16px) are read; capped so a stray huge value can't blow up layout. */
/* ---- viewport units (M1929) -------------------------------------------------
 * `vw`/`vh` resolve against the VIEWPORT, not the containing block, so unlike %
 * they do not need a box tree — just the window's content box. Found by actually
 * rendering example.com: its stylesheet is
 *     body{background:#eee;width:60vw;margin:15vh auto;...}
 * so without vw/vh the canonical test page laid out full-width and flush to the
 * top instead of as a centred column. The units were simply unparsed.
 *
 * The viewport is recorded by browser_render and read here at PARSE time, which
 * means a page parsed before the FIRST render of a given window size resolves
 * against the previous size (or the seed below). That is a deliberate trade: the
 * alternative is carrying the unit through every token payload and resolving at
 * paint, and a window is not normally resized between parsing a page and drawing
 * it. The seed is a typical content box so a first page is still sensible. */
static int g_vp_w = 980, g_vp_h = 700;

/* A length's unit multiplier, applied to an already-parsed integer `num`.
 * Returns the px value. Handles em/rem (~16px), vw, vh; anything else is px. */
static int css_unit_px(int num, const char *u, int ul) {
    if (ul >= 2 && (u[0]|32)=='v' && (u[1]|32)=='w') return num * g_vp_w / 100;
    if (ul >= 2 && (u[0]|32)=='v' && (u[1]|32)=='h') return num * g_vp_h / 100;
    if (ul >= 3 && (u[0]|32)=='r' && (u[1]|32)=='e' && (u[2]|32)=='m') return num * 16;
    if (ul >= 2 && (u[0]|32)=='e' && (u[1]|32)=='m') return num * 16;
    return num;
}

static int parse_px_val(const char *v, int vl) {
    int i = 0, num = 0, seen = 0;
    while (i < vl && (v[i] == ' ' || v[i] == '\t')) i++;
    while (i < vl && v[i] >= '0' && v[i] <= '9') { num = num*10 + (v[i]-'0'); i++; seen = 1; }
    if (!seen) return 0;
    if (i < vl && v[i] == '.') { i++; while (i < vl && v[i] >= '0' && v[i] <= '9') i++; }  /* skip fraction */
    const char *u = v + i; int ul = vl - i;
    num = css_unit_px(num, u, ul);                                       /* em / vw / vh (M1929) */
    return num > 120 ? 120 : num;                                        /* cap */
}
/* Total top vertical space a block contributes in this box-model-less renderer:
 * margin-top + padding-top (or the `margin`/`padding` shorthands' top value). px/em. */
static int parse_style_vspace(const char *s, int n) {
    int m = 0, vs, ve;
    if (style_prop(s, n, "margin-top", 10, &vs, &ve))  m += parse_px_val(s + vs, ve - vs);
    else if (style_prop(s, n, "margin", 6, &vs, &ve))  m += parse_px_val(s + vs, ve - vs);   /* shorthand: 1st value = top */
    /* padding-top used to be summed in here, which put it OUTSIDE the block's
     * background (it became pre-block spacing, i.e. margin-like) and left
     * padding-bottom dropped entirely. Since M1900 vertical padding is real box
     * geometry carried in the block token — see parse_style_padding_tb. */
    return m > 200 ? 200 : m;
}

/* margin-bottom in px (M1903). Until now only margin-top was ever read, so a
 * block's bottom margin was silently dropped — asymmetric with everything else in
 * the box model once padding-bottom started working (M1900). Applied as trailing
 * block spacing OUTSIDE the background (margins are outside the box; padding is
 * inside it), by handing it to emit_break's pending-margin slot on the close tag,
 * where it then COLLAPSES with the next block's margin-top through the existing
 * max() rule. */
static int parse_style_margin_bottom(const char *s, int n) {
    int vs, ve, m = 0;
    if (style_prop(s, n, "margin-bottom", 13, &vs, &ve)) m = parse_px_val(s + vs, ve - vs);
    else if (style_prop(s, n, "margin", 6, &vs, &ve))    m = parse_px_val(s + vs, ve - vs);  /* shorthand: 1st value applies to top+bottom */
    return m > 200 ? 200 : m;
}

/* box-sizing: border-box? (M1903)
 *
 * Near-universal in real CSS, and it matters now that padding participates in the
 * width constraint (M1897): with border-box the specified `width` INCLUDES the
 * padding, so the content width is width - padding-left - padding-right.
 *
 * Note on borders: in this renderer a block's border is stroked ON the padding
 * box's edge (M1901) rather than occupying its own ring of layout space, so
 * border width is not subtracted here. That keeps border-box self-consistent with
 * how the border is actually painted. */
static int parse_style_border_box(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "box-sizing", 10, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs, i = 0;
    while (i < vl && v[i] == ' ') i++;
    return (vl - i >= 6 && (v[i]|32) == 'b' && (v[i+1]|32) == 'o' && (v[i+2]|32) == 'r');
}

/* Vertical padding in px, capped at 255 so each side fits one byte of the block
 * token's payload. (M1900) */
static void parse_style_padding_tb(const char *s, int n, int *outt, int *outb) {
    int vs, ve, t = 0, bb = 0;
    if (style_prop(s, n, "padding-top", 11, &vs, &ve))    t = parse_px_val(s + vs, ve - vs);
    else if (style_prop(s, n, "padding", 7, &vs, &ve))    t = parse_px_val(s + vs, ve - vs);
    if (style_prop(s, n, "padding-bottom", 14, &vs, &ve)) bb = parse_px_val(s + vs, ve - vs);
    else if (style_prop(s, n, "padding", 7, &vs, &ve))    bb = parse_px_val(s + vs, ve - vs);
    *outt = t > 255 ? 255 : t; *outb = bb > 255 ? 255 : bb;
}

/* Vertical padding out of a block token's `off` word. maxw is capped at 4000 so
 * it lives in the low 16 bits, leaving the top two bytes for padding. (M1900) */
static inline int box_pad_top(const tok_t *tk)    { return (int)((tk->off >> 16) & 0xFF); }
static inline int box_pad_bottom(const tok_t *tk) { return (int)((tk->off >> 24) & 0xFF); }
/* Left indent a block contributes (margin-left + padding-left), in px, so indented
 * content (nested sections, quoted blocks) renders shifted right. Hooks the same
 * curindent mechanism <blockquote> uses; the shorthand's left value isn't decoded. */
/* The left value of a 1-4 token `margin`/`padding` shorthand: 4 tokens -> 4th
 * (top right bottom left), 2 or 3 -> 2nd (the horizontal value), 1 -> 1st (all sides). */
static int shorthand_left(const char *v, int vl) {
    int st[4], n = 0, i = 0;
    while (i < vl && n < 4) {
        while (i < vl && (v[i] == ' ' || v[i] == '\t')) i++;
        if (i >= vl) break;
        st[n++] = i;
        while (i < vl && v[i] != ' ' && v[i] != '\t') i++;
    }
    if (n < 1) return 0;
    int li = (n >= 4) ? 3 : (n >= 2) ? 1 : 0;
    return parse_px_val(v + st[li], vl - st[li]);
}
static int parse_style_hspace(const char *s, int n) {
    int m = 0, vs, ve;
    if (style_prop(s, n, "margin-left", 11, &vs, &ve))  m += parse_px_val(s + vs, ve - vs);
    else if (style_prop(s, n, "margin", 6, &vs, &ve))   m += shorthand_left(s + vs, ve - vs);   /* `margin: V H` etc. */
    /* Horizontal PADDING used to be folded in here, so a padded block was indented
     * on the left while its text ran to the container's right edge — padding-right
     * was dropped entirely. Since M1897 padding is real box geometry: it rides in
     * the block token and box_solve_column insets BOTH edges via the §10.3.3
     * solver, while the BACKGROUND still paints the padding box (see below). */
    return m > 200 ? 200 : m;
}

/* Horizontal padding in px, capped at 255 so each side fits one byte of the block
 * token's 16-bit payload. (M1897) */
static void parse_style_padding_lr(const char *s, int n, int *outl, int *outr) {
    int vs, ve, l = 0, r = 0;
    if (style_prop(s, n, "padding-left", 12, &vs, &ve))  l = parse_px_val(s + vs, ve - vs);
    else if (style_prop(s, n, "padding", 7, &vs, &ve))   l = shorthand_left(s + vs, ve - vs);
    if (style_prop(s, n, "padding-right", 13, &vs, &ve)) r = parse_px_val(s + vs, ve - vs);
    else if (style_prop(s, n, "padding", 7, &vs, &ve))   r = shorthand_left(s + vs, ve - vs);
    *outl = l > 255 ? 255 : l; *outr = r > 255 ? 255 : r;
}
/* returns 1 if the element should be hidden: display:none OR visibility:hidden.
 * (In this box-model-less renderer visibility:hidden can't preserve the element's
 * space, so it hides the content like display:none — fine for reader-mode.) */
static int parse_style_display(const char *s, int n) {
    int vs, ve;
    if (style_prop(s, n, "display", 7, &vs, &ve) && attr_eq(s + vs, ve - vs, "none")) return 1;
    if (style_prop(s, n, "visibility", 10, &vs, &ve) && attr_eq(s + vs, ve - vs, "hidden")) return 1;
    return 0;
}
/* display:flex / inline-flex -> 1 (lay direct children in a ROW). flex-direction:column -> 0:
 * a column flex stacks children vertically, which is already the default block flow, so we don't
 * switch to (horizontal) flex mode for it — that keeps a column layout from rendering as a row. */
static int parse_style_flex(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "display", 7, &vs, &ve)) return 0;
    if (!(attr_eq(s + vs, ve - vs, "flex") || attr_eq(s + vs, ve - vs, "inline-flex"))) return 0;
    /* NOTE: `display:grid` deliberately NOT mapped to flex-row — tried it (M1438 experiment),
     * but flex-row-wrap made grid heroes/2-col layouts flow awkwardly for an uncertain gain;
     * the clean vertical-stack fallback renders more reliably. Real grid needs box layout. */
    if (style_prop(s, n, "flex-direction", 14, &vs, &ve) && attr_eq(s + vs, ve - vs, "column")) return 0;
    return 1;
}
/* flex `gap` / `column-gap` in px (0 = use the default item spacing). */
static int parse_style_gap(const char *s, int n) {
    int vs, ve;
    if (style_prop(s, n, "gap", 3, &vs, &ve)) return parse_px_val(s + vs, ve - vs);
    if (style_prop(s, n, "column-gap", 10, &vs, &ve)) return parse_px_val(s + vs, ve - vs);
    return 0;
}
/* justify-content (main axis): 1 = center, 2 = end/right, 3 = space-between/around, 0 = start (default). */
static int parse_style_justify(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "justify-content", 15, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs;
    if (attr_eq(v, vl, "center")) return 1;
    if (attr_eq(v, vl, "flex-end") || attr_eq(v, vl, "end") || attr_eq(v, vl, "right")) return 2;
    if (attr_eq(v, vl, "space-between") || attr_eq(v, vl, "space-around") || attr_eq(v, vl, "space-evenly")) return 3;
    return 0;   /* flex-start / other -> start */
}
/* max-width in px (0 = none). Used to narrow + centre a block into a readable column
 * (the `max-width:Npx; margin:0 auto` pattern); centring is assumed (the common case). */
static int parse_style_maxwidth(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "max-width", 9, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs, i = 0, num = 0;   /* own parse: parse_px_val caps at 120, too small for a column width */
    while (i < vl && v[i] == ' ') i++;
    while (i < vl && v[i] >= '0' && v[i] <= '9') { num = num*10 + (v[i]-'0'); i++; }
    num = css_unit_px(num, v + i, vl - i);                   /* em / vw / vh (M1932) */   /* em -> ~16px */
    return num > 4000 ? 4000 : num;                                       /* sane upper cap */
}

/* `width: <px>` on a block, in the same spirit as parse_style_maxwidth (its own
 * digit scan, because parse_px_val caps at 120 — far too small for a column).
 * Returns 0 for absent/auto/percentage. (M1896) */
static int parse_style_width_px(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "width", 5, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs, i = 0, num = 0, digits = 0;
    while (i < vl && v[i] == ' ') i++;
    while (i < vl && v[i] >= '0' && v[i] <= '9') { num = num*10 + (v[i]-'0'); i++; digits++; }
    if (!digits) return 0;                                   /* auto / inherit / calc(...) */
    if (i < vl && v[i] == '%') return 0;                     /* percentages not handled here */
    num = css_unit_px(num, v + i, vl - i);                   /* em / vw / vh (M1929) */
    return num > 4000 ? 4000 : num;
}

/* `height: <px>` on a block (M1904). Until now `height` was only ever read as the
 * <img height=> HTML attribute — CSS height on a block was entirely unsupported,
 * even though the layout engine has modelled it since M1894. 0 = absent/auto/%. */
static int parse_style_height_px(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "height", 6, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs, i = 0, num = 0, digits = 0;
    while (i < vl && v[i] == ' ') i++;
    while (i < vl && v[i] >= '0' && v[i] <= '9') { num = num*10 + (v[i]-'0'); i++; digits++; }
    if (!digits) return 0;
    if (i < vl && v[i] == '%') return 0;
    num = css_unit_px(num, v + i, vl - i);                   /* em / vw / vh (M1932) */
    return num > 4000 ? 4000 : num;
}

/* `min-height: <px>` on a block (M1905). Grows the box when the content is
 * shorter, using the same mechanism as `height`.
 *
 * HISTORICAL NOTE (corrected M1910): this spot used to carry a comment claiming
 * `max-height` was blocked "architecturally rather than [by] effort", because a
 * block's painted extent IS its flow advance, and concluding that "shrinking the
 * advance instead would overlap whatever follows, which is worse than ignoring
 * the property". That conclusion was WRONG: overlapping the following content is
 * precisely what CSS `max-height` with the default `overflow: visible` does — the
 * box stops at the limit and its content spills out of it. So max-height is just
 * the symmetric clamp to the code above (`height`/`min-height` only ever RAISE
 * the cursor to a target; max-height LOWERS it), and it is implemented below.
 * float/position/z-index really do still need out-of-flow boxes. */
static int parse_style_minheight_px(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "min-height", 10, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs, i = 0, num = 0, digits = 0;
    while (i < vl && v[i] == ' ') i++;
    while (i < vl && v[i] >= '0' && v[i] <= '9') { num = num*10 + (v[i]-'0'); i++; digits++; }
    if (!digits) return 0;
    if (i < vl && v[i] == '%') return 0;
    num = css_unit_px(num, v + i, vl - i);                   /* em / vw / vh (M1932) */
    return num > 4000 ? 4000 : num;
}

/* `float: left | right` (M1928). Returns 1 for left, 2 for right, else 0.
 *
 * This renderer has no out-of-flow boxes, so a floated BLOCK CONTAINER (whose
 * children would have to be laid out inside a narrowed sub-column) is still out
 * of reach. A floated IMAGE is not: it is a single rectangle, so it can be
 * placed at the column edge, registered as an obstacle for the lines it spans,
 * and skipped in the vertical flow — which is the case real pages overwhelmingly
 * use floats for (text wrapping around a picture). */
static int parse_style_float(const char *st, int n) {
    int vs, ve;
    if (!style_prop(st, n, "float", 5, &vs, &ve)) return 0;
    const char *v = st + vs; int vl = ve - vs, i = 0;
    while (i < vl && v[i] == ' ') i++;
    if (i + 4 <= vl && (v[i]|32)=='l' && (v[i+1]|32)=='e' && (v[i+2]|32)=='f' && (v[i+3]|32)=='t') return 1;
    if (i + 5 <= vl && (v[i]|32)=='r' && (v[i+1]|32)=='i' && (v[i+2]|32)=='g' && (v[i+3]|32)=='h' && (v[i+4]|32)=='t') return 2;
    return 0;
}

/* `clear: left | right | both` — bit0 = clear left floats, bit1 = right. (M1928) */
static int parse_style_clear(const char *st, int n) {
    int vs, ve;
    if (!style_prop(st, n, "clear", 5, &vs, &ve)) return 0;
    const char *v = st + vs; int vl = ve - vs, i = 0;
    while (i < vl && v[i] == ' ') i++;
    if (i + 4 <= vl && (v[i]|32)=='l' && (v[i+1]|32)=='e' && (v[i+2]|32)=='f' && (v[i+3]|32)=='t') return 1;
    if (i + 5 <= vl && (v[i]|32)=='r' && (v[i+1]|32)=='i' && (v[i+2]|32)=='g' && (v[i+3]|32)=='h' && (v[i+4]|32)=='t') return 2;
    if (i + 4 <= vl && (v[i]|32)=='b' && (v[i+1]|32)=='o' && (v[i+2]|32)=='t' && (v[i+3]|32)=='h') return 3;
    return 0;
}

/* `overflow: hidden` (or `clip`) on a block (M1917). Only these two values are
 * honoured: they clip with no interaction affordance, so clipping IS the whole
 * behaviour. `auto` and `scroll` also clip in CSS, but they clip WITH a scrollbar
 * and scrollable content, and silently swallowing content the user could no
 * longer reach would be worse than leaving it visible — so they are deliberately
 * not treated as hidden. */
static int parse_style_overflow_hidden(const char *st, int n) {
    int vs, ve;
    if (!style_prop(st, n, "overflow", 8, &vs, &ve) &&
        !style_prop(st, n, "overflow-y", 10, &vs, &ve)) return 0;
    const char *v = st + vs; int vl = ve - vs, i = 0;
    while (i < vl && v[i] == ' ') i++;
    if (i + 6 <= vl && (v[i]|32)=='h' && (v[i+1]|32)=='i' && (v[i+2]|32)=='d'
        && (v[i+3]|32)=='d' && (v[i+4]|32)=='e' && (v[i+5]|32)=='n') return 1;
    if (i + 4 <= vl && (v[i]|32)=='c' && (v[i+1]|32)=='l' && (v[i+2]|32)=='i'
        && (v[i+3]|32)=='p') return 1;
    return 0;
}

/* `max-height: <px>` on a block (M1910). Caps the box; taller content overflows
 * it (CSS 2.1 §10.7 + the default `overflow: visible`). Capped at 4000 like the
 * others so the value always fits the 12 bits the CLOSE token carries it in. */
static int parse_style_maxheight_px(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "max-height", 10, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs, i = 0, num = 0, digits = 0;
    while (i < vl && v[i] == ' ') i++;
    while (i < vl && v[i] >= '0' && v[i] <= '9') { num = num*10 + (v[i]-'0'); i++; digits++; }
    if (!digits) return 0;                      /* `none` (the initial value) included */
    if (i < vl && v[i] == '%') return 0;        /* percentages need a resolved containing block */
    num = css_unit_px(num, v + i, vl - i);                   /* em / vw / vh (M1932) */
    return num > 4000 ? 4000 : num;
}

/* Which horizontal margins are `auto` — bit0 = margin-left, bit1 = margin-right.
 * `margin: 0 auto` (the centring idiom) sets both via the shorthand's H part. */
static int parse_style_auto_margins(const char *s, int n) {
    int vs, ve, bits = 0;
    if (style_prop(s, n, "margin-left", 11, &vs, &ve)) {
        if (ve - vs >= 4 && (s[vs]|32)=='a') bits |= 1;
    }
    if (style_prop(s, n, "margin-right", 12, &vs, &ve)) {
        if (ve - vs >= 4 && (s[vs]|32)=='a') bits |= 2;
    }
    if (!bits && style_prop(s, n, "margin", 6, &vs, &ve)) {
        /* Scan the shorthand's words; an `auto` in the horizontal position sets
         * both sides, which is what `margin: 0 auto` means. */
        const char *v = s + vs; int vl = ve - vs, i = 0;
        while (i < vl) {
            while (i < vl && v[i] == ' ') i++;
            int st2 = i;
            while (i < vl && v[i] != ' ') i++;
            if (i - st2 == 4 && (v[st2]|32)=='a' && (v[st2+1]|32)=='u'
                             && (v[st2+2]|32)=='t' && (v[st2+3]|32)=='o') { bits |= 3; break; }
        }
    }
    return bits;
}

/* Narrow the render column [*cl,*cr) to a block box's CONTENT box, using the
 * shared layout engine's CSS 2.1 §10.3.3 width solver (kernel/layout.h) instead
 * of the old always-centre approximation (M1896).
 *
 * Token payload: off = max-width px (0 = none), len = specified width px
 * (0 = auto), style bit0/bit1 = margin-left/right is `auto`.
 *
 * DELIBERATE DEVIATION, preserved from M933: `max-width` with no explicit
 * horizontal margins still CENTRES the column. Per spec max-width only clamps
 * the used width and the box stays left-aligned, but M933 introduced this as a
 * readability feature ("readable column") and existing pages are built around
 * it, so that case is expressed as "both margins auto" and routed through the
 * same solver rather than being special-cased in the renderer. Explicit `width`
 * and explicit `margin:auto` now follow the real rule. */
/* Solves the block's column and reports TWO geometries, because CSS needs both
 * and they differ whenever there is padding (M1897):
 *   *cl/*cr  -> the CONTENT box: where text lays out and wraps.
 *   *pbl/*pbr -> the PADDING box: what a background paints over (CSS 2.1 §14.2,
 *                background covers the padding box, not the content box).
 * Passing the content box as a background rect makes a padded block's background
 * hug its text instead of extending around it. `pbl`/`pbr` may be NULL for
 * callers that only need to wrap text (the background forward-scan). */
static void box_solve_column(const tok_t *tk, int *cl, int *cr, int *pbl, int *pbr) {
    int avail = *cr - *cl;
    if (pbl) *pbl = *cl;
    if (pbr) *pbr = *cr;
    if (avail <= 0) return;

    int spec_w = (int)tk->len;          /* 0 = auto */
    int maxw   = (int)(tk->off & 0xFFFF);   /* low 16 bits; upper bytes are v-padding */
    int autob  = (int)tk->style & 3;
    int padl   = (int)(tk->link & 0xFF);            /* horizontal padding, packed 8+8 */
    int padr   = (int)((tk->link >> 8) & 0xFF);

    lay_box lb;
    for (unsigned i = 0; i < sizeof lb; i++) ((unsigned char *)&lb)[i] = 0;
    lb.display = LAY_BLOCK;
    lb.height = LAY_AUTO;
    lb.first_child = lb.next_sibling = -1;

    /* box-sizing:border-box (style bit 2): the specified width INCLUDES the
     * padding, so peel the padding off to get the content width (M1903). */
    if (spec_w > 0 && (tk->style & 4)) {
        spec_w -= padl + padr;
        if (spec_w < 0) spec_w = 0;
    }
    lb.width = spec_w > 0 ? spec_w : LAY_AUTO;
    if (maxw > 0) {                      /* §10.4: max-width clamps the used width */
        int base = (lb.width == LAY_AUTO) ? avail : lb.width;
        if (base > maxw) lb.width = maxw;
    }
    /* The M933 centring case: a clamped column with no margins stated. */
    if (!autob && maxw > 0 && spec_w == 0) autob = 3;

    lb.margin.left  = (autob & 1) ? LAY_AUTO : 0;
    lb.margin.right = (autob & 2) ? LAY_AUTO : 0;

    lb.padding.left  = padl;
    lb.padding.right = padr;

    int ml, mr, w;
    lay_solve_width(&lb, avail, &ml, &mr, &w);
    (void)mr;
    int left = *cl + ml;                 /* the box's left border edge */
    if (pbl) *pbl = left;                /* padding box spans the padding + content */
    if (pbr) *pbr = left + padl + w + padr;
    *cl = left + padl;                   /* content box sits inside the padding */
    *cr = *cl + w;
}
/* list-style-type (or the `list-style` shorthand) on a <ul>/<ol>. Returns a marker code
 * for the list's items, applied per-<li>:
 *   0   = not specified (caller keeps the depth-varied default bullet / <ol> numbering)
 *  'N'  = none  -> suppress the marker entirely (the common nav-menu / link-list case)
 *  '-'  = disc, '*' = circle, '+' = square  (the 8x16 font has no bullet glyphs, so the
 *         three CSS bullet kinds map onto these ASCII markers — see kernel/font.c)
 *  '1'  = decimal/numbered (lets a <ul> opt into numbering, or restores it on an <ol>)
 * The shorthand `list-style:` can carry the type token anywhere (e.g. `none`, or
 * `square inside`); we scan its space-separated words for a known keyword. */
static int parse_style_listtype(const char *s, int n) {
    int vs, ve;
    if (!style_prop(s, n, "list-style-type", 15, &vs, &ve) &&
        !style_prop(s, n, "list-style", 10, &vs, &ve)) return 0;
    const char *v = s + vs; int vl = ve - vs;
    for (int i = 0; i < vl; ) {                              /* walk space-separated words (shorthand may list several) */
        while (i < vl && (v[i]==' '||v[i]=='\t')) i++;
        int w = i; while (i < vl && v[i]!=' ' && v[i]!='\t') i++;
        int wl = i - w; const char *p = v + w;
        if      (attr_eq(p, wl, "none"))    return 'N';
        else if (attr_eq(p, wl, "disc"))    return '-';
        else if (attr_eq(p, wl, "circle"))  return '*';
        else if (attr_eq(p, wl, "square"))  return '+';
        else if (attr_eq(p, wl, "decimal")) return '1';
    }
    return 0;   /* a value we don't render (e.g. `url(...)`, `inside`, lower-roman) -> keep the default */
}

/* void (self-closing) elements have no close tag, so they can't open an onclick scope */
static int is_void_tag(const char *t) {
    return tageq(t,"input")||tageq(t,"img")||tageq(t,"br")||tageq(t,"hr")||tageq(t,"meta")||
           tageq(t,"link")||tageq(t,"area")||tageq(t,"col")||tageq(t,"base")||tageq(t,"wbr")||
           tageq(t,"embed")||tageq(t,"source");
}
/* HTML block-level elements: a background-color on one fills the whole line band
 * (an inline element's bg only highlights behind its text). */
static int is_block_tag(const char *t) {
    /* NOT `body`: it never reaches handle_tag (a terminal else-if in the parse loop
     * consumes it), so listing it here would be dead code. body's box is applied to
     * the page's content column in browser_render instead -- see root_w/root_ma. */
    return tageq(t,"div")||tageq(t,"p")||tageq(t,"section")||tageq(t,"article")||
           tageq(t,"header")||tageq(t,"footer")||tageq(t,"nav")||tageq(t,"main")||
           tageq(t,"aside")||tageq(t,"blockquote")||tageq(t,"ul")||tageq(t,"ol")||
           tageq(t,"li")||tageq(t,"dl")||tageq(t,"dd")||tageq(t,"dt")||tageq(t,"table")||
           tageq(t,"tr")||tageq(t,"td")||tageq(t,"th")||tageq(t,"figure")||tageq(t,"form")||
           tageq(t,"fieldset")||tageq(t,"pre")||tageq(t,"address")||tageq(t,"details")||
           tageq(t,"summary")||tageq(t,"figcaption")||
           (t[0]=='h' && t[1]>='1' && t[1]<='6' && t[2]==0);
}
/* <style> support (defined after sel_parse): parse a <style> body into b->css_* rules,
 * and find the cascaded color/text-style for one element from those rules. */
static void capture_css(browser_t *b, const char *s, int n);
static int  css_match(browser_t *b, const char *tag, const char *attrs, int attrlen,
                      uint32_t *color, int *textstyle, int *underline, int *transform, uint32_t *bg,
                      int *align, int *size, int *hidden, int *margin, int *indent, uint32_t *border, int *flex,
                      int *lineheight, int *ws, int *cwidth, int *cmauto,
                      int *cpl, int *cpr, int *cpt, int *cpb, int *cheight);
static int  css_match_list(browser_t *b, const char *tag, const char *attrs, int attrlen);

/* Resolve the best URL for an <img> tag with "fallback only" semantics:
 * if src= is present and non-empty it is returned unchanged (zero regression).
 * When src is absent or empty we try srcset= (first candidate URL, stripping
 * the optional " 320w" / " 2x" descriptor), then data-src=, data-original=,
 * data-lazy-src= — first non-empty wins.  Returns 1 and sets *v/*vl to a
 * slice within attrs[0..attrlen); returns 0 if no usable URL found. */
static int img_src_attr(const char *attrs, int attrlen,
                        const char **v, int *vl) {
    /* 1. Canonical src= — unchanged behaviour. */
    if (find_attr(attrs, attrlen, "src", v, vl) && *vl > 0) return 1;
    /* 2. srcset="url descriptor, url descriptor, ..." — take first candidate URL
     *    (everything up to the first space or comma). */
    { const char *sv; int sl;
      if (find_attr(attrs, attrlen, "srcset", &sv, &sl) && sl > 0) {
          /* skip leading whitespace */
          int s = 0; while (s < sl && (sv[s]==' '||sv[s]=='\t'||sv[s]=='\n'||sv[s]=='\r')) s++;
          int e = s;
          while (e < sl && sv[e]!=' ' && sv[e]!='\t' && sv[e]!=',' &&
                 sv[e]!='\n' && sv[e]!='\r') e++;
          if (e > s) { *v = sv + s; *vl = e - s; return 1; }
      } }
    /* 3. data-src= / data-original= / data-lazy-src= (lazy-load patterns). */
    { static const char * const lazy[] = { "data-src", "data-original", "data-lazy-src", 0 };
      for (int i = 0; lazy[i]; i++) {
          if (find_attr(attrs, attrlen, lazy[i], v, vl) && *vl > 0) return 1;
      } }
    return 0;
}

static void handle_tag(browser_t *b, const char *tag, int closing,
                       const char *attrs, int attrlen,
                       int *style, int *linkdepth, int *curlink) {
    b->pending_vmargin = 0;   /* per-tag: cleared each call; set below from CSS margin, consumed by the next emit_break */
    /* inline onclick="CODE": make the element's content a clickable javascript: link,
     * scoped to the element (depth-counted so nested same-name tags don't end it early). */
    if (b->oc_depth > 0 && tageq(tag, b->oc_tag)) {
        if (closing) { if (--b->oc_depth == 0) { *curlink = b->oc_link; if (*style == STY_LINK) *style = b->oc_style; } }
        else b->oc_depth++;
    }
    /* style scope STACK (color / font-weight / font-style from inline style= and <style> rules).
     * A styled element pushes a frame; its matching close pops it (restoring colour + text-style),
     * so nested styled elements compose. Same-tag nesting is depth-counted per frame; the restore
     * mirrors the oc_* link scope (only if *style is still the one we set). */
    if (closing) {
        if (b->sc_sp > 0 && tageq(tag, b->sc[b->sc_sp-1].tag)) {
            if (--b->sc[b->sc_sp-1].depth == 0) {
                int sp = --b->sc_sp;
                b->curcolor = b->sc[sp].savecolor;
                b->curbg = b->sc[sp].savebg;
                b->curul = b->sc[sp].saveul;
                b->curtransform = b->sc[sp].savetransform;
                b->curalign = b->sc[sp].savealign;
                b->curscale = b->sc[sp].savescale;
                b->curlh_css = b->sc[sp].savelh;
                b->curindent = b->sc[sp].saveindent;
                b->curprews = b->sc[sp].saveprews;
                if (b->sc[sp].hidden && b->n_hidden > 0) b->n_hidden--;   /* leaving a display:none element */
                if (b->sc[sp].setstyle >= 0 && *style == b->sc[sp].setstyle) *style = b->sc[sp].savestyle;
                /* CLOSE carries padding-bottom: BORDER_CLOSE is emitted BEFORE
                 * MAXW_CLOSE, so `cy` has not yet had the bottom band added and the
                 * stroke would otherwise stop short of its own box (M1901). */
                if (b->sc[sp].hasborder && b->ntok < TOK_MAX) b->toks[b->ntok++] = (tok_t){ (uint32_t)(b->sc[sp].padb & 0xFF), 0, NO_LINK, STY_NORMAL, TK_BORDER_CLOSE };
                if (b->sc[sp].hasflex && b->ntok < TOK_MAX) b->toks[b->ntok++] = (tok_t){ 0, 0, NO_LINK, STY_NORMAL, TK_FLEX_CLOSE };   /* end the flex row */
                /* CLOSE carries padding-bottom in `off` so the renderer can add the
                 * bottom band; BG_CLOSE is emitted after it, so the background's
                 * forward scan naturally includes that band. (M1900) */
                /* CLOSE also carries the declared HEIGHT in `len` and the border-box
                 * bit in off:8 — close is exactly when the renderer needs them, to
                 * stretch the block down to its declared height (M1904). */
                /* `off` bits: 0-7 padding-bottom, 8 border-box, 12-23 max-height
                 * (M1910). len and link were already taken by height and min-height,
                 * and off's high bits were free — the same spare-bits trick the
                 * border/background tokens use. 12 bits holds the 4000px cap. */
                if (b->sc[sp].hasmaxw && b->ntok < TOK_MAX)
                    b->toks[b->ntok++] = (tok_t){ (uint32_t)(b->sc[sp].padb & 0xFF)
                                                    | (b->sc[sp].bordbox ? 0x100u : 0u)
                                                    | ((uint32_t)(b->sc[sp].boxmaxh & 0xFFF) << 12)
                                                    | (b->sc[sp].ovhidden ? (1u << 24) : 0u),
                                                  b->sc[sp].boxh, b->sc[sp].boxminh, STY_NORMAL, TK_MAXW_CLOSE };
                if (b->sc[sp].hasbg && b->ntok < TOK_MAX) b->toks[b->ntok++] = (tok_t){ 0, 0, NO_LINK, STY_NORMAL, TK_BG_CLOSE };   /* end the block-bg fill region */
                /* margin-bottom is OUTSIDE every box decoration, so it is applied
                 * after all the CLOSE markers, as pending spacing for the next
                 * break — where emit_break's max() rule collapses it against the
                 * following block's margin-top, which is what §8.3.1 asks for. */
                if (b->sc[sp].margb > b->pending_vmargin)
                    b->pending_vmargin = b->sc[sp].margb;
            }
        }
    } else if (!is_void_tag(tag)) {
        uint32_t c = 0; int ts = -1, ul = 0, tr = 0; uint32_t bg = 0; int al = 0, fs = 0, hide = 0, mv = 0, ml = 0; uint32_t bd = 0; int flex = 0, fgap = 0, fjust = 0, mw = 0; int lh_css = 0; int prews = 0; int bwpx = 0, bmauto = 0, bpadl = 0, bpadr = 0, bpadt = 0, bpadb = 0, bmargb = 0, bbordbox = 0, bhpx = 0, bminh = 0, bmaxh = 0, bovh = 0, bclear = 0;   /* width (M1896) / padding (M1897, M1900) / margin-bottom + box-sizing (M1903) / min+max-height (M1905, M1910) */
        int csw = 0, csma = 0, cspl = 0, cspr = 0, cspt = 0, cspb = 0, csh = 0;   /* box geometry from a stylesheet rule (M1929/M1930) */
        if (b->n_css > 0) css_match(b, tag, attrs, attrlen, &c, &ts, &ul, &tr, &bg, &al, &fs, &hide, &mv, &ml, &bd, &flex, &lh_css, &prews, &csw, &csma, &cspl, &cspr, &cspt, &cspb, &csh);   /* <style> rules first (lower priority) */
        bwpx = csw; bmauto = csma;   /* an inline style= below overrides these */
        bpadl = cspl; bpadr = cspr; bpadt = cspt; bpadb = cspb; bhpx = csh;
        if (mv) b->pending_vmargin = (uint16_t)mv;   /* CSS-rule vertical margin (an inline style= margin below overrides it) */
        const char *st; int stl;
        if (find_attr(attrs, attrlen, "style", &st, &stl)) {           /* inline style overrides per-property (cascade) */
            uint32_t ic = parse_style_color(st, stl);  if (ic) c = ic;
            int its = parse_style_textstyle(st, stl);  if (its >= 0) ts = its;
            { int iv = parse_style_underline(st, stl); if (iv) ul = iv; }   /* 1=underline, 2=none (suppress) */
            int itr = parse_style_transform(st, stl);  if (itr) tr = itr;   /* text-transform (inline only) */
            uint32_t ibg = parse_style_bg(st, stl);    if (ibg) bg = ibg;   /* background-color */
            uint32_t ibd = parse_style_border(st, stl); if (ibd) bd = ibd;   /* inline border overrides a <style> rule */
            if (parse_style_flex(st, stl)) flex = 1;                          /* display:flex */
            fgap = parse_style_gap(st, stl);                                  /* flex gap (px) */
            fjust = parse_style_justify(st, stl);                             /* justify-content: 1 center, 2 end */
            mw = parse_style_maxwidth(st, stl);                               /* max-width (px) -> centred column */
            /* GUARDED, like every other property in this block (M1932). These used to
             * assign unconditionally, so `<style>.hero{width:600px;margin:0 auto}</style>`
             * plus any unrelated inline declaration -- `style="color:#333"` -- reset the
             * width and the centring to zero. Mixing a stylesheet with a small inline
             * tweak is about the most common thing a real page does. */
            { int iw = parse_style_width_px(st, stl);      if (iw) bwpx = iw; }
            { int ima = parse_style_auto_margins(st, stl); if (ima) bmauto = ima; }
            { int ipl = 0, ipr = 0; parse_style_padding_lr(st, stl, &ipl, &ipr);
              if (ipl) bpadl = ipl; if (ipr) bpadr = ipr; }
            { int ipt = 0, ipb = 0; parse_style_padding_tb(st, stl, &ipt, &ipb);
              if (ipt) bpadt = ipt; if (ipb) bpadb = ipb; }
            bmargb   = parse_style_margin_bottom(st, stl);                    /* trailing margin, outside the bg (M1903) */
            bbordbox = parse_style_border_box(st, stl);                       /* box-sizing:border-box (M1903) */
            { int ih = parse_style_height_px(st, stl); if (ih) bhpx = ih; }    /* height (px) on a block (M1904) */
            bminh    = parse_style_minheight_px(st, stl);                      /* min-height (px) (M1905) */
            bmaxh    = parse_style_maxheight_px(st, stl);                       /* max-height (px) — caps the box, content spills (M1910) */
            bovh     = parse_style_overflow_hidden(st, stl);                   /* overflow:hidden/clip — clip content to the box (M1917) */
            bclear   = parse_style_clear(st, stl);                             /* clear: left/right/both (M1928) */

            int ial = parse_style_align(st, stl);      if (ial) al = ial;   /* text-align */
            int ifs = parse_style_fontsize(st, stl);   if (ifs) fs = ifs;   /* font-size (enlarge) */
            if (parse_style_display(st, stl)) hide = 1;                      /* display:none */
            int imv = parse_style_vspace(st, stl); if (imv) b->pending_vmargin = (uint16_t)imv;  /* CSS vertical margin+padding -> block spacing */
            int iml = parse_style_hspace(st, stl); if (iml) ml = iml;                            /* CSS left margin/padding -> indent */
            int ilh = parse_style_lineheight(st, stl); if (ilh) lh_css = ilh;                    /* line-height (inline overrides rule) */
            { int iws = parse_style_whitespace(st, stl); if (iws) prews = iws; }                 /* white-space: inline overrides a <style> rule (M1818/M1819) */
        }
        if (has_attr(attrs, attrlen, "hidden")) hide = 1;   /* the HTML5 `hidden` attribute */
        if (tageq(tag, "big")) { if (!fs) fs = 2; }         /* <big> -> 2x */
        if (tageq(tag, "font")) {                           /* <font size=N>: 5+ -> 2x, 6+/7 -> 3x */
            const char *sv; int svl;
            if (find_attr(attrs, attrlen, "size", &sv, &svl) && svl > 0) {
                int neg = (sv[0]=='+'||sv[0]=='-'), d = (svl>neg) ? sv[neg]-'0' : 0;
                if (sv[0] != '-' && d >= 6) fs = 3; else if (sv[0] != '-' && d >= 4) fs = 2;
            }
        }
        if (tageq(tag, "center")) al = 1;                   /* the legacy <center> tag */
        { const char *av; int avl;                          /* and the legacy align= attribute (div, p, headings, td) */
          if (find_attr(attrs, attrlen, "align", &av, &avl)) {
              if (attr_eq(av, avl, "center")) al = 1; else if (attr_eq(av, avl, "right")) al = 2; } }
        if (tageq(tag, "u") || tageq(tag, "ins")) ul = 1;   /* the <u>/<ins> tags also underline */
        int apply_ts = (ts >= 0 && *style == STY_NORMAL);   /* like <b>/<i>: only over normal-flow text */
        /* Box geometry counts too (M1932). This guard decides whether the element
         * gets a scope frame at all, and box_owner -- which emits TK_MAXW_OPEN -- is
         * computed INSIDE it. Omitting the box properties meant a rule carrying only
         * geometry (`.card{padding:20px}`) pushed no frame and was silently dropped:
         * the exact case M1930's own commit message advertised. The M1929/M1930
         * fixture hid it because every rule in it also set a background, which is
         * what actually pushed the frame. */
        if (c || apply_ts || ul || tr || bg || al || fs || hide || ml || bd || flex || mw || lh_css || prews
            || bwpx || bmauto || bpadl || bpadr || bpadt || bpadb || bhpx || bminh || bmaxh
            || bbordbox || bclear || bovh) {  /* styled/hidden/indented/bordered/flex/box-geometry element -> push a frame */
            if (b->sc_sp < SC_MAX) {
                int sp = b->sc_sp;
                b->sc[sp].hidden = hide; if (hide) b->n_hidden++;   /* enter a display:none subtree */
                b->sc[sp].savecolor = b->curcolor; if (c) b->curcolor = c;
                b->sc[sp].savebg = b->curbg; if (bg) b->curbg = is_block_tag(tag) ? (bg | 0x02000000u) : bg;   /* mark block bg = full-width */
                b->sc[sp].saveul = b->curul; if (ul) b->curul = ul;   /* 1=underline, 2=text-decoration:none */
                b->sc[sp].savetransform = b->curtransform; if (tr) b->curtransform = tr;
                b->sc[sp].savealign = b->curalign; if (al) b->curalign = al;
                b->sc[sp].savescale = b->curscale; if (fs) b->curscale = fs;
                b->sc[sp].savelh = b->curlh_css; if (lh_css) b->curlh_css = lh_css;   /* CSS line-height */
                b->sc[sp].saveindent = b->curindent; if (ml) b->curindent += ml;   /* CSS left indent (margin/padding-left) */
                b->sc[sp].saveprews = b->curprews;                                 /* white-space: pre-like -> preserve, normal/nowrap -> collapse (M1818) */
                if (prews == 1) b->curprews = 1; else if (prews == 2) b->curprews = 0;
                b->sc[sp].savestyle = *style; b->sc[sp].setstyle = -1;
                if (apply_ts) { *style = ts; b->sc[sp].setstyle = ts; }
                int i = 0; while (tag[i] && i < 15) { b->sc[sp].tag[i] = tag[i]; i++; } b->sc[sp].tag[i] = 0;
                b->sc[sp].cls[0] = 0;                            /* record the element's class for descendant-selector matching (M1434) */
                { const char *cv; int cvl; if (find_attr(attrs, attrlen, "class", &cv, &cvl)) { int w = 0; for (int z = 0; z < cvl && w < 31; z++) b->sc[sp].cls[w++] = cv[z]; b->sc[sp].cls[w] = 0; } }
                b->sc[sp].depth = 1;
                /* Does this element get a block box (a solved column)? Computed once
                 * so the border, the box itself and the background all agree. */
                int box_owner = (mw > 0 || bwpx > 0 || bmauto || bpadl > 0 || bpadr > 0
                                 || bpadt > 0 || bpadb > 0 || bbordbox || bhpx > 0
                                 || bminh > 0 || bmaxh > 0 || bclear > 0);
                b->sc[sp].hasborder = 0;
                if (bd && is_block_tag(tag) && b->ntok < TOK_MAX && b->n_hidden == 0) {   /* bracket the block's tokens with a border marker, drawn as one rect at render */
                    /* Bit 24 of `off` (above the 24-bit colour) marks that this element
                     * also owns a block box, so the renderer strokes the BORDER box
                     * around the padding box instead of the content box. Without it a
                     * bordered+padded block drew its stroke INSIDE its own background
                     * (M1901). Same spare-high-byte trick as the background token. */
                    b->toks[b->ntok++] = (tok_t){ (uint32_t)(bd & 0xFFFFFFu) | (box_owner ? (1u << 24) : 0u),
                                                  (uint16_t)((bd >> 24) & 0xF), (uint16_t)b->curindent,
                                                  (uint8_t)((bd >> 28) & 0xF), TK_BORDER_OPEN };   /* off=color(+bit24), len=sides, link=left-indent, style=width */
                    b->sc[sp].hasborder = 1;
                    if (((bd >> 24) & 0xF) == 15) b->curindent += BORDER_PAD;   /* full box: inset its text (left); the marker already captured the box's left edge */
                }
                b->sc[sp].hasflex = 0;
                if (flex && is_block_tag(tag) && b->ntok < TOK_MAX && b->n_hidden == 0) {   /* flex container: lay its children in a row */
                    b->toks[b->ntok++] = (tok_t){ (uint32_t)fgap, 0, NO_LINK, (uint8_t)fjust, TK_FLEX_OPEN };   /* off = gap px (0 = default); style = justify (1 center, 2 end) */
                    b->sc[sp].hasflex = 1;
                }
                b->sc[sp].hasmaxw = 0; b->sc[sp].padb = 0;
                b->sc[sp].margb = (uint8_t)(bmargb > 255 ? 255 : bmargb);   /* M1903 */
                b->sc[sp].boxh    = (uint16_t)bhpx;                           /* M1904 */
                b->sc[sp].boxminh = (uint16_t)bminh;                          /* M1905 */
                b->sc[sp].boxmaxh = (uint16_t)bmaxh;                          /* M1910 */
                b->sc[sp].ovhidden = (uint8_t)(bovh ? 1 : 0);                 /* M1917 */
                b->sc[sp].bordbox = (uint8_t)(bbordbox ? 1 : 0);
                /* A block box that constrains its content column: max-width, an
                 * explicit width, or auto horizontal margins. The renderer solves
                 * the actual geometry per CSS 2.1 §10.3.3 via box_solve_column
                 * (M1896); here we only carry the SPECIFIED values, because the
                 * containing-block width is a render-time quantity. */
                if (box_owner && is_block_tag(tag) && b->ntok < TOK_MAX && b->n_hidden == 0) {
                    uint16_t pk = (uint16_t)((bpadl & 0xFF) | ((bpadr & 0xFF) << 8));
                    uint32_t ow = ((uint32_t)mw & 0xFFFFu)
                                | ((uint32_t)(bpadt & 0xFF) << 16)
                                | ((uint32_t)(bpadb & 0xFF) << 24);
                    b->toks[b->ntok++] = (tok_t){ ow, (uint16_t)bwpx, pk,
                                                  (uint8_t)(bmauto | (bbordbox ? 4 : 0)
                                                            | ((bclear & 3) << 3)), TK_MAXW_OPEN };
                    b->sc[sp].hasmaxw = 1;
                    b->sc[sp].padb    = (uint8_t)(bpadb & 0xFF);
                }
                b->sc[sp].hasbg = 0;
                if (bg && is_block_tag(tag) && b->ntok < TOK_MAX && b->n_hidden == 0) {   /* block background: bracket the block so render fills ONE contiguous rect behind it */
                    /* Bit 24 of `off` (above the 24-bit colour) records that THIS
                     * element also emitted a block box, so the renderer knows to
                     * paint its padding box rather than the current column. Without
                     * the flag a background on a plain child inside a padded parent
                     * would wrongly inherit the PARENT's padding box and paint too
                     * wide. (M1897) */
                    uint32_t bgoff = (uint32_t)(bg & 0xFFFFFFu)
                                   | (b->sc[sp].hasmaxw ? (1u << 24) : 0u);
                    b->toks[b->ntok++] = (tok_t){ bgoff, 0, NO_LINK, 0, TK_BG_OPEN };
                    b->sc[sp].hasbg = 1;
                }
                b->sc_sp++;
            }   /* stack full: skip (no scope) — graceful, never overflows */
        } else if (b->sc_sp > 0 && tageq(tag, b->sc[b->sc_sp-1].tag)) {
            b->sc[b->sc_sp-1].depth++;                       /* unstyled same-tag nesting of the top frame */
        }
    }
    if (!closing && b->oc_depth == 0 && !is_void_tag(tag)) {
        const char *oc; int ocl;
        int lk = NO_LINK;
        if (find_attr(attrs, attrlen, "onclick", &oc, &ocl)) {
            lk = add_onclick(b, oc, ocl);              /* inline handler: scope the element to a javascript: link */
        } else if (find_attr(attrs, attrlen, "data-jsh", &oc, &ocl)) {   /* el.onclick=fn marker: clickable -> event:ID link (id-keyed registry) */
            const char *idv; int idl;
            if (find_attr(attrs, attrlen, "id", &idv, &idl) && idl > 0) lk = add_event_link(b, idv, idl);
        } else if (tageq(tag, "button")) {             /* a <button> with no handler submits the form (HTML default), unless type=button/reset */
            const char *tp; int tpl;
            int suppress = find_attr(attrs, attrlen, "type", &tp, &tpl) && (attr_eq(tp, tpl, "button") || attr_eq(tp, tpl, "reset"));
            if (!suppress) lk = add_submit_link(b, b->form_action, (int)(attrs - b->raw));
        }
        if (lk != NO_LINK) {                           /* open a click scope (depth-counted) over the element's content */
            b->oc_link = *curlink; b->oc_style = *style;
            *curlink = lk; if (*style == STY_NORMAL) *style = STY_LINK;
            int i = 0; while (tag[i] && i < 15) { b->oc_tag[i] = tag[i]; i++; } b->oc_tag[i] = 0;
            b->oc_depth = 1;
        }
    }
    if (!closing && b->anc_n < 32) {                     /* record id (or <a name>) -> token index for #fragment scroll-to */
        const char *idv; int idl;
        if ((find_attr(attrs, attrlen, "id", &idv, &idl) ||                     /* modern: any element's id */
             (tageq(tag, "a") && find_attr(attrs, attrlen, "name", &idv, &idl)))  /* legacy: <a name="..."> */
            && idl > 0 && idl < 32) {
            int k = 0; for (; k < idl; k++) b->anc_id[b->anc_n][k] = idv[k]; b->anc_id[b->anc_n][k] = 0;
            b->anc_tok[b->anc_n] = (uint16_t)(b->ntok < TOK_MAX ? b->ntok : TOK_MAX - 1);
            b->anc_n++;
        }
    }
    if (tageq(tag, "br")) { emit_break(b, TK_BREAK); return; }
    if (tag[0] == 'h' && tag[1] >= '1' && tag[1] <= '6' && tag[2] == 0) {
        if (!closing) { emit_break(b, TK_PARA); *style = (tag[1] <= '2') ? STY_H1 : STY_H2; }
        else          { *style = STY_NORMAL; emit_break(b, TK_PARA); }
        return;
    }
    if (tageq(tag, "a")) {
        if (!closing) {
            const char *v; int vl;
            *curlink = find_href(attrs, attrlen, &v, &vl) ? add_href(b, v, vl) : NO_LINK;
            if (*style == STY_NORMAL) *style = STY_LINK;
            (*linkdepth)++;
        } else {
            if (*linkdepth > 0) (*linkdepth)--;
            if (*linkdepth == 0) { if (*style == STY_LINK) *style = STY_NORMAL; *curlink = NO_LINK; }
        }
        return;
    }
    if (tageq(tag, "b") || tageq(tag, "strong")) {
        if (!closing) { if (*style == STY_NORMAL) *style = STY_BOLD; }
        else if (*style == STY_BOLD) *style = STY_NORMAL;
        return;
    }
    if (tageq(tag, "i") || tageq(tag, "em") || tageq(tag, "cite") ||      /* italic-by-convention */
        tageq(tag, "var") || tageq(tag, "dfn") || tageq(tag, "address")) {
        if (!closing) { if (*style == STY_NORMAL) *style = STY_EM; }
        else if (*style == STY_EM) *style = STY_NORMAL;
        return;
    }
    if (tageq(tag, "code") || tageq(tag, "tt") || tageq(tag, "kbd") || tageq(tag, "samp")) {
        if (!closing) { if (*style == STY_NORMAL) *style = STY_CODE; }
        else if (*style == STY_CODE) *style = STY_NORMAL;
        return;
    }
    if (tageq(tag, "s") || tageq(tag, "del") || tageq(tag, "strike")) {   /* strikethrough */
        if (!closing) { if (*style == STY_NORMAL) *style = STY_STRIKE; }
        else if (*style == STY_STRIKE) *style = STY_NORMAL;
        return;
    }
    if (tageq(tag, "mark")) {                                             /* highlighted text */
        if (!closing) { if (*style == STY_NORMAL) *style = STY_MARK; }
        else if (*style == STY_MARK) *style = STY_NORMAL;
        return;
    }
    if (tageq(tag, "sub") || tageq(tag, "sup")) {                         /* sub/superscript (drawn at a y-offset) */
        int st = tageq(tag, "sub") ? STY_SUB : STY_SUP;
        if (!closing) { if (*style == STY_NORMAL) *style = st; }
        else if (*style == st) *style = STY_NORMAL;
        return;
    }
    if (tageq(tag, "font")) {                            /* <font color="..."> text colour */
        if (!closing) {
            const char *v; int vl;
            if (find_attr(attrs, attrlen, "color", &v, &vl)) { uint32_t c = parse_color(v, vl); if (c) b->curcolor = c; }
        } else b->curcolor = 0;
        return;
    }
    if (tageq(tag, "hr")) { if (b->ntok < TOK_MAX && b->n_hidden == 0) b->toks[b->ntok++] = (tok_t){0,0,NO_LINK,STY_NORMAL,TK_HR}; return; }
    if (tageq(tag, "canvas")) {                          /* M1796: <canvas> — a writable image slot the JS 2D context draws into, then blitted like an image */
        if (!closing && b->n_hidden == 0 && b->ntok + 2 < TOK_MAX) {
            int cw = attr_int(attrs, attrlen, "width"), ch = attr_int(attrs, attrlen, "height");
            if (cw <= 0) cw = 300; if (ch <= 0) ch = 150;          /* HTML canvas defaults */
            if (cw > 800) cw = 800; if (ch > 600) ch = 600;        /* cap the backing buffer */
            int slot = canvas_new_slot(b, cw, ch);
            if (slot >= 0) {
                const char *idv; int idl;                          /* register id -> slot so getContext/fillRect can find it */
                if (b->n_canv < IMG_SLOTS && find_attr(attrs, attrlen, "id", &idv, &idl) && idl > 0) {
                    int m = idl > 31 ? 31 : idl; for (int i = 0; i < m; i++) b->canv_id[b->n_canv][i] = idv[i];
                    b->canv_id[b->n_canv][m] = 0; b->canv_slot[b->n_canv] = slot; b->n_canv++;
                }
                emit_break(b, TK_BREAK);
                b->tokalign[b->ntok] = (uint8_t)b->curalign;
                b->toks[b->ntok++] = (tok_t){ (uint16_t)cw, (uint16_t)ch, (uint16_t)slot, STY_NORMAL, TK_IMG };
                emit_break(b, TK_BREAK);
            }
        }
        return;
    }
    if (tageq(tag, "input")) {                           /* a form field: shows its value; focusable for typing */
        if (!closing) {
            const char *v; int vl, idl;
            const char *idp;
            char idbuf[32]; idbuf[0] = 0;
            if (find_attr(attrs, attrlen, "id", &idp, &idl) && idl < 32) { int k=0; for(;k<idl;k++) idbuf[k]=idp[k]; idbuf[k]=0; }
            /* no id? key the store/focus by name= so name-only inputs (e.g. Google's search
             * box <input name="q"> — no id, no type) are still focusable, typeable & submittable. */
            if (!idbuf[0] && find_attr(attrs, attrlen, "name", &idp, &idl) && idl > 0 && idl < 32) { int k=0; for(;k<idl;k++) idbuf[k]=idp[k]; idbuf[k]=0; }
            const char *tp; int tpl; int has_type = find_attr(attrs, attrlen, "type", &tp, &tpl);
            int is_submit = has_type && (attr_eq(tp, tpl, "submit") || attr_eq(tp, tpl, "image"));
            int is_hidden = has_type && attr_eq(tp, tpl, "hidden");
            int is_pw = has_type && attr_eq(tp, tpl, "password");
            int is_radio = has_type && attr_eq(tp, tpl, "radio");
            int is_check = is_radio || (has_type && attr_eq(tp, tpl, "checkbox"));
            if (is_check) {                              /* a checkbox/radio -> a [x]/(o) toggle link */
                if (idbuf[0] && !in_get(b, idbuf) && has_attr(attrs, attrlen, "checked")) in_set(b, idbuf, "on");  /* default-checked */
                const char *cur = idbuf[0] ? in_get(b, idbuf) : 0;
                int checked = cur && streqs(cur, "on");
                if (idbuf[0] && find_attr(attrs, attrlen, "name", &v, &vl) && vl > 0) {   /* checked -> submit name=on; unchecked -> omit */
                    if (checked) { char nb[32]; int n=vl; if(n>31)n=31; for(int i=0;i<n;i++) nb[i]=v[i]; nb[n]=0; in_name_set(b, idbuf, nb); }
                    else in_name_set(b, idbuf, "");
                }
                char s[4]; s[0]= is_radio?'(':'['; s[1]= checked?(is_radio?'o':'x'):' '; s[2]= is_radio?')':']'; s[3]=0;
                if (idbuf[0]) { int lk = add_check_link(b, idbuf); if (lk != NO_LINK) emit_literal_link(b, s, lk); else emit_literal(b, s, STY_EM); }
                else emit_literal(b, s, STY_EM);
                return;
            }
            if (is_submit) {                             /* a submit button -> a link that submits the form */
                char s[64]; int p = 0; s[p++] = '[';
                if (find_attr(attrs, attrlen, "value", &v, &vl) && vl > 0) { for (int i=0;i<vl&&p<60;i++) s[p++]=v[i]; }
                else { const char *d = "Submit"; for (int i=0; d[i] && p<60; i++) s[p++]=d[i]; }
                s[p++] = ']'; s[p] = 0;
                int lk = add_submit_link(b, b->form_action, (int)(attrs - b->raw));
                if (lk != NO_LINK) emit_literal_link(b, s, lk); else emit_literal(b, s, STY_EM);
                return;
            }
            /* seed a store slot from the value= attr (only if absent) so the field's
             * default is both shown and submittable; idempotent across re-renders. */
            if (idbuf[0] && !in_get(b, idbuf) && find_attr(attrs, attrlen, "value", &v, &vl) && vl > 0) {
                char vb[IN_VLEN]; int n = vl; if (n > IN_VLEN-1) n = IN_VLEN-1; for (int i=0;i<n;i++) vb[i]=v[i]; vb[n]=0;
                in_set(b, idbuf, vb);
            }
            if (idbuf[0]) {                              /* attach the name= for GET submit (if the slot exists) */
                const char *nm; int nml;
                if (find_attr(attrs, attrlen, "name", &nm, &nml) && nml > 0) {
                    char nb[32]; int n = nml; if (n > 31) n = 31; for (int i=0;i<n;i++) nb[i]=nm[i]; nb[n]=0;
                    in_name_set(b, idbuf, nb);
                }
            }
            if (is_hidden) return;                       /* hidden fields are submittable but not drawn */
            const char *stored = idbuf[0] ? in_get(b, idbuf) : 0;   /* typed / scripted / seeded .value */
            int focused = idbuf[0] && streqs(b->focus_id, idbuf);
            char s[100]; int p = 0; s[p++] = '['; int cursored = 0;
            if (stored)                                                                 { int sl=(int)strlen(stored), fc=b->field_cur; if(fc<0)fc=0; if(fc>sl)fc=sl;
                                                                                          for (int i=0; i<sl && p<92; i++) { if(focused&&i==fc){s[p++]='|';cursored=1;} if(p<92) s[p++]= is_pw ? '*' : stored[i]; }
                                                                                          if (focused && !cursored && p<92) { s[p++]='|'; cursored=1; } }
            else if (find_attr(attrs, attrlen, "value", &v, &vl) && vl > 0)             { for (int i=0; i<vl && p<92; i++) s[p++]= is_pw ? '*' : v[i]; }
            else if (find_attr(attrs, attrlen, "placeholder", &v, &vl) && vl > 0)       { for (int i=0; i<vl && p<92; i++) s[p++]=v[i]; }
            else                                                                        { s[p++]='_'; s[p++]='_'; s[p++]='_'; s[p++]='_'; }
            if (focused && !cursored) s[p++] = '|';      /* a cursor on the focused field */
            s[p++] = ']'; s[p] = 0;
            if (idbuf[0]) { int lk = add_input_link(b, idbuf);   /* a field with an id is focusable (Enter to type) */
                if (lk != NO_LINK) emit_literal_link(b, s, lk); else emit_literal(b, s, STY_EM); }
            else emit_literal(b, s, STY_EM);
        }
        return;
    }
    if (tageq(tag, "img")) {                             /* [alt] — a clickable link to the image */
        if (!closing) {
            { const char *st; int stl; int ih = has_attr(attrs, attrlen, "hidden");   /* a hidden image (its own display:none/visibility:hidden/hidden) shows nothing */
              if (find_attr(attrs, attrlen, "style", &st, &stl) && parse_style_display(st, stl)) ih = 1;
              if (ih) return; }
            /* float side for this image, read once and carried on the token's
             * `style` field (unused for TK_IMG). A floated image must NOT get the
             * emit_break() bracket the others do — those are what force an image
             * onto its own line, which is precisely what floating undoes. (M1928) */
            int imgflt = 0;
            { const char *st; int stl;
              if (find_attr(attrs, attrlen, "style", &st, &stl)) imgflt = parse_style_float(st, stl); }
            const char *v; int vl;
            char label[40]; int p = 0; label[p++] = '[';
            if (find_attr(attrs, attrlen, "alt", &v, &vl) && vl > 0)
                p += copy_decoded(label + p, 37 - p, v, vl);
            else { const char *im = "img"; while (*im && p < 37) label[p++] = *im++; }
            label[p++] = ']'; label[p] = 0;
            const char *src; int srcl;
            if (img_src_attr(attrs, attrlen, &src, &srcl) && srcl > 0) {
                /* a LOCAL image (file:NAME) decodes inline; everything else
                 * (http: etc.) stays a clickable link you can follow to view */
                int shown = 0;
                if (srcl > 5 && src[0]=='f'&&src[1]=='i'&&src[2]=='l'&&src[3]=='e'&&src[4]==':') {
                    char path[96]; int pn = 0;
                    for (int i = 5; i < srcl && pn < 95; i++) path[pn++] = src[i];
                    path[pn] = 0;
                    int slot = b->n_hidden ? -1 : decode_local_to_slot(b, path);   /* display:none -> don't show */
                    if (slot >= 0 && b->ntok + 2 < TOK_MAX) {
                        /* honour explicit width/height (off=w, len=h; 0 = natural) */
                        int aw = attr_int(attrs, attrlen, "width");
                        int ah = attr_int(attrs, attrlen, "height");
                        if (!imgflt) emit_break(b, TK_BREAK);
                        b->tokalign[b->ntok] = (uint8_t)b->curalign;   /* honour enclosing text-align when centred/right */
                        b->toks[b->ntok++] = (tok_t){ (uint16_t)aw, (uint16_t)ah, (uint16_t)slot, (uint8_t)imgflt, TK_IMG };
                        if (!imgflt) emit_break(b, TK_BREAK);
                        shown = 1;
                    }
                }
                if (!shown && srcl > 7 && src[0]=='d'&&src[1]=='a'&&src[2]=='t'&&src[3]=='a'&&src[4]==':') {
                    /* data:[<mediatype>][;base64],<bytes> — decode the embedded
                     * image inline (only the ;base64 form, universal for images). */
                    int comma = -1;
                    for (int i = 5; i < srcl; i++) if (src[i] == ',') { comma = i; break; }
                    int isb64 = 0;
                    for (int i = 5; comma >= 0 && i + 7 <= comma; i++)
                        if (src[i]==';'&&src[i+1]=='b'&&src[i+2]=='a'&&src[i+3]=='s'&&
                            src[i+4]=='e'&&src[i+5]=='6'&&src[i+6]=='4') { isb64 = 1; break; }
                    int enclen = comma >= 0 ? srcl - (comma + 1) : 0;
                    if (isb64 && !b->n_hidden && enclen > 0 && enclen <= DATA_URI_B64_MAX) {
                        int cap = enclen / 4 * 3 + 4;
                        uint8_t *bin = kmalloc((unsigned long)cap);
                        if (bin) {
                            int blen = b64_decode(src + comma + 1, enclen, bin, cap);
                            int slot = blen > 0 ? decode_bytes_to_slot(b, bin, blen) : -1;
                            kfree(bin);                       /* decode_bytes_to_slot copied/decoded already */
                            if (slot >= 0 && b->ntok + 2 < TOK_MAX) {
                                int aw = attr_int(attrs, attrlen, "width");
                                int ah = attr_int(attrs, attrlen, "height");
                                if (!imgflt) emit_break(b, TK_BREAK);
                                b->tokalign[b->ntok] = (uint8_t)b->curalign;   /* honour enclosing text-align when centred/right */
                                b->toks[b->ntok++] = (tok_t){ (uint16_t)aw, (uint16_t)ah, (uint16_t)slot, (uint8_t)imgflt, TK_IMG };
                                if (!imgflt) emit_break(b, TK_BREAK);
                                shown = 1;
                            }
                        }
                    }
                }
                if (!shown && !b->loading) {
                    /* A remote src the worker prefetched (matched by raw src string)
                     * decodes inline, like a local one; the compressed bytes were
                     * stashed in rimg_data[] pre-parse. Gated on !loading: the worker
                     * mutates rimg_* (drop+repopulate) only while loading==1, so reading
                     * them here on the WM thread when !loading is a DIRECT guard against
                     * a free/use race (not relying on the indirect "render triggers are
                     * disabled during load" invariant). */
                    for (int k = 0; k < b->n_rimg && !shown; k++) {
                        if (!b->rimg_data[k]) continue;
                        int m = 1;
                        for (int i = 0; i < srcl; i++) { if (b->rimg_src[k][i] != src[i]) { m = 0; break; } }
                        if (!m || b->rimg_src[k][srcl] != 0) continue;   /* exact length+bytes */
                        int slot = b->n_hidden ? -1 : decode_bytes_to_slot(b, b->rimg_data[k], b->rimg_len[k]);
                        if (slot >= 0 && b->ntok + 2 < TOK_MAX) {
                            int aw = attr_int(attrs, attrlen, "width");
                            int ah = attr_int(attrs, attrlen, "height");
                            if (!imgflt) emit_break(b, TK_BREAK);
                            b->tokalign[b->ntok] = (uint8_t)b->curalign;   /* honour enclosing text-align when centred/right */
                            b->toks[b->ntok++] = (tok_t){ (uint16_t)aw, (uint16_t)ah, (uint16_t)slot, (uint8_t)imgflt, TK_IMG };
                            if (!imgflt) emit_break(b, TK_BREAK);
                            shown = 1;
                        }
                    }
                }
                if (!shown) {
                    int link = add_href(b, src, srcl);       /* follow it to view the image */
                    int start = b->textlen;
                    for (int i = 0; label[i] && b->textlen < TEXT_MAX - 1; i++) b->text[b->textlen++] = label[i];
                    emit_word(b, start, STY_LINK, link);
                }
            } else emit_literal(b, label, STY_EM);
        }
        return;
    }
    if (tageq(tag, "ul") || tageq(tag, "ol")) {          /* track list nesting + kind */
        if (!closing) {
            if (b->listdepth < 8) {
                b->listtype[b->listdepth] = tag[0];
                char fmt = '1'; const char *tv; int tvl;                       /* <ol type=…> marker style */
                if (tag[0] == 'o' && find_attr(attrs, attrlen, "type", &tv, &tvl) && tvl >= 1
                    && (tv[0]=='a'||tv[0]=='A'||tv[0]=='i'||tv[0]=='I'||tv[0]=='1')) fmt = tv[0];
                b->listfmt[b->listdepth] = fmt;
                int st = (tag[0] == 'o') ? attr_int(attrs, attrlen, "start") : 0;   /* <ol start=N> */
                b->listnum[b->listdepth] = st > 0 ? st - 1 : 0;
                /* list-style-type for this list's items: a <style> rule first, then an
                 * inline style= overrides it (the usual cascade). 0 = use the default. */
                int lm = (b->n_css > 0) ? css_match_list(b, tag, attrs, attrlen) : 0;
                const char *lsst; int lsstl;
                if (find_attr(attrs, attrlen, "style", &lsst, &lsstl)) { int il = parse_style_listtype(lsst, lsstl); if (il) lm = il; }
                b->listmark[b->listdepth] = (char)lm;
                b->listdepth++;
            }
        } else if (b->listdepth > 0) b->listdepth--;
        emit_break(b, TK_BREAK);
        return;
    }
    if (tageq(tag, "li")) {
        if (!closing) {
            emit_break(b, TK_BREAK);
            /* marker[24]: depth<=8 → 16 indent spaces, digits capped at p<22,
             * then '.' at p<23, then NUL at p<=23 — stays within bounds. */
            char marker[24]; int p = 0;
            int depth = b->listdepth > 0 ? b->listdepth : 1;   /* indent: 2 spaces/level */
            for (int i = 0; i < depth && p < 18; i++) { marker[p++] = ' '; marker[p++] = ' '; }
            int lvl = b->listdepth - 1;                         /* current list level (-1 if a stray <li>) */
            int mark = (lvl >= 0) ? b->listmark[lvl] : 0;       /* list-style-type: 0 default, 'N' none, '-'/'*'/'+' bullet, '1' decimal */
            int numbered = (lvl >= 0 && b->listtype[lvl] == 'o' && mark != 'N'
                            && mark != '-' && mark != '*' && mark != '+')   /* an <ol>, unless an explicit bullet/none overrides */
                           || mark == '1';                                  /* or a list told to use decimal */
            /* `display` is ONE property: setting it to flex replaces `list-item`, so
             * a flex <li> generates no marker at all. Real pages rely on this —
             * danluu.com styles `li{display:flex}` to put a date and a title side by
             * side, and a bullet in front of every row is simply wrong. Checked
             * against both the inline style= and the stylesheet. (M1931) */
            int liflex = 0;
            { const char *lst; int lstl;
              if (find_attr(attrs, attrlen, "style", &lst, &lstl) && parse_style_flex(lst, lstl))
                  liflex = 1;
              if (!liflex && b->n_css > 0) {
                  uint32_t c2 = 0, bg2 = 0, bd2 = 0;
                  int ts2 = -1, ul2 = 0, tr2 = 0, al2 = 0, fs2 = 0, hd2 = 0, mv2 = 0, ml2 = 0,
                      fx2 = 0, lh2 = 0, pw2 = 0, w2 = 0, ma2 = 0, pl2 = 0, pr2 = 0, pt2 = 0,
                      pb2 = 0, h2 = 0;
                  css_match(b, tag, attrs, attrlen, &c2, &ts2, &ul2, &tr2, &bg2, &al2, &fs2,
                            &hd2, &mv2, &ml2, &bd2, &fx2, &lh2, &pw2, &w2, &ma2,
                            &pl2, &pr2, &pt2, &pb2, &h2);
                  liflex = fx2;
              } }
            if (mark == 'N' || liflex) {
                /* list-style:none — suppress the marker entirely (keep the indent so nested
                 * lists still step in). The bullet is the only thing dropped. */
            } else if (numbered) {
                int n = ++b->listnum[lvl];                      /* numbered item, formatted per <ol type> */
                char num[16]; fmt_li_num(n, b->listfmt[lvl], num, sizeof(num));
                for (int k = 0; num[k] && p < 22; k++) marker[p++] = num[k];
                if (p < 23) marker[p++] = '.';
            } else if (p < 23) {                                /* bulleted item */
                char bullet;
                if (mark == '-' || mark == '*' || mark == '+') bullet = (char)mark;   /* explicit list-style-type: disc/circle/square */
                else bullet = (depth <= 1) ? '-' : (depth == 2) ? '*' : '+';          /* default: vary by nesting depth (depth 1 keeps '-') */
                marker[p++] = bullet;
            }
            marker[p] = 0;
            emit_literal(b, marker, STY_NORMAL);
        }
        return;
    }
    if (tageq(tag, "dd")) { if (!closing) { emit_break(b, TK_BREAK); emit_literal(b, "  ", STY_NORMAL); } return; }
    if (tageq(tag, "tr")) { if (!closing) { emit_break(b, TK_BREAK); b->tdcount = 0; } return; }
    if (tageq(tag, "td") || tageq(tag, "th")) {          /* table cell: pipe-separated */
        if (!closing) {
            if (b->tdcount++ > 0) emit_literal(b, "|", STY_NORMAL);  /* divider between cells */
            if (tag[0] == 't' && tag[1] == 'h' && *style == STY_NORMAL) *style = STY_BOLD;  /* <th> bold */
        } else if (tag[0] == 't' && tag[1] == 'h' && *style == STY_BOLD) *style = STY_NORMAL;
        return;
    }
    if (tageq(tag, "form")) {                            /* capture the GET action; submit buttons snapshot it */
        if (!closing) {
            const char *v; int vl; b->form_action[0] = 0;
            if (find_attr(attrs, attrlen, "action", &v, &vl) && vl > 0) {
                int n = vl; if (n > URL_MAX - 1) n = URL_MAX - 1;
                for (int i = 0; i < n; i++) b->form_action[i] = v[i];
                b->form_action[n] = 0;
            }
        } else b->form_action[0] = 0;
        emit_break(b, TK_BREAK);
        return;
    }
    if (tageq(tag, "p") || tageq(tag, "dt")) { emit_break(b, TK_PARA); return; }
    if (tageq(tag, "table")) { emit_break(b, TK_PARA); b->tdcount = 0; return; }
    if (tageq(tag, "blockquote")) {                      /* indent the quoted block + a left accent bar */
        emit_break(b, TK_PARA);
        if (!closing) {
            if (b->curindent < 200) b->curindent += 24;
            /* reuse the border marker (left-only, sides=8): a 3px grey bar in the indent
             * gutter, left of the text — the universal blockquote convention. off=colour,
             * len=sides, link=x-anchor (cl+link), style=width; drawn by the TK_BORDER_CLOSE
             * handler, additive (no blockquote -> no token -> identical render). */
            if (b->ntok < TOK_MAX && b->n_hidden == 0)
                b->toks[b->ntok++] = (tok_t){ 0xC8CED8u, 8, (uint16_t)(b->curindent > 12 ? b->curindent - 12 : 0), 3, TK_BORDER_OPEN };
        } else {
            if (b->ntok < TOK_MAX && b->n_hidden == 0)
                b->toks[b->ntok++] = (tok_t){ 0, 0, NO_LINK, STY_NORMAL, TK_BORDER_CLOSE };
            b->curindent -= 24; if (b->curindent < 0) b->curindent = 0;
        }
        return;
    }
    if (tageq(tag, "div") || tageq(tag, "section") ||
        tageq(tag, "article") || tageq(tag, "header") || tageq(tag, "footer") ||
        tageq(tag, "nav") || tageq(tag, "pre") || tageq(tag, "dl") ||
        tageq(tag, "main"))
        emit_break(b, TK_BREAK);
}

/* Strip the HTML body into the token stream + href table. */
/* Append the text inside a <script>...</script> to b->scripts (so it can be run
 * after the page is parsed). Multiple scripts are separated by a newline+';'. */
static void capture_script(browser_t *b, const char *s, int len) {
    if (!b->scripts) return;
    if (b->scriptlen > 0 && b->scriptlen < SCRIPT_MAX - 2) { b->scripts[b->scriptlen++] = '\n'; b->scripts[b->scriptlen++] = ';'; }
    for (int k = 0; k < len && b->scriptlen < SCRIPT_MAX - 1; k++) b->scripts[b->scriptlen++] = s[k];
    b->scripts[b->scriptlen] = 0;
}

/* ---- <table> rendering: monospace column-aligned rows --------------------- *
 * A <table> is rendered self-contained: render_table consumes the whole
 * <table>..</table> region and emits cells padded (with spaces) to each column's
 * max width, so the fixed-width font lays them out as aligned columns. It does
 * its own bounded parsing of the region and never touches non-table content. */
#define TBL_COLS     16
#define TBL_CELL_MAX 64
/* Classify a tag at p: 1=<tr> 2=<td> 6=<th> 3=</tr> 4=</table> 5=</td>|</th> 0=other.
 * *after := just past '>'. All reads bounded by e. */
static int tbl_classify(const char *p, const char *e, const char **after) {
    const char *q = p + 1; int cl = 0;
    if (q < e && *q == '/') { cl = 1; q++; }
    char nm[8]; int nl = 0;
    while (q < e && nl < 7) { int ch = lc((unsigned char)*q); if (ch < 'a' || ch > 'z') break; nm[nl++] = (char)ch; q++; }
    const char *r = q; while (r < e && *r != '>') r++;
    *after = (r < e) ? r + 1 : e;
    if (nl == 2 && nm[0]=='t' && nm[1]=='r') return cl ? 3 : 1;
    if (nl == 2 && nm[0]=='t' && nm[1]=='d') return cl ? 5 : 2;
    if (nl == 2 && nm[0]=='t' && nm[1]=='h') return cl ? 5 : 6;
    if (nl == 5 && nm[0]=='t'&&nm[1]=='a'&&nm[2]=='b'&&nm[3]=='l'&&nm[4]=='e') return cl ? 4 : 0;
    return 0;
}
/* Extract a cell's visible text into out (capped): strip inline tags, decode entities,
 * fold non-ASCII, collapse runs of whitespace to one space. Returns the char length. */
static int cell_extract(const char *s, const char *e, char *out, int cap) {
    int n = 0, sp = 0;
    const char *p = s;
    while (p < e && n < cap - 1) {
        if (*p == '<') {
            /* a <style>/<script> inside a cell (e.g. a MediaWiki infobox's TemplateStyles
             * block) must be skipped WHOLE — its CSS/JS body is not cell text. */
            const char *q = p + 1; const char *rn = 0; int rl = 0;
            if (q + 6 <= e && lc(q[0])=='s'&&lc(q[1])=='c'&&lc(q[2])=='r'&&lc(q[3])=='i'&&lc(q[4])=='p'&&lc(q[5])=='t') { rn = "script"; rl = 6; }
            else if (q + 5 <= e && lc(q[0])=='s'&&lc(q[1])=='t'&&lc(q[2])=='y'&&lc(q[3])=='l'&&lc(q[4])=='e') { rn = "style"; rl = 5; }
            while (p < e && *p != '>') p++; if (p < e) p++;            /* past the open tag's '>' */
            if (rn) {                                                  /* skip the raw-text body + its close tag */
                while (p < e) {
                    if (*p == '<' && p + 1 < e && p[1] == '/') {
                        int ok = 1; for (int z = 0; z < rl; z++) if (p + 2 + z >= e || lc(p[2+z]) != rn[z]) { ok = 0; break; }
                        if (ok) { while (p < e && *p != '>') p++; if (p < e) p++; break; }
                    }
                    p++;
                }
            }
            continue;
        }
        char c;
        if (*p == '&') { char d; int adv = decode_entity(p, (int)(e - p), &d); if (adv) { c = d; p += adv; } else { c = *p; p++; } }
        else if ((unsigned char)*p >= 0x80) { unsigned cp; int adv = decode_utf8(p, (int)(e - p), &cp); c = uni_to_ascii(cp); p += (adv > 0 ? adv : 1); }
        else { c = *p; p++; }
        if (c==' '||c=='\t'||c=='\n'||c=='\r') { sp = 1; continue; }
        if (sp && n > 0 && n < cap - 1) out[n++] = ' ';
        sp = 0;
        if (n < cap - 1) out[n++] = c;
    }
    out[n] = 0;
    return n;
}
/* Render the table region [s, s+len). Returns chars consumed (to just past </table>). */
/* Does the <table> region s..e contain a form field (input/button/select/textarea)?
 * Such a table is a LAYOUT table (e.g. Google's search form) — render it through the
 * normal flow (so the fields actually show) instead of render_table's text extraction. */
static int table_has_field(const char *s, const char *e) {
    int depth = 1;                                        /* called just after the opening <table> */
    for (const char *p = s; p < e && depth > 0; p++) {
        if (*p != '<') continue;
        if (p+1 < e && p[1] == '/') { if (p+7 <= e && lc(p[2])=='t'&&lc(p[3])=='a'&&lc(p[4])=='b'&&lc(p[5])=='l'&&lc(p[6])=='e') depth--; continue; }
        if (p+6 <= e && lc(p[1])=='t'&&lc(p[2])=='a'&&lc(p[3])=='b'&&lc(p[4])=='l'&&lc(p[5])=='e') { depth++; continue; }
        if (p+6 <= e && lc(p[1])=='i'&&lc(p[2])=='n'&&lc(p[3])=='p'&&lc(p[4])=='u'&&lc(p[5])=='t') return 1;
        if (p+7 <= e && lc(p[1])=='b'&&lc(p[2])=='u'&&lc(p[3])=='t'&&lc(p[4])=='t'&&lc(p[5])=='o'&&lc(p[6])=='n') return 1;
        if (p+7 <= e && lc(p[1])=='s'&&lc(p[2])=='e'&&lc(p[3])=='l'&&lc(p[4])=='e'&&lc(p[5])=='c'&&lc(p[6])=='t') return 1;
        if (p+9 <= e && lc(p[1])=='t'&&lc(p[2])=='e'&&lc(p[3])=='x'&&lc(p[4])=='t'&&lc(p[5])=='a'&&lc(p[6])=='r'&&lc(p[7])=='e'&&lc(p[8])=='a') return 1;
    }
    return 0;
}
/* M1795: read colspan="N" from a <td>/<th> tag [tag..tagend) (default 1, clamped to
 * [1, TBL_COLS]). tag points at '<'; attributes start after the 3-char "<td"/"<th". */
static int cell_colspan(const char *tag, const char *tagend) {
    const char *attrs = tag + 3; int attrlen = (int)(tagend - attrs);
    if (attrlen <= 0) return 1;
    const char *v; int vl;
    if (!find_attr(attrs, attrlen, "colspan", &v, &vl)) return 1;
    int n = 0; for (int i = 0; i < vl && v[i] >= '0' && v[i] <= '9'; i++) n = n*10 + (v[i]-'0');
    if (n < 1) n = 1; if (n > TBL_COLS) n = TBL_COLS;
    return n;
}
static int render_table(browser_t *b, const char *s, int len) {
    if (len <= 0) return 0;
    const char *e = s + len, *tend = e;
    int col_w[TBL_COLS]; for (int i = 0; i < TBL_COLS; i++) col_w[i] = 0;
    char out[TBL_CELL_MAX];

    /* pass 1: measure each column's max cell width */
    { const char *p = s; int col = 0, guard = 0, depth = 1;   /* M1628: nested-<table> depth, same
                                                                 * tracking table_has_field already does
                                                                 * on this same region -- tbl_classify
                                                                 * returns the SAME code (0) for a nested
                                                                 * <table> open as for any other ignored
                                                                 * tag, so a nested table's own </table>
                                                                 * used to end this pass early */
      while (p < e && guard++ < 200000) {
        if (*p != '<') { p++; continue; }
        if (p+6 <= e && lc(p[1])=='t'&&lc(p[2])=='a'&&lc(p[3])=='b'&&lc(p[4])=='l'&&lc(p[5])=='e') { depth++; p += 6; continue; }
        const char *after; int k = tbl_classify(p, e, &after);
        if (k == 4) { if (--depth == 0) { tend = after; break; } p = after; continue; }
        if (k == 1) { col = 0; p = after; continue; }
        if (k == 2 || k == 6) {
            const char *cs = after, *cend = cs;
            while (cend < e) { if (*cend == '<') { const char *aa; if (tbl_classify(cend, e, &aa)) break; } cend++; }
            int n = cell_extract(cs, cend, out, TBL_CELL_MAX);
            int span = cell_colspan(p, after - 1);                               /* M1795: colspan */
            if (span == 1) { if (col < TBL_COLS && n > col_w[col]) col_w[col] = n; }  /* a single cell measures its own column */
            col += span; p = cend; continue;                                     /* a spanning cell advances the cursor by span (width summed in pass 2) */
        }
        p = after;
      }
    }
    /* pass 2: emit each cell padded to its column width (fixed-width font => aligned) */
    emit_break(b, TK_PARA);
    { const char *p = s; int col = 0, guard = 0, depth = 1;
      while (p < e && guard++ < 200000) {
        if (*p != '<') { p++; continue; }
        if (p+6 <= e && lc(p[1])=='t'&&lc(p[2])=='a'&&lc(p[3])=='b'&&lc(p[4])=='l'&&lc(p[5])=='e') { depth++; p += 6; continue; }
        const char *after; int k = tbl_classify(p, e, &after);
        if (k == 4) { if (--depth == 0) break; p = after; continue; }
        if (k == 1) { emit_break(b, TK_BREAK); col = 0; p = after; continue; }
        if (k == 2 || k == 6) {
            const char *cs = after, *cend = cs;
            while (cend < e) { if (*cend == '<') { const char *aa; if (tbl_classify(cend, e, &aa)) break; } cend++; }
            int n = cell_extract(cs, cend, out, TBL_CELL_MAX);
            int span = cell_colspan(p, after - 1);                               /* M1795: colspan */
            int w = 0; for (int c = col; c < col + span && c < TBL_COLS; c++) w += col_w[c];   /* pad to the SUM of the spanned columns */
            if (w == 0) w = n;
            char padded[TBL_CELL_MAX + 2]; int m = 0;
            for (int i = 0; i < n && m < TBL_CELL_MAX; i++) padded[m++] = out[i];
            while (m < w && m < TBL_CELL_MAX) padded[m++] = ' ';
            padded[m] = 0;
            emit_literal(b, padded, (k == 6) ? STY_BOLD : STY_NORMAL);
            col += span; p = cend; continue;
        }
        p = after;
      }
    }
    emit_break(b, TK_PARA);
    return (tend < e) ? (int)(tend - s) : len;
}

/* True if `id` belongs to a <textarea> (vs a one-line <input>): controls whether
 * Enter inserts a newline (textarea) or submits/blurs (input). */
static int is_textarea(browser_t *b, const char *id) {
    for (int i = 0; i < b->ta_n; i++) if (streqs(b->ta_ids[i], id)) return 1;
    return 0;
}
/* Render a <textarea> as a focusable, multi-line field: each line of the stored
 * value is a clickable field token (click to focus, then type — Enter adds a
 * line), with the caret '|' drawn at field_cur on its line. Empty -> a clickable
 * placeholder box. The value is the input store (in_get/in_set), so .value reads
 * it and the form submits name=value like any field. */
static void emit_textarea(browser_t *b, const char *id) {
    const char *val = in_get(b, id);
    int focused = streqs(b->focus_id, id);
    int vlen = val ? (int)strlen(val) : 0;
    int fc = b->field_cur; if (fc < 0) fc = 0; if (fc > vlen) fc = vlen;
    int lk = add_input_link(b, id);
    emit_break(b, TK_PARA);
    if (vlen == 0) {                                     /* empty: a clickable placeholder */
        emit_literal_link(b, focused ? "[|         ]" : "[ ......... ]", lk);
        emit_break(b, TK_PARA);
        return;
    }
    int ls = 0;
    for (;;) {
        int le = ls; while (le < vlen && val[le] != '\n') le++;   /* [ls,le) = this line (le at '\n' or end) */
        char s[128]; int p = 0;
        for (int k = ls; k <= le && p < 124; k++) {
            if (focused && k == fc) s[p++] = '|';        /* caret on this line */
            if (k < le) s[p++] = val[k];
        }
        s[p] = 0;
        emit_literal_link(b, s, lk);
        if (le >= vlen) break;                           /* that was the last line */
        ls = le + 1;
        emit_break(b, TK_BREAK);                         /* next line of the textarea */
    }
    emit_break(b, TK_PARA);
}

/* Parse a <select>'s inner HTML into option value/label pairs. value = the
 * `value` attr, else the label text. *defsel = index of the `selected` option, or -1. */
static void parse_select(const char *html, int len, char vals[][32], char labs[][48], int max, int *nopt, int *defsel) {
    int n = 0; *defsel = -1;
    for (int i = 0; i + 7 <= len && n < max; ) {
        if (!(html[i]=='<' && lc(html[i+1])=='o' && lc(html[i+2])=='p' && lc(html[i+3])=='t' &&
              lc(html[i+4])=='i' && lc(html[i+5])=='o' && lc(html[i+6])=='n')) { i++; continue; }
        int as = i + 7, j = as; char q = 0;                       /* scan the option tag's attrs to '>' */
        while (j < len) { char c = html[j]; if (q) { if (c==q) q=0; } else if (c=='"'||c=='\'') q=c; else if (c=='>') break; j++; }
        const char *vp; int vl; char vbuf[32]; vbuf[0]=0;
        if (find_attr(html+as, j-as, "value", &vp, &vl)) { int m=vl>31?31:vl; for(int k=0;k<m;k++) vbuf[k]=vp[k]; vbuf[m]=0; }
        int sel = has_attr(html+as, j-as, "selected");
        int ls = (j<len) ? j+1 : len, le = ls; while (le < len && html[le] != '<') le++;   /* label = text up to next tag */
        while (ls < le && (html[ls]==' '||html[ls]=='\n'||html[ls]=='\t')) ls++;
        while (le > ls && (html[le-1]==' '||html[le-1]=='\n'||html[le-1]=='\t')) le--;
        int lm = le-ls; if (lm>47) lm=47; if (lm<0) lm=0;
        for (int k=0;k<lm;k++){ labs[n][k]=html[ls+k]; } labs[n][lm]=0;
        if (vbuf[0]) { int k=0; while(vbuf[k]){vals[n][k]=vbuf[k];k++;} vals[n][k]=0; }
        else { int k=0; while(labs[n][k] && k<31){vals[n][k]=labs[n][k];k++;} vals[n][k]=0; }
        if (sel) *defsel = n;
        n++; i = le;
    }
    *nopt = n;
}

static void parse_html(browser_t *b, const char *body, int len) {
    drop_image(b);                                       /* a page replaces any prior image */
    drop_image_slots(b);                                 /* and its inline images */
    b->textlen = b->ntok = b->hreflen = b->nlink = 0;
    b->scriptlen = 0;                                    /* recaptured fresh each parse */
    b->ta_n = 0;                                         /* <textarea> id set rebuilt fresh each parse (values persist in the input store) */
    b->sel_n = 0;                                        /* <select> option lists rebuilt fresh each parse */
    b->oc_depth = 0;                                     /* no inline-onclick scope open yet */
    b->sc_sp = 0;                                        /* no style scopes open yet */
    b->n_hidden = 0;                                     /* nothing hidden yet */
    b->n_css = 0;                                        /* <style> rules captured fresh each parse */
    b->form_action[0] = 0;                               /* no <form> action open yet */
    b->anc_n = 0;                                        /* fresh #fragment anchor table */
    b->sel = NO_LINK;                                    /* no link selected on a fresh page */
    b->tsel0 = b->tsel1 = -1;                            /* drop any text selection on reparse */
    b->find_tok = -1;                                    /* clear any find highlight */
    b->curcolor = 0;                                     /* default text colour */
    b->curbg = 0;                                        /* no background-color in effect */
    b->curalign = 0;                                     /* default left alignment */
    b->curscale = 0;                                     /* no font-size override in effect */
    b->curlh_css = 0;                                    /* no CSS line-height override in effect */
    b->curindent = 0;                                    /* no blockquote indent in effect */
    b->curprews = 0;                                     /* no CSS white-space:pre in effect (M1818) */
    b->curul = 0;                                        /* no underline in effect */
    b->curtransform = 0;                                 /* no text-transform in effect */
    b->viewsource = 0;                                   /* show the rendered page, not source */
    b->listdepth = 0;                                    /* reset list nesting */
    b->tdcount = 0;
    memset(b->linky, 0xFF, sizeof(b->linky));            /* -1 = "not laid out this page" */
    b->title[0] = 0;
    int titlelen = 0, titlesp = 0;
    int style = STY_NORMAL, linkdepth = 0, curlink = NO_LINK;
    /* independent suppression flags: a stray </title> must not reveal <head>,
     * and <body> force-clears head/title so a missing </head> can't blank the
     * whole page (fail-safe on malformed input). */
    int inscript = 0, instyle = 0, intitle = 0, inhead = 0, inpre = 0, insvg = 0, wstart = -1;
    int sc_start = -1;                                   /* offset where current <script> body began */
    int st_start = -1;                                   /* offset where current <style> body began */
    int intextarea = 0, ta_start = -1; char ta_id[32] = {0}, ta_name[32] = {0};   /* <textarea>: raw-text capture -> field value */
    int inselect = 0, sel_start = -1; char sel_id[32] = {0}, sel_name[32] = {0};  /* <select>: raw-text capture -> option list */
    int det_n = 0, det_depth = 0, det_hide = 0, in_summary = 0, det_cur = 0;   /* <details>: index / nesting / suppress-depth / in-<summary> / current idx */
    int sum_link = NO_LINK, sum_style = STY_NORMAL;      /* saved link/style around a <summary> */

    /* Reader mode: render only the page's main-content region so a linear renderer
     * shows the article first, instead of stacking nav/header/sidebar chrome before
     * it. <style>/<title>/<head> are still processed below (page CSS + window title
     * keep working); only body content + content-emitting tags outside [rlo,rhi) are
     * skipped. When no clear content container is found, ron==0 -> the whole page. */
    int rlo = 0, rhi = len, ron = 0;
    if (b->reader) { int a, z; if (reader_main_region(body, len, &a, &z)) { rlo = a; rhi = z; ron = 1; } }

    for (int i = 0; i < len; i++) {
        char c = body[i];
        int rgate = ron && (i < rlo || i >= rhi);   /* reader mode: this byte/tag is chrome outside the main-content region */
        if (c == '<') {
            /* Inside <script>/<style>, content is raw: a '<' that isn't the matching
             * close tag (e.g. `i < 5`, or `<p>` inside a document.write string) must
             * be treated as content, NOT parsed as a tag — otherwise the (quote-aware)
             * tag scan can run past </script> and the block is never closed/captured. */
            if (inscript || instyle || intextarea || inselect) {
                const char *ct = inscript ? "/script" : instyle ? "/style" : intextarea ? "/textarea" : "/select";
                int ctlen = 0; while (ct[ctlen]) ctlen++;
                int match = (i+1 < len && body[i+1] == '/');
                if (match) for (int z = 0; z < ctlen; z++) { if (i+1+z >= len || lc(body[i+1+z]) != ct[z]) { match = 0; break; } }
                if (match) {                          /* require a tag terminator AFTER the name: `</script>`/`</script >` yes,
                                                       * `</scripting>` / `</selected>` no — else raw capture ends early on a
                                                       * substring (a textarea/select body containing `</selecting>` etc.). */
                    char e = (i+1+ctlen < len) ? body[i+1+ctlen] : '>';   /* at EOL: treat as the implicit close */
                    if (!(e=='>' || e==' ' || e=='\t' || e=='\n' || e=='\r' || e=='/')) match = 0;
                }
                if (!match) continue;                 /* '<' is script/style content; skip it */
            }
            if (wstart >= 0) { emit_word(b, wstart, style, curlink); wstart = -1; }
            /* HTML comment <!-- ... -->: skip to the "-->" terminator. A comment
             * may contain '>' (conditional comments, embedded markup), so we can't
             * just scan to the next '>' like an ordinary tag, or its tail leaks. */
            if (i + 3 < len && body[i+1] == '!' && body[i+2] == '-' && body[i+3] == '-') {
                int k = i + 4;
                while (k + 2 < len && !(body[k]=='-' && body[k+1]=='-' && body[k+2]=='>')) k++;
                i = (k + 2 < len) ? k + 2 : len;    /* loop ++ steps past the '>' */
                continue;
            }
            int j = i + 1, closing = 0;
            if (j < len && body[j] == '/') { closing = 1; j++; }
            char tag[12]; int tl = 0;
            while (j < len && tl < 11) {
                char tc = body[j];
                if (tc=='>'||tc==' '||tc=='/'||tc=='\t'||tc=='\n') break;
                tag[tl++] = (char)lc(tc); j++;
            }
            tag[tl] = 0;
            int astart = j;
            { char q = 0;                                 /* attributes -> unquoted '>' (so a quoted */
              while (j < len) { char ac = body[j];        /* '>' e.g. in href="javascript:...'<p>'" is kept) */
                  if (q) { if (ac == q) q = 0; }
                  else if (ac=='"' || ac=='\'') q = ac;
                  else if (ac=='>') break;
                  j++; } }

            if (tageq(tag, "script")) {
                if (!closing) { inscript = 1; sc_start = j + 1; }          /* body starts after '>' */
                else { if (inscript && sc_start >= 0 && i > sc_start) capture_script(b, body + sc_start, i - sc_start);
                       inscript = 0; sc_start = -1; }
            }
            else if (tageq(tag, "style")) {
                if (!closing) { instyle = 1; st_start = j + 1; }          /* body starts after '>' */
                else { if (instyle && st_start >= 0 && i > st_start) capture_css(b, body + st_start, i - st_start);
                       instyle = 0; st_start = -1; }
            }
            else if (tageq(tag, "textarea")) {                   /* multi-line field: inner text is the value */
                if (!closing) {
                    intextarea = 1; ta_start = j + 1;            /* body starts after '>' */
                    ta_id[0] = 0; ta_name[0] = 0;
                    const char *av; int al;
                    if (find_attr(body + astart, j - astart, "id",   &av, &al) && al > 0) { int n = al > 31 ? 31 : al; for (int k=0;k<n;k++){ ta_id[k]=av[k]; }   ta_id[n]=0; }
                    if (find_attr(body + astart, j - astart, "name", &av, &al) && al > 0) { int n = al > 31 ? 31 : al; for (int k=0;k<n;k++){ ta_name[k]=av[k]; } ta_name[n]=0; }
                    if (ta_id[0] && b->ta_n < 8) { int k=0; while (ta_id[k] && k<31) { b->ta_ids[b->ta_n][k]=ta_id[k]; k++; } b->ta_ids[b->ta_n][k]=0; b->ta_n++; }
                } else {
                    if (intextarea && ta_start >= 0 && ta_id[0]) {
                        if (!in_get(b, ta_id)) {                 /* seed from the inner text (only if not already typed/scripted) */
                            int ss = ta_start; if (ss < i && body[ss] == '\n') ss++;   /* HTML strips a leading newline */
                            char vb[IN_VLEN]; int n = i - ss; if (n > IN_VLEN-1) n = IN_VLEN-1; if (n < 0) n = 0;
                            for (int k = 0; k < n; k++){ vb[k] = body[ss + k]; } vb[n] = 0;
                            in_set(b, ta_id, vb);
                        }
                        if (ta_name[0]) in_name_set(b, ta_id, ta_name);   /* submit name=value */
                        emit_textarea(b, ta_id);
                    }
                    intextarea = 0; ta_start = -1; ta_id[0] = 0;
                }
            }
            else if (tageq(tag, "select")) {                     /* dropdown: a click cycles through its <option>s */
                if (!closing) {
                    inselect = 1; sel_start = j + 1;
                    sel_id[0] = 0; sel_name[0] = 0;
                    const char *av; int al;
                    if (find_attr(body + astart, j - astart, "id",   &av, &al) && al > 0) { int n = al > 31 ? 31 : al; for (int k=0;k<n;k++){ sel_id[k]=av[k]; }   sel_id[n]=0; }
                    if (find_attr(body + astart, j - astart, "name", &av, &al) && al > 0) { int n = al > 31 ? 31 : al; for (int k=0;k<n;k++){ sel_name[k]=av[k]; } sel_name[n]=0; }
                } else {
                    if (inselect && sel_start >= 0 && sel_id[0]) {
                        char vals[16][32], labs[16][48]; int nopt = 0, defsel = -1;
                        parse_select(body + sel_start, i - sel_start, vals, labs, 16, &nopt, &defsel);
                        if (nopt > 0) {
                            const char *cur = in_get(b, sel_id);
                            int selidx = -1;
                            if (cur) for (int k = 0; k < nopt; k++) if (streqs(vals[k], cur)) { selidx = k; break; }   /* keep a cycled/seeded choice */
                            if (selidx < 0) selidx = (defsel >= 0) ? defsel : 0;
                            if (!cur) in_set(b, sel_id, vals[selidx]);                 /* seed the default selection */
                            if (sel_name[0]) in_name_set(b, sel_id, sel_name);
                            if (b->sel_n < 8) {                                        /* remember the option order for click-cycling */
                                int k=0; while (sel_id[k] && k<31) { b->sel_ids[b->sel_n][k]=sel_id[k]; k++; } b->sel_ids[b->sel_n][k]=0;
                                int o=0; for (int v=0; v<nopt; v++) { if (v && o<511) b->sel_vals[b->sel_n][o++]='\n'; for (int c=0; vals[v][c] && o<511; c++) b->sel_vals[b->sel_n][o++]=vals[v][c]; }
                                b->sel_vals[b->sel_n][o]=0; b->sel_n++;
                            }
                            char disp[56]; int p=0; disp[p++]='['; disp[p++]=' ';      /* render "[ Label v]" as a focusable link */
                            for (int c=0; labs[selidx][c] && p<50; c++) disp[p++]=labs[selidx][c];
                            disp[p++]=' '; disp[p++]='v'; disp[p++]=']'; disp[p]=0;
                            int lk = add_select_link(b, sel_id);
                            if (lk != NO_LINK) emit_literal_link(b, disp, lk); else emit_literal(b, disp, STY_EM);
                        }
                    }
                    inselect = 0; sel_start = -1; sel_id[0] = 0;
                }
            }
            else if (tageq(tag, "svg")) insvg = !closing;        /* inline SVG: skip its guts */
            else if (tageq(tag, "title") && !insvg) intitle = !closing;  /* (svg <title> mustn't hijack) */
            else if (tageq(tag, "head")) inhead = !closing;
            else if (tageq(tag, "body")) inhead = intitle = 0;   /* visible content */
            else if (tageq(tag, "pre") && !rgate) {              /* preformatted block */
                inpre = !closing;
                emit_break(b, TK_PARA);                          /* pre starts/ends on its own line */
            }
            else if (tageq(tag, "details") && !rgate) {          /* collapsible: hide the body when closed */
                if (!closing) {
                    int idx = det_n < 16 ? det_n : 15; if (det_n < 16) det_n++;   /* cap idx so det_open[idx] stays in bounds */
                    if (b->det_open[idx] == 0xFF) b->det_open[idx] = has_attr(body + astart, j - astart, "open") ? 1 : 0;
                    det_depth++; det_cur = idx;
                    if (!b->det_open[idx] && !det_hide) det_hide = det_depth;     /* start hiding this closed details' body */
                } else { if (det_depth == det_hide) det_hide = 0; if (det_depth > 0) det_depth--; }
                emit_break(b, TK_PARA);
            }
            else if (tageq(tag, "summary") && !rgate) {          /* the always-shown, clickable toggle */
                if (!closing && det_depth > 0) {
                    in_summary = 1; sum_link = curlink; sum_style = style;
                    int lk = add_det_link(b, det_cur);
                    if (lk != NO_LINK) { curlink = lk; if (style == STY_NORMAL) style = STY_LINK;
                        emit_literal_link(b, b->det_open[det_cur] ? "[-] " : "[+] ", lk); }
                } else if (closing && in_summary) { in_summary = 0; curlink = sum_link; style = sum_style; }
            }
            else if (tageq(tag, "table") && !closing && !rgate &&
                     !inscript && !instyle && !intitle && !inhead && !insvg && !(det_hide && !in_summary) &&
                     !table_has_field(body + j + 1, body + len)) {   /* a form/layout table -> normal flow so its inputs render */
                /* render the whole <table>..</table> region as aligned columns, then skip past it */
                int consumed = render_table(b, body + j + 1, len - (j + 1));
                i = j + consumed;                         /* loop ++ lands just past </table> */
                continue;
            }
            else if (!rgate && !inscript && !instyle && !intitle && !inhead && !insvg && !(det_hide && !in_summary))
                handle_tag(b, tag, closing, body + astart, j - astart,
                           &style, &linkdepth, &curlink);

            i = j;                                        /* loop ++ steps past '>' */
            continue;
        }
        if (inscript || instyle || insvg || intextarea || inselect) continue;  /* never render script/style/svg/textarea/select body (handled at the close tag) */
        if (det_hide && !in_summary) continue;        /* inside a collapsed <details>, outside its <summary> */
        if (b->n_hidden > 0) continue;                /* inside a display:none element (tags still tracked above) */

        if (c == '&') {
            char dec; int adv = decode_entity(body + i, len - i, &dec);
            if (adv) { c = dec; i += adv - 1; }
        } else if ((unsigned char)c >= 0x80) {    /* fold a raw UTF-8 char to ASCII */
            unsigned cp; int adv = decode_utf8(body + i, len - i, &cp);
            c = uni_to_ascii(cp); i += adv - 1;
        }
        if (intitle) {                            /* capture <title> (even inside <head>) */
            if (c==' '||c=='\t'||c=='\n'||c=='\r') { if (titlelen > 0) titlesp = 1; }
            else { if (titlesp && titlelen < 63) b->title[titlelen++] = ' ';
                   titlesp = 0; if (titlelen < 63) b->title[titlelen++] = c; }
            continue;
        }
        if (inhead) continue;                     /* skip other <head> content */
        if (rgate) continue;                      /* reader mode: content outside the main-content region (title/head already handled above) */
        if (b->curtransform) {                    /* CSS text-transform: case-fold the RENDERED char (goes into b->text only; .textContent reads b->raw, so it stays original) */
            if (b->curtransform == 1 && c >= 'a' && c <= 'z') c -= 32;
            else if (b->curtransform == 2 && c >= 'A' && c <= 'Z') c += 32;
        }
        if (inpre || b->curprews) {               /* preformatted (<pre> or CSS white-space:pre): keep spaces + line breaks */
            if (c == '\r') continue;
            if (c == '\n') {
                if (wstart >= 0) { emit_word(b, wstart, style, curlink); wstart = -1; }
                if (b->ntok > 0 && b->ntok < TOK_MAX)            /* preserve blank lines too */
                    b->toks[b->ntok++] = (tok_t){0,0,NO_LINK,STY_NORMAL,TK_BREAK};
                continue;
            }
            if (c == '\t') c = ' ';               /* render tabs as a space */
            if (b->textlen < TEXT_MAX - 1) {       /* accumulate (spaces included) into one word */
                if (wstart < 0) wstart = b->textlen;
                b->text[b->textlen++] = c;
            }
            continue;
        }
        if (c==' '||c=='\t'||c=='\n'||c=='\r') {
            if (wstart >= 0) { emit_word(b, wstart, style, curlink); wstart = -1; }
            continue;
        }
        if (b->textlen < TEXT_MAX - 1) {
            if (wstart < 0) wstart = b->textlen;
            b->text[b->textlen++] = c;
        }
    }
    if (wstart >= 0) emit_word(b, wstart, style, curlink);
    b->title[titlelen] = 0;
}

/* ---- run a page's inline JavaScript ----
 * document.write() output is spliced into b->raw right after the body and the
 * page is re-parsed, so script-generated HTML renders. A real DOM (getElementById,
 * .innerHTML) is future work; this covers the classic document.write pattern. */
static char *g_sw_raw; static int g_sw_pos, g_sw_max;
static int  g_sw_base;   /* the document.write append base (body end at script start); a DOM
                          * mutation that shifts the buffer adjusts this + g_sw_pos together, so
                          * `written = g_sw_pos - g_sw_base` stays correct when both are used. */
static void script_write_cb(const char *s) {
    if (!g_sw_raw) return;
    while (*s && g_sw_pos < g_sw_max - 1) g_sw_raw[g_sw_pos++] = *s++;
    g_sw_raw[g_sw_pos] = 0;
}

/* localStorage backing: a per-page key->value store the JS engine reads/writes
 * (survives the engine's per-run arena reset, so click handlers keep state). */
static browser_t *g_ls_b;
static const char *browser_ls_get(const char *key) {
    if (!g_ls_b) return 0;
    for (int i = 0; i < g_ls_b->ls_n; i++) if (streqs(g_ls_b->ls_keys[i], key)) return g_ls_b->ls_vals[i];
    return 0;
}
static void browser_ls_set(const char *key, const char *val) {
    if (!g_ls_b) return;
    int i; for (i = 0; i < g_ls_b->ls_n; i++) if (streqs(g_ls_b->ls_keys[i], key)) break;
    if (i == g_ls_b->ls_n) { if (g_ls_b->ls_n >= 16) return; int j=0; while(key[j]&&j<31){g_ls_b->ls_keys[i][j]=key[j];j++;} g_ls_b->ls_keys[i][j]=0; g_ls_b->ls_n++; }
    int j=0; while(val[j]&&j<159){g_ls_b->ls_vals[i][j]=val[j];j++;} g_ls_b->ls_vals[i][j]=0;
}
/* removeItem/clear (M1619): getItem/setItem existed since the original
 * localStorage support, but nothing ever backed these two ordinary Web
 * Storage calls -- a page calling either just hit "not a function". */
static void browser_ls_remove(const char *key) {
    if (!g_ls_b) return;
    int i; for (i = 0; i < g_ls_b->ls_n; i++) if (streqs(g_ls_b->ls_keys[i], key)) break;
    if (i == g_ls_b->ls_n) return;                      /* not found: a no-op, matches real removeItem */
    for (int k = i; k < g_ls_b->ls_n - 1; k++) {         /* shift the tail down over the removed slot */
        int j = 0; while (g_ls_b->ls_keys[k+1][j]) { g_ls_b->ls_keys[k][j] = g_ls_b->ls_keys[k+1][j]; j++; } g_ls_b->ls_keys[k][j] = 0;
        j = 0; while (g_ls_b->ls_vals[k+1][j]) { g_ls_b->ls_vals[k][j] = g_ls_b->ls_vals[k+1][j]; j++; } g_ls_b->ls_vals[k][j] = 0;
    }
    g_ls_b->ls_n--;
}
static void browser_ls_clear(void) { if (g_ls_b) g_ls_b->ls_n = 0; }
/* ---- minimal DOM: find/read/mutate an element by id in the page source ----
 * Locate <tag … id="ID" …>INNER</tag> in the body region of b->raw and report
 * INNER's byte range [*is, *ie). Handles nested same-name tags by depth count. */
static int dom_alnum(int c){ return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9'); }
static int dom_find(browser_t *b, const char *id, int *is, int *ie) {
    const char *r = b->raw; int lo = b->bodyoff, hi = b->bodyoff + b->bodylen;
    int idlen = 0; while (id[idlen]) idlen++;
    if (idlen == 0) return 0;
    for (int i = lo; i + 4 < hi; i++) {
        if (!(r[i]=='i' && r[i+1]=='d' && r[i+2]=='=' && (r[i+3]=='"' || r[i+3]=='\''))) continue;
        char q = r[i+3]; int vs = i + 4, k = 0;
        while (k < idlen && vs + k < hi && r[vs+k] == id[k]) k++;
        if (!(k == idlen && vs + k < hi && r[vs+k] == q)) continue;   /* whole attr value must equal id */
        int ts = i; while (ts > lo && r[ts] != '<') ts--;             /* back up to the opening '<' */
        if (r[ts] != '<') continue;
        char tag[16]; int tn = 0, ne = ts + 1;
        while (ne < hi && dom_alnum(r[ne]) && tn < 15) tag[tn++] = r[ne++];
        if (tn == 0) continue;
        int gt = i; while (gt < hi && r[gt] != '>') gt++;             /* end of the opening tag */
        if (gt >= hi) return 0;
        int istart = gt + 1, depth = 1, p = istart;
        while (p < hi) {
            if (r[p] == '<') {
                if (p+2+tn <= hi && r[p+1]=='/' && memcmp(r+p+2, tag, tn)==0) { if(--depth==0){ *is=istart; *ie=p; return 1; } }
                else if (p+1+tn < hi && memcmp(r+p+1, tag, tn)==0 && (r[p+1+tn]==' '||r[p+1+tn]=='>'||r[p+1+tn]=='/')) depth++;
            }
            p++;
        }
        return 0;
    }
    return 0;
}
/* ---- querySelector(All): a tiny CSS-selector matcher over the page source ----
 * Supports simple selectors: a tag name, ".class", "#id", and compounds like
 * "div.note" / "p#x". Matches are reported as the byte offset of each opening
 * '<' in b->raw, which dom_find_at() then resolves to an inner-text span (the
 * same byte coordinates the id-keyed splice code already uses) — so id-less
 * matches become addressable WITHOUT changing the id path. */
#define QSA_MAX 256
/* sel_parse now lives in cssel.h (M688) so it can be host-fuzzed; included at the top. */
/* Word-boundary class match within a class="..." value (space-separated tokens). */
/* class_has (word-boundary class-token match) now lives in cssel.h (M690). */
/* ---- CSS custom properties: var() resolution (M1432) ----
 * Real stylesheets (e.g. milescoviello.com: 158 var() refs) define colours, spacing and
 * sizes through `--name: value` on :root and reference them with var(--name[, fallback]).
 * Before parsing rules we collect every custom-property declaration, flatten var() within
 * those values, then rewrite the <style> body replacing each var(...) with its value — so
 * the existing value parsers see concrete colours/sizes. Every buffer write is bounded. */
#define CSS_REWRITE_MAX 49152
#define CSS_VARS_MAX    256
#define CSS_VNAME       40
#define CSS_VVAL        96
static char g_css_rw[CSS_REWRITE_MAX];
static struct { char name[CSS_VNAME]; char val[CSS_VVAL]; } g_css_var[CSS_VARS_MAX];
static int  g_css_nvar;

static int css_var_find(const char *nm, int nl) {
    for (int i = 0; i < g_css_nvar; i++) {
        int k = 0; while (k < nl && g_css_var[i].name[k] && g_css_var[i].name[k] == nm[k]) k++;
        if (k == nl && g_css_var[i].name[k] == 0) return i;
    }
    return -1;
}
/* Copy src[0..n) -> dst, replacing var(--name[, fallback]) with the variable's value (or
 * the fallback, or nothing). Writes bounded by cap; returns out length or -1 on overflow. */
static int css_subst_once(const char *src, int n, char *dst, int cap, int *subst) {
    int op = 0; *subst = 0;
    for (int i = 0; i < n; ) {
        if (i + 4 <= n && src[i]=='v' && src[i+1]=='a' && src[i+2]=='r' && src[i+3]=='(') {
            int depth = 1, m = i + 4, comma = -1;
            while (m < n && depth > 0) {                       /* match the closing ')' */
                char c = src[m];
                if (c == '(') depth++;
                else if (c == ')') { depth--; if (depth == 0) break; }
                else if (c == ',' && depth == 1 && comma < 0) comma = m;
                m++;
            }
            if (m >= n) { if (op >= cap-1) return -1; dst[op++] = src[i++]; continue; }   /* unterminated */
            int close = m, ns = i + 4, ne = (comma >= 0) ? comma : close;
            while (ns < ne && (src[ns]==' '||src[ns]=='\t')) ns++;
            while (ne > ns && (src[ne-1]==' '||src[ne-1]=='\t')) ne--;
            int vi = css_var_find(src + ns, ne - ns);
            if (vi >= 0) { const char *v = g_css_var[vi].val; for (int z = 0; v[z]; z++) { if (op >= cap-1) return -1; dst[op++] = v[z]; } }
            else if (comma >= 0) {                             /* missing var -> use fallback */
                int fs = comma + 1, fe = close;
                while (fs < fe && (src[fs]==' '||src[fs]=='\t')) fs++;
                while (fe > fs && (src[fe-1]==' '||src[fe-1]=='\t')) fe--;
                for (int z = fs; z < fe; z++) { if (op >= cap-1) return -1; dst[op++] = src[z]; }
            }
            *subst = 1; i = close + 1;
        } else { if (op >= cap-1) return -1; dst[op++] = src[i++]; }
    }
    dst[op] = 0; return op;
}
static void css_collect_vars(const char *s, int n) {
    g_css_nvar = 0;
    for (int i = 0; i < n; ) {
        if (s[i] == '-' && i+1 < n && s[i+1] == '-') {         /* candidate "--name" */
            int ns = i, j = i + 2;
            while (j < n && ((s[j]>='a'&&s[j]<='z')||(s[j]>='A'&&s[j]<='Z')||(s[j]>='0'&&s[j]<='9')||s[j]=='-'||s[j]=='_')) j++;
            int ne = j, k = j;
            while (k < n && (s[k]==' '||s[k]=='\t'||s[k]=='\n'||s[k]=='\r')) k++;
            if (k < n && s[k] == ':') {                        /* "--name:" -> a definition */
                int vs = k + 1; while (vs < n && (s[vs]==' '||s[vs]=='\t')) vs++;
                int ve = vs, depth = 0;
                while (ve < n) { char c = s[ve]; if (c=='(') depth++; else if (c==')') { if (depth>0) depth--; } else if ((c==';'||c=='}') && depth==0) break; ve++; }
                int vend = ve; while (vend > vs && (s[vend-1]==' '||s[vend-1]=='\t'||s[vend-1]=='\n'||s[vend-1]=='\r')) vend--;
                if (g_css_nvar < CSS_VARS_MAX) {
                    int nl = ne - ns; if (nl > CSS_VNAME-1) nl = CSS_VNAME-1;
                    for (int z = 0; z < nl; z++) g_css_var[g_css_nvar].name[z] = s[ns+z];
                    g_css_var[g_css_nvar].name[nl] = 0;
                    int vl = vend - vs; if (vl > CSS_VVAL-1) vl = CSS_VVAL-1;
                    for (int z = 0; z < vl; z++) g_css_var[g_css_nvar].val[z] = s[vs+z];
                    g_css_var[g_css_nvar].val[vl] = 0;
                    g_css_nvar++;
                }
                i = ve;
            } else i = j;
        } else i++;
    }
    for (int round = 0; round < 6; round++) {                  /* flatten var() inside var values */
        int changed = 0;
        for (int vi = 0; vi < g_css_nvar; vi++) {
            int len = 0; while (g_css_var[vi].val[len]) len++;
            int sub = 0; char tmp[CSS_VVAL];
            int r = css_subst_once(g_css_var[vi].val, len, tmp, CSS_VVAL, &sub);
            if (r >= 0 && sub) { for (int z = 0; z <= r; z++) g_css_var[vi].val[z] = tmp[z]; changed = 1; }
        }
        if (!changed) break;
    }
}
static const char *css_resolve_vars(const char *s, int *np) {
    int n = *np;
    css_collect_vars(s, n);
    if (g_css_nvar == 0) return s;                             /* no custom properties */
    int sub = 0, r = css_subst_once(s, n, g_css_rw, CSS_REWRITE_MAX, &sub);
    if (r < 0 || !sub) return s;                               /* overflow / nothing changed */
    *np = r; return g_css_rw;
}

/* Parse a <style> body into simple `selector { color / font-weight / font-style }` rules
 * (b->css_*). A selector that isn't a single simple selector (descendant, comma-grouped,
 * @-rule) fails sel_parse and is skipped. Bounded read-only over s[0..n); caps at CSS_MAX. */
/* Does the declaration for property `name` (at a property boundary in s[0..n))
 * carry a `!important` priority marker in its value? Mirrors parse_style_color's
 * boundary test; scans the first matching declaration's value to ';'/'}' for
 * `!` [ws]* `important` (case-insensitive). Used to give !important declarations
 * cascade priority over higher-specificity normal ones (M1788, CSS survey F5). */
static int prop_imp(const char *s, int n, const char *name) {
    int nl = 0; while (name[nl]) nl++;
    for (int i = 0; i + nl < n; i++) {
        char before = i ? s[i-1] : ' ';
        if (!(before==' '||before==';'||before=='\t'||before=='\n'||before=='\r'||before=='{'||before=='"'||before=='\'')) continue;
        int m = 1; for (int k = 0; k < nl; k++) if (lc(s[i+k]) != lc(name[k])) { m = 0; break; }
        if (!m) continue;
        int k = i + nl; while (k < n && (s[k]==' '||s[k]=='\t')) k++;
        if (k >= n || s[k] != ':') continue;                 /* must be exactly "name:" */
        k++;
        for (; k < n && s[k] != ';' && s[k] != '}'; k++) {    /* scan this property's value */
            if (s[k] == '!') {
                int j = k + 1; while (j < n && (s[j]==' '||s[j]=='\t')) j++;
                if (j + 9 <= n && lc(s[j])=='i'&&lc(s[j+1])=='m'&&lc(s[j+2])=='p'&&lc(s[j+3])=='o'&&
                    lc(s[j+4])=='r'&&lc(s[j+5])=='t'&&lc(s[j+6])=='a'&&lc(s[j+7])=='n'&&lc(s[j+8])=='t') return 1;
            }
        }
        return 0;                                             /* found the property, no !important */
    }
    return 0;
}
static void capture_css(browser_t *b, const char *s, int n) {
    { int rn = n; s = css_resolve_vars(s, &rn); n = rn; }      /* resolve var() before parsing (M1432) */
    int i = 0;
    while (i < n && b->n_css < CSS_MAX) {
        while (i < n && (s[i]==' '||s[i]=='\t'||s[i]=='\n'||s[i]=='\r'||s[i]==';'||s[i]=='}')) i++;  /* ws / stray ; } */
        if (i >= n) break;
        int ss = i; while (i < n && s[i] != '{' && s[i] != '}') i++;   /* selector text up to '{' */
        if (i >= n || s[i] != '{') continue;         /* '}' (e.g. @-rule close) or end before '{' */
        int se = i; i++;                             /* selector is [ss,se); step past '{' */
        int ds = i; while (i < n && s[i] != '}') i++;   /* declaration block [ds,de) */
        int de = i; if (i < n) i++;                  /* step past '}' */
        /* parse the declaration block once (shared by all comma-grouped selectors) */
        uint32_t col = parse_style_color(s + ds, de - ds);           /* reuse the reviewed value parsers */
        int tsv = parse_style_textstyle(s + ds, de - ds);
        int ulv = parse_style_underline(s + ds, de - ds);
        int trv = parse_style_transform(s + ds, de - ds);
        uint32_t bgv = parse_style_bg(s + ds, de - ds);
        int alv = parse_style_align(s + ds, de - ds);
        int szv = parse_style_fontsize(s + ds, de - ds);
        int dnv = parse_style_display(s + ds, de - ds);
        if (parse_style_flex(s + ds, de - ds)) dnv = 2;             /* display:flex from a rule (1=none, 2=flex) */
        int mgv = parse_style_vspace(s + ds, de - ds);
        int hsv = parse_style_hspace(s + ds, de - ds);
        uint32_t bdv = parse_style_border(s + ds, de - ds);          /* border: shorthand from a stylesheet rule */
        int lsv = parse_style_listtype(s + ds, de - ds);             /* list-style-type from a stylesheet rule (applies to a <ul>/<ol>) */
        int lhv = parse_style_lineheight(s + ds, de - ds);           /* line-height from a stylesheet rule */
        int wsv = parse_style_whitespace(s + ds, de - ds);           /* white-space from a stylesheet rule (M1819) */
        int wv  = parse_style_width_px(s + ds, de - ds);             /* width from a stylesheet rule (M1929) */
        int mav = parse_style_auto_margins(s + ds, de - ds);         /* margin:auto from a stylesheet rule (M1929) */
        int pl = 0, pr = 0, pt = 0, pb = 0;                          /* padding from a rule (M1930) */
        parse_style_padding_lr(s + ds, de - ds, &pl, &pr);
        parse_style_padding_tb(s + ds, de - ds, &pt, &pb);
        int hv  = parse_style_height_px(s + ds, de - ds);            /* height from a rule (M1930) */
        if (!(col || tsv >= 0 || ulv || trv || bgv || alv || szv || dnv || mgv || hsv || bdv || lsv || lhv || wsv || wv || mav || pl || pr || pt || pb || hv)) continue;   /* nothing we render */
        const char *D = s + ds; int dn = de - ds;                    /* M1788: per-property !important bitmask, so an !important decl outranks a higher-specificity normal one */
        uint16_t imp = 0;
        if (prop_imp(D,dn,"color"))                                  imp |= 1u<<0;
        if (prop_imp(D,dn,"font-weight")||prop_imp(D,dn,"font-style")||prop_imp(D,dn,"font")||prop_imp(D,dn,"text-decoration")||prop_imp(D,dn,"text-decoration-line")) imp |= 1u<<1;
        if (prop_imp(D,dn,"text-decoration")||prop_imp(D,dn,"text-decoration-line")) imp |= 1u<<2;
        if (prop_imp(D,dn,"text-transform"))                        imp |= 1u<<3;
        if (prop_imp(D,dn,"background")||prop_imp(D,dn,"background-color")) imp |= 1u<<4;
        if (prop_imp(D,dn,"text-align"))                            imp |= 1u<<5;
        if (prop_imp(D,dn,"font-size")||prop_imp(D,dn,"font"))       imp |= 1u<<6;
        if (prop_imp(D,dn,"display")||prop_imp(D,dn,"visibility"))   imp |= 1u<<7;
        if (prop_imp(D,dn,"margin")||prop_imp(D,dn,"margin-top")||prop_imp(D,dn,"padding")||prop_imp(D,dn,"padding-top")) imp |= 1u<<8;
        if (prop_imp(D,dn,"margin-left")||prop_imp(D,dn,"padding-left")) imp |= 1u<<9;
        if (prop_imp(D,dn,"border")||prop_imp(D,dn,"border-top")||prop_imp(D,dn,"border-right")||prop_imp(D,dn,"border-bottom")||prop_imp(D,dn,"border-left")) imp |= 1u<<10;
        if (prop_imp(D,dn,"list-style-type")||prop_imp(D,dn,"list-style")) imp |= 1u<<11;
        if (prop_imp(D,dn,"line-height"))                           imp |= 1u<<12;
        if (prop_imp(D,dn,"white-space"))                           imp |= 1u<<13;
        if (prop_imp(D,dn,"width"))                                 imp |= 1u<<14;   /* M1932 */
        if (prop_imp(D,dn,"height"))                                imp |= 1u<<15;   /* M1932 */
        /* a selector list "a, b, c" -> one rule per simple sub-selector that parses */
        int p = ss;
        while (p < se && b->n_css < CSS_MAX) {
            int cs2 = p; while (p < se && s[p] != ',') p++;          /* one sub-selector [cs2, ce2) */
            int ce2 = p; if (p < se) p++;                            /* step past ',' */
            while (cs2 < ce2 && (s[cs2]==' '||s[cs2]=='\t'||s[cs2]=='\n'||s[cs2]=='\r')) cs2++;       /* trim */
            while (ce2 > cs2 && (s[ce2-1]==' '||s[ce2-1]=='\t'||s[ce2-1]=='\n'||s[ce2-1]=='\r')) ce2--;
            int sl = ce2 - cs2; if (sl <= 0 || sl >= 96) continue;   /* empty or too long -> skip this part */
            char selbuf[96]; for (int k = 0; k < sl; k++) selbuf[k] = s[cs2+k]; selbuf[sl] = 0;
            sel_t sel; if (!sel_parse(selbuf, &sel)) continue;       /* unsupported selector -> skip this part */
            /* specificity = 100*(#id) + 10*(#class + #attr + ancestor presence) + 1*(#tags) */
            int sp = (sel.id[0] ? 100 : 0)
                   + 10 * (sel_class_count(sel.cls) + (sel.attr[0] ? 1 : 0) + sel_class_count(sel.dcls))   /* M1775: each compound class counts (F1); a TAG ancestor scores at tag-weight below, not class-weight (F4) */
                   + (sel.tag[0] ? 1 : 0) + (sel.dtag[0] ? 1 : 0);
            b->css_spec[b->n_css] = (uint16_t)sp;
            b->css_imp[b->n_css] = imp;                             /* M1788 */
            b->css_sel[b->n_css] = sel;
            b->css_color[b->n_css] = col;
            b->css_style[b->n_css] = (int16_t)tsv;
            b->css_ul[b->n_css] = (uint8_t)ulv;
            b->css_transform[b->n_css] = (uint8_t)trv;
            b->css_bg[b->n_css] = bgv;
            b->css_align[b->n_css] = (uint8_t)alv;
            b->css_size[b->n_css] = (uint8_t)szv;
            b->css_disp[b->n_css] = (uint8_t)dnv;
            b->css_margin[b->n_css] = (uint8_t)mgv;
            b->css_indent[b->n_css] = (uint8_t)hsv;
            b->css_border[b->n_css] = bdv;
            b->css_list[b->n_css] = (uint8_t)lsv;
            b->css_lineheight[b->n_css] = (uint8_t)(lhv > 255 ? 255 : lhv);
            b->css_ws[b->n_css] = (uint8_t)wsv;
            b->css_w[b->n_css] = (uint16_t)(wv > 65535 ? 65535 : wv);
            b->css_mauto[b->n_css] = (uint8_t)mav;
            b->css_padl[b->n_css] = (uint8_t)(pl > 255 ? 255 : pl);
            b->css_padr[b->n_css] = (uint8_t)(pr > 255 ? 255 : pr);
            b->css_padt[b->n_css] = (uint8_t)(pt > 255 ? 255 : pt);
            b->css_padb[b->n_css] = (uint8_t)(pb > 255 ? 255 : pb);
            b->css_h[b->n_css] = (uint16_t)(hv > 65535 ? 65535 : hv);
            b->n_css++;
        }
    }
}
/* Test whether rule r's selector matches the current element (tag/attrs) and scope stack.
 * Shared by css_match and css_match_list. Returns 1 on match, 0 otherwise. */
/* M1793: match an element's attribute VALUE (v[0..vl), not NUL-terminated) against a
 * selector's [attr OP value] (aval NUL-terminated; op '='/'~'/'^'/'$'/'*'). Case-sensitive,
 * as CSS attribute-value matching is by default. '~='=one whitespace-separated token equals
 * aval; '^='=prefix; '$='=suffix; '*='=substring; '='=exact. An empty aval matches only an
 * empty value for '=', and never for the substring/prefix/suffix/token ops (per spec). */
static int attr_val_match(const char *v, int vl, const char *aval, char op) {
    int al = 0; while (aval[al]) al++;
    switch (op) {
        case '=': return al == vl && (vl == 0 || memcmp(v, aval, (size_t)vl) == 0);
        case '^': return al > 0 && al <= vl && memcmp(v, aval, (size_t)al) == 0;
        case '$': return al > 0 && al <= vl && memcmp(v + vl - al, aval, (size_t)al) == 0;
        case '*': if (al == 0) return 0; for (int i = 0; i + al <= vl; i++) if (memcmp(v + i, aval, (size_t)al) == 0) return 1; return 0;
        case '~': { if (al == 0) return 0; int i = 0; while (i < vl) {
                        while (i < vl && (v[i]==' '||v[i]=='\t'||v[i]=='\n'||v[i]=='\r'||v[i]=='\f')) i++;
                        int st = i; while (i < vl && !(v[i]==' '||v[i]=='\t'||v[i]=='\n'||v[i]=='\r'||v[i]=='\f')) i++;
                        if (i - st == al && memcmp(v + st, aval, (size_t)al) == 0) return 1;
                    } return 0; }
        default:  return 1;   /* op 0 is presence-only, handled by the caller */
    }
}
static int css_rule_matches(browser_t *b, int r, const char *tag, const char *attrs, int attrlen) {
    const sel_t *s = &b->css_sel[r];
    if (s->tag[0] && !tageq(tag, s->tag)) return 0;
    if (s->cls[0]) { const char *v; int vl; if (!find_attr(attrs, attrlen, "class", &v, &vl) || !class_has_all(v, vl, s->cls)) return 0; }   /* M1775: ALL compound classes must be present */
    if (s->id[0])  { const char *v; int vl; if (!find_attr(attrs, attrlen, "id", &v, &vl)    || !attr_eq(v, vl, s->id))     return 0; }
    if (s->attr[0]) {                                       /* [attr] presence, or [attr OP value] value match (M1793) */
        if (!has_attr(attrs, attrlen, s->attr)) return 0;
        if (s->aop) { const char *v; int vl; if (!find_attr(attrs, attrlen, s->attr, &v, &vl) || !attr_val_match(v, vl, s->aval, s->aop)) return 0; }
    }
    if (s->dcls[0] || s->dtag[0]) {                          /* descendant selector: some ancestor frame must match (M1434) */
        int found = 0;
        for (int f = 0; f < b->sc_sp; f++) {
            if (s->dcls[0]) { int cl = 0; while (b->sc[f].cls[cl]) cl++; if (cl && class_has_all(b->sc[f].cls, cl, s->dcls)) { found = 1; break; } }   /* M1775: compound-class ancestor */
            else if (tageq(b->sc[f].tag, s->dtag)) { found = 1; break; }
        }
        if (!found) return 0;
    }
    return 1;
}
/* Cascade the captured <style> rules onto one element: per-property specificity ordering
 * (M1439) — for each output property, the matching rule with the HIGHEST specificity wins;
 * ties are broken by source order (later wins, i.e. >= overwrites). Returns 1 if any rule
 * matched. Matching mirrors sel_match_all's per-element checks. */
static int css_match(browser_t *b, const char *tag, const char *attrs, int attrlen,
                     uint32_t *color, int *textstyle, int *underline, int *transform, uint32_t *bg,
                     int *align, int *size, int *hidden, int *margin, int *indent, uint32_t *border, int *flex,
                     int *lineheight, int *ws, int *cwidth, int *cmauto,
                     int *cpl, int *cpr, int *cpt, int *cpb, int *cheight) {
    int hit = 0;
    /* per-property specificity watermarks: each output property is set only when the rule's
     * specificity >= the watermark for that property (ties go to source order = later wins). */
    uint32_t sp_color=0, sp_style=0, sp_ul=0, sp_tr=0, sp_bg=0, sp_al=0, sp_sz=0,
             sp_dn=0, sp_mg=0, sp_in=0, sp_bd=0, sp_lh=0, sp_ws=0,
             /* Box geometry needs its OWN watermarks (M1932). Sharing sp_mg/sp_in and
              * never updating them broke the cascade both ways: a later low-specificity
              * `div{width:200px}` overwrote `#hero{width:800px}`, and an unrelated
              * `.box{margin-top:10px}` raised sp_mg enough to silently DROP a `div`
              * width rule. All four padding sides share one watermark and one
              * importance bit, because `padding:` is a single shorthand. */
             sp_w=0, sp_ma=0, sp_pad=0, sp_h=0;
    for (int r = 0; r < b->n_css; r++) {
        if (!css_rule_matches(b, r, tag, attrs, attrlen)) continue;
        uint32_t sp = b->css_spec[r]; uint16_t imp = b->css_imp[r];   /* M1788: priority = (this property is !important)<<16 | specificity, so any !important decl beats any normal one */
        #define PRI(bit) ((((uint32_t)(imp>>(bit))&1u) << 16) | sp)
        if (b->css_color[r]   && PRI(0) >= sp_color)   { *color      = b->css_color[r];       sp_color = PRI(0); }
        if (b->css_style[r] >= 0 && PRI(1) >= sp_style) { *textstyle = b->css_style[r];       sp_style = PRI(1); }
        if (b->css_ul[r]      && PRI(2) >= sp_ul)       { *underline  = b->css_ul[r];          sp_ul    = PRI(2); }
        if (b->css_transform[r] && PRI(3) >= sp_tr)     { *transform  = b->css_transform[r];  sp_tr    = PRI(3); }
        if (b->css_bg[r]      && PRI(4) >= sp_bg)       { *bg         = b->css_bg[r];         sp_bg    = PRI(4); }
        if (b->css_align[r]   && PRI(5) >= sp_al)       { *align      = b->css_align[r];      sp_al    = PRI(5); }
        if (b->css_size[r]    && PRI(6) >= sp_sz)       { *size       = b->css_size[r];       sp_sz    = PRI(6); }
        if (b->css_disp[r]    && PRI(7) >= sp_dn) {
            *hidden = (b->css_disp[r] == 1);          /* M1789: the display slot is exclusive — a winning */
            *flex   = (b->css_disp[r] == 2);          /* display value clears the loser (else a lower-priority */
            sp_dn = PRI(7);                           /* display:none left *hidden=1 even when display:flex later won) */
        }
        if (b->css_margin[r]  && PRI(8) >= sp_mg)       { *margin     = b->css_margin[r];     sp_mg    = PRI(8); }
        if (b->css_indent[r]  && PRI(9) >= sp_in)       { *indent     = b->css_indent[r];     sp_in    = PRI(9); }
        if (b->css_border[r]  && PRI(10) >= sp_bd)      { *border     = b->css_border[r];     sp_bd    = PRI(10); }
        if (b->css_lineheight[r] && PRI(12) >= sp_lh)   { *lineheight = b->css_lineheight[r]; sp_lh    = PRI(12); }
        if (b->css_ws[r]      && PRI(13) >= sp_ws)      { *ws         = b->css_ws[r];         sp_ws    = PRI(13); }
        /* Box geometry: own watermarks, own importance bits (M1932). */
        if (b->css_w[r]       && PRI(14) >= sp_w)       { *cwidth     = b->css_w[r];     sp_w   = PRI(14); }
        if (b->css_mauto[r]   && PRI(9)  >= sp_ma)      { *cmauto     = b->css_mauto[r]; sp_ma  = PRI(9); }
        if (b->css_h[r]       && PRI(15) >= sp_h)       { *cheight    = b->css_h[r];     sp_h   = PRI(15); }
        if ((b->css_padl[r] || b->css_padr[r] || b->css_padt[r] || b->css_padb[r])
            && PRI(8) >= sp_pad) {                       /* one shorthand -> one watermark */
            *cpl = b->css_padl[r]; *cpr = b->css_padr[r];
            *cpt = b->css_padt[r]; *cpb = b->css_padb[r];
            sp_pad = PRI(8);
        }
        #undef PRI
        hit = 1;
    }
    return hit;
}
/* list-style-type from the <style> rules for one <ul>/<ol> element (0 = none set).
 * Kept separate from css_match so the marker is resolved only at the two list-open
 * sites. Per-property specificity ordering applied (M1439): highest-specificity matching
 * rule wins; ties broken by source order. */
static int css_match_list(browser_t *b, const char *tag, const char *attrs, int attrlen) {
    int mark = 0;
    uint32_t sp_list = 0;
    for (int r = 0; r < b->n_css; r++) {
        if (!b->css_list[r]) continue;
        if (!css_rule_matches(b, r, tag, attrs, attrlen)) continue;
        uint32_t pri = ((((uint32_t)b->css_imp[r]>>11)&1u) << 16) | b->css_spec[r];   /* M1788: !important list-style */
        if (pri >= sp_list) { mark = b->css_list[r]; sp_list = pri; }
    }
    return mark;
}
/* Scan the body region for elements matching `sel`; fill offs[] with the byte
 * offset of each matching opening '<'. Returns the count (bounded by max). */
static int sel_match_all(browser_t *b, const sel_t *sel, int *offs, int max) {
    const char *body = b->raw; int lo = b->bodyoff, hi = b->bodyoff + b->bodylen;
    int n = 0;
    for (int i = lo; i < hi && n < max; i++) {
        if (body[i] != '<') continue;
        int j = i + 1;
        if (j>=hi || body[j]=='/' || body[j]=='!' || body[j]=='?') continue;   /* closing tag / comment / decl */
        char tag[16]; int tl = 0;
        while (j<hi && tl<15) { char c=body[j]; if(c=='>'||c==' '||c=='/'||c=='\t'||c=='\n') break; tag[tl++]=(char)lc(c); j++; }
        tag[tl]=0; if (tl==0) continue;
        int astart = j; char q=0;                                   /* quote-aware scan to '>' (mirrors parse_html) */
        while (j<hi) { char c=body[j]; if(q){if(c==q)q=0;} else if(c=='"'||c=='\'')q=c; else if(c=='>')break; j++; }
        int alen = j - astart;
        if (tageq(tag,"script") || tageq(tag,"style")) {   /* raw-text elements: skip their content so tag-like TEXT inside (e.g. "<li class=\"x\">" in a script string) isn't matched */
            int e = j + 1, found = 0;
            while (e + 2 + tl <= hi) {
                if (body[e]=='<' && body[e+1]=='/') { int m=0; while (m<tl && lc(body[e+2+m])==tag[m]) m++; if (m==tl) { found=1; break; } }
                e++;
            }
            i = found ? e : hi;   /* resume at the </tag> (for-loop i++ steps past its '<'); to end if unclosed */
            continue;
        }
        if (sel->tag[0] && !tageq(tag, sel->tag)) { i=j; continue; }
        if (sel->cls[0]) { const char *v; int vl; if(!find_attr(body+astart,alen,"class",&v,&vl) || !class_has_all(v,vl,sel->cls)) { i=j; continue; } }   /* M1775: compound classes */
        if (sel->id[0])  { const char *v; int vl; if(!find_attr(body+astart,alen,"id",&v,&vl)    || !attr_eq(v,vl,sel->id))     { i=j; continue; } }
        if (sel->attr[0]) {   /* [attr] presence, or [attr OP value] value match (M1793) */
            if (!has_attr(body+astart,alen,sel->attr)) { i=j; continue; }
            if (sel->aop) { const char *av2; int al2; if (!find_attr(body+astart,alen,sel->attr,&av2,&al2) || !attr_val_match(av2,al2,sel->aval,sel->aop)) { i=j; continue; } }
        }
        offs[n++] = i;          /* matched: record the '<' offset */
        i = j;                  /* advance past this opening tag (children are still scanned) */
    }
    return n;
}
/* Position variant of dom_find: the element whose opening '<' is at byte `off`.
 * Validates `off` is a real in-body opening tag (so a stale offset fails closed),
 * then returns INNER's [*is,*ie) via the same depth-count as dom_find. */
static int dom_find_at(browser_t *b, int off, int *is, int *ie) {
    const char *r = b->raw; int lo = b->bodyoff, hi = b->bodyoff + b->bodylen;
    if (off < lo || off >= hi - 1 || r[off] != '<' || !dom_alnum(r[off+1])) return 0;   /* `off >= hi-1` (not `off+1 >= hi`) so off==INT_MAX can't overflow past the guard */
    char tag[16]; int tn = 0, ne = off + 1;
    while (ne < hi && dom_alnum(r[ne]) && tn < 15) tag[tn++] = r[ne++];
    if (tn == 0) return 0;
    int gt = off; while (gt < hi && r[gt] != '>') gt++;
    if (gt >= hi) return 0;
    int istart = gt + 1, depth = 1, p = istart;
    while (p < hi) {
        if (r[p] == '<') {
            if (p+2+tn <= hi && r[p+1]=='/' && memcmp(r+p+2, tag, tn)==0) { if(--depth==0){ *is=istart; *ie=p; return 1; } }
            else if (p+1+tn < hi && memcmp(r+p+1, tag, tn)==0 && (r[p+1+tn]==' '||r[p+1+tn]=='>'||r[p+1+tn]=='/')) depth++;
        }
        p++;
    }
    return 0;
}
/* Resolve the id="" of the element whose opening '<' is at byte `off` into idbuf
 * (NUL-terminated). Returns 1 only on a non-empty id — the .value/.checked store is
 * id-keyed (see in_set / the input renderer at idbuf), so an id-less element can't
 * be addressed there at all. Lets a position handle (querySelector) reach that store. */
static int dom_id_at(browser_t *b, int off, char *idbuf, int max) {
    if (max) idbuf[0] = 0;
    int as, ae; if (!dom_attr_region_at(b, off, &as, &ae)) return 0;
    const char *v; int vl;
    if (!find_attr(b->raw + as, ae - as, "id", &v, &vl)) return 0;
    int n = vl; if (n > max - 1) n = max - 1; if (n < 0) n = 0;
    memcpy(idbuf, v, n); idbuf[n] = 0; return idbuf[0] != 0;
}
/* Read a position-addressed element's textContent/innerHTML (html 0/1), or — for
 * .value (html 2) / .checked (html 4) — resolve the element's id and delegate to the
 * id-keyed store, so `document.querySelector('input').value` works, not just
 * getElementById. (An id-less match still can't be tracked; the store has no key.) */
static int browser_dom_get_at(int off, char *out, int max, int html) {
    browser_t *b = g_ls_b; if (max) out[0] = 0; if (!b) return 0;
    if (html == 2 || html == 4) {
        char idbuf[32];
        if (!dom_id_at(b, off, idbuf, sizeof idbuf)) return 0;   /* no id -> untracked (matches the renderer) */
        return browser_dom_get(idbuf, out, max, html);
    }
    int is, ie; if (!dom_find_at(b, off, &is, &ie)) return 0;
    int len = ie - is; if (len > max - 1) len = max - 1; if (len < 0) len = 0;
    memcpy(out, b->raw + is, len); out[len] = 0; return 1;
}
/* Position variant of dom_attr_region: the opening-tag attr span of the element at `off`. */
static int dom_attr_region_at(browser_t *b, int off, int *as, int *ae) {
    const char *r = b->raw; int lo = b->bodyoff, hi = b->bodyoff + b->bodylen;
    if (off < lo || off >= hi - 1 || r[off] != '<' || !dom_alnum(r[off+1])) return 0;   /* `off >= hi-1` (not `off+1 >= hi`) so off==INT_MAX can't overflow past the guard */
    int ne = off + 1, tn = 0;
    while (ne < hi && dom_alnum(r[ne]) && tn < 15) { ne++; tn++; }   /* skip the tag name */
    if (tn == 0) return 0;
    int gt = off; while (gt < hi && r[gt] != '>') gt++;
    if (gt >= hi) return 0;
    *as = ne; *ae = gt; return 1;
}
/* getAttribute on a position-addressed element (read-only; mirrors browser_dom_getattr). */
static int browser_dom_getattr_at(int off, const char *attr, char *out, int max) {
    browser_t *b = g_ls_b; if (!b || max <= 0) return 0; out[0] = 0;
    int as, ae; if (!dom_attr_region_at(b, off, &as, &ae)) return 0;
    const char *v; int vl;
    if (!find_attr(b->raw + as, ae - as, attr, &v, &vl)) return 0;
    int n = vl; if (n > max - 1) n = max - 1; if (n < 0) n = 0;
    memcpy(out, v, n); out[n] = 0; return 1;
}
/* document.querySelector(All): parse the selector, scan, fill offs[] with match offsets. */
static int browser_dom_query(const char *sel, int *offs, int max) {
    browser_t *b = g_ls_b; if (!b) return 0;
    sel_t s; if (!sel_parse(sel, &s)) return 0;
    int m = (max < QSA_MAX) ? max : QSA_MAX;
    return sel_match_all(b, &s, offs, m);
}
static int dom_attr_region(browser_t *b, const char *id, int *as, int *ae);   /* fwd (defined below, near browser_dom_getattr) */
/* element.matches(sel): does the element whose opening '<' is at byte `off` match
 * the selector? Reuses the (reviewed) matcher — run it and test membership. */
static int browser_dom_matches_at(int off, const char *sel) {
    browser_t *b = g_ls_b; if (!b) return 0;
    sel_t s; if (!sel_parse(sel, &s)) return 0;
    int offs[QSA_MAX]; int n = sel_match_all(b, &s, offs, QSA_MAX);
    for (int i = 0; i < n; i++) if (offs[i] == off) return 1;
    return 0;
}
/* matches() for an id handle: locate the element's opening '<', then reuse the above. */
static int browser_dom_matches(const char *id, const char *sel) {
    browser_t *b = g_ls_b; if (!b) return 0;
    int as, ae; if (!dom_attr_region(b, id, &as, &ae)) return 0;   /* finds the element by id */
    const char *r = b->raw; int lo = b->bodyoff, off = as;
    while (off > lo && r[off] != '<') off--;
    if (r[off] != '<') return 0;
    return browser_dom_matches_at(off, sel);
}
/* element.closest(sel): the innermost element matching `sel` that is `off`'s self
 * or an ancestor — returns its byte offset, or -1. Forward approach (no backward
 * nesting scan): among the selector's matches, pick the largest offset that is
 * `off` itself or whose inner span [is,ie) ENCLOSES off (so it's an ancestor). */
static int browser_dom_closest_at(int off, const char *sel) {
    browser_t *b = g_ls_b; if (!b) return -1;
    sel_t s; if (!sel_parse(sel, &s)) return -1;
    int offs[QSA_MAX]; int n = sel_match_all(b, &s, offs, QSA_MAX);
    int best = -1;
    for (int i = 0; i < n; i++) {
        int o = offs[i];
        if (o == off) { if (o > best) best = o; }                          /* the element itself matches */
        else if (o < off) { int is, ie; if (dom_find_at(b, o, &is, &ie) && off >= is && off < ie && o > best) best = o; }   /* o encloses off -> ancestor */
    }
    return best;
}
static int browser_dom_closest(const char *id, const char *sel) {
    browser_t *b = g_ls_b; if (!b) return -1;
    int as, ae; if (!dom_attr_region(b, id, &as, &ae)) return -1;
    const char *r = b->raw; int lo = b->bodyoff, off = as;
    while (off > lo && r[off] != '<') off--;
    if (r[off] != '<') return -1;
    return browser_dom_closest_at(off, sel);
}
/* element.children: the byte offsets of the DIRECT child elements of the element
 * at `off`. Scans the inner span for top-level open tags, skipping each child's
 * own subtree (via dom_find_at) so descendants aren't counted. */
static int browser_dom_children_at(int off, int *offs, int max) {
    browser_t *b = g_ls_b; if (!b) return 0;
    int is, ie; if (!dom_find_at(b, off, &is, &ie)) return 0;   /* parent's inner span */
    const char *body = b->raw; int n = 0;
    for (int i = is; i < ie && n < max; ) {
        if (body[i] != '<') { i++; continue; }
        int j = i + 1;
        if (j >= ie || body[j]=='/' || body[j]=='!' || body[j]=='?') { i++; continue; }   /* not an opening tag */
        offs[n++] = i;                                  /* a direct child */
        int cis, cie, e;
        if (dom_find_at(b, i, &cis, &cie)) { e = cie; while (e < ie && body[e] != '>') e++; }   /* skip the child's whole element */
        else { e = i; while (e < ie && body[e] != '>') e++; }                                   /* void/self-closing: just past its '>' */
        i = (e < ie) ? e + 1 : ie;
    }
    return n;
}
static int browser_dom_children(const char *id, int *offs, int max) {
    browser_t *b = g_ls_b; if (!b) return 0;
    int as, ae; if (!dom_attr_region(b, id, &as, &ae)) return 0;
    const char *r = b->raw; int lo = b->bodyoff, off = as;
    while (off > lo && r[off] != '<') off--;
    if (r[off] != '<') return 0;
    return browser_dom_children_at(off, offs, max);
}
/* element.parentElement: the byte offset of the innermost element that ENCLOSES
 * the element at `off` (its immediate parent), or -1. Forward scan: the largest
 * offset < off whose inner span [is,ie) contains off. */
static int browser_dom_parent_at(int off) {
    browser_t *b = g_ls_b; if (!b) return -1;
    const char *body = b->raw; int lo = b->bodyoff, hi = b->bodyoff + b->bodylen;
    int best = -1;
    for (int i = lo; i < off && i < hi; i++) {
        if (body[i] != '<') continue;
        int j = i + 1;
        if (j >= hi || !dom_alnum(body[j])) continue;   /* an opening tag */
        int is, ie; if (dom_find_at(b, i, &is, &ie) && off >= is && off < ie && i > best) best = i;   /* i encloses off */
    }
    return best;
}
static int browser_dom_parent(const char *id) {
    browser_t *b = g_ls_b; if (!b) return -1;
    int as, ae; if (!dom_attr_region(b, id, &as, &ae)) return -1;
    const char *r = b->raw; int lo = b->bodyoff, off = as;
    while (off > lo && r[off] != '<') off--;
    if (r[off] != '<') return -1;
    return browser_dom_parent_at(off);
}
/* element.nextElementSibling / previousElementSibling: among the element's
 * siblings (the top-level children of its parent, or top-level body elements),
 * the nearest one after (*next) / before (*prev) it. One scan of the sibling range. */
static void browser_dom_siblings_at(int off, int *prev, int *next) {
    *prev = -1; *next = -1;
    browser_t *b = g_ls_b; if (!b) return;
    int lo, hi, parent = browser_dom_parent_at(off);
    if (parent >= 0) { int is, ie; if (!dom_find_at(b, parent, &is, &ie)) return; lo = is; hi = ie; }
    else { lo = b->bodyoff; hi = b->bodyoff + b->bodylen; }   /* top-level: siblings are body-level elements */
    const char *body = b->raw;
    for (int i = lo; i < hi; ) {
        if (body[i] != '<') { i++; continue; }
        int j = i + 1;
        if (j >= hi || body[j]=='/' || body[j]=='!' || body[j]=='?' || !dom_alnum(body[j])) { i++; continue; }
        if (i < off) { if (i > *prev) *prev = i; }              /* a sibling before off */
        else if (i > off && *next < 0) *next = i;               /* the first sibling after off */
        int cis, cie, e;
        if (dom_find_at(b, i, &cis, &cie)) { e = cie; while (e < hi && body[e] != '>') e++; }
        else { e = i; while (e < hi && body[e] != '>') e++; }
        i = (e < hi) ? e + 1 : hi;                              /* skip this sibling's whole element */
    }
}
static int browser_dom_sibling_at(int off, int dir) {   /* dir<0 = previous, else = next; returns offset or -1 */
    int prev, next; browser_dom_siblings_at(off, &prev, &next);
    return dir < 0 ? prev : next;
}
static int browser_dom_sibling(const char *id, int dir) {
    browser_t *b = g_ls_b; if (!b) return -1;
    int as, ae; if (!dom_attr_region(b, id, &as, &ae)) return -1;
    const char *r = b->raw; int lo = b->bodyoff, off = as;
    while (off > lo && r[off] != '<') off--;
    if (r[off] != '<') return -1;
    return browser_dom_sibling_at(off, dir);
}
/* element.tagName / nodeName: the element's tag name, UPPERCASED (per the DOM). */
static int browser_dom_tag_at(int off, char *out, int max) {
    browser_t *b = g_ls_b; if (max <= 0) return 0; out[0] = 0; if (!b) return 0;
    const char *r = b->raw; int hi = b->bodyoff + b->bodylen;
    if (off < b->bodyoff || off+1 >= hi || r[off] != '<' || !dom_alnum(r[off+1])) return 0;
    int p = off+1, o = 0;
    while (p < hi && dom_alnum(r[p]) && o < max-1) { char c = r[p++]; out[o++] = (c >= 'a' && c <= 'z') ? c - 32 : c; }
    out[o] = 0; return o > 0;
}
static int browser_dom_tag(const char *id, char *out, int max) {
    browser_t *b = g_ls_b; if (max <= 0) return 0; out[0] = 0; if (!b) return 0;
    int as, ae; if (!dom_attr_region(b, id, &as, &ae)) return 0;
    const char *r = b->raw; int lo = b->bodyoff, off = as;
    while (off > lo && r[off] != '<') off--;
    if (r[off] != '<') return 0;
    return browser_dom_tag_at(off, out, max);
}
/* <input> field values, keyed by id (the typed or scripted .value text) */
static const char *in_get(browser_t *b, const char *id) {
    for (int i = 0; i < b->in_n; i++) if (streqs(b->in_id[i], id)) return b->in_val[i];
    return 0;
}
static void in_set(browser_t *b, const char *id, const char *val) {
    int i; for (i = 0; i < b->in_n; i++) if (streqs(b->in_id[i], id)) break;
    if (i == b->in_n) { if (b->in_n >= IN_MAX || !id[0]) return; int j=0; while(id[j]&&j<31){b->in_id[i][j]=id[j];j++;} b->in_id[i][j]=0; b->in_name[i][0]=0; b->in_n++; }
    int j=0; while(val[j]&&j<IN_VLEN-1){b->in_val[i][j]=val[j];j++;} b->in_val[i][j]=0;
}
/* Record a field's name= (for GET submit) in the slot already created for its id. */
static void in_name_set(browser_t *b, const char *id, const char *name) {
    for (int i = 0; i < b->in_n; i++) if (streqs(b->in_id[i], id)) {
        int j=0; while(name[j]&&j<31){b->in_name[i][j]=name[j];j++;} b->in_name[i][j]=0; return;
    }
}
static int browser_dom_get(const char *id, char *out, int max, int html) {
    if (max) out[0] = 0;
    if (!g_ls_b) return 0;
    if (html == 2) {   /* element.value -> the input field's stored text */
        const char *v = in_get(g_ls_b, id); if (!v) return 0;
        int i = 0; while (v[i] && i < max - 1) { out[i] = v[i]; i++; } out[i] = 0; return 1;
    }
    if (html == 4) {   /* element.checked -> "1"/"0" from the checkbox/radio store ("on") */
        const char *v = in_get(g_ls_b, id);
        if (max) { out[0] = (v && streqs(v, "on")) ? '1' : '0'; if (max > 1) out[1] = 0; }
        return 1;
    }
    int is, ie; if (!dom_find(g_ls_b, id, &is, &ie)) return 0;
    int len = ie - is; if (len > max - 1) len = max - 1; if (len < 0) len = 0;
    memcpy(out, g_ls_b->raw + is, len); out[len] = 0; return 1;
}
static void browser_dom_set(const char *id, const char *value, int html) {
    browser_t *b = g_ls_b; if (!b) return;
    if (html == 2) { in_set(b, id, value); parse_html(b, b->raw + b->bodyoff, b->bodylen); return; }   /* element.value = … */
    if (html == 4) {   /* element.checked = truthy -> store "on"/"" so the box renders [x] + submits name=on */
        int on = value[0] && !streqs(value, "false") && !streqs(value, "0");
        in_set(b, id, on ? "on" : "");
        parse_html(b, b->raw + b->bodyoff, b->bodylen);
        return;
    }
    if (html == 3) {   /* element.remove(): splice the whole <tag id>…</tag> out of b->raw (full-span variant of the set below) */
        int is, ie; if (!dom_find(b, id, &is, &ie)) return;
        const char *r = b->raw; int lo = b->bodyoff;
        int ts = is - 1; while (ts > lo && r[ts] != '<') ts--; if (r[ts] != '<') return;   /* opening '<' */
        int bodyend = b->bodyoff + b->bodylen;
        int ce = ie; while (ce < bodyend && r[ce] != '>') ce++; if (ce >= bodyend) return; ce++;   /* past the closing '>' */
        int delta = -(ce - ts);                                   /* removing [ts, ce) */
        int active = (g_sw_raw == b->raw);
        int live_end = (active && g_sw_pos > bodyend) ? g_sw_pos : bodyend;
        memmove(b->raw + ts, b->raw + ce, live_end - ce);         /* shift the tail down over the removed element */
        b->bodylen += delta;
        if (active) { if (g_sw_pos > ts) g_sw_pos += delta; if (g_sw_base > ts) g_sw_base += delta; }   /* sync document.write cursors; pivot on ts (removed-span start) so both shift together */
        b->raw[live_end + delta] = 0;
        parse_html(b, b->raw + b->bodyoff, b->bodylen);
        return;
    }
    static char esc[8192];
    if (!html) {   /* textContent: HTML-escape so the text isn't interpreted as markup (innerHTML inserts raw) */
        int o = 0;
        for (int i = 0; value[i] && o < (int)sizeof(esc) - 7; i++) {
            char c = value[i];
            if (c=='<')      { memcpy(esc+o, "&lt;", 4); o += 4; }
            else if (c=='>') { memcpy(esc+o, "&gt;", 4); o += 4; }
            else if (c=='&') { memcpy(esc+o, "&amp;", 5); o += 5; }
            else esc[o++] = c;
        }
        esc[o] = 0; value = esc;
    }
    int is, ie; if (!dom_find(b, id, &is, &ie)) return;
    int vlen = 0; while (value[vlen]) vlen++;
    int delta = vlen - (ie - is);
    int active = (g_sw_raw == b->raw);                         /* a script's document.write is appending here */
    int bodyend = b->bodyoff + b->bodylen;
    int live_end = (active && g_sw_pos > bodyend) ? g_sw_pos : bodyend;   /* include any document.write'd bytes */
    if (live_end + delta >= RAW_MAX - 1 || live_end + delta < b->bodyoff) return;   /* out of room */
    memmove(b->raw + ie + delta, b->raw + ie, live_end - ie);  /* shift the tail (incl. document.write appends) */
    memcpy(b->raw + is, value, vlen);                          /* splice in the new content */
    b->bodylen += delta;
    if (active) { if (g_sw_pos > ie) g_sw_pos += delta; if (g_sw_base > ie) g_sw_base += delta; }   /* keep cursors in sync */
    b->raw[live_end + delta] = 0;
    parse_html(b, b->raw + b->bodyoff, b->bodylen);            /* re-render the page in place */
}
/* Locate the attribute span of the element with this id: [*as, *ae) is the text
 * between the tag name and the opening tag's '>'. Mirrors dom_find's tag locate. */
static int dom_attr_region(browser_t *b, const char *id, int *as, int *ae) {
    const char *r = b->raw; int lo = b->bodyoff, hi = b->bodyoff + b->bodylen;
    int idlen = 0; while (id[idlen]) idlen++;
    if (idlen == 0) return 0;
    for (int i = lo; i + 4 < hi; i++) {
        if (!(r[i]=='i' && r[i+1]=='d' && r[i+2]=='=' && (r[i+3]=='"' || r[i+3]=='\''))) continue;
        char q = r[i+3]; int vs = i + 4, k = 0;
        while (k < idlen && vs + k < hi && r[vs+k] == id[k]) k++;
        if (!(k == idlen && vs + k < hi && r[vs+k] == q)) continue;   /* whole attr value must equal id */
        int ts = i; while (ts > lo && r[ts] != '<') ts--;             /* back up to the opening '<' */
        if (r[ts] != '<') continue;
        int ne = ts + 1, tn = 0;
        while (ne < hi && dom_alnum(r[ne]) && tn < 15) { ne++; tn++; }  /* skip the tag name */
        if (tn == 0) continue;
        int gt = i; while (gt < hi && r[gt] != '>') gt++;             /* end of the opening tag */
        if (gt >= hi) return 0;
        *as = ne; *ae = gt; return 1;
    }
    return 0;
}
/* getAttribute(id, attr): read the named attribute off the element's opening tag. */
static int browser_dom_getattr(const char *id, const char *attr, char *out, int max) {
    browser_t *b = g_ls_b; if (!b || max <= 0) return 0; out[0] = 0;
    int as, ae; if (!dom_attr_region(b, id, &as, &ae)) return 0;
    const char *v; int vl;
    if (!find_attr(b->raw + as, ae - as, attr, &v, &vl)) return 0;
    int n = vl; if (n > max - 1) n = max - 1; if (n < 0) n = 0;
    memcpy(out, v, n); out[n] = 0; return 1;
}
/* setAttribute(id, attr, val): replace the attribute's value on the element's
 * opening tag (or insert the attribute if absent), then re-render. The splice
 * mirrors browser_dom_set; the value has quotes stripped so it can't break out. */
static void browser_dom_setattr(const char *id, const char *attr, const char *val) {
    browser_t *b = g_ls_b; if (!b || !attr[0]) return;   /* an empty attribute name is a no-op */
    int as, ae; if (!dom_attr_region(b, id, &as, &ae)) return;
    char vbuf[256]; int vlen = 0;                                 /* sanitized value (no quotes) */
    for (int i = 0; val[i] && vlen < (int)sizeof(vbuf) - 1; i++) { char c = val[i]; if (c != '"' && c != '\'') vbuf[vlen++] = c; }
    vbuf[vlen] = 0;
    const char *fv; int fvl;
    int rs, rend; const char *repl; int rlen; char ins[384];
    if (find_attr(b->raw + as, ae - as, attr, &fv, &fvl)) {        /* attr exists: replace its value (between quotes) */
        rs = (int)(fv - b->raw); rend = rs + fvl; repl = vbuf; rlen = vlen;
    } else {                                                       /* attr absent: insert ` attr="val"` before '>' */
        int p = 0; ins[p++] = ' ';
        for (int i = 0; attr[i] && p < 80; i++) { char c = attr[i]; if (c=='"'||c=='\''||c=='='||c==' '||c=='<'||c=='>'||c=='/') continue; ins[p++] = c; }
        ins[p++] = '='; ins[p++] = '"';
        for (int i = 0; i < vlen && p < 380; i++) ins[p++] = vbuf[i];
        ins[p++] = '"'; ins[p] = 0;
        rs = ae; rend = ae; repl = ins; rlen = p;
    }
    int delta = rlen - (rend - rs);
    int active = (g_sw_raw == b->raw);
    int bodyend = b->bodyoff + b->bodylen;
    int live_end = (active && g_sw_pos > bodyend) ? g_sw_pos : bodyend;
    if (live_end + delta >= RAW_MAX - 1 || live_end + delta < b->bodyoff) return;   /* out of room */
    memmove(b->raw + rend + delta, b->raw + rend, live_end - rend);   /* shift the tail */
    memcpy(b->raw + rs, repl, rlen);                                  /* write the new attr/value */
    b->bodylen += delta;
    if (active) { if (g_sw_pos > rend) g_sw_pos += delta; if (g_sw_base > rend) g_sw_base += delta; }
    b->raw[live_end + delta] = 0;
    parse_html(b, b->raw + b->bodyoff, b->bodylen);
}
/* Position-keyed write: textContent/innerHTML (html 0/1) and remove (html 3) on
 * the element whose opening '<' is at byte `off`. Duplicates browser_dom_set's
 * splice with dom_find_at in place of dom_find (the id path stays untouched).
 * NOTE: after a splice + re-render, the offsets of LATER elements shift, so a
 * second position handle into the same page is stale; dom_find_at re-validates
 * '<' at off, so a stale write fails closed (no-op) or edits a still-valid '<' —
 * always within bounds (memory-safe). Single-match writes are exact. */
static void browser_dom_set_at(int off, const char *value, int html) {
    browser_t *b = g_ls_b; if (!b) return;
    if (html == 2 || html == 4) {         /* .value/.checked: resolve the element's id and delegate to the id-keyed
                                           * store (so `querySelector('input').value = x` writes, not just by-id) */
        char idbuf[32];
        if (!dom_id_at(b, off, idbuf, sizeof idbuf)) return;   /* no id -> untracked (matches the renderer) */
        browser_dom_set(idbuf, value, html);
        return;
    }
    if (html == 3) {         /* remove(): off IS the opening '<'; splice [off, past-close) */
        int is, ie; if (!dom_find_at(b, off, &is, &ie)) return;
        const char *r = b->raw; int bodyend = b->bodyoff + b->bodylen;
        int ts = off;
        int ce = ie; while (ce < bodyend && r[ce] != '>') ce++; if (ce >= bodyend) return; ce++;
        int delta = -(ce - ts);
        int active = (g_sw_raw == b->raw);
        int live_end = (active && g_sw_pos > bodyend) ? g_sw_pos : bodyend;
        memmove(b->raw + ts, b->raw + ce, live_end - ce);
        b->bodylen += delta;
        if (active) { if (g_sw_pos > ts) g_sw_pos += delta; if (g_sw_base > ts) g_sw_base += delta; }
        b->raw[live_end + delta] = 0;
        parse_html(b, b->raw + b->bodyoff, b->bodylen);
        return;
    }
    static char esc[8192];
    if (!html) {   /* textContent: HTML-escape (innerHTML inserts raw) — same as browser_dom_set */
        int o = 0;
        for (int i = 0; value[i] && o < (int)sizeof(esc) - 7; i++) {
            char c = value[i];
            if (c=='<')      { memcpy(esc+o, "&lt;", 4); o += 4; }
            else if (c=='>') { memcpy(esc+o, "&gt;", 4); o += 4; }
            else if (c=='&') { memcpy(esc+o, "&amp;", 5); o += 5; }
            else esc[o++] = c;
        }
        esc[o] = 0; value = esc;
    }
    int is, ie; if (!dom_find_at(b, off, &is, &ie)) return;
    int vlen = 0; while (value[vlen]) vlen++;
    int delta = vlen - (ie - is);
    int active = (g_sw_raw == b->raw);
    int bodyend = b->bodyoff + b->bodylen;
    int live_end = (active && g_sw_pos > bodyend) ? g_sw_pos : bodyend;
    if (live_end + delta >= RAW_MAX - 1 || live_end + delta < b->bodyoff) return;
    memmove(b->raw + ie + delta, b->raw + ie, live_end - ie);
    memcpy(b->raw + is, value, vlen);
    b->bodylen += delta;
    if (active) { if (g_sw_pos > ie) g_sw_pos += delta; if (g_sw_base > ie) g_sw_base += delta; }
    b->raw[live_end + delta] = 0;
    parse_html(b, b->raw + b->bodyoff, b->bodylen);
}
/* Position-keyed setAttribute: duplicates browser_dom_setattr with dom_attr_region_at. */
static void browser_dom_setattr_at(int off, const char *attr, const char *val) {
    browser_t *b = g_ls_b; if (!b || !attr[0]) return;
    int as, ae; if (!dom_attr_region_at(b, off, &as, &ae)) return;
    char vbuf[256]; int vlen = 0;
    for (int i = 0; val[i] && vlen < (int)sizeof(vbuf) - 1; i++) { char c = val[i]; if (c != '"' && c != '\'') vbuf[vlen++] = c; }
    vbuf[vlen] = 0;
    const char *fv; int fvl;
    int rs, rend; const char *repl; int rlen; char ins[384];
    if (find_attr(b->raw + as, ae - as, attr, &fv, &fvl)) {
        rs = (int)(fv - b->raw); rend = rs + fvl; repl = vbuf; rlen = vlen;
    } else {
        int p = 0; ins[p++] = ' ';
        for (int i = 0; attr[i] && p < 80; i++) { char c = attr[i]; if (c=='"'||c=='\''||c=='='||c==' '||c=='<'||c=='>'||c=='/') continue; ins[p++] = c; }
        ins[p++] = '='; ins[p++] = '"';
        for (int i = 0; i < vlen && p < 380; i++) ins[p++] = vbuf[i];
        ins[p++] = '"'; ins[p] = 0;
        rs = ae; rend = ae; repl = ins; rlen = p;
    }
    int delta = rlen - (rend - rs);
    int active = (g_sw_raw == b->raw);
    int bodyend = b->bodyoff + b->bodylen;
    int live_end = (active && g_sw_pos > bodyend) ? g_sw_pos : bodyend;
    if (live_end + delta >= RAW_MAX - 1 || live_end + delta < b->bodyoff) return;
    memmove(b->raw + rend + delta, b->raw + rend, live_end - rend);
    memcpy(b->raw + rs, repl, rlen);
    b->bodylen += delta;
    if (active) { if (g_sw_pos > rend) g_sw_pos += delta; if (g_sw_base > rend) g_sw_base += delta; }
    b->raw[live_end + delta] = 0;
    parse_html(b, b->raw + b->bodyoff, b->bodylen);
}
/* Find the full " attr[=value]" span (incl one leading space) within the opening-tag
 * attr region [as,ae), for removeAttribute. Returns 1 + [*rs,*rend). */
static int attr_span(browser_t *b, int as, int ae, const char *attr, int *rs, int *rend) {
    const char *a = b->raw; int nl=0; while(attr[nl]) nl++; if(!nl) return 0;
    for (int i = as; i + nl <= ae; i++) {
        if (i>as && a[i-1]!=' ' && a[i-1]!='\t') continue;                 /* attr-name boundary */
        int m=0; while (m<nl && lc(a[i+m])==lc(attr[m])) m++;
        if (m!=nl) continue;
        int k=i+nl;
        if (k<ae && a[k]!=' ' && a[k]!='\t' && a[k]!='=' && a[k]!='>') continue;   /* complete token, not a prefix */
        int start=i; while (start>as && (a[start-1]==' '||a[start-1]=='\t')) start--;   /* eat one+ leading space */
        int e=k; while (e<ae && (a[e]==' '||a[e]=='\t')) e++;              /* optional =value */
        if (e<ae && a[e]=='=') { e++; while (e<ae && (a[e]==' '||a[e]=='\t')) e++;
            if (e<ae && (a[e]=='"'||a[e]=='\'')) { char q=a[e]; e++; while (e<ae && a[e]!=q) e++; if(e<ae) e++; }   /* quoted value */
            else { while (e<ae && a[e]!=' ' && a[e]!='\t') e++; } }                                                /* unquoted value */
        *rs = start; *rend = e; return 1;
    }
    return 0;
}
/* removeAttribute: splice " attr[=value]" out of the opening tag + re-render.
 * Mirrors browser_dom_set's remove-path splice (bounds-checked). */
static void browser_dom_rmattr(const char *id, const char *attr) {
    browser_t *b=g_ls_b; if(!b||!attr[0]) return;
    int as,ae; if(!dom_attr_region(b,id,&as,&ae)) return;
    int rs,rend; if(!attr_span(b,as,ae,attr,&rs,&rend)) return;
    int delta=-(rend-rs);
    int active=(g_sw_raw==b->raw); int bodyend=b->bodyoff+b->bodylen;
    int live_end=(active && g_sw_pos>bodyend)?g_sw_pos:bodyend;
    memmove(b->raw+rs, b->raw+rend, live_end-rend);
    b->bodylen+=delta;
    if(active){ if(g_sw_pos>rend)g_sw_pos+=delta; if(g_sw_base>rend)g_sw_base+=delta; }
    b->raw[live_end+delta]=0;
    parse_html(b,b->raw+b->bodyoff,b->bodylen);
}
static void browser_dom_rmattr_at(int off, const char *attr) {   /* position-handle variant */
    browser_t *b=g_ls_b; if(!b||!attr[0]) return;
    int as,ae; if(!dom_attr_region_at(b,off,&as,&ae)) return;
    int rs,rend; if(!attr_span(b,as,ae,attr,&rs,&rend)) return;
    int delta=-(rend-rs);
    int active=(g_sw_raw==b->raw); int bodyend=b->bodyoff+b->bodylen;
    int live_end=(active && g_sw_pos>bodyend)?g_sw_pos:bodyend;
    memmove(b->raw+rs, b->raw+rend, live_end-rend);
    b->bodylen+=delta;
    if(active){ if(g_sw_pos>rend)g_sw_pos+=delta; if(g_sw_base>rend)g_sw_base+=delta; }
    b->raw[live_end+delta]=0;
    parse_html(b,b->raw+b->bodyoff,b->bodylen);
}
/* fetch() backing for page JS (M685): a blocking GET (HTTP or, for https://, TLS) into a
 * scratch buffer, returning just the response BODY + the parsed status. Runs synchronously
 * on the same thread that already fetched the page, AFTER that fetch completed, so the
 * net/TLS stack is idle (a JS fetch is just another sequential get, like the per-page
 * image fetches). Its own kmalloc'd scratch — never b->raw — so it can't clobber the page
 * being rendered. */
static int browser_fetch(const char *url, const char *method, const char *ctype, const char *reqbody, char *out, int outmax, int *status) {
    if (!url || outmax <= 0) return -1;
    char cur[URL_MAX];
    /* Resolve relative request URLs (e.g. fetch('/api/weather')) against the
     * current page URL, like a real browser — without this a root-/dir-relative
     * fetch yields an empty host and fails (M-fetch-rel). An absolute http(s)://
     * URL is copied verbatim; resolve_img_url handles both. Fall back to a raw
     * copy if there's no page URL or resolution can't fit. */
    int urll = (int)strlen(url);
    if (!(g_ls_b && g_ls_b->url[0] && resolve_img_url(g_ls_b->url, url, urll, cur, sizeof(cur))))
        { int i=0; while (url[i] && i<URL_MAX-1) { cur[i]=url[i]; i++; } cur[i]=0; }
    int is_post = method && (method[0]=='P' || method[0]=='p');
    int reqlen = is_post && reqbody ? (int)strlen(reqbody) : 0;
    char *raw = kmalloc(RAW_MAX);
    if (!raw) return -1;
    for (int hop = 0; hop < 6; hop++) {                      /* follow up to 5 redirects, mirroring the page fetch (M705) */
        char host[96];
        const char *path = url_split(cur, host, sizeof(host));
        int https = startsw(cur, "https://");
        int n;
        if (is_post)
            n = https ? tls_post(host, path, ctype, reqbody, reqlen, (uint8_t *)raw, RAW_MAX - 1, (uint32_t)timer_ticks())
                      : http_post(host, path, ctype, reqbody, reqlen, raw, RAW_MAX - 1);
        else
            n = https ? tls_get(host, path, (uint8_t *)raw, RAW_MAX - 1, (uint32_t)timer_ticks())
                      : http_get(host, path, raw, RAW_MAX - 1);
        if (n <= 0) { kfree(raw); return -1; }                   /* DNS/connect/TLS/read failure -> fetch() rejects */
        raw[n] = 0;
        int st = 0;                                              /* parse "HTTP/1.x NNN ..." */
        { const char *sp = raw; while (*sp && *sp != ' ') sp++; while (*sp == ' ') sp++;
          for (int d = 0; d < 3 && sp[d] >= '0' && sp[d] <= '9'; d++) st = st*10 + (sp[d]-'0'); }
        if (st >= 300 && st < 400 && hop < 5) {                  /* 3xx: resolve Location against the current URL and re-fetch as GET */
            char loc[URL_MAX], next[URL_MAX];
            if (http_find_loc(raw, n, loc, sizeof(loc)) && resolve_img_url(cur, loc, (int)strlen(loc), next, sizeof(next))) {
                int i=0; while (next[i] && i<URL_MAX-1) { cur[i]=next[i]; i++; } cur[i]=0;
                is_post = 0; reqlen = 0; reqbody = 0;            /* a redirect is followed with GET (302/303 semantics), dropping the body */
                continue;
            }
        }
        *status = st ? st : 200;
        const char *body = raw; int j;                           /* skip headers: find CRLFCRLF (or LFLF) */
        for (j = 0; j+1 < n; j++) {
            if (j+3 < n && raw[j]=='\r' && raw[j+1]=='\n' && raw[j+2]=='\r' && raw[j+3]=='\n') { body = raw+j+4; break; }
            if (raw[j]=='\n' && raw[j+1]=='\n') { body = raw+j+2; break; }
        }
        int blen = n - (int)(body - raw);
        if (blen < 0) blen = 0;
        if (blen > outmax) blen = outmax;
        memcpy(out, body, (unsigned long)blen);
        kfree(raw);
        return blen;
    }
    kfree(raw);
    return -1;                                                   /* too many redirects */
}

/* EventSource backing (M-eventsource): GET `url` as Server-Sent-Events, read only the
 * FIRST event (the stream stays open, so tls_get_sse/http_get_sse stop + close after
 * the first `\n\n`), then extract that event's `data:` line(s) — joined with '\n' per
 * the SSE spec — into `out`. Relative URLs resolve against the page URL. Returns the
 * payload length, or <0 on a network error (so the JS side fires onerror). Its own
 * kmalloc'd scratch (never b->raw). */
static int browser_eventsource(const char *url, char *out, int outmax, int *status) {
    if (!url || outmax <= 0) return -1;
    char cur[URL_MAX];
    int urll = (int)strlen(url);
    if (!(g_ls_b && g_ls_b->url[0] && resolve_img_url(g_ls_b->url, url, urll, cur, sizeof(cur))))
        { int i=0; while (url[i] && i<URL_MAX-1) { cur[i]=url[i]; i++; } cur[i]=0; }
    char *raw = kmalloc(RAW_MAX);
    if (!raw) return -1;
    int n = 0;
    for (int hop = 0; hop < 6; hop++) {                          /* follow redirects (e.g. http->https) like browser_fetch */
        char host[96];
        const char *path = url_split(cur, host, sizeof(host));
        int https = startsw(cur, "https://");
        n = https ? tls_get_sse(host, path, (uint8_t *)raw, RAW_MAX - 1, (uint32_t)timer_ticks())
                  : http_get_sse(host, path, raw, RAW_MAX - 1);
        if (n <= 0) { kfree(raw); return -1; }
        raw[n] = 0;
        int st = 0;
        { const char *sp = raw; while (*sp && *sp != ' ') sp++; while (*sp == ' ') sp++;
          for (int d = 0; d < 3 && sp[d] >= '0' && sp[d] <= '9'; d++) st = st*10 + (sp[d]-'0'); }
        if (st >= 300 && st < 400 && hop < 5) {
            char loc[URL_MAX], next[URL_MAX];
            if (http_find_loc(raw, n, loc, sizeof(loc)) && resolve_img_url(cur, loc, (int)strlen(loc), next, sizeof(next))) {
                int i=0; while (next[i] && i<URL_MAX-1) { cur[i]=next[i]; i++; } cur[i]=0;
                continue;
            }
        }
        *status = st ? st : 200;
        break;
    }
    if (n <= 0) { kfree(raw); return -1; }
    /* find the body (after the HTTP header terminator) */
    int bodyoff = 0;
    for (int j = 0; j + 1 < n; j++) {
        if (j+3 < n && raw[j]=='\r' && raw[j+1]=='\n' && raw[j+2]=='\r' && raw[j+3]=='\n') { bodyoff = j+4; break; }
        if (raw[j]=='\n' && raw[j+1]=='\n') { bodyoff = j+2; break; }
    }
    /* parse the first SSE event: gather `data:` field value(s) until a blank line,
     * joining multiple data lines with '\n' (SSE framing). Bounds-safe on `out`. */
    int p = 0; int i = bodyoff;
    while (i < n) {
        int ls = i;                                              /* line start */
        while (i < n && raw[i] != '\n') i++;                     /* line end (exclusive) */
        int le = i;                                              /* points at '\n' or n */
        if (i < n) i++;                                          /* consume the '\n' */
        int len = le - ls;
        if (len > 0 && raw[le-1] == '\r') len--;                 /* trim a trailing CR */
        if (len == 0) break;                                     /* blank line -> end of event */
        if (len >= 5 && raw[ls]=='d'&&raw[ls+1]=='a'&&raw[ls+2]=='t'&&raw[ls+3]=='a'&&raw[ls+4]==':') {
            int vend = ls + len;                                 /* value end (CR already trimmed from len) */
            int vs = ls + 5; if (vs < vend && raw[vs] == ' ') vs++;   /* "data: x" — skip one optional space */
            if (p > 0 && p < outmax) out[p++] = '\n';            /* join multiple data lines */
            for (int k = vs; k < vend && p < outmax; k++) out[p++] = raw[k];
        }
        /* other fields (event:, id:, retry:, comments) are ignored for this snapshot */
    }
    if (p > outmax) p = outmax;
    kfree(raw);
    return p;
}
/* document.title get/set: read/write the page <title> (the window bar reads it on
 * the next paint, which the triggering click already schedules). */
static int browser_get_title(char *out, int max) {
    browser_t *b = g_ls_b; if (max) out[0] = 0; if (!b) return 0;
    const char *t = b->title_js_set ? b->title_js : b->title;
    int i = 0; while (t[i] && i < max - 1) { out[i] = t[i]; i++; } out[i] = 0; return 1;
}
static void browser_set_title(const char *v) {
    browser_t *b = g_ls_b; if (!b) return;
    int i = 0; while (v[i] && i < 63) { b->title_js[i] = v[i]; i++; } b->title_js[i] = 0;
    b->title_js_set = 1;                                 /* survives the parse_html re-render that follows */
}
static void js_bind_storage(browser_t *b){ g_ls_b=b; js_set_storage(browser_ls_get, browser_ls_set, browser_ls_remove, browser_ls_clear); js_set_title(browser_get_title, browser_set_title); js_set_dom(browser_dom_get, browser_dom_set); js_set_dom_attr(browser_dom_getattr, browser_dom_setattr); js_set_dom_pos(browser_dom_get_at, browser_dom_set_at, browser_dom_getattr_at, browser_dom_setattr_at, browser_dom_query); js_set_dom_match(browser_dom_matches, browser_dom_matches_at, browser_dom_closest, browser_dom_closest_at); js_set_dom_rmattr(browser_dom_rmattr, browser_dom_rmattr_at); js_set_dom_children(browser_dom_children, browser_dom_children_at, browser_dom_parent, browser_dom_parent_at, browser_dom_sibling, browser_dom_sibling_at); js_set_dom_tag(browser_dom_tag, browser_dom_tag_at); js_set_location(b->url); js_set_fetch(browser_fetch); js_set_eventsource(browser_eventsource); js_set_websocket(ws_open, ws_exchange); js_set_canvas(browser_canvas_op); }
static void run_page_scripts(browser_t *b, int bodyoff, int bodylen) {
    static char jsout[2048];
    int appendpos = bodyoff + bodylen;                   /* splice point in b->raw */
    if (appendpos >= RAW_MAX - 1) return;                /* no room to write */
    g_sw_raw = b->raw; g_sw_pos = appendpos; g_sw_base = appendpos; g_sw_max = RAW_MAX;
    js_bind_storage(b);
    js_page_load(b->scripts, jsout, sizeof(jsout), script_write_cb);   /* persists the page's global env for later events */
    int written = g_sw_pos - g_sw_base;                  /* g_sw_base may have shifted if a DOM write moved the buffer */
    g_sw_raw = 0;
    if (jsout[0]) kprintf("[js] %s\n", jsout);           /* console.log / errors -> serial */
    if (written > 0)                                     /* re-render incl. the written HTML */
        parse_html(b, b->raw + bodyoff, bodylen + written);  /* scriptlen reset inside; not re-run */
}

/* Run a `javascript:` link / onclick handler: execute the code, splice any
 * document.write output into the page after the body, and re-render. Reuses the
 * stored body region so the page updates in place on click. */
static void run_js_handler(browser_t *b, const char *code) {
    static char jsout[2048];
    int saved_sel = b->sel;                              /* the clicked link; re-render below clears it */
    int appendpos = b->bodyoff + b->bodylen;
    if (appendpos >= RAW_MAX - 1) return;
    g_sw_raw = b->raw; g_sw_pos = appendpos; g_sw_base = appendpos; g_sw_max = RAW_MAX;
    js_bind_storage(b);
    js_page_event(code, jsout, sizeof(jsout), script_write_cb);   /* runs in the persistent page env (sees load-script globals) */
    int written = g_sw_pos - g_sw_base;                  /* g_sw_base may have shifted if a DOM write moved the buffer */
    g_sw_raw = 0;
    if (jsout[0]) kprintf("[js] %s\n", jsout);
    if (written > 0) { b->bodylen += written; parse_html(b, b->raw + b->bodyoff, b->bodylen); }
    /* a DOM mutation or document.write re-render clears the selection; restore it so
     * pressing Enter again re-runs the same link (e.g. clicking a counter repeatedly). */
    if (saved_sel != NO_LINK && saved_sel < b->nlink) b->sel = saved_sel;
}
/* Activate an `event:ID` link: fire the JS-assigned handler registered for that
 * element id. Same document.write splice + re-render + selection-restore wrapper
 * as run_js_handler, but dispatches through js_fire_event (the persistent env). */
static void run_js_event(browser_t *b, const char *id, const char *type) {
    static char jsout[2048];
    int saved_sel = b->sel;
    int appendpos = b->bodyoff + b->bodylen;
    if (appendpos >= RAW_MAX - 1) return;
    g_sw_raw = b->raw; g_sw_pos = appendpos; g_sw_base = appendpos; g_sw_max = RAW_MAX;
    js_bind_storage(b);
    js_fire_event(id, type, jsout, sizeof(jsout), script_write_cb);
    int written = g_sw_pos - g_sw_base;
    g_sw_raw = 0;
    if (jsout[0]) kprintf("[js] %s\n", jsout);
    if (written > 0) { b->bodylen += written; parse_html(b, b->raw + b->bodyoff, b->bodylen); }
    if (saved_sel != NO_LINK && saved_sel < b->nlink) b->sel = saved_sel;
}
/* If the element has the named inline handler (onchange/oninput/…), run it.
 * Returns 1 if it ran (run_js_handler re-renders), so the caller can skip its own. */
static int fire_handler(browser_t *b, const char *id, const char *attr) {
    int as, ae;
    if (dom_attr_region(b, id, &as, &ae)) {
        const char *oc; int ocl;
        if (find_attr(b->raw + as, ae - as, attr, &oc, &ocl) && ocl > 0) {   /* inline onchange="CODE" */
            char code[1024]; int n = ocl; if (n > (int)sizeof(code) - 1) n = (int)sizeof(code) - 1;
            for (int i = 0; i < n; i++) code[i] = oc[i];   /* copy BEFORE run_js_handler mutates b->raw */
            code[n] = 0;
            run_js_handler(b, code);
            return 1;
        }
    }
    /* no inline attribute: try a JS-assigned handler (el.onchange=fn / addEventListener),
     * keyed by id with the bare event type ("on" stripped). Rides this same input path. */
    {
        static char jsout[2048];
        int saved_sel = b->sel;                          /* preserve selection across the re-render (parity with run_js_handler) */
        int appendpos = b->bodyoff + b->bodylen;
        if (appendpos >= RAW_MAX - 1) return 0;
        g_sw_raw = b->raw; g_sw_pos = appendpos; g_sw_base = appendpos; g_sw_max = RAW_MAX;
        js_bind_storage(b);
        int ran = js_fire_event(id, attr + 2, jsout, sizeof(jsout), script_write_cb);
        int written = g_sw_pos - g_sw_base;
        g_sw_raw = 0;
        if (jsout[0]) kprintf("[js] %s\n", jsout);
        if (written > 0) b->bodylen += written;
        if (ran || written > 0) parse_html(b, b->raw + b->bodyoff, b->bodylen);   /* re-render to show the change + handler effects */
        if (saved_sel != NO_LINK && saved_sel < b->nlink) b->sel = saved_sel;
        return ran;
    }
}
static int fire_onchange(browser_t *b, const char *id) { return fire_handler(b, id, "onchange"); }

/* Render plain text: words become WORD tokens, newlines become line breaks
 * (a blank line becomes a paragraph break), so file structure is preserved. */
static void parse_text(browser_t *b, const char *t, int len) {
    drop_image(b);                                       /* a page replaces any prior image */
    drop_image_slots(b);                                 /* and its inline images */
    b->textlen = b->ntok = b->hreflen = b->nlink = 0; b->title[0] = 0;
    b->sel = NO_LINK; b->curcolor = 0;
    memset(b->linky, 0xFF, sizeof(b->linky));
    int wstart = -1, nl = 0;
    for (int i = 0; i < len; i++) {
        char c = t[i];
        if (c == '\r') continue;
        if (c == '\n') {
            if (wstart >= 0) { emit_word(b, wstart, STY_NORMAL, NO_LINK); wstart = -1; }
            emit_break(b, ++nl >= 2 ? TK_PARA : TK_BREAK);
            continue;
        }
        if (c == ' ' || c == '\t') {
            if (wstart >= 0) { emit_word(b, wstart, STY_NORMAL, NO_LINK); wstart = -1; }
            continue;
        }
        nl = 0;
        if (b->textlen < TEXT_MAX - 1) {
            if (wstart < 0) wstart = b->textlen;
            b->text[b->textlen++] = c;
        }
    }
    if (wstart >= 0) emit_word(b, wstart, STY_NORMAL, NO_LINK);
}

/* ---- networking (async) ----
 *
 * The HTTP fetch blocks for up to a second, so it runs on a dedicated kernel
 * worker task — the window manager keeps compositing (cursor live, "Loading…"
 * shown) while the page downloads. The worker only fills the `raw` buffer; the
 * actual HTML parse happens back on the WM thread in browser_poll(), so parsing
 * and rendering never race. One fetch at a time (guarded by g_busy/g_req).
 */
static void set_status(browser_t *b, const char *s) {
    int i = 0; while (s[i] && i < 39) { b->status[i] = s[i]; i++; } b->status[i] = 0;
}

/* Save/disable + restore interrupts: makes the WM<->worker hand-offs atomic
 * against preemption (the timer IRQ can switch tasks at any instruction). */
#ifdef BROWSER_RING3   /* ring-3 browser app: single-threaded, can't run privileged cli/sti */
static inline uint64_t irq_save(void) { return 0; }
static inline void irq_restore(uint64_t f) { (void)f; }
#else
static inline uint64_t irq_save(void) {
    uint64_t f; __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory"); return f;
}
static inline void irq_restore(uint64_t f) {
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}
#endif

static volatile browser_t *g_req;        /* a browser queued for a fetch, or NULL */
static volatile int        g_busy;       /* worker is mid-fetch                   */
static task_t             *g_worker;

static void free_buffers(browser_t *b) {
    if (b->framebuf) kfree(b->framebuf);          /* animated GIF frames (img points into it) */
    else if (b->img) kfree(b->img);
    for (int i = 0; i < b->nimg; i++) if (b->imgs[i]) kfree(b->imgs[i]);
    drop_remote_imgs(b);                           /* prefetched remote-image bytes */
    kfree(b->lrec); kfree(b->wrec); kfree(b->links); kfree(b->hrefs);
    kfree(b->scripts);
    kfree(b->toks); kfree(b->text); kfree(b->raw); kfree(b);
}

/* url_split + resolve_img_url now live in url.c so they can be fuzzed in
 * isolation (M580). */

/* Atomically claim the single fetch worker for b. 1 = claimed, 0 = busy. */
static int claim_fetch(browser_t *b) {
    uint64_t f = irq_save();
    if (g_busy || g_req) { irq_restore(f); return 0; }
    b->need_parse = 0; b->loading = 1; g_req = b;
    irq_restore(f);
    return 1;
}


/* Best-effort: scan the fetched HTML in b->raw for up to REMOTE_IMG_MAX remote
 * <img src=...> URLs, fetch each over HTTP/HTTPS, and stash the COMPRESSED bytes
 * in b->rimg_data[]/rimg_len[] keyed by the RAW src string (b->rimg_src[]). The
 * parse later matches an <img>'s raw src against rimg_src[] and decodes inline.
 *
 * STRICTLY best-effort: any failure (alloc, fetch<=0, src too long, no src)
 * simply skips that image. Runs on the worker (it does the blocking tls_get/
 * http_get). Re-checks b->closed between fetches so a closed window bails fast. */
static void collect_remote_imgs(browser_t *b) {
    b->n_rimg = 0;
    if (!b->raw || b->rawlen <= 0) return;
    const char *h = b->raw;
    int len = b->rawlen;
    for (int i = 0; i + 4 < len && b->n_rimg < REMOTE_IMG_MAX; i++) {
        if (b->closed) return;                            /* window closed mid-scan */
        if (h[i] != '<') continue;
        if (lc(h[i+1]) != 'i' || lc(h[i+2]) != 'm' || lc(h[i+3]) != 'g') continue;
        if (h[i+4] != ' ' && h[i+4] != '\t' && h[i+4] != '\n' && h[i+4] != '\r' && h[i+4] != '/' && h[i+4] != '>') continue;
        /* find the end of this tag's attributes (the unquoted '>'), quote-aware
         * exactly like the main tokenizer so we delimit the same <img> it does */
        int as = i + 4, ae = as;
        { char q = 0;
          while (ae < len) { char ac = h[ae];
              if (q) { if (ac == q) q = 0; }
              else if (ac=='"' || ac=='\'') q = ac;
              else if (ac=='>') break;
              ae++; } }
        if (ae >= len) break;                             /* unterminated tag -> stop */
        const char *src; int srcl;
        if (img_src_attr(h + as, ae - as, &src, &srcl) && srcl > 0 && srcl <= 95) {
            /* our decoders handle PNG/GIF/JPEG/SVG + lossless WebP (M1466) — skip a src
             * whose extension is a format we still can't decode (AVIF/ICO, and lossy
             * VP8 WebP) so we don't waste a fetch + pre-paint latency on an image that
             * would just fall back to a link. Extension-less srcs are still tried (may
             * be a real image). */
            int pe = srcl; for (int x = 0; x < srcl; x++) if (src[x] == '?') { pe = x; break; }
            int unsup = 0;
            if (pe >= 4) { const char *e = src + pe - 4;
                if (e[0]=='.' && lc(e[1])=='i'&&lc(e[2])=='c'&&lc(e[3])=='o') unsup = 1; }     /* .ico */
            if (!unsup && pe >= 5) { const char *e = src + pe - 5;
                /* .webp is now FETCHED — decode_image decodes VP8L (lossless) webp (M1466).
                 * A lossy VP8 webp still falls back to a link, but lossless ones now display. */
                if (e[0]=='.' && lc(e[1])=='a'&&lc(e[2])=='v'&&lc(e[3])=='i'&&lc(e[4])=='f') unsup = 1; } /* .avif (still unsupported) */
            if (unsup) { i = ae; continue; }
            /* skip a src already queued (a page may repeat the same image) */
            int dup = 0;
            for (int k = 0; k < b->n_rimg; k++) {
                int m = 1;
                for (int j = 0; j < srcl; j++) { if (b->rimg_src[k][j] != src[j]) { m = 0; break; } }
                if (m && b->rimg_src[k][srcl] == 0) { dup = 1; break; }
            }
            if (!dup) {
                char url[URL_MAX];
                if (resolve_img_url(b->url, src, srcl, url, sizeof(url))) {
                    int k = b->n_rimg;                    /* candidate slot */
                    char host[96];
                    const char *path = url_split(url, host, sizeof(host));
                    int https = startsw(url, "https://");
                    uint8_t *scratch = kmalloc(IMG_READ_MAX);
                    if (scratch) {
                        int n = https
                            ? tls_get(host, path, scratch, IMG_READ_MAX - 1, (uint32_t)timer_ticks())
                            : http_get(host, path, (char *)scratch, IMG_READ_MAX - 1);
                        if (n > 0) {
                            /* tls_get/http_get returns the whole HTTP response; strip the
                             * headers (and de-chunk) to get the raw image bytes — exactly
                             * like the page path in browser_poll. Storing the response with
                             * its headers would put "HTTP/1.1 200..." before the image
                             * signature and the decoder would reject it. */
                            int bo = 0;
                            for (int x = 0; x + 3 < n; x++)
                                if (scratch[x]=='\r'&&scratch[x+1]=='\n'&&scratch[x+2]=='\r'&&scratch[x+3]=='\n') { bo = x + 4; break; }
                            int blen = n - bo;
                            if (bo > 0 && http_is_chunked((const char *)scratch, bo))
                                blen = http_dechunk((char *)scratch + bo, blen, IMG_READ_MAX);   /* bound = the actual scratch buffer, not RAW_MAX */
                            if (blen > 0) {
                                uint8_t *data = kmalloc((unsigned long)blen);
                                if (data) {
                                    memcpy(data, scratch + bo, (unsigned long)blen);
                                    /* commit this slot only once everything succeeded */
                                    for (int j = 0; j < srcl; j++) b->rimg_src[k][j] = src[j];
                                    b->rimg_src[k][srcl] = 0;
                                    b->rimg_data[k] = data;
                                    b->rimg_len[k]  = blen;
                                    b->n_rimg++;
                                }
                            }
                        }
                        kfree(scratch);
                    }
                }
            }
        }
        i = ae;                                           /* skip past this tag */
    }
}

/* Worker task: fetch b->url into b->raw. The close/finish decision is made under
 * a lock so EXACTLY ONE of the worker and browser_destroy frees b (review C1). */
static void worker_fetch(browser_t *b) {
    /* Free the PREVIOUS page's prefetched remote images here, on the worker
     * thread — this runs while loading==1, and the WM reads rimg_* only when
     * !loading (the <img> branch is gated on it), so the free/repopulate here
     * can't race a WM read. collect_remote_imgs below repopulates them. */
    drop_remote_imgs(b);
    char host[96];
    const char *path = url_split(b->url, host, sizeof(host));
    int n; int https = startsw(b->url, "https://");
    if (!b->raw)    n = -1;
    else if (https) n = tls_get(host, path, (uint8_t *)b->raw, RAW_MAX - 1, (uint32_t)timer_ticks());
    else            n = http_get(host, path, b->raw, RAW_MAX - 1);
    b->cert_status = https ? tls_cert_status() : -2;   /* surface TLS cert result in the UI */
    b->chain_ok = https ? tls_chain_anchored() : 0;
    b->host_match = https ? tls_host_match() : -2;
    b->cert_cn[0] = b->cert_expiry[0] = 0;
    if (https && n > 0) {                              /* snapshot the leaf identity for the 'i' display */
        const char *cn = tls_leaf_cn(), *ex = tls_leaf_expiry();
        int k = 0; while (cn[k] && k < (int)sizeof(b->cert_cn)-1) { b->cert_cn[k] = cn[k]; k++; } b->cert_cn[k] = 0;
        k = 0; while (ex[k] && k < (int)sizeof(b->cert_expiry)-1) { b->cert_expiry[k] = ex[k]; k++; } b->cert_expiry[k] = 0;
    }
    b->http_n = n;
    if (n > 0) { b->rawlen = n; b->raw[n] = 0; }
    /* Best-effort inline-image prefetch (worker-side; does its own blocking
     * fetches). MUST NOT prevent the render handoff below: collect_remote_imgs
     * never aborts the page and bails fast if the window closed. Only runs on a
     * real HTML fetch; a closed window skips it entirely (n_rimg already 0 from
     * the drop_remote_imgs above). */
    if (n > 0 && !b->closed) collect_remote_imgs(b);
    uint64_t f = irq_save();
    int closed = b->closed;                    /* did the window close mid-fetch? */
    if (!closed) { b->need_parse = 1; b->loading = 0; }
    irq_restore(f);
    if (closed) free_buffers(b);               /* then we own the free */
}

static void worker_main(void) {
    for (;;) {
        uint64_t f = irq_save();
        browser_t *b = (browser_t *)g_req;
        if (b) { g_req = NULL; g_busy = 1; }   /* atomic pickup */
        irq_restore(f);
        if (b) { worker_fetch(b); g_busy = 0; }
        else timer_wait(2);                    /* ~20ms idle poll (hlt-based) */
    }
}

void browser_init(void) {
    if (!g_worker) {
#ifdef BROWSER_RING3
        /* ring 3: webview shims task_create_stack onto sys_clone (a real fetch
         * thread, so the UI stays responsive during a load). No privileged CR3 read. */
        g_worker = task_create_stack(worker_main, 0, 0, 256 * 1024);
#else
        uint64_t cr3; __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
        /* 256 KB stack: this worker runs TLS + (future) bignum/RSA/ECDSA cert
         * verification, which overflows the default 16 KB task stack. */
        g_worker = task_create_stack(worker_main, cr3, 0, 256 * 1024);  /* pin to kernel space */
#endif
    }
}

/* Build the start page into b->raw (rendered locally, no network). The built-in
 * bookmarks are listed first, then any the user added to a "SITES" file on
 * disk (one host/URL per line) — so editing that file customizes the home page. */
static void build_home(browser_t *b) {
    char *o = b->raw; int p = 0;
    #define HAPP(s) do { for (const char *q = (s); *q && p < RAW_MAX - 1; q++) o[p++] = *q; } while (0)
    HAPP("<html><head><title>OS-DEV Start</title>"
         "<style> h1 { color: #2C66D6 }  dd { color: #555555 }  "
         ".new { color: #006400; font-weight: bold } </style></head><body>"
         "<h1>OS-DEV Browser</h1>"
         "<p>Press <b>?</b> (or Ctrl-F to find) for keyboard shortcuts.</p>"
         "<p class=\"new\">This very page is rendered + styled by the from-scratch HTML/CSS engine. "
         "The OS runs <b>id Software's DOOM and Quake</b> as windowed apps (with sound), plus thirty-odd "
         "more &mdash; a piano, a music jukebox, a maze, a Mandelbrot explorer, an ASCII paint, a text "
         "adventure, a typing test, Simon, tic-tac-toe against an unbeatable AI, and Blackjack.</p>"
         "<p>A from-scratch browser on a from-scratch OS, now over <b>real HTTPS</b> "
         "(a from-scratch TLS 1.3 client). Some pages that work:</p><dl>"
         "<dt><a href=\"https://text.npr.org\">https://text.npr.org</a></dt><dd>a LIVE news site over HTTPS &mdash; real headlines you can click</dd>"
         "<dt><a href=\"https://danluu.com\">https://danluu.com</a></dt><dd>a text-rich blog (minimal HTML, renders great)</dd>"
         "<dt><a href=\"https://example.com\">https://example.com</a></dt><dd>the classic example page, over TLS</dd>"
         "<dt><a href=\"https://www.gnu.org\">https://www.gnu.org</a></dt><dd>the GNU project (follow its links too)</dd>"
         "<dt><a href=\"http://example.com\">http://example.com</a></dt><dd>the same page over plain HTTP</dd>"
         "<dt><a href=\"http://info.cern.ch/hypertext/WWW/TheProject.html\">The WWW Project</a></dt>"
         "<dd>the original 1991 page about the World Wide Web</dd>"
         "<dt><a href=\"file:README.TXT\">file:README.TXT</a></dt><dd>a local file on the disk</dd>"
         "<dt><a href=\"file:help.htm\">file:help.htm</a></dt><dd>a built-in <b>help/manual</b> &mdash; apps, shell commands, and keyboard shortcuts (styled by the CSS engine)</dd>"
         "<dt><a href=\"file:index.htm\">Local demos</a></dt><dd>lists, tables, entities, colour, "
         "forms, inline code, and PNG / GIF / JPEG images &mdash; all rendered from scratch</dd>"
         "<dt><a href=\"file:jstest.htm\">file:jstest.htm</a></dt><dd>a page whose content is generated "
         "<b>live by JavaScript</b> (a from-scratch JS interpreter runs its &lt;script&gt;)</dd>"
         "<dt><a href=\"file:jsclick.htm\">file:jsclick.htm</a></dt><dd>links that <b>run JavaScript on click</b> "
         "(a from-scratch JS engine: arrows, JSON, try/catch &mdash; also at the shell: <tt>js</tt>)</dd>"
         "<dt><a href=\"file:anim.gif\">anim.gif</a></dt><dd>an animated GIF; "
         "<a href=\"file:pphoto.jpg\">pphoto.jpg</a> a progressive JPEG; "
         "<a href=\"file:inter.png\">inter.png</a> an interlaced PNG</dd>");

    char bm[512];
    long n = vfs_read("SITES", bm, sizeof(bm) - 1);   /* user bookmarks, if any */
    if (n > 0) {
        bm[n] = 0;
        int ls = 0;
        for (int i = 0; i <= (int)n; i++) {
            if (i == (int)n || bm[i] == '\n' || bm[i] == '\r') {
                if (i > ls) {
                    bm[i] = 0;
                    const char *url = bm + ls;
                    HAPP("<dt><a href=\"");
                    if (!startsw(url, "http://") && !startsw(url, "https://") && !startsw(url, "file:"))
                        HAPP("http://");
                    HAPP(url); HAPP("\">"); HAPP(url); HAPP("</a></dt><dd>bookmark</dd>");
                }
                ls = i + 1;
            }
        }
    }

    HAPP("</dl><hr>"
         "<p>This browser renders <b>bold</b> and <i>italic</i> text. Type a host "
         "(or file:NAME) and Enter, or click a link. Keyboard: Tab/n next link, "
         "p previous, Enter to follow, Backspace or &lt; to go back, &gt; forward, s to save, a to bookmark, "
         "\\ to find text. Bookmarks live in a SITES file (one URL per line).</p></body></html>");
    #undef HAPP
    b->bodyoff = 0; b->bodylen = p;   /* start page body region (for click-time JS) */
    parse_html(b, b->raw, p);
}

static void drop_image(browser_t *b) {
    if (b->framebuf) { kfree(b->framebuf); b->framebuf = 0; b->nframes = 0; b->img = 0; }
    else if (b->img) { kfree(b->img); }
    b->img = 0;                                   /* img points into framebuf when animated */
}

static void drop_image_slots(browser_t *b) {
    for (int i = 0; i < b->nimg; i++) { if (b->imgs[i]) kfree(b->imgs[i]); b->imgs[i] = 0; }
    b->nimg = 0;
    b->n_canv = 0;   /* M1796: canvas slots live in imgs[] (freed above); clear the id->slot registry */
}

/* Free the prefetched COMPRESSED remote-image bytes and clear the match table.
 * Called on navigation (before fetching the next page) and on teardown. NOT
 * called from parse_html, so the bytes survive every re-render of one page. */
static void drop_remote_imgs(browser_t *b) {
    for (int k = 0; k < REMOTE_IMG_MAX; k++) {
        if (b->rimg_data[k]) { kfree(b->rimg_data[k]); b->rimg_data[k] = 0; }
        b->rimg_len[k] = 0;
        b->rimg_src[k][0] = 0;
    }
    b->n_rimg = 0;
}

/* Decode a PNG/GIF blob into a freshly kmalloc'd RGBA buffer (caller frees).
 * Bounds the dimensions, allocates exactly what's needed, frees its own
 * scratch. Returns the RGBA buffer and sets ow/oh, or NULL on any failure. */
/* base64 alphabet value of one char, or -1 if not a base64 digit. */
static int b64val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Decode base64 `in` (inlen bytes) into `out` (cap bytes). Skips ASCII
 * whitespace; stops at '=' padding or the first non-alphabet byte. Returns the
 * decoded length, or -1 on output overflow. Bounded for untrusted input (the
 * payload of a data: image URI): every write is guarded against `cap` and every
 * read stays within [in, in+inlen). */
static int b64_decode(const char *in, int inlen, uint8_t *out, int cap) {
    unsigned acc = 0;
    int nbits = 0, op = 0;
    for (int i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (c == '=') break;
        int v = b64val(c);
        if (v < 0) break;
        acc = (acc << 6) | (unsigned)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (op >= cap) return -1;
            out[op++] = (uint8_t)((acc >> nbits) & 0xff);
        }
    }
    return op;
}

uint8_t *decode_image(const uint8_t *data, int len, int *ow, int *oh) {
    /* WebP (RIFF<size>WEBP): VP8L lossless. probe -> validate caps -> decode. A
     * lossy (VP8 ) or malformed webp makes webp_probe fail, so we return 0 and the
     * caller falls back to a clickable link (no other decoder handles a RIFF). */
    if (len >= 16 && data[0]=='R'&&data[1]=='I'&&data[2]=='F'&&data[3]=='F' &&
        data[8]=='W'&&data[9]=='E'&&data[10]=='B'&&data[11]=='P') {
        int w, h; long need;
        if (webp_probe(data, len, &w, &h, &need) != 0) return 0;
        if (w <= 0 || h <= 0 || w > 2048 || h > 2048 || (long)w * h > 1024*1024) return 0;
        if (need <= 0 || need > 32*1024*1024) return 0;   /* webp scratch ≤~20MB now (MAX_HGROUPS=64); bound it */
        long rgba_sz = (long)w * h * 4;
        uint8_t *rgba = kmalloc((unsigned long)rgba_sz);
        uint8_t *scr  = kmalloc((unsigned long)need);
        if (!rgba || !scr) { if (rgba) kfree(rgba); if (scr) kfree(scr); return 0; }
        int r = webp_decode(data, len, rgba, (int)rgba_sz, scr, (int)need, ow, oh);
        kfree(scr);
        if (r != 0) { kfree(rgba); return 0; }
        return rgba;
    }
    /* JPEG (FF D8 FF ...): probe for dimensions + scratch size, then decode */
    if (len >= 4 && data[0]==0xFF && data[1]==0xD8 && data[2]==0xFF) {
        int w, h; long need;
        if (jpeg_probe(data, len, &w, &h, &need) != 0) return 0;
        if (w <= 0 || h <= 0 || w > 2048 || h > 2048 || (long)w * h > 1024*1024) return 0;
        if (need <= 0 || need > 8*1024*1024) return 0;
        long rgba_sz = (long)w * h * 4;
        uint8_t *rgba = kmalloc((unsigned long)rgba_sz);
        uint8_t *scr  = kmalloc((unsigned long)need);
        if (!rgba || !scr) { if (rgba) kfree(rgba); if (scr) kfree(scr); return 0; }
        int r = jpeg_decode(data, len, rgba, (int)rgba_sz, scr, (int)need, ow, oh);
        kfree(scr);
        if (r != 0) { kfree(rgba); return 0; }
        return rgba;
    }
    /* BMP (BM ...): an uncompressed Windows bitmap — e.g. our own `screenshot`
     * output. Read W/H from the header, allocate, then decode. */
    if (len >= 54 && data[0]=='B' && data[1]=='M' &&
        ((uint32_t)data[14]|((uint32_t)data[15]<<8)|((uint32_t)data[16]<<16)|((uint32_t)data[17]<<24)) >= 40) {
        int32_t bw = (int32_t)(((uint32_t)data[18])|((uint32_t)data[19]<<8)|((uint32_t)data[20]<<16)|((uint32_t)data[21]<<24));
        int32_t bh = (int32_t)(((uint32_t)data[22])|((uint32_t)data[23]<<8)|((uint32_t)data[24]<<16)|((uint32_t)data[25]<<24));
        long aw = bw, ah = bh < 0 ? -(long)bh : (long)bh;
        if (aw >= 1 && aw <= 2048 && ah >= 1 && ah <= 2048 && aw * ah <= 1024*1024) {
            long rgba_sz = aw * ah * 4;
            uint8_t *rgba = kmalloc((unsigned long)rgba_sz);
            if (!rgba) return 0;
            int r = bmp_decode(data, len, rgba, (int)rgba_sz, ow, oh);
            if (r != 0) { kfree(rgba); return 0; }
            return rgba;
        }
    }
    /* SVG (text XML): detect "<svg" within the first chunk, then rasterize. svg_decode
     * caps W,H<=512, so a 1 MB worst-case buffer holds any output; shrink to exact after.
     * BUT skip this for an HTML document: an HTML page can carry "<svg" inside an inline
     * SVG, a data:image/svg favicon, etc., and must NOT be mis-decoded as a standalone
     * image (it would render the whole page as a tiny black bitmap). If the first non-
     * whitespace bytes are "<!doctype html" or "<html", treat it as HTML, not SVG. */
    { int issvg = 0, lim = len < 512 ? len : 512;
      /* Skip leading whitespace + a UTF-8 BOM to find the first real byte. The BOM
       * bytes MUST be written as UNSIGNED literals: `data` is a const uint8_t*, so
       * data[s] promotes to 0..255, while '\xEF' is a plain-char constant = -17 on
       * x86 (signed char). Comparing the two is always false, so this BOM skip was
       * DEAD CODE (caught by -Wtype-limits, fixed M1893).
       *
       * `s` feeds only the is_html tests below — the "<svg" scan is a free search
       * over the whole first chunk — so the consequence was NOT that a BOM'd SVG
       * failed to render (it still did). It was the reverse, and worse: an HTML
       * document beginning with a BOM left data[s] pointing at 0xEF rather than
       * '<', so neither the "<html" nor the "<!doctype" test could fire, is_html
       * stayed 0, and any such page carrying "<svg" in its first 512 bytes (an
       * inline SVG, an SVG data: favicon) was mis-detected as a standalone SVG
       * image — i.e. exactly the "render the whole page as a tiny black bitmap"
       * failure the comment above says this guard exists to prevent. */
      int s = 0; while (s < lim && (data[s]==' '||data[s]=='\t'||data[s]=='\r'||data[s]=='\n'||
                                    data[s]==0xEF||data[s]==0xBB||data[s]==0xBF)) s++;
      int is_html = 0;
      if (s+5 <= lim && data[s]=='<' && (data[s+1]|32)=='h'&&(data[s+2]|32)=='t'&&(data[s+3]|32)=='m'&&(data[s+4]|32)=='l') is_html = 1;   /* <html */
      if (!is_html && s+2 <= lim && data[s]=='<' && data[s+1]=='!') {   /* <!doctype html ...> (or any <!... that isn't an SVG/XML decl) */
          int k = s+2; while (k < lim && (data[k]==' '||data[k]=='\t')) k++;
          if (k+7 <= lim && (data[k]|32)=='d'&&(data[k+1]|32)=='o'&&(data[k+2]|32)=='c'&&(data[k+3]|32)=='t'&&(data[k+4]|32)=='y'&&(data[k+5]|32)=='p'&&(data[k+6]|32)=='e') is_html = 1;
      }
      if (!is_html)
      for (int i = 0; i + 4 <= lim; i++)
          if (data[i]=='<' && (data[i+1]|32)=='s' && (data[i+2]|32)=='v' && (data[i+3]|32)=='g') { issvg = 1; break; }
      if (issvg) {
          long ocap = 512L*512*4, scap = 256*1024;
          uint8_t *rgba = kmalloc((unsigned long)ocap);
          uint8_t *scr  = kmalloc((unsigned long)scap);
          if (!rgba || !scr) { if (rgba) kfree(rgba); if (scr) kfree(scr); return 0; }
          int w = 0, h = 0;
          int r = svg_decode(data, len, rgba, (int)ocap, scr, (int)scap, &w, &h);
          kfree(scr);
          if (r != 0 || w <= 0 || h <= 0) { kfree(rgba); return 0; }
          long exact = (long)w * h * 4;            /* shrink the 1 MB worst-case buffer to exactly W*H*4 */
          uint8_t *fit = kmalloc((unsigned long)exact);
          if (fit) { memcpy(fit, rgba, (unsigned long)exact); kfree(rgba); *ow = w; *oh = h; return fit; }
          *ow = w; *oh = h; return rgba;           /* shrink alloc failed: the big buffer is still valid */
      }
    }
    static const uint8_t pngsig[8] = {0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A};
    int ispng = 0, isgif = 0;
    if (len >= 24) { ispng = 1; for (int i = 0; i < 8; i++) if (data[i] != pngsig[i]) ispng = 0; }
    if (!ispng && len >= 13 && data[0]=='G'&&data[1]=='I'&&data[2]=='F'&&data[3]=='8') isgif = 1;
    if (!ispng && !isgif) return 0;

    int w, h;
    if (ispng) {                                              /* IHDR width/height */
        w = (int)(((uint32_t)data[16]<<24)|((uint32_t)data[17]<<16)|((uint32_t)data[18]<<8)|data[19]);
        h = (int)(((uint32_t)data[20]<<24)|((uint32_t)data[21]<<16)|((uint32_t)data[22]<<8)|data[23]);
    } else {                                                  /* GIF logical screen size */
        w = data[6] | (data[7]<<8); h = data[8] | (data[9]<<8);
    }
    if (w <= 0 || h <= 0 || w > 2048 || h > 2048 || (long)w * h > 1024*1024) return 0;
    long rgba_sz = (long)w * h * 4;
    long scr_sz  = ispng ? ((long)(w*4+1)*h + len + 64)       /* PNG: unfiltered rows + IDAT copy */
                         : ((long)w*h + 16);                  /* GIF: one index per pixel */
    uint8_t *rgba = kmalloc((unsigned long)rgba_sz);
    uint8_t *scr  = kmalloc((unsigned long)scr_sz);
    if (!rgba || !scr) { if (rgba) kfree(rgba); if (scr) kfree(scr); return 0; }
    int r = ispng ? png_decode(data, len, rgba, (int)rgba_sz, scr, (int)scr_sz, ow, oh)
                  : gif_decode(data, len, rgba, (int)rgba_sz, scr, (int)scr_sz, ow, oh);
    kfree(scr);
    if (r != 0) { kfree(rgba); return 0; }
    return rgba;
}

/* If `data` looks like a PNG or GIF, decode it into b->img (full-page image
 * view) and return 1; else 0. */
static int try_image(browser_t *b, const uint8_t *data, int len) {
    /* a GIF (possibly animated) -> decode every frame for full-page playback */
    if (len >= 13 && data[0]=='G'&&data[1]=='I'&&data[2]=='F'&&data[3]=='8') {
        int W = data[6] | (data[7]<<8), H = data[8] | (data[9]<<8);
        if (W > 0 && H > 0 && W <= 2048 && H <= 2048 && (long)W * H <= 1024*1024) {
            long fsz = (long)W * H * 4;
            int maxf = 64;
            while (maxf > 1 && fsz * maxf > 8L*1024*1024) maxf--;   /* cap total frame memory */
            uint8_t *frames = kmalloc((unsigned long)(fsz * maxf));
            uint8_t *scr    = kmalloc((unsigned long)(fsz + (long)W * H));
            if (frames && scr) {
                int w, h, nf = gif_decode_anim(data, len, frames, (int)(fsz * maxf),
                                               scr, (int)(fsz + (long)W * H), &w, &h,
                                               b->framedelay, maxf);
                kfree(scr);
                if (nf >= 1) {
                    drop_image(b); drop_image_slots(b);
                    b->framebuf = frames; b->nframes = nf; b->curframe = 0;
                    b->frametick = timer_ticks();
                    b->img = frames; b->imgw = w; b->imgh = h;
                    b->ntok = 0; b->nlrec = 0; b->sel = NO_LINK; b->find_tok = -1; b->scroll = 0;
                    return 1;
                }
                kfree(frames);
            } else { if (frames) kfree(frames); if (scr) kfree(scr); }
        }
    }
    int ow, oh;
    uint8_t *rgba = decode_image(data, len, &ow, &oh);
    if (!rgba) return 0;
    drop_image(b);
    drop_image_slots(b);                /* a full-page image replaces any inline ones */
    b->img = rgba; b->imgw = ow; b->imgh = oh;
    b->ntok = 0; b->nlrec = 0; b->sel = NO_LINK; b->find_tok = -1; b->scroll = 0;
    return 1;
}

/* Decode an in-memory image blob (PNG/GIF/JPEG) into the next inline-image
 * slot. Returns the slot index, or -1 (caller falls back to a clickable link).
 * Shared by the local-file and remote-image paths. */
static int decode_bytes_to_slot(browser_t *b, const uint8_t *data, int len) {
    if (b->nimg >= IMG_SLOTS) return -1;
    if (!data || len <= 0) return -1;
    int ow, oh;
    uint8_t *rgba = decode_image(data, len, &ow, &oh);
    if (!rgba) return -1;
    int s = b->nimg++;
    b->imgs[s] = rgba; b->imgsw[s] = ow; b->imgsh[s] = oh;
    return s;
}

/* M1796: allocate a blank (opaque-white) writable RGBA image slot for a <canvas>.
 * The JS 2D context draws into imgs[slot]; it blits like a decoded image at render
 * (RGBA, R at byte 0, matching decode_image). Returns the slot index, or -1. */
static int canvas_new_slot(browser_t *b, int cw, int ch) {
    if (b->nimg >= IMG_SLOTS || cw <= 0 || ch <= 0) return -1;
    uint8_t *px = kmalloc((long)cw * ch * 4);
    if (!px) return -1;
    for (long i = 0; i < (long)cw * ch * 4; i++) px[i] = 0xFF;   /* opaque white */
    int s = b->nimg++;
    b->imgs[s] = px; b->imgsw[s] = cw; b->imgsh[s] = ch;
    return s;
}
/* M1796/M1797: JS canvas 2D context drawing op. Resolves the canvas's slot by id,
 * parses the colour string (parse_color: #hex / named / hsl), and writes the slot's
 * RGBA buffer. op: 0=fillRect(a,b=x,y c,d=w,h), 1=strokeRect(1px outline), 2=clearRect
 * (fills opaque white), 3=line(a,b -> c,d, Bresenham). All writes bounds-clamped. */
static void browser_canvas_op(const char *id, int op, int a, int by, int c, int d, const char *color, const char *text, int lw) {
    browser_t *b = g_ls_b; if (!b || !id) return;
    if (lw < 1) lw = 1; if (lw > 40) lw = 40;               /* M1801: lineWidth (stroke ops), clamped */
    int slot = -1;
    for (int i = 0; i < b->n_canv; i++) {
        const char *ci = b->canv_id[i]; int j = 0;
        while (ci[j] && id[j] && ci[j] == id[j]) j++;
        if (!ci[j] && !id[j]) { slot = b->canv_slot[i]; break; }
    }
    if (slot < 0 || slot >= b->nimg || !b->imgs[slot]) return;
    int cw = b->imgsw[slot], chh = b->imgsh[slot];
    uint8_t *px = b->imgs[slot];
    uint32_t col = (op == 2) ? 0xFFFFFFu : (color ? parse_color(color, (int)strlen(color)) : 0);   /* clearRect -> white */
    uint8_t R = (uint8_t)((col >> 16) & 0xFF), G = (uint8_t)((col >> 8) & 0xFF), B = (uint8_t)(col & 0xFF);
    #define CVPX(X,Y) do { int _x=(X),_y=(Y); if(_x>=0&&_x<cw&&_y>=0&&_y<chh){ uint8_t*_p=px+((long)_y*cw+_x)*4; _p[0]=R;_p[1]=G;_p[2]=B;_p[3]=0xFF; } } while(0)
    #define PEN(X,Y)  do { if (lw <= 1) CVPX((X),(Y)); else { int _h=lw/2; for(int _py=-_h;_py<=lw-1-_h;_py++) for(int _px=-_h;_px<=lw-1-_h;_px++) CVPX((X)+_px,(Y)+_py); } } while(0)   /* M1801: lw×lw pen for stroke ops */
    if (op == 0 || op == 2) {                                /* fillRect / clearRect */
        int x0=a<0?0:a, y0=by<0?0:by, x1=a+c, y1=by+d; if(x1>cw)x1=cw; if(y1>chh)y1=chh;
        for (int yy=y0; yy<y1; yy++) for (int xx=x0; xx<x1; xx++) CVPX(xx,yy);
    } else if (op == 1) {                                    /* strokeRect: lw-px outline */
        int x1=a+c-1, y1=by+d-1;
        for (int xx=a; xx<=x1; xx++) { PEN(xx,by); PEN(xx,y1); }
        for (int yy=by; yy<=y1; yy++) { PEN(a,yy); PEN(x1,yy); }
    } else if (op == 3) {                                    /* line a,by -> c,d (Bresenham, lw-px) */
        int x0=a,y0=by,x1=c,y1=d, dx=x1-x0, dy=y1-y0;
        int adx=dx<0?-dx:dx, ady=dy<0?-dy:dy, sx=dx<0?-1:1, sy=dy<0?-1:1, err=(adx>ady?adx:-ady)/2;
        for (;;) { PEN(x0,y0); if(x0==x1&&y0==y1) break; int e2=err; if(e2>-adx){err-=ady;x0+=sx;} if(e2<ady){err+=adx;y0+=sy;} }
    } else if (op == 4 && text) {                            /* M1798: fillText(text, a=x, by=baseline y) in fillStyle, 8x16 bitmap font */
        int pen = a;
        for (const char *t = text; *t; t++) {
            unsigned char uc = (unsigned char)*t;
            const unsigned char *g = font_row(uc);   /* 0x80+ = the extended TUI set (M2015) */
            for (int row = 0; row < 16; row++) { unsigned char bits = g[row]; int yy = by - 13 + row;   /* by is the text baseline */
                for (int col = 0; col < 8; col++) if (bits & (0x80 >> col)) CVPX(pen + col, yy); }
            pen += 8;
        }
    } else if (op == 5) {                                    /* M1799: arc — full-circle outline, centre (a,by) radius c, in strokeStyle (midpoint circle, no trig; partial arcs draw the full circle) */
        int ccx=a, ccy=by, r=c<0?-c:c, xx=r, yy=0, e2=1-r;
        while (xx >= yy) {
            PEN(ccx+xx,ccy+yy); PEN(ccx-xx,ccy+yy); PEN(ccx+xx,ccy-yy); PEN(ccx-xx,ccy-yy);
            PEN(ccx+yy,ccy+xx); PEN(ccx-yy,ccy+xx); PEN(ccx+yy,ccy-xx); PEN(ccx-yy,ccy-xx);
            yy++; if (e2 < 0) e2 += 2*yy+1; else { xx--; e2 += 2*(yy-xx)+1; }
        }
    }
    #undef PEN
    #undef CVPX
}

/* Read a local file and decode it into the next inline-image slot. Returns the
 * slot index, or -1 (caller then falls back to a clickable link). */
static int decode_local_to_slot(browser_t *b, const char *path) {
    if (b->nimg >= IMG_SLOTS) return -1;
    uint8_t *buf = kmalloc(IMG_READ_MAX);
    if (!buf) return -1;
    long n = vfs_read(path, buf, IMG_READ_MAX);
    if (n <= 0) { kfree(buf); return -1; }
    int s = decode_bytes_to_slot(b, buf, (int)n);
    kfree(buf);
    return s;
}

/* Markdown->HTML and CSV->HTML converters live in a shared header so they can
 * be host-fuzzed off-target without dragging in the whole browser (see M1755
 * and tests/md/). url_ends() below stays here -- it is a general URL helper. */
#include "mdconv.h"

/* case-insensitive: does NUL-terminated `u` end with `ext`? */
static int url_ends(const char *u, const char *ext) {
    int lu = 0; while (u[lu]) lu++;
    int le = 0; while (ext[le]) le++;
    if (lu < le) return 0;
    for (int i = 0; i < le; i++) {
        char a = u[lu - le + i], b = ext[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return 1;
}

/* Request an async load of b->url. If the worker is busy, remember the intent
 * (b->want) and retry from browser_poll(), so a load is never silently dropped. */
static void browser_navigate(browser_t *b) {
    if (!b->raw || !b->text || !b->toks) return;
    b->bodyoff = 0; b->bodylen = 0;   /* clean baseline; HTML paths set the real region */
    b->ls_n = 0;                      /* fresh localStorage per page */
    b->in_n = 0; b->focus_id[0] = 0;  /* fresh input-field state per page */
    b->title_js_set = 0;              /* drop any document.title override on navigate (new page) */
    b->form_action[0] = 0;            /* and no carried-over form action */
    js_page_reset();                  /* drop the previous page's persistent JS globals */
    memset(b->det_open, 0xFF, sizeof(b->det_open));   /* <details> states unseeded until first render */
    if (!b->is_back) b->fwdn = 0;     /* a fresh navigation invalidates the forward stack */

    if (streqs(b->url, "home") || !b->url[0]) {       /* built-in start page, no net */
        if (b->loading) { set_status(b, "busy, retry"); return; }
        drop_remote_imgs(b);          /* no worker here: clear any prior page's remote-image table */
        if (!b->is_back && b->cur[0] && !streqs(b->cur, "home") && b->histn < 16)
            copy_url(b->hist[b->histn++], b->cur);
        b->is_back = 0; copy_url(b->url, "home"); copy_url(b->cur, "home");
        b->want = 0; b->scroll = 0;
        build_home(b);
        set_status(b, "home");
        return;
    }

    if (startsw(b->url, "file:")) {                   /* a local file, no net */
        if (b->loading) { set_status(b, "busy, retry"); return; }
        drop_remote_imgs(b);          /* no worker here: clear any prior page's remote-image table */
        if (!b->is_back && b->cur[0] && !streqs(b->cur, b->url) && b->histn < 16)
            copy_url(b->hist[b->histn++], b->cur);
        b->is_back = 0; copy_url(b->cur, b->url);
        b->want = 0; b->scroll = 0;
        /* A local image can be larger than the HTML buffer (a 24-bit BMP
         * screenshot is ~576 KB > RAW_MAX), so first read into a transient
         * buffer and try to decode it as an image; if it isn't one (or the
         * alloc fails), fall back to the HTML/text path on b->raw as before. */
        uint8_t *big = kmalloc(LOCAL_IMG_MAX);
        if (big) {
            long bn = vfs_read(b->url + 5, big, LOCAL_IMG_MAX);
            if (bn < 0) { kfree(big); b->ntok = 0; set_status(b, "file not found"); return; }
            if (try_image(b, big, (int)bn)) { kfree(big); set_status(b, "image"); return; }
            if (url_ends(b->url, ".md")) {                   /* Markdown -> HTML, then render normally */
                int hlen = md_to_html((const char *)big, (int)bn, b->raw, RAW_MAX - 1);
                kfree(big);
                b->raw[hlen] = 0; b->rawlen = hlen;
                b->bodyoff = 0; b->bodylen = hlen;
                parse_html(b, b->raw, hlen);
                set_status(b, "markdown");
                return;
            }
            if (url_ends(b->url, ".csv")) {                  /* CSV -> an HTML table */
                int hlen = csv_to_html((const char *)big, (int)bn, b->raw, RAW_MAX - 1);
                kfree(big);
                b->raw[hlen] = 0; b->rawlen = hlen;
                b->bodyoff = 0; b->bodylen = hlen;
                parse_html(b, b->raw, hlen);
                set_status(b, "csv");
                return;
            }
            long cp = bn < RAW_MAX - 1 ? bn : RAW_MAX - 1;   /* not an image: keep (capped) for text/HTML */
            memcpy(b->raw, big, (size_t)cp);
            kfree(big);
            b->raw[cp] = 0; b->rawlen = (int)cp;
        } else {
            long n0 = vfs_read(b->url + 5, b->raw, RAW_MAX - 1);
            if (n0 < 0) { b->ntok = 0; set_status(b, "file not found"); return; }
            b->raw[n0] = 0; b->rawlen = (int)n0;
            if (try_image(b, (const uint8_t *)b->raw, (int)n0)) { set_status(b, "image"); return; }
        }
        /* Strip a leading UTF-8 BOM (EF BB BF) before deciding HTML-vs-text, and
         * strip it from the content itself so nothing downstream renders it
         * (M1893). Second instance of the same bug class as the decode_image sniff
         * above: the whitespace skip below never accounted for a BOM, so a BOM'd
         * HTML file left *q pointing at 0xEF rather than '<' and the whole document
         * was handed to parse_text — the browser showed its raw markup as literal
         * text. Editors and web servers emit UTF-8 BOMs routinely, so this was not
         * an exotic input. Removing the bytes (rather than just stepping the sniff
         * pointer past them) also keeps them out of parse_text/parse_html output,
         * where they had been rendering as stray "???" glyphs. Images are untouched:
         * try_image already ran above, and no image format starts with a BOM. */
        if (b->rawlen >= 3 && (unsigned char)b->raw[0] == 0xEF
                           && (unsigned char)b->raw[1] == 0xBB
                           && (unsigned char)b->raw[2] == 0xBF) {
            memmove(b->raw, b->raw + 3, (size_t)(b->rawlen - 3) + 1);   /* +1 keeps the NUL */
            b->rawlen -= 3;
        }
        long n = b->rawlen;
        const char *q = b->raw; while (*q == ' ' || *q == '\n' || *q == '\r' || *q == '\t') q++;
        if (*q == '<') { b->bodyoff = 0; b->bodylen = (int)n; parse_html(b, b->raw, (int)n);  /* looks like HTML */
                         if (b->scriptlen > 0) run_page_scripts(b, 0, (int)n); }
        else           parse_text(b, b->raw, (int)n);  /* plain text */
        set_status(b, "local file");
        return;
    }

    if (!claim_fetch(b)) { b->want = 1; set_status(b, "queued..."); return; }
    b->want = 0;
    /* push the page we're leaving (unless this IS a Back, or a same-URL reload) */
    if (!b->is_back && b->cur[0] && !streqs(b->cur, b->url) && b->histn < 16)
        copy_url(b->hist[b->histn++], b->cur);
    b->is_back = 0;
    copy_url(b->cur, b->url);                  /* this is now the current page */
    b->ntok = 0; b->nlrec = 0; b->scroll = 0;
    set_status(b, "loading...");
}

void browser_back(browser_t *b) {
    if (!b || b->histn <= 0) return;
    /* M1621: mirror browser_forward's own `pushed` guard -- this used to push
     * onto the forward stack unconditionally and never undo it on either bail
     * path below, so a Back pressed while a fetch was already in flight (an
     * everyday occurrence, not an edge case) left a bogus duplicate `cur`
     * entry on `fwd[]` with nothing pushed to justify it, corrupting the
     * Forward button and, since the stack is capped at 16, eventually
     * squeezing out real forward history with junk. */
    int pushed = (b->cur[0] && b->fwdn < 16);  /* leaving page -> forward stack */
    if (pushed) copy_url(b->fwd[b->fwdn++], b->cur);
    const char *dest = b->hist[b->histn - 1];  /* peek the destination */

    if (streqs(dest, "home") || !dest[0] || startsw(dest, "file:")) {
        /* local page: render directly, no worker. Stay race-safe: if a fetch is
         * in flight, bail unchanged (same as the net path losing the claim). */
        uint64_t f = irq_save();
        if (g_busy || g_req) { irq_restore(f); if (pushed) b->fwdn--; return; }  /* fetch in flight: bail, undo */
        b->loading = 0;
        irq_restore(f);
        b->histn--;
        copy_url(b->url, dest);
        b->is_back = 1;                        /* navigate must not re-push history */
        browser_navigate(b);
        return;
    }

    /* network destination: set b->url to the target BEFORE claiming, so a worker
     * that picks up g_req in the gap can't fetch the stale (current) url. This
     * mirrors browser_navigate's set-then-claim ordering. */
    copy_url(b->url, dest);
    if (!claim_fetch(b)) { copy_url(b->url, b->cur); if (pushed) b->fwdn--; return; }  /* lost race: undo */
    b->histn--;                                /* pop only after a successful claim */
    b->is_back = 0;
    js_page_reset();                           /* this branch skips browser_navigate; drop the previous page's JS env so a script-less backed-to page doesn't reuse it */
    copy_url(b->cur, b->url);
    b->ntok = 0; b->nlrec = 0; b->scroll = 0;
    set_status(b, "loading...");
}

/* Forward: re-visit a page that Back left on the forward stack. Mirrors
 * browser_back but pops `fwd` and pushes the current page onto `hist` (so Back
 * returns here); the rest of the forward stack is kept for repeated Forwards. */
void browser_forward(browser_t *b) {
    if (!b || b->fwdn <= 0) return;
    const char *dest = b->fwd[b->fwdn - 1];    /* peek the destination */
    int pushed = (b->cur[0] && b->histn < 16); /* push the page we're leaving onto Back */
    if (pushed) copy_url(b->hist[b->histn++], b->cur);

    if (streqs(dest, "home") || !dest[0] || startsw(dest, "file:")) {
        uint64_t f = irq_save();
        if (g_busy || g_req) { irq_restore(f); if (pushed) b->histn--; return; }  /* fetch in flight: bail, undo */
        b->loading = 0;
        irq_restore(f);
        b->fwdn--;
        copy_url(b->url, dest);
        b->is_back = 1;                        /* navigate must not re-push hist or clear fwd */
        browser_navigate(b);
        return;
    }

    copy_url(b->url, dest);
    if (!claim_fetch(b)) { copy_url(b->url, b->cur); if (pushed) b->histn--; return; }  /* lost race: undo */
    b->fwdn--;
    b->is_back = 0;
    js_page_reset();
    copy_url(b->cur, b->url);
    b->ntok = 0; b->nlrec = 0; b->scroll = 0;
    set_status(b, "loading...");
}

void browser_go(browser_t *b, const char *url) {  /* navigate to a given URL */
    if (!b || !url) return;
    copy_url(b->url, url);
    browser_navigate(b);
}

/* Called by the WM each frame: when the worker has delivered bytes, parse them
 * here (on the WM thread). Returns 1 if the display changed. */
static void goto_href(browser_t *b, const char *href, int suppress_push);  /* fwd */
static int tok_matches(browser_t *b, tok_t *tk);                            /* fwd (in-page find) */

int browser_poll(browser_t *b) {
    int changed = 0;
    /* animated GIF: advance to the next frame once its delay (centiseconds, and
     * the PIT runs at 100 Hz so 1 tick == 1 cs) has elapsed, and ask for a redraw. */
    if (b->framebuf && b->nframes > 1) {
        uint64_t now = timer_ticks();
        int d = b->framedelay[b->curframe];
        if (d < 2) d = 10;                          /* clamp 0/too-fast to ~100ms, like browsers */
        if (now - b->frametick >= (uint64_t)d) {
            b->curframe = (b->curframe + 1) % b->nframes;
            b->img = b->framebuf + (long)b->curframe * b->imgw * b->imgh * 4;
            b->frametick = now;
            changed = 1;
        }
    }
    if (b->want && !b->loading) { browser_navigate(b); changed = 1; }  /* retry queued load */
    if (!b->need_parse) return changed;
    b->need_parse = 0;
    int n = b->http_n;
    if (n <= 0) {                               /* fetch failed (DNS/connect/TLS): render a clear error page, not a blank one */
        b->ntok = 0; b->redirects = 0;
        if (b->raw) {
            int p = 0; char *o = b->raw;
            const char *e1 = "<h2>Could not load page</h2><p>Could not reach <b>";
            const char *e2 = "</b>.</p><p>The host may not exist, the connection or TLS handshake failed, or the site refused our request. Check the address and your connection, then try again.</p>";
            for (const char *q = e1;     *q && p < RAW_MAX - 1; q++) o[p++] = *q;
            for (const char *q = b->url; *q && p < RAW_MAX - 1; q++) o[p++] = *q;
            for (const char *q = e2;     *q && p < RAW_MAX - 1; q++) o[p++] = *q;
            o[p] = 0;
            b->bodyoff = 0; b->bodylen = p;
            parse_html(b, o, p);                /* header-less HTML, like the local home page */
        }
        set_status(b, "failed");
        return 1;
    }

    if (n > 12 && b->raw[9] == '3') {               /* HTTP/1.x 3xx: follow Location */
        char loc[URL_MAX];
        if (b->redirects < 5 && http_find_loc(b->raw, n, loc, sizeof(loc))) {
            b->redirects++;
            set_status(b, "redirect...");
            goto_href(b, loc, 1);                   /* follow, replacing history */
            return 1;
        }
    }
    b->redirects = 0;                               /* reached a final page */

    int bodyoff = 0;
    for (int i = 0; i + 3 < n; i++)
        if (b->raw[i]=='\r'&&b->raw[i+1]=='\n'&&b->raw[i+2]=='\r'&&b->raw[i+3]=='\n') { bodyoff = i + 4; break; }
    int bodylen = n - bodyoff;
    if (bodyoff > 0 && http_is_chunked(b->raw, bodyoff))      /* de-chunk before parsing */
        bodylen = http_dechunk(b->raw + bodyoff, bodylen, RAW_MAX);
    if (try_image(b, (const uint8_t *)(b->raw + bodyoff), bodylen)) {  /* an image? */
        set_status(b, "image"); return 1;
    }
    b->bodyoff = bodyoff; b->bodylen = bodylen;          /* remember for click-time JS re-render */
    parse_html(b, b->raw + bodyoff, bodylen);
    if (b->scriptlen > 0) run_page_scripts(b, bodyoff, bodylen);   /* run inline <script> (once) */

    char st[40]; int v = n, k = 0, p = 0; char tmp[12];
    if (!v) tmp[k++] = '0'; while (v) { tmp[k++] = '0'+v%10; v/=10; }
    while (k) st[p++] = tmp[--k]; st[p++] = 'b';
    /* short TLS indicator (fits the narrow status area): "TLS*" = chain validated
     * to a trusted root CA; "TLS+" = the server proved leaf-key possession but the
     * chain isn't anchored to a known root; "TLS?" = a check failed. */
    const char *cs = b->chain_ok ? " TLS*"
                   : b->cert_status == 0 ? " TLS+"
                   : b->cert_status == -1 ? " TLS?" : 0;
    if (cs) for (int i = 0; cs[i] && p < 39; i++) st[p++] = cs[i];
    st[p] = 0;
    set_status(b, st);
    return 1;
}

/* Follow link id `id`, resolving its href against the current URL, then load. */
/* Resolve `href` (absolute / root-relative / relative) against the current URL
 * and navigate there. If suppress_push, replace the current history entry
 * rather than pushing (used for redirects, so Back doesn't loop). */
/* Collapse "." and ".." path segments in place, e.g. "/a/b/../c" -> "/a/c" and
 * "/a/./b" -> "/a/b" (M1636). `path` must start with '/'. goto_href's relative-
 * link resolution below used to build a path by straight concatenation with no
 * dot-segment removal at all, so a page using ../-relative links (an ordinary,
 * common pattern) navigated to the literal, uncollapsed URL instead of the
 * right one. A leading ".." past the root is dropped rather than erroring,
 * matching how real browsers clamp it. */
static void collapse_dot_segments(char *path) {
    /* M1771: normalize ONLY the path; a `/` or `.`/`..` inside a ?query or
     * #fragment is data, not a path segment, so split those off and re-append
     * them verbatim (was: the whole string was run through the segment splitter,
     * mangling e.g. "/r?url=http://x/y" -> "/r?url=http:/x/y"). */
    int plen = 0; while (path[plen] && path[plen] != '?' && path[plen] != '#') plen++;
    char qf[URL_MAX]; int qn = 0; for (int i = plen; path[i] && qn < URL_MAX-1; i++) qf[qn++] = path[i]; qf[qn] = 0;
    char out[URL_MAX]; int op = 0;
    int segstart[64]; int nseg = 0;   /* out[] offset of each kept segment's own '/' */
    int trail = plen > 0 && path[plen-1] == '/';   /* preserve a trailing slash (dir vs. file) of the PATH */
    const char *p = path, *pe = path + plen;
    while (p < pe) {
        while (p < pe && *p == '/') p++;
        const char *s = p; while (p < pe && *p != '/') p++;
        int len = (int)(p - s);
        if (len == 0) continue;
        if (len == 1 && s[0] == '.') continue;                         /* "." -> drop */
        if (len == 2 && s[0] == '.' && s[1] == '.') {                  /* ".." -> pop the previous segment */
            if (nseg > 0) { nseg--; op = segstart[nseg]; }
            continue;
        }
        if (op + len + 1 >= URL_MAX) break;
        if (nseg < 64) segstart[nseg++] = op;
        out[op++] = '/';
        for (int i = 0; i < len; i++) out[op++] = s[i];
    }
    if (op == 0) out[op++] = '/';                                      /* never produce an empty path */
    else if (trail && op < URL_MAX-1) out[op++] = '/';
    for (int i = 0; qf[i] && op < URL_MAX-1; i++) out[op++] = qf[i];   /* M1771: re-append ?query/#fragment untouched */
    out[op] = 0;
    int i = 0; while (out[i] && i < URL_MAX-1) { path[i] = out[i]; i++; } path[i] = 0;
}
static void goto_href(browser_t *b, const char *href, int suppress_push) {
    { const char *jp="javascript:"; int isjs=1; for (int k=0;k<11;k++) if (lc(href[k])!=jp[k]) { isjs=0; break; }
      if (isjs) { run_js_handler(b, href + 11); return; } }   /* javascript: (any case) runs, doesn't navigate */
    if (href[0] == '#') {                                /* in-page anchor: scroll to the element with that id */
        const char *id = href + 1;
        for (int i = 0; i < b->anc_n; i++)
            if (streqs(b->anc_id[i], id)) {
                int t = b->anc_tok[i];
                if (t < b->ntok) { b->scroll = b->toky[t] - 20; if (b->scroll < 0) b->scroll = 0; }
                return;
            }
        if (!id[0] || streqs(id, "top")) b->scroll = 0;  /* "#"/"#top" -> top; an unknown id stays put */
        return;
    }
    if (startsw(href, "mailto:")) return;

    char newurl[URL_MAX];
    if (startsw(href, "http://") || startsw(href, "https://") || startsw(href, "file:")) {  /* absolute */
        int i = 0; while (href[i] && i < URL_MAX-1) { newurl[i] = href[i]; i++; } newurl[i] = 0;
    } else {
        /* relative — resolve against the current page, KEEPING its scheme so a
         * link on an HTTPS page stays HTTPS (worker_fetch picks TLS by the
         * "https://" prefix; without it a relative link would drop to plain HTTP). */
        const char *cu = b->url;
        const char *scheme = startsw(cu, "https://") ? "https://" : "http://";
        if (startsw(cu, "http://")) cu += 7; else if (startsw(cu, "https://")) cu += 8;
        char host[96]; int hi = 0; while (cu[hi] && cu[hi] != '/' && hi < 95) { host[hi] = cu[hi]; hi++; } host[hi] = 0;

        int p = 0;
        for (const char *s = scheme; *s && p < URL_MAX-1; s++) newurl[p++] = *s;   /* scheme prefix */
        if (href[0] == '/' && href[1] == '/') {          /* protocol-relative //host/path */
            for (int i = 2; href[i] && p < URL_MAX-1; i++) newurl[p++] = href[i];
            newurl[p] = 0;
            copy_url(b->url, newurl);
            if (suppress_push) b->is_back = 1;
            browser_navigate(b);
            return;
        }
        for (int i = 0; host[i] && p < URL_MAX-1; i++) newurl[p++] = host[i];
        int path_start = p;   /* M1636: everything from here on is the path -- collapse ./ and ../ once it's built */
        if (href[0] == '/') {                            /* absolute path */
            for (int i = 0; href[i] && p < URL_MAX-1; i++) newurl[p++] = href[i];
        } else if (href[0] == '?') {                     /* M1771: query-only ref -> keep the base PATH, replace only the query (RFC 3986 5.3). `?page=2` on /a/b resolves to /a/b?page=2, not /a/?page=2 */
            const char *cp = cu + hi;                    /* base path incl leading '/' */
            if (!cp[0] && p < URL_MAX-1) newurl[p++] = '/';   /* empty base path -> "/" */
            for (int i = 0; cp[i] && cp[i] != '?' && cp[i] != '#' && p < URL_MAX-1; i++) newurl[p++] = cp[i];   /* base path, sans its own query/fragment */
            for (int i = 0; href[i] && p < URL_MAX-1; i++) newurl[p++] = href[i];   /* the new ?query (and any #fragment) */
        } else {                                         /* relative to current dir */
            const char *cp = cu + hi;                    /* current path incl leading '/' */
            int lastslash = 0;
            for (int i = 0; cp[i] && cp[i] != '?' && cp[i] != '#'; i++) if (cp[i] == '/') lastslash = i + 1;   /* M1771: the base directory is in the PATH only -- a '/' inside the base's ?query is not a separator */
            if (p < URL_MAX-1) newurl[p++] = '/';
            for (int i = 0; i < lastslash && cp[i] && p < URL_MAX-1; i++)
                if (!(i == 0 && cp[0] == '/')) newurl[p++] = cp[i];
            for (int i = 0; href[i] && p < URL_MAX-1; i++) newurl[p++] = href[i];
        }
        newurl[p] = 0;
        collapse_dot_segments(newurl + path_start);   /* M1636 */
    }
    copy_url(b->url, newurl);
    if (suppress_push) b->is_back = 1;          /* replace, don't push history */
    browser_navigate(b);
}

static void browser_follow(browser_t *b, int id) {
    if (id == NO_LINK || id >= b->nlink) return;
    int off = b->links[id].off, len = b->links[id].len;
    const char *hp = b->hrefs + off;
    /* a javascript: handler is code, not a URL — run the FULL slice; the URL_MAX
     * copy below would truncate a longer handler into a syntax error. */
    int isin = (len > 6); if (isin) for (int k = 0; k < 6; k++) if (lc(hp[k]) != "input:"[k]) { isin = 0; break; }
    if (isin) {                                          /* focus an <input> field for typing */
        int n = len - 6; if (n > 31) n = 31;
        for (int i = 0; i < n; i++) b->focus_id[i] = hp[6 + i];
        b->focus_id[n] = 0;
        if (!in_get(b, b->focus_id)) in_set(b, b->focus_id, "");   /* ensure a store slot exists */
        { const char *fv = in_get(b, b->focus_id); b->field_cur = fv ? (int)strlen(fv) : 0; }   /* caret at end */
        set_status(b, "type into the field, Enter when done");
        parse_html(b, b->raw + b->bodyoff, b->bodylen);  /* re-render to show the focus cursor */
        return;
    }
    int isdet = (len > 4); if (isdet) for (int k = 0; k < 4; k++) if (lc(hp[k]) != "det:"[k]) { isdet = 0; break; }
    if (isdet) {                                         /* toggle a <details> open/closed */
        int idx = 0; for (int k = 4; k < len; k++) if (hp[k] >= '0' && hp[k] <= '9') idx = idx * 10 + (hp[k] - '0');
        if (idx >= 0 && idx < 16) b->det_open[idx] = b->det_open[idx] ? 0 : 1;   /* flip (seeded by the render) */
        parse_html(b, b->raw + b->bodyoff, b->bodylen);
        return;
    }
    int ischk = (len > 6); if (ischk) for (int k = 0; k < 6; k++) if (lc(hp[k]) != "check:"[k]) { ischk = 0; break; }
    if (ischk) {                                         /* toggle a checkbox/radio */
        char cid[32]; int n = len - 6; if (n > 31) n = 31;
        for (int i = 0; i < n; i++) cid[i] = hp[6 + i];
        cid[n] = 0;
        const char *cur = in_get(b, cid);
        int turning_on = !(cur && streqs(cur, "on"));
        in_set(b, cid, turning_on ? "on" : "");                   /* flip; the re-render updates its submit name */
        if (turning_on) {                                         /* a radio turning on unchecks its group siblings */
            int as, ae; const char *tp; int tpl; const char *nm; int nml;
            if (dom_attr_region(b, cid, &as, &ae)
                && find_attr(b->raw + as, ae - as, "type", &tp, &tpl) && attr_eq(tp, tpl, "radio")
                && find_attr(b->raw + as, ae - as, "name", &nm, &nml) && nml > 0) {
                char grp[32]; int gn = nml; if (gn > 31) gn = 31; for (int i = 0; i < gn; i++) grp[i] = nm[i]; grp[gn] = 0;
                int myform = enclosing_form_start(b, as);         /* this radio's own <form>, computed fresh (not cached: a never-yet-clicked sibling may not even have a store slot yet) */
                for (int j = 0; j < b->in_n; j++) {                /* the previously-checked sibling has its name == group, in the SAME <form> (a same-named radio group in a different form is independent) */
                    if (streqs(b->in_id[j], cid) || !b->in_name[j][0] || !streqs(b->in_name[j], grp)) continue;
                    int as2, ae2;
                    if (dom_attr_region(b, b->in_id[j], &as2, &ae2) && enclosing_form_start(b, as2) == myform) b->in_val[j][0] = 0;
                }
            }
        }
        if (!fire_onchange(b, cid)) parse_html(b, b->raw + b->bodyoff, b->bodylen);   /* onchange (if any) re-renders */
        return;
    }
    int issel = (len > 7); if (issel) for (int k = 0; k < 7; k++) if (lc(hp[k]) != "selcyc:"[k]) { issel = 0; break; }
    if (issel) {                                         /* cycle a <select> to its next option */
        char sid[32]; int n = len - 7; if (n > 31) n = 31;
        for (int i = 0; i < n; i++) sid[i] = hp[7 + i];
        sid[n] = 0;
        const char *vals = 0;                            /* this select's '\n'-joined option values */
        for (int s = 0; s < b->sel_n; s++) if (streqs(b->sel_ids[s], sid)) { vals = b->sel_vals[s]; break; }
        if (vals && vals[0]) {
            char items[16][32]; int cnt = 0, sp = 0;     /* split the value list */
            for (int i = 0; cnt < 16; i++) {
                char c = vals[i];
                if (c == '\n' || c == 0) {
                    int il = i - sp; if (il > 31) il = 31;
                    for (int k = 0; k < il; k++){ items[cnt][k] = vals[sp + k]; } items[cnt][il] = 0;
                    cnt++; sp = i + 1;
                    if (c == 0) break;
                }
            }
            const char *cur = in_get(b, sid);            /* advance to the option after the current value (wrap) */
            int curidx = -1; if (cur) for (int k = 0; k < cnt; k++) if (streqs(items[k], cur)) { curidx = k; break; }
            if (cnt > 0) in_set(b, sid, items[(curidx + 1) % cnt]);   /* curidx<0 -> index 0 */
            if (!fire_onchange(b, sid)) parse_html(b, b->raw + b->bodyoff, b->bodylen);
        }
        return;
    }
    int issub = (len > 6); if (issub) for (int k = 0; k < 7; k++) if (lc(hp[k]) != "submit:"[k]) { issub = 0; break; }
    if (issub) {                                         /* a form submit: FORM:action?name=value&… (GET), scoped to the one owning <form> */
        int k; int subform = submit_link_form(hp, len, &k);
        char q[URL_MAX]; int p = 0;
        int al = len - k;                                /* the snapshotted action follows "submit:FORM:" */
        if (al > 0) { for (int i = 0; i < al && p < URL_MAX - 1; i++) q[p++] = hp[k + i]; }
        else { for (int i = 0; b->url[i] && b->url[i] != '?' && p < URL_MAX - 1; i++) q[p++] = b->url[i]; }  /* no action -> this page */
        int first = 1;
        for (int f = 0; f < b->in_n; f++) {              /* every named field IN THIS FORM becomes a query pair */
            if (!b->in_name[f][0]) continue;
            int asf, aef;
            if (!dom_attr_region(b, b->in_id[f], &asf, &aef) || enclosing_form_start(b, asf) != subform) continue;
            if (p < URL_MAX - 1) q[p++] = first ? '?' : '&';
            first = 0;
            p += url_encode(q + p, URL_MAX - 1 - p, b->in_name[f]);
            if (p < URL_MAX - 1) q[p++] = '=';
            p += url_encode(q + p, URL_MAX - 1 - p, b->in_val[f]);
        }
        q[p] = 0;
        b->focus_id[0] = 0;                              /* leave any field-typing mode */
        goto_href(b, q, 0);
        return;
    }
    int isjs = (len > 11); if (isjs) for (int k = 0; k < 11; k++) if (lc(hp[k]) != "javascript:"[k]) { isjs = 0; break; }
    if (isjs) {
        static char jsbuf[4096];
        int n = len - 11; if (n > (int)sizeof(jsbuf) - 1) n = (int)sizeof(jsbuf) - 1;
        for (int i = 0; i < n; i++) jsbuf[i] = hp[11 + i];
        jsbuf[n] = 0;
        run_js_handler(b, jsbuf);
        return;
    }
    int isev = (len > 6); if (isev) for (int k = 0; k < 6; k++) if (lc(hp[k]) != "event:"[k]) { isev = 0; break; }
    if (isev) {                                          /* event:ID -> fire the JS-assigned click handler for element ID */
        char eid[40]; int n = len - 6; if (n > 39) n = 39;
        for (int i = 0; i < n; i++) eid[i] = hp[6 + i];
        eid[n] = 0;
        run_js_event(b, eid, "click");
        return;
    }
    char href[URL_MAX]; int hl = len; if (hl > URL_MAX - 1) hl = URL_MAX - 1;
    for (int i = 0; i < hl; i++) href[i] = hp[i];
    href[hl] = 0;
    goto_href(b, href, 0);
}

/* ---- drawing ---- */
static void put_word(int x, int y, const char *s, int len, uint32_t fg, uint32_t bg, int scale) {
    char w[72]; if (len > 71) len = 71;
    for (int i = 0; i < len; i++) w[i] = s[i]; w[len] = 0;
    if (scale > 1) fb_text(x, y, w, fg, scale);
    else for (int i = 0; i < len; i++) fb_glyph(x + i*GW, y, w[i], fg, bg);
}
static void box(int x, int y, int w, int h, uint32_t c) {
    fb_fill_rect(x, y, w, 1, c); fb_fill_rect(x, y+h-1, w, 1, c);
    fb_fill_rect(x, y, 1, h, c); fb_fill_rect(x+w-1, y, 1, h, c);
}

/* Scratch row buffer for the <img> blits below: each pixel's colour is
 * data-dependent (alpha-blended per source pixel), so unlike fb_blit_scaled's
 * fixed-source-pixel memcpy trick, this file computes the row itself and
 * hands it to fb_row() for a single clip-and-resolve-once write instead of a
 * fb_pixel call per pixel. Sized past VBE_MAX_W (bochs_vbe.c, 1920) with
 * margin; static (BSS), not stack -- rendering is single-threaded so this is
 * safe, and a screen-width array doesn't belong on a guard-page-less stack. */
#define IMG_ROWBUF_MAX 4096
static uint32_t img_rowbuf[IMG_ROWBUF_MAX];

/* ---- float bands (M1928) ----------------------------------------------------
 * A floated image is an OBSTACLE: for the vertical range it occupies, the line
 * box is narrowed on its side, which is what makes text wrap around it. That is
 * the whole trick this renderer needs — it has no out-of-flow boxes, but it does
 * not need them for a float, only a per-line left/right inset.
 *
 * Bands are kept for the whole page (a page has very few floats), so the cost is
 * a walk over at most FBND_MAX entries per line. A line [y, y+lh) is obstructed
 * by a band [y0, y1) when they overlap at all. */
#define FBND_MAX 8
typedef struct { int y0, y1, edge, side; } fbnd_t;   /* side: 1 = left, 2 = right */

static int flt_left(const fbnd_t *f, int n, int cl, int y, int lh) {
    for (int i = 0; i < n; i++)
        if (f[i].side == 1 && y < f[i].y1 && y + lh > f[i].y0 && f[i].edge > cl) cl = f[i].edge;
    return cl;
}
static int flt_right(const fbnd_t *f, int n, int cr, int y, int lh) {
    for (int i = 0; i < n; i++)
        if (f[i].side == 2 && y < f[i].y1 && y + lh > f[i].y0 && f[i].edge < cr) cr = f[i].edge;
    return cr;
}
/* `clear`: drop below every float on the named side(s). mask bit0 = left, bit1 = right. */
static int flt_clearto(const fbnd_t *f, int n, int y, int mask) {
    for (int i = 0; i < n; i++)
        if ((mask & f[i].side) && f[i].y1 > y) y = f[i].y1;
    return y;
}

/* The `off` payload of the TK_MAXW_CLOSE matching the TK_MAXW_OPEN at index `i`,
 * or 0 if unmatched (M1910).
 *
 * max-height is carried on the CLOSE token, because that is where the renderer
 * needs `height`/`min-height`/padding-bottom. But suppressing the block background
 * under spilled content needs the cap at OPEN time, and the OPEN token's payload
 * is already fully spoken for (off = max-width | padding-top | padding-bottom, len
 * = width, link = h-padding, style = auto-margin + border-box bits). Rather than
 * add a token type, look the value up: a bounded integer walk with no painting,
 * which is the same thing the background does with its forward scan. */
static const tok_t *maxw_close_tok(const browser_t *b, int i) {
    int depth = 0;
    for (int j = i; j < b->ntok; j++) {
        if (b->toks[j].type == TK_MAXW_OPEN)  { depth++; continue; }
        if (b->toks[j].type == TK_MAXW_CLOSE) { if (--depth == 0) return &b->toks[j]; }
    }
    return 0;
}
static uint32_t maxw_close_off(const browser_t *b, int i) {
    const tok_t *c = maxw_close_tok(b, i);
    return c ? c->off : 0u;
}

void browser_render(browser_t *b, int x, int y, int w, int h) {
    uint32_t BG = 0xFFFFFF, page_fg = 0;
    int root_w = 0, root_ma = 0, root_mt = 0;   /* body/html width, auto-margins, margin-top (M1929) */
    for (int r = 0; r < b->n_css; r++) {                 /* page bg + default text colour from body/html (M1432, M1437) */
        sel_t *s = &b->css_sel[r];
        int is_root = !s->cls[0] && !s->id[0] && !s->attr[0] &&
            ((s->tag[0]=='b'&&s->tag[1]=='o'&&s->tag[2]=='d'&&s->tag[3]=='y'&&!s->tag[4]) ||
             (s->tag[0]=='h'&&s->tag[1]=='t'&&s->tag[2]=='m'&&s->tag[3]=='l'&&!s->tag[4]));
        if (is_root && b->css_bg[r])    BG = b->css_bg[r];
        if (is_root && b->css_color[r]) page_fg = b->css_color[r];   /* so a dark body{background} gets its light body{color} text (M1437) */
        /* body/html box geometry (M1929). `<body>` is consumed by a terminal
         * else-if in the tag parser and never reaches the generic element-scope
         * handler, so it can never own a box token the way a <div> does. It does
         * not need one: body's box IS the page's content column, so its width /
         * auto-margins / top margin are applied to that column directly below.
         * This is what makes `body{width:60vw;margin:15vh auto}` -- how real pages
         * (example.com included) centre themselves -- actually centre. */
        if (is_root && b->css_w[r])     root_w  = b->css_w[r];
        if (is_root && b->css_mauto[r]) root_ma = b->css_mauto[r];
        if (is_root && b->css_margin[r]) root_mt = b->css_margin[r];
    }
    fb_fill_rect(x, y, w, h, BG);

    /* address bar */
    fb_fill_rect(x, y, w, ADDR_H, 0xE7EAF0);
    fb_fill_rect(x, y + ADDR_H - 1, w, 1, 0x9AA3B2);
    int fy = y + 7;
    /* Back + Forward buttons (each greyed when its stack is empty) */
    uint32_t bbc = (b->histn > 0) ? 0x2C66D6 : 0xAAB2BE;
    uint32_t ffc = (b->fwdn  > 0) ? 0x2C66D6 : 0xAAB2BE;
    fb_fill_rect(x + 6, fy - 1, 18, 18, 0xF4F6FA); box(x + 6, fy - 1, 18, 18, 0xB4BCC8);
    put_word(x + 11, fy, "<", 1, bbc, 0xF4F6FA, 1);
    fb_fill_rect(x + 26, fy - 1, 18, 18, 0xF4F6FA); box(x + 26, fy - 1, 18, 18, 0xB4BCC8);
    put_word(x + 31, fy, ">", 1, ffc, 0xF4F6FA, 1);
    int fx = x + 50, fw = w - 132;
    fb_fill_rect(fx, fy, fw, 16, 0xFFFFFF);
    box(fx - 1, fy - 1, fw + 2, 18, b->editing ? 0x2C66D6 : 0xB4BCC8);
    int maxc = (fw - 6) / GW, ulen = (int)strlen(b->url);
    int cur = b->editing ? b->url_cur : ulen;            /* keep the caret in view */
    if (cur < 0) cur = 0; if (cur > ulen) cur = ulen;
    int from = (cur > maxc) ? cur - maxc : 0;            /* scroll so the caret is visible */
    for (int i = from; i < ulen && (i - from) <= maxc; i++)
        fb_glyph(fx + 4 + (i - from)*GW, fy, b->url[i], 0x102030, 0xFFFFFF);
    if (b->editing) fb_fill_rect(fx + 4 + (cur - from)*GW, fy + 1, 1, 14, 0x2C66D6);
    put_word(x + w - 78, fy, b->status, (int)strlen(b->status), 0x55606E, 0xE7EAF0, 1);

    /* content */
    int cl = x + 10, cr = x + w - 14, ct = y + ADDR_H + 6, cb = y + h - 8;
    /* Captured BEFORE the root box narrows the column (M1932): vw/vh are defined
     * against the VIEWPORT, not against body's used width. Capturing after meant
     * each navigation to a `body{width:60vw}` page re-based vw on the previous
     * page's narrowed column -- 980 -> 588 -> 352 -> 211, shrinking monotonically. */
    g_vp_w = cr - cl; g_vp_h = cb - ct;
    /* Apply the root box to the content column (M1929): a narrower width, centred
     * when both horizontal margins are auto (bits 0|1), plus any top margin. */
    if (root_w > 0 && root_w < cr - cl) {
        int slack = (cr - cl) - root_w;
        if ((root_ma & 3) == 3) cl += slack / 2;        /* margin: _ auto -> centre */
        else if (root_ma & 1)   cl += slack;            /* margin-left:auto -> right */
        cr = cl + root_w;
    }
    if (root_mt > 0) ct += root_mt;
    b->view_h = cb - ct;

    int cx = cl, cy = ct - b->scroll, curlh = 18;
    b->nlrec = 0;
    b->nwrec = 0;

    if (b->loading) { fb_text(cl, ct + 12, "Loading...", 0x4A6A9A, 2); return; }

    if (b->help_on) {                               /* '?' key-reference overlay (any key returns) */
        int ly = ct + 6;
        fb_text(cl, ly, "BROWSER KEYS  (any key returns)", 0x2C66D6, 2); ly += 28;
        const char *L[] = {
            "h home    r reload    < back    > forward",
            "Ctrl-F or \\  find     e or /  edit address",
            "Tab / n  next link     Enter  follow link",
            "+ -  zoom     0  reset     g top     G bottom",
            "space / b  page     j k  scroll a line",
            "s  save page    u  view source    a  bookmark",
            "i  cert info    m  reader mode    ?  this help",
        };
        for (unsigned i = 0; i < sizeof(L)/sizeof(L[0]); i++) { fb_text(cl, ly, L[i], 0x202830, 1); ly += 20; }
        return;
    }

    if (b->viewsource) {                            /* 'u': raw HTML source, wrapped */
        int maxcols = (cr - cl) / GW; if (maxcols < 1) maxcols = 1;
        int cyv = ct - b->scroll, col = 0;
        for (int i = 0; i < b->rawlen; i++) {
            char ch = b->raw[i];
            if (ch == '\n') { cyv += 16; col = 0; continue; }
            if (ch == '\t') ch = ' ';
            if (ch < 32 || ch > 126) ch = '.';
            if (col >= maxcols) { cyv += 16; col = 0; }
            if (cyv >= ct && cyv + 14 <= cb) fb_glyph(cl + col*GW, cyv, ch, 0x206020, BG);
            col++;
        }
        b->content_h = (cyv + 16) - (ct - b->scroll);
    } else if (b->img) {                            /* decoded image: blit scaled to width */
        int maxw = cr - cl, destw = b->imgw, desth = b->imgh;
        if (destw > maxw && destw > 0) { desth = (int)((long)desth * maxw / destw); destw = maxw; }
        b->content_h = desth;
        int rw = destw > IMG_ROWBUF_MAX ? IMG_ROWBUF_MAX : destw;
        for (int dy = 0; dy < desth; dy++) {
            int py = ct + dy - b->scroll;
            if (py < ct || py >= cb) continue;      /* clip to the content area */
            int sy = (int)((long)dy * b->imgh / (desth ? desth : 1));
            const uint8_t *srow = b->img + (long)sy * b->imgw * 4;
            for (int dx = 0; dx < rw; dx++) {
                int sx = (int)((long)dx * b->imgw / (destw ? destw : 1));
                const uint8_t *pp = srow + (long)sx * 4;
                int a = pp[3];                       /* alpha-blend over white */
                int r  = (pp[0]*a + 255*(255-a)) / 255;
                int g  = (pp[1]*a + 255*(255-a)) / 255;
                int bl = (pp[2]*a + 255*(255-a)) / 255;
                img_rowbuf[dx] = ((uint32_t)r<<16)|((uint32_t)g<<8)|(uint32_t)bl;
            }
            fb_row(cl, py, rw, img_rowbuf);
        }
    } else {
    int bstk_y[16]; uint32_t bstk_c[16]; int bstk_w[16]; int bstk_s[16]; int bstk_i[16], bsp = 0;   /* CSS border boxes: y_top+sides+left-indent pushed on OPEN, rect stroked on CLOSE */
    int bstk_x[16];   /* cx at TK_BORDER_OPEN (x_start for single-line tight-box detection) */
    int bstk_ob[16];  /* this border's element owns a block box -> stroke the border box (M1901) */
    int render_rpad = 0;   /* right-edge inset while inside full border boxes, so their text wraps short of the box (M916 horizontal padding) */
    int flex_depth = 0;    /* >0 while inside a display:flex container: child block-breaks become horizontal gaps (M927) */
    int flex_gap = 18;     /* px gap between flex items (from CSS `gap`, M930; 18 default) */
    /* Saved content column per active constrained block, restored on close. Stores
     * the ORIGINAL cl/cr rather than a single symmetric inset, because §10.3.3 can
     * produce ASYMMETRIC margins (e.g. `margin-left:auto` right-aligns) which a
     * single offset cannot express (M1896). */
    int mxcl[16], mxcr[16], mxpl[16], mxpr[16], mxsp = 0;
    /* The padding box of the innermost constrained block, for background fills.
     * With no constrained block active it is just the full column. (M1897) */
    int pbl = 0, pbr = 0;
    int pbtop = 0;            /* padding-top of the active block box, so a background
                               * can start ABOVE the content it wraps (M1900) */
    int mxpt[16];
    int mxy[16];              /* content-top y per open block box, for `height` (M1904) */
    int mxcap[16];            /* absolute y where this box's max-height cap ends; 0x7FFFFFFF = uncapped (M1910) */
    int mxclip[16];           /* absolute y to CLIP content at (overflow:hidden); 0x7FFFFFFF = no clip (M1917) */
    fbnd_t fbnd[FBND_MAX]; int nfbnd = 0;   /* active float obstacles (M1928) */
    int bgsp = 0;   /* block-bg nesting depth: counted so a nested TK_BG_OPEN's forward-scan stops at ITS matching close (M993) */
    for (int t = 0; t < b->ntok && t < TOK_MAX; t++) {   /* t < TOK_MAX: provably in-bounds for the per-token arrays */
        tok_t *tk = &b->toks[t];
        if (tk->type == TK_BORDER_OPEN) { if (bsp < 16) { int sd = tk->len ? tk->len : 15; bstk_y[bsp] = cy - 4; bstk_c[bsp] = tk->off & 0xFFFFFFu; bstk_w[bsp] = tk->style ? tk->style : 1; bstk_s[bsp] = sd; bstk_i[bsp] = tk->link; bstk_x[bsp] = cx; bstk_ob[bsp] = (int)((tk->off >> 24) & 1); bsp++; if (sd == 15) render_rpad += BORDER_PAD; } continue; }   /* y_top includes 4px top padding; full box insets the wrap-right; bstk_x tracks x-start for inline tight-box */
        if (tk->type == TK_BORDER_CLOSE) {
            if (bsp > 0) { bsp--; int y0 = bstk_y[bsp], y1 = cy + curlh + 3, w = bstk_w[bsp], sd = bstk_s[bsp]; uint32_t bc = bstk_c[bsp];   /* sd: 1=top 2=right 4=bottom 8=left; +3 bottom padding */
                if (sd == 15 && render_rpad >= BORDER_PAD) render_rpad -= BORDER_PAD;   /* leaving a full box: undo its wrap-right inset */
                int xl = cl + bstk_i[bsp];                                          /* left edge follows the block's own indent (blockquote / margin-left) */
                int xr = cr;                                                        /* right edge (content column by default) */
                /* If this element owns a block box, its border is the OUTERMOST edge:
                 * stroke the padding box, not the content box, and extend to the
                 * bottom padding band (which MAXW_CLOSE has not applied yet). Before
                 * M1901 a bordered+padded block stroked inside its own background. */
                if (bstk_ob[bsp] && mxsp > 0) {
                    xl = pbl; xr = pbr;
                    y1 += (int)(tk->off & 0xFF);
                }
                /* Single-line (inline) element: cy hasn't advanced past the opening line — stroke
                 * a tight box around just the content's horizontal span instead of full-width.
                 * bstk_y[bsp] = cy_at_open - 4, so cy_at_open = bstk_y[bsp] + 4; if cy still
                 * equals that value no line-wrap/break occurred and the element is inline. */
                int cy_at_open = bstk_y[bsp] + 4;
                int inline_el = (cy == cy_at_open);   /* true: no vertical advance between open+close */
                if (inline_el) {
                    /* tight box: [x_start-pad .. cx+pad] × [y0 .. y0+curlh+7] */
                    int x0t = bstk_x[bsp] - BORDER_PAD;   /* left of tight box */
                    int x1t = cx + BORDER_PAD;             /* right of tight box (cx is after last word) */
                    if (x0t < xl) x0t = xl;                /* never exceed block's own indent */
                    int yy0t = y0 < ct ? ct : y0, yy1t = y1 > cb ? cb : y1;
                    if (yy1t > yy0t) {
                        if (sd & 8) fb_fill_rect(x0t, yy0t, w, yy1t - yy0t, bc);       /* left  */
                        if (sd & 2) fb_fill_rect(x1t - w, yy0t, w, yy1t - yy0t, bc);   /* right */
                    }
                    if ((sd & 1) && y0 >= ct && y0 <= cb) fb_fill_rect(x0t, y0, x1t - x0t, w, bc);             /* top */
                    if ((sd & 4) && y1 - w >= ct && y1 - w <= cb) fb_fill_rect(x0t, y1 - w, x1t - x0t, w, bc); /* bottom */
                } else {
                    /* Multi-line (block) element: full-width behavior unchanged */
                    int yy0 = y0 < ct ? ct : y0, yy1 = y1 > cb ? cb : y1;
                    if (yy1 > yy0) {
                        if (sd & 8) fb_fill_rect(xl, yy0, w, yy1 - yy0, bc);            /* left edge (viewport-clipped) */
                        if (sd & 2) fb_fill_rect(xr - w, yy0, w, yy1 - yy0, bc);        /* right edge */
                    }
                    if ((sd & 1) && y0 >= ct && y0 <= cb) fb_fill_rect(xl, y0, xr - xl, w, bc);                /* top edge */
                    if ((sd & 4) && y1 - w >= ct && y1 - w <= cb) fb_fill_rect(xl, y1 - w, xr - xl, w, bc);     /* bottom edge */
                }
            }
            continue;
        }
        if (tk->type == TK_FLEX_OPEN)  {
            if (cx > cl) { cy += curlh; cx = cl; curlh = 18; }   /* start the row on its own line */
            flex_depth++; flex_gap = tk->off ? (int)tk->off : 18;   /* per-container gap */
            if (tk->style) {   /* justify-content: forward-scan THIS row's item-widths (ww) and gap count (nb) */
                int z = b->zoom > 0 ? b->zoom : 1, ww = 0, nb = 0, d2 = 1;
                for (int u = t + 1; u < b->ntok && u < TOK_MAX && d2 > 0; u++) {
                    tok_t *tu = &b->toks[u];
                    if (tu->type == TK_FLEX_OPEN) d2++;
                    else if (tu->type == TK_FLEX_CLOSE) d2--;
                    else if (d2 == 1 && tu->type == TK_WORD) ww += (tu->len + 1) * GW * z;   /* word + space (base size) */
                    else if (d2 == 1 && (tu->type == TK_BREAK || tu->type == TK_PARA)) nb++;   /* one gap per inter-item break */
                }
                int avail = cr - cl;
                if (tk->style == 3) {   /* space-between/around: widen the gap to fill the free space */
                    if (nb > 0 && ww < avail) flex_gap = (avail - ww) / nb;
                } else {                /* center (1) / end (2): keep gaps, offset the whole row */
                    int total = ww + nb * flex_gap;
                    if (total > 0 && total < avail) cx = cl + ((tk->style == 1) ? (avail - total) / 2 : (avail - total));
                }
            }
            continue;
        }
        if (tk->type == TK_FLEX_CLOSE) { if (flex_depth > 0) flex_depth--; cy += curlh; cx = cl; curlh = 18; continue; }   /* end the row */
        if (tk->type == TK_MAXW_OPEN)  {   /* narrow + centre the content column for this block */
            /* `clear` drops the cursor below every float on the named side(s)
             * before the box is placed, which is the whole point of the property:
             * it is how a page ends a float's text-wrap region. (M1928) */
            { int cmask = (tk->style >> 3) & 3;
              if (cmask) { int ny = flt_clearto(fbnd, nfbnd, cy, cmask);
                           if (ny > cy) { cy = ny; cx = cl; curlh = 18; } } }
            if (cx > cl) { cy += curlh; curlh = 18; }
            if (mxsp < 16) { mxcl[mxsp] = cl; mxcr[mxsp] = cr; mxpl[mxsp] = pbl; mxpr[mxsp] = pbr;
                             mxpt[mxsp] = pbtop; mxsp++;
                             box_solve_column(tk, &cl, &cr, &pbl, &pbr);
                             /* Open the top padding band: content starts below it, and
                              * the background (emitted next) reaches back up over it. */
                             pbtop = box_pad_top(tk); cy += pbtop;
                             mxy[mxsp - 1] = cy;          /* content top, for `height` (M1904) */
                             /* Where this box's max-height cap falls, so content that
                              * spills past it can be painted WITHOUT the box's
                              * background — the background belongs to the box, and the
                              * box stopped at the cap. (M1910) */
                             mxcap[mxsp - 1] = 0x7FFFFFFF;
                             { uint32_t cof = maxw_close_off(b, t);
                               int cap = (int)((cof >> 12) & 0xFFFu);
                               if (cap > 0) {
                                   int cc = ((cof & 0x100u) != 0)      /* border-box: cap includes padding */
                                          ? cap - pbtop - (int)(cof & 0xFF) : cap;
                                   if (cc < 0) cc = 0;
                                   mxcap[mxsp - 1] = cy + cc;
                               } }
                             /* overflow:hidden — clip content to the box's declared
                              * bottom (M1917). The bottom comes from `height` or
                              * `max-height`, whichever is set (the smaller if both);
                              * overflow:hidden on an AUTO-height box clips nothing,
                              * because the box grows to fit its content by definition. */
                             mxclip[mxsp - 1] = 0x7FFFFFFF;
                             { const tok_t *ct = maxw_close_tok(b, t);
                               if (ct && (ct->off & (1u << 24))) {
                                   int hgt = (int)ct->len, cap = (int)((ct->off >> 12) & 0xFFFu);
                                   int mnh = (int)ct->link;          /* min-height */
                                   int box = (hgt > 0 && cap > 0) ? (hgt < cap ? hgt : cap)
                                           : (hgt > 0 ? hgt : cap);
                                   /* §10.7 order, matching what TK_MAXW_CLOSE actually
                                    * draws: max caps the height, then min overrides it.
                                    * Without this a min-height:70 + max-height:20 box is
                                    * DRAWN 70px tall but CLIPPED at 20px, leaving 50px of
                                    * the box blank. (M1926) */
                                   if (mnh > 0 && mnh > box) box = mnh;
                                   if (box > 0) {
                                       int cc = ((ct->off & 0x100u) != 0)
                                              ? box - pbtop - (int)(ct->off & 0xFF) : box;
                                       if (cc < 0) cc = 0;
                                       mxclip[mxsp - 1] = cy + cc;
                                   }
                               } } }
            cx = cl; continue;
        }
        if (tk->type == TK_MAXW_CLOSE) {
            int cpadb = (int)(tk->off & 0xFF);
            cy += curlh + cpadb;                   /* + padding-bottom band (M1900) */
            /* A declared `height` fixes the block's bottom edge (M1904): stretch down
             * to it when the content came up short. Under box-sizing:border-box the
             * declared height INCLUDES the vertical padding, so peel that off to get
             * the content height. Content TALLER than `height` still overflows, which
             * matches CSS — it does not clip without `overflow`. */
            int hspec = (int)tk->len, minh = (int)tk->link;
            int maxh = (int)((tk->off >> 12) & 0xFFFu);        /* max-height (M1910) */
            if ((hspec > 0 || minh > 0 || maxh > 0) && mxsp > 0) {
                int bb = (tk->off & 0x100u) != 0;      /* border-box: heights include padding */
                int top = mxy[mxsp - 1];
                /* The content height the flow actually produced. cy already includes
                 * the bottom padding band added just above, so peel it back off. */
                int nch = cy - cpadb - top; if (nch < 0) nch = 0;
                int ch = (hspec > 0) ? hspec : nch;
                if (hspec > 0 && bb) { ch = hspec - pbtop - cpadb; if (ch < 0) ch = 0; }
                /* §10.7 applies max-height FIRST and then min-height, so min wins
                 * over a smaller max — that ordering is the spec's, not a tiebreak. */
                if (maxh > 0) {
                    int cmax = bb ? (maxh - pbtop - cpadb) : maxh;
                    if (cmax < 0) cmax = 0;
                    if (ch > cmax) ch = cmax;
                }
                /* min-height raises the used content height (§10.7); it wins over a
                 * smaller declared `height`, which is the spec's precedence. */
                if (minh > 0) {
                    int cmin = bb ? (minh - pbtop - cpadb) : minh;
                    if (cmin < 0) cmin = 0;
                    if (cmin > ch) ch = cmin;
                }
                int target = top + ch + cpadb;
                /* `height`/`min-height` only ever GROW the box: content taller than a
                 * declared height overflows it rather than being squeezed. max-height
                 * is the one property here that SHRINKS the advance — the box stops at
                 * the cap, the content already painted below it spills out, and what
                 * follows starts at the cap and overlaps the spill. That overlap is
                 * not a compromise: it is what `overflow: visible` renders. (M1910) */
                if (cy < target || (maxh > 0 && cy > target)) cy = target;
            }
            if (mxsp > 0) { --mxsp; cl = mxcl[mxsp]; cr = mxcr[mxsp]; pbl = mxpl[mxsp]; pbr = mxpr[mxsp]; pbtop = mxpt[mxsp]; }
            cx = cl; curlh = 18; continue;
        }
        if (tk->type == TK_BG_OPEN) {
            /* Forward-scan to the matching TK_BG_CLOSE, faithfully mirroring the main loop's
             * vertical advance, to find this block's y_bottom. Then fill ONE contiguous rect
             * behind the whole block BEFORE its content paints (correct z-order; covers para
             * spacing, <hr>/images and empty lines that a per-line band would leave gapped).
             * Local copies (sc?/scl/scr/slh) so the real cursor is untouched; bias toward NOT
             * overestimating (an overestimate would paint over the FOLLOWING block's bg). */
            uint32_t col = tk->off & 0xFFFFFFu;
            int scy = cy, scx = cx, slh = curlh, scl = cl, scr = cr;
            int srp = render_rpad, sfd = flex_depth, sfg = flex_gap, depth = 1;
            int smxcl[16], smxcr[16], smxpt[16], smxy[16], smxsp = 0;
            /* The scan starts at BG_OPEN, and MAXW_OPEN for THIS element was emitted
             * just BEFORE it — so the enclosing box never appears in this window and
             * the stack below is empty when its MAXW_CLOSE arrives. Seed the box's
             * geometry from the live cursor: at BG_OPEN, cy is already past
             * MAXW_OPEN's top-padding advance, so it IS the content top, and pbtop is
             * this box's padding-top. Missing this is why `height` silently did
             * nothing at first — the main loop stretched cy, but the background's
             * height comes from THIS scan, which skipped the stretch. (M1904) */
            int stop0 = scy, sptop0 = pbtop;
            int sbfull[16], sbsp = 0;   /* per nested border: was it a full box (so undo its wrap-right inset on close), mirroring the real loop's render_rpad bookkeeping */
            for (int u = t + 1; u < b->ntok && u < TOK_MAX && depth > 0; u++) {
                tok_t *tu = &b->toks[u];
                if (tu->type == TK_BG_OPEN) { depth++; continue; }
                if (tu->type == TK_BG_CLOSE) { depth--; continue; }
                if (tu->type == TK_BORDER_OPEN) { int full = (tu->len ? tu->len : 15) == 15; if (sbsp < 16) sbfull[sbsp++] = full; if (full) srp += BORDER_PAD; continue; }
                if (tu->type == TK_BORDER_CLOSE) { if (sbsp > 0 && sbfull[--sbsp] && srp >= BORDER_PAD) srp -= BORDER_PAD; continue; }   /* edges stroked after content (no vertical advance); undo the full-box wrap-right inset, like the real loop */
                if (tu->type == TK_FLEX_OPEN)  { if (scx > scl) { scy += slh; scx = scl; slh = 18; } sfd++; sfg = tu->off ? (int)tu->off : 18; continue; }
                if (tu->type == TK_FLEX_CLOSE) { if (sfd > 0) sfd--; scy += slh; scx = scl; slh = 18; continue; }
                /* Must use the SAME solver as the main loop above, or a block's
                 * background rect drifts away from its text (M1896). */
                if (tu->type == TK_MAXW_OPEN)  { if (scx > scl) { scy += slh; slh = 18; } if (smxsp < 16) { smxcl[smxsp] = scl; smxcr[smxsp] = scr; smxsp++; box_solve_column(tu, &scl, &scr, 0, 0); smxpt[smxsp-1] = box_pad_top(tu); scy += box_pad_top(tu); smxy[smxsp-1] = scy; } scx = scl; continue; }
                /* slh = 0, not 18: this close already consumed the block's last line
                 * box into scy, and the caller finishes with `y_bottom = scy + slh`.
                 * Leaving the usual 18px next-line reset here double-counted a line
                 * height onto every constrained block's measured bottom — invisible
                 * until M1900's padding band made the resulting asymmetry obvious.
                 * Any content that follows inside the same background recomputes slh
                 * from its own tokens, so zeroing it is safe. */
                if (tu->type == TK_MAXW_CLOSE) {
                    int spadb = (int)(tu->off & 0xFF);
                    scy += slh + spadb;
                    /* Mirror the main loop's `height` stretch, or a fixed-height
                     * block's background stops at its content. For the ENCLOSING box
                     * the stack is empty (its OPEN predates this window), so fall back
                     * to the seeded geometry. (M1904) */
                    int shspec = (int)tu->len, sminh = (int)tu->link;
                    int smaxh = (int)((tu->off >> 12) & 0xFFFu);   /* max-height (M1910) */
                    if (shspec > 0 || sminh > 0 || smaxh > 0) {
                        int base = (smxsp > 0) ? smxy[smxsp-1]  : stop0;
                        int ptop = (smxsp > 0) ? smxpt[smxsp-1] : sptop0;
                        int sbb  = (tu->off & 0x100u) != 0;
                        int snch = scy - spadb - base; if (snch < 0) snch = 0;
                        int sch  = (shspec > 0) ? shspec : snch;
                        if (shspec > 0 && sbb) { sch = shspec - ptop - spadb; if (sch < 0) sch = 0; }
                        if (smaxh > 0) {                          /* cap, then min (§10.7 order) */
                            int scmax = sbb ? (smaxh - ptop - spadb) : smaxh;
                            if (scmax < 0) scmax = 0;
                            if (sch > scmax) sch = scmax;
                        }
                        if (sminh > 0) {
                            int scmin = sbb ? (sminh - ptop - spadb) : sminh;
                            if (scmin < 0) scmin = 0;
                            if (scmin > sch) sch = scmin;
                        }
                        int starget = base + sch + spadb;
                        /* Same asymmetry as the main loop: only max-height shrinks, so
                         * the BACKGROUND stops at the cap while the spilled content
                         * paints past it. (M1910) */
                        if (scy < starget || (smaxh > 0 && scy > starget)) scy = starget;
                    }
                    if (smxsp > 0) { --smxsp; scl = smxcl[smxsp]; scr = smxcr[smxsp]; }
                    scx = scl; slh = 0; continue;
                }
                if (tu->type == TK_BREAK) { if (sfd > 0) { if (scx > scl) scx += sfg; continue; } scy += slh + tu->off; scx = scl; slh = 18; continue; }
                if (tu->type == TK_PARA)  { if (sfd > 0) { if (scx > scl) scx += sfg; continue; } scy += slh + 8 + tu->off; scx = scl; slh = 18; continue; }
                if (tu->type == TK_HR)    { scy += slh; scy += 12; scx = scl; slh = 18; continue; }
                if (tu->type == TK_IMG)   {
                    int idx = tu->link;
                    if (idx >= 0 && idx < b->nimg && b->imgs[idx]) {
                        int iw = b->imgsw[idx], ih = b->imgsh[idx];
                        int aw = tu->off, ah = tu->len, maxw = scr - scl, destw, desth;
                        if (aw > 0 || ah > 0) { destw = aw > 0 ? aw : (int)((long)ah * iw / (ih ? ih : 1)); desth = ah > 0 ? ah : (int)((long)aw * ih / (iw ? iw : 1)); }
                        else { destw = iw; desth = ih; }
                        if (destw > maxw && destw > 0) { desth = (int)((long)desth * maxw / destw); destw = maxw; }
                        if (desth > IMG_MAX_H && desth > 0) { destw = (int)((long)destw * IMG_MAX_H / desth); desth = IMG_MAX_H; }
                        if (scx > scl) { scy += slh; scx = scl; }
                        scy += desth + 6; scx = scl; slh = 18;
                    }
                    continue;
                }
                /* TK_WORD: replicate scale/line-height, wrap test, and cx advance */
                int zm2 = b->zoom > 0 ? b->zoom : 1;
                int tsc2 = (u < TOK_MAX) ? b->tokscale[u] : 0;
                int sc2 = (tsc2 ? tsc2 : scale_for(tu->style)) * zm2;
                int tlh2 = (u < TOK_MAX) ? b->toklh[u] : 0;
                int lh2 = tlh2 ? (tlh2 * zm2) : ((tsc2 ? (16 * tsc2 + 2) : lineh_for(tu->style)) * zm2);
                int wpx2 = tu->len * GW * sc2; if (wpx2 > scr - scl) wpx2 = scr - scl;
                { int s_cr = flt_right(fbnd, nfbnd, scr, scy, slh);
                  int s_cl = flt_left(fbnd, nfbnd, scl, scy, slh);
                  if (scx < s_cl) scx = s_cl;
                  if (scx + wpx2 > s_cr - srp && scx > s_cl) {
                      scy += slh; slh = 18;
                      scx = flt_left(fbnd, nfbnd, scl, scy, slh);
                  } }
                if (lh2 > slh) slh = lh2;
                scx += wpx2 + GW * sc2;
            }
            int y_bottom = scy + slh;   /* bottom of the last line of the block */
            int yy0 = cy < ct ? ct : cy, yy1 = y_bottom > cb ? cb : y_bottom;
            /* Paint the PADDING box, not the content box: a padded block's
             * background must extend around its text (CSS 2.1 §14.2). (M1897) */
            { int own_box = ((tk->off >> 24) & 1) && mxsp > 0;   /* see the emit site */
              int bx = own_box ? pbl : cl, bw = (own_box ? pbr : cr) - bx;
              /* Reach back up over the top padding band the block box opened, so
               * the background covers the padding box vertically too (M1900). */
              int ytop = own_box ? (yy0 - pbtop) : yy0;
              if (ytop < ct) ytop = ct;
              if (yy1 > ytop && bw > 0) fb_fill_rect(bx, ytop, bw, yy1 - ytop, col); }
            if (bgsp < 16) bgsp++;
            continue;
        }
        if (tk->type == TK_BG_CLOSE) { if (bgsp > 0) bgsp--; continue; }
        if (tk->type == TK_BREAK) { if (flex_depth > 0) { if (cx > cl) cx += flex_gap; continue; } cy += curlh + tk->off; curlh = 18; cx = flt_left(fbnd, nfbnd, cl, cy, curlh); continue; }   /* in flex: break -> horizontal gap between items */
        if (tk->type == TK_PARA)  { if (flex_depth > 0) { if (cx > cl) cx += flex_gap; continue; } cy += curlh + 8 + tk->off; curlh = 18; cx = flt_left(fbnd, nfbnd, cl, cy, curlh); continue; }
        if (tk->type == TK_HR) {
            cy += curlh;
            if (cy + 4 >= ct && cy + 4 <= cb) fb_fill_rect(cl, cy + 4, cr - cl, 1, 0xC8CED8);
            cy += 12; cx = cl; curlh = 18; continue;
        }
        if (tk->type == TK_IMG) {                       /* inline image: blit on its own line */
            int idx = tk->link;
            if (idx >= 0 && idx < b->nimg && b->imgs[idx]) {
                int iw = b->imgsw[idx], ih = b->imgsh[idx];
                int aw = tk->off, ah = tk->len;          /* explicit <img> width/height, 0=natural */
                int maxw = cr - cl, destw, desth;
                if (aw > 0 || ah > 0) {                  /* honour specified size, fill from aspect */
                    destw = aw > 0 ? aw : (int)((long)ah * iw / (ih ? ih : 1));
                    desth = ah > 0 ? ah : (int)((long)aw * ih / (iw ? iw : 1));
                } else { destw = iw; desth = ih; }
                if (destw > maxw && destw > 0) { desth = (int)((long)desth * maxw / destw); destw = maxw; }
                if (desth > IMG_MAX_H && desth > 0) { destw = (int)((long)destw * IMG_MAX_H / desth); desth = IMG_MAX_H; }
                int flt = tk->style;                     /* 1 = float:left, 2 = float:right (M1928) */
                if (!flt && cx > cl) { cy += curlh; cx = cl; }   /* drop to a fresh line */
                /* block image honours the enclosing text-align: centre/right shift the
                 * blit x within [cl, cr] (same offset math as the word path). align 0
                 * (left, the default) -> x0 == cl, so existing pages are byte-identical;
                 * clamped >= cl so a too-wide image stays pinned left. */
                int x0 = cl;
                if (flt) {
                    /* Place against the current line's left/right edge, already
                     * inset by any earlier float, then register the obstacle. The
                     * vertical cursor is deliberately NOT advanced: a float is out
                     * of flow, so the text that follows keeps its own line and is
                     * merely narrowed by the band below. */
                    int lcl = flt_left(fbnd, nfbnd, cl, cy, desth);
                    int lcr = flt_right(fbnd, nfbnd, cr, cy, desth);
                    x0 = (flt == 1) ? lcl : lcr - destw;
                    if (x0 < cl) x0 = cl;
                    if (nfbnd < FBND_MAX) {
                        fbnd[nfbnd].y0 = cy; fbnd[nfbnd].y1 = cy + desth + 4;   /* +4: a little gutter */
                        fbnd[nfbnd].edge = (flt == 1) ? x0 + destw + 6 : x0 - 6;
                        fbnd[nfbnd].side = flt; nfbnd++;
                    }
                }
                int ialn = (t < TOK_MAX) ? b->tokalign[t] : 0;
                if (!flt && ialn) {
                    int ioff = (ialn == 1) ? (cr - cl - destw) / 2 : (cr - cl - destw);
                    if (ioff < 0) ioff = 0;
                    x0 = cl + ioff;
                }
                if (t < TOK_MAX) b->toky[t] = cy - (ct - b->scroll);
                int rw = destw > IMG_ROWBUF_MAX ? IMG_ROWBUF_MAX : destw;
                for (int dy = 0; dy < desth; dy++) {
                    int py = cy + dy;
                    if (py < ct || py >= cb) continue;   /* clip to content area */
                    int sy = (int)((long)dy * ih / (desth ? desth : 1));
                    const uint8_t *srow = b->imgs[idx] + (long)sy * iw * 4;
                    for (int dx = 0; dx < rw; dx++) {
                        int sx = (int)((long)dx * iw / (destw ? destw : 1));
                        const uint8_t *pp = srow + (long)sx * 4;
                        int a = pp[3];                   /* alpha-blend over white */
                        int r  = (pp[0]*a + 255*(255-a)) / 255;
                        int g  = (pp[1]*a + 255*(255-a)) / 255;
                        int bl = (pp[2]*a + 255*(255-a)) / 255;
                        img_rowbuf[dx] = ((uint32_t)r<<16)|((uint32_t)g<<8)|(uint32_t)bl;
                    }
                    fb_row(x0, py, rw, img_rowbuf);
                }
                if (flt) { cx = flt_left(fbnd, nfbnd, cl, cy, curlh); }   /* out of flow: cy unchanged */
                else { cy += desth + 6; cx = cl; curlh = 18; }
            }
            continue;
        }

        int zm = b->zoom > 0 ? b->zoom : 1;                 /* content zoom (1..4) */
        int tsc = (t < TOK_MAX) ? b->tokscale[t] : 0;       /* CSS font-size override (0 = use style default) */
        int sc = (tsc ? tsc : scale_for(tk->style)) * zm;
        int tlh = (t < TOK_MAX) ? b->toklh[t] : 0;          /* CSS line-height override in px (0 = use style default) */
        int lh = tlh ? (tlh * zm) : ((tsc ? (16 * tsc + 2) : lineh_for(tk->style)) * zm);
        int wpx = tk->len * GW * sc; if (wpx > cr - cl) wpx = cr - cl;
        /* Float-aware line box (M1928): the right edge is pulled in by any
         * right float covering this line, and a wrapped line restarts at the
         * left edge a left float allows — which is what makes text flow around
         * a floated image instead of through it. Both collapse to plain cl/cr
         * when nothing is floated, so unfloated pages render byte-identically. */
        { int lcr = flt_right(fbnd, nfbnd, cr, cy, curlh);
          int lcl = flt_left(fbnd, nfbnd, cl, cy, curlh);
          if (cx < lcl) cx = lcl;                       /* start clear of a left float */
          if (cx + wpx > lcr - render_rpad && cx > lcl) {
              cy += curlh; curlh = 18;
              cx = flt_left(fbnd, nfbnd, cl, cy, curlh);
          } }
        if (lh > curlh) curlh = lh;
        /* at a line start (cx==cl): apply the line's left-indent (<blockquote>) and, for
         * center/right text-align, look ahead over the words that fit on the line
         * (replicating the wrap test) and shift cx. indent 0 + align 0 (the defaults) ->
         * cx stays cl, so ordinary pages are byte-for-byte unchanged; everything is bounded
         * by ntok and cx only ever moves within [cl, cr). A line takes its first token's value. */
        if (cx == cl) {
            int indent = (t < TOK_MAX) ? b->tokindent[t] : 0;
            if (indent > (cr - cl) - GW * 4) indent = (cr - cl) - GW * 4;   /* leave room for text */
            if (indent < 0) indent = 0;
            int ls = cl + indent;
            int al = (t < TOK_MAX) ? b->tokalign[t] : 0;
            if (al) {
                int avail = cr - ls, probe = ls, endx = ls;
                for (int u = t; u < b->ntok; u++) {
                    tok_t *pk = &b->toks[u];
                    if (pk->type != TK_WORD) break;          /* break/para/hr/img end the line */
                    int pts = (u < TOK_MAX) ? b->tokscale[u] : 0;
                    int ps = (pts ? pts : scale_for(pk->style)) * zm;
                    int pw = pk->len * GW * ps; if (pw > avail) pw = avail;
                    if (probe + pw > cr - render_rpad && probe > ls) break;  /* would wrap -> line ends here */
                    endx = probe + pw; probe = endx + GW * ps;
                }
                int off = (al == 1) ? (avail - (endx - ls)) / 2 : (avail - (endx - ls));
                if (off < 0) off = 0;
                cx = ls + off;
            } else cx = ls;
            /* block background (0x02000000) is now painted as ONE contiguous rect by the
             * TK_BG_OPEN forward-scan above — no per-line band here (it left vertical gaps). */
        }

        /* record every link's content-space y (even off-screen) so keyboard
         * link selection can scroll it into view */
        if (tk->style == STY_LINK && tk->link != NO_LINK && tk->link < LINK_MAX)
            b->linky[tk->link] = cy - (ct - b->scroll);
        if (t < TOK_MAX) b->toky[t] = cy - (ct - b->scroll);   /* per-token y for in-page find */

        if (cy >= ct && cy + lh <= cb + 2) {
            int selected = (tk->style == STY_LINK && tk->link == b->sel);
            /* in-page find: highlight every match; the current one stronger */
            int matched = (b->find_tok >= 0 && tk->type == TK_WORD && tok_matches(b, tk));
            int current = (t == b->find_tok);
            uint32_t fg = color_for(tk->style);
            if (page_fg && tk->style == STY_NORMAL) fg = page_fg & 0xFFFFFF;   /* body{color} is the default body-text colour (M1437) */
            if (b->tokcolor[t] & 0x01000000)               /* explicit colour (CSS / <font>) overrides the default — incl. for links (M1435), so a{color} wins over the default blue */
                fg = b->tokcolor[t] & 0xFFFFFF;
            /* content background: explicit CSS background-color wins over the <mark> default */
            uint32_t cbg = (b->tokbg[t] & 0x01000000) ? (b->tokbg[t] & 0xFFFFFF)
                         : (tk->style == STY_MARK ? 0xFFF080 : BG);
            /* Content below a max-height cap is OUTSIDE its box, so it must not carry
             * that box's background: a glyph paints its own background rect, and
             * without this the spilled text keeps the block colour and the block looks
             * like it never clamped at all. The effective cap is the INNERMOST one
             * (the min over the open boxes), since a nested box can be capped by an
             * ancestor as well as by itself. (M1910) */
            if (mxsp > 0 && (b->tokbg[t] & 0x02000000)) {
                int capy = 0x7FFFFFFF;
                for (int k = 0; k < mxsp; k++) if (mxcap[k] < capy) capy = mxcap[k];
                /* Test the glyph's BOTTOM edge, not its top: the line box that
                 * STRADDLES the cap starts inside the box but paints through it, and
                 * keying on the top left that line's background painting 12px past
                 * the cap. The box's own background rect (clamped by the forward
                 * scan) already covers everything legitimately inside. */
                if (cy + lh > capy) cbg = BG;
            }
            uint32_t wbg = selected ? 0xFFE9A8 : (current ? 0x7FC0FF : (matched ? 0xCDE8FF : cbg));
            /* overflow:hidden (M1917): a line whose top has passed the innermost clip
             * bottom is outside its box and must not paint at all. Clipped at LINE
             * granularity -- a partially visible line is dropped rather than
             * half-drawn, because this renderer has no pixel-level clip region.
             * Implemented by zeroing the draw length, which suppresses every drawing
             * call below (glyphs, faux-bold overstrike, strike-through, underlines)
             * without duplicating the guard on each one. */
            int clipy_ = 0x7FFFFFFF;
            for (int k = 0; k < mxsp; k++) if (mxclip[k] < clipy_) clipy_ = mxclip[k];
            int maxc = (cr - cx) / (GW * sc); if (maxc < 0) maxc = 0;
            int dl = tk->len > maxc ? maxc : tk->len;      /* clip to content width (no h-scroll) */
            /* BOTTOM edge, not the top: the line that STRADDLES the clip bottom
             * starts inside the box but paints past it, and keying on the top left
             * exactly that line visible below the box — caught on screen, not by
             * the first version of the test. Same boundary the M1910 background
             * suppression had to get right. */
            if (cy + lh > clipy_) dl = 0;                  /* vertically clipped away */
            int drawpx = dl * GW * sc;
            /* mouse text selection: highlight selected word tokens (white on blue) */
            if (b->tsel0 >= 0 && tk->type == TK_WORD) {
                int a0 = b->tsel0, z0 = b->tsel1; if (z0 < a0) { int sw = a0; a0 = z0; z0 = sw; }
                if (t >= a0 && t <= z0) { wbg = 0x2C66D6; fg = 0xFFFFFF; }
            }
            if (tk->type == TK_WORD && b->nwrec < LREC_MAX)   /* record the word's rect for hit-testing */
                b->wrec[b->nwrec++] = (lrec_t){ (int16_t)(cx - x), (int16_t)(cy - y),
                                                (int16_t)drawpx, (int16_t)lh, (uint16_t)t };
            int yo = tk->style == STY_SUB ? 5 : tk->style == STY_SUP ? -4 : 0;   /* sub/superscript vertical shift */
            put_word(cx, cy + yo, b->text + tk->off, dl, fg, wbg, sc);
            if (tk->style == STY_BOLD) {                   /* faux-bold: transparent 1px overstrike */
                char w[72]; int ln = dl > 71 ? 71 : dl;
                for (int i = 0; i < ln; i++) w[i] = b->text[tk->off + i];
                w[ln] = 0;
                fb_text(cx + 1, cy, w, fg, sc);
            }
            if (tk->style == STY_STRIKE) fb_fill_rect(cx, cy + 7, drawpx, 1, fg);   /* strike-line through the text */
            if (b->tokul[t] == 1 && tk->style != STY_LINK) fb_fill_rect(cx, cy + 15, drawpx, 1, fg);   /* underline (text-decoration:underline / <u>); 2 = none */
            if (tk->style == STY_LINK) {
                if (b->tokul[t] != 2) fb_fill_rect(cx, cy + 15, drawpx, 1, fg);   /* link underline, unless text-decoration:none */
                if (selected) box(cx - 1, cy - 1, drawpx + 2, lh, 0xC08000);  /* selection outline */
                if (tk->link != NO_LINK && b->nlrec < LREC_MAX)   /* clickable */
                    b->lrec[b->nlrec++] = (lrec_t){ (int16_t)(cx - x), (int16_t)(cy - y),
                                                    (int16_t)drawpx, (int16_t)lh, tk->link };
            }
        }
        cx += wpx + GW * sc;
    }

    int bottom = cy + curlh;
    b->content_h = bottom - (ct - b->scroll);
    }                                           /* end token-render branch */

    int maxscroll = b->content_h - b->view_h; if (maxscroll < 0) maxscroll = 0;
    if (b->scroll > maxscroll) b->scroll = maxscroll;
    if (b->scroll < 0) b->scroll = 0;

    if (b->content_h > b->view_h) {
        int track = cb - ct, sbx = x + w - 6;
        fb_fill_rect(sbx, ct, 4, track, 0xD8DCE4);
        int th = track * b->view_h / b->content_h; if (th < 16) th = 16;
        int ty = ct + (track - th) * b->scroll / (maxscroll ? maxscroll : 1);
        fb_fill_rect(sbx, ty, 4, th, 0x8893A4);
    }
}

/* Reconstruct the page as readable text (words + line breaks) and write it to
 * PAGE.TXT on the FAT32 disk — a tiny "reader mode" / offline save. */
static void browser_save(browser_t *b) {
    if (b->ntok == 0) { set_status(b, "nothing to save"); return; }
    int cap = TEXT_MAX + 4096;
    char *out = kmalloc(cap);
    if (!out) { set_status(b, "save: nomem"); return; }
    int p = 0;
    for (int t = 0; t < b->ntok && p < cap - 8; t++) {
        tok_t *tk = &b->toks[t];
        if (tk->type == TK_BORDER_OPEN || tk->type == TK_BORDER_CLOSE ||
            tk->type == TK_FLEX_OPEN   || tk->type == TK_FLEX_CLOSE ||
            tk->type == TK_MAXW_OPEN   || tk->type == TK_MAXW_CLOSE ||
            tk->type == TK_BG_OPEN     || tk->type == TK_BG_CLOSE) continue;   /* structural markers, not text */
        if (tk->type == TK_WORD) {
            for (int i = 0; i < tk->len && p < cap - 2; i++) out[p++] = b->text[tk->off + i];
            out[p++] = ' ';
        } else if (tk->type == TK_PARA) { out[p++] = '\n'; out[p++] = '\n'; }
        else if (tk->type == TK_HR)     { for (const char *s = "\n----\n"; *s; s++) out[p++] = *s; }
        else                            { out[p++] = '\n'; }   /* TK_BREAK */
    }
    long n = vfs_write("PAGE.TXT", out, (unsigned long)p);
    kfree(out);
    set_status(b, n < 0 ? "save failed" : "saved PAGE.TXT");
}

/* Append the current page's URL to the SITES bookmarks file (read on the home
 * page, M67). Closes the loop: browse -> 'a' -> it shows up as a bookmark. */
static void browser_bookmark(browser_t *b) {
    if (!startsw(b->cur, "http://") && !startsw(b->cur, "https://") && !startsw(b->cur, "file:")) {
        set_status(b, "not bookmarkable"); return;        /* don't bookmark "home"/empty */
    }
    static char sb[2048];
    long n = vfs_read("SITES", sb, sizeof(sb) - URL_MAX - 2);
    if (n < 0) n = 0;
    sb[n] = 0;
    /* skip if this exact URL is already a line in SITES */
    for (int i = 0; i <= (int)n; ) {
        int j = i; while (j < (int)n && sb[j] != '\n' && sb[j] != '\r') j++;
        char save = sb[j]; sb[j] = 0;
        if (streqs(sb + i, b->cur)) { sb[j] = save; set_status(b, "already saved"); return; }
        sb[j] = save; i = j + 1;
    }
    int p = (int)n;
    if (p > 0 && sb[p-1] != '\n') sb[p++] = '\n';          /* ensure newline-separated */
    for (int i = 0; b->cur[i] && p < (int)sizeof(sb) - 2; i++) sb[p++] = b->cur[i];
    sb[p++] = '\n';
    long w = vfs_write("SITES", sb, (unsigned long)p);
    set_status(b, w < 0 ? "bookmark failed" : "bookmarked");
}

/* Move the keyboard link selection by `dir` (+1 next / -1 prev), wrapping, then
 * scroll it into view and show its target href in the status line. This makes
 * the browser fully keyboard-drivable (and testable without a mouse). */
static void select_link(browser_t *b, int dir) {
    if (b->nlink <= 0) { set_status(b, "no links"); return; }
    int s = b->sel;
    if (s == NO_LINK || s < 0 || s >= b->nlink) s = (dir > 0) ? 0 : b->nlink - 1;
    else { s += dir; if (s < 0) s = b->nlink - 1; else if (s >= b->nlink) s = 0; }
    b->sel = s;
    if (s < LINK_MAX && b->linky[s] >= 0) {              /* only if laid out this page */
        b->scroll = b->linky[s] - 20; if (b->scroll < 0) b->scroll = 0;
    }
    char st[40]; int p = 0, hl = b->links[s].len, off = b->links[s].off;  /* show Enter target */
    for (int i = 0; i < hl && p < (int)sizeof(st) - 1; i++) st[p++] = b->hrefs[off + i];
    st[p] = 0;
    set_status(b, st);
}

/* ---- in-page find ---- */
static int tok_matches(browser_t *b, tok_t *tk) {       /* token text contains findq (ci)? */
    int qn = 0; while (b->findq[qn]) qn++;
    if (qn == 0 || tk->len < qn) return 0;
    for (int s = 0; s + qn <= tk->len; s++) {
        int j = 0;
        while (j < qn && lc(b->text[tk->off + s + j]) == lc(b->findq[j])) j++;
        if (j == qn) return 1;
    }
    return 0;
}
/* Find a matching word token starting at `start` and stepping by `dir` (+1 next
 * / -1 previous), wrapping, and scroll to it. */
static void do_find(browser_t *b, int start, int dir) {
    if (!b->findq[0]) { set_status(b, "find: type text"); return; }
    if (b->ntok <= 0) { b->find_tok = -1; set_status(b, "no text"); return; }
    for (int n = 0; n < b->ntok; n++) {
        int t = ((start + dir * n) % b->ntok + b->ntok) % b->ntok;
        if (b->toks[t].type == TK_WORD && tok_matches(b, &b->toks[t])) {
            b->find_tok = t;
            if (t < TOK_MAX) { b->scroll = b->toky[t] - 30; if (b->scroll < 0) b->scroll = 0; }
            char st[40]; int p = 0; const char *pre = "found: ";
            while (*pre && p < 39) st[p++] = *pre++;
            for (int i = 0; b->findq[i] && p < 39; i++) st[p++] = b->findq[i];
            st[p] = 0; set_status(b, st);
            return;
        }
    }
    b->find_tok = -1; set_status(b, "not found");
}
/* Show "find: <query>" in the status line while typing. */
static void find_prompt(browser_t *b) {
    char st[40]; int p = 0; const char *pre = "find: ";
    while (*pre && p < 39) st[p++] = *pre++;
    for (int i = 0; b->findq[i] && p < 39; i++) st[p++] = b->findq[i];
    st[p] = 0; set_status(b, st);
}

/* Does the address-bar text look like a web-search query rather than a URL?
 * A scheme (http/https/file), the home keyword, or a dotted host -> navigate;
 * a space or no dot at all (e.g. "operating systems", "weather") -> search. */
static int looks_like_search(const char *s) {
    if (startsw(s, "http://") || startsw(s, "https://") || startsw(s, "file:")) return 0;
    if (!s[0] || streqs(s, "home")) return 0;
    int hasdot = 0, hasspace = 0;
    for (int i = 0; s[i]; i++) { if (s[i] == '.') hasdot = 1; if (s[i] == ' ') hasspace = 1; }
    return hasspace || !hasdot;
}
/* Rewrite the address-bar query into a DuckDuckGo HTML search URL (in place). */
static void make_search_url(char *url) {
    char q[URL_MAX]; int p = 0;
    const char *pfx = "https://html.duckduckgo.com/html/?q=";
    for (int i = 0; pfx[i] && p < URL_MAX - 1; i++) q[p++] = pfx[i];
    p += url_encode(q + p, URL_MAX - 1 - p, url);
    q[p] = 0;
    copy_url(url, q);
}

/* Middle-click paste (WM passes the clipboard text): into the focused <input>
 * field if one is focused, otherwise into the address bar (entering edit mode,
 * appending to what's there). Control chars / newlines are dropped — URLs and
 * field values are single-line. */
void browser_paste(browser_t *b, const char *s, int n) {
    if (!b || n <= 0) return;
    if (b->focus_id[0]) {                               /* insert at the focused field's caret */
        const char *cur = in_get(b, b->focus_id);
        char t[IN_VLEN]; int k = 0;
        if (cur) while (cur[k] && k < IN_VLEN-1) { t[k] = cur[k]; k++; }
        t[k] = 0;
        int fc = b->field_cur; if (fc < 0) fc = 0; if (fc > k) fc = k;
        for (int i = 0; i < n && k < IN_VLEN-2; i++) {  /* shift the tail right, drop in each char */
            char ch = s[i]; if (ch < 32 || ch >= 127) continue;
            for (int j = k; j > fc; j--) t[j] = t[j-1];
            t[fc++] = ch; t[++k] = 0;
        }
        b->field_cur = fc; in_set(b, b->focus_id, t);
        if (!fire_handler(b, b->focus_id, "oninput")) parse_html(b, b->raw + b->bodyoff, b->bodylen);
    } else {                                            /* paste into the address bar (at the caret) */
        if (!b->editing) { b->editing = 1; b->url[0] = 0; b->url_cur = 0; }  /* a fresh paste replaces the bar */
        b->edit_fresh = 0;
        int len = (int)strlen(b->url), uc = b->url_cur; if (uc > len) uc = len;
        for (int i = 0; i < n && len < URL_MAX - 1; i++) {
            char ch = s[i]; if (ch < 32 || ch >= 127) continue;
            for (int j = len; j > uc; j--) b->url[j] = b->url[j-1];
            b->url[uc++] = ch; b->url[++len] = 0;
        }
        b->url_cur = uc;                                /* caret after the pasted text */
    }
}

/* Right-click: copy the URL of the link under the cursor into `out` (the WM then
 * puts it on the clipboard). Returns the href length, or 0 if not over a real
 * link. Internal pseudo-links (javascript:/submit:/event:) are skipped. */
int browser_rclick(browser_t *b, int rx, int ry, char *out, int max) {
    if (!b || ry < ADDR_H || max < 2) return 0;
    for (int i = 0; i < b->nlrec; i++) {
        lrec_t *L = &b->lrec[i];
        if (rx >= L->x && rx < L->x + L->w && ry >= L->y && ry < L->y + L->h) {
            int id = L->link;
            if (id < 0 || id >= b->nlink) return 0;
            const char *h = b->hrefs + b->links[id].off; int hl = b->links[id].len;
            static const char *skip[] = { "javascript:", "submit:", "event:" };
            for (int s = 0; s < 3; s++) {
                int sl = 0; while (skip[s][sl]) sl++;
                if (hl >= sl) { int m = 1; for (int k = 0; k < sl; k++) if (lc(h[k]) != skip[s][k]) { m = 0; break; } if (m) return 0; }
            }
            int n = 0; for (; n < hl && n < max - 1; n++) out[n] = h[n];
            out[n] = 0;
            set_status(b, "link copied");
            return n;
        }
    }
    return 0;
}

/* ---- mouse text selection (WM-driven; word granularity) ------------------ */
static int browser_hit_word(browser_t *b, int rx, int ry) {
    for (int i = 0; i < b->nwrec; i++) {
        lrec_t *W = &b->wrec[i];
        if (rx >= W->x && rx < W->x + W->w && ry >= W->y && ry < W->y + W->h) return W->link;
    }
    return -1;
}
void browser_sel_begin(browser_t *b, int rx, int ry) {
    if (!b) return;
    b->tsel0 = b->tsel1 = browser_hit_word(b, rx, ry);   /* -1 if not on a word */
}
void browser_sel_extend(browser_t *b, int rx, int ry) {
    if (!b) return;
    int t = browser_hit_word(b, rx, ry);
    if (t >= 0) { if (b->tsel0 < 0) b->tsel0 = t; b->tsel1 = t; }
}
void browser_sel_clear(browser_t *b) { if (b) b->tsel0 = b->tsel1 = -1; }
/* Double-click: select the single word token under (rx,ry) and copy it to `out`. */
int browser_sel_word(browser_t *b, int rx, int ry, char *out, int max) {
    if (!b) return 0;
    int t = browser_hit_word(b, rx, ry);
    if (t < 0 || t >= b->ntok) { b->tsel0 = b->tsel1 = -1; return 0; }
    b->tsel0 = b->tsel1 = t;                            /* highlight just this word */
    tok_t *tk = &b->toks[t];
    int n = 0;
    for (int k = 0; k < tk->len && n < max - 1; k++) out[n++] = b->text[tk->off + k];
    out[n] = 0;
    return n;
}

/* ---- draggable scrollbar (coords relative to the browser's x,y origin) ---- */
int browser_in_scrollbar(browser_t *b, int rx, int ry, int w, int h) {
    if (!b || b->content_h <= b->view_h) return 0;     /* no scrollbar when it all fits */
    int sbx = w - 6, ct = ADDR_H + 6, cb = h - 8;
    return rx >= sbx - 4 && rx <= sbx + 6 && ry >= ct && ry <= cb;
}
void browser_scroll_track(browser_t *b, int ry, int h) {
    if (!b) return;
    int ct = ADDR_H + 6, cb = h - 8, track = cb - ct;
    if (track <= 0) return;
    int maxscroll = b->content_h - b->view_h; if (maxscroll < 0) maxscroll = 0;
    /* M1641: mirror render()'s own thumb-height formula so dragging is the exact
     * inverse of where the thumb is actually drawn -- this used to map ry against
     * the FULL track, while render() only ever moves the thumb within
     * (track - th), leaving the thumb a few percent off the cursor after a drag
     * (worst on short pages where th is large relative to track). */
    int th = (b->content_h > 0) ? track * b->view_h / b->content_h : track; if (th < 16) th = 16;
    int range = track - th; if (range < 1) range = 1;
    int pos = ry - ct; if (pos < 0) pos = 0; if (pos > range) pos = range;
    b->scroll = maxscroll * pos / range;               /* render clamps */
}
/* Release: copy the selected token range to `out` (words joined by spaces, a
 * newline at each block break). Returns the length, or 0 for a non-drag click. */
int browser_sel_commit(browser_t *b, char *out, int max) {
    if (!b || b->tsel0 < 0 || b->tsel1 < 0 || b->tsel0 == b->tsel1) return 0;   /* need a real span */
    int a = b->tsel0, z = b->tsel1; if (z < a) { int t = a; a = z; z = t; }
    int n = 0;
    for (int t = a; t <= z && t < b->ntok && n < max - 1; t++) {
        tok_t *tk = &b->toks[t];
        if (tk->type == TK_WORD) {
            if (n > 0 && out[n-1] != '\n' && n < max - 1) out[n++] = ' ';
            for (int k = 0; k < tk->len && n < max - 1; k++) out[n++] = b->text[tk->off + k];
        } else if ((tk->type == TK_BREAK || tk->type == TK_PARA) && n > 0 && out[n-1] != '\n' && n < max - 1) {
            out[n++] = '\n';
        }
    }
    while (n > 0 && (out[n-1] == ' ' || out[n-1] == '\n')) n--;   /* trim trailing whitespace */
    out[n] = 0;
    return n;
}

void browser_key(browser_t *b, int c) {
    if (b->help_on) { b->help_on = 0; return; }         /* any key dismisses the help overlay */
    if (b->focus_id[0]) {                               /* typing into a focused <input> field */
        if ((c == '\n' || c == '\r') && is_textarea(b, b->focus_id)) {   /* textarea: Enter inserts a newline (not submit) */
            const char *cur = in_get(b, b->focus_id); char t[IN_VLEN]; int n=0;
            if (cur) { while (cur[n] && n<IN_VLEN-2) { t[n]=cur[n]; n++; } } t[n]=0;
            if (b->field_cur > n) b->field_cur = n;
            if (n < IN_VLEN-2) {
                for (int i = n; i > b->field_cur; i--) t[i] = t[i-1];
                t[b->field_cur] = '\n'; t[n+1] = 0; b->field_cur++;
                in_set(b, b->focus_id, t);
                if (!fire_handler(b, b->focus_id, "oninput")) parse_html(b, b->raw + b->bodyoff, b->bodylen);
            }
            return;
        }
        if (c == '\n' || c == '\r' || c == 27) {
            char fid[32]; { int k=0; while (b->focus_id[k] && k<31) { fid[k]=b->focus_id[k]; k++; } fid[k]=0; }   /* the field losing focus */
            int myform = -1; { int asf, aef; if (dom_attr_region(b, fid, &asf, &aef)) myform = enclosing_form_start(b, asf); }
            b->focus_id[0] = 0;                          /* leave typing mode */
            if (c != 27) {                               /* Enter (not Esc): submit THIS field's own form, if it has a submit button */
                for (int i = 0; i < b->nlink; i++) {
                    const char *h = b->hrefs + b->links[i].off; int hl = b->links[i].len;
                    int sub = (hl > 6); if (sub) for (int k = 0; k < 7; k++) if (lc(h[k]) != "submit:"[k]) { sub = 0; break; }
                    if (sub && submit_link_form(h, hl, 0) == myform) { browser_follow(b, i); return; }
                }
            }
            set_status(b, "");
            if (!fire_onchange(b, fid)) parse_html(b, b->raw + b->bodyoff, b->bodylen);   /* onchange fires on blur; it re-renders */
        }
        else if (c == 0x13 || c == 0x14 || c == 0x01 || c == 0x05) {   /* caret: left/right/Home/End */
            const char *cur = in_get(b, b->focus_id); int n = cur ? (int)strlen(cur) : 0;
            if (b->field_cur > n) b->field_cur = n;
            if (c == 0x13) { if (b->field_cur > 0) b->field_cur--; }
            else if (c == 0x14) { if (b->field_cur < n) b->field_cur++; }
            else if (c == 0x01) b->field_cur = 0;
            else b->field_cur = n;
            parse_html(b, b->raw + b->bodyoff, b->bodylen);            /* re-render to move the caret */
        }
        else if (c == 8 || c == 127 || c == 0x04) {     /* backspace (before caret) / Delete (at caret) */
            const char *cur = in_get(b, b->focus_id); char t[IN_VLEN]; int n=0;
            if (cur) while (cur[n] && n<IN_VLEN-1) { t[n]=cur[n]; n++; } t[n]=0;
            if (b->field_cur > n) b->field_cur = n;
            int del = (c == 0x04) ? b->field_cur : b->field_cur - 1;
            if (del >= 0 && del < n) {
                for (int i = del; i < n; i++) t[i] = t[i+1];
                if (c != 0x04) b->field_cur--;
                in_set(b, b->focus_id, t);
                if (!fire_handler(b, b->focus_id, "oninput")) parse_html(b, b->raw + b->bodyoff, b->bodylen);
            }
        } else if (c >= 32 && c < 127) {                /* insert a printable char at the caret */
            const char *cur = in_get(b, b->focus_id); char t[IN_VLEN]; int n=0;
            if (cur) while (cur[n] && n<IN_VLEN-2) { t[n]=cur[n]; n++; } t[n]=0;
            if (b->field_cur > n) b->field_cur = n;
            if (n < IN_VLEN-2) {
                for (int i = n; i > b->field_cur; i--) t[i] = t[i-1];
                t[b->field_cur] = (char)c; t[n+1] = 0; b->field_cur++;
                in_set(b, b->focus_id, t);
                if (!fire_handler(b, b->focus_id, "oninput")) parse_html(b, b->raw + b->bodyoff, b->bodylen);   /* oninput fires per keystroke */
            }
        }
        return;
    }
    if (b->finding) {                                   /* in-page find input mode */
        if (c == '\n' || c == '\r' || c == 0x12)         /* Enter / Down: next match */
            do_find(b, b->find_tok >= 0 ? b->find_tok + 1 : 0, +1);
        else if (c == 0x11)                              /* Up: previous match */
            do_find(b, b->find_tok >= 0 ? b->find_tok - 1 : 0, -1);
        else if (c == 27)            { b->finding = 0; b->find_tok = -1; set_status(b, ""); }
        else if (c == 8 || c == 127) { int n = (int)strlen(b->findq); if (n) b->findq[n-1] = 0; find_prompt(b); }
        else if (c >= 32 && c < 127) { int n = (int)strlen(b->findq); if (n < (int)sizeof(b->findq)-1) { b->findq[n]=(char)c; b->findq[n+1]=0; } find_prompt(b); }
        return;
    }
    if (b->editing) {
        int n = (int)strlen(b->url);
        if (b->url_cur > n) b->url_cur = n;
        if (c == '\n' || c == '\r') { b->editing = 0; if (looks_like_search(b->url)) make_search_url(b->url); browser_navigate(b); }
        else if (c == 27)            { b->editing = 0; }
        else if (c == 0x13) { b->edit_fresh = 0; if (b->url_cur > 0) b->url_cur--; }              /* left  */
        else if (c == 0x14) { b->edit_fresh = 0; if (b->url_cur < n) b->url_cur++; }              /* right */
        else if (c == 0x01) { b->edit_fresh = 0; b->url_cur = 0; }                                /* Home  */
        else if (c == 0x05) { b->edit_fresh = 0; b->url_cur = n; }                                /* End   */
        else if (c == 0x04) { b->edit_fresh = 0;                                                  /* Delete (at caret) */
            if (b->url_cur < n) { for (int i = b->url_cur; i < n; i++) b->url[i] = b->url[i+1]; } }
        else if (c == 8 || c == 127) { b->edit_fresh = 0;                                         /* backspace (before caret) */
            if (b->url_cur > 0) { for (int i = b->url_cur - 1; i < n; i++) b->url[i] = b->url[i+1]; b->url_cur--; } }
        else if (c >= 32 && c < 127) {                                                            /* insert at caret */
            if (b->edit_fresh) { b->url[0] = 0; b->url_cur = 0; n = 0; b->edit_fresh = 0; }       /* first keystroke replaces */
            if (n < URL_MAX-1) {
                for (int i = n; i > b->url_cur; i--) b->url[i] = b->url[i-1];                      /* shift right */
                b->url[b->url_cur++] = (char)c; b->url[n+1] = 0;
            }
        }
        return;
    }
    if (c == 8 || c == 127) { browser_back(b); return; }   /* Backspace = Back */
    int page = b->view_h ? b->view_h * 3 / 4 : 200;
    switch (c) {
    case ' ': case 'f': case 0x16: b->scroll += page; break;   /* space/f/PgDn */
    case 'b':           case 0x15: b->scroll -= page; break;   /* b/PgUp        */
    case 'j': case 0x12: b->scroll += 40;  break;          /* j / down-arrow */
    case 'k': case 0x11: b->scroll -= 40;  break;          /* k / up-arrow   */
    case 'g':           b->scroll = 0;     break;   /* top */
    case 'G':           b->scroll = 1 << 24; break; /* bottom (render clamps to maxscroll) */
    case '+': case '=': if (b->zoom < 4) b->zoom++; set_status(b, b->zoom>1?"zoom in":""); break;   /* content zoom */
    case '-': case '_': if (b->zoom > 1) b->zoom--; set_status(b, b->zoom>1?"zoom out":"1x"); break;
    case '0':           b->zoom = 1; set_status(b, "1x"); break;   /* reset zoom */
    case 'h':           copy_url(b->url, "home"); browser_navigate(b); break;  /* start page */
    case 'r':           browser_navigate(b); break;
    case 's':           browser_save(b);   break;   /* save page to PAGE.TXT */
    case 'u':           if (!b->img) { b->viewsource = !b->viewsource; b->scroll = 0;  /* toggle raw HTML */
                            set_status(b, b->viewsource ? "source" : ""); } break;
    case 'm':           b->reader = !b->reader;          /* toggle reader mode (article-first vs whole page) */
                        set_status(b, b->reader ? "reader on" : "reader off");
                        if (b->raw && b->bodylen > 0 && !b->img) { parse_html(b, b->raw + b->bodyoff, b->bodylen); b->scroll = 0; }
                        break;
    case 'i': {         /* cert info: identity + validity of the current HTTPS page */
        if (b->cert_status == -2) { set_status(b, "not HTTPS"); break; }
        char s[40]; int p = 0;
        for (const char *cn = b->cert_cn[0] ? b->cert_cn : "?"; *cn && p < 18; cn++) s[p++] = *cn;
        const char *tail = " exp";
        for (const char *t = tail; *t && p < (int)sizeof s - 1; t++) s[p++] = *t;
        for (int k = 0; k < 6 && b->cert_expiry[k] && p < (int)sizeof s - 1; k++) s[p++] = b->cert_expiry[k];  /* YYMMDD */
        /* a loaded HTTPS page already passed hostname + validity enforcement;
         * "anchored" also means the chain reached a trusted root in our store. */
        const char *vfy = b->chain_ok ? " anchored" : (b->host_match == 1 ? " verified" : " ?");
        for (const char *v = vfy; *v && p < (int)sizeof s - 1; v++) s[p++] = *v;
        s[p] = 0; set_status(b, s);
        break; }
    case 'a':           browser_bookmark(b); break; /* add current URL to SITES */
    case '/': case 'e': b->editing = 1; b->edit_fresh = 1;    break;
    case '\\': case 0x86: b->finding = 1; b->findq[0] = 0; b->find_tok = -1; set_status(b, "find: "); break;  /* \ or Ctrl-F */
    case '?': case 0x88: b->help_on = 1; break;     /* ? or Ctrl-H: key-reference overlay */
    case '<':            browser_back(b);    break; /* back    (also Backspace) */
    case '>':            browser_forward(b); break; /* forward */
    case '\t': case 'n': select_link(b, +1); break; /* next link (keyboard nav) */
    case 'p':            select_link(b, -1); break; /* previous link */
    case '\n': case '\r':                            /* follow the selected link */
        if (b->sel != NO_LINK) browser_follow(b, b->sel);
        break;
    }
    if (b->scroll < 0) b->scroll = 0;
}

int browser_click(browser_t *b, int rx, int ry, int w, int h) {
    (void)w; (void)h;
    if (ry < ADDR_H) {
        if (rx >= 6 && rx < 24) browser_back(b);          /* the Back button */
        else if (rx >= 26 && rx < 44) browser_forward(b); /* the Forward button */
        else { b->editing = 1; b->edit_fresh = 1; b->url_cur = (int)strlen(b->url); }  /* edit the address */
        return 1;
    }
    b->editing = 0;
    for (int i = 0; i < b->nlrec; i++) {                 /* a link? follow it */
        lrec_t *L = &b->lrec[i];
        if (rx >= L->x && rx < L->x + L->w && ry >= L->y && ry < L->y + L->h) {
            browser_follow(b, L->link);
            return 1;                                    /* consumed */
        }
    }
    return 0;   /* plain content click: not consumed -> the WM may start a text selection */
}

browser_t *browser_create(const char *url) {
    browser_init();                          /* ensure the fetch worker exists */
    browser_t *b = kzalloc(sizeof(browser_t));
    if (!b) return NULL;
    b->zoom  = 1;                            /* default 1x (zoom persists across pages) */
    b->reader = 1;                           /* reader mode on by default: show the article, not the chrome */
    b->raw   = kmalloc(RAW_MAX);
    b->text  = kmalloc(TEXT_MAX);
    b->toks  = kmalloc(sizeof(tok_t) * TOK_MAX);
    b->hrefs = kmalloc(HREF_MAX);
    b->links = kmalloc(sizeof(href_t) * LINK_MAX);
    b->lrec  = kmalloc(sizeof(lrec_t) * LREC_MAX);
    b->wrec  = kmalloc(sizeof(lrec_t) * LREC_MAX);
    b->tsel0 = b->tsel1 = -1;
    b->scripts = kmalloc(SCRIPT_MAX);
    if (!url || !url[0]) url = "home";        /* open the start page by default */
    int i = 0; while (url[i] && i < URL_MAX-1) { b->url[i] = url[i]; i++; }
    b->url[i] = 0;
    if (b->raw && b->text && b->toks && b->hrefs && b->links && b->lrec && b->wrec && b->scripts)
        browser_navigate(b);
    else set_status(b, "nomem");
    return b;
}

void browser_destroy(browser_t *b) {
    if (!b) return;
    uint64_t f = irq_save();
    int defer;
    if (g_req == b) {            /* queued, worker hasn't started: cancel + we free */
        g_req = NULL; defer = 0;
    } else if (b->loading) {     /* worker is mid-fetch on b: it frees when done */
        b->closed = 1; defer = 1;
    } else {                     /* idle/done: we free */
        defer = 0;
    }
    irq_restore(f);
    if (!defer) free_buffers(b);
}

const char *browser_title(browser_t *b) {
    if (b && b->title_js_set && b->title_js[0]) return b->title_js;   /* document.title override */
    return (b && b->title[0]) ? b->title : "Browser";
}
