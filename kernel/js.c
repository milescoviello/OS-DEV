/*
 * js.c — a small from-scratch JavaScript interpreter (tree-walking).
 *
 * Supports a useful core of the language: var/let/const, integer numbers,
 * strings, booleans, null/undefined; the usual operators (+ - * / %, comparisons,
 * && || !, ?:, ++/--, typeof); if/else, while, for, blocks, break/continue;
 * function declarations + expressions with lexical closures and recursion;
 * array and object literals with member/index access, .length and a few methods;
 * and the builtins print()/console.log() plus a small Math.
 *
 * Deliberate simplifications (this is an OS kernel with no FPU and tiny stacks):
 *  - Number is a 64-bit INTEGER (the kernel is built -mgeneral-regs-only, no
 *    floating point). So 7/2 === 3. Float support would need soft-float.
 *  - Memory is an arena that is reset wholesale after each top-level run (no GC):
 *    one script runs, prints, and the arena is recycled. Bounded by JS_ARENA.
 *  - Recursion (parser + evaluator) is depth-limited to stay within the stack.
 *
 * The file compiles both freestanding in the kernel and, with -DJS_HOSTTEST, as
 * a standalone host program for testing (see the main() at the bottom).
 */
#ifdef JS_HOSTTEST
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#else
#include "string.h"
#include "rtc.h"
#include <stdint.h>
#include <stddef.h>
#endif

/* ---- output sink: all print() output is appended here ---- */
static char  *g_out;
static int    g_out_cap, g_out_len;
static void out_str(const char *s) {
    while (*s && g_out_len < g_out_cap - 1) g_out[g_out_len++] = *s++;
    if (g_out_cap) g_out[g_out_len] = 0;
}

/* ---- arena allocator (no free; reset per run) ---- */
/* Holds the whole parsed AST + the global objects + every value a run allocates,
 * all at once (reset only between runs). Large scripts — the kitchen-sink
 * regression suite, or a page that defines several classes — need eval headroom
 * above the parsed AST; the buffer is static BSS, cheap on the kernel's RAM.
 * 4 MB: regex compilation is arena-heavy (each compiled program is sizeable), and
 * the kitchen-sink suite now compiles many regexes on top of a large AST.
 * 12 MB: the single-run regression suite (no GC -> every alloc accumulates until
 * the run ends) crossed 8 MB once querySelector(All) tests were added; 12 MB
 * restores headroom for the suite's continued growth and for heavy real pages.
 * 20 MB: the suite's peak crept to ~16.1 MB once the Proxy get/set-trap cases were
 * added (the adversarial self-recursive trap allocates a new_env per MAXDEPTH frame),
 * just past the prior 16 MB cap; 20 MB restores ~4 MB of headroom. (M-proxy)
 * 26 MB: the suite's peak reached ~22.1 MB after the M529/M530 method cases; 26 MB
 * restores the ~4 MB headroom (and gives heavy real pages more room). (M530)
 * 32 MB: the suite's peak reached ~26.7 MB after the M531-M542 cases; 32 MB
 * restores ~5 MB headroom. (M542)
 * OOM is graceful (aalloc -> g_oom -> NULL), so this is a capacity knob, not safety. */
#ifndef JS_ARENA                    /* overridable: the ring-3 jsrun build sets a smaller arena via -DJS_ARENA */
#define JS_ARENA   (45056 * 1024)   /* 44 MB. The parser builds the whole script's AST in the arena
                                     * before running it, and there's no GC (one run, then recycle), so a
                                     * big script (e.g. the growing jstest suite) needs headroom. Bumped
                                     * 20->26->32->40->44 as the suite grew (M906: real doubles format a
                                     * little heavier than the old int path); safe in the 256 MiB guest. */
#endif
#ifdef JS_HOSTTEST
static char g_arena_buf[JS_ARENA];
#else
static char g_arena_buf[JS_ARENA];   /* BSS */
#endif
static int  g_arena_off;
static int  g_oom;
/* n is a 64-bit signed size: callers pass sizeof(T)*count which is size_t, so a
 * count that would overflow a 32-bit size arrives here as a huge value and is
 * rejected (rather than silently truncating to a small/zero size -> OOB). */
static void *aalloc(long n) {
    if (n < 0) { g_oom = 1; return 0; }
    n = (n + 7) & ~7;
    if (n > (long)(JS_ARENA - g_arena_off)) { g_oom = 1; return 0; }   /* incl. n > JS_ARENA */
    void *p = g_arena_buf + g_arena_off; g_arena_off += (int)n;
    return p;
}
/* intern a (possibly non-terminated) name into a stable, NUL-terminated arena
 * string. Done once at parse time so eval never re-allocates for identifiers. */
static const char *intern(const char *s, int len) {
    char *p = aalloc(len + 1); if (!p) return "";
    if (len > 0) memcpy(p, s, len);    /* guard memcpy(_, NULL, 0) for an OOM'd token (UB) */
    p[len] = 0; return p;
}

/* ---- runtime error handling ---- */
/* g_err unwinds eval like an exception; a try/catch clears it. g_threw marks that
 * the in-flight error is an explicit `throw` (carrying g_throwval) vs a built-in
 * runtime error (caught as its message string). g_oom is NOT catchable. */
static int  g_err;
static char g_errmsg[128];
static int  g_threw;
static void rt_err(const char *m) {
    if (!g_err) { g_err = 1; int i = 0; while (m[i] && i < 127) { g_errmsg[i] = m[i]; i++; } g_errmsg[i] = 0; }
}

/* =========================== lexer =========================== */
enum { T_EOF, T_NUM, T_STR, T_IDENT, T_PUNC, T_KW, T_TEMPLATE, T_REGEX };
/* token.num is a double: number literals are IEEE-754 (the engine is no longer integer-only). */
typedef struct { int type; double num; const char *s; int len; } token;

static const char *kw[] = { "var","let","const","function","return","if","else",
    "while","for","true","false","null","undefined","break","continue","typeof",
    "switch","case","default","do","try","catch","finally","throw","this","new",
    "class","extends","super","delete","in","instanceof","void",0 };

typedef struct {
    const char *src; int pos, len;
    token cur, peeked; int has_peek;
    token last;   /* last token lex_next produced — used to decide `/` = regex vs division */
} lexer;

static int tok_is(token t, const char *p);   /* fwd: used by the regex/division decision in lex_next_raw */
static int is_id_start(int c){ return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'||c=='$'; }
static int is_id(int c){ return is_id_start(c)||(c>='0'&&c<='9'); }
static int is_digit(int c){ return c>='0'&&c<='9'; }

/* Scan forward from s[j] (depth=1: the '{' of a '${' was already consumed) to the
 * matching '}', skipping single/double-quoted strings and nested template literals so
 * their literal '{'/'}' characters don't confuse the depth counter.
 * Used by both the template LEXER and parse_template/parse_tagged.
 * Returns the index of the matching '}', capped at len if unclosed. */
static int tpl_scan_to_close(const char *s, int j, int len) {
    int depth = 1;
    while (j < len && depth > 0) {
        unsigned char ch = (unsigned char)s[j];
        if (ch == '\\') { j += 2; if (j > len) j = len; continue; }
        if (ch == '\'' || ch == '"') {   /* quoted string: skip to matching close */
            int q = ch; j++;
            while (j < len && (unsigned char)s[j] != q) {
                if (s[j] == '\\') { j++; if (j >= len) break; }
                j++;
            }
            if (j < len) j++;  /* step past the closing quote only if it exists */
            continue;
        }
        if (ch == '`') {                 /* nested template literal: skip to matching ` */
            j++;
            while (j < len) {
                if (s[j] == '\\') { j += 2; if (j > len) j = len; continue; }
                if ((unsigned char)s[j] == '`') { j++; break; }
                if (s[j] == '$' && j+1 < len && s[j+1] == '{') {
                    j = tpl_scan_to_close(s, j+2, len);
                    if (j < len) j++;    /* step past the matching '}' if found */
                    continue;
                }
                j++;
            }
            continue;
        }
        if (ch == '{') depth++;
        else if (ch == '}') { depth--; if (depth == 0) break; }
        j++;
    }
    return (j <= len) ? j : len;
}

static token lex_next_raw(lexer *L) {
    token t; t.type = T_EOF; t.s = 0; t.len = 0; t.num = 0.0;
    const char *s = L->src;
    /* skip whitespace + comments */
    for (;;) {
        while (L->pos < L->len && (s[L->pos]==' '||s[L->pos]=='\t'||s[L->pos]=='\n'||s[L->pos]=='\r')) L->pos++;
        if (L->pos+1 < L->len && s[L->pos]=='/' && s[L->pos+1]=='/') { while (L->pos<L->len && s[L->pos]!='\n') L->pos++; continue; }
        if (L->pos+1 < L->len && s[L->pos]=='/' && s[L->pos+1]=='*') { L->pos+=2; while (L->pos+1<L->len && !(s[L->pos]=='*'&&s[L->pos+1]=='/')) L->pos++; L->pos+=2; continue; }
        break;
    }
    if (L->pos >= L->len) return t;
    int c = s[L->pos];
    /* number (integer) */
    if (is_digit(c)) {
        int64_t v = 0;
        if (c=='0' && L->pos+1<L->len && (s[L->pos+1]=='x'||s[L->pos+1]=='X')) {
            L->pos += 2;
            while (L->pos<L->len) { int d=s[L->pos]; int h;
                if (d=='_') { L->pos++; continue; }   /* `_` separator */
                if (d>='0'&&d<='9') h=d-'0'; else if (d>='a'&&d<='f') h=d-'a'+10; else if (d>='A'&&d<='F') h=d-'A'+10; else break;
                v = v*16 + h; L->pos++; }
        } else if (c=='0' && L->pos+1<L->len && (s[L->pos+1]=='b'||s[L->pos+1]=='B')) {
            L->pos += 2;   /* binary 0b1010 */
            while (L->pos<L->len && (s[L->pos]=='0'||s[L->pos]=='1'||s[L->pos]=='_')) { if(s[L->pos]!='_') v = v*2 + (s[L->pos]-'0'); L->pos++; }
        } else if (c=='0' && L->pos+1<L->len && (s[L->pos+1]=='o'||s[L->pos+1]=='O')) {
            L->pos += 2;   /* octal 0o17 */
            while (L->pos<L->len && ((s[L->pos]>='0'&&s[L->pos]<='7')||s[L->pos]=='_')) { if(s[L->pos]!='_') v = v*8 + (s[L->pos]-'0'); L->pos++; }
        } else {
            /* decimal: integer [ . fraction ] [ (e|E)[+|-]exponent ] -> double (IEEE-754) */
            double dv=0;
            while (L->pos<L->len && (is_digit(s[L->pos])||s[L->pos]=='_')) { if(s[L->pos]!='_') dv = dv*10.0 + (s[L->pos]-'0'); L->pos++; }   /* `_` digit separators */
            if (L->pos<L->len && s[L->pos]=='.') { L->pos++; double f=0.1; while (L->pos<L->len && (is_digit(s[L->pos])||s[L->pos]=='_')) { if(s[L->pos]!='_'){ dv += (s[L->pos]-'0')*f; f*=0.1; } L->pos++; } }
            if (L->pos<L->len && (s[L->pos]=='e'||s[L->pos]=='E')) {            /* 1e3, 2.5e-4, … (back off if `e` starts an identifier) */
                int save=L->pos; L->pos++;
                int neg=0; if (L->pos<L->len && (s[L->pos]=='+'||s[L->pos]=='-')) { neg=(s[L->pos]=='-'); L->pos++; }
                if (L->pos<L->len && is_digit(s[L->pos])) {
                    int exp=0; while (L->pos<L->len && is_digit(s[L->pos])) { exp=exp*10+(s[L->pos]-'0'); if(exp>308)exp=308; L->pos++; }
                    double p=1.0; for (int k=0;k<exp;k++) p*=10.0; dv = neg ? dv/p : dv*p;
                } else L->pos=save;
            }
            t.type=T_NUM; t.num=dv; return t;
        }
        t.type=T_NUM; t.num=v; return t;   /* hex / binary / octal: integer value */
    }
    /* string */
    if (c=='"' || c=='\'') {
        int q = c; L->pos++;
        char *buf = aalloc(L->len); int n = 0;       /* generous; arena */
        while (L->pos<L->len && s[L->pos]!=q) {
            int ch = s[L->pos++];
            if (ch=='\\' && L->pos<L->len) {
                int e = s[L->pos++];
                if (e=='u') {          /* \uXXXX (M1623): decode 4 hex digits, keep the low byte (ASCII-only engine, matches fromCharCode's own &0xFF) */
                    int v=0, k=0;
                    for (; k<4 && L->pos<L->len; k++) {
                        int h = s[L->pos];
                        int d = (h>='0'&&h<='9') ? h-'0' : (h>='a'&&h<='f') ? h-'a'+10 : (h>='A'&&h<='F') ? h-'A'+10 : -1;
                        if (d<0) break;
                        v = v*16 + d; L->pos++;
                    }
                    ch = (k==4) ? (v & 0xFF) : 'u';   /* malformed: fall back to a literal 'u' */
                } else {
                    ch = e=='n'?'\n': e=='t'?'\t': e=='r'?'\r': e=='\\'?'\\': e=='\''?'\'': e=='"'?'"': e=='0'?0: e;
                }
            }
            if (buf) buf[n++] = (char)ch;
        }
        if (L->pos<L->len) L->pos++;                 /* closing quote */
        if (buf) buf[n]=0;
        t.type=T_STR; t.s=buf; t.len=n; return t;
    }
    /* template literal `...${expr}...` — capture the raw inner text (balancing
     * ${ } so a `}` inside a substitution doesn't end it); the parser splits it.
     * Uses tpl_scan_to_close() so strings/nested templates inside ${} are skipped. */
    if (c=='`') {
        int start = L->pos+1, i = start;
        while (i < L->len) {
            char ch = s[i];
            if (ch=='\\') { i += 2; if (i > L->len) i = L->len; continue; }
            if (ch=='`') break;
            if (ch=='$' && i+1<L->len && s[i+1]=='{') {
                /* skip the entire ${...} expression, properly handling strings/templates */
                int close = tpl_scan_to_close(s, i+2, L->len);  /* returns <= L->len */
                i = (close < L->len) ? close + 1 : L->len;       /* step past } if found */
                continue;
            }
            i++;
        }
        t.type=T_TEMPLATE; t.s=s+start; t.len=i-start; L->pos = (i<L->len)? i+1 : i;
        return t;
    }
    /* identifier / keyword (a leading # begins a private class field/method name,
     * kept as part of the name so `#x` declaration + `this.#x` access agree and
     * stay distinct from a public `x`) */
    if (is_id_start(c) || (c=='#' && L->pos+1<L->len && is_id_start((unsigned char)s[L->pos+1]))) {
        int start = L->pos; if (c=='#') L->pos++;   /* keep the leading # */
        while (L->pos<L->len && is_id(s[L->pos])) L->pos++;
        t.s = s+start; t.len = L->pos-start; t.type = T_IDENT;
        if (s[start] != '#') for (int i=0; kw[i]; i++) { int kl=(int)strlen(kw[i]); if (kl==t.len && memcmp(kw[i],t.s,kl)==0) { t.type=T_KW; break; } }
        return t;
    }
    /* regex literal /pattern/flags — `/` starts one unless the previous token ends an
     * operand (then it's division). The pattern bypasses the parser's depth guard, so
     * the regex compiler caps its own recursion (M179). */
    if (c=='/') {
        token p=L->last; int div_ctx=0;
        if (p.type==T_NUM||p.type==T_STR||p.type==T_TEMPLATE||p.type==T_IDENT||p.type==T_REGEX) div_ctx=1;
        else if (p.type==T_PUNC && (tok_is(p,")")||tok_is(p,"]")||tok_is(p,"++")||tok_is(p,"--"))) div_ctx=1;   /* postfix x++ / 2 is division */
        else if (p.type==T_KW && (tok_is(p,"this")||tok_is(p,"true")||tok_is(p,"false")||tok_is(p,"null")||tok_is(p,"undefined")||tok_is(p,"super"))) div_ctx=1;
        if (!div_ctx) {
            L->pos++;                                   /* opening / */
            int pstart=L->pos, inclass=0;
            while (L->pos<L->len) { int ch=s[L->pos];
                if (ch=='\\') { L->pos+=2; continue; }
                if (ch=='\n') break;
                if (ch=='[') inclass=1; else if (ch==']') inclass=0; else if (ch=='/' && !inclass) break;
                L->pos++; }
            int plen=L->pos-pstart;
            if (L->pos<L->len && s[L->pos]=='/') L->pos++;   /* closing / */
            int64_t fb=0; while (L->pos<L->len && is_id(s[L->pos])) { char f=s[L->pos]; if(f=='g')fb|=1; else if(f=='i')fb|=2; else if(f=='m')fb|=4; else if(f=='s')fb|=8; L->pos++; }
            t.type=T_REGEX; t.s=s+pstart; t.len=plen; t.num=fb; return t;
        }
    }
    /* punctuation / multi-char operators */
    static const char *ops[] = { "===","!==","<<=",">>>=",">>=","...","**=","**","==","!=","<=",">=",
        "||=","&&=","?\?=","&&","||","??","?.","++","--","+=","-=","*=","/=","%=","&=","|=","^=","<<",">>>",">>","=>",0 };
    for (int i=0; ops[i]; i++) { int ol=(int)strlen(ops[i]); if (L->pos+ol<=L->len && memcmp(ops[i],s+L->pos,ol)==0) { t.type=T_PUNC; t.s=s+L->pos; t.len=ol; L->pos+=ol; return t; } }
    t.type=T_PUNC; t.s=s+L->pos; t.len=1; L->pos++; return t;
}

static token lex_next(lexer *L){ token t=lex_next_raw(L); L->last=t; return t; }   /* track last token for the `/` regex/division decision */
static token peek(lexer *L){ if (!L->has_peek){ L->peeked=lex_next(L); L->has_peek=1; } return L->peeked; }
static token advance(lexer *L){ if (L->has_peek){ L->has_peek=0; return L->peeked; } return lex_next(L); }
/* save/restore lexer position for bounded lookahead (arrow-function detection) */
typedef struct { int pos, has_peek; token peeked, last; } lexsave;
static lexsave lex_save(lexer *L){ lexsave s; s.pos=L->pos; s.has_peek=L->has_peek; s.peeked=L->peeked; s.last=L->last; return s; }
static void lex_restore(lexer *L, lexsave s){ L->pos=s.pos; L->has_peek=s.has_peek; L->peeked=s.peeked; L->last=s.last; }
static int tok_is(token t, const char *p){ int l=(int)strlen(p); return t.len==l && t.s && memcmp(t.s,p,l)==0; }
static int peek_punc(lexer *L, const char *p){ token t=peek(L); return t.type==T_PUNC && tok_is(t,p); }
static int peek_kw(lexer *L, const char *p){ token t=peek(L); return t.type==T_KW && tok_is(t,p); }
static void skip_semi(lexer *L){ while (peek_punc(L,";")) advance(L); }   /* ; is an optional terminator */

/* =========================== AST =========================== */
enum { N_NUM, N_STR, N_BOOL, N_NULL, N_UNDEF, N_IDENT, N_ARRAY, N_OBJECT,
       N_FUNC, N_CALL, N_MEMBER, N_INDEX, N_UNARY, N_UPDATE, N_BINARY, N_LOGICAL,
       N_ASSIGN, N_COND, N_VAR, N_IF, N_WHILE, N_FOR, N_BLOCK, N_RETURN,
       N_BREAK, N_CONTINUE, N_EXPR, N_PROGRAM, N_PROP, N_SWITCH, N_CASE, N_DOWHILE, N_FOROF,
       N_TRY, N_THROW, N_FORIN, N_THIS, N_NEW, N_CLASS, N_SUPER, N_SPREAD, N_REGEX, N_YIELD, N_AWAIT, N_NEWTARGET };

typedef struct node node;
struct node {
    int type; double num; int op /*single-char or coded*/; const char *str; int slen;
    node *a, *b, *c, *d;
    node **list; int nlist;
    int prefix;   /* for N_UPDATE: prefix vs postfix */
    const char *label;   /* labeled stmt: a loop's own label; or a break/continue target. NULL=none (memset-zeroed by mknode) (M280) */
    int is_gen;   /* N_FUNC: 1 if a `function*` generator (eager-evaluated). zero-init by mknode. */
    int is_async; /* N_FUNC: 1 if an `async function` (returns a Promise; body may `await`). M680 */
};

static int g_depth;            /* recursion guard (parser + eval + val_to_str + calls) */
static int g_in_gen;           /* parser: nonzero while inside a `function*` body, so `yield` parses as N_YIELD */
static int g_in_async;         /* parser: nonzero while inside an `async function` body, so `await` parses as N_AWAIT (M680) */
/* The largest C frame per nesting level is eval_expr (~1.5 KB, measured via
 * objdump); the worst case (~120 × 1.5 KB ≈ 185 KB) stays within the 256 KB
 * kernel stacks BOTH entry paths run on — the ring-3 SYS_js task stack AND the
 * WM/boot stack the browser uses — with margin for the call chain + interrupts,
 * since neither stack has a guard page. (call_bound's comb[24] is a separate
 * ~0.9 KB frame on the rare bound-call path, kept out of the hot call_function_this
 * frame; the regex matcher caps itself at depth 900 — see re_run.) */
#define MAXDEPTH 120

/* On arena exhaustion, return a shared dummy node (never NULL) so the parser's
 * field writes (n->a=..., n->op=...) are harmless scribbles rather than NULL
 * derefs; g_oom is set and the parse loops bail. The garbage AST is never run. */
static node g_dummy_node;
static node *mknode(int type){ node *n=aalloc(sizeof(node)); if(!n){ memset(&g_dummy_node,0,sizeof(g_dummy_node)); return &g_dummy_node; } memset(n,0,sizeof(*n)); n->type=type; return n; }

/* ---- parser (recursive descent + precedence climbing) ---- */
static node *parse_expr(lexer *L);
static node *parse_assign(lexer *L);
static node *parse_stmt(lexer *L);
static node *parse_unary(lexer *L);
static node *parse_postfix(lexer *L);
static node *parse_primary(lexer *L);
static char *num_to_str(double d);   /* fwd: numeric object-literal keys intern their canonical string (M1751) */

static void expect_punc(lexer *L, const char *p){ token t=advance(L); if(!(t.type==T_PUNC && tok_is(t,p))) rt_err("syntax: expected punctuation"); }

/* Parse a `( p1, p2 = default, ... )` parameter list into fn->list. Shared by
 * `function`, object-literal method shorthand, and (indirectly) constructors. */
static void parse_fn_params(lexer *L, node *fn) {
    expect_punc(L,"(");
    fn->list = aalloc(sizeof(node*)*32); fn->nlist=0;
    while (!peek_punc(L,")") && peek(L).type!=T_EOF && !g_err && !g_oom) {
        int rest=0; if (peek_punc(L,"...")) { advance(L); rest=1; }   /* ...rest param */
        if (!rest && (peek_punc(L,"[")||peek_punc(L,"{"))) {          /* destructuring param: f([a,b], {c}) */
            node *pat=parse_primary(L);
            if (peek_punc(L,"=")) { advance(L); node *as=mknode(N_ASSIGN); as->op='='; as->a=pat; as->b=parse_assign(L); pat=as; }  /* default for a missing arg */
            if (fn->list && fn->nlist<32) fn->list[fn->nlist++]=pat;
            if (peek_punc(L,",")) advance(L); else break;
            continue;
        }
        token p=advance(L);
        if (p.type==T_IDENT){ node *id=mknode(N_IDENT); id->str=intern(p.s,p.len); id->slen=p.len;
            if (rest) id->op='.';                                      /* marks the rest param */
            else if (peek_punc(L,"=")) { advance(L); id->a=parse_assign(L); }   /* default param value */
            if (fn->list && fn->nlist<32) fn->list[fn->nlist++]=id; }
        if (rest) break;                                              /* rest is the last param */
        if (peek_punc(L,",")) advance(L); else break;
    }
    expect_punc(L,")");
}

static node **parse_list(lexer *L, const char *close, int *count) {
    node **arr = aalloc(sizeof(node*) * 64); int n = 0;
    while (!peek_punc(L, close) && peek(L).type != T_EOF && !g_err && !g_oom) {
        node *el;
        if (peek_punc(L,",")) el=mknode(N_UNDEF);   /* elision: `[1,,3]` -> a hole (undefined); the comma is consumed below */
        else if (peek_punc(L,"...")) { advance(L); el=mknode(N_SPREAD); el->a=parse_assign(L); }  /* ...spread */
        else el=parse_assign(L);
        if (arr && n < 64) arr[n++] = el;
        if (peek_punc(L, ",")) advance(L); else break;
    }
    expect_punc(L, close); *count = n; return arr;
}

static node *mkbin_plus(node *a, node *b){ node *n=mknode(N_BINARY); n->op='+'; n->a=a; n->b=b; return n; }

/* Parse a template literal's raw inner text into a `+`-concatenation of string
 * literals and `${expr}` substitutions. Always begins with a (possibly empty)
 * string literal, so the whole chain coerces to a string. */
/* \uXXXX inline decode for template literals (M1632): mirrors the main string
 * lexer's own fix (M1623), which never propagated to parse_template/parse_tagged's
 * SEPARATE escape loop below -- so `A` in a template literal still yielded
 * the 4 raw characters "u0041" instead of "A". Called with *pi pointing at the
 * first hex digit (right after "\u"); advances *pi past the 4 digits on success.
 * On a malformed escape (fewer than 4 valid hex digits), returns 'u' and leaves
 * *pi unchanged, matching the lexer's own fallback. */
static char tpl_decode_u(const char *raw, int len, int *pi) {
    int v=0, k=0, i=*pi;
    for (; k<4 && i<len; k++) {
        int h=raw[i]; int d=(h>='0'&&h<='9')?h-'0':(h>='a'&&h<='f')?h-'a'+10:(h>='A'&&h<='F')?h-'A'+10:-1;
        if (d<0) break;
        v=v*16+d; i++;
    }
    if (k==4) { *pi=i; return (char)(v & 0xFF); }
    return 'u';
}
static node *parse_template(const char *raw, int len) {
    node *chain = 0;
    char *lit = aalloc(len + 1); int ln = 0;
    #define TPL_FLUSH() do { if(lit) lit[ln]=0; node *sn=mknode(N_STR); sn->str=intern(lit?lit:"",ln); sn->slen=ln; chain = chain ? mkbin_plus(chain,sn) : sn; ln=0; } while(0)
    int i = 0;
    while (i < len) {
        if (raw[i]=='\\' && i+1<len) { char e=raw[i+1];
            if (e=='u') { int pi=i+2; char c=tpl_decode_u(raw,len,&pi); if(lit&&ln<len) lit[ln++]=c; i=pi; continue; }
            char c = e=='n'?'\n':e=='t'?'\t':e=='r'?'\r':e=='`'?'`':e=='$'?'$':e=='\\'?'\\':e; if(lit && ln<len) lit[ln++]=c; i+=2; continue; }
        if (raw[i]=='$' && i+1<len && raw[i+1]=='{') {
            TPL_FLUSH();                                  /* literal before the ${ */
            int j = tpl_scan_to_close(raw, i+2, len);   /* find the matching }, skipping strings/nested templates */
            lexer sub; memset(&sub,0,sizeof(sub)); sub.src=raw+i+2; sub.len=j-(i+2); sub.pos=0;
            node *e = parse_assign(&sub);
            chain = mkbin_plus(chain, e);                 /* chain is non-null after TPL_FLUSH */
            i = (j<len)? j+1 : j;
            continue;
        }
        if (lit && ln<len) lit[ln++]=raw[i];
        i++;
    }
    TPL_FLUSH();                                          /* trailing literal */
    return chain;
}

/* Tagged template `tag`a${x}b`` -> a call tag(["a","b"], x): the cooked string
 * parts become an array argument, the ${…} values become the rest of the args.
 * Mirrors parse_template's escape/`${}`-balancing walk but splits rather than +-chains. */
static node *parse_tagged(node *tag, const char *raw, int len) {
    node *call = mknode(N_CALL); call->a = tag;
    call->list = aalloc(sizeof(node*) * 64); call->nlist = 0;
    node *strs = mknode(N_ARRAY); strs->list = aalloc(sizeof(node*) * 33); strs->nlist = 0;
    node *vals[63]; int nv = 0;
    char *lit = aalloc(len + 1); int ln = 0;
    #define TT_FLUSH() do { if(lit) lit[ln]=0; node *sn=mknode(N_STR); sn->str=intern(lit?lit:"",ln); sn->slen=ln; if(strs->list && strs->nlist<33) strs->list[strs->nlist++]=sn; ln=0; } while(0)
    int i = 0;
    while (i < len) {
        if (raw[i]=='\\' && i+1<len) { char e=raw[i+1];
            if (e=='u') { int pi=i+2; char c=tpl_decode_u(raw,len,&pi); if(lit&&ln<len) lit[ln++]=c; i=pi; continue; }
            char c = e=='n'?'\n':e=='t'?'\t':e=='r'?'\r':e=='`'?'`':e=='$'?'$':e=='\\'?'\\':e; if(lit && ln<len) lit[ln++]=c; i+=2; continue; }
        if (raw[i]=='$' && i+1<len && raw[i+1]=='{') {
            TT_FLUSH();
            int j = tpl_scan_to_close(raw, i+2, len);   /* find matching }, skipping strings/nested templates */
            lexer sub; memset(&sub,0,sizeof(sub)); sub.src=raw+i+2; sub.len=j-(i+2); sub.pos=0;
            node *ex = parse_assign(&sub);
            if (nv < 63) vals[nv++] = ex;
            i = (j<len)? j+1 : j;
            continue;
        }
        if (lit && ln<len) lit[ln++]=raw[i];
        i++;
    }
    TT_FLUSH();                                           /* trailing string part */
    #undef TT_FLUSH
    if (call->list) {
        call->list[call->nlist++] = strs;                /* arg 0: the cooked strings array */
        for (int k=0; k<nv && call->nlist<64; k++) call->list[call->nlist++] = vals[k];   /* args 1..: the values */
    }
    return call;
}

/* In a class/object member position, consume a leading `async` IFF it marks an async
 * method (i.e. it's followed by a method name, `*`, or `[`) — NOT a member literally
 * named `async` (`async(){}` / `async: v` / `async = v` / shorthand `{async}`). Returns
 * 1 if it consumed an async marker. (M682) */
static int parse_async_method_marker(lexer *L) {
    token cur = peek(L);
    if (!(cur.type==T_IDENT && cur.len==5 && memcmp(cur.s,"async",5)==0)) return 0;
    lexsave sv = lex_save(L); advance(L);
    token nx = peek(L);
    if (nx.type==T_IDENT || nx.type==T_KW || nx.type==T_STR || (nx.type==T_PUNC && (tok_is(nx,"*")||tok_is(nx,"[")))) return 1;
    lex_restore(L, sv); return 0;
}

static node *parse_primary(lexer *L) {
    token t = peek(L);
    if (t.type == T_TEMPLATE) { advance(L); return parse_template(t.s, t.len); }
    if (t.type == T_NUM) { advance(L); node *n=mknode(N_NUM); n->num=t.num; return n; }
    if (t.type == T_STR) { advance(L); node *n=mknode(N_STR); n->str=t.s; n->slen=t.len; return n; }
    if (t.type == T_REGEX) { advance(L); node *n=mknode(N_REGEX); n->str=intern(t.s,t.len); n->slen=t.len; n->num=t.num; return n; }   /* /pattern/flags; num bit0=g bit1=i */
    if (t.type == T_IDENT && t.len==5 && memcmp(t.s,"async",5)==0) {   /* `async function …` (decl/expr); `async`-arrows are handled in parse_assign (M680) */
        lexsave sv = lex_save(L); advance(L);
        if (peek_kw(L,"function")) {
            advance(L); node *n=mknode(N_FUNC); n->is_async=1;
            if (peek_punc(L,"*")) { advance(L); n->is_gen=1; }   /* async function* (async generator) — rare; the body still collects yields eagerly */
            token name = peek(L);
            if (name.type==T_IDENT) { advance(L); n->str=intern(name.s,name.len); n->slen=name.len; }
            parse_fn_params(L, n);
            int sg=g_in_gen, sa=g_in_async; g_in_gen=n->is_gen; g_in_async=1;
            n->a = parse_stmt(L);
            g_in_gen=sg; g_in_async=sa;
            return n;
        }
        lex_restore(L, sv);   /* not `async function` -> fall through, `async` is an ordinary identifier */
    }
    if (t.type == T_KW) {
        if (tok_is(t,"true")||tok_is(t,"false")) { advance(L); node *n=mknode(N_BOOL); n->num=tok_is(t,"true"); return n; }
        if (tok_is(t,"null")) { advance(L); return mknode(N_NULL); }
        if (tok_is(t,"undefined")) { advance(L); return mknode(N_UNDEF); }
        if (tok_is(t,"function")) {
            advance(L); node *n=mknode(N_FUNC);
            if (peek_punc(L,"*")) { advance(L); n->is_gen=1; }   /* function* generator */
            token name = peek(L);
            if (name.type==T_IDENT) { advance(L); n->str=intern(name.s,name.len); n->slen=name.len; }
            parse_fn_params(L, n);
            int sg = g_in_gen; g_in_gen = n->is_gen;   /* `yield` is contextual to this generator body */
            n->a = parse_stmt(L);   /* body block */
            g_in_gen = sg;
            return n;
        }
        if (tok_is(t,"typeof")) { advance(L); node *n=mknode(N_UNARY); n->op='t'; n->a=parse_primary(L); return n; }
        if (tok_is(t,"this")) { advance(L); return mknode(N_THIS); }
        if (tok_is(t,"super")) { advance(L); return mknode(N_SUPER); }
        if (tok_is(t,"class")) {
            advance(L);
            node *cls=mknode(N_CLASS);
            token nm=peek(L); if(nm.type==T_IDENT){ advance(L); cls->str=intern(nm.s,nm.len); cls->slen=nm.len; }
            if (peek_kw(L,"extends")) { advance(L); cls->a=parse_postfix(L); }   /* superclass expression */
            expect_punc(L,"{");
            cls->list=aalloc(sizeof(node*)*32); cls->nlist=0;
            node *fieldblk=mknode(N_BLOCK); fieldblk->list=aalloc(sizeof(node*)*32); fieldblk->nlist=0;
            node *staticblk=mknode(N_BLOCK); staticblk->list=aalloc(sizeof(node*)*32); staticblk->nlist=0;  /* static members -> co->statics */
            while (!peek_punc(L,"}") && peek(L).type!=T_EOF && !g_err && !g_oom) {
                if (peek_punc(L,";")) { advance(L); continue; }   /* stray semicolons between members */
                int asyncm = parse_async_method_marker(L);   /* `async method(){…}` (M682) */
                int genm = 0; if (peek_punc(L,"*")) { advance(L); genm = 1; }   /* *method(){…} : generator method */
                if (peek_punc(L,"[")) {   /* computed method key: class C { [expr](params){body} } — e.g. [Symbol.iterator](){…} (M-symbol) */
                    advance(L); node *key=parse_assign(L); expect_punc(L,"]");
                    if (peek_punc(L,"(")) {
                        node *fn=mknode(N_FUNC); fn->b=key; fn->is_gen=genm; fn->is_async=asyncm;   /* fn->b = computed key expr (str stays NULL -> not "constructor", keyed via keystr at class-build) */
                        parse_fn_params(L,fn); { int sg=g_in_gen, sa=g_in_async; g_in_gen=genm; g_in_async=asyncm; fn->a=parse_stmt(L); g_in_gen=sg; g_in_async=sa; }
                        if (cls->list && cls->nlist<32) cls->list[cls->nlist++]=fn;
                    } else { skip_semi(L); }   /* computed FIELD [expr]=v: unsupported (rare); skip safely */
                    continue;
                }
                token mn=advance(L);                              /* member name (incl. "constructor") */
                int is_static=0;                                  /* `static <name>`: class-level member (co->statics) */
                if (mn.len==6 && memcmp(mn.s,"static",6)==0 && peek(L).type==T_IDENT) { is_static=1; mn=advance(L); }
                if (mn.type==T_IDENT && (tok_is(mn,"get")||tok_is(mn,"set")) && !peek_punc(L,"(")) {   /* class accessor: `get area(){…}` / `set area(v){…}` (mn already consumed) */
                    token nm=peek(L);
                    if (nm.type==T_IDENT||nm.type==T_KW||nm.type==T_STR) {
                        lexsave sv=lex_save(L); int isget=mn.s[0]=='g'; advance(L);   /* consume accessor name */
                        if (peek_punc(L,"(")) {
                            node *fn=mknode(N_FUNC); fn->str=intern(nm.s,nm.len); fn->slen=nm.len; fn->op=isget?'g':'s';
                            parse_fn_params(L,fn); fn->a=parse_stmt(L);
                            if (!is_static && cls->list && cls->nlist<32) cls->list[cls->nlist++]=fn;   /* static accessors parsed but unsupported in v1 */
                            continue;
                        }
                        lex_restore(L,sv);
                    }
                }
                if (peek_punc(L,"(")) {                           /* method:  name(params){body} */
                    node *fn=mknode(N_FUNC); fn->str=intern(mn.s,mn.len); fn->slen=mn.len; fn->is_gen=genm; fn->is_async=asyncm;
                    parse_fn_params(L, fn);
                    { int sg=g_in_gen, sa=g_in_async; g_in_gen=genm; g_in_async=asyncm; fn->a = parse_stmt(L); g_in_gen=sg; g_in_async=sa; }
                    if (is_static) { node *pr=mknode(N_PROP); pr->str=fn->str; pr->slen=fn->slen; pr->a=fn;
                                     if (staticblk->list && staticblk->nlist<32) staticblk->list[staticblk->nlist++]=pr; }
                    else if (cls->list && cls->nlist<32) cls->list[cls->nlist++]=fn;
                } else {                                          /* field:  name [= expr] */
                    node *init = peek_punc(L,"=") ? (advance(L), parse_assign(L)) : mknode(N_UNDEF);
                    if (is_static) {                              /* static field -> co->statics[name] = init */
                        node *pr=mknode(N_PROP); pr->str=intern(mn.s,mn.len); pr->slen=mn.len; pr->a=init;
                        if (staticblk->list && staticblk->nlist<32) staticblk->list[staticblk->nlist++]=pr;
                    } else {                                      /* instance field -> this.name = init (run in N_NEW) */
                        node *th=mknode(N_THIS);
                        node *mem=mknode(N_MEMBER); mem->a=th; mem->str=intern(mn.s,mn.len); mem->slen=mn.len;
                        node *as=mknode(N_ASSIGN); as->op='='; as->a=mem; as->b=init;
                        node *ex=mknode(N_EXPR); ex->a=as;
                        if (fieldblk->list && fieldblk->nlist<32) fieldblk->list[fieldblk->nlist++]=ex;
                    }
                    skip_semi(L);
                }
            }
            expect_punc(L,"}");
            if (fieldblk->nlist>0) cls->b=fieldblk;               /* instance field initializers (run in N_NEW) */
            if (staticblk->nlist>0) cls->c=staticblk;             /* static methods/fields (built into co->statics) */
            return cls;
        }
        if (tok_is(t,"new")) {
            advance(L);
            { lexsave sv=lex_save(L); if (peek_punc(L,".")) { advance(L); token mt=peek(L); if (mt.type==T_IDENT && mt.len==6 && memcmp(mt.s,"target",6)==0) { advance(L); return mknode(N_NEWTARGET); } lex_restore(L,sv); } }   /* new.target meta-property (M700) */
            node *callee = parse_primary(L);
            /* member chain (a.b.C / a[k]) binds to `new`, but a `(` opens the
             * constructor's own arg list — so we stop the chain before calls. */
            for (;;) {
                if (peek_punc(L,".")) { advance(L); token p=advance(L); node *m=mknode(N_MEMBER); m->a=callee; m->str=intern(p.s,p.len); m->slen=p.len; callee=m; }
                else if (peek_punc(L,"[")) { advance(L); node *idx=parse_expr(L); expect_punc(L,"]"); node *m=mknode(N_INDEX); m->a=callee; m->b=idx; callee=m; }
                else break;
            }
            node *nw = mknode(N_NEW); nw->a = callee;
            if (peek_punc(L,"(")) { advance(L); nw->list = parse_list(L,")",&nw->nlist); }
            return nw;
        }
    }
    if (t.type == T_IDENT) { advance(L); node *n=mknode(N_IDENT); n->str=intern(t.s,t.len); n->slen=t.len; return n; }
    if (t.type == T_PUNC) {
        if (tok_is(t,"(")) { advance(L); node *e=parse_expr(L); expect_punc(L,")"); return e; }
        if (tok_is(t,"[")) { advance(L); node *n=mknode(N_ARRAY); n->list=parse_list(L,"]",&n->nlist); return n; }
        if (tok_is(t,"{")) {
            advance(L); node *n=mknode(N_OBJECT); n->list=aalloc(sizeof(node*)*64); n->nlist=0;
            while (!peek_punc(L,"}") && peek(L).type!=T_EOF && !g_err && !g_oom) {
                if (peek_punc(L,"...")) { advance(L); node *sp=mknode(N_SPREAD); sp->a=parse_assign(L); if(n->list && n->nlist<64) n->list[n->nlist++]=sp; if(peek_punc(L,",")) advance(L); continue; }  /* {...obj} */
                int asyncm = parse_async_method_marker(L);   /* { async m(){…} } (M682) */
                int genm = 0; if (peek_punc(L,"*")) { advance(L); genm = 1; }   /* { *m(){…} } : generator method */
                if (peek_punc(L,"[")) {   /* computed key: {[expr]: value} or computed method {[expr](){…}} (pr->b = key expr) */
                    advance(L); node *pr=mknode(N_PROP); pr->b=parse_assign(L); expect_punc(L,"]");
                    if (peek_punc(L,"(")) { node *fn=mknode(N_FUNC); fn->is_gen=genm; fn->is_async=asyncm; parse_fn_params(L,fn); { int sg=g_in_gen, sa=g_in_async; g_in_gen=genm; g_in_async=asyncm; fn->a=parse_stmt(L); g_in_gen=sg; g_in_async=sa; } pr->a=fn; }   /* {[e](){…}} */
                    else { expect_punc(L,":"); pr->a=parse_assign(L); }                                                       /* {[e]: value} */
                    if (n->list && n->nlist<64) n->list[n->nlist++]=pr;
                    if (peek_punc(L,",")) advance(L); else break;
                    continue;
                }
                token gtok=peek(L);   /* `get x(){…}` / `set x(v){…}` accessor; `get`/`set` stay valid keys otherwise */
                if (gtok.type==T_IDENT && (tok_is(gtok,"get")||tok_is(gtok,"set"))) {
                    lexsave sv=lex_save(L); int isget=gtok.s[0]=='g'; advance(L);   /* consume get/set */
                    token nm=peek(L);
                    if (nm.type==T_IDENT||nm.type==T_KW||nm.type==T_STR) {
                        advance(L);                                   /* consume the accessor name */
                        if (peek_punc(L,"(")) {                       /* confirmed: get/set NAME ( … ) { … } */
                            node *pr=mknode(N_PROP); pr->op=isget?'g':'s'; pr->str=intern(nm.s,nm.len); pr->slen=nm.len;
                            node *fn=mknode(N_FUNC); parse_fn_params(L,fn); fn->a=parse_stmt(L); pr->a=fn;
                            if (n->list && n->nlist<64) n->list[n->nlist++]=pr;
                            if (peek_punc(L,",")) advance(L); else break;
                            continue;
                        }
                    }
                    lex_restore(L,sv);                                /* not an accessor — `get`/`set` is an ordinary key */
                }
                token k=advance(L); node *pr=mknode(N_PROP);
                if (k.type==T_NUM) {   /* numeric key {200:...}: a T_NUM token has no .s/.len, so intern(k.s,k.len) was intern("") -- ALL numeric keys collided to one empty slot (M1751). Use the same num_to_str keystr() uses for m[200]/{[200]:} so the literal key matches lookups. */
                    char *ks = num_to_str(k.num); int kl = 0; while (ks[kl]) kl++;
                    pr->str = intern(ks, kl); pr->slen = kl;
                } else {
                    pr->str=intern(k.s,k.len); pr->slen=k.len;
                }
                if (peek_punc(L,":")) { advance(L); pr->a=parse_assign(L); }
                else if (peek_punc(L,"(")) { node *fn=mknode(N_FUNC); fn->is_gen=genm; fn->is_async=asyncm; parse_fn_params(L,fn); { int sg=g_in_gen, sa=g_in_async; g_in_gen=genm; g_in_async=asyncm; fn->a=parse_stmt(L); g_in_gen=sg; g_in_async=sa; } pr->a=fn; }   /* method shorthand: name(args){…} */
                else if (peek_punc(L,"=")) { advance(L); node *id=mknode(N_IDENT); id->str=pr->str; id->slen=pr->slen; node *as=mknode(N_ASSIGN); as->op='='; as->a=id; as->b=parse_assign(L); pr->a=as; }   /* {x = default} (destructuring) */
                else { node *id=mknode(N_IDENT); id->str=pr->str; id->slen=pr->slen; pr->a=id; }   /* {x} shorthand == {x:x} */
                if (n->list && n->nlist<64) n->list[n->nlist++]=pr;
                if (peek_punc(L,",")) advance(L); else break;
            }
            expect_punc(L,"}"); return n;
        }
    }
    rt_err("syntax: unexpected token"); advance(L); return mknode(N_UNDEF);
}

static node *parse_postfix(lexer *L) {
    node *e = parse_primary(L);
    int opt = 0;   /* once a `?.` appears, the rest of this chain short-circuits on a nullish
                    * receiver too (so `a?.b.c()` yields undefined when a is null, per spec).
                    * Marking a link optional only ADDS a nullish guard; non-null behaviour is
                    * unchanged, so propagating it to later links is safe. */
    for (;;) {
        if (peek_punc(L,".")) { advance(L); token p=advance(L); node *m=mknode(N_MEMBER); m->a=e; m->str=intern(p.s,p.len); m->slen=p.len; m->prefix=opt; e=m; }
        else if (peek_punc(L,"?.")) { opt=1; advance(L);   /* optional chaining: ?.x  ?.[i]  ?.() */
            if (peek_punc(L,"(")) { advance(L); node *call=mknode(N_CALL); call->a=e; call->prefix=1; call->list=parse_list(L,")",&call->nlist); e=call; }
            else if (peek_punc(L,"[")) { advance(L); node *idx=parse_expr(L); expect_punc(L,"]"); node *m=mknode(N_INDEX); m->a=e; m->b=idx; m->prefix=1; e=m; }
            else { token p=advance(L); node *m=mknode(N_MEMBER); m->a=e; m->str=intern(p.s,p.len); m->slen=p.len; m->prefix=1; e=m; }
        }
        else if (peek_punc(L,"[")) { advance(L); node *idx=parse_expr(L); expect_punc(L,"]"); node *m=mknode(N_INDEX); m->a=e; m->b=idx; m->prefix=opt; e=m; }
        else if (peek_punc(L,"(")) { advance(L); node *call=mknode(N_CALL); call->a=e; call->prefix=0; call->list=parse_list(L,")",&call->nlist); e=call; }   /* M1638: a PLAIN call, not itself written ?.( -- must NOT inherit `opt`. Unlike member/index access (where a missing property never throws either way, so propagating the nullish-receiver guard changes nothing), a call's OWN prefix also gates "swallow a missing-method/not-a-function error" (js.c ~2361/2364/2365/2369) -- inheriting it here let a LATER, non-optional call in the same chain (obj?.method(), only ?. on the MEMBER) silently swallow a real "no such method" error instead of throwing. The receiver-nullish short-circuit itself is unaffected: it's driven by callee->prefix (the member/index node's own flag), which still propagates correctly. */
        else if (peek_punc(L,"++")||peek_punc(L,"--")) { token o=advance(L); node *u=mknode(N_UPDATE); u->op=o.s[0]; u->a=e; u->prefix=0; e=u; }
        else if (peek(L).type==T_TEMPLATE) { token tt=advance(L); e = parse_tagged(e, tt.s, tt.len); }   /* tagged template: tag`…${x}…` -> tag([strings], x) */
        else break;
    }
    return e;
}

static node *parse_unary_inner(lexer *L) {
    if (g_in_async) {   /* inside an `async function`: `await expr` (a unary prefix, tighter than binary ops) (M680) */
        token aw = peek(L);
        if (aw.type==T_IDENT && aw.len==5 && memcmp(aw.s,"await",5)==0) { advance(L); node *u=mknode(N_AWAIT); u->a=parse_unary(L); return u; }
    }
    if (peek_punc(L,"!")||peek_punc(L,"-")||peek_punc(L,"+")||peek_punc(L,"~")) { token o=advance(L); node *u=mknode(N_UNARY); u->op=o.s[0]; u->a=parse_unary(L); return u; }
    if (peek_punc(L,"++")||peek_punc(L,"--")) { token o=advance(L); node *u=mknode(N_UPDATE); u->op=o.s[0]; u->prefix=1; u->a=parse_unary(L); return u; }
    if (peek_kw(L,"typeof")) { advance(L); node *u=mknode(N_UNARY); u->op='t'; u->a=parse_unary(L); return u; }
    if (peek_kw(L,"delete")) { advance(L); node *u=mknode(N_UNARY); u->op='d'; u->a=parse_unary(L); return u; }
    if (peek_kw(L,"void"))   { advance(L); node *u=mknode(N_UNARY); u->op='v'; u->a=parse_unary(L); return u; }
    return parse_postfix(L);
}
/* depth-guarded wrapper: a `!!!!...` / `typeof typeof...` / `- - -...` chain
 * otherwise recurses C-stack-deep with no bound (parse_assign only guards via the
 * paren/binary paths). MAXDEPTH protects the guard-page-less kernel stack. */
static node *parse_unary(lexer *L) {
    if (++g_depth > MAXDEPTH) { rt_err("expression nested too deep"); g_depth--; return mknode(N_UNDEF); }
    node *r = parse_unary_inner(L); g_depth--; return r;
}

/* binary precedence */
static int bin_prec(token t, int *code) {
    if (t.type==T_KW && tok_is(t,"in")) { *code='I'; return 8; }   /* `in` operator: relational precedence */
    if (t.type==T_KW && tok_is(t,"instanceof")) { *code='S'; return 8; }   /* `instanceof`: relational precedence */
    if (t.type!=T_PUNC) return 0;
    if (tok_is(t,"**")) { *code='P'; return 12; }   /* exponentiation: tighter than * / %, right-associative */
    if (tok_is(t,"*")||tok_is(t,"/")||tok_is(t,"%")) { *code=t.s[0]; return 11; }
    if (tok_is(t,"+")||tok_is(t,"-")) { *code=t.s[0]; return 10; }
    if (tok_is(t,">>>")) { *code='U'; return 9; }   /* unsigned right shift (M269) */
    if (tok_is(t,"<<")||tok_is(t,">>")) { *code=(t.s[0]=='<')?'L':'R'; return 9; }
    if (tok_is(t,"<")||tok_is(t,">")) { *code=t.s[0]; return 8; }
    if (tok_is(t,"<=")) { *code='l'; return 8; } if (tok_is(t,">=")) { *code='g'; return 8; }
    if (tok_is(t,"===")) { *code='='; return 7; }  if (tok_is(t,"==")) { *code='e'; return 7; }   /* === strict, == loose (M271) */
    if (tok_is(t,"!==")) { *code='!'; return 7; }  if (tok_is(t,"!=")) { *code='n'; return 7; }   /* !== strict, != loose (M271) */
    if (tok_is(t,"&")) { *code='&'; return 6; }
    if (tok_is(t,"^")) { *code='^'; return 5; }   /* bitwise XOR: between & and | */
    if (tok_is(t,"|")) { *code='|'; return 4; }
    if (tok_is(t,"&&")) { *code='A'; return 3; }
    if (tok_is(t,"||")) { *code='O'; return 2; }
    if (tok_is(t,"??")) { *code='N'; return 2; }   /* nullish coalescing */
    return 0;
}

static node *parse_binary(lexer *L, int minp) {
    node *left = parse_unary(L);
    for (;;) {
        int code; int p = bin_prec(peek(L), &code);
        if (p == 0 || p < minp) break;
        advance(L);
        node *right = parse_binary(L, code=='P'?p:p+1);   /* `**` is right-associative (recurse at same precedence) */
        int logical = (code=='A'||code=='O'||code=='N');
        node *n = mknode(logical?N_LOGICAL:N_BINARY); n->op=code; n->a=left; n->b=right;
        left = n;
    }
    return left;
}

static node *parse_cond(lexer *L) {
    node *c = parse_binary(L, 1);
    if (peek_punc(L,"?")) { advance(L); node *n=mknode(N_COND); n->a=c; n->b=parse_assign(L); expect_punc(L,":"); n->c=parse_assign(L); return n; }
    return c;
}

/* Build an arrow function N_FUNC from already-parsed params; parses the body
 * (a `{ }` block, or an expression that becomes an implicit `return`). */
static node *make_arrow(lexer *L, node **params, int np, int is_async) {
    node *fn = mknode(N_FUNC);
    fn->prefix = 1;   /* mark as arrow: inherits `this` lexically (no own binding) */
    fn->is_async = is_async;
    fn->list = aalloc((long)sizeof(node*) * (np>0?np:1)); fn->nlist = np;
    for (int i=0;i<np;i++) fn->list[i]=params[i];
    int sa = g_in_async; g_in_async = is_async;   /* `await` is valid in the body iff this arrow is async (M681) */
    if (peek_punc(L,"{")) { fn->a = parse_stmt(L); }
    else { node *ret=mknode(N_RETURN); ret->a=parse_assign(L);
           node *blk=mknode(N_BLOCK); blk->list=aalloc(sizeof(node*)); if(blk->list){blk->list[0]=ret; blk->nlist=1;} fn->a=blk; }
    g_in_async = sa;
    return fn;
}

static node *parse_assign(lexer *L) {
    if (++g_depth > MAXDEPTH) { rt_err("max recursion"); g_depth--; return mknode(N_UNDEF); }
    if (g_in_gen) {                              /* inside a `function*` body: `yield [*] [expr]` */
        token yt = peek(L);
        if (yt.type==T_IDENT && yt.len==5 && memcmp(yt.s,"yield",5)==0) {
            advance(L);                          /* consume `yield` */
            node *y = mknode(N_YIELD);
            if (peek_punc(L,"*")) { advance(L); y->op='*'; }   /* yield* delegate (spreads an iterable) */
            token nt = peek(L);                  /* operand optional: `yield` / `yield;` -> yield undefined */
            if (!(nt.type==T_EOF || (nt.type==T_PUNC && (tok_is(nt,";")||tok_is(nt,")")||tok_is(nt,"]")||tok_is(nt,"}")||tok_is(nt,",")||tok_is(nt,":")))))
                y->a = parse_assign(L);
            g_depth--; return y;
        }
    }
    /* arrow functions: `x => body`, `(a, b, ...) => body`, plus the `async` forms
     * `async x => …` / `async (…) => …`. Detected with bounded lookahead (save/restore
     * the lexer) so a plain `(expr)`, a call `async(...)`, or `async` as a bare
     * identifier isn't misparsed. (async forms: M681) */
    token t0 = peek(L);
    int a_async = 0; lexsave a_sv = lex_save(L);
    if (t0.type==T_IDENT && t0.len==5 && memcmp(t0.s,"async",5)==0) {
        advance(L);                                  /* tentatively consume `async` */
        token nx = peek(L);
        if (nx.type==T_IDENT || (nx.type==T_PUNC && tok_is(nx,"("))) { a_async = 1; t0 = nx; }   /* maybe `async x =>` / `async (...) =>` */
        else lex_restore(L, a_sv);                   /* `async` followed by something else -> not an async arrow */
    }
    if (t0.type==T_IDENT) {
        lexsave sv = lex_save(L); token id = advance(L);
        if (peek_punc(L,"=>")) { advance(L); node *p=mknode(N_IDENT); p->str=intern(id.s,id.len); p->slen=id.len;
                                 node *ps[1]={p}; node *fn=make_arrow(L,ps,1,a_async); g_depth--; return fn; }
        lex_restore(L, sv);
        if (a_async) lex_restore(L, a_sv);            /* consumed `async` but no arrow -> give it all back */
    } else if (t0.type==T_PUNC && tok_is(t0,"(")) {
        lexsave sv = lex_save(L); advance(L);
        node *ps[16]; int np=0, ok=1;
        if (!peek_punc(L,")")) for(;;){ int rest=0; if(peek_punc(L,"...")){ advance(L); rest=1; }
            if (!rest && (peek_punc(L,"[")||peek_punc(L,"{"))) {   /* ([a,b])=>… / ({x})=>… destructuring param */
                node *pat=parse_primary(L);
                if (peek_punc(L,"=")) { advance(L); node *as=mknode(N_ASSIGN); as->op='='; as->a=pat; as->b=parse_assign(L); pat=as; }
                if(np<16) ps[np++]=pat;
                if(peek_punc(L,",")) { advance(L); continue; } else break;
            }
            token p=peek(L); if(p.type!=T_IDENT){ ok=0; break; } advance(L);
            if(np<16){ node *id=mknode(N_IDENT); id->str=intern(p.s,p.len); id->slen=p.len; if(rest) id->op='.'; ps[np++]=id; }
            if(rest) break;   /* ...rest is the last param */
            if(peek_punc(L,",")) advance(L); else break; }
        if (ok && peek_punc(L,")")) { advance(L); if (peek_punc(L,"=>")) { advance(L); node *fn=make_arrow(L,ps,np,a_async); g_depth--; return fn; } }
        lex_restore(L, sv);
        if (a_async) lex_restore(L, a_sv);            /* `async (...)` with no arrow -> a call to `async`; give it all back */
    }
    node *left = parse_cond(L);
    token t = peek(L);
    if (t.type==T_PUNC && (tok_is(t,"=")||tok_is(t,"+=")||tok_is(t,"-=")||tok_is(t,"*=")||tok_is(t,"/=")||tok_is(t,"%=")||
                           tok_is(t,"&=")||tok_is(t,"|=")||tok_is(t,"^=")||tok_is(t,"<<=")||tok_is(t,">>>=")||tok_is(t,">>=")||tok_is(t,"**=")||
                           tok_is(t,"||=")||tok_is(t,"&&=")||tok_is(t,"?\?="))) {
        advance(L); node *n=mknode(N_ASSIGN);
        /* explicit op codes (reuse the binary-operator codes): t.s[0] can't tell
         * <<= from < or **= from *=, so map each token to its compute code.
         * ||= &&= ??= get lowercase o/a/n -- they short-circuit (handled separately). */
        n->op = tok_is(t,"+=")?'+': tok_is(t,"-=")?'-': tok_is(t,"*=")?'*': tok_is(t,"/=")?'/': tok_is(t,"%=")?'%':
                tok_is(t,"&=")?'&': tok_is(t,"|=")?'|': tok_is(t,"^=")?'^':
                tok_is(t,"<<=")?'L': tok_is(t,">>>=")?'U': tok_is(t,">>=")?'R': tok_is(t,"**=")?'P':
                tok_is(t,"||=")?'o': tok_is(t,"&&=")?'a': tok_is(t,"?\?=")?'n': '=';
        n->a=left; n->b=parse_assign(L); g_depth--; return n;
    }
    g_depth--; return left;
}

static node *parse_expr(lexer *L) {
    node *e = parse_assign(L);
    while (peek_punc(L,",")) { advance(L); e = parse_assign(L); }   /* comma: keep last */
    return e;
}

static node *parse_block(lexer *L) {
    expect_punc(L,"{"); node *n=mknode(N_BLOCK); n->list=aalloc(sizeof(node*)*256); n->nlist=0;
    for (;;) { skip_semi(L); if (peek_punc(L,"}")||peek(L).type==T_EOF||g_err||g_oom) break; node *s=parse_stmt(L); if(n->list&&n->nlist<256) n->list[n->nlist++]=s; }
    expect_punc(L,"}"); return n;
}

static node *parse_var(lexer *L) {
    int block_scoped = peek_kw(L,"let") || peek_kw(L,"const");   /* vs function-scoped `var` */
    advance(L);  /* var/let/const */
    node *n=mknode(N_VAR); n->num=block_scoped; n->list=aalloc(sizeof(node*)*32); n->nlist=0;
    for (;;) {
        node *decl=mknode(N_PROP);
        if (peek_punc(L,"[")||peek_punc(L,"{")) { decl->b=parse_primary(L); }   /* [..]/{..} destructuring pattern */
        else { token id=advance(L); decl->str=intern(id.s,id.len); decl->slen=id.len; }
        if (peek_punc(L,"=")) { advance(L); decl->a=parse_assign(L); }
        if (n->list && n->nlist<32) n->list[n->nlist++]=decl;
        if (g_err || g_oom) break;
        if (peek_punc(L,",")) advance(L); else break;
    }
    return n;
}

static node *parse_stmt(lexer *L) {
    if (++g_depth > MAXDEPTH) { rt_err("max recursion"); g_depth--; return mknode(N_UNDEF); }
    node *r;
    if (peek(L).type==T_IDENT) {   /* labeled statement `name: stmt` (M280): IDENT then ':' at statement start. ?:/object-literal/case: never start a statement with IDENT-then-colon, so this is unambiguous; lex_restore if it's just an expression like `a ? b : c`. */
        lexsave sv=lex_save(L); token id=advance(L);
        if (peek_punc(L,":")) { advance(L); node *body=parse_stmt(L); body->label=intern(id.s,id.len); g_depth--; return body; }
        lex_restore(L,sv);
    }
    if (peek_punc(L,"{")) { r=parse_block(L); g_depth--; return r; }
    if (peek_kw(L,"var")||peek_kw(L,"let")||peek_kw(L,"const")) { r=parse_var(L); g_depth--; return r; }
    if (peek_kw(L,"function")) { r=parse_primary(L); g_depth--; return r; }   /* function decl */
    if (peek_kw(L,"return")) { advance(L); node *n=mknode(N_RETURN); if(!peek_punc(L,"}")&&!peek_punc(L,";")&&peek(L).type!=T_EOF) n->a=parse_expr(L); g_depth--; return n; }
    if (peek_kw(L,"break")) { advance(L); node *n=mknode(N_BREAK); if (peek(L).type==T_IDENT){ token lt=advance(L); n->label=intern(lt.s,lt.len); } g_depth--; return n; }   /* break [label] (M280) */
    if (peek_kw(L,"continue")) { advance(L); node *n=mknode(N_CONTINUE); if (peek(L).type==T_IDENT){ token lt=advance(L); n->label=intern(lt.s,lt.len); } g_depth--; return n; }
    if (peek_kw(L,"if")) {
        advance(L); expect_punc(L,"("); node *n=mknode(N_IF); n->a=parse_expr(L); expect_punc(L,")");
        n->b=parse_stmt(L); skip_semi(L);   /* a ; may terminate the then-branch before else */
        if (peek_kw(L,"else")) { advance(L); n->c=parse_stmt(L); } g_depth--; return n;
    }
    if (peek_kw(L,"while")) { advance(L); expect_punc(L,"("); node *n=mknode(N_WHILE); n->a=parse_expr(L); expect_punc(L,")"); n->b=parse_stmt(L); g_depth--; return n; }
    if (peek_kw(L,"try")) {
        advance(L); node *n=mknode(N_TRY); n->a=parse_block(L);
        if (peek_kw(L,"catch")) { advance(L);
            if (peek_punc(L,"(")) { advance(L); token p=advance(L); if(p.type==T_IDENT){ n->str=intern(p.s,p.len); n->slen=p.len; } expect_punc(L,")"); }
            n->b=parse_block(L); }
        if (peek_kw(L,"finally")) { advance(L); n->c=parse_block(L); }
        g_depth--; return n;
    }
    if (peek_kw(L,"throw")) { advance(L); node *n=mknode(N_THROW); n->a=parse_expr(L); g_depth--; return n; }
    if (peek_kw(L,"do")) { advance(L); node *n=mknode(N_DOWHILE); n->b=parse_stmt(L); skip_semi(L);
        if (peek_kw(L,"while")) advance(L); expect_punc(L,"("); n->a=parse_expr(L); expect_punc(L,")"); g_depth--; return n; }
    if (peek_kw(L,"switch")) {
        advance(L); expect_punc(L,"("); node *n=mknode(N_SWITCH); n->a=parse_expr(L); expect_punc(L,")"); expect_punc(L,"{");
        n->list=aalloc(sizeof(node*)*64); n->nlist=0;
        while (!peek_punc(L,"}") && peek(L).type!=T_EOF && !g_err && !g_oom) {
            node *cl=mknode(N_CASE);
            if (peek_kw(L,"case")) { advance(L); cl->a=parse_expr(L); expect_punc(L,":"); }
            else if (peek_kw(L,"default")) { advance(L); cl->a=0; expect_punc(L,":"); }
            else { advance(L); continue; }                /* tolerate stray tokens */
            cl->list=aalloc(sizeof(node*)*64); cl->nlist=0;
            for (;;) { skip_semi(L); if (peek_kw(L,"case")||peek_kw(L,"default")||peek_punc(L,"}")||peek(L).type==T_EOF||g_err||g_oom) break;
                node *s=parse_stmt(L); if (cl->list && cl->nlist<64) cl->list[cl->nlist++]=s; }
            if (n->list && n->nlist<64) n->list[n->nlist++]=cl;
        }
        expect_punc(L,"}"); g_depth--; return n;
    }
    if (peek_kw(L,"for")) {
        advance(L); expect_punc(L,"(");
        /* for (x of iterable) — detect the contextual `of` with bounded lookahead */
        lexsave sv = lex_save(L);
        int fe_blk = peek_kw(L,"let")||peek_kw(L,"const");   /* block-scoped loop var -> fresh per iteration */
        if (peek_kw(L,"var")||peek_kw(L,"let")||peek_kw(L,"const")) advance(L);
        if (peek_punc(L,"[")||peek_punc(L,"{")) {   /* for (var [a,b] of ...) — destructuring loop var */
            node *pat=parse_primary(L); token kw=peek(L);
            if (kw.type==T_IDENT && kw.len==2 && kw.s[0]=='o' && kw.s[1]=='f') {
                advance(L); node *fo=mknode(N_FOROF); fo->c=pat; fo->num=fe_blk;
                fo->a=parse_expr(L); expect_punc(L,")"); fo->b=parse_stmt(L); g_depth--; return fo; }
        } else {
            token v = peek(L);
            if (v.type==T_IDENT) { advance(L); token kw = peek(L);
                int isof = (kw.type==T_IDENT && kw.len==2 && kw.s[0]=='o' && kw.s[1]=='f');
                int isin = ((kw.type==T_IDENT||kw.type==T_KW) && kw.len==2 && kw.s[0]=='i' && kw.s[1]=='n');   /* `in` is now a keyword */
                if (isof || isin) {
                    advance(L); node *fo=mknode(isof?N_FOROF:N_FORIN); fo->num=fe_blk; fo->str=intern(v.s,v.len); fo->slen=v.len;
                    fo->a=parse_expr(L); expect_punc(L,")"); fo->b=parse_stmt(L); g_depth--; return fo; }
            }
        }
        lex_restore(L, sv);
        node *n=mknode(N_FOR);
        if (!peek_punc(L,";")) { if (peek_kw(L,"var")||peek_kw(L,"let")||peek_kw(L,"const")) n->a=parse_var(L); else n->a=parse_expr(L); }
        expect_punc(L,";");
        if (!peek_punc(L,";")) n->b=parse_expr(L);
        expect_punc(L,";");
        if (!peek_punc(L,")")) n->c=parse_expr(L);
        expect_punc(L,")");
        n->d=parse_stmt(L); g_depth--; return n;
    }
    node *e=mknode(N_EXPR); e->a=parse_expr(L); g_depth--; return e;
}

static node *parse_program(lexer *L) {
    node *n=mknode(N_PROGRAM); n->list=aalloc(sizeof(node*)*1024); n->nlist=0;
    for (;;) { skip_semi(L); if (peek(L).type==T_EOF||g_err||g_oom) break; node *s=parse_stmt(L); if(n->list&&n->nlist<1024) n->list[n->nlist++]=s; }
    return n;
}

/* =========================== values =========================== */
enum { V_UNDEF, V_NULL, V_BOOL, V_NUM, V_STR, V_OBJ, V_ARR, V_FUN, V_NATIVE,
       V_MAP, V_SET, V_REGEX, V_DATE, V_ELEMENT, V_BOUND, V_ACCESSOR, V_CLASSLIST, V_CANVASCTX,
       /* V_PROXY (ES6 Proxy, get/set traps): like V_ACCESSOR/V_BOUND its val.t stays
        * V_OBJ — only obj->kind is V_PROXY. The target lives in vals[0], the handler in
        * vals[1] (n==2). is_proxy/proxy_target/proxy_handler below; NOT obj_keyed, so its
        * vals[] are never iterated as property keys (no internal-layout leak). (M-proxy) */
       V_PROXY,
       /* V_SYMBOL is a real val.t (a primitive), unlike the markers above which are
        * only obj->kind tags. A symbol carries a unique id in val.num and an optional
        * description string in val.str. (M-symbol) */
       V_SYMBOL,
       /* V_PROMISE (synchronous-resolution model, M679): an obj->kind tag like V_MAP —
        * its val.t stays V_OBJ (so typeof is "object", method dispatch goes via the
        * V_OBJ branch). To add ZERO bytes to every obj, state+value live in the promise's
        * own vals[]: vals[0]=NUM(state) (0=pending,1=fulfilled,2=rejected), vals[1]=value/
        * reason (see pstate/pvalue/pset). Not obj_keyed, so vals[] is never walked as props. */
       V_PROMISE,
       /* V_ARRAYBUF (ArrayBuffer) + V_U8ARRAY (Uint8Array): binary byte stores (M1850).
        * val.t stays V_OBJ (typeof "object"). Bytes live in obj->bytes[0..nbytes); a
        * Uint8Array keeps its backing ArrayBuffer in vals[0] (for .buffer + liveness).
        * Not obj_keyed — indexing is byte access via dedicated N_INDEX branches. */
       V_ARRAYBUF, V_U8ARRAY };
typedef struct val val;
typedef struct obj obj;
typedef struct env env;

struct val { int t; double num; const char *str; obj *o; };   /* num is IEEE-754 double (V_NUM); also holds V_BOOL 0/1 and a V_SYMBOL id (< 2^53) */

struct obj {
    int kind;
    int frozen;        /* Object.freeze: blocks property set/delete (shallow) */
    /* object: parallel key/val arrays */
    const char **keys; val *vals; int n, cap;
    /* function */
    node *fn; env *scope;
    val (*native)(val *args, int nargs);
    obj *home_proto;   /* class constructors: an object holding the methods to copy onto each new instance */
    obj *super_class;  /* a class method/ctor's parent constructor, for super() / super.m() */
    obj *ctor_class;   /* the constructor `new` used to build this instance (for `instanceof`) */
    obj *parent_class; /* a class ctor's TRUE direct parent (distinct from super_class, which points
                        * at the GRANDparent for an inherited ctor); the `instanceof` chain walks this */
    node *fields;      /* a class ctor's OWN instance-field initializers (an N_BLOCK of `this.x=init`);
                        * N_NEW runs them up the parent_class chain before the constructor */
    obj *statics;      /* a class ctor's static methods/fields as a V_OBJ (Class.method / Class.field) */
    void *rx;          /* compiled regex (struct regex*) when kind==V_REGEX */
    obj *match_props;  /* a regex match-result V_ARR's named props (.index, .groups) as a keyed V_OBJ; NULL otherwise (M577) */
    obj *proto;        /* [[Prototype]] chain parent; NULL = none (every pre-M263 object, Object.create(null)) */
    obj *fn_proto;     /* a plain function's `.prototype` object (becomes each `new F()` instance's proto). Stored in a field, NOT a keyed prop, because functions aren't obj_keyed */
    uint8_t *bytes; int nbytes;   /* byte store for V_ARRAYBUF (ArrayBuffer) / V_U8ARRAY (Uint8Array view). NULL otherwise (M1850) */
};

struct env { const char **keys; val *vals; int n, cap; env *parent; int func_scope; };   /* func_scope=1 marks a function (or the global) boundary: `var` hoists to here, not into inner blocks */

static val UND(void){ val v; v.t=V_UNDEF; v.num=0; v.str=0; v.o=0; return v; }
static val NUM(double x){ val v=UND(); v.t=V_NUM; v.num=x; return v; }
static val BOOLV(int b){ val v=UND(); v.t=V_BOOL; v.num=b?1:0; return v; }
static val STRV(const char *s){ val v=UND(); v.t=V_STR; v.str=s?s:""; return v; }
/* ---- ES6 Symbol (M-symbol) ----
 * A symbol is a primitive identity: equal iff same id. `id` lives in val.num, the
 * optional description (for Symbol(desc) / val_to_str) in val.str.
 * Well-known symbols reserve LOW fixed ids (so Symbol.iterator === Symbol.iterator
 * is stable across calls); Symbol() hands out ids from g_sym_next, which STARTS
 * above the reserved range so a user symbol can never collide with a well-known one. */
#define SYM_ID_ITERATOR 1          /* Symbol.iterator (fixed well-known id) */
#define SYM_ID_FIRST    16         /* Symbol() ids start here, above all well-knowns */
static int64_t g_sym_next = SYM_ID_FIRST;
static val SYMV(int64_t id, const char *desc){ val v=UND(); v.t=V_SYMBOL; v.num=id; v.str=desc; return v; }
static val g_throwval;        /* value of the in-flight `throw` (when g_threw) */
static val g_newtarget;       /* new.target — the constructor an active `new` is building; V_UNDEF (zero-init) outside construction (M700) */

static obj *new_obj(int kind){ obj *o=aalloc(sizeof(obj)); if(!o) return 0; memset(o,0,sizeof(*o)); o->kind=kind; o->cap=4; o->keys=aalloc(sizeof(char*)*o->cap); o->vals=aalloc(sizeof(val)*o->cap); if(!o->keys||!o->vals){ g_oom=1; return 0; } return o; }
static obj *g_gen_arr;   /* eval: the active generator's yield-collection array (NULL outside a generator body) */
/* The built-in Array/Object constructor objects, recorded at setup so `instanceof`
 * can recognise array/object literals against them (they have no ctor_class link). M419 */
static obj *g_array_ctor, *g_object_ctor, *g_promise_ctor;

/* True only for objects whose keys[]/vals[] are real keyed properties (V_OBJ and
 * V_REGEX, which use obj_set). V_ARR/V_MAP/V_SET/V_DATE store data in vals[] via
 * arr_push_val, which does NOT maintain keys[] — keys[] there is garbage and
 * shorter than n, so it must NEVER be iterated as property keys. */
static int obj_keyed(obj *o){ return o && (o->kind==V_OBJ || o->kind==V_REGEX || o->kind==V_CANVASCTX); }   /* M1796: a canvas 2D context stores __cid + fillStyle as keyed properties */
static void obj_set(obj *o, const char *key, val v) {
    if (!o || !o->keys || !o->vals) { g_oom=1; return; }   /* a NULL/half-built obj (OOM) — don't deref */
    if (!obj_keyed(o)) return;   /* not a keyed object (array/map/set/date) — ignore stray property writes */
    if (o->frozen) return;       /* Object.freeze: silently ignore writes (non-strict semantics) */
    for (int i=0;i<o->n;i++) if (strcmp(o->keys[i],key)==0) { o->vals[i]=v; return; }
    if (o->n>=o->cap) { int nc=o->cap*2; const char **nk=aalloc(sizeof(char*)*nc); val *nv=aalloc(sizeof(val)*nc); if(!nk||!nv){g_oom=1;return;} memcpy(nk,o->keys,sizeof(char*)*o->n); memcpy(nv,o->vals,sizeof(val)*o->n); o->keys=nk; o->vals=nv; o->cap=nc; }
    o->keys[o->n]=key; o->vals[o->n]=v; o->n++;
}
static int obj_get(obj *o, const char *key, val *out) {
    if (!obj_keyed(o)) return 0;   /* array/map/set/date have no keyed properties */
    for (int i=0;i<o->n;i++) if (strcmp(o->keys[i],key)==0) { *out=o->vals[i]; return 1; }
    return 0;
}
/* Remove an own property (the `delete obj.x` operator). Shifts keys[]/vals[] down,
 * exactly like the proven Map/Set .delete(); only touches keyed objects (V_OBJ/V_REGEX),
 * never arrays/maps whose vals[] are positional. */
static int obj_delete(obj *o, const char *key) {
    if (!obj_keyed(o)) return 0;
    if (o->frozen) return 0;   /* Object.freeze: can't delete */
    for (int i=0;i<o->n;i++) if (strcmp(o->keys[i],key)==0) {
        for (int j=i;j+1<o->n;j++) { o->keys[j]=o->keys[j+1]; o->vals[j]=o->vals[j+1]; }
        o->n--; return 1;
    }
    return 0;
}
static void arr_push_val(obj *o, val v) {
    if (o->n >= o->cap) { int nc=o->cap*2+2; val *nv=aalloc((long)sizeof(val)*nc); if(!nv){g_oom=1;return;} memcpy(nv,o->vals,sizeof(val)*o->n); o->vals=nv; o->cap=nc; }
    o->vals[o->n++]=v;
}
static val obj_val(obj *o);          /* fwd (defined near install_globals) */
static val obj_val_native(obj *o);

/* ---- number/string helpers ---- */
static char *i64_to_str(int64_t v) {
    char tmp[24]; int i=0; int neg = v<0; uint64_t u = neg?(uint64_t)(-(v+1))+1:(uint64_t)v;
    if (u==0) tmp[i++]='0';
    while (u){ tmp[i++]='0'+(int)(u%10); u/=10; }
    if (neg) tmp[i++]='-';
    char *s=aalloc(i+1); if(!s) return ""; for(int j=0;j<i;j++) s[j]=tmp[i-1-j]; s[i]=0; return s;
}

/* ---- IEEE-754 double helpers (the engine's numbers are doubles; js.o is built with SSE) ---- */
#define JS_INF (__builtin_inf())
#define JS_NAN (__builtin_nan(""))
static int js_isnan(double x){ return x != x; }
static int js_isfinite(double x){ return (x - x) == 0.0; }   /* finite -> 0; inf/nan -> nan != 0 */
static int js_isinf(double x){ return js_isfinite(x) ? 0 : !js_isnan(x); }
static int js_toint(double d){ return js_isnan(d) ? 0 : (int)d; }   /* ES ToIntegerOrInfinity: NaN (e.g. from an undefined index arg) -> 0, not a huge negative (int)NaN (M1782) */
static double js_trunc(double x){            /* toward zero */
    if (!js_isfinite(x)) return x;
    if (x >= 4503599627370496.0 || x <= -4503599627370496.0) return x;   /* >= 2^52: already integral */
    return (double)(int64_t)x;
}
static double js_floor(double x){ double t=js_trunc(x); return (js_isfinite(x) && t>x) ? t-1.0 : t; }
static double js_ceil (double x){ double t=js_trunc(x); return (js_isfinite(x) && t<x) ? t+1.0 : t; }
static double js_round(double x){ return js_isfinite(x) ? js_floor(x+0.5) : x; }   /* JS Math.round = floor(x+0.5) */
static double js_fabs (double x){ return x<0 ? -x : x; }
static double js_fmod (double a, double b){   /* JS %: sign of a; a - b*trunc(a/b); x%0 and Inf%y -> NaN */
    if (js_isnan(a) || js_isnan(b) || js_isinf(a) || b==0.0) return JS_NAN;
    if (js_isinf(b)) return a;
    return a - js_trunc(a/b)*b;
}
static double js_sqrt(double x){             /* Newton; no libm/libcall (freestanding kernel + host) */
    if (x < 0.0) return JS_NAN;
    if (x == 0.0 || !js_isfinite(x)) return x;   /* 0, +Inf, NaN pass through */
    double g = x > 1.0 ? x : 1.0;
    for (int i=0;i<64;i++){ double ng=0.5*(g + x/g); if (ng==g) break; g=ng; }
    return g;
}
static double js_cbrt(double x){
    if (x==0.0 || !js_isfinite(x)) return x;
    int neg = x<0; double a = neg?-x:x, g = a>1.0?a:1.0;
    for (int i=0;i<80;i++){ double ng=(2.0*g + a/(g*g))/3.0; if (ng==g) break; g=ng; }
    return neg?-g:g;
}
static double js_ln(double x){               /* natural log; x>0 */
    if (x<=0.0) return x==0.0 ? -JS_INF : JS_NAN;
    if (!js_isfinite(x)) return x;           /* ln(+inf)=+inf, ln(NaN)=NaN — M1779: the m*2^k range reduction below never leaves +inf (inf*0.5==inf), so this guards a script-triggerable infinite loop (Math.log(1/0), Math.pow(1/0,0.5)) */
    int k=0; while (x>=2.0){ x*=0.5; k++; } while (x<1.0){ x*=2.0; k--; }   /* x = m*2^k, m in [1,2) */
    double t=(x-1.0)/(x+1.0), t2=t*t, term=t, sum=0.0;                      /* ln(m)=2*(t+t^3/3+t^5/5+..) */
    for (int i=1;i<=25;i+=2){ sum += term/i; term *= t2; }
    return 2.0*sum + (double)k*0.69314718055994530942;
}
static double js_exp(double x){
    if (x==0.0) return 1.0;
    if (js_isinf(x)) return x<0 ? 0.0 : JS_INF;
    double ln2=0.69314718055994530942; double kf=js_round(x/ln2); int k=(int)kf;   /* x = k*ln2 + r */
    double r=x-kf*ln2, term=1.0, sum=1.0;
    for (int i=1;i<=20;i++){ term *= r/i; sum += term; }
    double p=1.0; if (k>=0){ for(int i=0;i<k;i++) p*=2.0; } else { for(int i=0;i<-k;i++) p*=0.5; }
    return sum*p;
}
static double js_pow(double b, double e){
    if (e==0.0) return 1.0;
    if (e==js_trunc(e) && e>=-1024.0 && e<=1024.0){            /* integer exponent: exact repeated multiply */
        int neg=e<0; int64_t n=(int64_t)(neg?-e:e); double r=1.0;
        for (int64_t i=0;i<n;i++) r*=b;
        return neg ? 1.0/r : r;
    }
    if (b==0.0) return 0.0;
    if (b<0.0) return JS_NAN;                                  /* negative base, fractional exp -> NaN */
    return js_exp(e*js_ln(b));                                 /* general b^e = exp(e*ln b) */
}
/* ---- trig (range-reduced Taylor; ~12-15 digits over the reduced range) ---- */
static double js_sin(double x){
    if (!js_isfinite(x)) return JS_NAN;
    double twopi=6.283185307179586, pi=3.141592653589793;
    x = js_fmod(x, twopi); if (x>pi) x-=twopi; else if (x<-pi) x+=twopi;   /* reduce to [-pi, pi] */
    double term=x, sum=x, x2=x*x;
    for (int i=1;i<=12;i++){ term *= -x2/((double)(2*i)*(2*i+1)); sum += term; }   /* x - x^3/3! + x^5/5! - .. */
    return sum;
}
static double js_cos(double x){ return js_isfinite(x) ? js_sin(x + 1.5707963267948966) : JS_NAN; }   /* cos x = sin(x + pi/2) */
static double js_tan(double x){ double c=js_cos(x); return c==0.0 ? JS_NAN : js_sin(x)/c; }
static double js_atan(double x){             /* arctan, result in (-pi/2, pi/2) */
    if (js_isnan(x)) return JS_NAN;
    if (js_isinf(x)) return x<0 ? -1.5707963267948966 : 1.5707963267948966;
    int neg=x<0; if(neg) x=-x;
    /* halve the argument until small (atan(x)=2*atan(x/(1+sqrt(1+x^2)))) so the Taylor
     * series converges fast — a plain series at x~1 (Leibniz) is far too slow. */
    int halvings=0; while (x > 0.2 && halvings < 60){ x = x/(1.0 + js_sqrt(1.0 + x*x)); halvings++; }
    double term=x, sum=x, x2=x*x;
    for (int i=1;i<=14;i++){ term *= -x2; sum += term/(2*i+1); }   /* x - x^3/3 + x^5/5 - .. */
    while (halvings-- > 0) sum *= 2.0;
    return neg ? -sum : sum;
}
static double js_atan2(double y, double x){  /* full-quadrant angle of (x,y) */
    if (x>0.0) return js_atan(y/x);
    if (x<0.0) return js_atan(y/x) + (y>=0.0 ? 3.141592653589793 : -3.141592653589793);
    if (y>0.0) return 1.5707963267948966;
    if (y<0.0) return -1.5707963267948966;
    return 0.0;
}
static double js_asin(double x){ if (x<-1.0||x>1.0) return JS_NAN; if (x==1.0) return 1.5707963267948966; if (x==-1.0) return -1.5707963267948966; return js_atan(x/js_sqrt(1.0-x*x)); }
static double js_acos(double x){ if (x<-1.0||x>1.0) return JS_NAN; return 1.5707963267948966 - js_asin(x); }
static double js_sinh(double x){ double e=js_exp(x); return (e - 1.0/e)*0.5; }
static double js_cosh(double x){ double e=js_exp(x); return (e + 1.0/e)*0.5; }
static double js_tanh(double x){ if (x>20.0) return 1.0; if (x<-20.0) return -1.0; double e=js_exp(2.0*x); return (e-1.0)/(e+1.0); }
/* JS ToInt32: NaN/Inf -> 0; truncate toward zero; take low 32 bits (signed). */
static int32_t to_i32(double d){
    if (!js_isfinite(d)) return 0;
    if (d>=9.2e18 || d<=-9.2e18){ double two32=4294967296.0; d -= js_trunc(d/two32)*two32; }
    return (int32_t)(uint32_t)(int64_t)d;
}
/* double -> string, JS Number-to-string-ish: integers print exactly; otherwise up to 16
 * significant digits with trailing zeros trimmed; NaN/Infinity spelled out. Not a full
 * shortest-round-trip dtoa, but it renders the common cases (3.14, 0.5, 2/3, 1e21) cleanly. */
static char *num_to_str(double d){
    if (js_isnan(d)) return "NaN";
    if (js_isinf(d)) return d<0 ? "-Infinity" : "Infinity";
    if (d==0.0) return "0";                                              /* String(-0) === "0" */
    if (d==js_trunc(d) && d>=-9.0e18 && d<=9.0e18) return i64_to_str((int64_t)d);   /* integral & exact */
    char *buf=aalloc(40); if(!buf) return "0"; int p=0;
    double x=d; if (x<0){ buf[p++]='-'; x=-x; }
    int e=0; double t=x;                                                 /* normalize: t in [1,10), value = t*10^e */
    while (t>=10.0){ t*=0.1; e++; } while (t<1.0){ t*=10.0; e--; }
    char dig[18]; int nd=0;                                              /* 15 significant digits via ONE integer scaling (stays < 2^53 -> exact; avoids the per-digit (t-c)*10 drift that printed 9876.5 as 9876.500000000002) */
    double sc = js_floor(t * 1e14 + 0.5);                                /* t in [1,10) -> a 15-digit integer */
    if (sc >= 1e15) { sc *= 0.1; e++; }                                  /* rounded up to 10.x -> renormalize */
    int64_t iv = (int64_t)sc;
    { int64_t z=iv; for(int i=14;i>=0;i--){ dig[i]=(char)('0'+(int)(z%10)); z/=10; } nd=15; }   /* iv is in [1e14,1e15): exactly 15 digits */
    while (nd>1 && dig[nd-1]=='0') nd--;                                 /* trim trailing zeros */
    if (e< -6 || e>=21){                                                 /* exponential notation */
        buf[p++]=dig[0];
        if (nd>1){ buf[p++]='.'; for(int i=1;i<nd;i++) buf[p++]=dig[i]; }
        buf[p++]='e'; buf[p++]=(e<0)?'-':'+'; int ae=e<0?-e:e;
        char eb[4]; int en=0; if(ae==0) eb[en++]='0'; while(ae){ eb[en++]=(char)('0'+ae%10); ae/=10; }
        while(en>0) buf[p++]=eb[--en];
    } else if (e>=0){                                                    /* d d d . d d  (point after e+1 digits) */
        for (int i=0;i<=e;i++) buf[p++]= (i<nd)?dig[i]:'0';
        if (nd>e+1){ buf[p++]='.'; for (int i=e+1;i<nd;i++) buf[p++]=dig[i]; }
    } else {                                                             /* 0.00..ddd  (-1>=e>=-6) */
        buf[p++]='0'; buf[p++]='.';
        for (int i=0;i<(-e-1);i++) buf[p++]='0';
        for (int i=0;i<nd;i++) buf[p++]=dig[i];
    }
    buf[p]=0; return buf;
}
/* ---- symbol-keyed property support (M-symbol) ----
 * A V_SYMBOL used as a computed property key is encoded to a reserved internal
 * STRING key "@@sym:<id>", then stored via the ordinary string-keyed obj_get/obj_set
 * — so the property machinery is entirely unchanged; only the computed-key path
 * translates the symbol first. These internal keys are HIDDEN from every enumeration
 * (Object.keys, for-in, JSON.stringify, Object.values/entries/assign, structuredClone)
 * via is_internal_key() below.
 *
 * COLLISION NOTE (theoretical): a user could literally write obj["@@sym:1"]=v, which
 * would land in the same slot and also be hidden from enumeration. "@@sym:" is the
 * conventional prefix and the hiding is what matters; a normal program never writes it.
 *
 * SYM_KEY_MAX bounds the formatted key: "@@sym:" (6) + up to 20 digits for a 64-bit
 * id + NUL = 27; 32 is comfortable. The id is non-negative (counter from SYM_ID_FIRST,
 * well-knowns from 1), so no '-' sign. Formatting is length-bounded by construction. */
#define SYM_KEY_MAX 32
static const char *val_to_str(val v); /* fwd (keystr below coerces a non-symbol key) */
static const char *sym_key(int64_t id){
    char buf[SYM_KEY_MAX]; int p=0;
    buf[p++]='@'; buf[p++]='@'; buf[p++]='s'; buf[p++]='y'; buf[p++]='m'; buf[p++]=':';
    const char *d = i64_to_str(id < 0 ? 0 : id);   /* clamp defensively; ids are >=1 */
    while (*d && p < SYM_KEY_MAX-1) buf[p++]=*d++;
    buf[p]=0;
    return intern(buf, p);   /* stable, NUL-terminated arena copy (obj_set stores the pointer) */
}
/* True for any reserved internal key (the "@@" namespace, currently only "@@sym:").
 * Enumeration sites skip these so symbol-keyed (and any future internal) props stay hidden. */
static int is_internal_key(const char *k){ return k && k[0]=='@' && k[1]=='@'; }
/* Translate a computed-member key value to its property-string: a symbol -> its
 * "@@sym:<id>" encoding, anything else -> the usual val_to_str. Used at the two
 * computed-key sites (obj[k] read and obj[k]=v write). */
static const char *keystr(val k){ return k.t==V_SYMBOL ? sym_key((int64_t)k.num) : val_to_str(k); }   /* symbol id lives in num (< 2^53) */
static const char *val_to_str(val v); /* fwd */
static int truthy(val v) {
    switch (v.t) {
        case V_UNDEF: case V_NULL: return 0;
        case V_BOOL: case V_NUM: return v.num!=0 && !js_isnan(v.num);   /* NaN is falsy in JS; NaN!=0 is true in C (M1752). A bool's num is 0/1, never NaN, so V_BOOL is unchanged. */
        case V_STR: return v.str && v.str[0];
        default: return 1;
    }
}
static int64_t days_from_civil(int64_t y, int64_t m, int64_t d);   /* fwd (defined near Date) — lets to_num(Date) return the epoch, so date2-date1 works (M429) */
/* fwd (defined below): to_num's ToPrimitive(number) path invokes a user object's
 * valueOf/toString via the same depth-guarded getter call path. */
static int proto_lookup(obj *start, const char *name, val recv, val *out);
static val call_function_this(val fn, val thisv, val *args, int nargs);
/* true iff the rest of `s` is only trailing whitespace (so the numeric literal was the WHOLE string). */
static int tn_tail_ws(const char *s){ while(*s==' '||*s=='\t'||*s=='\n'||*s=='\r'||*s=='\f'||*s=='\v') s++; return *s==0; }
static double to_num(val v) {
    switch (v.t) {
        case V_UNDEF: return JS_NAN;   /* M1766: undefined -> NaN (null stays 0 via default), so 1+undefined, Number(undefined), +undefined, isNaN(undefined), undefined<5 all match real JS instead of silently yielding 0 */
        case V_NUM: case V_BOOL: return v.num;
        case V_STR: { const char*s=v.str;
            while(*s==' '||*s=='\t'||*s=='\n'||*s=='\r'||*s=='\f'||*s=='\v') s++;   /* JS ToNumber skips leading whitespace */
            if(!*s) return 0;                                  /* "" / all-whitespace -> 0 (per spec) */
            int neg=0; if(*s=='-'){neg=1;s++;} else if(*s=='+'){s++;}
            if(s[0]=='0' && (s[1]=='x'||s[1]=='X')){ int64_t x=0; int any=0; s+=2;   /* 0x.. hex (Number("0x10")===16) */
                for(;;){ char c=*s; int d; if(c>='0'&&c<='9')d=c-'0'; else if(c>='a'&&c<='f')d=c-'a'+10; else if(c>='A'&&c<='F')d=c-'A'+10; else break; x=x*16+d; s++; any=1; }
                if(!any || !tn_tail_ws(s)) return JS_NAN;
                return neg?-(double)x:(double)x; }
            if(s[0]=='0' && (s[1]=='b'||s[1]=='B')){ int64_t x=0; int any=0; s+=2; while(*s=='0'||*s=='1'){ x=x*2+(*s-'0'); s++; any=1; } if(!any||!tn_tail_ws(s)) return JS_NAN; return neg?-(double)x:(double)x; }   /* 0b.. binary (M693) */
            if(s[0]=='0' && (s[1]=='o'||s[1]=='O')){ int64_t x=0; int any=0; s+=2; while(*s>='0'&&*s<='7'){ x=x*8+(*s-'0'); s++; any=1; } if(!any||!tn_tail_ws(s)) return JS_NAN; return neg?-(double)x:(double)x; }   /* 0o.. octal (M693) */
            if(s[0]=='I'&&s[1]=='n'&&s[2]=='f'&&s[3]=='i'&&s[4]=='n'&&s[5]=='i'&&s[6]=='t'&&s[7]=='y'){ s+=8; if(!tn_tail_ws(s)) return JS_NAN; return neg?-JS_INF:JS_INF; }   /* Number("Infinity") (short-circuit && never reads past the NUL) */
            double x=0; int any=0;            /* decimal: integer . fraction [e exponent] */
            while(*s>='0'&&*s<='9'){ x=x*10.0+(*s-'0'); s++; any=1; }
            if(*s=='.'){ s++; double f=0.1; while(*s>='0'&&*s<='9'){ x+=(*s-'0')*f; f*=0.1; s++; any=1; } }
            if(!any) return JS_NAN;           /* no digits at all ("abc", ".", "+", "e5") -> NaN, not 0 */
            if(*s=='e'||*s=='E'){ s++; int eneg=0; if(*s=='+')s++; else if(*s=='-'){eneg=1;s++;} int ex=0,ed=0; while(*s>='0'&&*s<='9'){ ex=ex*10+(*s-'0'); s++; ed=1; } if(!ed) return JS_NAN; x*=js_pow(10.0, eneg?-(double)ex:(double)ex); }   /* "1e" w/o exponent digits -> NaN */
            if(!tn_tail_ws(s)) return JS_NAN; /* trailing garbage ("12abc", "5px") -> NaN, not a partial parse */
            return neg?-x:x; }
        case V_OBJ:
            if (v.o && v.o->kind==V_DATE && v.o->n>=6)   /* Date -> epoch ms, matching getTime (M429) */
                return (days_from_civil(v.o->vals[0].num, v.o->vals[1].num, v.o->vals[2].num)*86400 + v.o->vals[3].num*3600 + v.o->vals[4].num*60 + v.o->vals[5].num)*1000;
            /* ToPrimitive(number hint): a user object's valueOf() wins, else its
             * toString() (own or inherited). Invoked via the depth-guarded getter
             * call path, so a valueOf that recurses is bounded by MAXDEPTH; a result
             * that's still an object is skipped, falling through to 0 (integer engine,
             * no NaN). Objects with neither are 0, as before — so existing coercion is
             * unchanged. A string result is parsed by recursing into to_num. */
            if (v.o) {
                static const char *names[2] = { "valueOf", "toString" };
                for (int k=0; k<2; k++) {
                    val fn;
                    if (obj_get(v.o, names[k], &fn) ||
                        (v.o->proto && proto_lookup(v.o->proto, names[k], v, &fn))) {
                        if (fn.t==V_FUN || fn.t==V_NATIVE || (fn.t==V_OBJ && fn.o && fn.o->kind==V_BOUND)) {
                            val r = call_function_this(fn, v, 0, 0);
                            if (r.t != V_OBJ && r.t != V_ARR && r.t != V_FUN && r.t != V_NATIVE)
                                return to_num(r);
                        }
                    }
                }
            }
            return 0;
        default: return 0;
    }
}
/* ToPrimitive(v) with the default/number hint (M1790): a user object's valueOf()
 * wins if it returns a primitive, else the object's string form (toString, via
 * val_to_str). Primitives pass through unchanged. Used by `+`/`+=` so an object
 * with a numeric valueOf does numeric addition — ({valueOf(){return 5}})+1 is 6,
 * not "[object Object]1" — while plain objects/arrays still stringify as before
 * (their inherited valueOf returns the object itself, not a primitive). Date keeps
 * its string form (its default hint is string; its epoch valueOf must NOT hijack
 * `date+""`). Each operand's valueOf/toString runs at most once (spec: once). */
static val to_primitive(val v) {
    if (v.t != V_OBJ && v.t != V_ARR && v.t != V_FUN && v.t != V_NATIVE) return v;  /* already primitive */
    if (v.t == V_OBJ && v.o && v.o->kind == V_DATE) return STRV(val_to_str(v));     /* Date: default hint = string */
    if (v.o) {
        val fn;
        if (obj_get(v.o, "valueOf", &fn) ||
            (v.o->proto && proto_lookup(v.o->proto, "valueOf", v, &fn))) {
            if (fn.t==V_FUN || fn.t==V_NATIVE || (fn.t==V_OBJ && fn.o && fn.o->kind==V_BOUND)) {
                val r = call_function_this(fn, v, 0, 0);
                if (r.t!=V_OBJ && r.t!=V_ARR && r.t!=V_FUN && r.t!=V_NATIVE) return r;  /* primitive wins */
            }
        }
    }
    return STRV(val_to_str(v));   /* toString / default string form */
}
/* `===`-style equality, used for Map keys and Set members: primitives by value,
 * objects/functions by identity (same obj pointer). */
static int val_equal(val a, val b) {
    if (a.t!=b.t) return 0;          /* strict (===): 1 !== true, etc. */
    switch (a.t) {
        case V_UNDEF: case V_NULL: return 1;
        case V_NUM: case V_BOOL: return a.num==b.num;
        case V_STR: return a.str && b.str && strcmp(a.str,b.str)==0;
        case V_SYMBOL: return a.num==b.num;   /* symbols: equal iff same id (M-symbol). a.t==b.t already checked, so a symbol is never == a non-symbol */
        default: return a.o==b.o;   /* V_OBJ/V_ARR/V_FUN/V_NATIVE: identity */
    }
}
/* SameValueZero: like === (val_equal) but NaN equals NaN — the equality that Map
 * keys, Set members and Array.includes use, so a NaN key/element is findable.
 * (+0/-0 already compare equal via ==; === keeps NaN!=NaN, as do indexOf/lastIndexOf.) */
static int same_value_zero(val a, val b) {
    if (a.t==V_NUM && b.t==V_NUM && js_isnan(a.num) && js_isnan(b.num)) return 1;
    return val_equal(a, b);
}

/* =========================== regular expressions ===========================
 * A from-scratch regex: pattern -> tree -> a small instruction program, run by
 * a recursive backtracking matcher with a STEP BUDGET + DEPTH CAP so a
 * pathological pattern on untrusted input fails gracefully instead of hanging or
 * overflowing the kernel stack (verified on `(a+)+$`). Supports literals, . ,
 * [classes] (ranges, negation, \d\w\s\D\W\S), * + ? (greedy), | , (capture
 * groups), ^ $, escapes; flags i (ignore case) and g (global). */
enum { I_CHAR, I_ANY, I_CLASS, I_BOL, I_EOL, I_WORDB, I_NWORDB, I_BACKREF, I_AHEAD, I_AHEADEND, I_BEHIND, I_BEHINDEND, I_SAVE, I_SPLIT, I_JMP, I_MATCH };
typedef struct { int op; int c; int x, y; unsigned char *cls; } reinst;
#define RE_MAXPROG 512
#define RE_MAXGROUP 9
typedef struct { reinst *prog; int n; int ngroup; int icase; int global; int multiline; int dotall; int lastIndex; const char *source; int ok; const char *gnames[RE_MAXGROUP+1]; } regex;

enum { RN_CHAR, RN_ANY, RN_CLASS, RN_BOL, RN_EOL, RN_WORDB, RN_NWORDB, RN_BACKREF, RN_AHEAD, RN_BEHIND, RN_CAT, RN_ALT, RN_STAR, RN_PLUS, RN_OPT, RN_GROUP, RN_EMPTY };
typedef struct rnode rnode;
struct rnode { int type; int c; unsigned char *cls; rnode *a, *b; int group; int lazy; };
typedef struct { const char *p; int len, pos; int ngroup; int err; int depth; const char *gnames[RE_MAXGROUP+1]; } rparse;

static rnode *rx_node(int t){ rnode *n=aalloc(sizeof(rnode)); if(!n) return 0; memset(n,0,sizeof(*n)); n->type=t; return n; }
static rnode *rx_alt(rparse *P);
static void cls_set(unsigned char *cls,int c){ cls[(c&0xff)>>3] |= 1<<(c&7); }
static void cls_class(unsigned char *cls,int kind){
    if(kind=='d'){ for(int c='0';c<='9';c++) cls_set(cls,c); }
    else if(kind=='w'){ for(int c='0';c<='9';c++) cls_set(cls,c); for(int c='a';c<='z';c++) cls_set(cls,c); for(int c='A';c<='Z';c++) cls_set(cls,c); cls_set(cls,'_'); }
    else if(kind=='s'){ cls_set(cls,' '); cls_set(cls,'\t'); cls_set(cls,'\n'); cls_set(cls,'\r'); cls_set(cls,'\f'); cls_set(cls,'\v'); }
}
/* a \w word char (same set cls_class('w') builds): [A-Za-z0-9_]. Used for \b/\B. */
static int rx_isword(unsigned char c){ return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'; }
static rnode *rx_class(rparse *P){
    rnode *n=rx_node(RN_CLASS); if(!n){P->err=1;return 0;} n->cls=aalloc(32); if(!n->cls){P->err=1;return 0;} memset(n->cls,0,32);
    int neg=0; if(P->pos<P->len && P->p[P->pos]=='^'){ neg=1; P->pos++; }
    while(P->pos<P->len && P->p[P->pos]!=']'){
        int c=(unsigned char)P->p[P->pos++];
        if(c=='\\' && P->pos<P->len){ int e=(unsigned char)P->p[P->pos++];
            if(e=='d'||e=='w'||e=='s'){ cls_class(n->cls,e); continue; }
            if(e=='D'||e=='W'||e=='S'){ unsigned char tmp[32]; memset(tmp,0,32); cls_class(tmp,e+32); for(int i=0;i<32;i++) n->cls[i]|=~tmp[i]; continue; }
            if(e=='n')c='\n'; else if(e=='t')c='\t'; else if(e=='r')c='\r'; else c=e;
        }
        if(P->pos+1<P->len && P->p[P->pos]=='-' && P->p[P->pos+1]!=']'){ P->pos++; int hi=(unsigned char)P->p[P->pos++]; if(hi=='\\'&&P->pos<P->len) hi=(unsigned char)P->p[P->pos++]; for(int x=c;x<=hi;x++) cls_set(n->cls,x); }
        else cls_set(n->cls,c);
    }
    if(P->pos<P->len && P->p[P->pos]==']') P->pos++; else P->err=1;
    n->c=neg; return n;
}
/* Fixed match length of a regex subtree, or -1 if it can vary (quantifiers,
 * backrefs, or unequal-length alternation). Used to validate + size a lookbehind
 * (only fixed-length lookbehind is supported — the tractable subset). (M1814) */
static int rx_fixedlen(rnode *n){
    if(!n) return 0;
    switch(n->type){
        case RN_CHAR: case RN_ANY: case RN_CLASS: return 1;
        case RN_BOL: case RN_EOL: case RN_WORDB: case RN_NWORDB:
        case RN_EMPTY: case RN_AHEAD: case RN_BEHIND: return 0;          /* zero-width */
        case RN_CAT: { int a=rx_fixedlen(n->a); if(a<0) return -1; int b=rx_fixedlen(n->b); if(b<0) return -1; return a+b; }
        case RN_ALT: { int a=rx_fixedlen(n->a), b=rx_fixedlen(n->b); return (a<0||b<0||a!=b) ? -1 : a; }
        case RN_GROUP: return rx_fixedlen(n->a);
        default: return -1;                                             /* RN_STAR/PLUS/OPT/BACKREF: variable */
    }
}
static rnode *rx_atom(rparse *P){
    if(P->pos>=P->len) return rx_node(RN_EMPTY);
    int c=(unsigned char)P->p[P->pos];
    if(c=='('){ P->pos++;
        if(P->pos+1<P->len && P->p[P->pos]=='?' && (P->p[P->pos+1]=='='||P->p[P->pos+1]=='!')){   /* (?= lookahead, (?! negative lookahead (zero-width) */
            int neg=(P->p[P->pos+1]=='!'); P->pos+=2;
            rnode *body=rx_alt(P); if(P->pos<P->len&&P->p[P->pos]==')')P->pos++; else P->err=1;
            rnode *la=rx_node(RN_AHEAD); if(!la){P->err=1;return 0;} la->a=body; la->c=neg; return la; }
        if(P->pos+2<P->len && P->p[P->pos]=='?' && P->p[P->pos+1]=='<' && (P->p[P->pos+2]=='='||P->p[P->pos+2]=='!')){   /* (?<= lookbehind, (?<! negative lookbehind (zero-width, FIXED-LENGTH body only) */
            int neg=(P->p[P->pos+2]=='!'); P->pos+=3;
            rnode *body=rx_alt(P); if(P->pos<P->len&&P->p[P->pos]==')')P->pos++; else P->err=1;
            int L=rx_fixedlen(body); if(L<0){ P->err=1; return rx_node(RN_EMPTY); }   /* variable-length lookbehind unsupported */
            rnode *lb=rx_node(RN_BEHIND); if(!lb){P->err=1;return 0;} lb->a=body; lb->c=neg; lb->group=L; return lb; }   /* ->group repurposed: the fixed body length */
        const char *gnm=0; int gnl=0; int noncap=0;   /* (?<name>… capture name span, if present */
        if(P->pos+1<P->len && P->p[P->pos]=='?' && P->p[P->pos+1]==':') { P->pos+=2; noncap=1; }   /* (?: non-capturing: skip ?: AND don't allocate a group */
        else if(P->pos+2<P->len && P->p[P->pos]=='?' && P->p[P->pos+1]=='<' && P->p[P->pos+2]!='=' && P->p[P->pos+2]!='!'){   /* (?<name>… named capture: capture the name, treat as a numbered group */
            P->pos+=2; gnm=P->p+P->pos; while(P->pos<P->len && P->p[P->pos]!='>') P->pos++; gnl=(int)(P->p+P->pos-gnm); if(P->pos<P->len) P->pos++; }
        int gi=noncap ? 0 : ((P->ngroup<RE_MAXGROUP)?++P->ngroup:0);
        if(gnm && gi>0 && gnl>0){ char *nm=aalloc(gnl+1); if(nm){ memcpy(nm,gnm,gnl); nm[gnl]=0; P->gnames[gi]=nm; } }   /* group# -> name, for match.groups (M577) */
        rnode *body=rx_alt(P); if(P->pos<P->len&&P->p[P->pos]==')')P->pos++; else P->err=1; rnode *g=rx_node(RN_GROUP); if(!g){P->err=1;return 0;} g->a=body; g->group=gi; return g; }
    if(c=='['){ P->pos++; return rx_class(P); }
    if(c=='.'){ P->pos++; return rx_node(RN_ANY); }
    if(c=='^'){ P->pos++; return rx_node(RN_BOL); }
    if(c=='$'){ P->pos++; return rx_node(RN_EOL); }
    if(c=='\\' && P->pos+1<P->len){ P->pos++; int e=(unsigned char)P->p[P->pos++];
        if(e=='d'||e=='w'||e=='s'){ rnode *n=rx_node(RN_CLASS); if(!n){P->err=1;return 0;} n->cls=aalloc(32); if(!n->cls){P->err=1;return 0;} memset(n->cls,0,32); cls_class(n->cls,e); n->c=0; return n; }
        if(e=='D'||e=='W'||e=='S'){ rnode *n=rx_node(RN_CLASS); if(!n){P->err=1;return 0;} n->cls=aalloc(32); if(!n->cls){P->err=1;return 0;} memset(n->cls,0,32); cls_class(n->cls,e+32); n->c=1; return n; }
        if(e=='b'||e=='B'){ rnode *n=rx_node(e=='b'?RN_WORDB:RN_NWORDB); if(!n){P->err=1;return 0;} return n; }   /* \b word boundary, \B non-boundary (zero-width) */
        if(e>='1'&&e<='9'){ rnode *n=rx_node(RN_BACKREF); if(!n){P->err=1;return 0;} n->c=e-'0'; return n; }   /* \1..\9 backreference to a capture group */
        if(e=='x' && P->pos+1<P->len){   /* \xHH hex escape */
            int a=(unsigned char)P->p[P->pos], b=(unsigned char)P->p[P->pos+1];
            int va=(a>='0'&&a<='9')?a-'0':(a>='a'&&a<='f')?a-'a'+10:(a>='A'&&a<='F')?a-'A'+10:-1;
            int vb=(b>='0'&&b<='9')?b-'0':(b>='a'&&b<='f')?b-'a'+10:(b>='A'&&b<='F')?b-'A'+10:-1;
            if(va>=0&&vb>=0){ P->pos+=2; rnode *n=rx_node(RN_CHAR); if(!n){P->err=1;return 0;} n->c=(va<<4)|vb; return n; } }
        rnode *n=rx_node(RN_CHAR); if(!n){P->err=1;return 0;} if(e=='n')n->c='\n'; else if(e=='t')n->c='\t'; else if(e=='r')n->c='\r'; else n->c=e; return n; }
    P->pos++; rnode *n=rx_node(RN_CHAR); if(!n){P->err=1;return 0;} n->c=c; return n;
}
/* `{n,m}` support is implemented by EXPANDING the bounded quantifier in the
 * PARSER into the existing node types (a{2,4} -> a a a? a?, a{2,} -> a a a*,
 * a{3} -> a a a). This deliberately leaves the compiler + the recursive
 * backtracking matcher — the depth/step-budget-bounded code reviews scrutinised —
 * COMPLETELY UNTOUCHED; repetitions inherit the existing greedy/backtrack
 * semantics. The count is capped (RE_MAXREP) so the digit parse can't overflow,
 * and the expansion is further bounded by RE_MAXPROG at emit + arena OOM, so a
 * huge bound (e.g. a{1,99999}) fails gracefully ("too complex") rather than
 * exploding. A `{` that isn't a well-formed quantifier stays a literal char. */
#define RE_MAXREP 1000
static rnode *rx_clone(rnode *n, int depth){
    if(!n) return 0;
    if(depth > 400) return 0;                         /* atom depth is rx_alt-capped at 400; bound the clone too */
    rnode *c=rx_node(n->type); if(!c) return 0;
    c->c=n->c; c->cls=n->cls; c->group=n->group;      /* cls is read-only after parse -> shareable */
    if(n->a){ c->a=rx_clone(n->a,depth+1); if(!c->a) return 0; }
    if(n->b){ c->b=rx_clone(n->b,depth+1); if(!c->b) return 0; }
    return c;
}
static rnode *rx_cat2(rnode *a, rnode *b){ if(!a) return b; if(!b) return a; rnode *c=rx_node(RN_CAT); if(!c) return 0; c->a=a; c->b=b; return c; }
/* Build the {n1,n2} expansion of `atom` (n2<0 means open-ended {n1,}). Uses the
 * original `atom` once and clones for the rest. Sets P->err + returns 0 on OOM. */
static rnode *rx_expand_rep(rparse *P, rnode *atom, int n1, int n2){
    rnode *result=0; int used=0;
    for(int i=0;i<n1;i++){                            /* n1 mandatory copies */
        rnode *cp = used?rx_clone(atom,0):atom; used=1;
        if(!cp){ P->err=1; return 0; }
        result=rx_cat2(result,cp); if(!result){ P->err=1; return 0; }
    }
    if(n2<0){                                         /* open {n1,}: append a STAR */
        rnode *base = used?rx_clone(atom,0):atom; used=1;
        if(!base){ P->err=1; return 0; }
        rnode *st=rx_node(RN_STAR); if(!st){ P->err=1; return 0; } st->a=base;
        result=rx_cat2(result,st); if(!result){ P->err=1; return 0; }
    } else {                                          /* bounded {n1,n2}: (n2-n1) optional copies */
        for(int i=n1;i<n2;i++){
            rnode *base = used?rx_clone(atom,0):atom; used=1;
            if(!base){ P->err=1; return 0; }
            rnode *opt=rx_node(RN_OPT); if(!opt){ P->err=1; return 0; } opt->a=base;
            result=rx_cat2(result,opt); if(!result){ P->err=1; return 0; }
        }
    }
    return result ? result : rx_node(RN_EMPTY);        /* {0} / {0,0} -> empty */
}
static rnode *rx_rep(rparse *P){
    rnode *a=rx_atom(P); if(!a) return 0;
    while(P->pos<P->len){ int c=P->p[P->pos];
        if(c=='*'||c=='+'||c=='?'){ P->pos++; rnode *q=rx_node(c=='*'?RN_STAR:c=='+'?RN_PLUS:RN_OPT); if(!q){P->err=1;return 0;} q->a=a;
            if(P->pos<P->len && P->p[P->pos]=='?'){ P->pos++; q->lazy=1; }   /* `*?` `+?` `??`: non-greedy — try the shorter match first */
            a=q; }
        else if(c=='{'){                              /* {n} / {n,} / {n,m}; else literal { */
            int save=P->pos; P->pos++;
            int n1=0,n2=-1,have=0;
            while(P->pos<P->len && P->p[P->pos]>='0'&&P->p[P->pos]<='9'){ n1=n1*10+(P->p[P->pos]-'0'); if(n1>RE_MAXREP)n1=RE_MAXREP; P->pos++; have=1; }
            if(!have){ P->pos=save; break; }          /* { not followed by a digit -> literal */
            if(P->pos<P->len && P->p[P->pos]==','){ P->pos++;
                if(P->pos<P->len && P->p[P->pos]>='0'&&P->p[P->pos]<='9'){ n2=0; while(P->pos<P->len && P->p[P->pos]>='0'&&P->p[P->pos]<='9'){ n2=n2*10+(P->p[P->pos]-'0'); if(n2>RE_MAXREP)n2=RE_MAXREP; P->pos++; } }
                else n2=-1;                            /* {n,} open-ended */
            } else n2=n1;                              /* {n} exact */
            if(!(P->pos<P->len && P->p[P->pos]=='}')){ P->pos=save; break; }  /* no } -> literal { */
            if(n2>=0 && n2<n1){ P->pos=save; break; } /* {3,2} invalid -> literal */
            P->pos++;                                  /* past } */
            a=rx_expand_rep(P,a,n1,n2); if(!a){ P->err=1; return 0; }
        }
        else break; }
    return a;
}
static rnode *rx_cat(rparse *P){
    rnode *a=0;
    while(P->pos<P->len && P->p[P->pos]!='|' && P->p[P->pos]!=')'){ rnode *r=rx_rep(P); if(P->err) return a; if(!a) a=r; else { rnode *c=rx_node(RN_CAT); if(!c){P->err=1;return a;} c->a=a; c->b=r; a=c; } }
    return a?a:rx_node(RN_EMPTY);
}
static rnode *rx_alt(rparse *P){
    /* group nesting recurses here (rx_atom -> rx_alt for `(`); the pattern is an
     * ordinary string so the interpreter's MAXDEPTH doesn't bound it. Cap it well
     * below the ~1700-group C-stack cliff on the kernel's 256 KB JS stack. */
    if(++P->depth > 400){ P->err=1; P->depth--; return rx_node(RN_EMPTY); }
    rnode *a=rx_cat(P);
    while(P->pos<P->len && P->p[P->pos]=='|'){ P->pos++; rnode *b=rx_cat(P); rnode *alt=rx_node(RN_ALT); if(!alt){P->err=1;break;} alt->a=a; alt->b=b; a=alt; }
    P->depth--;
    return a;
}
typedef struct { reinst *prog; int pc; int err; } remit;
static int rx_emit(remit *E,int op,int c,int x,int y,unsigned char*cls){ if(E->pc>=RE_MAXPROG){E->err=1;return 0;} int at=E->pc++; E->prog[at].op=op; E->prog[at].c=c; E->prog[at].x=x; E->prog[at].y=y; E->prog[at].cls=cls; return at; }
static void rx_compile(remit *E, rnode *n){
    if(!n||E->err) return;
    switch(n->type){
        case RN_CHAR: rx_emit(E,I_CHAR,n->c,0,0,0); break;
        case RN_ANY: rx_emit(E,I_ANY,0,0,0,0); break;
        case RN_CLASS: rx_emit(E,I_CLASS,n->c,0,0,n->cls); break;
        case RN_BOL: rx_emit(E,I_BOL,0,0,0,0); break;
        case RN_EOL: rx_emit(E,I_EOL,0,0,0,0); break;
        case RN_WORDB: rx_emit(E,I_WORDB,0,0,0,0); break;
        case RN_NWORDB: rx_emit(E,I_NWORDB,0,0,0,0); break;
        case RN_BACKREF: rx_emit(E,I_BACKREF,n->c,0,0,0); break;
        /* (?= )/(?! ): emit I_AHEAD, the body, then I_AHEADEND; patch I_AHEAD.x to the
         * instruction after the body so a successful (zero-width) assertion resumes there. */
        case RN_AHEAD: { int a=rx_emit(E,I_AHEAD,n->c,0,0,0); rx_compile(E,n->a); rx_emit(E,I_AHEADEND,0,0,0,0); E->prog[a].x=E->pc; break; }
        /* (?<=)/(?<!): I_BEHIND.c=negate, .y=fixed body length, .x patched past I_BEHINDEND (M1814) */
        case RN_BEHIND: { int a=rx_emit(E,I_BEHIND,n->c,0,n->group,0); rx_compile(E,n->a); rx_emit(E,I_BEHINDEND,0,0,0,0); E->prog[a].x=E->pc; break; }
        case RN_EMPTY: break;
        case RN_CAT: rx_compile(E,n->a); rx_compile(E,n->b); break;
        case RN_GROUP: if(n->group){ rx_emit(E,I_SAVE,2*n->group,0,0,0); rx_compile(E,n->a); rx_emit(E,I_SAVE,2*n->group+1,0,0,0); } else rx_compile(E,n->a); break;
        /* I_SPLIT tries .x before .y, so greedy = body-first, lazy = exit-first (swap x/y). */
        case RN_STAR: { int l1=rx_emit(E,I_SPLIT,0,0,0,0); rx_compile(E,n->a); rx_emit(E,I_JMP,0,l1,0,0); if(n->lazy){ E->prog[l1].x=E->pc; E->prog[l1].y=l1+1; } else { E->prog[l1].x=l1+1; E->prog[l1].y=E->pc; } break; }
        case RN_PLUS: { int l1=E->pc; rx_compile(E,n->a); int sp=rx_emit(E,I_SPLIT,0,0,0,0); if(n->lazy){ E->prog[sp].x=E->pc; E->prog[sp].y=l1; } else { E->prog[sp].x=l1; E->prog[sp].y=E->pc; } break; }
        case RN_OPT: { int l1=rx_emit(E,I_SPLIT,0,0,0,0); rx_compile(E,n->a); if(n->lazy){ E->prog[l1].x=E->pc; E->prog[l1].y=l1+1; } else { E->prog[l1].x=l1+1; E->prog[l1].y=E->pc; } break; }
        case RN_ALT: { int l1=rx_emit(E,I_SPLIT,0,0,0,0); rx_compile(E,n->a); int j=rx_emit(E,I_JMP,0,0,0,0); E->prog[l1].x=l1+1; E->prog[l1].y=E->pc; rx_compile(E,n->b); E->prog[j].x=E->pc; break; }
    }
}
static regex *re_compile(const char *pat, const char *flags){
    regex *re=aalloc(sizeof(regex)); if(!re) return 0; memset(re,0,sizeof(*re));
    if(flags) for(const char*f=flags;*f;f++){ if(*f=='i')re->icase=1; else if(*f=='g')re->global=1; else if(*f=='m')re->multiline=1; else if(*f=='s')re->dotall=1; }
    re->source=pat?pat:"";
    rparse P; memset(&P,0,sizeof(P)); P.p=pat?pat:""; P.len=(int)strlen(P.p);
    rnode *tree=rx_alt(&P);
    if(P.err || P.pos!=P.len){ re->ok=0; return re; }
    re->ngroup=P.ngroup;
    for(int g=1; g<=P.ngroup && g<=RE_MAXGROUP; g++) re->gnames[g]=P.gnames[g];   /* named-capture names -> match.groups (M577) */
    remit E; E.prog=aalloc((long)sizeof(reinst)*RE_MAXPROG); if(!E.prog){re->ok=0;return re;} E.pc=0; E.err=0;
    rx_emit(&E,I_SAVE,0,0,0,0); rx_compile(&E,tree); rx_emit(&E,I_SAVE,1,0,0,0); rx_emit(&E,I_MATCH,0,0,0,0);
    if(E.err){ re->ok=0; return re; }
    re->prog=E.prog; re->n=E.pc; re->ok=1; return re;
}
static int rx_eqc(int a,int b,int icase){ if(a==b) return 1; if(icase){ int la=(a>='A'&&a<='Z')?a+32:a, lb=(b>='A'&&b<='Z')?b+32:b; return la==lb; } return 0; }
static int re_run(regex *re,int pc,const char*s,int slen,int sp,int*caps,long*budget,int depth){
    /* re_run recurses per I_SPLIT/I_SAVE, so a greedy quantifier matching N chars
     * recurses ~N deep. The kernel JS task stack is 256 KB with NO guard page and
     * already holds the interpreter's eval frames, so cap conservatively (~900) —
     * the host's 8 MB stack tolerated 3000, the kernel's does not. A single run
     * longer than this fails to match rather than corrupting kernel memory. */
    if(--*budget<0 || depth>900) return -2;
    for(;;){
        reinst *in=&re->prog[pc];
        switch(in->op){
            case I_CHAR: if(sp<slen && rx_eqc((unsigned char)s[sp],in->c,re->icase)){ sp++; pc++; continue; } return 0;
            case I_ANY: if(sp<slen && (re->dotall || s[sp]!='\n')){ sp++; pc++; continue; } return 0;   /* . matches \n only with the s (dotall) flag */
            case I_CLASS: { if(sp>=slen) return 0; unsigned char ch=(unsigned char)s[sp]; int hit=(in->cls[ch>>3]>>(ch&7))&1;
                if(re->icase && !hit){ int o=(ch>='a'&&ch<='z')?ch-32:(ch>='A'&&ch<='Z')?ch+32:ch; hit=(in->cls[(o&0xff)>>3]>>(o&7))&1; }
                if(in->c) hit=!hit; if(hit){ sp++; pc++; continue; } return 0; }
            case I_BOL: if(sp==0 || (re->multiline && s[sp-1]=='\n')){ pc++; continue; } return 0;   /* ^ anchors string start; also after \n only with the m (multiline) flag */
            case I_EOL: if(sp==slen || (re->multiline && s[sp]=='\n')){ pc++; continue; } return 0;   /* $ anchors string end; also before \n only with m */
            case I_WORDB: case I_NWORDB: {   /* \b / \B : zero-width word boundary (transition between \w and non-\w) */
                int bw=(sp>0)&&rx_isword((unsigned char)s[sp-1]); int aw=(sp<slen)&&rx_isword((unsigned char)s[sp]);
                int bnd=(bw!=aw); if(in->op==I_WORDB ? bnd : !bnd){ pc++; continue; } return 0; }
            case I_BACKREF: {   /* \1..\9 : match the same text the group captured */
                int g=in->c, st=-1, en=-1;
                if(g>=1 && g<=RE_MAXGROUP){ st=caps[2*g]; en=caps[2*g+1]; }
                if(st<0 || en<0 || en<st){ pc++; continue; }   /* group didn't participate -> matches empty (JS) */
                int blen=en-st; if(sp+blen>slen) return 0;
                for(int k=0;k<blen;k++) if(!rx_eqc((unsigned char)s[sp+k],(unsigned char)s[st+k],re->icase)) return 0;
                sp+=blen; pc++; continue; }
            case I_AHEAD: {   /* (?=…)/(?!…): does the body match at sp? zero-width — sp unchanged on success */
                int r=re_run(re,pc+1,s,slen,sp,caps,budget,depth+1); if(r==-2) return -2;
                if((r>0) != (in->c!=0)){ pc=in->x; continue; } return 0; }   /* in->c = negate flag */
            case I_AHEADEND: return 1;   /* terminal success for a lookahead sub-match */
            case I_BEHIND: {   /* (?<=…)/(?<!…): does the fixed-length (in->y) body match ENDING at sp? zero-width */
                int L=in->y, start=sp-L, matched;
                if(start<0) matched=0;   /* not enough preceding text */
                else { int r=re_run(re,pc+1,s,slen,start,caps,budget,depth+1); if(r==-2) return -2; matched=(r>0); }
                if(matched != (in->c!=0)){ pc=in->x; continue; } return 0; }   /* in->c = negate flag */
            case I_BEHINDEND: return 1;   /* terminal success for a lookbehind sub-match (fixed length => ends exactly at sp) */
            case I_JMP: pc=in->x; continue;
            case I_SPLIT: { int r=re_run(re,in->x,s,slen,sp,caps,budget,depth+1); if(r!=0) return r; pc=in->y; continue; }
            case I_SAVE: { int idx=in->c; int old=(idx<2*(RE_MAXGROUP+1))?caps[idx]:-1; if(idx<2*(RE_MAXGROUP+1)) caps[idx]=sp;
                int r=re_run(re,pc+1,s,slen,sp,caps,budget,depth+1); if(r!=0) return r; if(idx<2*(RE_MAXGROUP+1)) caps[idx]=old; return 0; }
            case I_MATCH: return 1;
        }
        return 0;
    }
}
/* search at or after `start`; fills caps[0..]=match+groups; returns match start or -1 */
static int re_search(regex *re,const char*s,int slen,int start,int*caps){
    if(!re||!re->ok||!re->prog) return -1;
    for(int sp=start; sp<=slen; sp++){
        for(int i=0;i<2*(RE_MAXGROUP+1);i++) caps[i]=-1;
        long budget=300000;
        if(re_run(re,0,s,slen,sp,caps,&budget,0)==1) return caps[0];
    }
    return -1;
}
/* build the [fullMatch, g1, g2, …] result array from caps, with .index and (when
 * the pattern has named groups) .groups attached via the array's match_props
 * side-object so `m.index` / `m.groups.name` work (M577). */
static val re_result(regex *re,const char*s,int*caps){
    obj *a=new_obj(V_ARR); if(!a){ g_oom=1; return UND(); }
    for(int g=0; g<=re->ngroup; g++){ int st=caps[2*g], en=caps[2*g+1];
        if(st>=0 && en>=st){ char*m=aalloc(en-st+1); if(m){ memcpy(m,s+st,en-st); m[en-st]=0; } arr_push_val(a, STRV(m?m:"")); }
        else arr_push_val(a, UND()); }
    obj *mp=new_obj(V_OBJ);
    if(mp){
        obj_set(mp,"index",NUM(caps[0]));
        int named=0; for(int g=1; g<=re->ngroup; g++) if(re->gnames[g]){ named=1; break; }
        if(named){
            obj *gr=new_obj(V_OBJ);
            if(gr){ for(int g=1; g<=re->ngroup; g++) if(re->gnames[g]){
                        int st=caps[2*g], en=caps[2*g+1];
                        if(st>=0 && en>=st){ char*m=aalloc(en-st+1); if(m){ memcpy(m,s+st,en-st); m[en-st]=0; } obj_set(gr,re->gnames[g],STRV(m?m:"")); }
                        else obj_set(gr,re->gnames[g],UND()); }
                val gv=UND(); gv.t=V_OBJ; gv.o=gr; obj_set(mp,"groups",gv); }
        } else obj_set(mp,"groups",UND());   /* no named groups -> .groups is undefined (per spec) */
        a->match_props=mp;
    }
    val r=UND(); r.t=V_ARR; r.o=a; return r;
}
static regex *rx_of(val v){ return (v.t==V_OBJ && v.o && v.o->kind==V_REGEX) ? (regex*)v.o->rx : 0; }
/* a growable string builder on the arena (no realloc/free; grows by doubling) */
typedef struct { char *buf; int len, cap; } sbuild;
static void sb_put(sbuild *b, const char *s, int n){ if(n<0) return; if(b->len+n+1>b->cap){ int nc=b->cap*2; if(nc<b->len+n+16) nc=b->len+n+16; char*nb=aalloc(nc); if(!nb){g_oom=1;return;} if(b->buf) memcpy(nb,b->buf,b->len); b->buf=nb; b->cap=nc; } if(b->buf){ memcpy(b->buf+b->len,s,n); b->len+=n; } }
/* expand a replacement template ($&=whole match, $1..$9=group, $<name>=named group,
 * $`/$'=before/after, $$=$) into b. gnames (group#->name, or NULL) drives $<name>. */
static void sb_expand(sbuild *b, const char *repl, const char *s, int *caps, int ngroup, const char **gnames){
    int rl=(int)strlen(repl);
    for(int i=0;i<rl;i++){ if(repl[i]=='$' && i+1<rl){ char d=repl[i+1];
        if(d=='&'){ sb_put(b, s+caps[0], caps[1]-caps[0]); i++; continue; }
        if(d=='$'){ sb_put(b,"$",1); i++; continue; }
        if(d=='`'){ sb_put(b, s, caps[0]); i++; continue; }                       /* $` : text before the match */
        if(d=='\''){ sb_put(b, s+caps[1], (int)strlen(s+caps[1])); i++; continue; }  /* $' : text after the match */
        if(d=='<' && gnames){   /* $<name> : named-group substitution (M696) */
            int j=i+2, nl=0; while(j<rl && repl[j]!='>'){ j++; nl++; }
            if(j<rl){ const char *nm=repl+i+2;
                for(int g=1; g<=ngroup; g++){ if(gnames[g] && (int)strlen(gnames[g])==nl && memcmp(gnames[g],nm,nl)==0){ int a=caps[2*g],e=caps[2*g+1]; if(a>=0&&e>=a) sb_put(b,s+a,e-a); break; } }
                i=j; continue;   /* skip through the closing '>' */
            }
        }
        if(d>='1'&&d<='9'){ int g=d-'0'; if(g<=ngroup){ int a=caps[2*g],e=caps[2*g+1]; if(a>=0&&e>=a) sb_put(b,s+a,e-a); } i++; continue; } }
        sb_put(b, repl+i, 1); }
}
/* methods on a RegExp object (recv.o->kind==V_REGEX, recv.o->rx is the regex*) */
static val eval_regex_method(val recv, const char *name, val *args, int nargs){
    regex *re=(regex*)recv.o->rx; if(!re){ return UND(); }
    const char *s = nargs? val_to_str(args[0]) : ""; int slen=(int)strlen(s);
    int caps[2*(RE_MAXGROUP+1)];
    if(strcmp(name,"test")==0){ int start = re->global ? re->lastIndex : 0; if(start<0||start>slen) start=0;
        int st=re_search(re,s,slen,start,caps);
        if(re->global) re->lastIndex = (st>=0) ? (caps[1]>caps[0]?caps[1]:caps[1]+1) : 0;
        return BOOLV(st>=0); }
    if(strcmp(name,"exec")==0){ int start = re->global ? re->lastIndex : 0; if(start<0||start>slen) start=0;
        int st=re_search(re,s,slen,start,caps);
        if(st<0){ if(re->global) re->lastIndex=0; val nv=UND(); nv.t=V_NULL; return nv; }
        if(re->global) re->lastIndex = caps[1]>caps[0]?caps[1]:caps[1]+1;
        return re_result(re,s,caps); }
    rt_err("unknown RegExp method"); return UND();
}
/* build a V_REGEX object from a pattern + flags string (shared by RegExp() and /literals/) */
static val make_regex_val(const char *pat, const char *fl){
    regex *re=re_compile(pat?pat:"", fl?fl:"");
    obj *o=new_obj(V_REGEX); if(!o){ g_oom=1; return UND(); }
    o->rx=re; obj_set(o,"source",STRV(pat?pat:"")); obj_set(o,"global",BOOLV(re&&re->global)); obj_set(o,"flags",STRV(fl?fl:""));
    return obj_val(o);
}
/* RegExp(pattern, flags) / new RegExp(...) -> a V_REGEX object */
static val nat_regexp(val *args, int nargs){
    const char *pat = nargs>0? val_to_str(args[0]) : "";
    const char *fl  = nargs>1? val_to_str(args[1]) : "";
    return make_regex_val(pat, fl);
}
static const char *val_to_str_inner(val v) {
    if (v.t == V_OBJ && v.o && v.o->kind == V_BOUND) return "function";   /* a bound function */
    if (v.t == V_OBJ && v.o && v.o->kind == V_U8ARRAY) {   /* Uint8Array -> "1,2,3" like an array (M1850) */
        obj *o = v.o; char *buf = aalloc((long)o->nbytes * 4 + 1); if (!buf) return "[Uint8Array]";
        int p = 0;
        for (int i = 0; i < o->nbytes; i++) { if (i) buf[p++] = ','; int b = o->bytes[i]; char t[4]; int tl=0; do { t[tl++]=(char)('0'+b%10); b/=10; } while(b); while(tl) buf[p++]=t[--tl]; }
        buf[p] = 0; return buf;
    }
    if (v.t == V_OBJ && v.o && v.o->kind == V_ARRAYBUF) return "[object ArrayBuffer]";
    switch (v.t) {
        case V_UNDEF: return "undefined";
        case V_NULL: return "null";
        case V_BOOL: return v.num?"true":"false";
        case V_NUM: return num_to_str(v.num);
        case V_STR: return v.str;
        case V_FUN: case V_NATIVE: return "function";
        case V_SYMBOL: {   /* "Symbol(desc)" — kernel-safe: do NOT throw (spec throws on String(symbol)) (M-symbol) */
            const char *d = v.str ? v.str : "";
            long dl = (long)strlen(d);
            char *buf = aalloc(dl + 9);   /* "Symbol(" (7) + desc + ")" (1) + NUL (1) */
            if (!buf) return "Symbol()";
            int p=0; const char *pre="Symbol(";
            while (*pre) buf[p++]=*pre++;
            for (long i=0;i<dl;i++) buf[p++]=d[i];
            buf[p++]=')'; buf[p]=0; return buf;
        }
        case V_ARR: {
            /* two passes: stringify each element, sum the REAL lengths (a wrong
             * n*24 estimate would overflow the buffer for long element strings),
             * then allocate exactly. total is 64-bit so it can't overflow. */
            obj *o=v.o;
            const char **parts = aalloc((long)sizeof(char*) * (o->n>0?o->n:1));
            if (!parts) return "[array]";
            long total = 0;
            for (int i=0;i<o->n;i++){ val ev=o->vals[i]; parts[i]=(ev.t==V_UNDEF||ev.t==V_NULL)?"":val_to_str(ev); total += (long)strlen(parts[i]) + 1; }   /* null/undefined array elements render as "" in join/toString (M1752), matching the engine's own join */
            char *buf=aalloc(total+1); if(!buf) return "[array]"; int p=0;
            for (int i=0;i<o->n;i++){ if(i) buf[p++]=','; const char*s=parts[i]; while(*s) buf[p++]=*s++; }
            buf[p]=0; return buf;
        }
        case V_OBJ:
            if (v.o && v.o->kind==V_DATE && v.o->n>=6) {   /* "YYYY-MM-DD HH:MM:SS" from vals[0..5] */
                char *b=aalloc(24); if(!b) return "[date]"; int p=0; int y=(int)v.o->vals[0].num;
                b[p++]='0'+(y/1000)%10; b[p++]='0'+(y/100)%10; b[p++]='0'+(y/10)%10; b[p++]='0'+y%10;
                for (int f=1; f<6; f++){ b[p++]=(f<3)?'-':(f==3)?' ':':'; int x=(int)v.o->vals[f].num; b[p++]='0'+(x/10)%10; b[p++]='0'+x%10; }
                b[p]=0; return b;
            }
            /* ToPrimitive: a user object's OWN or inherited toString() (a function,
             * e.g. `{toString(){…}}` or a `class` method) wins over the generic
             * fallbacks below. Invoked via call_function_this exactly like an
             * inherited getter — so a toString that recurses or returns the object
             * is bounded by MAXDEPTH (and we only USE a primitive result), never an
             * OOB or hang. Plain objects with no toString fall straight through, so
             * existing stringification (incl. the Error-like case) is unchanged. */
            if (v.o) {
                val ts; int got = obj_get(v.o, "toString", &ts) ||
                                  (v.o->proto && proto_lookup(v.o->proto, "toString", v, &ts));
                if (got && (ts.t==V_FUN || ts.t==V_NATIVE || (ts.t==V_OBJ && ts.o && ts.o->kind==V_BOUND))) {
                    val r = call_function_this(ts, v, 0, 0);
                    if (r.t != V_OBJ && r.t != V_ARR && r.t != V_FUN && r.t != V_NATIVE)
                        return val_to_str(r);   /* primitive result -> use it; else fall through */
                }
            }
            /* an Error-like object (string name + message) stringifies as "name: message"
             * (covers `new Error(m)` and `class X extends Error`); else generic. */
            if (v.o && obj_keyed(v.o)) {
                const char *nm=0,*msg=0;
                for (int i=0;i<v.o->n;i++) if (v.o->keys[i] && v.o->vals[i].t==V_STR) {
                    if (!strcmp(v.o->keys[i],"name")) nm=v.o->vals[i].str;
                    else if (!strcmp(v.o->keys[i],"message")) msg=v.o->vals[i].str;
                }
                if (nm && msg) {
                    if (!msg[0]) return nm;
                    long ln=(long)strlen(nm)+2+(long)strlen(msg); char*b=aalloc(ln+1);
                    if (b){ int p=0; for(const char*s=nm;*s;)b[p++]=*s++; b[p++]=':'; b[p++]=' '; for(const char*s=msg;*s;)b[p++]=*s++; b[p]=0; return b; }
                }
            }
            return "[object Object]";
    }
    return "";
}
/* depth-guarded wrapper: stops infinite recursion on a self-referential value
 * (e.g. `var a=[]; a.push(a); print(a);`) before it overruns the kernel stack. */
static const char *val_to_str(val v) {
    if (++g_depth > MAXDEPTH) { g_depth--; return "[...]"; }
    const char *s = val_to_str_inner(v); g_depth--; return s;
}

/* Promise helpers (defined with the Promise natives below) — forward-declared here so
 * call_function_this can wrap an async function's result and N_AWAIT can read state (M680). */
static val make_promise(int state, val v);
static val take_pending_error(void);
static int pstate(obj *p); static val pvalue(obj *p);
static val nat_promise_resolve(val *args, int nargs);   /* fwd: `await x` assimilates a thenable like Promise.resolve(x) (M687) */

/* ---- environments ---- */
static env *new_env(env *parent){ env *e=aalloc(sizeof(env)); if(!e) return 0; e->cap=4; e->keys=aalloc(sizeof(char*)*e->cap); e->vals=aalloc(sizeof(val)*e->cap); if(!e->keys||!e->vals){ g_oom=1; return 0; } e->n=0; e->parent=parent; e->func_scope=0; return e; }
/* The nearest function-or-global env walking up from `e` — where a `var` (not let/const) is defined,
 * so a `var` inside a block/loop is visible in the rest of the enclosing function (the global env, with
 * parent==0, is the boundary at top level). */
static env *env_func_scope(env *e){ while (e->parent && !e->func_scope) e = e->parent; return e; }
static void env_define(env *e, const char *key, val v) {
    for (int i=0;i<e->n;i++) if (strcmp(e->keys[i],key)==0){ e->vals[i]=v; return; }
    if (e->n>=e->cap){ int nc=e->cap*2; const char**nk=aalloc(sizeof(char*)*nc); val*nv=aalloc(sizeof(val)*nc); if(!nk||!nv){g_oom=1;return;} memcpy(nk,e->keys,sizeof(char*)*e->n); memcpy(nv,e->vals,sizeof(val)*e->n); e->keys=nk; e->vals=nv; e->cap=nc; }
    e->keys[e->n]=key; e->vals[e->n]=v; e->n++;
}
static val *env_find(env *e, const char *key) {
    for (; e; e=e->parent) for (int i=0;i<e->n;i++) if (strcmp(e->keys[i],key)==0) return &e->vals[i];
    return 0;
}

/* =========================== evaluator =========================== */
enum { C_NORMAL, C_RETURN, C_BREAK, C_CONTINUE };
typedef struct { int kind; val v; const char *label; } comp;   /* label: target of a labeled break/continue (NULL=unlabeled) (M280) */

static val eval_expr(node *n, env *e);
static comp eval_stmt(node *n, env *e);
static void bind_pattern(node *pat, val v, env *e);   /* destructuring (defined below) */
static void hoist_vars(node *n, env *fe);             /* var-hoisting pre-pass (defined below, near eval_stmt) */

static const char *node_name(node *n){ return n->str ? n->str : ""; }   /* names interned at parse time */

/* Call `fn` with an explicit `this` binding. Regular functions bind `this` in
 * their call frame (a method's receiver, the new object under `new`, or undefined
 * for a plain call); arrow functions (node->prefix==1) deliberately do NOT bind
 * one, so `this` resolves lexically up the scope chain to the enclosing function. */
static val call_function_this(val fn, val thisv, val *args, int nargs);   /* fwd: call_bound recurses into it */
static int iter_collect(val it, obj *dest, val mapfn, int hasfn);   /* fwd: drives the [Symbol.iterator] protocol for array-spread / Array.from (defined after from_push) */
static void register_handler(obj *el, const char *type, val fn);   /* fwd: el.onclick=fn / addEventListener -> the per-page handler registry */
static void unregister_handler(obj *el, const char *type);          /* fwd: el.onclick=null / removeEventListener */
/* Does this function body reference `arguments`? (skips nested functions — they have their
 * own.) Walked once per function then cached in node->num, so functions that never use it
 * pay nothing (no per-call arguments allocation). The AST is MAXDEPTH-bounded, so the
 * recursion is shallow. */
static int node_uses_args(node *n){
    if (!n) return 0;
    if (n->type==N_FUNC && !n->prefix) return 0;   /* a nested NON-arrow function has its own arguments; arrows inherit, so descend into them */
    if (n->type==N_IDENT && n->str && strcmp(n->str,"arguments")==0) return 1;
    if (node_uses_args(n->a) || node_uses_args(n->b) || node_uses_args(n->c)) return 1;
    for (int i=0;i<n->nlist;i++) if (n->list && node_uses_args(n->list[i])) return 1;
    return 0;
}
/* A bound function (V_BOUND): prepend its bound `this` + partial args, then call
 * the original. Kept OUT of call_function_this so its comb[24] doesn't bloat that
 * hot, deeply-recursed frame. Depth-guarded so a bind() chain can't overflow. */
static __attribute__((noinline)) val call_bound(obj *bf, val *args, int nargs) {
    if (++g_depth > MAXDEPTH) { rt_err("max call depth"); g_depth--; return UND(); }
    val orig  = bf->n > 0 ? bf->vals[0] : UND();
    val bthis = bf->n > 1 ? bf->vals[1] : UND();
    int np = bf->n > 2 ? bf->n - 2 : 0;
    val comb[24]; int cn = 0;
    for (int i = 0; i < np && cn < 24; i++) comb[cn++] = bf->vals[2 + i];
    for (int i = 0; i < nargs && cn < 24; i++) comb[cn++] = args[i];
    val r = call_function_this(orig, bthis, comb, cn);   /* bound `this` is fixed; the call-site thisv is ignored */
    g_depth--;
    return r;
}
static val call_function_this(val fn, val thisv, val *args, int nargs) {
    if (fn.t==V_OBJ && fn.o && fn.o->kind==V_BOUND) return call_bound(fn.o, args, nargs);
    if (fn.t==V_NATIVE) return fn.o->native(args,nargs);
    if (fn.t!=V_FUN) { rt_err("not a function"); return UND(); }
    if (++g_depth > MAXDEPTH) { rt_err("max call depth"); g_depth--; return UND(); }
    env *fe = new_env(fn.o->scope);
    if (!fe) { g_oom=1; g_depth--; return UND(); }     /* arena exhausted: bail, don't deref NULL */
    fe->func_scope = 1;                                /* this is a function boundary: `var` in the body hoists here, not into inner blocks */
    node *def = fn.o->fn;
    if (!def->prefix) {                                /* non-arrow gets its own `this` (+ `super` if a class member) */
        env_define(fe, "this", thisv);
        if (fn.o->super_class) { val sup=UND(); sup.t=V_FUN; sup.o=fn.o->super_class; env_define(fe, "@super", sup); }
    }
    for (int i=0;i<def->nlist;i++){ node *pn=def->list[i];
        if (pn->type!=N_IDENT) {   /* destructuring param ([a,b], {c}, or =default wrapping a pattern) */
            bind_pattern(pn, (i<nargs)?args[i]:UND(), fe); continue;
        }
        if (pn->op=='.') {   /* ...rest: gather the remaining args into an array, then stop */
            obj *ro=new_obj(V_ARR); if(!ro){ g_oom=1; break; }
            for (int j=i;j<nargs && !g_oom;j++) arr_push_val(ro, args[j]);
            val rv=UND(); rv.t=V_ARR; rv.o=ro; env_define(fe, node_name(pn), rv); break;
        }
        val pv = (i<nargs) ? args[i] : (pn->a ? eval_expr(pn->a, fe) : UND());   /* default value if arg omitted */
        env_define(fe, node_name(pn), pv); }
    if (!def->prefix) {   /* `arguments`: only for non-arrow functions that actually reference it (cached) */
        if (def->num==0) def->num = node_uses_args(def->a) ? 1 : 2;
        if (def->num==1) { int taken=0; for(int i=0;i<fe->n;i++) if(strcmp(fe->keys[i],"arguments")==0){taken=1;break;}   /* a param named `arguments` wins -- don't clobber it */
            if(!taken){ obj *ao=new_obj(V_ARR); if(ao){ for(int i=0;i<nargs && !g_oom;i++) arr_push_val(ao,args[i]); val av=UND(); av.t=V_ARR; av.o=ao; env_define(fe,"arguments",av); } } }   /* V_ARR val (obj_val would tag it V_OBJ) */
    }
    hoist_vars(def->a, fe);                     /* pre-define `var` names (undefined) so use-before-decl / a var in an un-taken branch reads undefined, not "undefined variable" */
    if (def->is_gen) {                          /* generator: eager-run the body, collecting each yield */
        obj *ga = new_obj(V_ARR);
        obj *saved = g_gen_arr; g_gen_arr = ga;
        if (ga) eval_stmt(def->a, fe);          /* N_YIELD appends to g_gen_arr; the body's return is discarded */
        g_gen_arr = saved;
        g_depth--;
        val rv = UND(); if (ga) { rv.t = V_ARR; rv.o = ga; }
        return rv;                              /* an array — iterable via for-of / [...spread] / .forEach */
    }
    comp c = eval_stmt(def->a, fe);
    g_depth--;
    if (def->is_async) {                        /* async function: body result becomes a settled Promise (M680) */
        if (g_err) return make_promise(2, take_pending_error());        /* a throw (incl. an awaited rejection) -> rejected promise */
        val rv = c.kind==C_RETURN ? c.v : UND();
        if (rv.t==V_OBJ && rv.o && rv.o->kind==V_PROMISE) return rv;    /* `return aPromise` -> adopt it */
        return make_promise(1, rv);
    }
    return c.kind==C_RETURN ? c.v : UND();
}
static val call_function(val fn, val *args, int nargs){ return call_function_this(fn, UND(), args, nargs); }

/* Evaluate call-argument nodes into a flat array, expanding `...spread` of arrays
 * (and strings → chars). Returns the count, capped at maxargs. */
static int build_args(node **list, int nlist, env *e, val *args, int maxargs) {
    int na=0;
    for (int i=0;i<nlist && na<maxargs;i++){
        node *el=list[i];
        if (el->type==N_SPREAD){
            val v=eval_expr(el->a,e);
            if (v.t==V_ARR && v.o){ for(int j=0;j<v.o->n && na<maxargs;j++) args[na++]=v.o->vals[j]; }
            else if (v.t==V_STR){ const char*s=v.str; for(int j=0;s[j] && na<maxargs;j++){ char*c=aalloc(2); if(c){c[0]=s[j];c[1]=0;} args[na++]=STRV(c?c:""); } }
            else if (v.t==V_OBJ && v.o && v.o->kind==V_SET){ for(int j=0;j<v.o->n && na<maxargs;j++) args[na++]=v.o->vals[j]; }   /* f(...set) */
            else if (v.t==V_OBJ && v.o && v.o->kind==V_MAP){ for(int j=0;j+1<v.o->n && na<maxargs;j+=2){ obj*p=new_obj(V_ARR); if(!p){g_oom=1;break;} arr_push_val(p,v.o->vals[j]); arr_push_val(p,v.o->vals[j+1]); val pv=UND();pv.t=V_ARR;pv.o=p; args[na++]=pv; } }   /* f(...map) */
            /* a non-iterable spread contributes nothing */
        } else { args[na++]=eval_expr(el,e); }
    }
    return na;
}

/* Bind a destructuring pattern (an N_ARRAY/N_OBJECT of targets, reusing the
 * literal parsers) to a value, defining each leaf identifier in `e`. Handles
 * defaults (N_ASSIGN), array/object rest (N_SPREAD), rename, and nesting.
 * Pattern nesting is already bounded by the parser's depth guard, but bind_pattern
 * carries its own g_depth guard too (via the wrapper below) so it can never be the
 * path that overflows the C stack regardless of the entry task's stack budget. */
static void bind_pat(node *pat, val v, env *e, int assign);   /* guarded wrapper (fwd) */
static void bind_pat_inner(node *pat, val v, env *e, int assign) {
    if (!pat || g_oom) return;
    if (pat->type==N_ASSIGN) { if (v.t==V_UNDEF) v=eval_expr(pat->b,e); bind_pat(pat->a, v, e, assign); return; }
    if (pat->type==N_IDENT || pat->type==N_MEMBER || pat->type==N_INDEX) {   /* a leaf target */
        if (!assign) { env_define(e, node_name(pat), v); return; }           /* var/param/for-of: fresh binding */
        /* assignment target — match N_ASSIGN's identifier/member/index semantics */
        if (pat->type==N_IDENT) { const char *nm=node_name(pat); val *slot=env_find(e,nm); if(slot) *slot=v; else env_define(e,nm,v); }
        else if (pat->type==N_MEMBER) { val recv=eval_expr(pat->a,e); if((recv.t==V_OBJ||recv.t==V_ARR)&&recv.o) obj_set(recv.o, node_name(pat), v); }
        else { val recv=eval_expr(pat->a,e), idx=eval_expr(pat->b,e);
               if (recv.t==V_ARR && recv.o){ int i=(int)to_num(idx); if(i>=0&&i<recv.o->n) recv.o->vals[i]=v; }
               else if (recv.t==V_OBJ && recv.o) obj_set(recv.o, val_to_str(idx), v); }
        return;
    }
    if (pat->type==N_ARRAY) {
        for (int i=0;i<pat->nlist && !g_oom;i++){ node *el=pat->list[i];
            if (el->type==N_SPREAD){ obj *ro=new_obj(V_ARR); if(!ro){g_oom=1;return;}
                if (v.t==V_ARR && v.o) for(int j=i;j<v.o->n && !g_oom;j++) arr_push_val(ro, v.o->vals[j]);
                val rv=UND(); rv.t=V_ARR; rv.o=ro; bind_pat(el->a, rv, e, assign); break; }
            val ev = (v.t==V_ARR && v.o && i<v.o->n) ? v.o->vals[i] : UND();
            bind_pat(el, ev, e, assign);
        }
        return;
    }
    if (pat->type==N_OBJECT) {
        for (int i=0;i<pat->nlist && !g_oom;i++){ node *pr=pat->list[i];
            if (pr->type==N_SPREAD){ obj *ro=new_obj(V_OBJ); if(!ro){g_oom=1;return;}
                if (v.t==V_OBJ && obj_keyed(v.o)) for(int j=0;j<v.o->n && !g_oom;j++){ const char*k=v.o->keys[j]; int named=0;
                    for(int m=0;m<i;m++){ node*q=pat->list[m]; if(q->type!=N_SPREAD && q->str && strcmp(q->str,k)==0){named=1;break;} }
                    if(!named) obj_set(ro, k, v.o->vals[j]); }
                val rv=UND(); rv.t=V_OBJ; rv.o=ro; bind_pat(pr->a, rv, e, assign); break; }
            val ev=UND(); if (v.t==V_OBJ && v.o) obj_get(v.o, pr->str, &ev);
            bind_pat(pr->a, ev, e, assign);   /* pr->a is the target (ident, N_ASSIGN default, member, or nested pattern) */
        }
        return;
    }
}
static void bind_pat(node *pat, val v, env *e, int assign) {
    if (++g_depth > MAXDEPTH) { g_depth--; rt_err("pattern too deeply nested"); return; }
    bind_pat_inner(pat, v, e, assign); g_depth--;
}
static void bind_pattern(node *pat, val v, env *e)        { bind_pat(pat, v, e, 0); }   /* var / param / for-of (declarations) */
static void bind_pattern_assign(node *pat, val v, env *e) { bind_pat(pat, v, e, 1); }   /* [a,b]=… / ({x}=…) (assignments) */

/* resolve a member/index target for assignment: returns the container + key */
static val eval_string_method(val recv, const char *name, val *args, int nargs);
static val eval_array_method(val recv, const char *name, val *args, int nargs);
static val eval_number_method(val recv, const char *name, val *args, int nargs);
static val eval_map_method(val recv, const char *name, val *args, int nargs);
static val eval_u8_method(val recv, const char *name, val *args, int nargs);   /* Uint8Array methods (M1850) */
static val eval_set_method(val recv, const char *name, val *args, int nargs);
static val eval_promise_method(val recv, const char *name, val *args, int nargs);   /* Promise.prototype then/catch/finally (M679) */
static int is_callable(val v){ return v.t==V_FUN || v.t==V_NATIVE || (v.t==V_OBJ && v.o && v.o->kind==V_BOUND); }
static val eval_date_method(val recv, const char *name, val *args, int nargs);
static val eval_element_method(val recv, const char *name, val *args, int nargs);
static val eval_canvas_method(val recv, const char *name, val *args, int nargs);   /* M1796: canvas 2D context methods */
static val eval_classlist_method(val recv, const char *name, val *args, int nargs);
static val classlist_handle(obj *el);
static val children_array(obj *el);   /* fwd: el.children -> array of position handles */
static val parent_handle(obj *el);     /* fwd: el.parentElement -> a position handle or null */
static val sibling_handle(obj *el, int dir);   /* fwd: el.next/previousElementSibling -> a position handle or null */
static int dom_prop(obj *el, const char *name, const char *setval, char *out, int outmax);   /* DOM element read/write */
static obj *g_doc_obj;                          /* the `document` object, so document.title can bridge to the page */
static int  (*g_get_title)(char *out, int max); /* document.title get -> the browser's <title> */
static void (*g_set_title)(const char *v);      /* document.title set -> update <title> + the window bar */

/* Accessor properties (getters/setters). An accessor is a V_ACCESSOR obj stored
 * AS the property value (its val.t stays V_OBJ, like V_BOUND), holding getter in
 * vals[0] and setter in vals[1] (UND() when absent). obj_get returns it raw — only
 * the eval READ sites (member/index get, method dispatch) fire the getter and the
 * WRITE sites (member/index assign) fire the setter, so `in`/`delete`/enumeration
 * correctly never trigger side effects. */
static int  is_accessor(val v){ return v.t==V_OBJ && v.o && v.o->kind==V_ACCESSOR; }
static obj *new_accessor(void){ obj *a=new_obj(V_ACCESSOR); if(a){ a->vals[0]=UND(); a->vals[1]=UND(); a->n=2; } return a; }
static val  fire_getter(val acc, val recv){ val g=acc.o->vals[0]; if(g.t==V_UNDEF) return UND(); return call_function_this(g, recv, 0, 0); }
#define JS_PROTO_MAX 1000   /* shared cap: proto-chain walks (proto_lookup) AND the proxy deproxy() guard below */
/* ES6 Proxy (M-proxy). A V_PROXY obj holds the target in vals[0] and the handler in
 * vals[1] (n==2); its val.t stays V_OBJ (like V_ACCESSOR/V_BOUND). is_proxy() is the
 * single branch the hot member-get/set/enumeration sites add — false for every normal
 * object, so non-proxy paths are byte-for-byte unchanged. The get/set traps go through
 * call_function_this, so a self-recursive handler is bounded by MAXDEPTH (graceful
 * "[js error: max call depth]", never a C-stack overflow). target/handler are the only
 * slots, and only ever read as objects, so no vals[] layout ever leaks as a property. */
static int  is_proxy(val v){ return v.t==V_OBJ && v.o && v.o->kind==V_PROXY; }
static val  proxy_target(val v){ return (v.o && v.o->n>0) ? v.o->vals[0] : UND(); }
static val  proxy_handler(val v){ return (v.o && v.o->n>1) ? v.o->vals[1] : UND(); }
/* Resolve a value to a proxy's target if it is a proxy (one hop is enough: new Proxy()
 * always wraps a non-proxy target here, but a guard keeps it total). Used by the
 * enumeration/JSON pass-through sites so a trap-less proxy behaves like its target and
 * never exposes vals[0]/vals[1]. (M-proxy) */
static val  deproxy(val v){ int g=0; while(is_proxy(v) && ++g<=JS_PROTO_MAX) v=proxy_target(v); return v; }
/* The SET trap, shared by the member-assign and index-assign write sites. `prox` must be
 * a V_PROXY. If handler.set is callable, fire handler.set(target, key, value, proxy) and
 * let the handler decide whether/how to mutate the target; otherwise write the property
 * straight onto the TARGET (a trap-less proxy is a transparent write-through). The call is
 * depth-guarded (call_function_this), so a self-recursive set handler hits MAXDEPTH rather
 * than overflowing. Always "handles" the write — the caller just returns rhs. (M-proxy) */
static void proxy_set(val prox, const char *key, val value){
    val target=proxy_target(prox), handler=proxy_handler(prox), trap;
    if (handler.t==V_OBJ && handler.o && obj_get(handler.o,"set",&trap) && (trap.t==V_FUN||trap.t==V_NATIVE||(trap.t==V_OBJ&&trap.o&&trap.o->kind==V_BOUND))) {
        val targs[4] = { target, STRV(key), value, prox };   /* handler.set(target, key, value, proxy); proxy is `this` */
        call_function_this(trap, prox, targs, 4);            /* depth-guarded; return value (trap's bool) is discarded — non-strict semantics */
        return;
    }
    if (target.t==V_OBJ && target.o) obj_set(target.o, key, value);   /* no set handler: write straight through to the target */
}
/* Prototype chain (M263). Walk starts AFTER an own-property miss; on a hit, an inherited
 * accessor fires with `this`=recv (the ORIGINAL receiver, not the holder). Cycle-capped
 * (a.__proto__=b; b.__proto__=a) so it can never infinite-loop. ONLY the evaluator's member
 * sites call this -- obj_get stays own-only, so in/delete/enumeration never walk the chain. */
static int proto_lookup(obj *start, const char *name, val recv, val *out) {
    int guard=0;
    for (obj *p=start; p && ++guard<=JS_PROTO_MAX; p=p->proto) {
        val v; if (obj_get(p,name,&v)) { if (is_accessor(v)) { *out=fire_getter(v,recv); return 1; } *out=v; return 1; }
    }
    return 0;
}
/* Non-firing variant for the WRITE path: find the first OWN match on the chain; report it
 * only if it's an accessor (with a settable half). A plain data prop on the chain stops the
 * search -> caller shadows it with an own property (never writes through). */
static int proto_find_accessor(obj *start, const char *name, val *out) {
    int guard=0;
    for (obj *p=start; p && ++guard<=JS_PROTO_MAX; p=p->proto) { val v; if(obj_get(p,name,&v)){ if(is_accessor(v)){*out=v; return 1;} return 0; } }
    return 0;
}

static val eval_member_get(val recv, const char *name) {
    if (recv.t==V_STR) { if (strcmp(name,"length")==0) return NUM((int64_t)strlen(recv.str)); }
    if (recv.t==V_ARR && recv.o) {        /* recv.o can be NULL if a producing method hit OOM */
        if (strcmp(name,"length")==0) return NUM(recv.o->n);
        /* a regex match-result array carries .index / .groups in match_props (M577);
         * only set on match results, so ordinary arrays are unaffected. */
        if (recv.o->match_props) { val out; if (obj_get(recv.o->match_props, name, &out)) return out; }
        /* else: arrays store elements in vals[] with keys[] unused — no named-property lookup */
    }
    if (recv.t==V_OBJ && recv.o && recv.o->kind==V_PROXY) {   /* ES6 Proxy GET trap (M-proxy): runs BEFORE any normal lookup */
        val target=proxy_target(recv), handler=proxy_handler(recv), trap;
        if (handler.t==V_OBJ && handler.o && obj_get(handler.o,"get",&trap) && (trap.t==V_FUN||trap.t==V_NATIVE||(trap.t==V_OBJ&&trap.o&&trap.o->kind==V_BOUND))) {
            val targs[3] = { target, STRV(name), recv };   /* handler.get(target, key, proxy); proxy is `this` */
            return call_function_this(trap, recv, targs, 3);   /* depth-guarded -> self-recursive trap hits MAXDEPTH, never overflows */
        }
        /* No get handler: transparently read the TARGET. The target may itself be a
         * proxy (proxies are nestable via `new Proxy(aProxy,…)`), so walk a chain of
         * trap-LESS proxies ITERATIVELY (bounded by JS_PROTO_MAX) rather than recursing
         * eval_member_get — a deep nested trap-less chain would otherwise overflow the
         * guard-page-less kernel stack. Stop at the first non-proxy or trap-HAVING proxy;
         * the final read recurses at most one guarded trap-fire deep. */
        val t = target; long pg = 0;
        /* cap far above any arena-buildable chain (each proxy+handler costs ~hundreds
         * of bytes, so the 20 MB arena OOMs at tens of thousands) so a real acyclic
         * chain is fully walked in ONE pass -> the final read recurses at most one
         * guarded trap-fire deep; the cap only defends against a hypothetical cycle. */
        while (t.t==V_OBJ && t.o && t.o->kind==V_PROXY && ++pg < 4000000) {
            val h = proxy_handler(t), tr;
            if (h.t==V_OBJ && h.o && obj_get(h.o,"get",&tr) &&
                (tr.t==V_FUN||tr.t==V_NATIVE||(tr.t==V_OBJ&&tr.o&&tr.o->kind==V_BOUND)))
                break;                       /* this proxy HAS a get trap: recurse once to fire it (guarded) */
            t = proxy_target(t);             /* trap-less proxy: transparent, walk through */
        }
        return eval_member_get(t, name);
    }
    if (recv.t==V_OBJ && recv.o) {
        if (recv.o == g_doc_obj && strcmp(name,"title")==0) { char tb[80]; tb[0]=0; if (g_get_title) g_get_title(tb,(int)sizeof tb); return STRV(intern(tb,(int)strlen(tb))); }   /* document.title -> the page <title> */
        if (strcmp(name,"__proto__")==0) { if (recv.o->proto) return obj_val(recv.o->proto); val nu=UND(); nu.t=V_NULL; return nu; }   /* magic [[Prototype]] accessor (M263) */
        if (recv.o->kind==V_MAP && strcmp(name,"size")==0) return NUM((double)(recv.o->n/2));   /* entries are [k,v] pairs */
        if (recv.o->kind==V_SET && strcmp(name,"size")==0) return NUM(recv.o->n);
        if (recv.o->kind==V_U8ARRAY) {   /* Uint8Array props (M1850) */
            if (strcmp(name,"length")==0 || strcmp(name,"byteLength")==0) return NUM(recv.o->nbytes);
            if (strcmp(name,"buffer")==0) return recv.o->n > 0 ? recv.o->vals[0] : UND();
            if (strcmp(name,"BYTES_PER_ELEMENT")==0) return NUM(1);
        }
        if (recv.o->kind==V_ARRAYBUF && strcmp(name,"byteLength")==0) return NUM(recv.o->nbytes);
        if (recv.o->kind==V_REGEX && strcmp(name,"lastIndex")==0) { regex *re=(regex*)recv.o->rx; return NUM(re?re->lastIndex:0); }   /* M1627: test/exec maintain this on the C-side regex*, not as an obj_set property */
        if (recv.o->kind==V_ELEMENT) { if(strcmp(name,"classList")==0) return classlist_handle(recv.o); if(strcmp(name,"children")==0) return children_array(recv.o); if(strcmp(name,"parentElement")==0||strcmp(name,"parentNode")==0) return parent_handle(recv.o); if(strcmp(name,"nextElementSibling")==0) return sibling_handle(recv.o,1); if(strcmp(name,"previousElementSibling")==0) return sibling_handle(recv.o,-1); if(strcmp(name,"checked")==0){ char cb[4]; cb[0]=0; dom_prop(recv.o,name,0,cb,sizeof cb); return BOOLV(cb[0]=='1'); } static char domb[4096]; if(dom_prop(recv.o,name,0,domb,sizeof(domb))) return STRV(intern(domb,(int)strlen(domb))); return UND(); }
        val out; if (obj_get(recv.o,name,&out)) { if (is_accessor(out)) return fire_getter(out, recv); return out; }
        if (recv.o->proto) { val pv; if (proto_lookup(recv.o->proto, name, recv, &pv)) return pv; }   /* inherited property/method (M263) */
        if (strcmp(name,"constructor")==0 && recv.o->ctor_class) { val cv=UND(); cv.o=recv.o->ctor_class; cv.t=(recv.o->ctor_class->kind==V_NATIVE)?V_NATIVE:V_FUN; return cv; }   /* obj.constructor -> the constructor `new` used (unless one was set explicitly, found above) (M699) */
    }
    if ((recv.t==V_FUN||recv.t==V_NATIVE) && recv.o) {
        if (recv.t==V_FUN && strcmp(name,"prototype")==0) { if (!recv.o->fn_proto) { recv.o->fn_proto=new_obj(V_OBJ); if(!recv.o->fn_proto){ g_oom=1; return UND(); } } return obj_val(recv.o->fn_proto); }   /* lazy F.prototype, in a field (functions aren't obj_keyed) (M263) */
        if (recv.t==V_FUN && strcmp(name,"name")==0) return STRV(recv.o->fn && recv.o->fn->str ? recv.o->fn->str : "");   /* fn.name / Class.name (the declared name, "" if anonymous) — so obj.constructor.name works (M699) */
        for (obj *k=recv.o; k; k=k->parent_class) if (k->statics) { val out; if (obj_get(k->statics,name,&out)) return out; }   /* Class.staticField / Number.isInteger / static method as a value (inherited up the chain) */
    }
    return UND();
}

/* JS abstract equality (==): same type -> strict (val_equal); null/undefined are inter-equal
 * but unequal to everything else; an object vs a primitive coerces the object to a string and
 * re-compares; number/string/boolean cross-type compare numerically. Recursion is bounded to
 * one object->primitive step. (=== uses val_equal directly; this is only for loose ==.) (M271) */
static int loose_eq(val a, val b) {
    if (a.t==b.t) return val_equal(a,b);
    if ((a.t==V_NULL||a.t==V_UNDEF) && (b.t==V_NULL||b.t==V_UNDEF)) return 1;
    if (a.t==V_NULL||a.t==V_UNDEF||b.t==V_NULL||b.t==V_UNDEF) return 0;
    if (a.t==V_SYMBOL||b.t==V_SYMBOL) return 0;   /* a symbol == only the SAME symbol (handled by a.t==b.t above); never loosely-equal to any other type — don't fall through to the numeric coercion below (M-symbol) */
    int aobj=(a.t==V_OBJ||a.t==V_ARR||a.t==V_FUN||a.t==V_NATIVE), bobj=(b.t==V_OBJ||b.t==V_ARR||b.t==V_FUN||b.t==V_NATIVE);
    if (aobj && bobj) return a.o==b.o;                    /* two objects of any val-types: reference identity ({}==[] -> false) (M271 review fix) */
    if (aobj) return loose_eq(to_primitive(a), b);        /* M1791: object vs primitive -> ToPrimitive(default hint = valueOf-first), re-compare (one bounded step; to_primitive never returns an object, so no further coercion) */
    if (bobj) return loose_eq(a, to_primitive(b));
    return to_num(a)==to_num(b);   /* number/string/boolean cross-type */
}

static val eval_expr_inner(node *n, env *e) {
    if (g_err || g_oom) return UND();
    switch (n->type) {
        case N_NUM: return NUM(n->num);
        case N_STR: return STRV(n->str);
        case N_REGEX: { char fl[5]; int k=0; int rf=(int)n->num; if(rf&1)fl[k++]='g'; if(rf&2)fl[k++]='i'; if(rf&4)fl[k++]='m'; if(rf&8)fl[k++]='s'; fl[k]=0; return make_regex_val(node_name(n), intern(fl,k)); }   /* intern: flags must be arena-stable, not a dead stack buffer */
        case N_BOOL: return BOOLV((int)n->num);
        case N_NULL: { val v=UND(); v.t=V_NULL; return v; }
        case N_UNDEF: return UND();
        case N_IDENT: { const char *nm=node_name(n); val *p=env_find(e,nm); if(!p){ rt_err("undefined variable"); return UND(); } return *p; }
        case N_ARRAY: { obj *o=new_obj(V_ARR); if(!o) return UND();
            for(int i=0;i<n->nlist && !g_oom;i++){ node *el=n->list[i];
                if (el->type==N_SPREAD){ val sv=eval_expr(el->a,e);
                    if (sv.t==V_ARR && sv.o){ for(int j=0;j<sv.o->n && !g_oom;j++) arr_push_val(o, sv.o->vals[j]); }
                    else if (sv.t==V_STR){ const char*s=sv.str; for(int j=0;s[j] && !g_oom;j++){ char*c=aalloc(2); if(c){c[0]=s[j];c[1]=0;} arr_push_val(o, STRV(c?c:"")); } }
                    else if (sv.t==V_OBJ && sv.o && sv.o->kind==V_SET){ for(int j=0;j<sv.o->n && !g_oom;j++) arr_push_val(o, sv.o->vals[j]); }   /* [...set] */
                    else if (sv.t==V_OBJ && sv.o && sv.o->kind==V_MAP){ for(int j=0;j+1<sv.o->n && !g_oom;j+=2){ obj*p=new_obj(V_ARR); if(!p){g_oom=1;break;} arr_push_val(p,sv.o->vals[j]); arr_push_val(p,sv.o->vals[j+1]); val pv=UND();pv.t=V_ARR;pv.o=p; arr_push_val(o,pv); } }   /* [...map] -> [[k,v],...] */
                    else if (sv.t==V_OBJ && sv.o) iter_collect(sv, o, UND(), 0);   /* [...customIterable]: drive [Symbol.iterator] (no-op for a non-iterable plain object) (M-iter) */
                } else arr_push_val(o, eval_expr(el,e));
            }
            val r=UND(); r.t=V_ARR; r.o=o; return r; }
        case N_OBJECT: { obj *o=new_obj(V_OBJ); if(!o) return UND();
            for(int i=0;i<n->nlist && !g_oom;i++){ node*pr=n->list[i];
                if (pr->type==N_SPREAD){ val sv=eval_expr(pr->a,e);
                    if (sv.t==V_OBJ && obj_keyed(sv.o)){ for(int j=0;j<sv.o->n && !g_oom;j++){ val pv=sv.o->vals[j]; if(is_accessor(pv)) pv=fire_getter(pv,sv); obj_set(o, sv.o->keys[j], pv); } }   /* spread copies the [[Get]] value, firing source getters once (M428) */
                } else if (pr->op=='g' || pr->op=='s') {   /* accessor half: merge get/set for one key into a V_ACCESSOR */
                    const char *key = node_name(pr); val cur; obj *acc;
                    if (obj_get(o,key,&cur) && is_accessor(cur)) acc=cur.o;       /* fill the other slot of an existing accessor */
                    else { acc=new_accessor(); if(!acc){ g_oom=1; break; } obj_set(o,key,obj_val(acc)); }
                    acc->vals[pr->op=='g'?0:1] = eval_expr(pr->a,e);              /* getter->[0], setter->[1] */
                } else { const char *key = pr->b ? keystr(eval_expr(pr->b,e)) : node_name(pr);   /* pr->b = computed key; symbol -> "@@sym:<id>" so {[Symbol.iterator]:fn} works (M-symbol) */
                    obj_set(o, key, eval_expr(pr->a,e)); }
            }
            val r=UND(); r.t=V_OBJ; r.o=o; return r; }
        case N_FUNC: { obj *o=new_obj(V_FUN); if(!o) return UND(); o->fn=n; o->scope=e; val r=UND(); r.t=V_FUN; r.o=o; if(n->str){ env_define(e,node_name(n),r); } return r; }
        case N_YIELD: {   /* eager generators: append the yielded value(s) to the active collection array */
            val v = n->a ? eval_expr(n->a, e) : UND();
            if (g_gen_arr) {
                if (n->op=='*') {   /* yield* spreads an iterable -- same type coverage as [...spread] (M1626); used to
                                     * only handle V_ARR, silently yielding a Set/Map/string/custom-iterable as ONE item */
                    if (v.t==V_ARR && v.o) { for (int i=0; i<v.o->n && !g_oom; i++) arr_push_val(g_gen_arr, v.o->vals[i]); }
                    else if (v.t==V_STR) { const char *s=v.str; for (int i=0; s[i] && !g_oom; i++){ char *c=aalloc(2); if(c){c[0]=s[i];c[1]=0;} arr_push_val(g_gen_arr, STRV(c?c:"")); } }
                    else if (v.t==V_OBJ && v.o && v.o->kind==V_SET) { for (int i=0; i<v.o->n && !g_oom; i++) arr_push_val(g_gen_arr, v.o->vals[i]); }
                    else if (v.t==V_OBJ && v.o && v.o->kind==V_MAP) { for (int i=0; i+1<v.o->n && !g_oom; i+=2){ obj *p=new_obj(V_ARR); if(!p){g_oom=1;break;} arr_push_val(p,v.o->vals[i]); arr_push_val(p,v.o->vals[i+1]); val pv=UND();pv.t=V_ARR;pv.o=p; arr_push_val(g_gen_arr,pv); } }
                    else if (v.t==V_OBJ && v.o) iter_collect(v, g_gen_arr, UND(), 0);   /* custom iterable: drive [Symbol.iterator] */
                }
                else arr_push_val(g_gen_arr, v);
            }
            return UND();   /* eager mode has no .next() argument, so `x = yield e` gives undefined */
        }
        case N_AWAIT: {   /* `await expr` (M680): unwrap a settled promise; rejection re-throws its reason */
            val v = n->a ? eval_expr(n->a, e) : UND();
            if (g_err) return UND();
            if (v.t==V_OBJ && v.o && v.o->kind!=V_PROMISE && obj_keyed(v.o)) {   /* await x === await Promise.resolve(x): assimilate a thenable (M687) */
                val tf; if (obj_get(v.o, "then", &tf) && is_callable(tf)) { val ra[1]={v}; v = nat_promise_resolve(ra, 1); if (g_err) return UND(); }
            }
            if (v.t==V_OBJ && v.o && v.o->kind==V_PROMISE) {
                if (pstate(v.o)==2) {   /* awaiting a rejected promise throws its reason (like N_THROW) */
                    val rv = pvalue(v.o);
                    if (!g_err) { g_throwval=rv; g_threw=1; g_err=1; const char *s=val_to_str(rv); int i=0; while(s[i]&&i<127){g_errmsg[i]=s[i];i++;} g_errmsg[i]=0; }
                    return UND();
                }
                return pvalue(v.o);   /* fulfilled -> its value (a still-pending promise yields undefined) */
            }
            return v;   /* await of a non-thenable -> the value itself */
        }
        case N_COND: return truthy(eval_expr(n->a,e)) ? eval_expr(n->b,e) : eval_expr(n->c,e);
        case N_LOGICAL: { val l=eval_expr(n->a,e);
            if(n->op=='N') return (l.t==V_UNDEF||l.t==V_NULL) ? eval_expr(n->b,e) : l;   /* ?? : only null/undefined fall through */
            if(n->op=='A') return truthy(l)?eval_expr(n->b,e):l; else return truthy(l)?l:eval_expr(n->b,e); }
        case N_UNARY: {
            if (n->op=='t') {
                if (n->a->type==N_IDENT && !env_find(e, node_name(n->a))) return STRV("undefined");   /* `typeof undeclaredVar` -> "undefined" (don't throw — the feature-detection idiom) */
                val v=eval_expr(n->a,e); const char*ty= v.t==V_UNDEF?"undefined":v.t==V_NULL?"object":v.t==V_BOOL?"boolean":v.t==V_NUM?"number":v.t==V_STR?"string":v.t==V_SYMBOL?"symbol":(v.t==V_FUN||v.t==V_NATIVE||(v.t==V_OBJ&&v.o&&v.o->kind==V_BOUND))?"function":"object"; return STRV(ty); }
            if (n->op=='d') {   /* delete obj.x / obj[k]: remove an own property, evaluate to true */
                node *t=n->a;
                if (t->type==N_MEMBER) { val r=deproxy(eval_expr(t->a,e)); if(r.t==V_OBJ&&r.o) obj_delete(r.o,node_name(t)); }   /* delete proxy.x -> deletes on the TARGET (no trap) (M-proxy) */
                else if (t->type==N_INDEX) { val r=deproxy(eval_expr(t->a,e)); val k=eval_expr(t->b,e);
                    if(r.t==V_OBJ&&r.o) obj_delete(r.o,keystr(k));   /* delete obj[sym] -> "@@sym:<id>" (M-symbol); proxy -> target (M-proxy) */
                    else if(r.t==V_ARR&&r.o){ int i=(int)to_num(k); if(i>=0&&i<r.o->n) r.o->vals[i]=UND(); } }
                return BOOLV(1);
            }
            val v=eval_expr(n->a,e);
            if (n->op=='!') return BOOLV(!truthy(v));
            if (n->op=='-') return NUM(-to_num(v));
            if (n->op=='+') return NUM(to_num(v));
            if (n->op=='~') return NUM((double)(~to_i32(to_num(v))));   /* JS ~ : ToInt32 then bitwise NOT */
            if (n->op=='v') return UND();   /* void: operand already evaluated for side effects, yield undefined */
            return UND();
        }
        case N_UPDATE: {
            node *t=n->a; val *slot=0; val recv=UND();
            if (t->type==N_IDENT) { slot=env_find(e,node_name(t)); }
            else if (t->type==N_MEMBER) {            /* o.prop++ */
                recv=eval_expr(t->a,e);
                if (recv.t==V_OBJ && obj_keyed(recv.o)) { const char *key=node_name(t);
                    for (int i=0;i<recv.o->n;i++) if(strcmp(recv.o->keys[i],key)==0){ slot=&recv.o->vals[i]; break; }
                    if (!slot) { obj_set(recv.o,key,NUM(0)); for (int i=0;i<recv.o->n;i++) if(strcmp(recv.o->keys[i],key)==0){ slot=&recv.o->vals[i]; break; } }
                }
                else if (recv.t==V_FUN && recv.o) { const char *key=node_name(t);   /* Class.staticField++ : the slot is in the side statics object (mirrors N_ASSIGN) */
                    if (!recv.o->statics) { recv.o->statics=new_obj(V_OBJ); if(!recv.o->statics) g_oom=1; }   /* M1635: lazily create on first write, like plain assignment now does -- a class/function with no PRE-declared static member used to throw "invalid ++/-- target" here instead */
                    obj *st=recv.o->statics;
                    if (st) {
                        for (int i=0;i<st->n;i++) if(strcmp(st->keys[i],key)==0){ slot=&st->vals[i]; break; }
                        if (!slot) { obj_set(st,key,NUM(0)); for (int i=0;i<st->n;i++) if(strcmp(st->keys[i],key)==0){ slot=&st->vals[i]; break; } }
                    }
                }
            }
            else if (t->type==N_INDEX) {             /* arr[i]++ / o[k]++ */
                recv=eval_expr(t->a,e); val idx=eval_expr(t->b,e);
                if (recv.t==V_ARR && recv.o) { int i=(int)to_num(idx); if(i>=0&&i<recv.o->n) slot=&recv.o->vals[i]; }
                else if (recv.t==V_OBJ && obj_keyed(recv.o)) { const char *key=keystr(idx);   /* symbol key -> "@@sym:<id>" (M-symbol) */
                    for (int i=0;i<recv.o->n;i++) if(strcmp(recv.o->keys[i],key)==0){ slot=&recv.o->vals[i]; break; }
                    if (!slot) { obj_set(recv.o,key,NUM(0)); for (int i=0;i<recv.o->n;i++) if(strcmp(recv.o->keys[i],key)==0){ slot=&recv.o->vals[i]; break; } }
                }
            }
            if (!slot) { rt_err("invalid ++/-- target"); return UND(); }
            if (is_accessor(*slot)) {   /* o.accessor++ : read via getter, write via setter -- NEVER overwrite the accessor slot (M261 review Finding 1) */
                if (recv.t!=V_OBJ) { rt_err("invalid ++/-- on accessor"); return UND(); }   /* detached (e.g. destructured) accessor: no receiver */
                val acc=*slot; double old=to_num(fire_getter(acc,recv)); double nw = n->op=='+'?old+1:old-1;   /* capture acc by value before firing (getter may realloc vals[], dangling slot); double, not int64 -- ++/-- must keep the fraction (M1752) */
                val s=acc.o->vals[1]; if(s.t!=V_UNDEF){ val av=NUM(nw); call_function_this(s,recv,&av,1); }       /* getter-only: write ignored (non-strict) */
                return NUM(n->prefix?nw:old);
            }
            double old=to_num(*slot); double nw = n->op=='+'?old+1:old-1; *slot=NUM(nw);   /* double, not int64: 9.99++ is 10.99, NaN++/Inf++ propagate (M1752) */
            return NUM(n->prefix?nw:old);
        }
        case N_BINARY: {
            val a=eval_expr(n->a,e), b=eval_expr(n->b,e);
            if (n->op=='+') { val pa=to_primitive(a),pb=to_primitive(b);   /* M1790: ToPrimitive(default) both, THEN concat iff a primitive is a string/symbol (V_STR..: an object whose valueOf yields a number now adds numerically — ({valueOf(){return 5}})+1 is 6 — while plain objects/arrays/Date still stringify) */
                if (pa.t>=V_STR||pb.t>=V_STR) { const char*sa=val_to_str(pa),*sb=val_to_str(pb); int la=(int)strlen(sa),lb=(int)strlen(sb); char*s=aalloc(la+lb+1); if(!s) return UND(); memcpy(s,sa,la); memcpy(s+la,sb,lb); s[la+lb]=0; return STRV(s); }
                return NUM(to_num(pa)+to_num(pb)); }
            double x=to_num(a), y=to_num(b);
            switch (n->op) {
                case '-': return NUM(x-y);
                case '*': return NUM(x*y);
                case '/': return NUM(x/y);                 /* real division; IEEE x/0 -> +/-Infinity, 0/0 -> NaN */
                case '%': return NUM(js_fmod(x,y));        /* remainder (sign of x); x%0 -> NaN */
                case '<': if(a.t==V_STR&&b.t==V_STR) return BOOLV(strcmp(a.str,b.str)<0);  return BOOLV(x<y);   /* two strings compare lexically; else numeric (M267) */
                case '>': if(a.t==V_STR&&b.t==V_STR) return BOOLV(strcmp(a.str,b.str)>0);  return BOOLV(x>y);
                case 'l': if(a.t==V_STR&&b.t==V_STR) return BOOLV(strcmp(a.str,b.str)<=0); return BOOLV(x<=y);
                case 'g': if(a.t==V_STR&&b.t==V_STR) return BOOLV(strcmp(a.str,b.str)>=0); return BOOLV(x>=y);
                case 'P': return NUM(js_pow(x,y));   /* x ** y (real Math.pow) */
                case 'I':   /* `in`: own-OR-inherited property on objects (walks the proto chain, non-firing — M264), valid-index test on arrays */
                    b=deproxy(b);   /* `key in proxy` -> test the TARGET (no has trap) (M-proxy) */
                    if (b.t==V_OBJ && b.o) { const char *k=val_to_str(a); val tmp; if (obj_get(b.o,k,&tmp)) return BOOLV(1);
                        int g=0; for (obj *p=b.o->proto; p && ++g<=JS_PROTO_MAX; p=p->proto) if (obj_get(p,k,&tmp)) return BOOLV(1); return BOOLV(0); }
                    if (b.t==V_ARR && b.o) return BOOLV(x>=0 && x<b.o->n);
                    return BOOLV(0);
                case 'S':   /* `instanceof`: the instance's ctor chain (classes) OR the RHS's .prototype in the instance's proto chain (M264) */
                    if (b.o && b.o==g_array_ctor) return BOOLV(a.t==V_ARR);   /* [..] instanceof Array (literals carry no ctor_class) M419 */
                    if (b.o && b.o==g_object_ctor) return BOOLV(a.t==V_ARR||a.t==V_OBJ||a.t==V_FUN||a.t==V_NATIVE);   /* arrays/objects/functions are all `instanceof Object` M419 */
                    if (a.t!=V_OBJ || !a.o || (b.t!=V_FUN && b.t!=V_NATIVE) || !b.o) return BOOLV(0);   /* RHS: a class (V_FUN) or a native ctor (Map/Set/Error/Date) */
                    for (obj *c=a.o->ctor_class; c; c=c->parent_class) if (c==b.o) return BOOLV(1);
                    if (b.o->fn_proto) { int g=0; for (obj *p=a.o->proto; p && ++g<=JS_PROTO_MAX; p=p->proto) if (p==b.o->fn_proto) return BOOLV(1); }   /* Object.create(F.prototype) instanceof F */
                    return BOOLV(0);
                /* bitwise ops follow JS: operands are coerced to int32 (ToInt32 = low 32 bits,
                 * signed), the shift count is masked to & 31, and the result is int32 (sign-
                 * extended back to the int64 number). >>> uses uint32. This matches the M269 >>>
                 * path, so e.g. 1<<31 = -2147483648 and 0xFFFFFFFF|0 = -1, like real JS — what
                 * browser scripts (|0 int-coercion, (r<<16)|(g<<8)|b packing, hashes) expect. */
                case '&': return NUM((double)(to_i32(x) & to_i32(y))); case '|': return NUM((double)(to_i32(x) | to_i32(y))); case '^': return NUM((double)(to_i32(x) ^ to_i32(y)));
                case 'L': return NUM((double)(int32_t)((uint32_t)to_i32(x) << (to_i32(y)&31))); case 'R': return NUM((double)(to_i32(x) >> (to_i32(y)&31)));
                case 'U': return NUM((double)((uint32_t)to_i32(x) >> (to_i32(y)&31)));   /* >>> unsigned (32-bit, JS semantics): -1>>>0 = 4294967295 (M269) */
                case '=': return BOOLV(val_equal(a,b));    /* === strict: val_equal is exactly it (same-type required incl. object identity; fixes 1===true which was true) (M271) */
                case '!': return BOOLV(!val_equal(a,b));    /* !== strict */
                case 'e': return BOOLV(loose_eq(a,b));      /* == loose abstract equality (M271) */
                case 'n': return BOOLV(!loose_eq(a,b));     /* != loose */
            }
            return UND();
        }
        case N_ASSIGN: {
            node *t=n->a;
            val rhs;
            if (n->op=='o'||n->op=='a'||n->op=='n') {   /* ||= &&= ??= : evaluate + assign RHS only when the short-circuit condition holds */
                val cur=eval_expr(t,e);
                int doassign = n->op=='o' ? !truthy(cur) : n->op=='a' ? truthy(cur) : (cur.t==V_UNDEF||cur.t==V_NULL);
                if (!doassign) return cur;
                rhs = eval_expr(n->b,e);
            } else {
                rhs = eval_expr(n->b,e);
                if (n->op!='=') { val cur=eval_expr(t,e);
                    if (n->op=='+') { val pa=to_primitive(cur),pb=to_primitive(rhs);   /* M1790: += matches binary + — ToPrimitive both, concat iff a string/symbol else numeric (to_primitive fires each valueOf/toString once; non-+ ops below fire it once via to_num) */
                        if (pa.t>=V_STR||pb.t>=V_STR) { const char*sa=val_to_str(pa),*sb=val_to_str(pb); int la=(int)strlen(sa),lb=(int)strlen(sb); char*s=aalloc(la+lb+1); if(s){memcpy(s,sa,la);memcpy(s+la,sb,lb);s[la+lb]=0;} rhs=STRV(s?s:""); }
                        else rhs=NUM(to_num(pa)+to_num(pb)); }
                    else { double x=to_num(cur),y=to_num(rhs); rhs = NUM(n->op=='-'?x-y: n->op=='*'?x*y: n->op=='/'?x/y: n->op=='%'?js_fmod(x,y):
                                   n->op=='&'?(double)(to_i32(x)&to_i32(y)): n->op=='|'?(double)(to_i32(x)|to_i32(y)): n->op=='^'?(double)(to_i32(x)^to_i32(y)):
                                   n->op=='L'?(double)(int32_t)((uint32_t)to_i32(x)<<(to_i32(y)&31)): n->op=='R'?(double)(to_i32(x)>>(to_i32(y)&31)): n->op=='U'?(double)((uint32_t)to_i32(x)>>(to_i32(y)&31)):
                                   n->op=='P'?js_pow(x,y): 0.0); } }
            }
            if ((t->type==N_ARRAY || t->type==N_OBJECT) && n->op=='=') { bind_pattern_assign(t, rhs, e); return rhs; }   /* [a,b]=… / ({x}=…) */
            if (t->type==N_IDENT) { const char*nm=node_name(t); val *slot=env_find(e,nm); if(slot) *slot=rhs; else env_define(e,nm,rhs); return rhs; }
            if (t->type==N_MEMBER) { val recv=eval_expr(t->a,e);
                if (is_proxy(recv)) { proxy_set(recv, node_name(t), rhs); return rhs; }   /* proxy.prop = v -> SET trap (M-proxy) */
                if (recv.t==V_OBJ && recv.o==g_doc_obj && strcmp(node_name(t),"title")==0) { if (g_set_title) g_set_title(val_to_str(rhs)); return rhs; }   /* document.title = … */
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_ELEMENT) {
                    const char *pn = node_name(t);
                    if (pn[0]=='o' && pn[1]=='n') {
                        if (rhs.t==V_FUN || rhs.t==V_NATIVE || (rhs.t==V_OBJ && rhs.o && rhs.o->kind==V_BOUND))
                            { register_handler(recv.o, pn+2, rhs); return rhs; }       /* el.onclick = fn  -> register */
                        if (rhs.t==V_NULL || rhs.t==V_UNDEF)
                            { unregister_handler(recv.o, pn+2); return rhs; }          /* el.onclick = null -> unregister */
                    }
                    dom_prop(recv.o, pn, val_to_str(rhs), 0, 0); return rhs;   /* el.textContent/innerHTML/value = … -> mutate the page */
                }
                if (recv.t==V_FUN && recv.o && strcmp(node_name(t),"prototype")==0 && rhs.t==V_OBJ && rhs.o) { recv.o->fn_proto = rhs.o; return rhs; }   /* F.prototype = obj : reassign the [[Prototype]] each `new F()` gets, so the classic `B.prototype=Object.create(A.prototype)` inheritance chain works (M698) */
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_REGEX && strcmp(node_name(t),"lastIndex")==0) { regex *re=(regex*)recv.o->rx; if(re) re->lastIndex=(int)to_num(rhs); return rhs; }   /* re.lastIndex = 0 (the standard idiom for resetting a shared global regex) must reach the C-side field test/exec actually read (M1627) */
                if (recv.t==V_FUN && recv.o) {   /* Class.staticField = … / fn.prop = … (write to the side statics object) */
                    if (!recv.o->statics) { recv.o->statics=new_obj(V_OBJ); if(!recv.o->statics){ g_oom=1; return rhs; } }   /* M1635: lazily create on first write -- this used to silently do nothing for a class/function with no PRE-declared static member */
                    obj_set(recv.o->statics, node_name(t), rhs); return rhs;
                }
                if((recv.t==V_OBJ||recv.t==V_ARR)&&recv.o){ const char *wk=node_name(t); val cur;
                    if(recv.t==V_ARR && strcmp(wk,"length")==0){ int nl=(int)to_num(rhs); if(nl<0)nl=0; if(nl>(1<<24)){ rt_err("array length too large"); return rhs; }
                        if(nl<=recv.o->n) recv.o->n=nl; else while(recv.o->n<nl && !g_oom) arr_push_val(recv.o,UND()); return rhs; }   /* a.length = n: truncate or grow-with-undefined (M267) */
                    if(recv.t==V_OBJ && strcmp(wk,"__proto__")==0){ recv.o->proto=(rhs.t==V_OBJ&&rhs.o)?rhs.o:0; return rhs; }   /* a.__proto__ = b / null (M263) */
                    if(obj_get(recv.o,wk,&cur)&&is_accessor(cur)){ val s=cur.o->vals[1]; if(s.t!=V_UNDEF) call_function_this(s,recv,&rhs,1); }                       /* own setter */
                    else if(recv.o->proto && proto_find_accessor(recv.o->proto,wk,&cur)){ val s=cur.o->vals[1]; if(s.t!=V_UNDEF) call_function_this(s,recv,&rhs,1); }   /* inherited setter (M263) */
                    else obj_set(recv.o, wk, rhs);                                                                                                                    /* own data prop (shadows inherited data) */
                } return rhs; }
            if (t->type==N_INDEX) { val recv=eval_expr(t->a,e); val idx=eval_expr(t->b,e);
                if (is_proxy(recv)) { proxy_set(recv, keystr(idx), rhs); return rhs; }   /* proxy[key] = v -> SET trap (M-proxy) */
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_U8ARRAY) {   /* Uint8Array byte write, clamped to 0-255 (M1850) */
                    int i = (int)to_num(idx);
                    if (i >= 0 && i < recv.o->nbytes) recv.o->bytes[i] = (uint8_t)((long)to_num(rhs) & 0xff);
                    return rhs;
                }
                if (recv.t==V_ARR && recv.o) {
                    long i = to_num(idx);
                    if (i < 0 || i > (1<<24)) { rt_err("array index out of range"); return rhs; }
                    while (recv.o->n <= (int)i && !g_oom) {           /* grow with UND() to reach i */
                        if (recv.o->n >= recv.o->cap) {
                            int nc = recv.o->cap*2; if (nc <= (int)i) nc = (int)i + 1;   /* i<=2^24: no int overflow */
                            val *nv = aalloc((long)sizeof(val)*nc);   /* 64-bit size; rejects if > arena */
                            if (!nv) break;                            /* g_oom set; do NOT write below */
                            memcpy(nv, recv.o->vals, sizeof(val)*recv.o->n); recv.o->vals=nv; recv.o->cap=nc;
                        }
                        recv.o->vals[recv.o->n++]=UND();
                    }
                    if (!g_oom && (int)i < recv.o->n) recv.o->vals[(int)i]=rhs;
                }
                else if (recv.t==V_OBJ && recv.o) { const char *key=keystr(idx); val cur; if(obj_get(recv.o,key,&cur)&&is_accessor(cur)){ val s=cur.o->vals[1]; if(s.t!=V_UNDEF) call_function_this(s,recv,&rhs,1); } /* own setter */ else { val acc; if(recv.o->proto && proto_find_accessor(recv.o->proto,key,&acc)){ val s=acc.o->vals[1]; if(s.t!=V_UNDEF) call_function_this(s,recv,&rhs,1); } else obj_set(recv.o, key, rhs); } }   /* inherited setter or own data; symbol key -> "@@sym:<id>" (M-symbol) */
                return rhs; }
            rt_err("invalid assignment target"); return UND();
        }
        case N_SUPER: { val *s=env_find(e,"@super"); return s?*s:UND(); }
        case N_MEMBER: {
            if (n->a->type==N_SUPER) {   /* super.prop (no call): read from the parent's method table */
                val *sup=env_find(e,"@super");
                if (sup && sup->t==V_FUN && sup->o->home_proto){ val out; if(obj_get(sup->o->home_proto,node_name(n),&out)) return out; }
                return UND();
            }
            val recv=eval_expr(n->a,e);
            if (n->prefix && (recv.t==V_UNDEF||recv.t==V_NULL)) return UND();   /* obj?.prop short-circuit */
            return eval_member_get(recv, node_name(n)); }
        case N_INDEX: { val recv=eval_expr(n->a,e);
            if (n->prefix && (recv.t==V_UNDEF||recv.t==V_NULL)) return UND();   /* obj?.[i] short-circuit */
            val idx=eval_expr(n->b,e);
            if (recv.t==V_ARR && recv.o){ int i=(int)to_num(idx); if(i>=0&&i<recv.o->n) return recv.o->vals[i]; return UND(); }
            if (recv.t==V_OBJ && recv.o && recv.o->kind==V_U8ARRAY){ int i=(int)to_num(idx); if(i>=0&&i<recv.o->nbytes) return NUM(recv.o->bytes[i]); return UND(); }   /* Uint8Array byte read (M1850) */
            if (recv.t==V_STR){ int i=(int)to_num(idx); int l=(int)strlen(recv.str); if(i>=0&&i<l){ char*s=aalloc(2); if(s){s[0]=recv.str[i]; s[1]=0;} return STRV(s?s:"");} return UND(); }
            if (is_proxy(recv)) return eval_member_get(recv, keystr(idx));   /* proxy[key]: route through eval_member_get's GET trap (M-proxy) */
            if (recv.t==V_OBJ && recv.o){ const char *ik=keystr(idx); val out; if(obj_get(recv.o,ik,&out)){ if(is_accessor(out)) return fire_getter(out,recv); return out; } if(recv.o->proto){ val pv; if(proto_lookup(recv.o->proto,ik,recv,&pv)) return pv; } }   /* inherited (M263); symbol key -> "@@sym:<id>" (M-symbol) */
            return UND(); }
        case N_CALL: {
            /* method call a.b(...) needs the receiver for string/array methods */
            node *callee=n->a; val args[16]; int na=build_args(n->list, n->nlist, e, args, 16);
            /* super(...) and super.m(...): resolve via the call frame's @super (the
             * parent constructor), invoked with the current `this`. */
            if (callee->type==N_SUPER) {
                val *sup=env_find(e,"@super"), *th=env_find(e,"this");
                if (!sup || !sup->o) { rt_err("super outside a derived constructor"); return UND(); }
                if (sup->o->native) {   /* native base (e.g. Error): run it, copy its props onto `this` (so super(msg) sets this.message) */
                    val made = sup->o->native(args, na);
                    if (th && th->t==V_OBJ && th->o && made.t==V_OBJ && made.o)
                        for (int i=0;i<made.o->n && !g_oom;i++) obj_set(th->o, made.o->keys[i], made.o->vals[i]);
                    return UND();
                }
                if (sup->t!=V_FUN) { rt_err("super outside a derived constructor"); return UND(); }
                call_function_this(*sup, th?*th:UND(), args, na); return UND();
            }
            if (callee->type==N_MEMBER && callee->a->type==N_SUPER) {
                val *sup=env_find(e,"@super"), *th=env_find(e,"this"); const char *m=node_name(callee);
                if (!sup || sup->t!=V_FUN || !sup->o->home_proto) { rt_err("no super method"); return UND(); }
                val fn; if (obj_get(sup->o->home_proto,m,&fn)) return call_function_this(fn, th?*th:UND(), args, na);
                rt_err("no such super method"); return UND();
            }
            if (callee->type==N_MEMBER) {
                val recv=eval_expr(callee->a,e); const char *m=node_name(callee);
                if (callee->prefix && (recv.t==V_UNDEF||recv.t==V_NULL)) return UND();   /* obj?.method() short-circuit */
                if (is_proxy(recv)) {   /* proxy.method(...): resolve the method via the GET trap, then call it with `this`=proxy (M-proxy) */
                    val fn=eval_member_get(recv,m);
                    if (callee->prefix && (fn.t==V_UNDEF||fn.t==V_NULL)) return UND();
                    return call_function_this(fn,recv,args,na);   /* depth-guarded; non-callable fn -> graceful rt_err("not a function") */
                }
                /* universal toString()/valueOf() for strings, arrays, plain objects (M275).
                 * Excludes Number/Boolean (eval_number_method keeps the radix-aware toString) and
                 * the kind-marked objects (Map/Set/Date/Regex/Element keep their own methods, e.g.
                 * Date.valueOf -> epoch). A plain object's OWN toString/valueOf still wins. */
                if (na==0 && (strcmp(m,"toString")==0 || strcmp(m,"valueOf")==0)
                    && (recv.t==V_STR || recv.t==V_ARR || (recv.t==V_OBJ && recv.o && recv.o->kind==V_OBJ))) {
                    if (recv.t==V_OBJ) { val f; if(obj_get(recv.o,m,&f) && (f.t==V_FUN||f.t==V_NATIVE)) return call_function_this(f,recv,args,na); }
                    return m[0]=='v' ? recv : STRV(val_to_str(recv));
                }
                if (recv.t==V_STR) return eval_string_method(recv,m,args,na);
                if (recv.t==V_ARR) return eval_array_method(recv,m,args,na);
                if (recv.t==V_NUM || recv.t==V_BOOL) return eval_number_method(recv,m,args,na);
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_U8ARRAY) return eval_u8_method(recv,m,args,na);   /* Uint8Array methods (M1850) */
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_MAP) return eval_map_method(recv,m,args,na);
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_SET) return eval_set_method(recv,m,args,na);
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_PROMISE) return eval_promise_method(recv,m,args,na);
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_REGEX) return eval_regex_method(recv,m,args,na);
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_DATE) return eval_date_method(recv,m,args,na);
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_ELEMENT) return eval_element_method(recv,m,args,na);
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_CLASSLIST) return eval_classlist_method(recv,m,args,na);
                if (recv.t==V_OBJ && recv.o && recv.o->kind==V_CANVASCTX) return eval_canvas_method(recv,m,args,na);   /* M1796: canvas 2D context */
                if (recv.t==V_FUN || recv.t==V_NATIVE || (recv.t==V_OBJ && recv.o && recv.o->kind==V_BOUND)) {   /* Function call/apply/bind */
                    if (strcmp(m,"call")==0)  return call_function_this(recv, na>0?args[0]:UND(), na>1?args+1:args, na>1?na-1:0);
                    if (strcmp(m,"apply")==0) { val th=na>0?args[0]:UND();
                        if (na>1 && args[1].t==V_ARR && args[1].o) return call_function_this(recv, th, args[1].o->vals, args[1].o->n);
                        return call_function_this(recv, th, 0, 0); }
                    if (strcmp(m,"bind")==0) { obj *bf=new_obj(V_BOUND); if(!bf){g_oom=1;return UND();}
                        arr_push_val(bf, recv); arr_push_val(bf, na>0?args[0]:UND());   /* [0]=fn [1]=this */
                        for (int i=1;i<na && !g_oom;i++) arr_push_val(bf, args[i]);      /* [2..]=partial args */
                        return obj_val(bf); }
                    if ((recv.t==V_FUN||recv.t==V_NATIVE) && recv.o) { for (obj *k=recv.o; k; k=k->parent_class) if (k->statics) { val sfn; if(obj_get(k->statics,m,&sfn)) return call_function_this(sfn, recv, args, na); } }   /* Class.staticMethod() / Number.isInteger() — `this` is the (sub)class; inherited up the chain */
                }
                if (recv.t==V_OBJ && recv.o) { val fn; if(obj_get(recv.o,m,&fn)){ if(is_accessor(fn)) fn=fire_getter(fn,recv); if(n->prefix && (fn.t==V_UNDEF||fn.t==V_NULL)) return UND(); return call_function_this(fn,recv,args,na); }
                    if(strcmp(m,"hasOwnProperty")==0){ val tmp; return BOOLV(na>0 && obj_keyed(recv.o) && obj_get(recv.o, val_to_str(args[0]), &tmp)); }   /* built-in own-property test (M274) */
                    if(strcmp(m,"propertyIsEnumerable")==0){ val tmp; return BOOLV(na>0 && obj_keyed(recv.o) && obj_get(recv.o, val_to_str(args[0]), &tmp)); }   /* all own props are enumerable here (M279) */
                    if(recv.o->proto && proto_lookup(recv.o->proto,m,recv,&fn)){ if(n->prefix && (fn.t==V_UNDEF||fn.t==V_NULL)) return UND(); return call_function_this(fn,recv,args,na); } }   /* inherited method, this=recv (M263) */
                if (n->prefix) return UND();   /* obj.method?.() where method is absent */
                rt_err("no such method"); return UND();
            }
            val fn=eval_expr(callee,e);
            if (n->prefix && (fn.t==V_UNDEF||fn.t==V_NULL)) return UND();   /* fn?.() short-circuit */
            return call_function(fn,args,na);
        }
        case N_THIS: { val *t=env_find(e,"this"); return t?*t:UND(); }
        case N_NEWTARGET: return g_newtarget;   /* the constructor an active `new` is building, else undefined (M700) */
        case N_CLASS: {
            /* Build the method table P, then a constructor function value carrying
             * P in home_proto. `extends` copies the parent's methods into P first
             * (children override by being added after), and an absent child
             * constructor inherits the parent's. Each own method/ctor records its
             * parent constructor in super_class so super()/super.m() can find it. */
            obj *P=new_obj(V_OBJ); if(!P){ g_oom=1; return UND(); }
            node *ctor_node=0; val parentC=UND(); int has_parent=0; obj *parent_obj=0;
            if (n->a) {
                parentC=eval_expr(n->a,e); has_parent=(parentC.t==V_FUN || parentC.t==V_NATIVE); if(has_parent) parent_obj=parentC.o;   /* a native base (e.g. class X extends Error) is a valid parent too */
                if (has_parent && parentC.o->home_proto) { obj *pp=parentC.o->home_proto; for(int i=0;i<pp->n && !g_oom;i++) obj_set(P,pp->keys[i],pp->vals[i]); }
            }
            for (int i=0;i<n->nlist && !g_oom;i++){ node *m=n->list[i];
                /* mkey = the method's property key: a computed [expr] method (m->b set) is
                 * evaluated now and symbol-encoded via keystr; otherwise the interned name.
                 * A computed-key method has str==NULL so it can never be "constructor". (M-symbol) */
                const char *mkey = m->b ? keystr(eval_expr(m->b,e)) : node_name(m);
                if (!m->b && strcmp(mkey,"constructor")==0){ ctor_node=m; continue; }
                obj *fo=new_obj(V_FUN); if(!fo){ g_oom=1; return UND(); } fo->fn=m; fo->scope=e; fo->super_class=parent_obj;
                val fv=UND(); fv.t=V_FUN; fv.o=fo;
                if (m->op=='g' || m->op=='s') {   /* accessor method -> merge into an accessor in P[name] (fresh copy so overriding a parent's accessor doesn't mutate it) */
                    obj *acc=new_accessor(); if(!acc){ g_oom=1; return UND(); }
                    val cur; if (obj_get(P,mkey,&cur) && is_accessor(cur)){ acc->vals[0]=cur.o->vals[0]; acc->vals[1]=cur.o->vals[1]; }
                    acc->vals[m->op=='g'?0:1]=fv; obj_set(P, mkey, obj_val(acc));
                } else obj_set(P, mkey, fv);
            }
            obj *ctor_super=parent_obj;   /* own ctor: super is this class's parent */
            int inherited_ctor=0;
            if (!ctor_node && has_parent) { ctor_node = parentC.o->fn; ctor_super = parentC.o->super_class; inherited_ctor=1; }  /* inherited ctor: its super is the GRANDparent (where it was defined) */
            if (!ctor_node) { node *em=mknode(N_FUNC); em->list=aalloc(sizeof(node*)); em->nlist=0; em->a=mknode(N_BLOCK); ctor_node=em; }
            if (!inherited_ctor && n->str) ctor_node->str = n->str;   /* Class.name: tag this class's own/synthesized ctor node with the class name, so co->fn->str feeds eval_member_get's .name (don't mutate an inherited parent node) (M699) */
            obj *co=new_obj(V_FUN); if(!co){ g_oom=1; return UND(); } co->fn=ctor_node; co->scope=e; co->home_proto=P; co->super_class=ctor_super; co->parent_class=parent_obj; co->fields=n->b;
            val cv=UND(); cv.t=V_FUN; cv.o=co;
            if (n->str) env_define(e, node_name(n), cv);   /* bind the class name first so statics can reference it */
            if (n->c && n->c->type==N_BLOCK && n->c->nlist>0) {   /* build co->statics (Class.method / Class.field) */
                obj *st=new_obj(V_OBJ);
                if (st) { co->statics=st;   /* attach BEFORE the loop so a static init can reference an earlier static via the class name */
                          for (int i=0;i<n->c->nlist && !g_oom;i++){ node *pr=n->c->list[i]; obj_set(st, node_name(pr), eval_expr(pr->a, e)); } }
            }
            return cv;
        }
        case N_NEW: {
            val ctor=eval_expr(n->a,e); val args[16]; int na=build_args(n->list, n->nlist, e, args, 16);
            if (ctor.t==V_NATIVE) { val r=ctor.o->native(args,na); if (r.t==V_OBJ && r.o && !r.o->ctor_class) r.o->ctor_class=ctor.o; return r; }   /* new Map()/Set()/Error()/Date(): native makes the instance; link it to the ctor for instanceof */
            if (ctor.t!=V_FUN) { rt_err("not a constructor"); return UND(); }
            obj *self=new_obj(V_OBJ); if(!self){ g_oom=1; return UND(); }
            self->ctor_class = ctor.o;   /* record the constructor so `instanceof` can find it */
            if (!ctor.o->home_proto) {   /* PLAIN function (home_proto==NULL) -> instances inherit from F.prototype (the fn_proto object); classes (home_proto!=NULL) use the copy below, untouched (M263) */
                if (!ctor.o->fn_proto) { ctor.o->fn_proto=new_obj(V_OBJ); if(!ctor.o->fn_proto){ g_oom=1; return UND(); } }
                self->proto = ctor.o->fn_proto;
            }
            /* class instance: copy the class's methods onto the new object as own
             * properties (we model methods by copying rather than a prototype chain) */
            if (ctor.o->home_proto) { obj *P=ctor.o->home_proto; for(int i=0;i<P->n && !g_oom;i++) obj_set(self,P->keys[i],P->vals[i]); }
            val selfv=obj_val(self);
            val nt_saved=g_newtarget; g_newtarget=ctor;   /* new.target = the constructor being `new`'d, throughout field-init + the ctor (+ super) chain (M700) */
            /* run instance field initializers (this.x=init), parent-class first so a child can override */
            { obj *chain[32]; int cn=0; for (obj *k=ctor.o; k && cn<32; k=k->parent_class) chain[cn++]=k;
              for (int ci=cn-1; ci>=0 && !g_err && !g_oom; ci--) { obj *k=chain[ci];
                  if (k->fields && k->fields->type==N_BLOCK) {
                      env *fe=new_env(k->scope); if(!fe){ g_oom=1; break; }
                      env_define(fe,"this",selfv);
                      for (int si=0; si<k->fields->nlist && !g_err && !g_oom; si++) eval_stmt(k->fields->list[si], fe);
                  } } }
            val r=call_function_this(ctor, selfv, args, na);
            g_newtarget=nt_saved;   /* restore (a nested `new` saved/restored its own; top level returns to V_UNDEF) */
            /* a constructor that explicitly returns an object overrides `this` */
            return (r.t==V_OBJ||r.t==V_ARR) ? r : selfv;
        }
    }
    return UND();
}

/* depth-guarded wrapper around the expression evaluator: a deep AST (member/index
 * chains, nested operators, self-referential structures via val_to_str) would
 * otherwise recurse C-stack-deep. Shares g_depth with the parser/calls. */
static val eval_expr(node *n, env *e) {
    if (++g_depth > MAXDEPTH) { rt_err("expression too deeply nested"); g_depth--; return UND(); }
    val v = eval_expr_inner(n, e); g_depth--; return v;
}

static comp CN(void){ comp c; c.kind=C_NORMAL; c.v=UND(); c.label=0; return c; }
/* labeled break/continue (M280): does completion c (a BREAK/CONTINUE) terminate/re-target a loop
 * labeled `lbl` (NULL=unlabeled loop)? An unlabeled completion (c.label==0) applies to ANY loop;
 * a labeled one only to its matching label. intern() does NOT dedup, so compare with strcmp. */
static int label_here(comp c, const char *lbl){ return c.label==0 || (lbl && strcmp(c.label,lbl)==0); }

/* Does this subtree contain a function/arrow? Used by `for(let …)` to decide
 * whether a fresh per-iteration binding is observable: only a closure can
 * capture the loop variable, so without one we reuse a single env (no per-
 * iteration allocation — important on the GC-less arena for big loops). */
static int node_has_func(node *n, int depth){
    if(!n || depth>500) return 0;
    if(n->type==N_FUNC) return 1;
    if(node_has_func(n->a,depth+1)||node_has_func(n->b,depth+1)||node_has_func(n->c,depth+1)||node_has_func(n->d,depth+1)) return 1;
    for(int i=0;i<n->nlist;i++) if(node_has_func(n->list[i],depth+1)) return 1;
    return 0;
}

/* Run one for-of/for-in body iteration, binding `cv` to the loop target. With a
 * block-scoped (let/const) loop var AND a closure in the body, each iteration
 * gets a fresh env so the closure captures this step's value; otherwise the
 * shared `fe` is reused (no per-iteration allocation, as for `var`). */
static comp eval_stmt(node *n, env *e);
static comp foreach_step(node *n, env *e, env *fe, const char *vn, int per_iter, val cv){
    env *ie = fe;
    if(per_iter){ ie=new_env(e); if(!ie){ g_oom=1; return CN(); } }
    if(n->c) bind_pattern(n->c, cv, ie);
    else if(per_iter) env_define(ie, vn, cv);
    else { val *slot=env_find(fe,vn); if(slot) *slot=cv; }
    return eval_stmt(n->b, ie);
}

/* define-if-absent: a `var` re-declaration / a name already a param or a hoisted binding must NOT be reset. */
static void hoist_def(env *fe, const char *nm){ if(!nm || !nm[0]) return; for(int k=0;k<fe->n;k++) if(strcmp(fe->keys[k],nm)==0) return; env_define(fe,nm,UND()); }
/* Pre-pass run once at function/program entry: define every `var`-declared name (NOT let/const) as `undefined`
 * in the function/global env `fe`, so a `var` read before its line — or in a branch that never executes — yields
 * `undefined` (JS hoisting) instead of throwing "undefined variable". Walks statements, descending into
 * blocks/if/loops/switch/try but STOPPING at a nested function (its vars belong to its own scope). */
static void hoist_vars(node *n, env *fe){
    if(!n) return;
    switch(n->type){
        case N_FUNC: return;                                  /* nested function: its own var scope */
        case N_VAR:
            if(!n->num) for(int i=0;i<n->nlist;i++){ node*d=n->list[i]; if(d && !d->b) hoist_def(fe, node_name(d)); }   /* var, plain name (skip let/const + destructuring patterns) */
            return;
        case N_PROGRAM: case N_BLOCK:
            for(int i=0;i<n->nlist;i++) hoist_vars(n->list[i],fe);
            return;
        case N_IF:                hoist_vars(n->b,fe); hoist_vars(n->c,fe); return;
        case N_WHILE: case N_DOWHILE: hoist_vars(n->b,fe); return;
        case N_FOR:               hoist_vars(n->a,fe); hoist_vars(n->d,fe); return;   /* a=init (maybe `for(var i…)`), d=body */
        case N_FOROF: case N_FORIN:
            if(!n->num && !n->c) hoist_def(fe, node_name(n));  /* for(var x of/in …): the plain loop var */
            hoist_vars(n->b,fe); return;
        case N_SWITCH:
            for(int i=0;i<n->nlist;i++){ node*cl=n->list[i]; if(cl) for(int j=0;j<cl->nlist;j++) hoist_vars(cl->list[j],fe); } return;
        case N_TRY:               hoist_vars(n->a,fe); hoist_vars(n->b,fe); hoist_vars(n->c,fe); return;
        default: return;                                      /* expressions / return / break / etc. hold no var statements */
    }
}
/* Does executing this N_BLOCK's OWN statement list (not nested blocks/loops/
 * ifs, which scope themselves when THEY run) define a name that must live in
 * a scope distinct from the parent's? A plain `var` doesn't count — it's
 * defined via env_func_scope, which already walks past a block env whether or
 * not one exists, so it works identically either way. Exactly three
 * constructs bind directly into a block's OWN env: a let/const declaration, a
 * function declaration (mirrors the hoisting loop just below in
 * eval_stmt_inner's N_BLOCK case), and a named class declaration (a class
 * expression env_define's its own name — see N_CLASS in eval_expr). A block
 * with none of these can safely reuse the parent env with no observable
 * difference, since nothing it runs writes anywhere but through
 * env_func_scope (var) or into a nested construct's own env. */
static int block_needs_own_scope(node *n){
    for(int i=0;i<n->nlist;i++){
        node *s=n->list[i]; if(!s) continue;
        if(s->type==N_VAR && s->num) return 1;                                    /* let/const */
        if(s->type==N_FUNC && s->str) return 1;                                   /* function decl */
        if(s->type==N_EXPR && s->a && s->a->type==N_CLASS && s->a->str) return 1; /* named class decl */
    }
    return 0;
}
static comp eval_stmt_inner(node *n, env *e) {
    if (g_err || g_oom) return CN();
    switch (n->type) {
        case N_PROGRAM: case N_BLOCK: {
            env *be = (n->type==N_BLOCK && block_needs_own_scope(n))? new_env(e) : e;
            if (!be) { g_oom=1; return CN(); }
            /* Hoist function declarations: define every `function name(){…}` in this
             * block before any statement runs, so a call textually BEFORE the
             * declaration resolves (standard JS). Skip them in the main pass below so
             * each keeps a single identity. (var hoisting + expressions unaffected.) */
            for (int i=0;i<n->nlist;i++){ node*s=n->list[i]; if(s && s->type==N_FUNC && s->str){ eval_expr(s,be); if(g_oom) return CN(); } }
            for (int i=0;i<n->nlist;i++){ node*s=n->list[i]; if(s && s->type==N_FUNC && s->str) continue;   /* already hoisted */
                comp c=eval_stmt(s,be); if(c.kind!=C_NORMAL||g_err||g_oom) return c; }
            return CN();
        }
        case N_VAR: { env *te = n->num ? e : env_func_scope(e);   /* let/const stay block-scoped (e); var is function-scoped, so it survives its block */
            for(int i=0;i<n->nlist;i++){ node*d=n->list[i];
                if (!d->a && !d->b && !n->num) { hoist_def(te, node_name(d)); continue; }   /* bare `var x;` (no init): keep any hoisted value / a same-named param — define undefined ONLY if absent, never reset */
                val v = d->a?eval_expr(d->a,e):UND();
                if (d->b) bind_pattern(d->b, v, te); else env_define(te,node_name(d),v); }
            return CN(); }
        case N_FUNC: { eval_expr(n,e); return CN(); }
        case N_EXPR: { eval_expr(n->a,e); return CN(); }
        case N_IF: { if (truthy(eval_expr(n->a,e))) return eval_stmt(n->b,e); else if (n->c) return eval_stmt(n->c,e); return CN(); }
        case N_WHILE: {
            int guard=0;
            while (truthy(eval_expr(n->a,e))) { if(++guard>5000000){rt_err("loop limit");break;} comp c=eval_stmt(n->b,e); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c; if(g_err||g_oom) break; }
            return CN();
        }
        case N_DOWHILE: {
            int guard=0;
            do { comp c=eval_stmt(n->b,e); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c; if(g_err||g_oom) break; if(++guard>5000000){rt_err("loop limit");break;} } while (truthy(eval_expr(n->a,e)));
            return CN();
        }
        case N_SWITCH: {
            val disc=eval_expr(n->a,e); env *se=new_env(e); if(!se){ g_oom=1; return CN(); }
            int matched=-1, defidx=-1;
            for (int i=0;i<n->nlist && !g_err && !g_oom;i++){ node*cl=n->list[i]; if(!cl->a){ defidx=i; continue; }
                val cv=eval_expr(cl->a,se); int eq;
                if (disc.t==V_STR && cv.t==V_STR) eq=(strcmp(disc.str,cv.str)==0);
                else if ((disc.t==V_NUM||disc.t==V_BOOL)&&(cv.t==V_NUM||cv.t==V_BOOL)) eq=(disc.num==cv.num);
                else eq=(disc.t==cv.t && disc.o==cv.o);   /* objects/arrays/functions/null/undefined: switch uses ===, i.e. reference identity (was disc.num==cv.num, which is 0==0 for ALL objects -> any object case matched) */
                if (eq){ matched=i; break; } }
            if (matched<0) matched=defidx;
            if (matched>=0) for (int i=matched;i<n->nlist;i++){ node*cl=n->list[i];
                for (int j=0;j<cl->nlist;j++){ comp c=eval_stmt(cl->list[j],se);
                    if (c.kind==C_BREAK){ if (c.label==0) return CN(); else return c; } if (c.kind==C_RETURN||c.kind==C_CONTINUE) return c; if (g_err||g_oom) return CN(); } }   /* unlabeled break ends the switch; labeled break + any continue propagate to the enclosing loop (M280) */
            return CN();
        }
        case N_FOR: {
            env *fe=new_env(e); if(!fe){ g_oom=1; return CN(); }
            if(n->a){ if(n->a->type==N_VAR) eval_stmt(n->a,fe); else eval_expr(n->a,fe); }
            /* `for(let …)` gives each iteration a FRESH binding of the loop vars
             * so a closure made in the body captures that iteration's value — but
             * only bother (allocating an env per iteration) when the body actually
             * has a closure; otherwise reuse fe, identical to a `var` loop. */
            int per_iter = (n->a && n->a->type==N_VAR && n->a->num && node_has_func(n->d,0));
            int guard=0;
            for(;;){
                env *ie=fe;
                if(per_iter){ ie=new_env(e); if(!ie){ g_oom=1; break; } for(int k=0;k<fe->n;k++) env_define(ie, fe->keys[k], fe->vals[k]); }
                if(n->b && !truthy(eval_expr(n->b,ie))) break;
                if(++guard>5000000){rt_err("loop limit");break;}
                comp c=eval_stmt(n->d,ie); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c; if(g_err) break;
                if(per_iter){ for(int k=0;k<fe->n;k++) fe->vals[k]=ie->vals[k]; }   /* copy any body mutation back before the update */
                if(n->c) eval_expr(n->c,fe);
            }
            return CN();
        }
        case N_FOROF: {
            val it=eval_expr(n->a,e); env *fe=new_env(e); if(!fe){ g_oom=1; return CN(); }
            const char *vn = n->c ? 0 : node_name(n);   /* n->c is a destructuring pattern, else a plain name */
            int per_iter = (n->num && node_has_func(n->b,0));   /* let/const + a closure in the body -> fresh binding per iteration */
            if (vn) env_define(fe, vn, UND());
            if (it.t==V_ARR && it.o) {
                for (int i=0;i<it.o->n && !g_err && !g_oom;i++){
                    comp c=foreach_step(n,e,fe,vn,per_iter,it.o->vals[i]); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c; }
            } else if (it.t==V_OBJ && it.o && it.o->kind==V_U8ARRAY) {   /* for..of over a Uint8Array's bytes (M1850) */
                for (int i=0;i<it.o->nbytes && !g_err && !g_oom;i++){
                    comp c=foreach_step(n,e,fe,vn,per_iter,NUM(it.o->bytes[i])); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c; }
            } else if (it.t==V_STR) {
                int l=(int)strlen(it.str);
                for (int i=0;i<l && !g_err && !g_oom;i++){ char*ch=aalloc(2); if(ch){ch[0]=it.str[i];ch[1]=0;} val cv=STRV(ch?ch:"");
                    comp c=foreach_step(n,e,fe,vn,per_iter,cv); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c; }
            } else if (it.t==V_OBJ && it.o && it.o->kind==V_SET) {
                for (int i=0;i<it.o->n && !g_err && !g_oom;i++){ val cv=it.o->vals[i];
                    comp c=foreach_step(n,e,fe,vn,per_iter,cv); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c; }
            } else if (it.t==V_OBJ && it.o && it.o->kind==V_MAP) {
                for (int i=0;i+1<it.o->n && !g_err && !g_oom;i+=2){             /* each entry is a fresh [k,v] array */
                    obj *pair=new_obj(V_ARR); if(!pair){ g_oom=1; break; } arr_push_val(pair,it.o->vals[i]); arr_push_val(pair,it.o->vals[i+1]);
                    val cv=UND(); cv.t=V_ARR; cv.o=pair;
                    comp c=foreach_step(n,e,fe,vn,per_iter,cv); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c; }
            } else if (it.t==V_OBJ && it.o && it.o->kind==V_OBJ) {
                /* ----- ES6 iterator protocol (M-symbol) -----
                 * A plain object is iterable iff it has a callable obj[Symbol.iterator].
                 * Call it (this=obj) to get an iterator, then repeatedly call iterator.next()
                 * (this=iterator) -> {value, done}; stop when done is truthy, binding value
                 * to the loop target each step (same break/continue/return handling as the
                 * V_ARR branch). Absent/non-callable [Symbol.iterator] -> iterate nothing.
                 *
                 * TERMINATION SAFETY (kernel, untrusted input): each next() RETURNS, so the
                 * recursion depth guard does NOT bound this loop — a misbehaving iterator that
                 * never yields done:true must not hang the kernel. Two co-guards make
                 * termination unconditional:
                 *   1. FOROF_ITER_MAX — a hard iteration cap (catchable rt_err). This is the
                 *      decisive guard: a JS next() that allocates nothing per call (so it never
                 *      trips OOM) is still stopped here. The cap bounds ONLY custom iterables;
                 *      arrays/strings/sets/maps use their own branches above, so legitimate
                 *      large iterations are unaffected.
                 *   2. g_oom — every JS next() call allocates a call frame in the arena (no GC),
                 *      so a runaway ALLOCATING iterator trips graceful OOM and the loop breaks on
                 *      g_oom (OOM is NOT masked: it propagates as the engine's real OOM, it is
                 *      just an additional early stop).
                 * Reachability: an allocating next() consumes ~0.5 KB of arena per call, so on the
                 * default 16 MB arena only tens of thousands of calls fit from a FRESH arena, and
                 * far fewer once a long script has already consumed most of it (no GC). The cap is
                 * therefore set LOW ENOUGH (2,000) to stay a REACHABLE, exercised guard — the
                 * regression suite hits it at exactly 2,000 even though the suite has already used
                 * ~14 MB by then — while remaining far larger than any realistic CUSTOM iterable
                 * (arrays/strings/sets/maps use their own uncapped branches above; this branch only
                 * bounds user-defined [Symbol.iterator] objects). A non-allocating iterator (which
                 * OOM would never catch) is also stopped here, which is the cap's core purpose. */
                #define FOROF_ITER_MAX 2000
                val itfn = eval_member_get(it, sym_key(SYM_ID_ITERATOR));
                int callable = (itfn.t==V_FUN || itfn.t==V_NATIVE || (itfn.t==V_OBJ && itfn.o && itfn.o->kind==V_BOUND));
                if (callable && !g_err && !g_oom) {
                    val iter = call_function_this(itfn, it, 0, 0);
                    if (iter.t==V_ARR && iter.o && !g_err && !g_oom) {   /* eager generator as [Symbol.iterator]: iterate its collected values */
                        for (int i=0;i<iter.o->n && !g_oom;i++) {
                            comp c=foreach_step(n,e,fe,vn,per_iter,iter.o->vals[i]); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c;
                        }
                    } else if (iter.t==V_OBJ && iter.o && !g_err && !g_oom) {
                        val nextfn = eval_member_get(iter, "next");   /* fetch next ONCE: every real iterator exposes a fixed `next` data method. (Re-reading it per step, as the spec's GetMethod does, would add a member-get allocation per iteration and lower the OOM/cap headroom for no practical gain.) */
                        int ncall = (nextfn.t==V_FUN || nextfn.t==V_NATIVE || (nextfn.t==V_OBJ && nextfn.o && nextfn.o->kind==V_BOUND));
                        long guard=0;
                        while (ncall) {
                            if (g_err || g_oom) break;
                            if (++guard > FOROF_ITER_MAX) { rt_err("for-of: iterator did not terminate"); break; }
                            val res = call_function_this(nextfn, iter, 0, 0);
                            if (g_err || g_oom) break;
                            if (res.t!=V_OBJ || !res.o) break;                     /* result must be an object; otherwise stop */
                            if (truthy(eval_member_get(res, "done"))) break;       /* done:truthy -> finished */
                            val cv = eval_member_get(res, "value");
                            if (g_err || g_oom) break;
                            comp c=foreach_step(n,e,fe,vn,per_iter,cv); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c;
                        }
                    }
                }
                #undef FOROF_ITER_MAX
            }
            return CN();
        }
        case N_THROW: { val v=eval_expr(n->a,e);
            if(!g_err){ g_throwval=v; g_threw=1; g_err=1; const char*s=val_to_str(v); int i=0; while(s[i]&&i<127){g_errmsg[i]=s[i];i++;} g_errmsg[i]=0; }
            return CN(); }   /* unwinds via g_err; if the operand itself errored, that error propagates */
        case N_TRY: {
            comp tc = eval_stmt(n->a, e);                /* try block */
            if (g_err && !g_oom && n->b) {               /* caught — ONLY if a catch clause exists */
                /* copy the message into the arena BEFORE clearing g_errmsg (STRV stores the pointer) */
                val ev = g_threw ? g_throwval : STRV(intern(g_errmsg[0]?g_errmsg:"error", (int)strlen(g_errmsg[0]?g_errmsg:"error")));
                g_err=0; g_threw=0; g_errmsg[0]=0; tc=CN();
                env *ce=new_env(e); if(!ce){ g_oom=1; } else { if(n->str) env_define(ce, node_name(n), ev); tc=eval_stmt(n->b,ce); }
            }
            /* with no catch clause, g_err stays set so the exception propagates (re-raised
             * past finally via the save/restore below, or out of the try if no finally). */
            if (n->c) {                                  /* finally always runs (on a clean slate) */
                int s_err=g_err, s_threw=g_threw; val s_tv=g_throwval; char s_msg[128]; memcpy(s_msg,g_errmsg,128);
                g_err=0; g_threw=0;
                comp fc=eval_stmt(n->c,e);
                if (fc.kind!=C_NORMAL) return fc;        /* finally's return/break/continue wins */
                if (g_err) return tc;                    /* finally itself threw -> propagate it */
                g_err=s_err; g_threw=s_threw; g_throwval=s_tv; memcpy(g_errmsg,s_msg,128);   /* restore pending */
            }
            return tc;
        }
        case N_FORIN: {
            val it=eval_expr(n->a,e); env *fe=new_env(e); if(!fe){ g_oom=1; return CN(); }
            it=deproxy(it);   /* for-in over a proxy enumerates the TARGET's keys (no ownKeys trap; never exposes vals[0]/vals[1]) (M-proxy) */
            const char *vn=node_name(n); env_define(fe, vn, UND());
            int per_iter = (n->num && node_has_func(n->b,0));   /* let/const + a closure -> fresh binding per iteration */
            if (it.t==V_OBJ && obj_keyed(it.o)) {   /* keyed objects only (Date/Map/Set/arrays have no enumerable own keys here) */
                for (int i=0;i<it.o->n && !g_err && !g_oom;i++){
                    if(is_internal_key(it.o->keys[i])) continue;   /* hide @@ symbol keys from for-in (M-symbol) */
                    comp c=foreach_step(n,e,fe,vn,per_iter,STRV(it.o->keys[i])); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c; }
            } else if (it.t==V_ARR && it.o) {
                for (int i=0;i<it.o->n && !g_err && !g_oom;i++){
                    comp c=foreach_step(n,e,fe,vn,per_iter,NUM(i)); if(c.kind==C_BREAK){ if(label_here(c,n->label)) break; else return c; } if(c.kind==C_CONTINUE && !label_here(c,n->label)) return c; if(c.kind==C_RETURN) return c; }
            }
            return CN();
        }
        case N_RETURN: { comp c; c.kind=C_RETURN; c.v = n->a?eval_expr(n->a,e):UND(); c.label=0; return c; }
        case N_BREAK: { comp c=CN(); c.kind=C_BREAK; c.label=n->label; return c; }   /* c.label = target label or NULL (M280) */
        case N_CONTINUE: { comp c=CN(); c.kind=C_CONTINUE; c.label=n->label; return c; }
        default: eval_expr(n,e); return CN();
    }
}
/* depth-guarded wrapper around the statement evaluator (deeply nested blocks /
 * if / while / for). Shares g_depth with eval_expr, the parser, and calls. */
static comp eval_stmt(node *n, env *e) {
    if (++g_depth > MAXDEPTH) { rt_err("statements too deeply nested"); g_depth--; return CN(); }
    comp c = eval_stmt_inner(n, e); g_depth--; return c;
}

/* ---- builtin methods + globals ---- */
/* methods on number/bool primitives: (255).toString(16) -> "ff", (3.14159).toFixed(2) -> "3.14".
 * Numbers are real doubles (M906); toString() base-10 = full float, a non-10 radix uses the integer value. */
static val eval_number_method(val recv, const char *name, val *args, int nargs) {
    long long v=(long long)to_num(recv);
    if (strcmp(name,"toString")==0) {
        int radix=nargs?(int)to_num(args[0]):10; if(radix<2||radix>36) radix=10;
        if (radix==10) return STRV(num_to_str(to_num(recv)));   /* base 10: full float formatting ((3.14).toString() === "3.14"), not the integer-only radix path */
        { double dv=to_num(recv); if (js_isnan(dv)||js_isinf(dv)) return STRV(num_to_str(dv)); }   /* NaN/Infinity have no radix form -> "NaN"/"Infinity" (was a 64-bit garbage string from the int cast) */
        char tmp[72]; int i=0; int neg=v<0;
        unsigned long long u = neg ? (unsigned long long)(-(v+1))+1ULL : (unsigned long long)v;
        if(u==0) tmp[i++]='0';
        while(u){ int d=(int)(u%(unsigned)radix); tmp[i++]=d<10?('0'+d):('a'+d-10); u/=(unsigned)radix; }
        if(neg) tmp[i++]='-';
        /* M1794: fractional part in the chosen radix — (3.5).toString(16) === "3.8", not "3".
         * Up to 32 fractional digits (bounds the buffer + non-terminating fractions like 0.1 base-2). */
        double dvv=to_num(recv), frac=(dvv<0?-dvv:dvv)-(double)(neg?-v:v);
        char fbuf[40]; int fn=0;
        while(frac>0 && fn<32){ frac*=radix; int fd=(int)frac; if(fd<0)fd=0; if(fd>=radix)fd=radix-1; fbuf[fn++]=fd<10?('0'+fd):('a'+fd-10); frac-=fd; }
        char*r=aalloc(i+(fn?fn+1:0)+1); if(!r) return STRV("");
        int p=0; for(int j=0;j<i;j++){ r[p++]=tmp[i-1-j]; }
        if(fn){ r[p++]='.'; for(int j=0;j<fn;j++) r[p++]=fbuf[j]; }
        r[p]=0; return STRV(r);
    }
    if (strcmp(name,"toFixed")==0) {                 /* round to k decimals: (3.14159).toFixed(2) -> "3.14" */
        int k = nargs ? (int)to_num(args[0]) : 0;
        if (k < 0) k = 0; if (k > 100) k = 100;
        double d = to_num(recv);
        if (js_isnan(d)) return STRV("NaN");
        if (js_isinf(d)) return STRV(d<0?"-Infinity":"Infinity");
        int neg = d < 0; if (neg) d = -d;
        double scale = 1.0; for (int j=0;j<k;j++) scale *= 10.0;
        double scaled = js_floor(d*scale + 0.5);     /* round half up, to an integer-valued double */
        char digs[420]; int nd=0;                    /* extract decimal digits of `scaled` */
        if (scaled < 1.0) digs[nd++]='0';
        else { char tmp[420]; int tn=0; double t=scaled;
               while (t>=1.0 && tn<419){ double q=js_floor(t/10.0); int dg=(int)(t-q*10.0); tmp[tn++]=(char)('0'+dg); t=q; }
               for (int j=tn-1;j>=0;j--) digs[nd++]=tmp[j]; }
        char *r = aalloc(nd + k + 4); if(!r) return STRV(""); int p=0;
        if (neg && !(scaled==0.0)) r[p++]='-';        /* -0 -> "0.00" not "-0.00" */
        if (k==0) { for(int j=0;j<nd;j++) r[p++]=digs[j]; }
        else if (nd<=k) { r[p++]='0'; r[p++]='.'; for(int j=0;j<k-nd;j++) r[p++]='0'; for(int j=0;j<nd;j++) r[p++]=digs[j]; }
        else { int il=nd-k; for(int j=0;j<il;j++) r[p++]=digs[j]; r[p++]='.'; for(int j=il;j<nd;j++) r[p++]=digs[j]; }
        r[p]=0; return STRV(r);
    }
    if (strcmp(name,"toExponential")==0 || strcmp(name,"toPrecision")==0) {
        int prec = strcmp(name,"toPrecision")==0;                /* 1 = toPrecision, 0 = toExponential */
        double dv = to_num(recv);
        if (js_isnan(dv)) return STRV("NaN");
        if (js_isinf(dv)) return STRV(dv<0?"-Infinity":"Infinity");
        if (prec && !nargs) return STRV(num_to_str(dv));         /* toPrecision() with no arg == toString */
        int k = nargs ? (int)to_num(args[0]) : 6;                /* toExponential default 6 frac digits */
        if (k < 1 && prec) k = 1; if (k < 0) k = 0; if (k > 17) k = 17;
        int ndig = prec ? k : k+1;                               /* total significant digits to produce */
        char *r = aalloc(48); if(!r) return STRV(""); int p=0;
        if (dv < 0) { r[p++]='-'; dv=-dv; }
        int e = 0;
        if (dv != 0.0) { double t=dv; while(t>=10.0){t*=0.1;e++;} while(t<1.0){t*=10.0;e--;} dv=t; }   /* dv in [1,10) */
        double scl=1.0; for(int j=0;j<ndig-1;j++) scl*=10.0;
        double sc = js_floor(dv*scl + 0.5); if (sc >= 10.0*scl){ sc*=0.1; e++; }   /* ndig-digit integer */
        char dg[20]; int dn=0; { char tmp[20]; int tn=0; int64_t z=(int64_t)sc; if(z==0)tmp[tn++]='0'; while(z){tmp[tn++]=(char)('0'+(int)(z%10));z/=10;} while(tn<ndig)tmp[tn++]='0'; for(int i=tn-1;i>=0;i--) dg[dn++]=tmp[i]; }
        if (!prec || e < -6 || e >= ndig) {                      /* exponential form: d.dddde±XX */
            r[p++]=dg[0];
            if (ndig>1){ r[p++]='.'; for(int i=1;i<ndig;i++) r[p++]=(i<dn)?dg[i]:'0'; }
            r[p++]='e'; r[p++]=(e<0)?'-':'+'; int ae=e<0?-e:e;
            char eb[4]; int en=0; if(ae==0)eb[en++]='0'; while(ae){eb[en++]=(char)('0'+ae%10);ae/=10;} while(en>0) r[p++]=eb[--en];
        } else if (e >= 0) {                                     /* toPrecision fixed, point after e+1 digits */
            for(int i=0;i<=e;i++) r[p++]=(i<dn)?dg[i]:'0';
            if (ndig>e+1){ r[p++]='.'; for(int i=e+1;i<ndig;i++) r[p++]=(i<dn)?dg[i]:'0'; }
        } else {                                                 /* toPrecision fixed, 0.00ddd */
            r[p++]='0'; r[p++]='.'; for(int i=0;i<-e-1;i++) r[p++]='0'; for(int i=0;i<ndig;i++) r[p++]=(i<dn)?dg[i]:'0';
        }
        r[p]=0; return STRV(r);
    }
    if (strcmp(name,"valueOf")==0) return recv;
    if (strcmp(name,"toLocaleString")==0){   /* group integer digits in 3s with commas, keeping any fraction: 1234567 -> "1,234,567", 1234.5 -> "1,234.5" (M278, M920) */
        double dv = to_num(recv);
        if (js_isnan(dv) || js_isinf(dv)) return STRV(num_to_str(dv));
        const char *ns = num_to_str(dv);                          /* "1234.5" / "-1234" / "1e21" */
        int neg = ns[0]=='-', si = neg?1:0, dot = si;
        while (ns[dot] && ns[dot]!='.' && ns[dot]!='e' && ns[dot]!='E') dot++;   /* integer part is [si, dot) */
        char out[80]; int oi=0; if(neg && oi<79) out[oi++]='-';
        for (int i=si; i<dot && oi<76; i++){ out[oi++]=ns[i]; int rem=dot-1-i; if(rem>0 && rem%3==0) out[oi++]=','; }   /* thousands separators */
        for (int i=dot; ns[i] && oi<79; i++) out[oi++]=ns[i];     /* append ".frac" / "eXX" unchanged */
        out[oi]=0; char*r=aalloc(oi+1); if(!r) return STRV(""); memcpy(r,out,oi+1); return STRV(r);
    }
    rt_err("no such number method"); return UND();
}

static val eval_string_method(val recv, const char *name, val *args, int nargs) {
    const char *s=recv.str; int len=(int)strlen(s);
    if (strcmp(name,"charAt")==0){ int i=nargs?js_toint(to_num(args[0])):0; if(i<0||i>=len) return STRV(""); char*r=aalloc(2); r[0]=s[i]; r[1]=0; return STRV(r); }   /* M1782: NaN/undefined index -> 0 */
    if (strcmp(name,"charCodeAt")==0){ int i=nargs?js_toint(to_num(args[0])):0; if(i<0||i>=len) return NUM(JS_NAN); return NUM((unsigned char)s[i]); }   /* M1766: out-of-range -> NaN; M1782: NaN index -> 0 */
    if (strcmp(name,"codePointAt")==0){ int i=nargs?js_toint(to_num(args[0])):0; if(i<0||i>=len) return UND(); return NUM((unsigned char)s[i]); }   /* = charCodeAt for ASCII (M278); M1782: NaN index -> 0 */
    if (strcmp(name,"localeCompare")==0){ const char*o=nargs?val_to_str(args[0]):""; int c=strcmp(s,o); return NUM(c<0?-1:c>0?1:0); }   /* ASCII collation (M278) */
    if (strcmp(name,"toUpperCase")==0||strcmp(name,"toLocaleUpperCase")==0){ char*r=aalloc(len+1); for(int i=0;i<len;i++) r[i]=(s[i]>='a'&&s[i]<='z')?s[i]-32:s[i]; r[len]=0; return STRV(r); }
    if (strcmp(name,"toLowerCase")==0||strcmp(name,"toLocaleLowerCase")==0){ char*r=aalloc(len+1); for(int i=0;i<len;i++) r[i]=(s[i]>='A'&&s[i]<='Z')?s[i]+32:s[i]; r[len]=0; return STRV(r); }
    if (strcmp(name,"normalize")==0) return recv;   /* ASCII has no composed forms: NFC/NFD/… are identity */
    if (strcmp(name,"concat")==0){ int tot=len; for(int i=0;i<nargs;i++) tot+=(int)strlen(val_to_str(args[i])); char*r=aalloc(tot+1); if(!r) return STRV(""); int p=0; for(int j=0;j<len;j++) r[p++]=s[j]; for(int i=0;i<nargs;i++){ const char*a=val_to_str(args[i]); for(int j=0;a[j];j++) r[p++]=a[j]; } r[p]=0; return STRV(r); }
    if (strcmp(name,"substring")==0||strcmp(name,"slice")==0){ int a=nargs>0?(int)to_num(args[0]):0; int b=nargs>1?(int)to_num(args[1]):len;
        if (name[1]=='l') { if(a<0)a+=len; if(b<0)b+=len; }   /* slice (name[1]=='l') counts negatives from the end; substring clamps to 0 */
        if(a<0)a=0; if(b<0)b=0; if(a>len)a=len; if(b>len)b=len;
        if (name[1]=='u' && a>b) { int t=a; a=b; b=t; }   /* substring swaps its args when start>end (slice clamps to empty instead) */
        if(b<a)b=a; char*r=aalloc(b-a+1); if(!r) return STRV(""); memcpy(r,s+a,b-a); r[b-a]=0; return STRV(r); }
    if (strcmp(name,"indexOf")==0){ if(!nargs) return NUM(-1); const char*sub=val_to_str(args[0]); int sl=(int)strlen(sub); int from=nargs>1?(int)to_num(args[1]):0; if(from<0)from=0; if(from>len)from=len; /* M1630: clamp the upper bound too, like startsWith/endsWith already do -- "abc".indexOf("",10) is 3, not -1 */ for(int i=from;i+sl<=len;i++){ if(memcmp(s+i,sub,sl)==0) return NUM(i);} return NUM(-1); }
    if (strcmp(name,"lastIndexOf")==0){ if(!nargs) return NUM(-1); const char*sub=val_to_str(args[0]); int sl=(int)strlen(sub); int from=nargs>1?(int)to_num(args[1]):len; if(from<0)from=0; if(from>len)from=len; int start=from; if(start>len-sl)start=len-sl; for(int i=start;i>=0;i--){ if(memcmp(s+i,sub,sl)==0) return NUM(i);} return NUM(-1); }
    if (strcmp(name,"includes")==0){ if(!nargs) return BOOLV(0); const char*sub=val_to_str(args[0]); int sl=(int)strlen(sub); int from=nargs>1?(int)to_num(args[1]):0; if(from<0)from=0; if(from>len)from=len; /* M1630: same upper-bound clamp as indexOf */ for(int i=from;i+sl<=len;i++) if(memcmp(s+i,sub,sl)==0) return BOOLV(1); return BOOLV(0); }
    if (strcmp(name,"startsWith")==0){ if(!nargs) return BOOLV(0); const char*sub=val_to_str(args[0]); int sl=(int)strlen(sub); int pos=nargs>1?(int)to_num(args[1]):0; if(pos<0)pos=0; if(pos>len)pos=len; /* match from position (M694) */ return BOOLV(sl<=len-pos && memcmp(s+pos,sub,sl)==0); }
    if (strcmp(name,"endsWith")==0){ if(!nargs) return BOOLV(0); const char*sub=val_to_str(args[0]); int sl=(int)strlen(sub); int end=nargs>1?(int)to_num(args[1]):len; if(end<0)end=0; if(end>len)end=len; /* treat the string as if it ended at `end` (M694) */ return BOOLV(sl<=end && memcmp(s+end-sl,sub,sl)==0); }
    if (strcmp(name,"trim")==0){ int a=0,b=len; while(a<b&&(s[a]==' '||s[a]=='\t'||s[a]=='\n'||s[a]=='\r'))a++; while(b>a&&(s[b-1]==' '||s[b-1]=='\t'||s[b-1]=='\n'||s[b-1]=='\r'))b--; char*r=aalloc(b-a+1); if(!r) return STRV(""); memcpy(r,s+a,b-a); r[b-a]=0; return STRV(r); }
    if (strcmp(name,"trimStart")==0){ int a=0; while(a<len&&(s[a]==' '||s[a]=='\t'||s[a]=='\n'||s[a]=='\r'))a++; char*r=aalloc(len-a+1); if(!r) return STRV(""); memcpy(r,s+a,len-a); r[len-a]=0; return STRV(r); }
    if (strcmp(name,"trimEnd")==0){ int b=len; while(b>0&&(s[b-1]==' '||s[b-1]=='\t'||s[b-1]=='\n'||s[b-1]=='\r'))b--; char*r=aalloc(b+1); if(!r) return STRV(""); memcpy(r,s,b); r[b]=0; return STRV(r); }
    if (strcmp(name,"repeat")==0){ int cnt=nargs?(int)to_num(args[0]):0; if(cnt<0){ rt_err("Invalid count value"); return STRV(""); } /* negative -> RangeError (M694) */ long total=(long)len*cnt; if(total>JS_ARENA){ rt_err("repeat too large"); return STRV(""); } char*r=aalloc(total+1); if(!r) return STRV(""); int p=0; for(int k=0;k<cnt;k++) for(int j=0;j<len;j++) r[p++]=s[j]; r[p]=0; return STRV(r); }
    if (strcmp(name,"search")==0){ regex *re=nargs?rx_of(args[0]):0; if(!re&&nargs) re=re_compile(val_to_str(args[0]),""); if(!re) return NUM(-1); int caps[2*(RE_MAXGROUP+1)]; return NUM(re_search(re,s,len,0,caps)); }
    if (strcmp(name,"match")==0){ regex *re=nargs?rx_of(args[0]):0; if(!re&&nargs) re=re_compile(val_to_str(args[0]),""); if(!re||!re->ok){ val nv=UND(); nv.t=V_NULL; return nv; }
        int caps[2*(RE_MAXGROUP+1)];
        if(re->global){ obj*a=new_obj(V_ARR); if(!a) return UND(); int pos=0,any=0; while(pos<=len){ int st=re_search(re,s,len,pos,caps); if(st<0) break; any=1; char*m=aalloc(caps[1]-caps[0]+1); if(m){memcpy(m,s+caps[0],caps[1]-caps[0]);m[caps[1]-caps[0]]=0;} arr_push_val(a,STRV(m?m:"")); pos = caps[1]>caps[0]?caps[1]:caps[1]+1; if(g_oom)break; } if(!any){ val nv=UND(); nv.t=V_NULL; return nv; } val r=UND();r.t=V_ARR;r.o=a;return r; }
        int st=re_search(re,s,len,0,caps); if(st<0){ val nv=UND(); nv.t=V_NULL; return nv; } return re_result(re,s,caps); }
    if (strcmp(name,"matchAll")==0){ regex *re=nargs?rx_of(args[0]):0; if(!re&&nargs) re=re_compile(val_to_str(args[0]),"");
        obj*out=new_obj(V_ARR); if(!out) return UND();                  /* array of [fullMatch, g1, g2, …] result arrays */
        if(re&&re->ok){ int caps[2*(RE_MAXGROUP+1)]; int pos=0;
            while(pos<=len && !g_oom && !g_err){ int st=re_search(re,s,len,pos,caps); if(st<0) break; arr_push_val(out, re_result(re,s,caps)); pos = caps[1]>caps[0]?caps[1]:caps[1]+1; } }
        val r=UND(); r.t=V_ARR; r.o=out; return r; }
    if ((strcmp(name,"replace")==0||strcmp(name,"replaceAll")==0) && nargs>=1 && rx_of(args[0])){ regex *re=rx_of(args[0]);
        int all = strcmp(name,"replaceAll")==0;   /* replaceAll(re,…): replace every match regardless of the /g flag */
        int has_fn = nargs>1 && (args[1].t==V_FUN||args[1].t==V_NATIVE);   /* str.replace(re, (m,g1,…)=>…) */
        const char *repl = (nargs>1 && !has_fn) ? val_to_str(args[1]) : "";
        int caps[2*(RE_MAXGROUP+1)]; sbuild b; memset(&b,0,sizeof(b)); int pos=0;
        for(;;){ int st=re_search(re,s,len,pos,caps); if(st<0||g_oom||g_err) break;
            sb_put(&b, s+pos, caps[0]-pos);
            if(has_fn){ val fa[RE_MAXGROUP+3]; int na=0;                    /* M1770: pass (match, g1, …, gN, offset, wholeString) per spec */
                for(int gi=0; gi<=re->ngroup && na<RE_MAXGROUP+1; gi++){ int a=caps[2*gi],e=caps[2*gi+1]; if(a>=0&&e>=a){ char*m=aalloc(e-a+1); if(m){memcpy(m,s+a,e-a);m[e-a]=0;} fa[na++]=STRV(m?m:""); } else fa[na++]=UND(); }
                fa[na++]=NUM(caps[0]); fa[na++]=STRV(s);                    /* M1770: the match offset, then the whole subject string */
                val rv=call_function(args[1], fa, na); const char *rs=val_to_str(rv); sb_put(&b, rs, (int)strlen(rs)); }
            else sb_expand(&b, repl, s, caps, re->ngroup, re->gnames);
            pos = caps[1]>caps[0]?caps[1]:caps[1]+1; if(caps[1]==caps[0] && caps[0]<len) sb_put(&b, s+caps[0], 1);   /* zero-width: emit a char, advance */
            if(!re->global && !all){ break; } }
        sb_put(&b, s+pos, len-pos); if(b.buf) b.buf[b.len]=0; return STRV(b.buf?b.buf:""); }
    if (strcmp(name,"replace")==0){ if(nargs<2) return STRV(s); const char*from=val_to_str(args[0]); int fl=(int)strlen(from); if(fl==0) return STRV(s);
        int has_fn = args[1].t==V_FUN||args[1].t==V_NATIVE;                 /* M1780: str.replace("lit", fn) must CALL fn(match, offset, whole), not stringify it */
        const char *repl = has_fn ? "" : val_to_str(args[1]);
        for(int i=0;i+fl<=len;i++){ if(memcmp(s+i,from,fl)==0){
            sbuild b; memset(&b,0,sizeof(b)); sb_put(&b, s, i);             /* text before the match */
            if(has_fn){ val fa[3]; fa[0]=STRV(from); fa[1]=NUM(i); fa[2]=STRV(s); val rv=call_function(args[1],fa,3); const char*rs=val_to_str(rv); sb_put(&b,rs,(int)strlen(rs)); }
            else { int caps[2]={i,i+fl}; sb_expand(&b, repl, s, caps, 0, 0); }   /* M1780: expand $& $$ $` $' in the replacement */
            sb_put(&b, s+i+fl, len-i-fl); if(b.buf) b.buf[b.len]=0; return STRV(b.buf?b.buf:""); } }
        return STRV(s); }
    if (strcmp(name,"replaceAll")==0){ if(nargs<2) return STRV(s); const char*from=val_to_str(args[0]); int fl=(int)strlen(from); if(fl==0) return STRV(s);
        int has_fn = args[1].t==V_FUN||args[1].t==V_NATIVE;                 /* M1780: fn replacer + $-expansion, per match */
        const char *repl = has_fn ? "" : val_to_str(args[1]);
        sbuild b; memset(&b,0,sizeof(b));
        for(int i=0;i<len;){ if(i+fl<=len && memcmp(s+i,from,fl)==0){
                if(has_fn){ val fa[3]; fa[0]=STRV(from); fa[1]=NUM(i); fa[2]=STRV(s); val rv=call_function(args[1],fa,3); const char*rs=val_to_str(rv); sb_put(&b,rs,(int)strlen(rs)); }
                else { int caps[2]={i,i+fl}; sb_expand(&b, repl, s, caps, 0, 0); }
                i+=fl; if(g_oom||g_err) break; }
            else { sb_put(&b, s+i, 1); i++; } }
        if(b.buf) b.buf[b.len]=0; return STRV(b.buf?b.buf:""); }
    if (strcmp(name,"at")==0){ int i=nargs?js_toint(to_num(args[0])):0; if(i<0) i+=len; if(i<0||i>=len) return UND(); char*r=aalloc(2); if(r){r[0]=s[i];r[1]=0;} return STRV(r?r:""); }   /* M1782: NaN index -> 0 */
    if (strcmp(name,"padStart")==0||strcmp(name,"padEnd")==0){ int tgt=nargs?(int)to_num(args[0]):0; const char*pad=nargs>1?val_to_str(args[1]):" "; int pl=(int)strlen(pad); if(tgt<=len||pl==0||tgt>JS_ARENA){ char*r=aalloc(len+1); if(r){memcpy(r,s,len);r[len]=0;} return STRV(r?r:""); }
        char*r=aalloc(tgt+1); if(!r) return STRV(""); int padn=tgt-len; int p=0;
        if(name[3]=='S'){ for(int i=0;i<padn;i++) r[p++]=pad[i%pl]; for(int i=0;i<len;i++) r[p++]=s[i]; }   /* padStart */
        else { for(int i=0;i<len;i++) r[p++]=s[i]; for(int i=0;i<padn;i++) r[p++]=pad[i%pl]; }              /* padEnd */
        r[p]=0; return STRV(r); }
    if (strcmp(name,"split")==0 && nargs>=1 && rx_of(args[0])){ regex *re=rx_of(args[0]); obj*arr=new_obj(V_ARR); if(!arr) return UND(); int caps[2*(RE_MAXGROUP+1)]; int start=0,pos=0;
        while(pos<=len){ int st=re_search(re,s,len,pos,caps); if(st<0||g_oom) break;
            if(caps[0]==caps[1] && (caps[0]<=start || caps[0]>=len)){ pos=caps[0]+1; continue; }   /* M1770: a zero-width match at the current segment start or at end-of-string is not a split boundary -- just advance (was: skip ALL zero-width, so `split(/(?=X)/)` never split) */
            char*p=aalloc(caps[0]-start+1); if(p){memcpy(p,s+start,caps[0]-start);p[caps[0]-start]=0;} arr_push_val(arr,STRV(p?p:""));
            for(int g=1; g<=re->ngroup; g++){ int gs=caps[2*g],ge=caps[2*g+1];   /* per spec: captured groups are spliced into the result */
                if(gs>=0&&ge>=gs){ char*gp=aalloc(ge-gs+1); if(gp){memcpy(gp,s+gs,ge-gs);gp[ge-gs]=0;} arr_push_val(arr,STRV(gp?gp:"")); } else arr_push_val(arr,UND()); }
            start=caps[1]; pos = caps[1]>caps[0] ? caps[1] : caps[1]+1; }   /* M1770: advance past a zero-width boundary to make progress */
        char*p=aalloc(len-start+1); if(p){memcpy(p,s+start,len-start);p[len-start]=0;} arr_push_val(arr,STRV(p?p:""));
        if (nargs>1) { int lim=(int)to_num(args[1]); if(lim>=0 && arr->n>lim) arr->n=lim; }   /* split(re, limit) */
        val v=UND();v.t=V_ARR;v.o=arr;return v; }
    if (strcmp(name,"split")==0){ obj*arr=new_obj(V_ARR); if(!arr) return UND(); const char*sep=nargs?val_to_str(args[0]):0; int sl=sep?(int)strlen(sep):-1;
        if(sl<0){ arr_push_val(arr,STRV(s)); }                       /* no separator: whole string */
        else if(sl==0){ for(int i=0;i<len;i++){ char*c=aalloc(2); if(c){c[0]=s[i];c[1]=0;} arr_push_val(arr,STRV(c?c:"")); } }  /* "" -> chars */
        else { int start=0; for(int i=0;i+sl<=len;){ if(memcmp(s+i,sep,sl)==0){ char*p=aalloc(i-start+1); if(p){memcpy(p,s+start,i-start);p[i-start]=0;} arr_push_val(arr,STRV(p?p:"")); i+=sl; start=i; } else i++; } char*p=aalloc(len-start+1); if(p){memcpy(p,s+start,len-start);p[len-start]=0;} arr_push_val(arr,STRV(p?p:"")); }
        if (nargs>1) { int lim=(int)to_num(args[1]); if(lim>=0 && arr->n>lim) arr->n=lim; }   /* split(sep, limit) */
        val v=UND(); v.t=V_ARR; v.o=arr; return v; }
    if (strcmp(name,"substr")==0){ int a=nargs>0?(int)to_num(args[0]):0; if(a<0){a+=len; if(a<0)a=0;} if(a>len)a=len;   /* substr(start, length) -- legacy (M276) */
        int ln=nargs>1?(int)to_num(args[1]):(len-a); if(ln<0)ln=0; if(ln>len-a)ln=len-a;
        char*r=aalloc(ln+1); if(!r) return STRV(""); memcpy(r,s+a,ln); r[ln]=0; return STRV(r); }
    rt_err("unknown string method"); return UND();
}
/* recursively flatten `src` into `r` up to `depth` levels (depth is caller-capped) */
static void flat_into(obj *r, obj *src, int depth){
    for(int i=0;i<src->n && !g_oom;i++){ val e=src->vals[i];
        if(depth>0 && e.t==V_ARR && e.o) flat_into(r, e.o, depth-1); else arr_push_val(r, e); }
}
static val eval_array_method(val recv, const char *name, val *args, int nargs) {
    obj *o=recv.o; if(!o) return UND();   /* a method that OOM'd can yield a NULL-backed array */
    if (strcmp(name,"push")==0){ for(int i=0;i<nargs;i++){ if(o->n>=o->cap){int nc=o->cap*2+4;val*nv=aalloc(sizeof(val)*nc);if(!nv){g_oom=1;break;}memcpy(nv,o->vals,sizeof(val)*o->n);o->vals=nv;o->cap=nc;} o->vals[o->n++]=args[i]; } return NUM(o->n); }
    if (strcmp(name,"pop")==0){ if(o->n==0) return UND(); return o->vals[--o->n]; }
    if (strcmp(name,"join")==0){
        const char*sep=(nargs && args[0].t!=V_UNDEF)?val_to_str(args[0]):","; long sl=(long)strlen(sep);   /* M1782: join(undefined) uses the default "," separator (spec) */
        const char **parts=aalloc((long)sizeof(char*)*(o->n>0?o->n:1)); if(!parts) return STRV("");
        long total=0; for(int i=0;i<o->n;i++){ val ev=o->vals[i]; parts[i]=(ev.t==V_UNDEF||ev.t==V_NULL)?"":val_to_str(ev);   /* per spec: undefined/null elements join as "" */
            total+=(long)strlen(parts[i]); if(i) total+=sl; }
        char*buf=aalloc(total+1); if(!buf) return STRV(""); int p=0;
        for(int i=0;i<o->n;i++){ if(i){ for(long k=0;k<sl;k++) buf[p++]=sep[k]; } const char*v=parts[i]; while(*v) buf[p++]=*v++; }
        buf[p]=0; return STRV(buf);
    }
    if (strcmp(name,"indexOf")==0){ int from=nargs>1?(int)to_num(args[1]):0; if(from<0)from+=o->n; if(from<0)from=0; for(int i=from;i<o->n;i++) if(nargs && val_equal(o->vals[i],args[0])) return NUM(i); return NUM(-1); }   /* strict (===): also finds objects by identity, null, undefined */
    if (strcmp(name,"includes")==0){ int from=nargs>1?(int)to_num(args[1]):0; if(from<0)from+=o->n; if(from<0)from=0; for(int i=from;i<o->n;i++) if(nargs && same_value_zero(o->vals[i],args[0])) return BOOLV(1); return BOOLV(0); }   /* includes uses SameValueZero: [NaN].includes(NaN) is true (indexOf stays strict ===) */
    if (strcmp(name,"concat")==0){ obj*r=new_obj(V_ARR); if(!r) return UND(); for(int i=0;i<o->n;i++) arr_push_val(r,o->vals[i]); for(int a=0;a<nargs;a++){ if(args[a].t==V_ARR&&args[a].o){ for(int i=0;i<args[a].o->n;i++) arr_push_val(r,args[a].o->vals[i]); } else arr_push_val(r,args[a]); } val v=UND(); v.t=V_ARR; v.o=r; return v; }
    if (strcmp(name,"fill")==0){ val fv=nargs>0?args[0]:UND(); int a=nargs>1?(int)to_num(args[1]):0, b=nargs>2?(int)to_num(args[2]):o->n; if(a<0)a+=o->n; if(b<0)b+=o->n; if(a<0)a=0; if(b>o->n)b=o->n; for(int i=a;i<b;i++) o->vals[i]=fv; return recv; }   /* fill existing slots [start,end) */
    if (strcmp(name,"slice")==0){ int a=nargs>0?(int)to_num(args[0]):0, b=nargs>1?(int)to_num(args[1]):o->n; if(a<0)a+=o->n; if(b<0)b+=o->n; if(a<0)a=0; if(b>o->n)b=o->n; obj*r=new_obj(V_ARR); if(!r) return UND(); for(int i=a;i<b;i++) arr_push_val(r,o->vals[i]); val v=UND(); v.t=V_ARR; v.o=r; return v; }
    if (strcmp(name,"reverse")==0){ for(int i=0,j=o->n-1;i<j;i++,j--){ val t=o->vals[i]; o->vals[i]=o->vals[j]; o->vals[j]=t; } return recv; }
    if (strcmp(name,"shift")==0){ if(o->n==0) return UND(); val r=o->vals[0]; for(int i=1;i<o->n;i++) o->vals[i-1]=o->vals[i]; o->n--; return r; }
    if (strcmp(name,"unshift")==0){ int need=o->n+nargs;
        if(need>o->cap){ int nc=o->cap*2+4; while(nc<need) nc*=2; val*nv=aalloc((long)sizeof(val)*nc); if(!nv){g_oom=1;return NUM(o->n);} memcpy(nv,o->vals,(long)sizeof(val)*o->n); o->vals=nv; o->cap=nc; }
        for(int i=o->n-1;i>=0;i--) o->vals[i+nargs]=o->vals[i];   /* shift existing right */
        for(int i=0;i<nargs;i++) o->vals[i]=args[i]; o->n+=nargs; return NUM(o->n); }
    if (strcmp(name,"splice")==0){   /* splice(start, delCount, ...items) -> removed array */
        int start=nargs>0?(int)to_num(args[0]):0; if(start<0){ start+=o->n; if(start<0)start=0; } if(start>o->n)start=o->n;
        int del=nargs>1?(int)to_num(args[1]):(o->n-start); if(del<0)del=0; if(del>o->n-start)del=o->n-start;
        int nins=nargs>2?nargs-2:0;
        obj*rem=new_obj(V_ARR); if(!rem){g_oom=1;return UND();}
        for(int i=0;i<del;i++) arr_push_val(rem,o->vals[start+i]);   /* collect removed */
        int newn=o->n-del+nins, tail=o->n-(start+del);
        if(newn>o->cap){ int nc=o->cap*2+4; while(nc<newn) nc*=2; val*nv=aalloc((long)sizeof(val)*nc); if(!nv){g_oom=1; val v=UND(); v.t=V_ARR; v.o=rem; return v; } memcpy(nv,o->vals,(long)sizeof(val)*o->n); o->vals=nv; o->cap=nc; }
        if(nins>del){ for(int i=tail-1;i>=0;i--) o->vals[start+nins+i]=o->vals[start+del+i]; }       /* grow: move tail right (backwards) */
        else if(nins<del){ for(int i=0;i<tail;i++) o->vals[start+nins+i]=o->vals[start+del+i]; }      /* shrink: move tail left (forwards) */
        for(int i=0;i<nins;i++) o->vals[start+i]=args[2+i]; o->n=newn;
        val v=UND(); v.t=V_ARR; v.o=rem; return v; }
    if (strcmp(name,"fill")==0){ val fv=nargs?args[0]:UND(); int st=nargs>1?(int)to_num(args[1]):0, en=nargs>2?(int)to_num(args[2]):o->n; if(st<0)st+=o->n; if(en<0)en+=o->n; if(st<0)st=0; if(en>o->n)en=o->n; for(int i=st;i<en;i++) o->vals[i]=fv; return recv; }
    if (strcmp(name,"lastIndexOf")==0){ int start=o->n-1; if(nargs>1){ int fi=(int)to_num(args[1]); if(fi<0) fi+=o->n; if(fi<start) start=fi; } /* search backward from fromIndex (M692) */ for(int i=start;i>=0;i--) if(nargs && val_equal(o->vals[i],args[0])) return NUM(i); return NUM(-1); }   /* strict (===) */
    if (strcmp(name,"flat")==0){ double dd=nargs?to_num(args[0]):1; int depth=(js_isnan(dd)||dd<=0)?0:((js_isinf(dd)||dd>64)?64:(int)dd); /* flat(Infinity) -> 64 (deep); check non-finite BEFORE the (int) cast (UB on Inf) */ obj*r=new_obj(V_ARR); if(!r) return UND(); flat_into(r,o,depth); val v=UND(); v.t=V_ARR; v.o=r; return v; }
    if (strcmp(name,"forEach")==0){ if(nargs) for(int i=0;i<o->n && !g_err && !g_oom;i++){ val ca[3]={o->vals[i],NUM(i),recv}; call_function(args[0],ca,3); } return UND(); }
    if (strcmp(name,"map")==0){ obj*r=new_obj(V_ARR); if(!r) return UND(); if(nargs) for(int i=0;i<o->n && !g_err && !g_oom;i++){ val ca[3]={o->vals[i],NUM(i),recv}; arr_push_val(r,call_function(args[0],ca,3)); } val v=UND(); v.t=V_ARR; v.o=r; return v; }
    if (strcmp(name,"filter")==0){ obj*r=new_obj(V_ARR); if(!r) return UND(); if(nargs) for(int i=0;i<o->n && !g_err && !g_oom;i++){ val ca[3]={o->vals[i],NUM(i),recv}; if(truthy(call_function(args[0],ca,3))) arr_push_val(r,o->vals[i]); } val v=UND(); v.t=V_ARR; v.o=r; return v; }
    if (strcmp(name,"find")==0){ if(nargs) for(int i=0;i<o->n && !g_err && !g_oom;i++){ val ca[3]={o->vals[i],NUM(i),recv}; if(truthy(call_function(args[0],ca,3))) return o->vals[i]; } return UND(); }
    if (strcmp(name,"findLast")==0){ if(nargs) for(int i=o->n-1;i>=0 && !g_err && !g_oom;i--){ val ca[3]={o->vals[i],NUM(i),recv}; if(truthy(call_function(args[0],ca,3))) return o->vals[i]; } return UND(); }
    if (strcmp(name,"findLastIndex")==0){ if(nargs) for(int i=o->n-1;i>=0 && !g_err && !g_oom;i--){ val ca[3]={o->vals[i],NUM(i),recv}; if(truthy(call_function(args[0],ca,3))) return NUM(i); } return NUM(-1); }
    if (strcmp(name,"at")==0){ int i=nargs?js_toint(to_num(args[0])):0; if(i<0) i+=o->n; if(i>=0&&i<o->n) return o->vals[i]; return UND(); }   /* M1782: NaN index -> 0 */
    if (strcmp(name,"flatMap")==0){ obj*r=new_obj(V_ARR); if(!r) return UND(); if(nargs) for(int i=0;i<o->n && !g_err && !g_oom;i++){ val ca[3]={o->vals[i],NUM(i),recv}; val m=call_function(args[0],ca,3); if(m.t==V_ARR&&m.o){ for(int j=0;j<m.o->n && !g_oom;j++) arr_push_val(r,m.o->vals[j]); } else arr_push_val(r,m); } val v=UND(); v.t=V_ARR; v.o=r; return v; }
    if (strcmp(name,"findIndex")==0){ if(nargs) for(int i=0;i<o->n && !g_err && !g_oom;i++){ val ca[3]={o->vals[i],NUM(i),recv}; if(truthy(call_function(args[0],ca,3))) return NUM(i); } return NUM(-1); }
    if (strcmp(name,"some")==0){ if(nargs) for(int i=0;i<o->n && !g_err && !g_oom;i++){ val ca[3]={o->vals[i],NUM(i),recv}; if(truthy(call_function(args[0],ca,3))) return BOOLV(1); } return BOOLV(0); }
    if (strcmp(name,"every")==0){ if(nargs) for(int i=0;i<o->n && !g_err && !g_oom;i++){ val ca[3]={o->vals[i],NUM(i),recv}; if(!truthy(call_function(args[0],ca,3))) return BOOLV(0); } return BOOLV(1); }
    if (strcmp(name,"reduce")==0){ if(!nargs) return UND(); int i=0; val acc; if(nargs>1) acc=args[1]; else { if(o->n==0){ rt_err("Reduce of empty array with no initial value"); return UND(); } acc=o->vals[0]; i=1; }   /* M692: empty + no init throws (per spec) */
        for(; i<o->n && !g_err && !g_oom; i++){ val ca[4]={acc,o->vals[i],NUM(i),recv}; acc=call_function(args[0],ca,4); } return acc; }
    if (strcmp(name,"reduceRight")==0){ if(!nargs) return UND(); int i=o->n-1; val acc; if(nargs>1) acc=args[1]; else { if(o->n==0){ rt_err("Reduce of empty array with no initial value"); return UND(); } acc=o->vals[o->n-1]; i=o->n-2; }
        for(; i>=0 && !g_err && !g_oom; i--){ val ca[4]={acc,o->vals[i],NUM(i),recv}; acc=call_function(args[0],ca,4); } return acc; }
    if (strcmp(name,"sort")==0){   /* in-place insertion sort: comparator if given, else string order (JS default) */
        int havecmp = (nargs && (args[0].t==V_FUN || args[0].t==V_NATIVE));
        int m=0; for(int i=0;i<o->n;i++) if(o->vals[i].t!=V_UNDEF) o->vals[m++]=o->vals[i];   /* M1781: undefined sorts to the END, and is NOT passed to the comparator (spec) */
        for(int i=m;i<o->n;i++) o->vals[i]=UND();
        for (int i=1; i<m && !g_err && !g_oom; i++){ val key=o->vals[i]; int j=i-1;
            while (j>=0){ int cmp;
                if (havecmp){ val ca[2]={o->vals[j],key}; double cd=to_num(call_function(args[0],ca,2)); cmp=cd>0?1:(cd<0?-1:0); }   /* compare the SIGN of the comparator's result, not its int truncation: (a-b)/10 etc. must still sort */
                else cmp=strcmp(val_to_str(o->vals[j]), val_to_str(key));
                if (cmp>0){ o->vals[j+1]=o->vals[j]; j--; } else break; }
            o->vals[j+1]=key; }
        return recv; }
    /* ES2023 change-array-by-copy: return a NEW array, never mutate the receiver */
    if (strcmp(name,"with")==0){ int idx=nargs>0?(int)to_num(args[0]):0; if(idx<0)idx+=o->n;
        if(idx<0||idx>=o->n){ rt_err("Array.with index out of range"); return UND(); }
        obj*r=new_obj(V_ARR); if(!r) return UND();
        for(int i=0;i<o->n;i++) arr_push_val(r, i==idx ? (nargs>1?args[1]:UND()) : o->vals[i]);
        val v=UND(); v.t=V_ARR; v.o=r; return v; }
    if (strcmp(name,"toReversed")==0){ obj*r=new_obj(V_ARR); if(!r) return UND();
        for(int i=o->n-1;i>=0;i--) arr_push_val(r,o->vals[i]);
        val v=UND(); v.t=V_ARR; v.o=r; return v; }
    if (strcmp(name,"toSorted")==0){ obj*r=new_obj(V_ARR); if(!r) return UND();
        for(int i=0;i<o->n;i++) arr_push_val(r,o->vals[i]);   /* copy, then sort the copy in place (mirrors `sort`) */
        int havecmp = (nargs && (args[0].t==V_FUN || args[0].t==V_NATIVE));
        int m=0; for(int i=0;i<r->n;i++) if(r->vals[i].t!=V_UNDEF) r->vals[m++]=r->vals[i];   /* M1781: undefined to the end (mirrors sort) */
        for(int i=m;i<r->n;i++) r->vals[i]=UND();
        for (int i=1; i<m && !g_err && !g_oom; i++){ val key=r->vals[i]; int j=i-1;
            while (j>=0){ int cmp;
                if (havecmp){ val ca[2]={r->vals[j],key}; double cd=to_num(call_function(args[0],ca,2)); cmp=cd>0?1:(cd<0?-1:0); }   /* compare the SIGN of the comparator's result, not its int truncation: (a-b)/10 etc. must still sort */
                else cmp=strcmp(val_to_str(r->vals[j]), val_to_str(key));
                if (cmp>0){ r->vals[j+1]=r->vals[j]; j--; } else break; }
            r->vals[j+1]=key; }
        val v=UND(); v.t=V_ARR; v.o=r; return v; }
    if (strcmp(name,"toSpliced")==0){   /* toSpliced(start, delCount, ...items) -> new array */
        int start=nargs>0?(int)to_num(args[0]):0; if(start<0){ start+=o->n; if(start<0)start=0; } if(start>o->n)start=o->n;
        int del=nargs>1?(int)to_num(args[1]):(o->n-start); if(del<0)del=0; if(del>o->n-start)del=o->n-start;
        obj*r=new_obj(V_ARR); if(!r) return UND();
        for(int i=0;i<start;i++) arr_push_val(r,o->vals[i]);        /* head */
        for(int i=2;i<nargs;i++) arr_push_val(r,args[i]);           /* inserted items */
        for(int i=start+del;i<o->n;i++) arr_push_val(r,o->vals[i]); /* tail */
        val v=UND(); v.t=V_ARR; v.o=r; return v; }
    if (strcmp(name,"hasOwnProperty")==0){ const char *k=nargs?val_to_str(args[0]):""; if(strcmp(k,"length")==0) return BOOLV(1); int i=nargs?(int)to_num(args[0]):-1; return BOOLV(i>=0 && i<o->n); }   /* arr.hasOwnProperty(index|"length") (M274) */
    if (strcmp(name,"toLocaleString")==0) return STRV(val_to_str(recv));   /* = join, like toString (M279) */
    if (strcmp(name,"keys")==0){ obj*r=new_obj(V_ARR); if(!r)return UND(); for(int i=0;i<o->n && !g_oom;i++) arr_push_val(r,NUM(i)); val v=UND();v.t=V_ARR;v.o=r;return v; }   /* eager-array iterators (work with for-of) (M276) */
    if (strcmp(name,"values")==0){ obj*r=new_obj(V_ARR); if(!r)return UND(); for(int i=0;i<o->n && !g_oom;i++) arr_push_val(r,o->vals[i]); val v=UND();v.t=V_ARR;v.o=r;return v; }
    if (strcmp(name,"entries")==0){ obj*r=new_obj(V_ARR); if(!r)return UND(); for(int i=0;i<o->n && !g_oom;i++){ obj*p=new_obj(V_ARR); if(!p){g_oom=1;break;} arr_push_val(p,NUM(i)); arr_push_val(p,o->vals[i]); val pv=UND();pv.t=V_ARR;pv.o=p; arr_push_val(r,pv); } val v=UND();v.t=V_ARR;v.o=r;return v; }
    if (strcmp(name,"copyWithin")==0){   /* copyWithin(target, start, end): copy the slice [start,end) over target, in place (M272) */
        int len=o->n; int tgt=nargs>0?(int)to_num(args[0]):0, st=nargs>1?(int)to_num(args[1]):0, en=nargs>2?(int)to_num(args[2]):len;
        if(tgt<0)tgt+=len; if(st<0)st+=len; if(en<0)en+=len;
        if(tgt<0)tgt=0; if(st<0)st=0; if(en<0)en=0; if(tgt>len)tgt=len; if(st>len)st=len; if(en>len)en=len;
        int count=en-st; if(count>len-tgt)count=len-tgt;
        if(count>0) memmove(&o->vals[tgt], &o->vals[st], (size_t)count*sizeof(val));   /* memmove handles overlapping ranges */
        return recv; }
    rt_err("unknown array method"); return UND();
}

/* ---- Promise (M679): a SYNCHRONOUS-resolution model ----
 * The OS has no event loop and its I/O (fetch/network) is blocking, so this models
 * Promises with eager, synchronous settlement: an executor runs immediately, resolve/
 * reject settle the promise on the spot, and .then/await read an ALREADY-settled state.
 * This faithfully covers the common synchronous-fetch patterns (await fetch(); .then
 * chains; Promise.all over settled work) without a microtask queue. The cost: there is
 * no genuine concurrency — a promise that is never resolved synchronously stays pending
 * forever (its .then never fires), and ordering across "parallel" awaits is sequential.
 *
 * A promise carries the captured `this` (the promise) to its resolve/reject as a BOUND
 * argument (V_BOUND vals[2]), since native fns receive no self pointer. State + value
 * live in obj->promise_state / promise_val. */
/* State+value live in the promise's own vals[] (vals[0]=NUM(state), vals[1]=value)
 * so a Promise adds NO bytes to the shared obj struct (a long script allocates
 * millions of objs; +1 field there overflowed the 40MB arena). */
static int  pstate(obj *p){ return p && p->n>=1 ? (int)p->vals[0].num : 0; }
static val  pvalue(obj *p){ return p && p->n>=2 ? p->vals[1] : UND(); }
static void pset(obj *p, int st, val v){ if (p && p->n>=2){ p->vals[0]=NUM(st); p->vals[1]=v; } }
static val make_promise(int state, val v){
    obj *p=new_obj(V_PROMISE); if(!p){ g_oom=1; return UND(); }
    arr_push_val(p, NUM(state)); arr_push_val(p, v);   /* vals[0]=state, vals[1]=value */
    p->ctor_class=g_promise_ctor;                      /* ctor_class -> instanceof Promise */
    return obj_val(p);
}
/* Snapshot the in-flight throw/runtime-error as a catchable value, then clear it
 * (the rejection is now captured in a promise). Mirrors N_TRY's catch-binding. */
static val take_pending_error(void){
    val r = g_threw ? g_throwval : STRV(intern(g_errmsg[0]?g_errmsg:"error", (int)strlen(g_errmsg[0]?g_errmsg:"error")));
    g_err=0; g_threw=0; g_errmsg[0]=0; return r;
}
static val make_resolver(val (*fn)(val*,int), val carried);   /* fwd: assimilation builds resolve/reject for the thenable */
static val promise_reject_native(val *args, int nargs);       /* fwd: thenable's reject path */
static val promise_resolve_native(val *args, int nargs){
    if (nargs<1 || args[0].t!=V_OBJ || !args[0].o || args[0].o->kind!=V_PROMISE) return UND();
    obj *p=args[0].o; if (pstate(p)!=0) return UND();   /* settle at most once */
    val v = nargs>1 ? args[1] : UND();
    if (v.t==V_OBJ && v.o && v.o->kind==V_PROMISE) { pset(p, pstate(v.o), pvalue(v.o)); return UND(); }   /* adopt another promise's state */
    if (v.t==V_OBJ && v.o && obj_keyed(v.o)) {          /* thenable assimilation (M687): resolve(x) where x.then is callable */
        val thenfn;
        if (obj_get(v.o, "then", &thenfn) && is_callable(thenfn)) {
            val resolve=make_resolver(promise_resolve_native, obj_val(p));   /* the thenable drives our settle */
            val reject =make_resolver(promise_reject_native, obj_val(p));
            val ta[2]={resolve, reject};
            call_function_this(thenfn, v, ta, 2);        /* x.then(resolve, reject) — runs synchronously in this model */
            if (g_err && pstate(p)==0) pset(p, 2, take_pending_error());   /* then() itself threw -> reject */
            return UND();
        }
    }
    pset(p, 1, v);   /* a plain value (or a non-thenable object) */
    return UND();
}
static val promise_reject_native(val *args, int nargs){
    if (nargs<1 || args[0].t!=V_OBJ || !args[0].o || args[0].o->kind!=V_PROMISE) return UND();
    obj *p=args[0].o; if (pstate(p)!=0) return UND();
    pset(p, 2, nargs>1 ? args[1] : UND());
    return UND();
}
/* A native bound to a captured value: a V_BOUND whose [0]=native, [2]=carried, so
 * calling it invokes native([carried, ...callArgs]) (see call_bound). Used for
 * resolve/reject (carry the promise) and Response.text/json (carry the body) — natives
 * receive no self pointer, so this is how a "native closure" carries state. */
static val make_resolver(val (*fn)(val*,int), val carried){
    obj *nat=new_obj(V_NATIVE); if(!nat){ g_oom=1; return UND(); } nat->native=fn;
    obj *bf=new_obj(V_BOUND);  if(!bf){ g_oom=1; return UND(); }
    arr_push_val(bf, obj_val_native(nat));   /* [0] the native */
    arr_push_val(bf, UND());                 /* [1] this (unused) */
    arr_push_val(bf, carried);               /* [2] bound: the captured value */
    return obj_val(bf);
}
/* Run a then/catch handler on `arg`; settle the chained promise from its result
 * (a returned promise is adopted; a throw becomes a rejection). */
static val run_reaction(val cb, val arg){
    val r = call_function(cb, &arg, 1);
    if (g_err) return make_promise(2, take_pending_error());
    if (r.t==V_OBJ && r.o && r.o->kind==V_PROMISE) return r;   /* flatten a returned promise */
    return make_promise(1, r);
}
static val nat_promise(val *args, int nargs){
    val pv = make_promise(0, UND()); if (g_oom) return UND();   /* pending */
    obj *p = pv.o;
    val resolve=make_resolver(promise_resolve_native, obj_val(p));
    val reject =make_resolver(promise_reject_native, obj_val(p));
    if (g_oom) return UND();
    if (nargs>0 && is_callable(args[0])){
        val exa[2]={ resolve, reject };
        call_function(args[0], exa, 2);
        if (g_err){ val reason=take_pending_error(); if (pstate(p)==0) pset(p, 2, reason); }   /* executor threw -> reject */
    }
    return pv;
}
static val eval_promise_method(val recv, const char *m, val *args, int na){
    obj *p=recv.o; int st=pstate(p); val pv=pvalue(p);
    val onF = na>0?args[0]:UND(), onR = na>1?args[1]:UND();
    if (strcmp(m,"then")==0){
        if (st==1) return is_callable(onF) ? run_reaction(onF, pv) : make_promise(1, pv);
        if (st==2) return is_callable(onR) ? run_reaction(onR, pv) : make_promise(2, pv);   /* unhandled rejection propagates */
        return make_promise(0, UND());   /* still pending: chain stays pending */
    }
    if (strcmp(m,"catch")==0){
        if (st==2) return is_callable(onF) ? run_reaction(onF, pv) : make_promise(2, pv);
        return make_promise(st, pv);     /* fulfilled/pending pass straight through */
    }
    if (strcmp(m,"finally")==0){
        if (is_callable(onF)){ call_function(onF, 0, 0); if (g_err) return make_promise(2, take_pending_error()); }
        return make_promise(st, pv);     /* finally observes but does not alter the settlement */
    }
    rt_err("no such Promise method"); return UND();
}
static val nat_promise_resolve(val *args, int nargs){
    val v = nargs>0?args[0]:UND();
    if (v.t==V_OBJ && v.o && v.o->kind==V_PROMISE) return v;   /* Promise.resolve(promise) === that promise */
    val pv = make_promise(0, UND()); if (g_oom) return UND();
    val ra[2] = { pv, v };
    promise_resolve_native(ra, 2);   /* settle pv with v — fulfils a plain value, assimilates a thenable (M687) */
    return pv;
}
static val nat_promise_reject(val *args, int nargs){ return make_promise(2, nargs>0?args[0]:UND()); }
/* Promise.any: the first FULFILMENT wins; if all reject, reject with an AggregateError-
 * like object carrying every reason in .errors (M687). */
static val nat_promise_any(val *args, int nargs){
    obj *errs=new_obj(V_ARR); if(!errs){ g_oom=1; return UND(); }
    if (nargs>0 && args[0].t==V_ARR && args[0].o){
        obj *a=args[0].o;
        for (int i=0;i<a->n && !g_oom;i++){
            val e=a->vals[i];
            if (e.t==V_OBJ && e.o && e.o->kind==V_PROMISE){
                if (pstate(e.o)==1) return make_promise(1, pvalue(e.o));   /* first fulfilment */
                arr_push_val(errs, pstate(e.o)==2 ? pvalue(e.o) : UND());
            } else return make_promise(1, e);                              /* a non-promise fulfils immediately */
        }
    }
    obj *agg=new_obj(V_OBJ); if(!agg){ g_oom=1; return UND(); }            /* all rejected */
    obj_set(agg,"name",STRV("AggregateError")); obj_set(agg,"message",STRV("All promises were rejected"));
    val ev=UND(); ev.t=V_ARR; ev.o=errs; obj_set(agg,"errors",ev);
    return make_promise(2, obj_val(agg));
}
/* Promise.all: fulfilled with [values] once all settle; rejected with the FIRST
 * rejection reason. Non-promise array members are taken as already-fulfilled. */
static val nat_promise_all(val *args, int nargs){
    obj *out=new_obj(V_ARR); if(!out){ g_oom=1; return UND(); }
    if (nargs>0 && args[0].t==V_ARR && args[0].o){
        obj *a=args[0].o;
        for (int i=0;i<a->n && !g_oom;i++){
            val e=a->vals[i];
            if (e.t==V_OBJ && e.o && e.o->kind==V_PROMISE){
                if (pstate(e.o)==2) return make_promise(2, pvalue(e.o));   /* short-circuit on first rejection */
                arr_push_val(out, pstate(e.o)==1 ? pvalue(e.o) : UND());
            } else arr_push_val(out, e);
        }
    }
    val av=UND(); av.t=V_ARR; av.o=out; return make_promise(1, av);
}
static val nat_promise_race(val *args, int nargs){   /* first settled member wins (M1631): unlike any/all/allSettled just
                                                       * below, this used to look only at vals[0], so a still-pending
                                                       * first element permanently masked an already-settled second one
                                                       * -- e.g. Promise.race([pending, Promise.resolve(2)]) never
                                                       * resolved. Loop like its three siblings do. */
    if (nargs>0 && args[0].t==V_ARR && args[0].o){
        obj *a=args[0].o;
        for (int i=0;i<a->n;i++){
            val e=a->vals[i];
            if (e.t==V_OBJ && e.o && e.o->kind==V_PROMISE){
                if (pstate(e.o)!=0) return make_promise(pstate(e.o), pvalue(e.o));   /* first non-pending member */
            } else return make_promise(1, e);                                        /* a non-promise settles immediately */
        }
        if (a->n>0) { val e=a->vals[0]; return make_promise(pstate(e.o), pvalue(e.o)); }   /* all pending: mirror today's behavior */
    }
    return make_promise(0, UND());
}
static val nat_promise_allSettled(val *args, int nargs){
    obj *out=new_obj(V_ARR); if(!out){ g_oom=1; return UND(); }
    if (nargs>0 && args[0].t==V_ARR && args[0].o){
        obj *a=args[0].o;
        for (int i=0;i<a->n && !g_oom;i++){
            val e=a->vals[i]; obj *rec=new_obj(V_OBJ); if(!rec){ g_oom=1; break; }
            if (e.t==V_OBJ && e.o && e.o->kind==V_PROMISE && pstate(e.o)==2){ obj_set(rec,"status",STRV("rejected")); obj_set(rec,"reason",pvalue(e.o)); }
            else { val fv=(e.t==V_OBJ && e.o && e.o->kind==V_PROMISE)?pvalue(e.o):e; obj_set(rec,"status",STRV("fulfilled")); obj_set(rec,"value",fv); }
            arr_push_val(out, obj_val(rec));
        }
    }
    val av=UND(); av.t=V_ARR; av.o=out; return make_promise(1, av);
}

/* ---- fetch() (M684): JS-initiated HTTP, on the synchronous-resolution Promise model ----
 * The host/browser registers g_fetch (js_set_fetch) — a BLOCKING get that fills `out` with
 * the response body, sets *status to the HTTP status, and returns the body length (or <0 on
 * a network error). fetch(url) runs that get synchronously, then returns an already-settled
 * Promise<Response>, so both `fetch(url).then(r=>…)` and `await fetch(url)` work without an
 * event loop. Response = { status, ok, text():Promise<string>, json():Promise<any> } — text/
 * json carry the body via make_resolver's bound-arg trick. Like real fetch, an HTTP error
 * status (404…) still RESOLVES (ok=false); only a network failure rejects. */
static int (*g_fetch)(const char *url, const char *method, const char *ctype, const char *body, char *out, int outmax, int *status);   /* method/ctype/body NULL for a GET (M703) */
static val nat_json_parse(val *a, int n);   /* fwd: Response.json() parses the body */
static val nat_uint8array(val *args, int nargs);   /* fwd: r.bytes()/binary onmessage build a Uint8Array */
static val nat_arraybuffer(val *args, int nargs);   /* fwd: r.arrayBuffer()/binaryType "arraybuffer" */
static val fetch_text_native(val *args, int nargs){ return make_promise(1, nargs>0?args[0]:STRV("")); }   /* args[0]=bound body */
/* Response.arrayBuffer()/bytes() (M1860): resolve a Promise with a fresh copy of
 * the body bytes as an ArrayBuffer / Uint8Array. args[0] = the bound body
 * Uint8Array (built length-tracked in nat_fetch, so binary bodies with embedded
 * NULs survive — unlike the string body used by .text()/.json()). */
static val fetch_arraybuffer_native(val *args, int nargs){
    obj *src = (nargs>0 && args[0].t==V_OBJ) ? args[0].o : 0;
    int n = src ? src->nbytes : 0;
    val ab = nat_arraybuffer((val[]){ NUM(n) }, 1); if (g_oom) return UND();
    if (src && src->bytes) for (int i=0;i<n;i++) ab.o->bytes[i] = src->bytes[i];
    return make_promise(1, ab);
}
static val fetch_bytes_native(val *args, int nargs){
    obj *src = (nargs>0 && args[0].t==V_OBJ) ? args[0].o : 0;
    int n = src ? src->nbytes : 0;
    val u = nat_uint8array((val[]){ NUM(n) }, 1); if (g_oom) return UND();
    if (src && src->bytes) for (int i=0;i<n;i++) u.o->bytes[i] = src->bytes[i];
    return make_promise(1, u);
}
static val fetch_json_native(val *args, int nargs){
    val body = nargs>0 ? args[0] : STRV("");
    val parsed = nat_json_parse(&body, 1);
    if (g_err) return make_promise(2, take_pending_error());   /* malformed JSON -> rejected promise */
    return make_promise(1, parsed);
}
static val nat_fetch(val *args, int nargs){
    if (nargs<1 || args[0].t!=V_STR) return make_promise(2, STRV("fetch: a URL string is required"));
    if (!g_fetch) return make_promise(2, STRV("fetch: no network backing"));   /* not wired (e.g. host without js_set_fetch) */
    const char *method=0, *ctype=0, *reqbody=0;   /* fetch(url, {method, body, headers}) (M703) */
    if (nargs>1 && args[1].t==V_OBJ && args[1].o && obj_keyed(args[1].o)) {
        val mv, bv, hv;
        if (obj_get(args[1].o,"method",&mv) && mv.t==V_STR) method=mv.str;
        if (obj_get(args[1].o,"body",&bv) && bv.t!=V_UNDEF && bv.t!=V_NULL) { const char *bs=val_to_str(bv); reqbody=intern(bs,(int)strlen(bs)); }   /* intern: stable through the call */
        if (obj_get(args[1].o,"headers",&hv) && hv.t==V_OBJ && hv.o && obj_keyed(hv.o)) {
            val cv; if ((obj_get(hv.o,"Content-Type",&cv)||obj_get(hv.o,"content-type",&cv)) && cv.t==V_STR) ctype=cv.str;
        }
    }
    int cap = 131072; char *buf = aalloc(cap); if (!buf) { g_oom=1; return UND(); }
    int status = 0;
    int n = g_fetch(args[0].str, method, ctype, reqbody, buf, cap-1, &status);
    if (n < 0) return make_promise(2, STRV("fetch failed: network error"));   /* DNS/connect/read failure -> reject */
    if (n > cap-1) n = cap-1;
    buf[n] = 0;
    val body = STRV(buf);                                /* buf is arena-allocated -> persists for the run */
    val bytesv = nat_uint8array((val[]){ NUM(n) }, 1); if (g_oom) return UND();   /* length-tracked body copy */
    for (int i=0;i<n;i++) bytesv.o->bytes[i] = (unsigned char)buf[i];
    obj *resp = new_obj(V_OBJ); if (!resp) { g_oom=1; return UND(); }
    obj_set(resp, "status", NUM(status));
    obj_set(resp, "ok", BOOLV(status>=200 && status<300));
    obj_set(resp, "text", make_resolver(fetch_text_native, body));   /* r.text() -> Promise<body> */
    obj_set(resp, "json", make_resolver(fetch_json_native, body));   /* r.json() -> Promise<parsed> */
    obj_set(resp, "arrayBuffer", make_resolver(fetch_arraybuffer_native, bytesv));   /* r.arrayBuffer() -> Promise<ArrayBuffer> (M1860) */
    obj_set(resp, "bytes",       make_resolver(fetch_bytes_native, bytesv));         /* r.bytes() -> Promise<Uint8Array> (M1860) */
    return make_promise(1, obj_val(resp));
}

/* ---- EventSource (M-eventsource): a ONE-SHOT Server-Sent-Events snapshot ----
 * The engine has no event loop, so a real long-lived SSE stream can't be sustained.
 * Instead `new EventSource(url)` models the common dashboard pattern (es.onmessage =
 * apply(JSON.parse(e.data))) by delivering exactly the FIRST event: on construction
 * we enqueue a deferred task (like setTimeout(...,0)) that runs after the current
 * script — so the user's es.onmessage/.onopen are set first — then does a blocking
 * GET that the browser stops + closes after the first complete `\n\n`-terminated SSE
 * block, gathers its `data:` lines into one payload, and fires onmessage({data,...}).
 * Subsequent events never arrive (no loop), which is enough to populate the page once.
 *
 * The browser registers g_eventsource (js_set_eventsource): a blocking GET that reads
 * the first SSE event's data payload into out, sets *status, and returns the payload
 * length (or <0 on a network error -> onerror). NULL (host without a backing) -> the
 * task fires onerror. */
static int (*g_eventsource)(const char *url, char *out, int outmax, int *status);
static void (*g_canvas_op)(const char *id, int op, int a, int b, int c, int d, const char *color, const char *text, int lw);   /* M1796-M1801: canvas 2D op (0=fill 1=stroke 2=clear 3=line 4=fillText 5=arc; lw=lineWidth) */
static int js_enqueue_task(val fn);                  /* fwd: defined with the timer queue */
static val nat_json_parse(val *a, int n);            /* (already fwd-declared above; harmless) */

/* es.close(): mark the EventSource CLOSED so a not-yet-run deferred task becomes a
 * no-op. Carries the es object as the bound arg (args[0]). */
static val es_close_native(val *args, int nargs){
    if (nargs>0 && args[0].t==V_OBJ && args[0].o) obj_set(args[0].o, "readyState", NUM(2));   /* CLOSED */
    return UND();
}
/* The deferred task: args[0] = the carried es object. Runs after the script. */
static val es_deliver_native(val *args, int nargs){
    if (nargs<1 || args[0].t!=V_OBJ || !args[0].o) return UND();
    obj *es = args[0].o; val v;
    if (obj_get(es, "readyState", &v) && v.t==V_NUM && v.num==2) return UND();   /* closed before firing */
    val urlv; const char *url = (obj_get(es,"url",&urlv) && urlv.t==V_STR) ? urlv.str : 0;
    int ok = 0, status = 0; const char *payload = "";
    if (url && g_eventsource) {
        int cap = 131072; char *buf = aalloc(cap);
        if (!buf) { g_oom=1; return UND(); }
        int n = g_eventsource(url, buf, cap-1, &status);
        if (n >= 0) { if (n > cap-1) n = cap-1; buf[n]=0; payload = buf; ok = 1; }
    }
    if (ok) {
        obj_set(es, "readyState", NUM(1));                 /* OPEN */
        val cb;
        if (obj_get(es, "onopen", &cb) && is_callable(cb)) {   /* fire onopen first (standard order) */
            obj *ev=new_obj(V_OBJ); if(ev){ obj_set(ev,"type",STRV("open")); val a[1]={obj_val(ev)}; call_function_this(cb, obj_val(es), a, 1); }
            if (g_err) return UND();
        }
        if (obj_get(es, "onmessage", &cb) && is_callable(cb)) {
            obj *ev=new_obj(V_OBJ); if(!ev){ g_oom=1; return UND(); }
            obj_set(ev, "data", STRV(payload));            /* the joined data: payload (arena-stable) */
            obj_set(ev, "type", STRV("message"));
            obj_set(ev, "lastEventId", STRV(""));
            obj_set(ev, "origin", urlv);                   /* approximate origin = the URL */
            val a[1]={obj_val(ev)};
            call_function_this(cb, obj_val(es), a, 1);
        }
    } else {
        val cb;                                            /* network error (or no backing) -> onerror */
        if (obj_get(es, "onerror", &cb) && is_callable(cb)) {
            obj *ev=new_obj(V_OBJ); if(ev){ obj_set(ev,"type",STRV("error")); val a[1]={obj_val(ev)}; call_function_this(cb, obj_val(es), a, 1); }
        }
    }
    return UND();
}
/* new EventSource(url[, opts]): build the es object, then enqueue the deferred
 * first-event delivery. */
static val nat_eventsource(val *args, int nargs){
    obj *es = new_obj(V_OBJ); if(!es){ g_oom=1; return UND(); }
    const char *u = (nargs>0 && args[0].t==V_STR) ? args[0].str : "";
    obj_set(es, "url", STRV(u));
    obj_set(es, "readyState", NUM(0));                     /* CONNECTING */
    obj_set(es, "withCredentials", BOOLV(0));
    obj_set(es, "onmessage", UND());
    obj_set(es, "onerror", UND());
    obj_set(es, "onopen", UND());
    obj_set(es, "close", make_resolver(es_close_native, obj_val(es)));   /* es.close() carries es */
    /* CONNECTING/OPEN/CLOSED constants (real EventSource exposes these) */
    obj_set(es, "CONNECTING", NUM(0)); obj_set(es, "OPEN", NUM(1)); obj_set(es, "CLOSED", NUM(2));
    js_enqueue_task(make_resolver(es_deliver_native, obj_val(es)));   /* deferred: runs after the script */
    return obj_val(es);
}

/* ---- WebSocket (M1844): a one-shot request/reply model over a real WS connection ----
 *
 * Like EventSource, this is honest about the engine's single-threaded, run-to-
 * completion task model: it does NOT hold a socket open for arbitrary server
 * push over time. Instead `new WebSocket(url)` enqueues a deferred "pump" task
 * that (after the script sets its handlers) opens the connection + does the
 * RFC 6455 handshake, fires onopen, drains everything queued by ws.send()
 * (INCLUDING sends issued from inside onopen — the ubiquitous
 * `ws.onopen = () => ws.send(req)` idiom), reads the server's reply frames,
 * fires onmessage per reply, then closes and fires onclose. Perfect for
 * echo/RPC-style servers; a persistent server-push stream is out of scope.
 *
 * The browser registers two backings (js_set_websocket), mocked in the host
 * test: g_ws_open (connect + Upgrade handshake -> conn id, or -1) and
 * g_ws_exchange (on that id: send the queued messages, read the replies, close).
 * Splitting open from exchange is what lets onopen run — and queue more sends —
 * between connect and the first send.
 *
 * Both send and receive buffers use a length-prefixed record framing so binary
 * data (which contains NUL bytes) round-trips and each frame's TEXT/BIN type is
 * carried: each record is [opcode:1][len:4 little-endian][payload:len], opcode
 * WSREC_TEXT(1) or WSREC_BIN(2) — matching kernel/wsframe.h WS_OP_TEXT/BIN and
 * net.c ws_exchange (M1859). */
#define WSREC_TEXT 1
#define WSREC_BIN  2
static int (*g_ws_open)(const char *url, int *status);
static int (*g_ws_exchange)(int id, const char *sendbuf, int sendtot,
                            char *out, int outmax, int *nrecv);

/* ws.send(data): stringify + append to the ws's private send queue. A no-op once
 * the socket is CLOSING/CLOSED. args[0] = the carried ws (make_resolver), args[1]
 * = the JS-supplied data. */
static val ws_send_native(val *args, int nargs){
    if (nargs<1 || args[0].t!=V_OBJ || !args[0].o) return UND();
    obj *ws = args[0].o; val v;
    if (obj_get(ws,"readyState",&v) && v.t==V_NUM && (v.num==2 || v.num==3)) return UND();
    val q; if (!(obj_get(ws,"__sendq",&q) && q.t==V_ARR && q.o)) return UND();
    val d = nargs>1 ? args[1] : STRV("");
    if (d.t==V_OBJ && d.o && (d.o->kind==V_U8ARRAY || d.o->kind==V_ARRAYBUF)) {
        /* binary: snapshot the bytes NOW (real send() is synchronous; our flush is
         * deferred to the pump), so a later mutation of the array can't change what
         * was "sent". A fresh Uint8Array copy carries WSREC_BIN at marshal time. */
        int nb = d.o->nbytes;
        val cp = nat_uint8array((val[]){ NUM(nb) }, 1); if (g_oom) return UND();
        for (int j=0;j<nb;j++) cp.o->bytes[j] = d.o->bytes[j];
        arr_push_val(q.o, cp);
    } else {
        arr_push_val(q.o, STRV(val_to_str(d)));         /* text: stringify like real send() */
    }
    return UND();
}
/* ws.close(): mark it closed so a not-yet-run pump becomes a no-op (mirrors
 * es.close()). If already OPEN the pump owns the teardown; just flag it. */
static val ws_close_native(val *args, int nargs){
    if (nargs>0 && args[0].t==V_OBJ && args[0].o) obj_set(args[0].o, "__closed", BOOLV(1));
    return UND();
}
/* Fire ws.<name>(event{...}) if it is callable, with event.data = `data` when
 * `has_data`. Returns 0 and stops if a handler threw. */
static int ws_fire_data(obj *ws, const char *name, const char *type, val data, int has_data){
    val cb;
    if (!obj_get(ws, name, &cb) || !is_callable(cb)) return 1;
    obj *ev = new_obj(V_OBJ); if(!ev){ g_oom=1; return 0; }
    obj_set(ev, "type", STRV(type));
    if (has_data) obj_set(ev, "data", data);
    val a[1] = { obj_val(ev) };
    call_function_this(cb, obj_val(ws), a, 1);
    return !g_err;
}
/* Fire with a C-string data field (onmessage TEXT) or no data (onopen/onclose/
 * onerror pass NULL). Thin wrapper over ws_fire_data. */
static int ws_fire(obj *ws, const char *name, const char *type, const char *data){
    return ws_fire_data(ws, name, type, data ? STRV(data) : UND(), data ? 1 : 0);
}
/* The deferred pump: args[0] = the carried ws. Runs after the script drains. */
static val ws_pump_native(val *args, int nargs){
    if (nargs<1 || args[0].t!=V_OBJ || !args[0].o) return UND();
    obj *ws = args[0].o; val v;
    if (obj_get(ws,"__closed",&v) && truthy(v)) return UND();   /* closed before firing */
    val urlv; const char *url = (obj_get(ws,"url",&urlv) && urlv.t==V_STR) ? urlv.str : 0;
    int status = 0, id = (url && g_ws_open) ? g_ws_open(url, &status) : -1;
    if (id < 0) {                                               /* connect/handshake failed */
        obj_set(ws, "readyState", NUM(3));                     /* CLOSED */
        if (!ws_fire(ws, "onerror", "error", 0)) return UND();
        ws_fire(ws, "onclose", "close", 0);
        return UND();
    }
    obj_set(ws, "readyState", NUM(1));                         /* OPEN */
    if (!ws_fire(ws, "onopen", "open", 0)) return UND();       /* may ws.send() -> queues below */

    /* Marshal the (possibly onopen-extended) send queue into length-prefixed
     * records ([op][len:4 LE][payload]): binary items (Uint8Array/ArrayBuffer)
     * as WSREC_BIN with their raw bytes, everything else stringified as WSREC_TEXT. */
    int cap = 131072; char *sbuf = aalloc(cap); if(!sbuf){ g_oom=1; return UND(); }
    int soff = 0; val q;
    if (obj_get(ws,"__sendq",&q) && q.t==V_ARR && q.o) {
        for (int i=0;i<q.o->n;i++){
            val it = q.o->vals[i];
            const unsigned char *data; int L, op;
            if (it.t==V_OBJ && it.o && (it.o->kind==V_U8ARRAY || it.o->kind==V_ARRAYBUF)) {
                data = it.o->bytes; L = it.o->nbytes; op = WSREC_BIN;
            } else {
                const char *m = val_to_str(it); L=0; while(m[L]) L++;
                data = (const unsigned char *)m; op = WSREC_TEXT;
            }
            if (soff + 5 + L > cap) break;                     /* queue overflow -> drop the rest */
            sbuf[soff++] = (char)op;
            sbuf[soff++] = (char)(L & 0xff);          sbuf[soff++] = (char)((L >> 8) & 0xff);
            sbuf[soff++] = (char)((L >> 16) & 0xff);  sbuf[soff++] = (char)((L >> 24) & 0xff);
            for (int j=0;j<L;j++) sbuf[soff++] = (char)data[j];
        }
    }
    int rcap = 131072, nrecv = 0; char *rbuf = aalloc(rcap); if(!rbuf){ g_oom=1; return UND(); }
    int rn = g_ws_exchange ? g_ws_exchange(id, sbuf, soff, rbuf, rcap, &nrecv) : -1;
    if (rn < 0) {                                              /* exchange error mid-stream */
        obj_set(ws, "readyState", NUM(3));
        if (!ws_fire(ws, "onerror", "error", 0)) return UND();
        ws_fire(ws, "onclose", "close", 0);
        return UND();
    }
    if (rn > rcap) rn = rcap;
    /* fire onmessage per reply record; TEXT -> a string, BIN -> a Uint8Array
     * (or ArrayBuffer if ws.binaryType is "arraybuffer"). */
    val bt; int as_ab = (obj_get(ws,"binaryType",&bt) && bt.t==V_STR && strcmp(bt.str,"arraybuffer")==0);
    const unsigned char *p = (const unsigned char *)rbuf; int off = 0;
    for (int i=0; i<nrecv && off + 5 <= rn; i++){
        int op = p[off];
        int L = (int)((unsigned)p[off+1] | ((unsigned)p[off+2] << 8) |
                      ((unsigned)p[off+3] << 16) | ((unsigned)p[off+4] << 24));
        off += 5;
        if (L < 0 || off + L > rn) break;                      /* truncated record */
        if (op == WSREC_BIN) {
            val dv = as_ab ? nat_arraybuffer((val[]){ NUM(L) }, 1)
                           : nat_uint8array((val[]){ NUM(L) }, 1);
            if (g_oom) return UND();
            for (int j=0;j<L;j++) dv.o->bytes[j] = p[off+j];
            if (!ws_fire_data(ws, "onmessage", "message", dv, 1)) return UND();
        } else {
            char *s = aalloc(L+1); if(!s){ g_oom=1; return UND(); }  /* records aren't NUL-terminated */
            for (int j=0;j<L;j++) s[j] = (char)p[off+j]; s[L] = 0;
            if (!ws_fire_data(ws, "onmessage", "message", STRV(s), 1)) return UND();
        }
        off += L;
    }
    obj_set(ws, "readyState", NUM(3));                         /* CLOSED */
    ws_fire(ws, "onclose", "close", 0);
    return UND();
}
/* new WebSocket(url[, protocols]): build the ws object + its send queue, then
 * enqueue the deferred pump. */
static val nat_websocket(val *args, int nargs){
    obj *ws = new_obj(V_OBJ); if(!ws){ g_oom=1; return UND(); }
    const char *u = (nargs>0 && args[0].t==V_STR) ? args[0].str : "";
    obj_set(ws, "url", STRV(u));
    obj_set(ws, "readyState", NUM(0));                         /* CONNECTING */
    obj_set(ws, "bufferedAmount", NUM(0));
    obj_set(ws, "protocol", STRV(""));
    obj_set(ws, "binaryType", STRV("blob"));                   /* set to "arraybuffer" for ArrayBuffer onmessage data (M1859) */
    obj_set(ws, "onopen", UND()); obj_set(ws, "onmessage", UND());
    obj_set(ws, "onclose", UND()); obj_set(ws, "onerror", UND());
    obj *qa = new_obj(V_ARR); if(!qa){ g_oom=1; return UND(); }
    val qv = UND(); qv.t=V_ARR; qv.o=qa; obj_set(ws, "__sendq", qv);
    obj_set(ws, "send",  make_resolver(ws_send_native,  obj_val(ws)));
    obj_set(ws, "close", make_resolver(ws_close_native, obj_val(ws)));
    /* readyState constants (real WebSocket exposes these) */
    obj_set(ws, "CONNECTING", NUM(0)); obj_set(ws, "OPEN", NUM(1));
    obj_set(ws, "CLOSING", NUM(2)); obj_set(ws, "CLOSED", NUM(3));
    js_enqueue_task(make_resolver(ws_pump_native, obj_val(ws)));   /* deferred: runs after the script */
    return obj_val(ws);
}

/* ---- Map & Set ----
 * Both are V_OBJ values whose obj->kind is V_MAP/V_SET. A Map stores entries
 * interleaved in obj->vals as [k0,v0,k1,v1,…] (so n is 2*size); a Set stores
 * [v0,v1,…]. Lookup is a linear scan with `===` equality (val_equal). */
static val nat_map(val *args, int nargs){
    obj *o=new_obj(V_MAP); if(!o){g_oom=1;return UND();} o->n=0; val mv=obj_val(o);
    if (nargs>0 && args[0].t==V_ARR && args[0].o) {          /* new Map([[k,v],…]) */
        obj *src=args[0].o; for(int i=0;i<src->n && !g_oom;i++){ val e=src->vals[i]; if(e.t==V_ARR && e.o && e.o->n>=1){ val kv[2]={e.o->vals[0], e.o->n>1?e.o->vals[1]:UND()}; eval_map_method(mv,"set",kv,2); } }
    } else if (nargs>0 && args[0].t==V_OBJ && args[0].o && args[0].o->kind==V_MAP) {   /* new Map(otherMap) */
        obj *src=args[0].o; for(int i=0;i+1<src->n && !g_oom;i+=2){ val kv[2]={src->vals[i],src->vals[i+1]}; eval_map_method(mv,"set",kv,2); }
    }
    return mv;
}
static val nat_set(val *args, int nargs){
    obj *o=new_obj(V_SET); if(!o){g_oom=1;return UND();} o->n=0; val sv=obj_val(o);
    if (nargs>0) { val src=args[0];                          /* new Set([…]) / new Set("…") / new Set(otherSet) */
        if (src.t==V_ARR && src.o) for(int i=0;i<src.o->n && !g_oom;i++) eval_set_method(sv,"add",&src.o->vals[i],1);
        else if (src.t==V_OBJ && src.o && src.o->kind==V_SET) for(int i=0;i<src.o->n && !g_oom;i++) eval_set_method(sv,"add",&src.o->vals[i],1);
        else if (src.t==V_STR) { const char*s=src.str; for(int i=0;s[i]&&!g_oom;i++){ char*c=aalloc(2); if(c){c[0]=s[i];c[1]=0;} val cv=STRV(c?c:""); eval_set_method(sv,"add",&cv,1); } }
    }
    return sv;
}
/* new Proxy(target, handler) (M-proxy): build a V_PROXY obj with target in vals[0],
 * handler in vals[1] (n==2), val.t==V_OBJ. Both are EXPECTED to be objects; to never
 * crash on untrusted input, a non-object target/handler is replaced by a fresh empty
 * V_OBJ (so trap lookups simply miss and reads/writes pass through to an empty target).
 * Dispatched from N_NEW exactly like new Map()/new Set() (the ctor is a V_NATIVE). */
static val nat_proxy(val *args, int nargs){
    obj *p=new_obj(V_PROXY); if(!p){ g_oom=1; return UND(); }
    val target = (nargs>0 && args[0].t==V_OBJ && args[0].o) ? args[0] : obj_val(new_obj(V_OBJ));
    val handler= (nargs>1 && args[1].t==V_OBJ && args[1].o) ? args[1] : obj_val(new_obj(V_OBJ));
    if(g_oom){ return UND(); }                       /* the fallback new_obj()s may have OOM'd */
    p->vals[0]=target; p->vals[1]=handler; p->n=2;   /* cap is 4 from new_obj, so n=2 fits without realloc */
    return obj_val(p);
}

/* ---- ArrayBuffer + Uint8Array (M1850): binary byte stores ----
 * A minimal but real typed-array core: ArrayBuffer owns a zeroed byte block; a
 * Uint8Array is a view over one (kept in vals[0] for .buffer + liveness). Byte
 * indexing is via dedicated N_INDEX branches; methods via eval_u8_method. */
#define TA_MAX (1 << 24)                                 /* 16 MiB cap on a buffer */
static val nat_arraybuffer(val *args, int nargs){
    int n = (nargs > 0 && args[0].t == V_NUM) ? (int)args[0].num : 0;
    if (n < 0) n = 0; if (n > TA_MAX) n = TA_MAX;
    obj *o = new_obj(V_ARRAYBUF); if(!o){ g_oom=1; return UND(); }
    o->bytes = aalloc(n > 0 ? n : 1); if(!o->bytes){ g_oom=1; return UND(); }
    for (int i = 0; i < n; i++) o->bytes[i] = 0;
    o->nbytes = n;
    return obj_val(o);
}
/* new Uint8Array(n) | (array) | (uint8array) | (arraybuffer view) */
static val nat_uint8array(val *args, int nargs){
    obj *o = new_obj(V_U8ARRAY); if(!o){ g_oom=1; return UND(); }
    if (nargs > 0 && args[0].t == V_OBJ && args[0].o && args[0].o->kind == V_ARRAYBUF) {
        obj *ab = args[0].o;                             /* view over an existing buffer (shares bytes) */
        o->bytes = ab->bytes; o->nbytes = ab->nbytes;
        arr_push_val(o, args[0]);                        /* vals[0] = the buffer */
        return obj_val(o);
    }
    obj *src = 0; int n = 0;
    if (nargs > 0 && args[0].t == V_NUM) n = (int)args[0].num;
    else if (nargs > 0 && args[0].t == V_ARR && args[0].o) { src = args[0].o; n = src->n; }
    else if (nargs > 0 && args[0].t == V_OBJ && args[0].o && args[0].o->kind == V_U8ARRAY) { src = args[0].o; n = src->nbytes; }
    if (n < 0) n = 0; if (n > TA_MAX) n = TA_MAX;
    val abv = nat_arraybuffer((val[]){ NUM(n) }, 1); if (g_oom) return UND();
    o->bytes = abv.o->bytes; o->nbytes = n;
    arr_push_val(o, abv);                                /* vals[0] = backing ArrayBuffer */
    if (src) {
        if (src->kind == V_ARR) for (int i = 0; i < n; i++) o->bytes[i] = (uint8_t)((long)to_num(src->vals[i]) & 0xff);
        else                    for (int i = 0; i < n; i++) o->bytes[i] = src->bytes[i];
    }
    return obj_val(o);
}
/* Uint8Array.prototype methods (M1850): set/subarray/slice/fill/indexOf/join. */
static val eval_u8_method(val recv, const char *name, val *args, int nargs){
    obj *o = recv.o; if (!o) return UND();
    if (strcmp(name, "set") == 0) {                      /* u8.set(src[, offset]) */
        int off = (nargs > 1) ? (int)to_num(args[1]) : 0;
        if (nargs > 0 && args[0].t == V_ARR && args[0].o)
            for (int i = 0; i < args[0].o->n && off + i < o->nbytes; i++) o->bytes[off + i] = (uint8_t)((long)to_num(args[0].o->vals[i]) & 0xff);
        else if (nargs > 0 && args[0].t == V_OBJ && args[0].o && args[0].o->kind == V_U8ARRAY)
            for (int i = 0; i < args[0].o->nbytes && off + i < o->nbytes; i++) o->bytes[off + i] = args[0].o->bytes[i];
        return UND();
    }
    if (strcmp(name, "fill") == 0) {                     /* u8.fill(v[, start[, end]]) */
        uint8_t v = (uint8_t)((nargs > 0 ? (long)to_num(args[0]) : 0) & 0xff);
        int s = nargs > 1 ? (int)to_num(args[1]) : 0, e = nargs > 2 ? (int)to_num(args[2]) : o->nbytes;
        if (s < 0) s = 0; if (e > o->nbytes) e = o->nbytes;
        for (int i = s; i < e; i++) o->bytes[i] = v;
        return recv;
    }
    if (strcmp(name, "subarray") == 0 || strcmp(name, "slice") == 0) {   /* copy [begin,end) into a new Uint8Array */
        int b = nargs > 0 ? (int)to_num(args[0]) : 0, e = nargs > 1 ? (int)to_num(args[1]) : o->nbytes;
        if (b < 0) b += o->nbytes; if (e < 0) e += o->nbytes;
        if (b < 0) b = 0; if (e > o->nbytes) e = o->nbytes; if (e < b) e = b;
        int m = e - b;
        val nv = nat_uint8array((val[]){ NUM(m) }, 1); if (g_oom) return UND();
        for (int i = 0; i < m; i++) nv.o->bytes[i] = o->bytes[b + i];
        return nv;
    }
    if (strcmp(name, "indexOf") == 0) {
        uint8_t v = (uint8_t)((nargs > 0 ? (long)to_num(args[0]) : 0) & 0xff);
        for (int i = 0; i < o->nbytes; i++) if (o->bytes[i] == v) return NUM(i);
        return NUM(-1);
    }
    if (strcmp(name, "join") == 0) {
        const char *sep = (nargs > 0 && args[0].t == V_STR) ? args[0].str : ",";
        int sl = 0; while (sep[sl]) sl++;
        char *b = aalloc(o->nbytes * 4 + o->nbytes * sl + 1); if(!b){ g_oom=1; return UND(); }
        int p = 0;
        for (int i = 0; i < o->nbytes; i++) {
            if (i) { for (int k = 0; k < sl; k++) b[p++] = sep[k]; }
            int v = o->bytes[i]; char t[4]; int tl = 0; do { t[tl++] = (char)('0' + v % 10); v /= 10; } while (v);
            while (tl) b[p++] = t[--tl];
        }
        b[p] = 0; return STRV(b);
    }
    return UND();
}

/* ---- TextEncoder / TextDecoder (M1851): string <-> Uint8Array ----
 * The engine already stores strings as their raw (UTF-8) bytes, so encode/decode
 * are a straight byte copy — no codepoint math. A real, common consumer of the
 * M1850 typed arrays. */
static val nat_text_encode(val *a, int n){                    /* enc.encode(str) -> Uint8Array */
    const char *s = (n > 0) ? val_to_str(a[0]) : "";
    int len = 0; while (s[len]) len++;
    val uv = nat_uint8array((val[]){ NUM(len) }, 1); if (g_oom) return UND();
    for (int i = 0; i < len; i++) uv.o->bytes[i] = (uint8_t)s[i];
    return uv;
}
static val nat_text_decode(val *a, int n){                    /* dec.decode(u8) -> string */
    if (n < 1 || a[0].t != V_OBJ || !a[0].o || a[0].o->kind != V_U8ARRAY) return STRV("");
    obj *o = a[0].o;
    char *buf = aalloc(o->nbytes + 1); if (!buf) { g_oom = 1; return UND(); }
    for (int i = 0; i < o->nbytes; i++) buf[i] = (char)o->bytes[i];
    buf[o->nbytes] = 0;
    return STRV(buf);
}
static val nat_textencoder(val *a, int n){ (void)a; (void)n;
    obj *o = new_obj(V_OBJ); if (!o) { g_oom = 1; return UND(); }
    obj *e = new_obj(V_NATIVE); if (e) { e->native = nat_text_encode; obj_set(o, "encode", obj_val_native(e)); }
    obj_set(o, "encoding", STRV("utf-8")); return obj_val(o);
}
static val nat_textdecoder(val *a, int n){ (void)a; (void)n;
    obj *o = new_obj(V_OBJ); if (!o) { g_oom = 1; return UND(); }
    obj *d = new_obj(V_NATIVE); if (d) { d->native = nat_text_decode; obj_set(o, "decode", obj_val_native(d)); }
    obj_set(o, "encoding", STRV("utf-8")); return obj_val(o);
}

static val eval_map_method(val recv, const char *name, val *args, int nargs) {
    obj *o=recv.o; val k = nargs>0?args[0]:UND();
    if (strcmp(name,"set")==0){ val v=nargs>1?args[1]:UND();
        for(int i=0;i+1<o->n;i+=2) if(same_value_zero(o->vals[i],k)){ o->vals[i+1]=v; return recv; }
        arr_push_val(o,k); arr_push_val(o,v); return recv; }                  /* returns the map (chainable) */
    if (strcmp(name,"get")==0){ for(int i=0;i+1<o->n;i+=2) if(same_value_zero(o->vals[i],k)) return o->vals[i+1]; return UND(); }
    if (strcmp(name,"has")==0){ for(int i=0;i+1<o->n;i+=2) if(same_value_zero(o->vals[i],k)) return BOOLV(1); return BOOLV(0); }
    if (strcmp(name,"delete")==0){ for(int i=0;i+1<o->n;i+=2) if(same_value_zero(o->vals[i],k)){ for(int j=i;j+2<o->n;j++) o->vals[j]=o->vals[j+2]; o->n-=2; return BOOLV(1); } return BOOLV(0); }
    if (strcmp(name,"clear")==0){ o->n=0; return UND(); }
    if (strcmp(name,"forEach")==0){ if(nargs<1) return UND(); for(int i=0;i+1<o->n && !g_err && !g_oom;i+=2){ val cb[3]={o->vals[i+1],o->vals[i],recv}; call_function(args[0],cb,3); } return UND(); }
    if (strcmp(name,"keys")==0||strcmp(name,"values")==0){ obj *a=new_obj(V_ARR); if(!a){g_oom=1;return UND();} int off=(name[0]=='v')?1:0; for(int i=0;i+1<o->n && !g_oom;i+=2) arr_push_val(a,o->vals[i+off]); val r=UND(); r.t=V_ARR; r.o=a; return r; }
    if (strcmp(name,"entries")==0){ obj *a=new_obj(V_ARR); if(!a){g_oom=1;return UND();} for(int i=0;i+1<o->n && !g_oom;i+=2){ obj *pair=new_obj(V_ARR); if(!pair){g_oom=1;break;} arr_push_val(pair,o->vals[i]); arr_push_val(pair,o->vals[i+1]); val pv=UND();pv.t=V_ARR;pv.o=pair; arr_push_val(a,pv); } val r=UND(); r.t=V_ARR; r.o=a; return r; }
    rt_err("unknown Map method"); return UND();
}
static val eval_set_method(val recv, const char *name, val *args, int nargs) {
    obj *o=recv.o; val v = nargs>0?args[0]:UND();
    if (strcmp(name,"add")==0){ for(int i=0;i<o->n;i++) if(same_value_zero(o->vals[i],v)) return recv; arr_push_val(o,v); return recv; }
    if (strcmp(name,"has")==0){ for(int i=0;i<o->n;i++) if(same_value_zero(o->vals[i],v)) return BOOLV(1); return BOOLV(0); }
    if (strcmp(name,"delete")==0){ for(int i=0;i<o->n;i++) if(same_value_zero(o->vals[i],v)){ for(int j=i;j+1<o->n;j++) o->vals[j]=o->vals[j+1]; o->n--; return BOOLV(1); } return BOOLV(0); }
    if (strcmp(name,"clear")==0){ o->n=0; return UND(); }
    if (strcmp(name,"forEach")==0){ if(nargs<1) return UND(); for(int i=0;i<o->n && !g_err && !g_oom;i++){ val cb[3]={o->vals[i],o->vals[i],recv}; call_function(args[0],cb,3); } return UND(); }
    if (strcmp(name,"values")==0||strcmp(name,"keys")==0){ obj *a=new_obj(V_ARR); if(!a){g_oom=1;return UND();} for(int i=0;i<o->n && !g_oom;i++) arr_push_val(a,o->vals[i]); val r=UND(); r.t=V_ARR; r.o=a; return r; }
    /* entries() (M1621): Map/Array both already have it; Set fell through to
     * "unknown method" -- a real throw on ordinary iteration surface like
     * `for (const [v] of s.entries())`. Per spec a Set yields [value,value]
     * pairs (no separate key), mirroring Map's own entries case above. */
    if (strcmp(name,"entries")==0){ obj *a=new_obj(V_ARR); if(!a){g_oom=1;return UND();} for(int i=0;i<o->n && !g_oom;i++){ obj *pair=new_obj(V_ARR); if(!pair){g_oom=1;break;} arr_push_val(pair,o->vals[i]); arr_push_val(pair,o->vals[i]); val pv=UND();pv.t=V_ARR;pv.o=pair; arr_push_val(a,pv); } val r=UND(); r.t=V_ARR; r.o=a; return r; }
    rt_err("unknown Set method"); return UND();
}

/* URI encode/decode (pure string funcs; bounded output). `comp`=1 for the stricter
 * encodeURIComponent set, 0 for encodeURI (keeps reserved URI delimiters). */
static int uri_keep(int c, int comp){
    if((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')) return 1;
    if(c=='-'||c=='_'||c=='.'||c=='!'||c=='~'||c=='*'||c=='\''||c=='('||c==')') return 1;
    if(!comp && (c==';'||c==','||c=='/'||c=='?'||c==':'||c=='@'||c=='&'||c=='='||c=='+'||c=='$'||c=='#')) return 1;
    return 0;
}
static val uri_encode(val *args, int nargs, int comp){
    if(!nargs) return STRV("undefined"); const char *s=val_to_str(args[0]); int len=(int)strlen(s);
    char *r=aalloc((long)len*3+1); if(!r) return STRV(""); int p=0;
    for(int i=0;i<len;i++){ unsigned char c=s[i];
        if(uri_keep(c,comp)) r[p++]=c;
        else { const char *hex="0123456789ABCDEF"; r[p++]='%'; r[p++]=hex[c>>4]; r[p++]=hex[c&15]; } }
    r[p]=0; return STRV(r);
}
static int hexval(int c){ if(c>='0'&&c<='9')return c-'0'; if(c>='A'&&c<='F')return c-'A'+10; if(c>='a'&&c<='f')return c-'a'+10; return -1; }
static val uri_decode(val *args, int nargs){
    if(!nargs) return STRV("undefined"); const char *s=val_to_str(args[0]); int len=(int)strlen(s);
    char *r=aalloc(len+1); if(!r) return STRV(""); int p=0;
    for(int i=0;i<len;i++){ if(s[i]=='%' && i+2<len){ int h=hexval(s[i+1]),l=hexval(s[i+2]); if(h>=0&&l>=0){ r[p++]=(char)(h*16+l); i+=2; continue; } } r[p++]=s[i]; }
    r[p]=0; return STRV(r);
}
static val nat_encodeURIComponent(val *a,int n){ return uri_encode(a,n,1); }
static val nat_encodeURI(val *a,int n){ return uri_encode(a,n,0); }
static val nat_decodeURI(val *a,int n){ return uri_decode(a,n); }

/* native print/console.log */
static val native_print(val *args, int nargs) {
    for (int i=0;i<nargs;i++){ if(i) out_str(" "); out_str(val_to_str(args[i])); }
    out_str("\n"); return UND();
}

/* document.write(...): when a host (the browser) registers g_doc_write, the joined
 * argument string is handed to it (to splice into the page); otherwise it falls
 * back to the normal output stream so `js` at the shell still shows it. */
static void (*g_doc_write)(const char *s);
static val native_doc_write(val *args, int nargs) {
    for (int i=0;i<nargs;i++){ const char *s=val_to_str(args[i]); if(g_doc_write) g_doc_write(s); else out_str(s); }
    return UND();
}

/* ---- minimal DOM ---- document.getElementById(id) returns a V_ELEMENT handle
 * (the id lives in vals[0]); reading/writing its .textContent/.innerHTML calls
 * host callbacks the browser registers — it finds the element in the page source,
 * mutates it, and re-renders (mirroring the document.write / localStorage model). */
static int  (*g_dom_get)(const char *id, char *out, int max, int html);   /* 1 if found */
static void (*g_dom_set)(const char *id, const char *value, int html);
static int  (*g_dom_getattr)(const char *id, const char *attr, char *out, int max);   /* getAttribute; 1 if present */
static void (*g_dom_setattr)(const char *id, const char *attr, const char *val);      /* setAttribute */
/* querySelector(All): a handle can instead be keyed by a BYTE OFFSET into the
 * page source (an id-less match). These callbacks address such elements by
 * position, parallel to the id-keyed ones above (additive — id handles never
 * use them). g_dom_query runs the selector match and returns match offsets. */
static int  (*g_dom_get_at)(int off, char *out, int max, int html);
static void (*g_dom_set_at)(int off, const char *value, int html);                /* textContent/innerHTML/remove on a match */
static int  (*g_dom_getattr_at)(int off, const char *attr, char *out, int max);   /* getAttribute on a match */
static void (*g_dom_setattr_at)(int off, const char *attr, const char *val);      /* setAttribute on a match */
static int  (*g_dom_query)(const char *sel, int *offs, int max);   /* returns match count */
static int  (*g_dom_matches)(const char *id, const char *sel);     /* element.matches(sel) — id handle */
static int  (*g_dom_matches_at)(int off, const char *sel);         /* element.matches(sel) — position handle */
static int  (*g_dom_closest)(const char *id, const char *sel);     /* element.closest(sel) — id handle; returns an offset or -1 */
static int  (*g_dom_closest_at)(int off, const char *sel);         /* element.closest(sel) — position handle */
static void (*g_dom_rmattr)(const char *id, const char *attr);     /* removeAttribute — id handle */
static void (*g_dom_rmattr_at)(int off, const char *attr);         /* removeAttribute — position handle */
static int  (*g_dom_children)(const char *id, int *offs, int max);  /* element.children — id handle; fills child offsets */
static int  (*g_dom_children_at)(int off, int *offs, int max);      /* element.children — position handle */
static int  (*g_dom_parent)(const char *id);                        /* element.parentElement — id handle; returns an offset or -1 */
static int  (*g_dom_parent_at)(int off);                            /* element.parentElement — position handle */
static int  (*g_dom_sibling)(const char *id, int dir);              /* next/previousElementSibling (dir<0=prev) — id handle */
static int  (*g_dom_sibling_at)(int off, int dir);                  /* next/previousElementSibling — position handle */
static int  (*g_dom_tag)(const char *id, char *out, int max);       /* element.tagName — id handle */
static int  (*g_dom_tag_at)(int off, char *out, int max);           /* element.tagName — position handle */
#define QSA_MAX_JS 256   /* cap on querySelectorAll results (bounds the on-stack offs[]) */
static char g_location_url[256];   /* current page URL, snapshotted into window.location before page JS runs */
static val element_handle(const char *id) {
    obj *o = new_obj(V_ELEMENT); if(!o){ g_oom=1; return UND(); }
    arr_push_val(o, STRV(intern(id, (int)strlen(id))));   /* vals[0] = the element id */
    return obj_val(o);
}
/* A position-keyed element handle (a querySelector match with no id): vals[0]
 * is "" and vals[1] is the byte offset of its opening '<'. Reads/writes route
 * through the g_dom_*_at callbacks. Legacy id handles have n==1 (no vals[1]). */
static val element_handle_at(int off) {
    obj *o = new_obj(V_ELEMENT); if(!o){ g_oom=1; return UND(); }
    arr_push_val(o, STRV(intern("", 0)));   /* vals[0] = "" (no id) */
    arr_push_val(o, NUM(off));              /* vals[1] = byte offset of the opening '<' */
    return obj_val(o);
}
static val nat_getElementById(val *args, int nargs) {
    return element_handle(nargs ? val_to_str(args[0]) : "");
}
/* document.createElement(tag): a detached element — a plain object holding the
 * tag + (settable) textContent/innerHTML/className/id; appendChild builds its HTML
 * and splices it into a parent's content (via the innerHTML path). */
static val nat_createElement(val *args, int nargs) {
    obj *o = new_obj(V_OBJ); if(!o){ g_oom=1; return UND(); }
    const char *tag = nargs ? val_to_str(args[0]) : "div";
    obj_set(o, "tagName", STRV(intern(tag, (int)strlen(tag))));
    return obj_val(o);
}
/* querySelector: a pure "#id" selector keeps the fast id path (byte-identical);
 * tag/class/compound selectors run the host matcher and return the first match
 * as a position handle, or null if nothing matched. */
static val nat_querySelector(val *args, int nargs) {
    const char *sel = nargs ? val_to_str(args[0]) : "";
    if (sel[0]=='#' && sel[1]) {                       /* pure #id (no .class / compound) -> fast id handle */
        int plain=1; for (const char *p=sel+1; *p; p++) if(*p=='.'||*p=='#'||*p=='['||*p==' ') { plain=0; break; }
        if (plain) return element_handle(sel+1);
    }
    int offs[1]; int n = g_dom_query ? g_dom_query(sel, offs, 1) : 0;
    if (n > 0) return element_handle_at(offs[0]);
    val nv=UND(); nv.t=V_NULL; return nv;
}
/* Run a selector and collect every match as an array of position handles
 * (.length, [i], forEach, for-of all work via the generic array machinery). */
static val qsa_array(const char *sel) {
    obj *a = new_obj(V_ARR); if(!a){ g_oom=1; return UND(); }
    int offs[QSA_MAX_JS]; int n = g_dom_query ? g_dom_query(sel, offs, QSA_MAX_JS) : 0;
    for (int i=0; i<n && !g_oom; i++) arr_push_val(a, element_handle_at(offs[i]));
    val r=UND(); r.t=V_ARR; r.o=a; return r;
}
static val nat_querySelectorAll(val *args, int nargs) {
    return qsa_array(nargs ? val_to_str(args[0]) : "");
}
/* getElementsByTagName(name): the tag selector. */
static val nat_getElementsByTagName(val *args, int nargs) {
    return qsa_array(nargs ? val_to_str(args[0]) : "");
}
/* getElementsByClassName(name): the ".name" selector (built into a small buffer). */
static val nat_getElementsByClassName(val *args, int nargs) {
    char buf[64]; buf[0]='.'; const char *s = nargs ? val_to_str(args[0]) : "";
    int i=0; while (s[i] && i<62) { buf[i+1]=s[i]; i++; } buf[i+1]=0;
    return qsa_array(buf);
}
/* read/write a V_ELEMENT property; returns 1 if handled (so eval_member_get /
 * assignment can fall through for anything else). `set` NULL = read into out. */
static int dom_prop(obj *el, const char *name, const char *setval, char *out, int outmax) {
    const char *id = (el->n>0 && el->vals[0].t==V_STR) ? el->vals[0].str : "";
    int has_pos = (el->n>1 && el->vals[1].t==V_NUM);   /* a querySelector match keyed by byte offset */
    int off = has_pos ? (int)el->vals[1].num : 0;
    if (strcmp(name,"id")==0) {   /* position handles have no stored id -> read the id attribute from the source */
        if (!setval && out) {
            if (has_pos) { out[0]=0; if (g_dom_getattr_at) g_dom_getattr_at(off, "id", out, outmax); }
            else { int i=0; while(id[i]&&i<outmax-1){out[i]=id[i];i++;} out[i]=0; }
        }
        return 1;
    }
    if (strcmp(name,"tagName")==0 || strcmp(name,"nodeName")==0) {   /* the element's uppercased tag (read-only) */
        if (!setval && out) { out[0]=0; if (has_pos) { if(g_dom_tag_at) g_dom_tag_at(off, out, outmax); } else { if(g_dom_tag) g_dom_tag(id, out, outmax); } }
        return 1;
    }
    {   /* properties that directly reflect an HTML attribute (className -> class, the rest same-named),
         * so el.className/href/src/name/title/alt/placeholder/type read+write via getAttribute/setAttribute */
        const char *attr = 0;
        if (strcmp(name,"className")==0) attr = "class";
        else if (strcmp(name,"href")==0 || strcmp(name,"src")==0 || strcmp(name,"name")==0 ||
                 strcmp(name,"title")==0 || strcmp(name,"alt")==0 || strcmp(name,"placeholder")==0 ||
                 strcmp(name,"type")==0) attr = name;
        if (attr) {
            if (setval)   { if (has_pos) { if(g_dom_setattr_at) g_dom_setattr_at(off,attr,setval); } else { if(g_dom_setattr) g_dom_setattr(id,attr,setval); } }
            else if (out) { out[0]=0; if (has_pos) { if(g_dom_getattr_at) g_dom_getattr_at(off,attr,out,outmax); } else { if(g_dom_getattr) g_dom_getattr(id,attr,out,outmax); } }
            return 1;
        }
    }
    int kind = -1;                                   /* 0=textContent, 1=innerHTML, 2=input .value, 4=checkbox .checked */
    if (strcmp(name,"value")==0) kind = 2;
    else if (strcmp(name,"checked")==0) kind = 4;
    else if (strcmp(name,"innerHTML")==0) kind = 1;
    else if (strcmp(name,"textContent")==0 || strcmp(name,"innerText")==0) kind = 0;
    if (kind >= 0) {
        if (setval) {
            if (has_pos) { if(g_dom_set_at) g_dom_set_at(off, setval, kind); }
            else         { if(g_dom_set)    g_dom_set(id, setval, kind); }
        } else if (out) {
            out[0]=0;
            if (has_pos) { if(g_dom_get_at) g_dom_get_at(off, out, outmax, kind); }
            else         { if(g_dom_get)    g_dom_get(id, out, outmax, kind); }
        }
        return 1;
    }
    return 0;
}
/* Build the HTML for a createElement node (a plain object carrying tagName +
 * textContent/innerHTML/className/id properties), for appendChild. Bounded. */
static void build_child_html(obj *child, char *out, int max) {
    val v; const char *tag = "div";
    if (obj_get(child, "tagName", &v) && v.t==V_STR && v.str[0]) tag = v.str;
    int p = 0;
    out[p++]='<'; for (const char *t=tag; *t && p<max-2; t++) out[p++]=*t;
    if (obj_get(child, "id", &v) && v.t==V_STR && v.str[0]) {            /* id="..." (quotes stripped from the value) */
        const char *a=" id=\""; while(*a && p<max-2) out[p++]=*a++;
        for (const char *s=v.str; *s && p<max-2; s++) if(*s!='"' && *s!='<' && *s!='>') out[p++]=*s;
        if(p<max-2) out[p++]='"';
    }
    if (obj_get(child, "className", &v) && v.t==V_STR && v.str[0]) {     /* class="..." */
        const char *a=" class=\""; while(*a && p<max-2) out[p++]=*a++;
        for (const char *s=v.str; *s && p<max-2; s++) if(*s!='"' && *s!='<' && *s!='>') out[p++]=*s;
        if(p<max-2) out[p++]='"';
    }
    if (p<max-2) out[p++]='>';
    if (obj_get(child, "innerHTML", &v) && v.t==V_STR && v.str[0]) {     /* innerHTML: raw */
        for (const char *s=v.str; *s && p<max-2; s++) out[p++]=*s;
    } else if (obj_get(child, "textContent", &v) && v.t==V_STR) {       /* textContent: HTML-escaped */
        for (const char *s=v.str; *s && p<max-7; s++) {
            char c=*s;
            if(c=='<'){ memcpy(out+p,"&lt;",4); p+=4; }
            else if(c=='>'){ memcpy(out+p,"&gt;",4); p+=4; }
            else if(c=='&'){ memcpy(out+p,"&amp;",5); p+=5; }
            else out[p++]=c;
        }
    }
    if (p<max-3) { out[p++]='<'; out[p++]='/'; for(const char *t=tag; *t && p<max-2; t++) out[p++]=*t; if(p<max-1) out[p++]='>'; }
    out[p]=0;
}
/* methods on a DOM element handle (recv.o->kind==V_ELEMENT): getAttribute(name). */
/* M1796: canvas 2D context methods. Context state lives as normal properties on the
 * object — __cid (the canvas element's id) + fillStyle (a CSS colour string, settable
 * via `ctx.fillStyle=...` like any property). fillRect(x,y,w,h) routes to the browser's
 * g_canvas_fillrect (id -> writable image slot -> fill), drawn during the page's load
 * script and blitted at render. Unknown methods no-op (forward-compatible). */
static val eval_canvas_method(val recv, const char *name, val *args, int nargs) {
    obj *c = recv.o; if (!c || !g_canvas_op) return UND();
    val cidv; const char *cid = (obj_get(c, "__cid", &cidv) && cidv.t == V_STR) ? cidv.str : "";
    int a = nargs > 0 ? (int)to_num(args[0]) : 0, b = nargs > 1 ? (int)to_num(args[1]) : 0;
    int cc = nargs > 2 ? (int)to_num(args[2]) : 0, d = nargs > 3 ? (int)to_num(args[3]) : 0;
    int lw = 1; { val lwv; if (obj_get(c,"lineWidth",&lwv) && lwv.t==V_NUM && lwv.num>=1) lw=(int)lwv.num; }   /* M1801: stroke width for line/strokeRect/arc */
    if (strcmp(name, "moveTo") == 0) { obj_set(c, "__cx", NUM(a)); obj_set(c, "__cy", NUM(b)); return UND(); }
    if (strcmp(name, "lineTo") == 0) {   /* draw current-point -> (a,b) in strokeStyle, then move the current point */
        val cxv, cyv, ssv;
        int cx = (obj_get(c,"__cx",&cxv) && cxv.t==V_NUM) ? (int)cxv.num : 0;
        int cy = (obj_get(c,"__cy",&cyv) && cyv.t==V_NUM) ? (int)cyv.num : 0;
        const char *ss = (obj_get(c,"strokeStyle",&ssv) && ssv.t==V_STR) ? ssv.str : "#000000";
        g_canvas_op(cid, 3, cx, cy, a, b, ss, 0, lw);
        obj_set(c, "__cx", NUM(a)); obj_set(c, "__cy", NUM(b)); return UND();
    }
    if (strcmp(name, "fillText") == 0) { /* M1798: fillText(text, x, y) — x=args[1], y=baseline args[2], colour = fillStyle */
        const char *txt = nargs > 0 ? val_to_str(args[0]) : "";
        int tx = nargs > 1 ? (int)to_num(args[1]) : 0, ty = nargs > 2 ? (int)to_num(args[2]) : 0;
        val fsv; const char *fs=(obj_get(c,"fillStyle",&fsv)&&fsv.t==V_STR)?fsv.str:"#000000";
        g_canvas_op(cid, 4, tx, ty, 0, 0, fs, txt, 1); return UND();
    }
    if (strcmp(name, "fillRect") == 0)   { val fsv; const char *fs=(obj_get(c,"fillStyle",  &fsv)&&fsv.t==V_STR)?fsv.str:"#000000"; g_canvas_op(cid, 0, a, b, cc, d, fs, 0, 1); return UND(); }
    if (strcmp(name, "strokeRect") == 0) { val ssv; const char *ss=(obj_get(c,"strokeStyle",&ssv)&&ssv.t==V_STR)?ssv.str:"#000000"; g_canvas_op(cid, 1, a, b, cc, d, ss, 0, lw); return UND(); }
    if (strcmp(name, "clearRect") == 0)  { g_canvas_op(cid, 2, a, b, cc, d, "", 0, 1); return UND(); }
    if (strcmp(name, "arc") == 0)        { val ssv; const char *ss=(obj_get(c,"strokeStyle",&ssv)&&ssv.t==V_STR)?ssv.str:"#000000"; g_canvas_op(cid, 5, a, b, cc, 0, ss, 0, lw); return UND(); }   /* M1799: arc(x,y,r,...) -> full-circle outline */
    /* beginPath / closePath / stroke / fill / save / restore: accepted no-ops (lineTo draws immediately) */
    return UND();
}
static val eval_element_method(val recv, const char *name, val *args, int nargs) {
    obj *el = recv.o;
    const char *id = (el->n > 0 && el->vals[0].t == V_STR) ? el->vals[0].str : "";
    int has_pos = (el->n > 1 && el->vals[1].t == V_NUM);   /* a querySelector match keyed by byte offset */
    int off = has_pos ? (int)el->vals[1].num : 0;
    if (strcmp(name, "remove") == 0) {   /* element.remove(): splice the whole element out (id or position handle) */
        if (has_pos) { if (g_dom_set_at) g_dom_set_at(off, "", 3); }
        else         { if (g_dom_set)    g_dom_set(id, "", 3); }
        return UND();
    }
    if (strcmp(name, "hasAttribute") == 0) {
        const char *aname = nargs ? val_to_str(args[0]) : "";
        static char hb[256]; hb[0] = 0;
        int got = has_pos ? (g_dom_getattr_at && g_dom_getattr_at(off, aname, hb, (int)sizeof(hb)))
                          : (g_dom_getattr    && g_dom_getattr(id, aname, hb, (int)sizeof(hb)));
        return BOOLV(got);
    }
    if (strcmp(name, "getAttribute") == 0) {
        const char *aname = nargs ? val_to_str(args[0]) : "";
        static char ab[2048]; ab[0] = 0;
        int got = has_pos ? (g_dom_getattr_at && g_dom_getattr_at(off, aname, ab, (int)sizeof(ab)))
                          : (g_dom_getattr    && g_dom_getattr(id, aname, ab, (int)sizeof(ab)));
        if (got) return STRV(intern(ab, (int)strlen(ab)));
        val nv = UND(); nv.t = V_NULL; return nv;   /* missing attribute -> null, per the DOM */
    }
    if (strcmp(name, "getContext") == 0) {   /* M1796: canvas.getContext('2d') -> a 2D context bound to this canvas's id */
        obj *c = new_obj(V_CANVASCTX);
        if (!c) { g_oom = 1; return UND(); }
        obj_set(c, "__cid", STRV(intern(id, (int)strlen(id))));   /* the canvas element's id (drawing routes id -> slot) */
        obj_set(c, "fillStyle", STRV("#000000"));                 /* CSS default; ctx.fillStyle='...' overrides as a normal property */
        obj_set(c, "strokeStyle", STRV("#000000"));               /* M1797: strokeRect/lineTo colour */
        obj_set(c, "lineWidth", NUM(1));                          /* M1801: stroke width */
        val v = UND(); v.t = V_OBJ; v.o = c; return v;
    }
    if (strcmp(name, "setAttribute") == 0) {
        char an[128];   /* copy the name BEFORE the 2nd val_to_str (it may share a static buffer) */
        { const char *s = nargs > 0 ? val_to_str(args[0]) : ""; int i = 0; while (s[i] && i < 127) { an[i] = s[i]; i++; } an[i] = 0; }
        const char *av = nargs > 1 ? val_to_str(args[1]) : "";
        if (has_pos) { if (g_dom_setattr_at) g_dom_setattr_at(off, an, av); }
        else         { if (g_dom_setattr)    g_dom_setattr(id, an, av); }
        return UND();
    }
    if (strcmp(name, "addEventListener") == 0) {   /* addEventListener("click", fn) -> the same registry as el.onclick=fn (type already bare, e.g. "click") */
        const char *type = nargs > 0 ? val_to_str(args[0]) : "";
        if (nargs > 1 && (args[1].t==V_FUN || args[1].t==V_NATIVE || (args[1].t==V_OBJ && args[1].o && args[1].o->kind==V_BOUND)))
            register_handler(el, type, args[1]);
        return UND();
    }
    if (strcmp(name, "removeEventListener") == 0) {   /* v1: unregister by type (listener-fn identity isn't tracked) */
        unregister_handler(el, nargs > 0 ? val_to_str(args[0]) : "");
        return UND();
    }
    if (strcmp(name, "matches") == 0) {   /* does this element match the CSS selector? (event-delegation idiom e.target.matches('.x')) */
        const char *sel = nargs ? val_to_str(args[0]) : "";
        int m = has_pos ? (g_dom_matches_at && g_dom_matches_at(off, sel))
                        : (g_dom_matches    && g_dom_matches(id, sel));
        return BOOLV(m);
    }
    if (strcmp(name, "closest") == 0) {   /* nearest self-or-ancestor matching the selector, or null */
        const char *sel = nargs ? val_to_str(args[0]) : "";
        int r = has_pos ? (g_dom_closest_at ? g_dom_closest_at(off, sel) : -1)
                        : (g_dom_closest    ? g_dom_closest(id, sel)     : -1);
        if (r >= 0) return element_handle_at(r);
        val nv = UND(); nv.t = V_NULL; return nv;
    }
    if (strcmp(name, "appendChild") == 0) {   /* append a createElement node: parent.innerHTML += built-child-HTML (reuses the innerHTML splice) */
        if (nargs < 1 || args[0].t != V_OBJ || !args[0].o) return UND();
        static char chtml[4096]; build_child_html(args[0].o, chtml, sizeof(chtml));
        static char cur[4096]; cur[0]=0;
        if (has_pos) { if(g_dom_get_at) g_dom_get_at(off, cur, (int)sizeof(cur), 1); }
        else         { if(g_dom_get)    g_dom_get(id, cur, (int)sizeof(cur), 1); }
        static char nh[8192]; int p=0;
        for (int i=0; cur[i] && p<8000; i++) nh[p++]=cur[i];
        for (int i=0; chtml[i] && p<8180; i++) nh[p++]=chtml[i];
        nh[p]=0;
        if (has_pos) { if(g_dom_set_at) g_dom_set_at(off, nh, 1); }
        else         { if(g_dom_set)    g_dom_set(id, nh, 1); }
        return args[0];   /* DOM appendChild returns the appended child */
    }
    if (strcmp(name, "removeAttribute") == 0) {   /* splice " attr=…" out of the opening tag (completes get/set/has/remove) */
        const char *aname = nargs ? val_to_str(args[0]) : "";
        if (has_pos) { if (g_dom_rmattr_at) g_dom_rmattr_at(off, aname); }
        else         { if (g_dom_rmattr)    g_dom_rmattr(id, aname); }
        return UND();
    }
    rt_err("no such element method"); return UND();
}
/* el.classList -> a V_CLASSLIST handle carrying the same id/offset addressing as
 * the element; its add/remove/toggle/contains read & rewrite the class attribute
 * via the existing get/setAttribute callbacks (works for id + position handles). */
static val classlist_handle(obj *el) {
    obj *o = new_obj(V_CLASSLIST); if(!o){ g_oom=1; return UND(); }
    arr_push_val(o, (el->n>0 && el->vals[0].t==V_STR) ? el->vals[0] : STRV(intern("",0)));   /* vals[0] = id or "" */
    if (el->n>1 && el->vals[1].t==V_NUM) arr_push_val(o, el->vals[1]);                        /* vals[1] = byte offset (position handle) */
    return obj_val(o);
}
/* el.children -> an array of position handles for the direct child elements. */
static val children_array(obj *el) {
    obj *a = new_obj(V_ARR); if(!a){ g_oom=1; return UND(); }
    const char *id = (el->n>0 && el->vals[0].t==V_STR) ? el->vals[0].str : "";
    int has_pos = (el->n>1 && el->vals[1].t==V_NUM); int off = has_pos ? (int)el->vals[1].num : 0;
    int offs[QSA_MAX_JS];
    int n = has_pos ? (g_dom_children_at ? g_dom_children_at(off, offs, QSA_MAX_JS) : 0)
                    : (g_dom_children    ? g_dom_children(id, offs, QSA_MAX_JS)     : 0);
    for (int i=0; i<n && !g_oom; i++) arr_push_val(a, element_handle_at(offs[i]));
    val r=UND(); r.t=V_ARR; r.o=a; return r;
}
/* el.parentElement / el.parentNode -> a position handle for the enclosing element, or null. */
static val parent_handle(obj *el) {
    const char *id = (el->n>0 && el->vals[0].t==V_STR) ? el->vals[0].str : "";
    int has_pos = (el->n>1 && el->vals[1].t==V_NUM); int off = has_pos ? (int)el->vals[1].num : 0;
    int r = has_pos ? (g_dom_parent_at ? g_dom_parent_at(off) : -1) : (g_dom_parent ? g_dom_parent(id) : -1);
    if (r >= 0) return element_handle_at(r);
    val nv=UND(); nv.t=V_NULL; return nv;
}
/* el.nextElementSibling (dir>0) / previousElementSibling (dir<0) -> a position handle or null. */
static val sibling_handle(obj *el, int dir) {
    const char *id = (el->n>0 && el->vals[0].t==V_STR) ? el->vals[0].str : "";
    int has_pos = (el->n>1 && el->vals[1].t==V_NUM); int off = has_pos ? (int)el->vals[1].num : 0;
    int r = has_pos ? (g_dom_sibling_at ? g_dom_sibling_at(off, dir) : -1) : (g_dom_sibling ? g_dom_sibling(id, dir) : -1);
    if (r >= 0) return element_handle_at(r);
    val nv=UND(); nv.t=V_NULL; return nv;
}
/* whitespace-delimited token membership */
static int cl_has(const char *s, const char *tok) {
    int tl=0; while(tok[tl]) tl++; if(!tl) return 0;
    for(int i=0; s[i]; ){
        while(s[i]==' '||s[i]=='\t') i++;
        int st=i; while(s[i]&&s[i]!=' '&&s[i]!='\t') i++;
        if(i-st==tl){ int m=0; while(m<tl && s[st+m]==tok[m]) m++; if(m==tl) return 1; }
    }
    return 0;
}
static val eval_classlist_method(val recv, const char *name, val *args, int nargs) {
    obj *el = recv.o;
    const char *id = (el->n>0 && el->vals[0].t==V_STR) ? el->vals[0].str : "";
    int has_pos = (el->n>1 && el->vals[1].t==V_NUM);
    int off = has_pos ? (int)el->vals[1].num : 0;
    static char clbuf[2048]; clbuf[0]=0;
    if (has_pos) { if(g_dom_getattr_at) g_dom_getattr_at(off,"class",clbuf,(int)sizeof(clbuf)); }
    else         { if(g_dom_getattr)    g_dom_getattr(id,"class",clbuf,(int)sizeof(clbuf)); }
    const char *tok = nargs ? val_to_str(args[0]) : "";
    int present = cl_has(clbuf, tok);
    if (strcmp(name,"contains")==0) return BOOLV(present);
    int want;                                            /* 1 = ensure present (add), 0 = ensure absent (remove) */
    if (strcmp(name,"add")==0) want = 1;
    else if (strcmp(name,"remove")==0) want = 0;
    else if (strcmp(name,"toggle")==0) want = (nargs > 1) ? truthy(args[1]) : !present;   /* toggle(name, force): force the state if a 2nd arg is given */
    else { rt_err("no such classList method"); return UND(); }
    if (want != present && tok[0]) {                     /* rebuild + write only when it changes (and the token is non-empty) */
        static char nb[2100]; int o=0;
        if (want) {                                      /* add: append the token */
            int i=0; while(clbuf[i] && o<2090) nb[o++]=clbuf[i++];
            if (o>0 && nb[o-1]!=' ') nb[o++]=' ';
            for (int t=0; tok[t] && o<2098; t++) nb[o++]=tok[t];
            nb[o]=0;
        } else {                                         /* remove: copy every token except `tok` */
            int tl=0; while(tok[tl]) tl++;
            int i=0; while(clbuf[i]){
                while(clbuf[i]==' '||clbuf[i]=='\t') i++;
                int st=i; while(clbuf[i]&&clbuf[i]!=' '&&clbuf[i]!='\t') i++;
                int len=i-st; if(len==0) continue;
                int istok=0; if(len==tl){ int m=0; while(m<tl && clbuf[st+m]==tok[m]) m++; if(m==tl) istok=1; }
                if(!istok){ if(o>0 && o<2098) nb[o++]=' '; for(int k=0;k<len && o<2098;k++) nb[o++]=clbuf[st+k]; }
            }
            nb[o]=0;
        }
        if (has_pos) { if(g_dom_setattr_at) g_dom_setattr_at(off,"class",nb); }
        else         { if(g_dom_setattr)    g_dom_setattr(id,"class",nb); }
    }
    if (strcmp(name,"toggle")==0) return BOOLV(want);
    return UND();
}

/* localStorage: a host-provided key->value (string) store that survives the
 * per-run arena reset, so page click-handlers can accumulate state (a counter). */
static const char *(*g_ls_get)(const char *key);
static void        (*g_ls_set)(const char *key, const char *val);
static void        (*g_ls_remove)(const char *key);
static void        (*g_ls_clear)(void);
static val native_ls_getItem(val *args, int nargs) {
    if (!g_ls_get || !nargs) { val v=UND(); v.t=V_NULL; return v; }
    const char *r = g_ls_get(val_to_str(args[0]));
    if (!r) { val v=UND(); v.t=V_NULL; return v; }
    return STRV(intern(r, (int)strlen(r)));               /* copy out (host buffer may change) */
}
static val native_ls_setItem(val *args, int nargs) {
    if (g_ls_set && nargs>=2) g_ls_set(val_to_str(args[0]), val_to_str(args[1]));
    return UND();
}
static val native_ls_removeItem(val *args, int nargs) {
    if (g_ls_remove && nargs) g_ls_remove(val_to_str(args[0]));
    return UND();
}
static val native_ls_clear(val *args, int nargs) {
    (void)args; (void)nargs;
    if (g_ls_clear) g_ls_clear();
    return UND();
}

/* Date() -> current wall-clock as "YYYY-MM-DD HH:MM:SS" (a useful subset of the
 * real Date). Reads the CMOS RTC directly (kernel); a fixed string on the host. */
/* Days since the Unix epoch (1970-01-01) for a proleptic-Gregorian y/m(1-12)/d.
 * Howard Hinnant's branch-free algorithm; exact, no FPU. Used by Date.getTime/getDay. */
static int64_t days_from_civil(int64_t y, int64_t m, int64_t d){
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y-399) / 400;
    int64_t yoe = y - era*400;
    int64_t doy = (153*(m + (m > 2 ? -3 : 9)) + 2)/5 + d-1;
    int64_t doe = yoe*365 + yoe/4 - yoe/100 + doy;
    return era*146097 + doe - 719468;
}
/* inverse of days_from_civil: epoch day count -> year / month(1-12) / day. */
static void civil_from_days(int64_t z, int64_t *yr, int64_t *mo, int64_t *dy){
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    int64_t doe = z - era*146097;                                   /* [0, 146096] */
    int64_t yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;  /* [0, 399]   */
    int64_t y = yoe + era*400;
    int64_t doy = doe - (365*yoe + yoe/4 - yoe/100);                /* [0, 365]   */
    int64_t mp = (5*doy + 2)/153;                                   /* [0, 11]    */
    int64_t d = doy - (153*mp+2)/5 + 1;                             /* [1, 31]    */
    int64_t m = mp < 10 ? mp+3 : mp-9;                              /* [1, 12]    */
    *yr = y + (m <= 2); *mo = m; *dy = d;
}
/* Normalize possibly out-of-range y/mo(1-based)/d/h/mi/s in place: fold the
 * month into [1,12] carrying the year, then round-trip the whole instant
 * through the civil calendar so day/hour/min/sec overflow settles too --
 * exactly what new Date(y,mo,d,...)'s multi-arg form already does inline
 * below. Shared with the setters (M1625): they used to store the raw field
 * with no normalization at all, so e.g. setDate(0) (the "last day of the
 * previous month" idiom the constructor's own comment advertises) left a
 * bare day=0 that days_from_civil -- which itself needs a pre-normalized
 * month, not just a tolerant day -- then fed straight into getTime/getDay. */
static void date_normalize(int64_t *y, int64_t *mo, int64_t *d, int64_t *h, int64_t *mi, int64_t *s){
    int64_t mo0 = *mo-1; *y += mo0/12; mo0 %= 12; if(mo0<0){ mo0+=12; (*y)--; } *mo=mo0+1;
    int64_t secs = days_from_civil(*y,*mo,*d)*86400 + *h*3600 + *mi*60 + *s;
    int64_t nd = secs/86400, tod = secs - nd*86400; if(tod<0){ tod+=86400; nd--; }
    civil_from_days(nd,y,mo,d); *h=tod/3600; *mi=(tod%3600)/60; *s=tod%60;
}
/* Overwrite Date field `field` (0=y,1=mo,2=d,3=h,4=mi,5=s) with `newval`, then
 * renormalize + write all six vals[] back -- the setter counterpart of the
 * constructor's inline normalization above (M1625). */
static void date_set_field(obj *o, int field, int64_t newval){
    int64_t y=(int64_t)o->vals[0].num, mo=(int64_t)o->vals[1].num, d=(int64_t)o->vals[2].num,
            h=(int64_t)o->vals[3].num, mi=(int64_t)o->vals[4].num, s=(int64_t)o->vals[5].num;
    int64_t *f[6] = {&y,&mo,&d,&h,&mi,&s};
    *f[field] = newval;
    date_normalize(&y,&mo,&d,&h,&mi,&s);
    o->vals[0]=NUM(y); o->vals[1]=NUM(mo); o->vals[2]=NUM(d); o->vals[3]=NUM(h); o->vals[4]=NUM(mi); o->vals[5]=NUM(s);
}
/* Parse an ISO-8601-ish date string "YYYY-MM-DD[THH:MM:SS[.sss]][Z]" into components
 * (the trailing fractional seconds + Z/timezone are accepted but ignored — this engine
 * treats everything as UTC). Returns 1 on a usable parse, 0 otherwise. (M695) */
static int parse_iso(const char *s, int64_t *yr, int64_t *mo, int64_t *dy, int64_t *hh, int64_t *mi, int64_t *se){
    while(*s==' '||*s=='\t') s++;
    if(!(*s>='0'&&*s<='9')) return 0;
    int64_t Y=0,M=1,D=1,H=0,Mi=0,S=0;
    while(*s>='0'&&*s<='9'){ Y=Y*10+(*s-'0'); s++; }
    if(*s=='-'){ s++; if(!(*s>='0'&&*s<='9')) return 0; M=0; while(*s>='0'&&*s<='9'){ M=M*10+(*s-'0'); s++; }
        if(*s=='-'){ s++; if(!(*s>='0'&&*s<='9')) return 0; D=0; while(*s>='0'&&*s<='9'){ D=D*10+(*s-'0'); s++; } } }
    if(*s=='T'||*s==' '){ s++; if(*s>='0'&&*s<='9'){ H=0; while(*s>='0'&&*s<='9'){ H=H*10+(*s-'0'); s++; }
        if(*s==':'){ s++; Mi=0; while(*s>='0'&&*s<='9'){ Mi=Mi*10+(*s-'0'); s++; }
            if(*s==':'){ s++; S=0; while(*s>='0'&&*s<='9'){ S=S*10+(*s-'0'); s++; } } } } }
    *yr=Y; *mo=M; *dy=D; *hh=H; *mi=Mi; *se=S; return 1;
}
/* Date() / new Date() -> a V_DATE object holding [year,month,day,hour,min,sec] in
 * vals[0..5] (read from the RTC at construction). Methods via eval_date_method;
 * val_to_str renders "YYYY-MM-DD HH:MM:SS" so it still prints/coerces like before. */
static val nat_date(val *a, int n){
    int64_t y,mo,d,h,mi,s;
    if(n==1 && a[0].t==V_NUM){              /* new Date(epochMs) — honor the timestamp, don't snapshot "now" */
        int64_t ms=a[0].num, secs=ms/1000; if(ms<0 && ms%1000) secs--;     /* floor toward -inf */
        int64_t days=secs/86400, tod=secs-days*86400; if(tod<0){ tod+=86400; days--; }
        civil_from_days(days,&y,&mo,&d); h=tod/3600; mi=(tod%3600)/60; s=tod%60;
    } else if(n>=2){                        /* new Date(year, month0, day[, h, m, s]) */
        y=(int64_t)to_num(a[0]); mo=(int64_t)to_num(a[1])+1;               /* JS month arg is 0-based */
        d = n>2?(int64_t)to_num(a[2]):1; h = n>3?(int64_t)to_num(a[3]):0;
        mi= n>4?(int64_t)to_num(a[4]):0; s = n>5?(int64_t)to_num(a[5]):0;
        /* Normalize out-of-range parts like JS: fold the month into [1,12] (carrying
         * the year — new Date(y,12,…) is next January), then round-trip the whole
         * instant through the civil calendar so day/hour/min/sec overflow settles —
         * incl. day 0 = the last day of the previous month, so the common
         * `new Date(y, m+1, 0)` "last day of month" idiom and date arithmetic work. */
        date_normalize(&y,&mo,&d,&h,&mi,&s);
    } else if(n>=1 && a[0].t==V_STR && parse_iso(a[0].str,&y,&mo,&d,&h,&mi,&s)){
        /* new Date("YYYY-MM-DD[THH:MM:SS]") — parse the ISO string (M695) */
    } else {                                /* new Date() / an unparseable string — current time */
#ifndef JS_HOSTTEST
    struct rtc_time t; rtc_now(&t); y=t.year; mo=t.month; d=t.day; h=t.hour; mi=t.min; s=t.sec;
#else
    y=2026; mo=6; d=13; h=12; mi=0; s=0;
#endif
    }
    obj *o=new_obj(V_DATE); if(!o){ g_oom=1; return UND(); }
    arr_push_val(o,NUM(y)); arr_push_val(o,NUM(mo)); arr_push_val(o,NUM(d)); arr_push_val(o,NUM(h)); arr_push_val(o,NUM(mi)); arr_push_val(o,NUM(s));
    return obj_val(o);
}
static val nat_date_now(val *a, int n){ (void)a; (void)n; int y,mo,d,h,mi,s;   /* Date.now() -> current epoch ms */
#ifndef JS_HOSTTEST
    struct rtc_time t; rtc_now(&t); y=t.year; mo=t.month; d=t.day; h=t.hour; mi=t.min; s=t.sec;
#else
    y=2026; mo=6; d=13; h=12; mi=0; s=0;
#endif
    int64_t z=days_from_civil(y,mo,d); return NUM((z*86400 + (int64_t)h*3600 + mi*60 + s)*1000); }
static val nat_date_parse(val *a, int n){   /* Date.parse("YYYY-MM-DD…") -> epoch ms (M695) */
    int64_t y,mo,d,h,mi,s;
    if(n>=1 && a[0].t==V_STR && parse_iso(a[0].str,&y,&mo,&d,&h,&mi,&s))
        return NUM((days_from_civil(y,mo,d)*86400 + h*3600 + mi*60 + s)*1000);
    return NUM(0);   /* unparseable -> 0 (this engine has no NaN) */
}
static val eval_date_method(val recv, const char *name, val *args, int nargs){
    (void)args;(void)nargs; obj *o=recv.o; if(!o || o->n<6) return UND();
    if(strcmp(name,"getFullYear")==0) return o->vals[0];
    if(strcmp(name,"getMonth")==0)    return NUM(o->vals[1].num-1);   /* JS months are 0-based */
    if(strcmp(name,"getDate")==0)     return o->vals[2];
    if(strcmp(name,"getHours")==0)    return o->vals[3];
    if(strcmp(name,"getMinutes")==0)  return o->vals[4];
    if(strcmp(name,"getSeconds")==0)  return o->vals[5];
    if(strcmp(name,"getMilliseconds")==0) return NUM(0);   /* RTC is second-resolution */
    if(strcmp(name,"getDay")==0){ int64_t z=days_from_civil(o->vals[0].num,o->vals[1].num,o->vals[2].num); int64_t wd=(z+4)%7; if(wd<0)wd+=7; return NUM(wd); }   /* 0=Sun..6=Sat (epoch day 0 was a Thursday) */
    if(strcmp(name,"getTime")==0||strcmp(name,"valueOf")==0){ int64_t z=days_from_civil(o->vals[0].num,o->vals[1].num,o->vals[2].num); int64_t secs=z*86400 + o->vals[3].num*3600 + o->vals[4].num*60 + o->vals[5].num; return NUM(secs*1000); }   /* epoch ms */
    /* setters store the field AND renormalize (M1625; used to skip normalization
     * entirely, so e.g. setDate(0) left a bare day=0 instead of rolling back a
     * month like the constructor's own out-of-range handling does), then return
     * the new epoch ms */
    if(strcmp(name,"setFullYear")==0){ if(nargs) date_set_field(o,0,(int64_t)to_num(args[0]));   return eval_date_method(recv,"getTime",0,0); }
    if(strcmp(name,"setMonth")==0)   { if(nargs) date_set_field(o,1,(int64_t)to_num(args[0])+1); return eval_date_method(recv,"getTime",0,0); }   /* arg is 0-based */
    if(strcmp(name,"setDate")==0)    { if(nargs) date_set_field(o,2,(int64_t)to_num(args[0]));   return eval_date_method(recv,"getTime",0,0); }
    if(strcmp(name,"setHours")==0)   { if(nargs) date_set_field(o,3,(int64_t)to_num(args[0]));   return eval_date_method(recv,"getTime",0,0); }
    if(strcmp(name,"setMinutes")==0) { if(nargs) date_set_field(o,4,(int64_t)to_num(args[0]));   return eval_date_method(recv,"getTime",0,0); }
    if(strcmp(name,"setSeconds")==0) { if(nargs) date_set_field(o,5,(int64_t)to_num(args[0]));   return eval_date_method(recv,"getTime",0,0); }
    if(strcmp(name,"setTime")==0){   /* set the whole instant from epoch ms, mirroring the new Date(ms) decomposition (M1815) */
        int64_t ms = nargs ? (int64_t)to_num(args[0]) : 0;
        int64_t secs=ms/1000; if(ms<0 && ms%1000) secs--;                          /* floor toward -inf */
        int64_t days=secs/86400, tod=secs-days*86400; if(tod<0){ tod+=86400; days--; }
        int64_t Y,Mo,D; civil_from_days(days,&Y,&Mo,&D);
        int64_t H=tod/3600, Mi=(tod%3600)/60, S=tod%60;
        o->vals[0]=NUM(Y); o->vals[1]=NUM(Mo); o->vals[2]=NUM(D);
        o->vals[3]=NUM(H); o->vals[4]=NUM(Mi); o->vals[5]=NUM(S);
        return eval_date_method(recv,"getTime",0,0);
    }
    if(strcmp(name,"getTimezoneOffset")==0) return NUM(0);   /* this engine has no timezone — always UTC (M1815) */
    if(strcmp(name,"toString")==0) return STRV(val_to_str(recv));
    if(strcmp(name,"toISOString")==0||strcmp(name,"toJSON")==0){   /* "YYYY-MM-DDTHH:MM:SS.000Z" (UTC; ms always 000 at second resolution) */
        char *b=aalloc(28); if(!b) return STRV("");
        int64_t Y=o->vals[0].num,Mo=o->vals[1].num,D=o->vals[2].num,H=o->vals[3].num,Mi=o->vals[4].num,S=o->vals[5].num; int p=0;
        b[p++]='0'+(int)((Y/1000)%10); b[p++]='0'+(int)((Y/100)%10); b[p++]='0'+(int)((Y/10)%10); b[p++]='0'+(int)(Y%10); b[p++]='-';
        b[p++]='0'+(int)((Mo/10)%10); b[p++]='0'+(int)(Mo%10); b[p++]='-';
        b[p++]='0'+(int)((D/10)%10); b[p++]='0'+(int)(D%10); b[p++]='T';
        b[p++]='0'+(int)((H/10)%10); b[p++]='0'+(int)(H%10); b[p++]=':';
        b[p++]='0'+(int)((Mi/10)%10); b[p++]='0'+(int)(Mi%10); b[p++]=':';
        b[p++]='0'+(int)((S/10)%10); b[p++]='0'+(int)(S%10);
        b[p++]='.'; b[p++]='0'; b[p++]='0'; b[p++]='0'; b[p++]='Z'; b[p]=0;
        return STRV(b);
    }
    /* no timezone in this engine, so the UTC getters equal the local ones: getUTCX -> getX */
    if(name[0]=='g'&&name[1]=='e'&&name[2]=='t'&&name[3]=='U'&&name[4]=='T'&&name[5]=='C'){ char ln[28]; ln[0]='g';ln[1]='e';ln[2]='t'; int j=3; for(const char*p=name+6;*p&&j<27;p++) ln[j++]=*p; ln[j]=0; return eval_date_method(recv,ln,args,nargs); }
    /* the toLocale / toDate / toTime / toUTC string variants: render a valid date string (no locale/zone formatting) */
    if(strcmp(name,"toLocaleString")==0||strcmp(name,"toLocaleDateString")==0||strcmp(name,"toLocaleTimeString")==0||
       strcmp(name,"toDateString")==0||strcmp(name,"toTimeString")==0||strcmp(name,"toUTCString")==0||strcmp(name,"toGMTString")==0)
        return STRV(val_to_str(recv));
    rt_err("unknown Date method"); return UND();
}

/* ---- Math (real IEEE-754 doubles; js.o is built with SSE — M906) ---- */
static val nat_abs(val *a, int n){ return NUM(n ? js_fabs(to_num(a[0])) : 0); }
static val nat_max(val *a, int n){ if(!n) return NUM(-JS_INF); double m=to_num(a[0]); for(int i=1;i<n;i++){double v=to_num(a[i]); if(js_isnan(v)) return NUM(JS_NAN); if(v>m)m=v;} return NUM(m); }   /* Math.max() = -Infinity */
static val nat_min(val *a, int n){ if(!n) return NUM(JS_INF);  double m=to_num(a[0]); for(int i=1;i<n;i++){double v=to_num(a[i]); if(js_isnan(v)) return NUM(JS_NAN); if(v<m)m=v;} return NUM(m); }   /* Math.min() = +Infinity */
static val nat_floor(val *a, int n){ return NUM(n?js_floor(to_num(a[0])):0); }
static val nat_ceil (val *a, int n){ return NUM(n?js_ceil (to_num(a[0])):0); }
static val nat_round(val *a, int n){ return NUM(n?js_round(to_num(a[0])):0); }
static val nat_trunc(val *a, int n){ return NUM(n?js_trunc(to_num(a[0])):0); }
static val nat_sqrt(val *a, int n){ double x=n?to_num(a[0]):0; return NUM(js_sqrt(x)); }   /* hardware sqrtsd — exact for perfect squares */
static val nat_hypot(val *a, int n){ double s=0; for(int i=0;i<n;i++){ double v=to_num(a[i]); s+=v*v; } return NUM(js_sqrt(s)); }
static val nat_log2(val *a, int n){ return NUM(js_ln(n?to_num(a[0]):0)/0.69314718055994530942); }   /* real log2; exact for powers of two */
static val nat_cbrt(val *a, int n){ return NUM(js_cbrt(n?to_num(a[0]):0)); }
static val nat_clz32(val *a, int n){ uint32_t u=(uint32_t)to_i32(n?to_num(a[0]):0); if(!u) return NUM(32); int c=0; while(!(u&0x80000000u)){ u<<=1; c++; } return NUM(c); }   /* count leading zeros in 32 bits */
static val nat_imul(val *a, int n){ int32_t x=to_i32(n>0?to_num(a[0]):0), y=to_i32(n>1?to_num(a[1]):0); return NUM((double)(int32_t)((uint32_t)x*(uint32_t)y)); }   /* 32-bit integer multiply */
static val nat_pow(val *a, int n){ double b=n>0?to_num(a[0]):0, e=n>1?to_num(a[1]):0; return NUM(js_pow(b,e)); }
static val nat_log(val *a, int n){ return NUM(js_ln(n?to_num(a[0]):0)); }                          /* natural log */
static val nat_exp(val *a, int n){ return NUM(js_exp(n?to_num(a[0]):0)); }
static val nat_log10(val *a, int n){ return NUM(js_ln(n?to_num(a[0]):0)/2.302585092994046); }       /* log base 10 */
static val nat_sin(val *a, int n){ return NUM(js_sin(n?to_num(a[0]):0)); }
static val nat_cos(val *a, int n){ return NUM(js_cos(n?to_num(a[0]):0)); }
static val nat_tan(val *a, int n){ return NUM(js_tan(n?to_num(a[0]):0)); }
static val nat_atan(val *a, int n){ return NUM(js_atan(n?to_num(a[0]):0)); }
static val nat_atan2(val *a, int n){ return NUM(js_atan2(n>0?to_num(a[0]):0, n>1?to_num(a[1]):0)); }
static val nat_asin(val *a, int n){ return NUM(js_asin(n?to_num(a[0]):0)); }
static val nat_acos(val *a, int n){ return NUM(js_acos(n?to_num(a[0]):0)); }
static val nat_sinh(val *a, int n){ return NUM(js_sinh(n?to_num(a[0]):0)); }
static val nat_cosh(val *a, int n){ return NUM(js_cosh(n?to_num(a[0]):0)); }
static val nat_tanh(val *a, int n){ return NUM(js_tanh(n?to_num(a[0]):0)); }
/* Math.random(): the no-arg form returns a real double in [0,1) (standard, M917 — the
 * engine has IEEE doubles since M906; M918). Math.random(n) is a kept non-standard extension
 * returning a uniform integer in [0,n) (a die/range). xorshift64, lazily seeded from the
 * CPU's cycle counter so it varies across boots. */
static uint64_t js_rng_state = 0;
static val nat_random(val *a, int n){
    if(js_rng_state == 0){ uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); js_rng_state = (((uint64_t)hi<<32) | lo) | 1ull; }
    js_rng_state ^= js_rng_state << 13; js_rng_state ^= js_rng_state >> 7; js_rng_state ^= js_rng_state << 17;
    uint64_t r = js_rng_state;
    if(n >= 1){ int64_t m = (int64_t)to_num(a[0]); return NUM(m > 0 ? (double)(int64_t)(r % (uint64_t)m) : 0.0); }   /* Math.random(n) -> [0,n) integer (non-standard extension, kept) */
    return NUM((double)(r >> 11) * (1.0 / 9007199254740992.0));                                   /* Math.random() -> [0,1) real (53-bit; 2^53) */
}

/* ---- global functions ---- */
static val nat_parseInt(val *a, int n){                                            /* parseInt(str, radix), with 0x detection */
    if(!n) return NUM(0);
    const char *s=val_to_str(a[0]); int radix=(n>1)?(int)to_num(a[1]):0;
    while(*s==' '||*s=='\t'||*s=='\n'||*s=='\r'||*s=='\f'||*s=='\v') s++;   /* M1782: skip all JS whitespace (was missing \f/\v; to_num + parseFloat already do) */
    int neg=0; if(*s=='+') s++; else if(*s=='-'){ neg=1; s++; }
    if((radix==0||radix==16) && s[0]=='0' && (s[1]=='x'||s[1]=='X')){ radix=16; s+=2; }
    if(radix<2||radix>36) radix=10;
    int64_t v=0; int any=0;
    for(; *s; s++){ int d; char c=*s;
        if(c>='0'&&c<='9') d=c-'0'; else if(c>='a'&&c<='z') d=c-'a'+10; else if(c>='A'&&c<='Z') d=c-'A'+10; else break;
        if(d>=radix) break; v=v*radix+d; any=1; }
    return NUM(any?(neg?-v:v):JS_NAN);   /* M1629: no leading digit -> NaN per spec, matching parseFloat's own handling (the OLD ":0" here is exactly what that function's comment calls out as the odd-one-out) */
}
static val nat_parseFloat(val *a, int n){                                          /* parseFloat(str): leading float prefix -> double, else NaN */
    if(!n) return NUM(JS_NAN);
    const char *s=val_to_str(a[0]);
    while(*s==' '||*s=='\t'||*s=='\n'||*s=='\r'||*s=='\f'||*s=='\v') s++;
    int neg=0; if(*s=='+') s++; else if(*s=='-'){ neg=1; s++; }
    if(s[0]=='I'&&s[1]=='n'&&s[2]=='f'&&s[3]=='i'&&s[4]=='n'&&s[5]=='i'&&s[6]=='t'&&s[7]=='y') return NUM(neg?-JS_INF:JS_INF);
    int any=0; double x=0;
    while(*s>='0'&&*s<='9'){ x=x*10.0+(*s-'0'); s++; any=1; }
    if(*s=='.'){ s++; double f=0.1; while(*s>='0'&&*s<='9'){ x+=(*s-'0')*f; f*=0.1; s++; any=1; } }
    if(!any) return NUM(JS_NAN);                                                   /* no leading digits -> NaN (parseInt matches this too, M1629) */
    if(*s=='e'||*s=='E'){ const char *p=s+1; int eneg=0; if(*p=='+')p++; else if(*p=='-'){eneg=1;p++;}
        if(*p>='0'&&*p<='9'){ int en=0; while(*p>='0'&&*p<='9'){en=en*10+(*p-'0');p++;} x*=js_pow(10.0,eneg?-(double)en:(double)en); } }
    return NUM(neg?-x:x);
}
static val nat_String(val *a, int n){ return STRV(n ? val_to_str(a[0]) : ""); }
static val nat_Number(val *a, int n){ return NUM(n ? to_num(a[0]) : 0); }
static val nat_Boolean(val *a, int n){ return BOOLV(n ? truthy(a[0]) : 0); }
static val nat_isNaN(val *a, int n){ return BOOLV(n && js_isnan(to_num(a[0]))); }                  /* global isNaN: coerce to number, then test */
static val nat_isFinite(val *a, int n){ return BOOLV(n && js_isfinite(to_num(a[0]))); }            /* global isFinite: coerce to number, then test */
static val nat_num_isInteger(val *a, int n){ return BOOLV(n && a[0].t==V_NUM && js_isfinite(a[0].num) && a[0].num==js_trunc(a[0].num)); }   /* Number.isInteger: no coercion */
static val nat_num_isFinite(val *a, int n){ return BOOLV(n && a[0].t==V_NUM && js_isfinite(a[0].num)); }     /* Number.isFinite: no coercion */
static val nat_num_isSafeInteger(val *a, int n){ if(!n||a[0].t!=V_NUM) return BOOLV(0); double x=a[0].num; return BOOLV(js_isfinite(x) && x==js_trunc(x) && x>=-9007199254740991.0 && x<=9007199254740991.0); }
static val nat_str_fromCharCode(val *a, int n){ char *r=aalloc(n+1); if(!r) return STRV(""); for(int i=0;i<n;i++) r[i]=(char)((int64_t)to_num(a[i])&0xFF); r[n]=0; return STRV(r); }
/* Error constructors: `new Error("msg")` / `Error("msg")` -> an object with .message and .name.
 * (Engine-thrown runtime errors are still caught as their message string; this is for user code.) */
static val make_error(const char *name, val *a, int n){ obj *o=new_obj(V_OBJ); if(!o) return UND(); obj_set(o,"message", (n && a[0].t!=V_UNDEF)?STRV(val_to_str(a[0])):STRV("")); obj_set(o,"name", STRV(name)); return obj_val(o); }
static val nat_Error(val *a, int n){ return make_error("Error",a,n); }
static val nat_TypeError(val *a, int n){ return make_error("TypeError",a,n); }
static val nat_RangeError(val *a, int n){ return make_error("RangeError",a,n); }
static val nat_SyntaxError(val *a, int n){ return make_error("SyntaxError",a,n); }

/* ---- Object.keys(o) -> array of key strings ---- */
static val nat_obj_keys(val *a, int n){
    obj *r = new_obj(V_ARR); if(!r) return UND();
    if (n) a[0]=deproxy(a[0]);   /* Object.keys(proxy) -> the TARGET's keys (no ownKeys trap; never leaks vals[0]/vals[1]) (M-proxy) */
    if (n && a[0].t==V_OBJ && obj_keyed(a[0].o)) {   /* keyed objects only (Date/Map/Set have no enumerable own keys) */
        obj *o=a[0].o;
        for (int i=0;i<o->n;i++){ if(is_internal_key(o->keys[i])) continue; arr_push_val(r, STRV(o->keys[i])); }   /* hide symbol-keyed (@@) props (M-symbol) */
    }
    val v=UND(); v.t=V_ARR; v.o=r; return v;
}

/* ---- JSON.stringify (bounded 16 KB output; depth-guarded against cycles) ---- */
static char *g_json; static int g_json_pos, g_json_cap;
static void js_app(const char *s){ while(*s && g_json_pos<g_json_cap-1) g_json[g_json_pos++]=*s++; }
static void js_appq(const char *s){ js_app("\""); for(; *s && g_json_pos<g_json_cap-8; s++){ unsigned char c=(unsigned char)*s;
        if(c=='"'||c=='\\'){ g_json[g_json_pos++]='\\'; g_json[g_json_pos++]=(char)c; }
        else if(c=='\n'){ js_app("\\n"); } else if(c=='\t'){ js_app("\\t"); } else if(c=='\r'){ js_app("\\r"); }
        else if(c=='\b'){ js_app("\\b"); } else if(c=='\f'){ js_app("\\f"); }         /* M1768: the two remaining standard JSON short escapes */
        else if(c<0x20){ const char*hx="0123456789abcdef"; char u[7]={'\\','u','0','0',hx[(c>>4)&0xF],hx[c&0xF],0}; js_app(u); }   /* M1768: any other control char -> \u00XX; was emitted RAW, producing JSON no conformant parser accepts. (unsigned char keeps bytes >=0x80 raw, not mis-escaped.) */
        else g_json[g_json_pos++]=(char)c; } js_app("\""); }
static int g_json_pretty; static char g_json_unit[16];   /* indentation: "" (compact) or N spaces / a string */
static obj *g_json_allow;   /* array replacer: a property-name allowlist (NULL = include every key) */
static int json_allowed(const char *k){
    if(!g_json_allow) return 1;
    for(int i=0;i<g_json_allow->n;i++){ val e=g_json_allow->vals[i]; if(e.t==V_STR && e.str && strcmp(e.str,k)==0) return 1; }
    return 0;
}
static val g_json_replfn; static int g_json_hasrepl;   /* function replacer: repl(key,value) transforms each node */
static val json_repl(const char *key, val v){ if(!g_json_hasrepl) return v; val ra[2]={STRV(key), v}; return call_function(g_json_replfn, ra, 2); }
static void js_nl(int depth){ if(!g_json_pretty) return; js_app("\n"); for(int i=0;i<depth && i<64;i++) js_app(g_json_unit); }
static void json_val(val v, int depth){
    if(++g_depth>MAXDEPTH){ g_depth--; js_app("null"); return; }
    switch(v.t){
        case V_BOOL: js_app(v.num?"true":"false"); break;
        case V_NUM:  if(!js_isfinite(v.num)) js_app("null"); else js_app(num_to_str(v.num)); break;   /* NaN/Infinity serialize as null, per JSON (M691) */
        case V_STR:  js_appq(v.str); break;
        case V_ARR:  if(v.o->n==0){ js_app("[]"); break; } js_app("[");
            for(int i=0;i<v.o->n;i++){ if(i) js_app(","); js_nl(depth+1); json_val(json_repl(num_to_str((double)i), v.o->vals[i]), depth+1); } js_nl(depth); js_app("]"); break;   /* M1637: the function replacer used to run on every object property but skip array elements entirely -- per spec it sees each array index too (as a string key, like an object property) */
        case V_OBJ:
            if(is_proxy(v)){ val tv=deproxy(v); if(tv.t!=V_OBJ){ json_val(tv,depth); break; } v=tv; }   /* JSON.stringify(proxy) serializes the TARGET; never the proxy's vals[] (M-proxy) */
            if(v.o && v.o->kind==V_DATE){ js_appq(val_to_str(v)); break; }   /* a Date serializes as its string */
            { val tj; if(obj_keyed(v.o) && obj_get(v.o,"toJSON",&tj) && is_callable(tj)){   /* toJSON() hook: serialize its result instead (M691) */
                  val r=call_function_this(tj, v, 0, 0); json_val(r, depth); g_depth--; return; } }
            if(!obj_keyed(v.o) || v.o->n==0){ js_app("{}"); break; }          /* map/set/empty: no enumerable props */
            js_app("{");
            { int wrote=0; for(int i=0;i<v.o->n;i++){ if(is_internal_key(v.o->keys[i])) continue;   /* hide @@ symbol keys; `wrote` (not i) drives the comma so no dangling separator (M-symbol) */
                if(!json_allowed(v.o->keys[i])) continue;   /* array replacer: only allowlisted keys (applies at every depth) */
                val pv=v.o->vals[i]; if(is_accessor(pv)) pv=fire_getter(pv,v);   /* fire getters during serialization (M425) — targeted to JSON, not the global obj_get hot path */
                pv = json_repl(v.o->keys[i], pv);   /* function replacer: transform/drop each value (M657) */
                if(pv.t==V_UNDEF||pv.t==V_FUN||pv.t==V_NATIVE||pv.t==V_SYMBOL) continue;   /* per spec: undefined/function/symbol object properties are OMITTED (only array elements become null) */
                if(wrote){ js_app(","); } wrote=1; js_nl(depth+1); js_appq(v.o->keys[i]); js_app(g_json_pretty?": ":":"); json_val(pv, depth+1); } if(wrote){ js_nl(depth); } } js_app("}"); break;
        default:     js_app("null"); break;   /* undefined/null/function */
    }
    g_depth--;
}
static val nat_json_stringify(val *a, int n){ if(!n) return UND(); char *buf=aalloc(16384); if(!buf) return STRV("");
    g_json=buf; g_json_pos=0; g_json_cap=16384; g_json_pretty=0; g_json_unit[0]=0;
    g_json_allow = (n>1 && a[1].t==V_ARR && a[1].o) ? a[1].o : 0;   /* an array replacer is a key allowlist */
    g_json_hasrepl = (n>1 && (a[1].t==V_FUN || a[1].t==V_NATIVE));   /* a function replacer transforms each (key,value) */
    if(g_json_hasrepl) g_json_replfn = a[1];
    if(n>2){ val sp=a[2];                         /* a[1]: array replacer (allowlist) handled above; a[2] is the indent */
        if(sp.t==V_NUM){ int k=(int)sp.num; if(k<0)k=0; if(k>10)k=10; for(int i=0;i<k;i++) g_json_unit[i]=' '; g_json_unit[k]=0; if(k>0) g_json_pretty=1; }
        else if(sp.t==V_STR){ int i=0; for(; sp.str[i] && i<15; i++) g_json_unit[i]=sp.str[i]; g_json_unit[i]=0; if(i>0) g_json_pretty=1; }
    }
    val top = json_repl("", a[0]);      /* the replacer also sees the top-level value with key "" */
    if(top.t==V_UNDEF || top.t==V_FUN || top.t==V_NATIVE || top.t==V_SYMBOL) return UND();   /* M1769: top-level undefined/function/symbol -> the value `undefined`, not the string "null" */
    json_val(top, 0);
    buf[g_json_pos]=0; return STRV(buf); }

/* ---- JSON.parse (recursive descent; bounded + depth-guarded) ---- */
static const char *jp, *jp_end; static int jp_err;
static void jp_ws(void){ while(jp<jp_end && (*jp==' '||*jp=='\t'||*jp=='\n'||*jp=='\r')) jp++; }
static val json_parse_val(void);
static const char *jp_string(void){          /* assumes *jp == '"'; sizes from the raw token */
    jp++; const char *raw=jp, *e=jp;
    while(e<jp_end && *e!='"'){ if(*e=='\\' && e+1<jp_end) e++; e++; }
    int cap=(int)(e-raw)+1; char *buf=aalloc(cap); int nn=0;
    while(jp<e){ char c=*jp++; if(c=='\\' && jp<jp_end){ char x=*jp++;
            if(x=='u'){ int v=0,k=0; for(;k<4 && jp<jp_end;k++){ char h=*jp; int d=(h>='0'&&h<='9')?h-'0':(h>='a'&&h<='f')?h-'a'+10:(h>='A'&&h<='F')?h-'A'+10:-1; if(d<0) break; v=v*16+d; jp++; } if(k<4){ jp_err=1; c='?'; } else c=(char)(v & 0xFF); }   /* M1768: bad/short \u is now an error (still low byte only -- single-byte engine) */
            else if(x=='n')c='\n'; else if(x=='t')c='\t'; else if(x=='r')c='\r'; else if(x=='b')c='\b'; else if(x=='f')c='\f'; else if(x=='"')c='"'; else if(x=='\\')c='\\'; else if(x=='/')c='/';   /* M1768: added the standard \b \f */
            else { jp_err=1; c=x; } }   /* M1768: an unrecognized escape (\a, \x..) is invalid JSON, not a literal */
        if(buf && nn<cap-1) buf[nn++]=c; }
    if(jp<jp_end && *jp=='"') jp++; else jp_err=1;   /* M1768: an unterminated string (no closing ") is now an error */
    if(buf) buf[nn]=0; return buf?buf:"";
}
static val json_parse_val(void){
    if(++g_depth>MAXDEPTH){ g_depth--; jp_err=1; return UND(); }
    val r=UND(); jp_ws();
    if(jp>=jp_end) jp_err=1;
    else if(*jp=='{'){ obj*o=new_obj(V_OBJ); if(!o){ jp_err=1; g_depth--; return UND(); } jp++; jp_ws();
        if(jp<jp_end && *jp=='}') jp++;
        else for(;;){ jp_ws(); if(jp>=jp_end||*jp!='"'){ jp_err=1; break; } const char*k=jp_string(); jp_ws();
            if(jp<jp_end && *jp==':') jp++; else { jp_err=1; break; }
            val v=json_parse_val(); if(o) obj_set(o,k,v); jp_ws();
            if(jp<jp_end && *jp==','){ jp++; continue; } if(jp<jp_end && *jp=='}'){ jp++; } else jp_err=1; break; }
        r=obj_val(o); }
    else if(*jp=='['){ obj*o=new_obj(V_ARR); if(!o){ jp_err=1; g_depth--; return UND(); } jp++; jp_ws();
        if(jp<jp_end && *jp==']') jp++;
        else for(;;){ val v=json_parse_val(); if(o) arr_push_val(o,v); jp_ws();
            if(jp<jp_end && *jp==','){ jp++; continue; } if(jp<jp_end && *jp==']'){ jp++; } else jp_err=1; break; }
        val vv=UND(); vv.t=V_ARR; vv.o=o; r=vv; }
    else if(*jp=='"'){ r=STRV(jp_string()); }
    else if(*jp=='t'){ if(jp+4<=jp_end && jp[1]=='r'&&jp[2]=='u'&&jp[3]=='e'){ r=BOOLV(1); jp+=4; } else jp_err=1; }   /* exact spelling: "truX"/"tru" are invalid JSON, not `true` */
    else if(*jp=='f'){ if(jp+5<=jp_end && jp[1]=='a'&&jp[2]=='l'&&jp[3]=='s'&&jp[4]=='e'){ r=BOOLV(0); jp+=5; } else jp_err=1; }
    else if(*jp=='n'){ if(jp+4<=jp_end && jp[1]=='u'&&jp[2]=='l'&&jp[3]=='l'){ r.t=V_NULL; jp+=4; } else jp_err=1; }
    else if(*jp=='-' || (*jp>='0'&&*jp<='9')){ int neg=0; if(*jp=='-'){ neg=1; jp++; } double v=0; int idig=0;   /* JSON number: -?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)? -- strict (M1769: was lenient, accepting 01/5./bare-/1e) */
        if(jp<jp_end && *jp=='0'){ jp++; idig=1; }                          /* a leading 0 stands alone (no 01/007: the next digit is left as trailing garbage -> caller errors) */
        else while(jp<jp_end && *jp>='0'&&*jp<='9'){ v=v*10.0+(*jp-'0'); jp++; idig=1; }
        if(!idig) jp_err=1;                                                 /* a bare '-' or leading '.' has no integer digit */
        if(jp<jp_end && *jp=='.'){ jp++; double f=0.1; int fd=0; while(jp<jp_end && *jp>='0'&&*jp<='9'){ v+=(*jp-'0')*f; f*=0.1; jp++; fd=1; } if(!fd) jp_err=1; }   /* '.' requires >=1 fraction digit (no 5.) */
        if(jp<jp_end && (*jp=='e'||*jp=='E')){ jp++; int eneg=0; if(jp<jp_end&&(*jp=='+'||*jp=='-')){ eneg=(*jp=='-'); jp++; } int ex=0,ed=0; while(jp<jp_end && *jp>='0'&&*jp<='9'){ ex=ex*10+(*jp-'0'); jp++; ed=1; } if(!ed) jp_err=1; else v*=js_pow(10.0, eneg?-(double)ex:(double)ex); }   /* exponent requires >=1 digit (no 1e/1e+) */
        r=NUM(neg?-v:v); }
    else jp_err=1;
    g_depth--; return r;
}
/* JSON.parse reviver (InternalizeJSONProperty): post-order walk — recurse into a
 * value's children first (replacing each by the reviver's return, deleting on
 * undefined), then call reviver.call(holder, key, value). Bounded by the parsed
 * structure's depth (json_parse_val depth-limits) and call_function_this's
 * MAXDEPTH guard, so it can't overrun the stack. (M578) */
static val json_revive(val v, val holder, const char *key, val reviver){
    if (v.t==V_OBJ && v.o && obj_keyed(v.o)) {
        for (int i=0; i<v.o->n; ) {
            const char *ck=v.o->keys[i];
            val nv=json_revive(v.o->vals[i], v, ck, reviver);
            if (nv.t==V_UNDEF) obj_delete(v.o, ck);     /* delete -> shifts down; don't advance i */
            else { v.o->vals[i]=nv; i++; }
        }
    } else if (v.t==V_ARR && v.o) {
        for (int i=0; i<v.o->n; i++)
            v.o->vals[i]=json_revive(v.o->vals[i], v, i64_to_str(i), reviver);   /* index as string key */
    }
    val args[2]={ STRV(key), v };
    return call_function_this(reviver, holder, args, 2);
}
static val nat_json_parse(val *a, int n){
    if(!n || a[0].t!=V_STR) return UND();
    const char *s=a[0].str; jp=s; jp_end=s+strlen(s); jp_err=0;
    val r=json_parse_val(); jp_ws(); if(jp_err || jp!=jp_end){ rt_err("JSON.parse: invalid JSON"); return UND(); }   /* reject trailing garbage after a complete value: `1 x` / `[1,2] z` are not valid JSON */
    if (n>1 && (a[1].t==V_FUN||a[1].t==V_NATIVE||(a[1].t==V_OBJ&&a[1].o&&a[1].o->kind==V_BOUND))) {
        obj *root=new_obj(V_OBJ); if(!root) return r;   /* spec root holder { "": result } */
        obj_set(root,"",r); val rv=UND(); rv.t=V_OBJ; rv.o=root;
        r=json_revive(r, rv, "", a[1]);
    }
    return r;
}

/* ---- Object.values / Object.entries, Array.isArray / Array.from ---- */
static val nat_obj_values(val *a, int n){
    obj *r=new_obj(V_ARR); if(!r) return UND();
    if (n) a[0]=deproxy(a[0]);   /* Object.values(proxy) -> the TARGET's values (M-proxy) */
    if (n && a[0].t==V_OBJ && obj_keyed(a[0].o)) for (int i=0;i<a[0].o->n;i++){ if(is_internal_key(a[0].o->keys[i])) continue; val pv=a[0].o->vals[i]; if(is_accessor(pv)) pv=fire_getter(pv,a[0]); arr_push_val(r, pv); }   /* fire getters (M426); hide @@ symbol keys (M-symbol) */
    val v=UND(); v.t=V_ARR; v.o=r; return v;
}
static val nat_obj_entries(val *a, int n){
    obj *r=new_obj(V_ARR); if(!r) return UND();
    if (n) a[0]=deproxy(a[0]);   /* Object.entries(proxy) -> the TARGET's entries (M-proxy) */
    if (n && a[0].t==V_OBJ && obj_keyed(a[0].o)) for (int i=0;i<a[0].o->n;i++){
        if(is_internal_key(a[0].o->keys[i])) continue;   /* hide @@ symbol keys (M-symbol) */
        obj *pair=new_obj(V_ARR); if(!pair) break; arr_push_val(pair, STRV(a[0].o->keys[i])); val gv=a[0].o->vals[i]; if(is_accessor(gv)) gv=fire_getter(gv,a[0]); arr_push_val(pair, gv);   /* fire getters (M426) */
        val pv=UND(); pv.t=V_ARR; pv.o=pair; arr_push_val(r, pv); }
    val v=UND(); v.t=V_ARR; v.o=r; return v;
}
static val nat_array_isArray(val *a, int n){ return BOOLV(n && a[0].t==V_ARR); }
/* Object.fromEntries([[k,v],…]) or fromEntries(map) -> { k: v, … } */
static val nat_obj_fromEntries(val *a, int n){
    obj *r=new_obj(V_OBJ); if(!r) return UND();
    if (n && a[0].t==V_OBJ && a[0].o && a[0].o->kind==V_MAP) {           /* a Map: entries are interleaved [k,v,…] */
        obj *m=a[0].o; for (int i=0;i+1<m->n && !g_oom;i+=2) obj_set(r, val_to_str(m->vals[i]), m->vals[i+1]);
    } else if (n && a[0].t==V_ARR && a[0].o) {                           /* an array of [k,v] pairs */
        obj *arr=a[0].o; for (int i=0;i<arr->n && !g_oom;i++){ val e=arr->vals[i];
            if (e.t==V_ARR && e.o && e.o->n>=1) obj_set(r, val_to_str(e.o->vals[0]), e.o->n>1?e.o->vals[1]:UND()); }
    }
    return obj_val(r);
}
static val nat_obj_freeze(val *a, int n){ if(n && a[0].t==V_OBJ && a[0].o) a[0].o->frozen=1; return n?a[0]:UND(); }
static val nat_obj_isFrozen(val *a, int n){ if(!n || a[0].t!=V_OBJ || !a[0].o) return BOOLV(1); return BOOLV(a[0].o->frozen!=0); }   /* non-objects are "frozen" per spec */
static val nat_object_is(val *a, int n){   /* Object.is: like === but Object.is(NaN,NaN)=true and Object.is(+0,-0)=false (M919, real IEEE doubles) */
    val x = n>0?a[0]:UND(), y = n>1?a[1]:UND();
    if (x.t==V_NUM && y.t==V_NUM) {
        if (js_isnan(x.num) && js_isnan(y.num)) return BOOLV(1);                      /* both NaN -> true (unlike ===) */
        if (x.num==0.0 && y.num==0.0) return BOOLV((1.0/x.num)==(1.0/y.num));         /* +0 vs -0: 1/+0=+Inf, 1/-0=-Inf */
        return BOOLV(x.num==y.num);
    }
    return BOOLV(val_equal(x, y));
}
static val nat_obj_hasOwn(val *a, int n){ if(n<2 || !a[0].o) return BOOLV(0); val tmp;   /* Object.hasOwn(obj, key) (M274) */
    if (a[0].t==V_OBJ && obj_keyed(a[0].o)) return BOOLV(obj_get(a[0].o, val_to_str(a[1]), &tmp));
    if (a[0].t==V_ARR) { const char *k=val_to_str(a[1]); if(strcmp(k,"length")==0) return BOOLV(1); int i=(int)to_num(a[1]); return BOOLV(i>=0 && i<a[0].o->n); }
    return BOOLV(0); }
/* Object.defineProperty(obj, key, descriptor): the programmatic way to install an
 * accessor (reusing M261's V_ACCESSOR) or a data property. {get}/{set} -> accessor;
 * {value} -> plain value. writable/enumerable/configurable are accepted but not
 * enforced (this engine has no such property attributes). Returns the object. */
static val nat_obj_defineProperty(val *a, int n){
    if (n<3 || a[0].t!=V_OBJ || !obj_keyed(a[0].o) || a[2].t!=V_OBJ) { rt_err("Object.defineProperty(obj, key, descriptor)"); return UND(); }
    obj *o=a[0].o; const char *key=val_to_str(a[1]); obj *desc=a[2].o; val g,s,v;
    int hg=obj_get(desc,"get",&g) && (g.t==V_FUN||g.t==V_NATIVE);
    int hs=obj_get(desc,"set",&s) && (s.t==V_FUN||s.t==V_NATIVE);
    if (hg||hs) { obj *acc=new_accessor(); if(!acc){g_oom=1;return UND();} if(hg)acc->vals[0]=g; if(hs)acc->vals[1]=s; obj_set(o,key,obj_val(acc)); }   /* accessor descriptor */
    else if (obj_get(desc,"value",&v)) obj_set(o,key,v);                                                                                          /* data descriptor */
    else obj_set(o,key,UND());
    return a[0];
}
/* Object.getOwnPropertyDescriptor(obj, key): the read pair. Accessor -> {get,set,...},
 * data -> {value,writable,...}; missing key -> undefined. Flags are always true
 * (no attribute enforcement here). Reads the slot RAW (obj_get doesn't fire). */
static val nat_obj_getOwnPropertyDescriptor(val *a, int n){
    if (n<2 || a[0].t!=V_OBJ || !obj_keyed(a[0].o)) return UND();
    val stored; if (!obj_get(a[0].o, val_to_str(a[1]), &stored)) return UND();
    obj *d=new_obj(V_OBJ); if(!d){g_oom=1;return UND();}
    if (is_accessor(stored)) { obj_set(d,"get",stored.o->vals[0]); obj_set(d,"set",stored.o->vals[1]); }
    else { obj_set(d,"value",stored); obj_set(d,"writable",BOOLV(1)); }
    obj_set(d,"enumerable",BOOLV(1)); obj_set(d,"configurable",BOOLV(1));
    return obj_val(d);
}
static val nat_obj_getOwnPropertyDescriptors(val *a, int n){   /* {key: descriptor} for every own key (reuses the singular form) (M279) */
    obj *r=new_obj(V_OBJ); if(!r){g_oom=1;return UND();}
    if (n>=1 && a[0].t==V_OBJ && obj_keyed(a[0].o)) { obj*o=a[0].o; for(int i=0;i<o->n && !g_oom;i++){ if(is_internal_key(o->keys[i])) continue; val da[2]={ a[0], STRV(o->keys[i]) }; obj_set(r, o->keys[i], nat_obj_getOwnPropertyDescriptor(da,2)); } }   /* hide @@ symbol keys (M-symbol) */
    return obj_val(r);
}
/* Object.defineProperties(obj, descriptors): defineProperty for each own key of the descriptors
 * object (also backs Object.create's 2nd arg). Reuses the reviewed nat_obj_defineProperty. (M265) */
static val nat_obj_defineProperties(val *a, int n){
    if (n<2 || a[0].t!=V_OBJ || !obj_keyed(a[0].o) || a[1].t!=V_OBJ || !obj_keyed(a[1].o)) { rt_err("Object.defineProperties(obj, descriptors)"); return UND(); }
    obj *descs=a[1].o;
    for (int i=0;i<descs->n && !g_oom && !g_err;i++) { val da[3]={ a[0], STRV(descs->keys[i]), descs->vals[i] }; nat_obj_defineProperty(da,3); }
    return a[0];
}
/* Prototype-chain natives (M263). Object.create(proto[, descriptors]) makes an object whose
 * [[Prototype]] is proto (null -> none) and applies the optional descriptors (M265).
 * get/setPrototypeOf read/write the link; the chain is consulted only at the evaluator member sites. */
static val nat_obj_create(val *a, int n){ obj *o=new_obj(V_OBJ); if(!o){ g_oom=1; return UND(); }
    if (n>=1 && a[0].t==V_OBJ && a[0].o) o->proto=a[0].o;   /* Object.create(null) / non-object -> proto stays NULL */
    if (n>=2 && a[1].t==V_OBJ && obj_keyed(a[1].o)) { val da[2]={ obj_val(o), a[1] }; nat_obj_defineProperties(da,2); }   /* 2nd arg: property descriptors (M265) */
    return obj_val(o); }
static val nat_obj_getPrototypeOf(val *a, int n){ if (n>=1 && (a[0].t==V_OBJ||a[0].t==V_FUN) && a[0].o && a[0].o->proto) return obj_val(a[0].o->proto); val v=UND(); v.t=V_NULL; return v; }
static val nat_obj_setPrototypeOf(val *a, int n){ if (n>=1 && a[0].t==V_OBJ && a[0].o) a[0].o->proto = (n>=2 && a[1].t==V_OBJ && a[1].o) ? a[1].o : 0; return n? a[0] : UND(); }
static val nat_obj_assign(val *a, int n){   /* Object.assign(target, ...sources) -> target */
    if (!n || a[0].t!=V_OBJ || !a[0].o) return n?a[0]:UND();
    for (int i=1;i<n;i++) a[i]=deproxy(a[i]);   /* a proxy source contributes its TARGET's own props (M-proxy) */
    for (int i=1;i<n;i++) if (a[i].t==V_OBJ && obj_keyed(a[i].o)) for (int j=0;j<a[i].o->n;j++){
        if(is_internal_key(a[i].o->keys[j])) continue;   /* don't copy @@ symbol keys (M-symbol) */
        val sv=a[i].o->vals[j]; if(is_accessor(sv)) sv=fire_getter(sv,a[i]);   /* read source via getter (M427) */
        const char *key=a[i].o->keys[j]; val cur;
        if(obj_get(a[0].o,key,&cur) && is_accessor(cur)){ val st=cur.o->vals[1]; if(st.t!=V_UNDEF) call_function_this(st,a[0],&sv,1); }   /* fire target's setter; getter-only target ignores the write */
        else obj_set(a[0].o, key, sv);
    }
    return a[0];
}
static val nat_sign(val *a, int n){ if(!n) return NUM(0); double x=to_num(a[0]); return NUM(js_isnan(x)?JS_NAN: x>0?1.0: x<0?-1.0: x); }   /* sign: 1/-1/0 (preserves -0 and NaN) */
/* push `e` onto r, applying the optional Array.from map function (e, index) */
static void from_push(obj *r, val e, val fn, int hasfn){ if(hasfn){ val ca[2]={e,NUM(r->n)}; e=call_function(fn,ca,2); } arr_push_val(r,e); }
/* Drive the ES6 iterator protocol on `it` and append each yielded value to `dest` via
 * from_push (so an Array.from map fn is applied; array-spread passes hasfn=0). This is the
 * SHARED engine for [...customIterable] and Array.from(customIterable) — it mirrors the
 * for-of loop's iterator-drive EXACTLY: same callable test (V_FUN/V_NATIVE/V_BOUND), same
 * fetch-next-ONCE, the SAME hard cap (2000, the FOROF_ITER_MAX value), and the same
 * g_err/g_oom checks EVERY iteration so a runaway/allocating user iterator can neither hang
 * nor OOM the kernel (no GC, untrusted input). Returns 1 iff `it` had a CALLABLE
 * [Symbol.iterator] (it was iterable); returns 0 (appending NOTHING) otherwise, so callers
 * can safely use it as an `else if` condition that falls through for non-iterables. */
static int iter_collect(val it, obj *dest, val mapfn, int hasfn){
    val itfn = eval_member_get(it, sym_key(SYM_ID_ITERATOR));
    int callable = (itfn.t==V_FUN || itfn.t==V_NATIVE || (itfn.t==V_OBJ && itfn.o && itfn.o->kind==V_BOUND));
    if (!callable) return 0;                                /* not iterable -> caller falls through (nothing appended) */
    if (g_err || g_oom) return 1;
    val iter = call_function_this(itfn, it, 0, 0);          /* @@iterator() -> the iterator object */
    if (iter.t==V_ARR && iter.o) {                          /* eager generator as [Symbol.iterator]: iterate its collected values */
        for (int i=0;i<iter.o->n && !g_oom;i++) from_push(dest, iter.o->vals[i], mapfn, hasfn);
        return 1;
    }
    if (iter.t!=V_OBJ || !iter.o || g_err || g_oom) return 1;
    val nextfn = eval_member_get(iter, "next");             /* fetch `next` ONCE (as the for-of loop does) */
    int ncall = (nextfn.t==V_FUN || nextfn.t==V_NATIVE || (nextfn.t==V_OBJ && nextfn.o && nextfn.o->kind==V_BOUND));
    long guard=0;
    while (ncall) {
        if (g_err || g_oom) break;
        if (++guard > 2000) { rt_err("iterator did not terminate"); break; }   /* hard cap == FOROF_ITER_MAX: guaranteed termination on untrusted iterators */
        val res = call_function_this(nextfn, iter, 0, 0);
        if (g_err || g_oom) break;
        if (res.t!=V_OBJ || !res.o) break;                  /* result must be an object; otherwise stop */
        if (truthy(eval_member_get(res, "done"))) break;    /* done:truthy -> finished */
        val cv = eval_member_get(res, "value");
        if (g_err || g_oom) break;
        from_push(dest, cv, mapfn, hasfn);                  /* append (applying the Array.from map fn when hasfn) */
    }
    return 1;                                               /* it WAS iterable (even if zero-length / it errored mid-stream) */
}
static val nat_array_from(val *a, int n){
    obj *r=new_obj(V_ARR); if(!r) return UND();
    val fn = n>1?a[1]:UND(); int hasfn=(fn.t==V_FUN||fn.t==V_NATIVE);
    if (n && a[0].t==V_ARR && a[0].o) for (int i=0;i<a[0].o->n && !g_oom;i++) from_push(r, a[0].o->vals[i], fn, hasfn);
    else if (n && a[0].t==V_OBJ && a[0].o && a[0].o->kind==V_SET) for (int i=0;i<a[0].o->n && !g_oom;i++) from_push(r, a[0].o->vals[i], fn, hasfn);   /* Array.from(set) — dedup idiom */
    else if (n && a[0].t==V_OBJ && a[0].o && a[0].o->kind==V_MAP) for (int i=0;i+1<a[0].o->n && !g_oom;i+=2){ obj*p=new_obj(V_ARR); if(!p){g_oom=1;break;} arr_push_val(p,a[0].o->vals[i]); arr_push_val(p,a[0].o->vals[i+1]); val pv=UND();pv.t=V_ARR;pv.o=p; from_push(r, pv, fn, hasfn); }
    else if (n && a[0].t==V_STR) { const char*s=a[0].str; for (int i=0;s[i] && !g_oom;i++){ char*c=aalloc(2); if(c){c[0]=s[i];c[1]=0;} from_push(r, STRV(c?c:""), fn, hasfn); } }
    else if (n && a[0].t==V_OBJ && a[0].o && iter_collect(a[0], r, fn, hasfn)) { }   /* custom iterable: drive [Symbol.iterator] (applies the map fn). Returns 0 (no-op) for a non-iterable -> falls through to the array-like branch. (M-iter) */
    else if (n && a[0].t==V_OBJ && a[0].o && obj_keyed(a[0].o)) {   /* array-like {length:n}: Array.from({length:3}) -> [undefined x3] (pairs with .fill / a map fn) */
        val lv; int64_t len = obj_get(a[0].o,"length",&lv) ? to_num(lv) : 0;
        if (len<0) len=0; if (len>1000000) len=1000000;   /* bound a malicious {length:1e18} */
        for (int64_t i=0;i<len && !g_oom;i++) from_push(r, UND(), fn, hasfn);
    }
    val v=UND(); v.t=V_ARR; v.o=r; return v;
}
static val nat_array_of(val *a, int n){ obj *r=new_obj(V_ARR); if(!r) return UND(); for(int i=0;i<n && !g_oom;i++) arr_push_val(r,a[i]); val v=UND(); v.t=V_ARR; v.o=r; return v; }
/* Array(...) / new Array(...): a single NUMBER arg -> a length-n array of undefined;
 * otherwise the args become the elements. Array is a callable V_NATIVE (so `typeof Array`
 * === "function"); isArray/from/of live on its side statics, like Number/String. (M268) */
static val nat_array_ctor(val *a, int n){ obj *r=new_obj(V_ARR); if(!r){g_oom=1;return UND();}
    if (n==1 && a[0].t==V_NUM) { int64_t len=a[0].num; if(len<0||len>(1<<24)){ rt_err("invalid array length"); return UND(); } for(int64_t i=0;i<len && !g_oom;i++) arr_push_val(r,UND()); }
    else { for(int i=0;i<n && !g_oom;i++) arr_push_val(r,a[i]); }
    val v=UND(); v.t=V_ARR; v.o=r; return v; }

/* register a native function on object `o` under `name` */
static void def_native(obj *o, const char *name, val (*fn)(val*,int)){
    obj *f=new_obj(V_NATIVE); if(!f) return; f->native=fn; val v=UND(); v.t=V_NATIVE; v.o=f; obj_set(o,name,v);
}
static val obj_val(obj *o){ val v=UND(); v.t=V_OBJ; v.o=o; return v; }
static val obj_val_native(obj *o){ val v=UND(); v.t=V_NATIVE; v.o=o; return v; }

/* structuredClone (M266): a deep clone that PRESERVES cycles & shared refs (the JSON
 * round-trip can't). Plain objects/arrays cloned recursively; primitives by value; a
 * `seen` map sends a re-encountered source to the SAME clone (cycles/shared refs kept).
 * Functions and the exotic kinds (Map/Set/Date/RegExp/accessor/element) are not cloneable
 * -> throw. Depth-capped; the bounded `seen[]` lives in the caller frame (no per-level alloc). */
typedef struct { obj *from; obj *to; } sclone_pair;
static val sclone(val v, sclone_pair *seen, int *nseen, int cap, int depth) {
    if (g_err || g_oom) return UND();
    if (depth > 64) { rt_err("structuredClone: structure too deep"); return UND(); }
    if (v.t == V_FUN || v.t == V_NATIVE) { rt_err("structuredClone: cannot clone a function"); return UND(); }
    if (v.t != V_OBJ && v.t != V_ARR) return v;        /* primitives copied by value */
    if (!v.o) return v;
    if (v.t == V_OBJ && v.o->kind != V_OBJ) { rt_err("structuredClone: value not cloneable"); return UND(); }   /* Map/Set/Date/RegExp/accessor/element */
    for (int i=0;i<*nseen;i++) if (seen[i].from == v.o) { val r=UND(); r.t=v.t; r.o=seen[i].to; return r; }      /* already cloned -> same clone */
    obj *c = new_obj(v.t==V_ARR ? V_ARR : V_OBJ); if(!c){ g_oom=1; return UND(); }
    if (*nseen < cap) { seen[*nseen].from=v.o; seen[*nseen].to=c; (*nseen)++; }                                  /* register before recursing (cycles) */
    val cv=UND(); cv.t=v.t; cv.o=c;
    if (v.t==V_ARR) { for(int i=0;i<v.o->n && !g_oom && !g_err;i++) arr_push_val(c, sclone(v.o->vals[i], seen, nseen, cap, depth+1)); }
    else { for(int i=0;i<v.o->n && !g_oom && !g_err;i++){ if(is_internal_key(v.o->keys[i])) continue; obj_set(c, v.o->keys[i], sclone(v.o->vals[i], seen, nseen, cap, depth+1)); } }   /* skip @@ symbol keys (M-symbol) */
    return cv;
}
static val nat_structured_clone(val *a, int n){ if(!n) return UND(); sclone_pair seen[128]; int nseen=0; return sclone(a[0], seen, &nseen, 128, 0); }

/* Reflect: standard metaprogramming namespace mirroring the core object operations. get reuses
 * the read path (fires getters, walks the proto chain); ownKeys = Object.keys; deleteProperty =
 * delete; has = own+prototype existence; set fires an own setter else writes an own data prop. (M277) */
static val nat_reflect_get(val *a, int n){ if(n<2) return UND(); return eval_member_get(a[0], val_to_str(a[1])); }
static val nat_reflect_has(val *a, int n){ if(n<2 || a[0].t!=V_OBJ || !obj_keyed(a[0].o)) return BOOLV(0); const char *k=val_to_str(a[1]); val t;
    if(obj_get(a[0].o,k,&t)) return BOOLV(1); int g=0; for(obj*p=a[0].o->proto; p && ++g<=JS_PROTO_MAX; p=p->proto) if(obj_get(p,k,&t)) return BOOLV(1); return BOOLV(0); }
static val nat_reflect_set(val *a, int n){ if(n<3 || a[0].t!=V_OBJ || !obj_keyed(a[0].o)) return BOOLV(0); obj*o=a[0].o; const char*k=val_to_str(a[1]); val cur;
    if(obj_get(o,k,&cur) && is_accessor(cur)){ val s=cur.o->vals[1]; if(s.t!=V_UNDEF){ val rv=a[2]; call_function_this(s,a[0],&rv,1); } return BOOLV(1); }
    obj_set(o,k,a[2]); return BOOLV(1); }
static val nat_reflect_deleteProperty(val *a, int n){ if(n<2 || a[0].t!=V_OBJ || !a[0].o) return BOOLV(0); return BOOLV(obj_delete(a[0].o, val_to_str(a[1]))); }
static val nat_reflect_ownKeys(val *a, int n){ return nat_obj_keys(a,n); }   /* own enumerable keys (= Object.keys) */

/* Symbol(desc): called as a FUNCTION (not `new`), returns a fresh unique symbol.
 * Each call takes the next id from the monotonic counter (which starts above the
 * reserved well-known ids), so Symbol() !== Symbol(). The optional description is
 * interned into the arena so it outlives the args[] frame. (M-symbol) */
static val nat_Symbol(val *a, int n){
    const char *desc = 0;
    if (n && a[0].t!=V_UNDEF) { const char *s=val_to_str(a[0]); desc=intern(s,(int)strlen(s)); }
    return SYMV(g_sym_next++, desc);
}

/* ---- setTimeout / setInterval: a deferred-callback queue ----
 * The engine has no real event loop (its I/O is blocking and Promises resolve
 * eagerly), so timers can't truly wait on a wall clock. We model them the only
 * way a run-to-completion interpreter can: queue the callbacks, then once the
 * top-level script finishes, run them in (delay, registration) order until the
 * queue drains — so the huge amount of real-world JS that defers work with
 * setTimeout(fn, …) actually executes instead of dying on "setTimeout is not
 * defined". setInterval fires once (a synchronous engine can't loop forever).
 * The queue is per-run (reset on entry, drained while the arena is still live). */
#define JS_NTIMERS 256
static struct { val fn; long delay; int id; int active; long seq; } g_timers[JS_NTIMERS];
static int g_ntimers, g_timer_id, g_timer_seq;
static int js_callable(val v){ return v.t==V_FUN || v.t==V_NATIVE || (v.t==V_OBJ && v.o && v.o->kind==V_BOUND); }

static val nat_setTimeout(val *a, int n){
    if (n < 1 || !js_callable(a[0]) || g_ntimers >= JS_NTIMERS) return NUM(0);
    long d = (n >= 2 && a[1].t==V_NUM) ? a[1].num : 0;
    int id = ++g_timer_id;
    g_timers[g_ntimers].fn = a[0]; g_timers[g_ntimers].delay = d < 0 ? 0 : d;
    g_timers[g_ntimers].id = id; g_timers[g_ntimers].active = 1; g_timers[g_ntimers].seq = g_timer_seq++;
    g_ntimers++;
    return NUM(id);
}
static val nat_clearTimeout(val *a, int n){
    if (n >= 1 && a[0].t==V_NUM)
        for (int i=0;i<g_ntimers;i++) if (g_timers[i].id==(int)a[0].num) g_timers[i].active=0;
    return UND();
}
/* Enqueue a 0-delay deferred task into the timer queue (used by EventSource to run
 * the first-event delivery AFTER the current script). Returns the timer id, or 0 if
 * full / not callable. */
static int js_enqueue_task(val fn){
    if (!js_callable(fn) || g_ntimers >= JS_NTIMERS) return 0;
    int id = ++g_timer_id;
    g_timers[g_ntimers].fn = fn; g_timers[g_ntimers].delay = 0;
    g_timers[g_ntimers].id = id; g_timers[g_ntimers].active = 1; g_timers[g_ntimers].seq = g_timer_seq++;
    g_ntimers++;
    return id;
}
/* Run queued timers in (delay, seq) order; callbacks may queue more. Bounded so a
 * self-rescheduling setTimeout / setInterval can't spin forever. */
static void js_drain_timers(void){
    int budget = 100000;
    while (budget-- > 0 && !g_err && !g_oom) {
        int best = -1;
        for (int i=0;i<g_ntimers;i++) if (g_timers[i].active)
            if (best<0 || g_timers[i].delay<g_timers[best].delay ||
                (g_timers[i].delay==g_timers[best].delay && g_timers[i].seq<g_timers[best].seq)) best=i;
        if (best<0) break;
        val fn = g_timers[best].fn; g_timers[best].active = 0;
        call_function_this(fn, UND(), 0, 0);
    }
}

static void install_globals(env *g) {
    obj *p=new_obj(V_NATIVE); p->native=native_print; val pv=UND(); pv.t=V_NATIVE; pv.o=p; env_define(g,"print",pv);
    /* setTimeout/setInterval (deferred-callback queue) + clearTimeout/clearInterval */
    { obj *st=new_obj(V_NATIVE); st->native=nat_setTimeout;   val v=UND(); v.t=V_NATIVE; v.o=st; env_define(g,"setTimeout",v);  env_define(g,"setInterval",v);
      env_define(g,"requestAnimationFrame",v); env_define(g,"queueMicrotask",v); }   /* rAF/microtask: same deferred-callback queue */
    { obj *ct=new_obj(V_NATIVE); ct->native=nat_clearTimeout; val v=UND(); v.t=V_NATIVE; v.o=ct; env_define(g,"clearTimeout",v); env_define(g,"clearInterval",v);
      env_define(g,"cancelAnimationFrame",v); }
    /* console.log */
    obj *log=new_obj(V_NATIVE); log->native=native_print; val lv=UND(); lv.t=V_NATIVE; lv.o=log;
    obj *con=new_obj(V_OBJ); obj_set(con,"log",lv); obj_set(con,"warn",lv); obj_set(con,"error",lv); obj_set(con,"info",lv); obj_set(con,"debug",lv);   /* all print; page scripts use warn/error too */
    val cv=UND(); cv.t=V_OBJ; cv.o=con; env_define(g,"console",cv);
    /* document: write() splices HTML into the page; getElementById(id) returns a
     * live element handle whose .textContent/.innerHTML read & mutate the page. */
    obj *dw=new_obj(V_NATIVE); dw->native=native_doc_write; val dwv=UND(); dwv.t=V_NATIVE; dwv.o=dw;
    obj *doc=new_obj(V_OBJ); obj_set(doc,"write",dwv); obj_set(doc,"writeln",dwv);
    def_native(doc,"getElementById",nat_getElementById);
    def_native(doc,"createElement",nat_createElement);
    def_native(doc,"querySelector",nat_querySelector);
    def_native(doc,"querySelectorAll",nat_querySelectorAll);
    def_native(doc,"getElementsByTagName",nat_getElementsByTagName);
    def_native(doc,"getElementsByClassName",nat_getElementsByClassName);
    val docv=UND(); docv.t=V_OBJ; docv.o=doc; env_define(g,"document",docv); g_doc_obj=doc;   /* remember it for document.title */
    /* window.location: a read-only snapshot of the current page URL, parsed into
     * href/protocol/host/pathname/search so page JS can inspect it (e.g. ?query). */
    { obj *loc=new_obj(V_OBJ);
      if (loc) {
        const char *u=g_location_url; int ulen=(int)strlen(u);
        obj_set(loc,"href",STRV(intern(u,ulen)));
        const char *proto=""; const char *hs=u; int hashost=0;
        if (ulen>=8 && memcmp(u,"https://",8)==0)      { proto="https:"; hs=u+8; hashost=1; }
        else if (ulen>=7 && memcmp(u,"http://",7)==0)  { proto="http:";  hs=u+7; hashost=1; }
        else if (ulen>=5 && memcmp(u,"file:",5)==0)    { proto="file:";  hs=u+5; }   /* file: has no //host */
        obj_set(loc,"protocol",STRV(intern(proto,(int)strlen(proto))));
        const char *rest=hs;
        if (hashost) { int hl=0; while(hs[hl] && hs[hl]!='/' && hs[hl]!='?') hl++;   /* host = up to '/' or '?' */
                       obj_set(loc,"host",STRV(intern(hs,hl))); rest=hs+hl; }
        else obj_set(loc,"host",STRV(intern("",0)));
        int pl=0; while(rest[pl] && rest[pl]!='?') pl++;   /* path, then ?search */
        obj_set(loc,"pathname",STRV(intern(rest,pl)));
        obj_set(loc,"search",STRV(intern(rest+pl,(int)strlen(rest+pl))));
        env_define(g,"location",obj_val(loc));
        obj *win=new_obj(V_OBJ); if(win){ obj_set(win,"location",obj_val(loc)); env_define(g,"window",obj_val(win)); }
      }
    }
    /* localStorage.getItem/setItem (browser-backed; no-ops at the shell) */
    obj *ls=new_obj(V_OBJ); def_native(ls,"getItem",native_ls_getItem); def_native(ls,"setItem",native_ls_setItem);
    def_native(ls,"removeItem",native_ls_removeItem); def_native(ls,"clear",native_ls_clear);
    env_define(g,"localStorage",obj_val(ls));

    /* Math */
    obj *math=new_obj(V_OBJ);
    def_native(math,"abs",nat_abs); def_native(math,"max",nat_max); def_native(math,"min",nat_min);
    def_native(math,"floor",nat_floor); def_native(math,"ceil",nat_ceil); def_native(math,"round",nat_round); def_native(math,"trunc",nat_trunc);
    def_native(math,"sqrt",nat_sqrt); def_native(math,"pow",nat_pow); def_native(math,"sign",nat_sign); def_native(math,"random",nat_random);
    def_native(math,"hypot",nat_hypot); def_native(math,"log2",nat_log2);
    def_native(math,"cbrt",nat_cbrt); def_native(math,"clz32",nat_clz32); def_native(math,"imul",nat_imul);
    def_native(math,"log",nat_log); def_native(math,"exp",nat_exp); def_native(math,"log10",nat_log10);
    def_native(math,"sin",nat_sin); def_native(math,"cos",nat_cos); def_native(math,"tan",nat_tan);
    def_native(math,"atan",nat_atan); def_native(math,"atan2",nat_atan2); def_native(math,"asin",nat_asin); def_native(math,"acos",nat_acos);
    def_native(math,"sinh",nat_sinh); def_native(math,"cosh",nat_cosh); def_native(math,"tanh",nat_tanh);
    obj_set(math,"PI",NUM(3.141592653589793)); obj_set(math,"E",NUM(2.718281828459045));               /* Math constants (real doubles now) */
    obj_set(math,"LN2",NUM(0.6931471805599453)); obj_set(math,"LN10",NUM(2.302585092994046));
    obj_set(math,"LOG2E",NUM(1.4426950408889634)); obj_set(math,"LOG10E",NUM(0.4342944819032518));
    obj_set(math,"SQRT2",NUM(1.4142135623730951)); obj_set(math,"SQRT1_2",NUM(0.7071067811865476));
    env_define(g,"Math",obj_val(math));
    /* Object (Object.keys) */
    obj *objc=new_obj(V_OBJ); def_native(objc,"keys",nat_obj_keys); def_native(objc,"values",nat_obj_values); def_native(objc,"entries",nat_obj_entries); def_native(objc,"assign",nat_obj_assign); def_native(objc,"fromEntries",nat_obj_fromEntries); def_native(objc,"getOwnPropertyNames",nat_obj_keys); def_native(objc,"freeze",nat_obj_freeze); def_native(objc,"isFrozen",nat_obj_isFrozen); def_native(objc,"is",nat_object_is); def_native(objc,"hasOwn",nat_obj_hasOwn); def_native(objc,"defineProperty",nat_obj_defineProperty); def_native(objc,"defineProperties",nat_obj_defineProperties); def_native(objc,"getOwnPropertyDescriptor",nat_obj_getOwnPropertyDescriptor); def_native(objc,"getOwnPropertyDescriptors",nat_obj_getOwnPropertyDescriptors); def_native(objc,"create",nat_obj_create); def_native(objc,"getPrototypeOf",nat_obj_getPrototypeOf); def_native(objc,"setPrototypeOf",nat_obj_setPrototypeOf); g_object_ctor=objc; env_define(g,"Object",obj_val(objc));
    { obj *refl=new_obj(V_OBJ); if(refl){ def_native(refl,"get",nat_reflect_get); def_native(refl,"has",nat_reflect_has); def_native(refl,"set",nat_reflect_set); def_native(refl,"deleteProperty",nat_reflect_deleteProperty); def_native(refl,"ownKeys",nat_reflect_ownKeys); env_define(g,"Reflect",obj_val(refl)); } }   /* Reflect metaprogramming namespace (M277) */
    { obj *mp=new_obj(V_NATIVE); if(mp){ mp->native=nat_map; val v=UND(); v.t=V_NATIVE; v.o=mp; env_define(g,"Map",v); } }   /* new Map() */
    { obj *st=new_obj(V_NATIVE); if(st){ st->native=nat_set; val v=UND(); v.t=V_NATIVE; v.o=st; env_define(g,"Set",v); } }   /* new Set() */
    { obj *wm=new_obj(V_NATIVE); if(wm){ wm->native=nat_map; val v=UND(); v.t=V_NATIVE; v.o=wm; env_define(g,"WeakMap",v); } }   /* WeakMap: backed by Map (no GC, so weak refs are moot) -- distinct ctor for instanceof (M273) */
    { obj *ws=new_obj(V_NATIVE); if(ws){ ws->native=nat_set; val v=UND(); v.t=V_NATIVE; v.o=ws; env_define(g,"WeakSet",v); } }   /* WeakSet: backed by Set (M273) */
    { obj *rx=new_obj(V_NATIVE); if(rx){ rx->native=nat_regexp; val v=UND(); v.t=V_NATIVE; v.o=rx; env_define(g,"RegExp",v); } }   /* RegExp(pat,flags) / new RegExp(...) */
    { obj *px=new_obj(V_NATIVE); if(px){ px->native=nat_proxy; val v=UND(); v.t=V_NATIVE; v.o=px; env_define(g,"Proxy",v); } }   /* new Proxy(target,handler) — get/set traps (M-proxy) */
    { obj *ab=new_obj(V_NATIVE); if(ab){ ab->native=nat_arraybuffer; env_define(g,"ArrayBuffer",obj_val_native(ab)); } }   /* new ArrayBuffer(n) (M1850) */
    { obj *u8=new_obj(V_NATIVE); if(u8){ u8->native=nat_uint8array;  env_define(g,"Uint8Array",obj_val_native(u8)); } }    /* new Uint8Array(n|arr|buf) (M1850) */
    { obj *te=new_obj(V_NATIVE); if(te){ te->native=nat_textencoder; env_define(g,"TextEncoder",obj_val_native(te)); } }   /* new TextEncoder().encode(str) (M1851) */
    { obj *td=new_obj(V_NATIVE); if(td){ td->native=nat_textdecoder; env_define(g,"TextDecoder",obj_val_native(td)); } }   /* new TextDecoder().decode(u8) (M1851) */
    { obj *pc=new_obj(V_NATIVE); if(pc){ pc->native=nat_promise; g_promise_ctor=pc;   /* Promise (synchronous-resolution model, M679) */
        obj *pst=new_obj(V_OBJ); if(pst){ def_native(pst,"resolve",nat_promise_resolve); def_native(pst,"reject",nat_promise_reject); def_native(pst,"all",nat_promise_all); def_native(pst,"any",nat_promise_any); def_native(pst,"race",nat_promise_race); def_native(pst,"allSettled",nat_promise_allSettled); pc->statics=pst; }
        val v=UND(); v.t=V_NATIVE; v.o=pc; env_define(g,"Promise",v); } }
    { obj *f=new_obj(V_NATIVE); if(f){ f->native=nat_fetch; env_define(g,"fetch",obj_val_native(f)); } }   /* fetch(url) -> Promise<Response> (M684); functional once js_set_fetch wires a backing */
    { obj *es=new_obj(V_NATIVE); if(es){ es->native=nat_eventsource; env_define(g,"EventSource",obj_val_native(es)); } }   /* new EventSource(url): one-shot SSE first-event snapshot (M-eventsource) */
    { obj *wsc=new_obj(V_NATIVE); if(wsc){ wsc->native=nat_websocket; env_define(g,"WebSocket",obj_val_native(wsc)); } }   /* new WebSocket(url): one-shot request/reply over a real WS connection (M1844) */
    { obj *arrc=new_obj(V_NATIVE); if(arrc){ arrc->native=nat_array_ctor;   /* Array() constructor; statics on the side so isArray/from/of still resolve (M268) */
        obj *ast=new_obj(V_OBJ); if(ast){ def_native(ast,"isArray",nat_array_isArray); def_native(ast,"from",nat_array_from); def_native(ast,"of",nat_array_of); arrc->statics=ast; }
        g_array_ctor=arrc; env_define(g,"Array",obj_val_native(arrc)); } }
    /* JSON (stringify) */
    obj *json=new_obj(V_OBJ); def_native(json,"stringify",nat_json_stringify); def_native(json,"parse",nat_json_parse); env_define(g,"JSON",obj_val(json));
    /* Symbol(desc) -> fresh unique symbol; Symbol.iterator is the fixed well-known symbol
     * (read off the side statics, like Number.MAX_SAFE_INTEGER). (M-symbol) */
    { obj *symc=new_obj(V_NATIVE); if(symc){ symc->native=nat_Symbol;
        obj *sst=new_obj(V_OBJ); if(sst){ obj_set(sst,"iterator",SYMV(SYM_ID_ITERATOR,"Symbol.iterator")); symc->statics=sst; }
        env_define(g,"Symbol",obj_val_native(symc)); } }
    /* global functions */
    obj *pi=new_obj(V_NATIVE); pi->native=nat_parseInt; env_define(g,"parseInt",obj_val_native(pi));
    obj *pf=new_obj(V_NATIVE); pf->native=nat_parseFloat; env_define(g,"parseFloat",obj_val_native(pf));
    obj *sf=new_obj(V_NATIVE); sf->native=nat_String;   env_define(g,"String",obj_val_native(sf));
    obj *nf=new_obj(V_NATIVE); nf->native=nat_Number;   env_define(g,"Number",obj_val_native(nf));
    { obj *nst=new_obj(V_OBJ); if(nst){ def_native(nst,"isInteger",nat_num_isInteger); def_native(nst,"isFinite",nat_num_isFinite); def_native(nst,"isNaN",nat_isNaN); def_native(nst,"isSafeInteger",nat_num_isSafeInteger); def_native(nst,"parseInt",nat_parseInt); def_native(nst,"parseFloat",nat_parseFloat); obj_set(nst,"MAX_SAFE_INTEGER",NUM(9007199254740991LL)); obj_set(nst,"MIN_SAFE_INTEGER",NUM(-9007199254740991LL)); obj_set(nst,"POSITIVE_INFINITY",NUM(JS_INF)); obj_set(nst,"NEGATIVE_INFINITY",NUM(-JS_INF)); obj_set(nst,"MAX_VALUE",NUM(1.7976931348623157e308)); obj_set(nst,"MIN_VALUE",NUM(5e-324)); obj_set(nst,"EPSILON",NUM(2.220446049250313e-16)); obj_set(nst,"NaN",NUM(JS_NAN)); nf->statics=nst; }
      obj *sst=new_obj(V_OBJ); if(sst){ def_native(sst,"fromCharCode",nat_str_fromCharCode); def_native(sst,"fromCodePoint",nat_str_fromCharCode); sf->statics=sst; } }   /* String.fromCharCode/fromCodePoint (ASCII: same) via side-statics; Number/String stay V_NATIVE */
    obj *bf=new_obj(V_NATIVE); bf->native=nat_Boolean;  env_define(g,"Boolean",obj_val_native(bf));
    obj *nan=new_obj(V_NATIVE); nan->native=nat_isNaN;  env_define(g,"isNaN",obj_val_native(nan));
    { obj *fin=new_obj(V_NATIVE); fin->native=nat_isFinite; env_define(g,"isFinite",obj_val_native(fin)); }
    /* Infinity / NaN: real IEEE-754 values now that numbers are doubles (js.o is built
     * with SSE). 1/0 -> Infinity, 0/0 -> NaN, Math.max() -> -Infinity, etc. */
    env_define(g,"Infinity",NUM(JS_INF));
    env_define(g,"NaN",NUM(JS_NAN));
    /* Error + its subtypes: link each subtype's ctor parent_class to Error so
     * `new TypeError(...) instanceof Error` is true (the instanceof chain walks
     * ctor_class -> parent_class), matching JS's Error hierarchy. */
    obj *errc=new_obj(V_NATIVE); errc->native=nat_Error; env_define(g,"Error",obj_val_native(errc));
    { obj *e=new_obj(V_NATIVE); e->native=nat_TypeError;   e->parent_class=errc; env_define(g,"TypeError",obj_val_native(e)); }
    { obj *e=new_obj(V_NATIVE); e->native=nat_RangeError;  e->parent_class=errc; env_define(g,"RangeError",obj_val_native(e)); }
    { obj *e=new_obj(V_NATIVE); e->native=nat_SyntaxError; e->parent_class=errc; env_define(g,"SyntaxError",obj_val_native(e)); }
    { obj *e=new_obj(V_NATIVE); e->native=nat_encodeURIComponent; env_define(g,"encodeURIComponent",obj_val_native(e)); }
    { obj *e=new_obj(V_NATIVE); e->native=uri_decode;             env_define(g,"decodeURIComponent",obj_val_native(e)); }
    { obj *e=new_obj(V_NATIVE); e->native=nat_encodeURI;          env_define(g,"encodeURI",obj_val_native(e)); }
    { obj *e=new_obj(V_NATIVE); e->native=nat_decodeURI;          env_define(g,"decodeURI",obj_val_native(e)); }
    { obj *e=new_obj(V_NATIVE); e->native=nat_structured_clone; env_define(g,"structuredClone",obj_val_native(e)); }   /* deep clone w/ cycle preservation (M266) */
    obj *dt=new_obj(V_NATIVE); dt->native=nat_date;     env_define(g,"Date",obj_val_native(dt));   /* Date() -> wall-clock string */
    { obj *dst=new_obj(V_OBJ); if(dst){ def_native(dst,"now",nat_date_now); def_native(dst,"parse",nat_date_parse); dt->statics=dst; } }   /* Date.now() / Date.parse() */

    /* globalThis / self: the universal global object that modern JS and UMD-style
     * libraries reference (typeof globalThis, globalThis.X, self.X). Build a plain
     * object exposing the globals defined above as properties so globalThis.JSON,
     * globalThis.setTimeout, etc. resolve, with self === globalThis (and
     * globalThis.globalThis === globalThis). window/location are browser-only, so
     * env_find returns NULL for them at the shell and they're simply skipped. */
    { obj *gt = new_obj(V_OBJ);
      if (gt) {
        static const char *gn[] = {
            "print","parseInt","parseFloat","isNaN","isFinite","Infinity",
            "setTimeout","clearTimeout","setInterval","clearInterval",
            "requestAnimationFrame","cancelAnimationFrame","queueMicrotask",
            "Math","JSON","Object","Array","String","Number","Boolean","Date",
            "Map","Set","WeakMap","WeakSet","Promise","Proxy","Reflect","Symbol","RegExp",
            "Error","TypeError","RangeError","SyntaxError",
            "console","document","localStorage","fetch","window","location",
            "encodeURI","decodeURI","encodeURIComponent","decodeURIComponent","structuredClone", 0 };
        for (int i = 0; gn[i]; i++) { val *v = env_find(g, gn[i]); if (v) obj_set(gt, gn[i], *v); }
        val gtv = obj_val(gt);
        obj_set(gt, "globalThis", gtv); obj_set(gt, "self", gtv);
        env_define(g, "globalThis", gtv); env_define(g, "self", gtv);
      }
    }
}

/* =========================== entry point =========================== */
/* Run JS source; print output into out[0..outmax). Returns output length, or -1
 * on error (with the message appended to the output). Serialized: uses static
 * arena + globals, so only one js_run() may be in flight at a time. */
/* Interpreter state is static (arena + globals), so only one run may be in flight.
 * The browser (WM thread) and the shell's `js` (a ring-3 syscall) are distinct
 * preemptible tasks, so guard with an irq-protected flag like tls_get does. */
#if defined(JS_HOSTTEST) || defined(JS_RING3)
/* Host test and the RING-3 build (user/jsrun.c): no privileged cli/sti — a ring-3
 * process can't execute them, and the single-flight concern is moot (one run). */
static inline unsigned long js_irq_save(void){ return 0; }
static inline void js_irq_restore(unsigned long f){ (void)f; }
#else
static inline unsigned long js_irq_save(void){ unsigned long f; __asm__ volatile("pushfq; pop %0; cli":"=r"(f)::"memory"); return f; }
static inline void js_irq_restore(unsigned long f){ __asm__ volatile("push %0; popfq"::"r"(f):"memory","cc"); }
#endif
static volatile int js_busy;

/* A page's persistent global env (across its load <script> + every later event
 * handler), so a function/var defined at load survives to fire on a click. Set
 * on a page-begin run, reused by page-event runs, discarded on the next page-begin
 * (the arena is reset then). The shell `js` path never touches it. */
static env *g_page_env;
/* mode: 0 = fresh (shell `js`/document.write — reset arena, new env, no persist);
 *       1 = page-begin (navigation load script — reset arena, new env, PERSIST it);
 *       2 = page-event (onclick/onchange — KEEP arena + REUSE the persistent env). */
static int js_run_impl(const char *src, char *out, int outmax, int mode) {
    unsigned long f = js_irq_save();
    if (js_busy) { js_irq_restore(f); if (outmax) out[0]=0; return -1; }   /* another run in flight */
    js_busy = 1; js_irq_restore(f);

    int reuse = (mode == 2 && g_page_env);             /* an event reusing the live page env */
    if (!reuse) g_arena_off = 0;                       /* events keep the arena so the env survives */
    g_oom=0; g_err=0; g_errmsg[0]=0; g_depth=0; g_ntimers=0; g_timer_seq=0;
    g_out=out; g_out_cap=outmax; g_out_len=0; if(outmax) out[0]=0;

    lexer L; memset(&L,0,sizeof(L)); L.src=src; L.len=(int)strlen(src); L.pos=0;
    node *prog = parse_program(&L);
    g_depth = 0;                          /* parse balances g_depth to 0; reset defensively for eval */
    if (!g_err && !g_oom) {
        env *g = reuse ? g_page_env : new_env(0);
        if (g) {
            if (!reuse) { install_globals(g); if (mode >= 1) g_page_env = g; }   /* persist on page-begin (1) AND a script-less page's first event (mode 2, no env yet) so its later clicks share state */
            hoist_vars(prog, g);                                                  /* top-level var hoisting (global env) */
            eval_stmt(prog, g);
            js_drain_timers();      /* run setTimeout/setInterval callbacks the script queued */
        }
    }
    if (g_oom) rt_err("out of memory (arena)");
    int r = g_out_len;
    if (g_err) { out_str("\n[js error: "); out_str(g_errmsg); out_str("]\n"); r = -1; }
    js_busy = 0;
    return r;
}

int js_run(const char *src, char *out, int outmax) {
    g_doc_write = 0;                      /* shell `js`: document.write falls back to output */
    g_ls_get = 0; g_ls_set = 0; g_ls_remove = 0; g_ls_clear = 0;   /* and no persistent storage */
    g_dom_get = 0; g_dom_set = 0; g_dom_getattr = 0; g_dom_setattr = 0;   /* and no DOM (no page) */
    g_get_title = 0; g_set_title = 0;     /* and no page <title> bridge */
    g_page_env = 0;                       /* shell `js`: never reuse a page env */
    g_location_url[0] = 0;                /* shell `js`: window.location is empty */
    return js_run_impl(src, out, outmax, 0);
}

/* The browser registers document.title get/set (reads/writes the page <title>). */
void js_set_title(int (*get)(char *, int), void (*set)(const char *)) {
    g_get_title = get; g_set_title = set;
}
/* The browser registers a localStorage backing store before running page JS. */
void js_set_storage(const char *(*get)(const char *), void (*set)(const char *, const char *),
                     void (*remove_fn)(const char *), void (*clear_fn)(void)) {
    g_ls_get = get; g_ls_set = set; g_ls_remove = remove_fn; g_ls_clear = clear_fn;
}
/* The browser registers a blocking HTTP backing for fetch() (M684): fills out/+status,
 * returns body length or <0 on a network error. NULL (default) -> fetch() rejects. */
void js_set_fetch(int (*fn)(const char *url, const char *method, const char *ctype, const char *body, char *out, int outmax, int *status)) {
    g_fetch = fn;
}
/* The browser registers a blocking SSE first-event backing for EventSource (M-eventsource):
 * GET url, read the first complete event's data payload into out/+status, return its length
 * or <0 on a network error. NULL (default) -> a constructed EventSource fires onerror. */
void js_set_eventsource(int (*fn)(const char *url, char *out, int outmax, int *status)) {
    g_eventsource = fn;
}
/* Register the browser's WebSocket backings (M1844): `open` does connect +
 * RFC 6455 handshake (returns a conn id, or -1), `exchange` sends the queued
 * messages on that id and reads the replies, then closes. */
void js_set_websocket(int (*open)(const char *url, int *status),
                      int (*exchange)(int id, const char *sendbuf, int sendtot,
                                      char *out, int outmax, int *nrecv)) {
    g_ws_open = open;
    g_ws_exchange = exchange;
}
void js_set_canvas(void (*op)(const char *id, int op, int a, int b, int c, int d, const char *color, const char *text, int lw)) {   /* M1796-M1801 */
    g_canvas_op = op;
}
/* The browser registers DOM read/mutate callbacks for getElementById handles. */
void js_set_dom(int (*get)(const char *, char *, int, int), void (*set)(const char *, const char *, int)) {
    g_dom_get = get; g_dom_set = set;
}
/* The browser registers getAttribute/setAttribute backings (separate so js_set_dom's signature is untouched). */
void js_set_dom_attr(int (*getattr)(const char *, const char *, char *, int),
                     void (*setattr)(const char *, const char *, const char *)) {
    g_dom_getattr = getattr; g_dom_setattr = setattr;
}
/* The browser registers position-keyed DOM callbacks for querySelector(All) matches. */
void js_set_dom_pos(int (*get_at)(int, char *, int, int),
                    void (*set_at)(int, const char *, int),
                    int (*getattr_at)(int, const char *, char *, int),
                    void (*setattr_at)(int, const char *, const char *),
                    int (*query)(const char *, int *, int)) {
    g_dom_get_at = get_at; g_dom_set_at = set_at;
    g_dom_getattr_at = getattr_at; g_dom_setattr_at = setattr_at; g_dom_query = query;
}
/* The browser registers element.matches()/closest() backings (id + position variants). */
void js_set_dom_match(int (*matches)(const char *, const char *), int (*matches_at)(int, const char *),
                      int (*closest)(const char *, const char *), int (*closest_at)(int, const char *)) {
    g_dom_matches = matches; g_dom_matches_at = matches_at;
    g_dom_closest = closest; g_dom_closest_at = closest_at;
}
/* The browser registers removeAttribute backings (id + position variants). */
void js_set_dom_rmattr(void (*rmattr)(const char *, const char *), void (*rmattr_at)(int, const char *)) {
    g_dom_rmattr = rmattr; g_dom_rmattr_at = rmattr_at;
}
/* The browser registers element.children + parentElement + sibling backings (id + position variants). */
void js_set_dom_children(int (*children)(const char *, int *, int), int (*children_at)(int, int *, int),
                         int (*parent)(const char *), int (*parent_at)(int),
                         int (*sibling)(const char *, int), int (*sibling_at)(int, int)) {
    g_dom_children = children; g_dom_children_at = children_at;
    g_dom_parent = parent; g_dom_parent_at = parent_at;
    g_dom_sibling = sibling; g_dom_sibling_at = sibling_at;
}
/* The browser registers element.tagName backings (id + position variants). */
void js_set_dom_tag(int (*tag)(const char *, char *, int), int (*tag_at)(int, char *, int)) {
    g_dom_tag = tag; g_dom_tag_at = tag_at;
}
/* The browser sets the current page URL before running page JS (for window.location). */
void js_set_location(const char *url) {
    int i = 0; if (url) while (url[i] && i < (int)sizeof(g_location_url) - 1) { g_location_url[i] = url[i]; i++; }
    g_location_url[i] = 0;
}

/* Run page scripts with a host document.write sink (the browser splices the
 * written HTML into the page and re-parses). */
int js_run_doc(const char *src, char *out, int outmax, void (*write_cb)(const char *)) {
    g_doc_write = write_cb;
    int r = js_run_impl(src, out, outmax, 0);
    g_doc_write = 0;
    return r;
}
/* Page navigation: run the load <script> and PERSIST its global env so later
 * event handlers (onclick/onchange) can see the functions/vars it defined. */
int js_page_load(const char *src, char *out, int outmax, void (*write_cb)(const char *)) {
    g_doc_write = write_cb;
    int r = js_run_impl(src, out, outmax, 1);
    g_doc_write = 0;
    return r;
}
/* A page event handler: run in the persistent page env (no arena reset), so the
 * code can call functions / read vars defined by the load script. */
int js_page_event(const char *src, char *out, int outmax, void (*write_cb)(const char *)) {
    g_doc_write = write_cb;
    int r = js_run_impl(src, out, outmax, 2);
    g_doc_write = 0;
    return r;
}
/* The browser calls this on navigation so a new page never inherits the previous
 * page's persistent globals (the next js_page_load — or the first event on a
 * script-less page — rebuilds the env from scratch and resets the arena). */
void js_page_reset(void) { g_page_env = 0; }

/* ---- JS-assigned event handlers (el.onclick=fn / addEventListener) ----
 * Handlers live in a per-page registry `@handlers` (a V_OBJ keyed "type:id" ->
 * fn) bound in the persistent g_page_env, so they survive across events and are
 * dropped on navigation with the env (M287). The element is marked clickable via
 * a synthetic `data-jsh` attribute (written through the existing setAttribute +
 * re-render path); the renderer then turns it into an `event:ID` link that the
 * browser dispatches back to js_fire_event. v1 keys by id (offsets are stale once
 * the re-render the assignment triggers shifts the buffer); id-less elements are
 * a no-op. */
static void hkey(char *key, const char *type, const char *id) {   /* "type:id", bounded to key[160] */
    int k=0; for (const char *p=type; *p && k<78; p++) key[k++]=*p;
    if (k<159) key[k++]=':';
    for (const char *p=id; *p && k<159; p++) key[k++]=*p;
    key[k]=0;
}
static obj *handlers_obj(void) {
    if (!g_page_env) return 0;
    val *hv = env_find(g_page_env, "@handlers");
    if (hv && hv->t==V_OBJ && hv->o) return hv->o;
    obj *o = new_obj(V_OBJ); if (!o) { g_oom=1; return 0; }
    env_define(g_page_env, "@handlers", obj_val(o));
    return o;
}
static void register_handler(obj *el, const char *type, val fn) {
    const char *id = (el->n>0 && el->vals[0].t==V_STR) ? el->vals[0].str : "";
    if (!id[0] || !type[0]) return;                 /* v1: id-keyed only */
    obj *h = handlers_obj(); if (!h || h->n >= 128) return;   /* bound the registry */
    char key[160]; hkey(key, type, id);
    obj_set(h, intern(key, (int)strlen(key)), fn);   /* intern: obj_set stores the key POINTER, so it must outlive this stack frame */
    if (strcmp(type,"click")==0 && g_dom_setattr) g_dom_setattr(id, "data-jsh", "1");   /* mark clickable -> renderer makes it an event link */
}
/* el.onclick=null / removeEventListener: drop the handler. The data-jsh marker is
 * left in place (a click then finds no handler and is a safe no-op) — fully
 * un-marking would need removeAttribute, a separate feature. */
static void unregister_handler(obj *el, const char *type) {
    const char *id = (el->n>0 && el->vals[0].t==V_STR) ? el->vals[0].str : "";
    if (!id[0] || !type[0] || !g_page_env) return;
    val *hv = env_find(g_page_env, "@handlers");
    if (!hv || hv->t!=V_OBJ || !hv->o) return;
    char key[160]; hkey(key, type, id);
    obj_delete(hv->o, key);
}
/* The browser calls this when an `event:ID` link is activated: look up and invoke
 * the registered handler in the persistent env (no arena reset). 1 if one ran. */
int js_fire_event(const char *id, const char *type, char *out, int outmax, void (*write_cb)(const char *)) {
    unsigned long f = js_irq_save();
    if (js_busy || !g_page_env) { js_irq_restore(f); if (outmax) out[0]=0; return 0; }
    js_busy = 1; js_irq_restore(f);
    g_doc_write = write_cb;
    g_oom=0; g_err=0; g_errmsg[0]=0; g_depth=0;
    g_out=out; g_out_cap=outmax; g_out_len=0; if (outmax) out[0]=0;
    int ran = 0;
    val *hv = env_find(g_page_env, "@handlers");
    if (hv && hv->t==V_OBJ && hv->o) {
        char key[160]; hkey(key, type, id);
        val fn;
        if (obj_get(hv->o, key, &fn) && (fn.t==V_FUN || fn.t==V_NATIVE || (fn.t==V_OBJ && fn.o && fn.o->kind==V_BOUND))) {
            val target = element_handle(id);                    /* the element the event fired on */
            obj *eo = new_obj(V_OBJ); val ev = UND();           /* a minimal event: { type, target } */
            if (eo) { obj_set(eo, "type", STRV(intern(type,(int)strlen(type)))); obj_set(eo, "target", target); ev = obj_val(eo); }
            call_function_this(fn, target, &ev, 1);   /* this = the element, arg[0] = the event; in the persistent env (no arena reset) */
            ran = 1;
        }
    }
    if (g_err) { out_str("\n[js error: "); out_str(g_errmsg); out_str("]\n"); }
    g_doc_write = 0;
    js_busy = 0;
    return ran;
}

#ifdef JS_HOSTTEST
/* a tiny in-memory localStorage so host tests can exercise the persistent path */
static char hk[16][32], hv[16][160]; static int hn;
static const char *host_get(const char *k){ for(int i=0;i<hn;i++) if(!strcmp(hk[i],k)) return hv[i]; return 0; }
static void host_set(const char *k, const char *v){
    int i; for(i=0;i<hn;i++) if(!strcmp(hk[i],k)) break;
    if(i==hn){ if(hn>=16) return; int j=0; while(k[j]&&j<31){hk[hn][j]=k[j];j++;} hk[hn][j]=0; i=hn++; }
    int j=0; while(v[j]&&j<159){hv[i][j]=v[j];j++;} hv[i][j]=0;
}
static void host_remove(const char *k){
    int i; for(i=0;i<hn;i++) if(!strcmp(hk[i],k)) break;
    if(i==hn) return;
    for(int m=i;m<hn-1;m++){
        int j=0; while(hk[m+1][j]){hk[m][j]=hk[m+1][j];j++;} hk[m][j]=0;
        j=0; while(hv[m+1][j]){hv[m][j]=hv[m+1][j];j++;} hv[m][j]=0;
    }
    hn--;
}
static void host_clear(void){ hn = 0; }
/* a trivial in-memory "DOM" (id -> text) so host tests can exercise getElementById */
static char dk[16][32], dv[16][256]; static int dnn;
static void hdom_set(const char *id, const char *v, int html){ (void)html; int i; for(i=0;i<dnn;i++) if(!strcmp(dk[i],id)) break; if(i==dnn){ if(dnn>=16) return; int j=0; while(id[j]&&j<31){dk[dnn][j]=id[j];j++;} dk[dnn][j]=0; i=dnn++; } int j=0; while(v[j]&&j<255){dv[i][j]=v[j];j++;} dv[i][j]=0; }
static int hdom_get(const char *id, char *out, int max, int html){ (void)html; for(int i=0;i<dnn;i++) if(!strcmp(dk[i],id)){ int j=0; while(dv[i][j]&&j<max-1){out[j]=dv[i][j];j++;} out[j]=0; return 1; } if(max) out[0]=0; return 0; }
/* mock getAttribute: echo the attr name back as its value (so the suite can assert the round-trip) */
static int hdom_getattr(const char *id, const char *attr, char *out, int max){ (void)id; if(max<=0) return 0; int j=0; while(attr[j]&&j<max-1){out[j]=attr[j];j++;} out[j]=0; return 1; }
static void hdom_setattr(const char *id, const char *attr, const char *val){ (void)id; (void)attr; (void)val; }
/* mock querySelector(All): "p"/".item" match two elements (offsets 10,20); "#solo"/"b.x" match one. */
static int hdom_query(const char *sel, int *offs, int max){ if(max<1) return 0;
    if(!strcmp(sel,"p")||!strcmp(sel,".item")){ int n=0; if(n<max)offs[n++]=10; if(n<max)offs[n++]=20; return n; }
    if(!strcmp(sel,"#solo")||!strcmp(sel,"b.x")||!strcmp(sel,"[data-x]")){ offs[0]=10; return 1; }
    return 0; }
/* a tiny offset->text override store so position writes are observable on read-back */
static int wat_off[8]; static char wat_txt[8][64]; static int wat_n;
static int hdom_get_at(int off, char *out, int max, int html){ (void)html; if(max<=0) return 0;
    for(int i=0;i<wat_n;i++) if(wat_off[i]==off){ int j=0; while(wat_txt[i][j]&&j<max-1){out[j]=wat_txt[i][j];j++;} out[j]=0; return 1; }
    const char *t = off==10 ? "alpha" : off==20 ? "beta" : ""; int j=0; while(t[j]&&j<max-1){out[j]=t[j];j++;} out[j]=0; return 1; }
/* a per-offset "class" attribute store so classList round-trips host-side */
static int hcls_off[8]; static char hcls_val[8][128]; static int hcls_n;
/* mock getAttribute-by-position: "class" comes from the class store (so classList
 * works); any other attr echoes "<attr>@<off>" (so the M282 getAttribute test holds) */
static int hdom_getattr_at(int off, const char *attr, char *out, int max){ if(max<=0) return 0;
    if(!strcmp(attr,"class")){ for(int i=0;i<hcls_n;i++) if(hcls_off[i]==off){ int j=0; while(hcls_val[i][j]&&j<max-1){out[j]=hcls_val[i][j];j++;} out[j]=0; return j>0; } out[0]=0; return 0; }
    int j=0; while(attr[j]&&j<max-2){out[j]=attr[j];j++;} if(j<max-2)out[j++]='@'; if(j<max-1)out[j++]=(char)('0'+(off/10)%10); out[j]=0; return 1; }
/* mock writes-by-position: store into the shared offset->text store so a read-back reflects it */
static void hdom_set_at(int off, const char *value, int html){ (void)html; int i; for(i=0;i<wat_n;i++) if(wat_off[i]==off) break;
    if(i==wat_n){ if(wat_n>=8) return; wat_off[wat_n++]=off; } int j=0; while(value[j]&&j<63){wat_txt[i][j]=value[j];j++;} wat_txt[i][j]=0; }
static void hdom_setattr_at(int off, const char *attr, const char *val){ if(strcmp(attr,"class")) return;   /* only "class" is stored (for classList) */
    int i; for(i=0;i<hcls_n;i++) if(hcls_off[i]==off) break; if(i==hcls_n){ if(hcls_n>=8) return; hcls_off[hcls_n++]=off; } int j=0; while(val[j]&&j<127){hcls_val[i][j]=val[j];j++;} hcls_val[i][j]=0; }
/* mock matches: reuse hdom_query (membership), mirroring the real browser_dom_matches_at */
static int hdom_matches_at(int off, const char *sel){ int offs[8]; int n=hdom_query(sel,offs,8); for(int i=0;i<n;i++) if(offs[i]==off) return 1; return 0; }
static int hdom_matches(const char *id, const char *sel){ (void)id; (void)sel; return 0; }   /* id handles: mock store has no offset */
static int hdom_closest_at(int off, const char *sel){ int offs[8]; int n=hdom_query(sel,offs,8); for(int i=0;i<n;i++) if(offs[i]==off) return off; return -1; }   /* mock: self-match only (no ancestor spans) */
static int hdom_closest(const char *id, const char *sel){ (void)id; (void)sel; return -1; }
/* mock children: off 10 has two "children" (reusing the canned 10/20 offsets so .textContent works) */
static int hdom_children_at(int off, int *offs, int max){ if(off==10 && max>=2){ offs[0]=10; offs[1]=20; return 2; } return 0; }
static int hdom_children(const char *id, int *offs, int max){ (void)id; (void)offs; (void)max; return 0; }
static int hdom_parent_at(int off){ (void)off; return -1; }   /* mock has no element tree; real parent tested in-OS */
static int hdom_parent(const char *id){ (void)id; return -1; }
static int hdom_sibling_at(int off, int dir){ if(off==10 && dir>0) return 20; if(off==20 && dir<0) return 10; return -1; }   /* canned: 10<->20 (real scan tested in-OS) */
static int hdom_sibling(const char *id, int dir){ (void)id; (void)dir; return -1; }
static int hdom_tag_at(int off, char *out, int max){ if(max<=0)return 0; const char *t=off==10?"P":off==20?"LI":"DIV"; int j=0; while(t[j]&&j<max-1){out[j]=t[j];j++;} out[j]=0; return 1; }
static int hdom_tag(const char *id, char *out, int max){ (void)id; if(max<=0)return 0; const char *t="DIV"; int j=0; while(t[j]&&j<max-1){out[j]=t[j];j++;} out[j]=0; return 1; }
/* mock removeAttribute: clear the class store entry (so a later hasAttribute("class") reads false) */
static void hdom_rmattr_at(int off, const char *attr){ if(strcmp(attr,"class")) return; for(int i=0;i<hcls_n;i++) if(hcls_off[i]==off){ hcls_val[i][0]=0; return; } }
static void hdom_rmattr(const char *id, const char *attr){ (void)id; (void)attr; }   /* id handles: no id-class store in the mock */
#ifndef JS_NO_MAIN   /* a host harness embedding js.c (e.g. tests/jsonfuzz) defines this to supply its own main */
/* mock fetch backing for host tests: canned bodies keyed off the URL (no real network).
 * "/json" -> a JSON object; "/fail" -> a network error (<0); anything else -> a text body. */
static int hfetch(const char *url, const char *method, const char *ctype, const char *reqbody, char *out, int outmax, int *status) {
    if (strstr(url, "fail")) return -1;                       /* simulate a network error -> reject */
    *status = strstr(url, "404") ? 404 : 200;
    int n=0;
    if (method && (method[0]=='P'||method[0]=='p')) {         /* POST: echo "POST <ctype>:<body>" so tests can assert method/body/ctype reached the backing */
        const char *pre="POST "; for (int i=0; pre[i] && n<outmax-1; i++) out[n++]=pre[i];
        for (const char *c=ctype?ctype:"text/plain"; *c && n<outmax-1; c++) out[n++]=*c;
        if (n<outmax-1) out[n++]=':';
        for (const char *b=reqbody?reqbody:""; *b && n<outmax-1; b++) out[n++]=*b;
        out[n]=0; return n;
    }
    if (strstr(url, "bin")) {                                 /* binary body incl. a leading NUL + a >127 byte */
        static const unsigned char blob[] = { 0x00, 0x01, 0x80, 0xff, 0x41 };   /* 5 bytes; index-0 NUL would truncate a C string to len 0 */
        for (int i=0; i<(int)sizeof(blob) && n<outmax; i++) out[n++]=(char)blob[i];
        return n;                                             /* returns the true length 5, not strlen (0) */
    }
    const char *body = strstr(url, "json") ? "{\"a\":1,\"b\":[2,3]}" : "hello from fetch";
    while (body[n] && n<outmax-1) { out[n]=body[n]; n++; } out[n]=0;
    return n;
}
/* mock EventSource backing: "/fail" -> network error (<0); else a canned first-event
 * data payload (the joined data: lines), so the SSE snapshot path is testable host-side. */
static int hes(const char *url, char *out, int outmax, int *status) {
    if (strstr(url, "fail")) return -1;
    *status = 200;
    const char *body = "{\"msg\":\"sse-snapshot\",\"n\":7}";
    int n=0; while (body[n] && n<outmax-1) { out[n]=body[n]; n++; } out[n]=0;
    return n;
}
/* Mock WebSocket backing for the JS host test (M1844): a "fail" URL refuses the
 * connection; otherwise the handshake succeeds (101) and the exchange echoes
 * each sent record back, modelling a WS echo server so timers.js can assert
 * onopen -> send -> onmessage -> onclose. Speaks the M1859 record framing
 * ([op][len:4 LE][payload]): a TEXT record echoes as "echo:<msg>", a BIN record
 * echoes the same bytes back (so a binary round-trip can be asserted). */
static int hws_open(const char *url, int *status) {
    if (strstr(url, "fail")) { *status = 0; return -1; }
    *status = 101; return 1;                     /* a fake connection id */
}
static int hws_put_rec(char *out, int *off, int outmax, int op, const unsigned char *data, int L) {
    if (*off + 5 + L > outmax) return 0;
    out[(*off)++] = (char)op;
    out[(*off)++] = (char)(L & 0xff);        out[(*off)++] = (char)((L >> 8) & 0xff);
    out[(*off)++] = (char)((L >> 16) & 0xff); out[(*off)++] = (char)((L >> 24) & 0xff);
    for (int j=0;j<L;j++) out[(*off)++] = (char)data[j];
    return 1;
}
static int hws_exchange(int id, const char *sendbuf, int sendtot,
                        char *out, int outmax, int *nrecv) {
    (void)id;
    int off = 0, rc = 0;
    const unsigned char *p = (const unsigned char *)sendbuf, *pend = p + sendtot;
    while (p + 5 <= pend) {                       /* each record: [op][len:4 LE][payload] */
        int op = p[0];
        int L = (int)((unsigned)p[1] | ((unsigned)p[2]<<8) | ((unsigned)p[3]<<16) | ((unsigned)p[4]<<24));
        p += 5; if (L < 0 || p + L > pend) break;
        if (op == WSREC_BIN) {
            if (!hws_put_rec(out, &off, outmax, WSREC_BIN, p, L)) break;
        } else {
            unsigned char tmp[512]; int tl = 0;   /* "echo:" + payload (test messages are short) */
            const char *pre = "echo:"; for (int j=0;j<5 && tl<(int)sizeof(tmp);j++) tmp[tl++] = (unsigned char)pre[j];
            for (int j=0;j<L && tl<(int)sizeof(tmp);j++) tmp[tl++] = p[j];
            if (!hws_put_rec(out, &off, outmax, WSREC_TEXT, tmp, tl)) break;
        }
        rc++; p += L;
    }
    *nrecv = rc; return off;
}

/* M1800: mock canvas 2D op — records each dispatched op into the output stream (via
 * out_str, same as console.log) so canvas.js can assert the JS->op dispatch: op code,
 * coords, fill/strokeStyle colour, and fillText text. Locks eval_canvas_method. */
static void hcanvas(const char *id, int op, int a, int b, int c, int d, const char *color, const char *text, int lw) {
    char buf[192];
    snprintf(buf, sizeof buf, "CVOP id=%s op=%d %d,%d,%d,%d col=%s txt=%s lw=%d\n",
             id?id:"", op, a, b, c, d, color?color:"", text?text:"", lw);
    out_str(buf);
}
int main(int argc, char **argv) {
    static char src[200000]; int n=0; FILE *f = argc>1?fopen(argv[1],"rb"):stdin;
    n = (int)fread(src,1,sizeof(src)-1,f); src[n]=0;
    static char outb[200000];
    js_set_storage(host_get, host_set, host_remove, host_clear);   /* mirror the browser: storage + js_run_doc */
    js_set_dom(hdom_get, hdom_set);                      /* mock DOM for host tests */
    js_set_dom_attr(hdom_getattr, hdom_setattr);
    js_set_dom_pos(hdom_get_at, hdom_set_at, hdom_getattr_at, hdom_setattr_at, hdom_query);   /* mock querySelector(All) for host tests */
    js_set_dom_match(hdom_matches, hdom_matches_at, hdom_closest, hdom_closest_at);   /* mock element.matches/closest for host tests */
    js_set_dom_children(hdom_children, hdom_children_at, hdom_parent, hdom_parent_at, hdom_sibling, hdom_sibling_at);   /* mock element.children/parentElement/sibling for host tests */
    js_set_dom_tag(hdom_tag, hdom_tag_at);   /* mock element.tagName for host tests */
    js_set_dom_rmattr(hdom_rmattr, hdom_rmattr_at);    /* mock removeAttribute for host tests */
    js_set_location("https://host.example/dir/page?q=hi&n=2");   /* mock URL for window.location tests */
    js_set_fetch(hfetch);                                /* mock network for fetch() tests (M684) */
    js_set_eventsource(hes);                             /* mock SSE first-event for EventSource tests (M-eventsource) */
    js_set_websocket(hws_open, hws_exchange);            /* mock WS echo server for WebSocket tests (M1844) */
    js_set_canvas(hcanvas);                              /* M1800: mock canvas 2D op recorder for canvas.js */
    hdom_set("c", "", 0);                                /* seed a <canvas id="c"> so getElementById('c').getContext works */
    int r = js_run_doc(src, outb, sizeof(outb), 0);
    fputs(outb, stdout);
    if (getenv("JS_ARENA_REPORT")) fprintf(stderr, "ARENA_END=%d / %d (headroom %d)\n", g_arena_off, JS_ARENA, JS_ARENA-g_arena_off);
    return r<0?1:0;
}
#endif /* JS_NO_MAIN */
#endif
