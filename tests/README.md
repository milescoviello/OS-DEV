# Tests

Host-side regression + fuzz tests for the from-scratch parsers that run
**kernel-side on untrusted input** (a malicious web server, an on-path attacker,
or page scripts) on a **16 KB stack with no guard page** — where an out-of-bounds
access is silent kernel memory corruption. Each suite compiles the *real* kernel
source on the host under **ASan + UBSan** and exercises it with crafted edge
cases + deterministic fuzzing.

## Running

```sh
make check       # run all 102 suites (~7 min total)
make jstest      # JS engine      — tests/js/suite.js vs the golden output
make imgtest     # image decoders — tests/img/img_test.c   (jpeg/png/gif/bmp/inflate)
make x509test    # X.509 parser   — tests/x509/x509_test.c
make nettest     # TCP/IP stack   — tests/net/net_test.c   (packet parse + reassembly)
make fstest      # FAT32 driver   — tests/fs/fs_test.c     (corrupt/cyclic on-disk structures + write stress)
make kattest     # crypto KAT     — tests/crypto/crypto_test.c (RFC/FIPS known-answer vectors)
make svgtest     # SVG rasterizer — tests/svg/svg_test.c   (shapes/paths + adversarial XML fuzz)
make deflatetest # DEFLATE/gzip   — compressor vs the decoder, round-trip
make pngenctest  # PNG encoder    — encoder vs the decoder, round-trip
make ziptest     # ZIP extractor  — extraction + corrupt-input fuzz
make tartest     # tar extractor  — extraction + corrupt-input fuzz
make heaptest    # userspace malloc — umalloc.c alloc/free regression
make journaltest # write-ahead journal — kernel/journal.c crash-consistency (power-loss injected at every write; never torn)
make wavtest     # WAV header     — wav_parse over corrupt RIFF chunks
make acpiamltest # AML parser     — tests/acpiaml (Alias/Field namespace correctness + truncated/random DSDT fuzz)
make webptest    # WebP VP8L      — tests/webp (real cwebp round-trips + malformed-input fuzz)
make elftest     # ELF64 loader   — tests/elf/elf_test.c   (validators + load round-trip + every shipped app binary)
make httptest    # HTTP parsers   — tests/http/http_test.c (chunked-transfer decode + header scans)
make kheaptest   # kernel heap    — tests/kheap/kheap_test.c (kmalloc/kfree split/coalesce/grow torture)
make jsonfuzztest # JSON.parse     — tests/jsonfuzz (untrusted/malformed/deep server JSON)
make regexfuzztest # regex engine  — tests/regexfuzz (ReDoS shapes + malformed patterns, compile+search)
make jssrcfuzztest # JS source     — tests/jssrcfuzz (full parse+run pipeline on adversarial script source)
make htmlentfuzztest # HTML entities — tests/htmlentfuzz (decode_entity over untrusted/malformed page bytes)
make htmlattrtest # HTML attrs    — tests/htmlattr (find_attr/has_attr/attr_int over untrusted tag bytes)
make urltest     # URL parser    — tests/url (url_split/resolve_img_url over untrusted URLs)
make colortest   # CSS colour    — tests/color (parse_color over untrusted #hex/rgb/hsl/named tokens)
make csstest     # CSS styles    — tests/css (style_prop scans untrusted style="" declarations)
make csseltest   # CSS selectors — tests/cssel (sel_parse: tag/.class/#id/[attr], bounds-fuzzed)
make boottest    # in-guest boot  — boots the real kernel headless, asserts every bring-up marker (no crash)
make gfxtest     # in-guest gfx   — captures the VGA framebuffer, asserts the desktop actually painted
make browsertest # in-guest web   — launches the Browser from the Apps menu, asserts its home page rendered
```

The last two boot the real kernel under QEMU (unlike the host suites, which
`#include` one `.c` in isolation). They **SKIP cleanly** if QEMU — or, for
`gfxtest`, `socat`/`python3` — is unavailable, so the host-only gate still
passes. `make test` is a related target — the same headless boot but printing
the COM1 log for a human to read, rather than asserting markers.

For *interactive* headless debugging, `tools/osdrive.py` drives the booted
desktop — inject keys (HMP `sendkey`) and absolute-mouse clicks/drags (QMP
`input-send-event`), and grab framebuffer screenshots — e.g.
`tools/osdrive.py --out /tmp -c 'key f9; key ret; sleep 2; shot browser.png'`.
This is how the M558–M561 desktop changes were verified without a display.

You can also run the JS suite inside the OS: `js suite.js` (if copied onto the
disk), or the baked-in demos `js`, `js showcase.js`, `js sample.js`.

## What each suite covers

| Suite | Source under test | What it checks |
|-------|-------------------|----------------|
| `jstest`  | `kernel/js.c` | A golden-output regression of ~60 language/stdlib features (core operators, closures/recursion, arrows, default params, arrays + higher-order methods, strings, objects, `JSON`, template literals, `switch`/`for-of`/`do-while`, `try/catch/finally`); ASan/UBSan-clean, ran-to-completion, matches `tests/js/suite.expected`. Includes the M419 `instanceof` + M420 `+` ToPrimitive fixes, the integer-arithmetic / div-by-zero-guard contract, the ToPrimitive/ToNumber coercion edges (`[]+[]`, `+[]`, `null+1`, `true+true`, string arithmetic), and the M640 bitwise int32 semantics (`& \| ^ << >>` coerce to int32 + mask the shift count, like JS — `1<<31` = -2147483648, `0xFFFFFFFF\|0` = -1, the canonical int32 "hello" hash = 99162322). **Regex (M642-M646):** `\b`/`\B` word boundaries, `\1`..`\9` backreferences (incl. backtracking), the `m` (multiline) + `s` (dotall) flags with correct string-anchored `^`/`$`/`.` defaults, `(?:)` non-capturing groups, `\xHH` escapes, and `(?=)`/`(?!)` lookahead — all golden-locked. **More semantics (M652-M654):** Date constructor normalization (the `new Date(y,m+1,0)` last-day-of-month idiom, month/day overflow, 2100 not a leap year), function-declaration hoisting (forward calls), class private fields `#x` (work + stay distinct from public `x`), built-in Error subtypes `instanceof Error`, `JSON.stringify` function replacers, `ToNumber` whitespace/0x-hex/sign parsing, `String.replace` `$\``/`$'` patterns, and **generators** (`function*`/`yield`/`yield*` + generator methods + `*[Symbol.iterator]()` iterables, eager model — for-of/spread/`.map`/`Array.from`). **async/Promise (M679-M682, synchronous-resolution model)** lives in a SECOND golden run `tests/js/suite-promise.js` (its own fresh arena, since `suite.js` sits ~350KB under the 40MB cap): `new Promise`/`then`/`catch`/`finally`, `Promise.resolve`/`reject`/`all`/`race`/`allSettled`, `instanceof Promise`, and `async function`/expression/arrow/method + `await` (an awaited rejection re-throws so `try/catch` works; `async`/`await` stay ordinary identifiers outside an async body). |
| `imgtest` | `jpeg.c` `png.c` `gif.c` `bmp.c` `inflate.c` | The M422 JPEG DRI out-of-bounds-read PoC, truncated/bare-magic headers, a 120k random-bytes fuzz through all decoders, a direct 120k DEFLATE fuzz (huffman + LZ77), and a BMP 2×2 correctness + 120k BMP fuzz. **Deep-path fuzzing (M635-M637):** the magic-prefix fuzz can't reach a decoder's core (it needs a structurally valid header first), so a real header is built and the *payload* fuzzed, into buffers sized to the EXACT image (tight ASan red-zones): **GIF** decodes a known 2×2 then fuzzes 120k LZW sub-block streams (variable-width codes / dictionary / KwKwK); **JPEG** decodes a real embedded 8×8 baseline then fuzzes 120k entropy scans (Huffman→dequant→IDCT→YCbCr); **PNG** decodes colour types 0/2/4/6 then fuzzes 120k scanlines via a STORED-deflate IDAT (recon_filters' 5 filter types + expand_px); **animated GIF (M639)** decodes a known 3-frame anim then fuzzes 120k mutated multi-frame streams through `gif_decode_anim` (the GCE, disposal restore-to-background, the per-frame snapshot). |
| `x509test`| `kernel/x509.c` | Crafted adversarial DER (4 GB length claim, truncated/indefinite-length, nested headers) + a 200k-iteration fuzz of the `tlv` reader. **Plus SAN/hostname verification (M451):** 4 real openssl-generated certs assert that `find_san` parses subjectAltName dNSNames and `host_matches_cert` applies the RFC 6125 rules — exact + multi-SAN match, case-insensitivity, single-leftmost-label wildcard (matches `a.x.com`, rejects the bare apex `x.com` and `a.b.x.com` and `*.com`), CN fallback only when there is no SAN, and **no** CN fallback when a SAN is present — plus a 400k-iteration mutation fuzz of those certs (byte-flips + truncation) driving `find_san` over near-valid SAN/extension DER, asserting `n_san` stays in `[0,16]` and the matcher never OOBs. |
| `nettest` | `kernel/net.c` | 150k random Ethernet/IPv4/TCP frames through `tcp_recv_seg`, and 150k crafted `seq`/`dlen` through the 96 KB `ooo_store` reassembly buffer (far-future/past/wraparound). Stubs the NIC + timer. |
| `fstest`  | `kernel/fat32.c` | **Read path:** a valid minimal FAT32 image then 12k corrupted copies (BPB/FAT/root-dir bytes randomized) through `mount`/`list`/`read`/`find`/`tree` — locks the M435 `cluster_in_range` guard, the cluster-chain cycle guard, and the dir-recursion depth caps (a corrupt/cyclic FAT must never OOB or hang). **Write path:** 8k accumulating `write`/`delete`/`mkdir` ops (the "heavy repeated writes" scenario) — confirms `alloc_cluster`/`add_entry`/`write_fat`/chain-extension are memory-safe (its known fragility is logical/persistence, not OOB). **Regressions (M634):** `rm <non-empty-dir>` is refused with NO cluster leak — `df` is unchanged by the refused delete, the child stays readable, and a child-then-dir delete reclaims the free count exactly (the M624 fix); and a name that 8.3-truncates ("dl.html"→`DL.HTM`, "verylongname.txt"→`VERYLONG.TXT`) reads back by its long name (the M630 dir_find fix). `#include`s fat32.c and stubs the disk (`ata_read`/`ata_write` → an in-memory image) + `vfs_register`. |
| `kattest`  | `sha256.c` `sha512.c` `aes.c` `aesgcm.c` `chachapoly.c` `hkdf.c` `x25519.c` | **Known-answer** (not fuzz): checks each from-scratch crypto primitive against its published vector — SHA-256/384/512 (FIPS 180-4), HMAC-SHA256 (RFC 4231), HKDF (RFC 5869), AES-128 block (FIPS-197), AES-128-GCM (GCM spec TC1/2), ChaCha20-Poly1305 (RFC 8439 §2.8.2, incl. forged-tag rejection), X25519 (RFC 7748 §5.2/6.1), and **signature verify** — ECDSA P-256/P-384 + RSA-2048 PKCS#1 (vectors openssl-generated + independently re-verified; valid sig accepted, tampered sig rejected), covering the X.509 cert-path-validation crypto. The crypto .c files are compiled as separate translation units (no static collisions); mem* resolves to libc. Locks the TLS 1.3 crypto foundation against silent regression. |
| `bignumfuzztest` | `kernel/bignum.c` | Property-based fuzz of the modular-reduction primitive (`bn_mod`, internal/`static`, reached via `#include`) against Python's arbitrary-precision `%` as an independent oracle: hand-picked edge cases (mod-by-1, a==m, a<m, power-of-two moduli) + a structured sweep of real modulus sizes (P-256/P-384/RSA-2048/RSA-4096, and 2x those for post-multiply reduction) + 600 uniform-random vectors across the full 1..8320-bit range, 1204 vectors total (fixed seed — deterministic). Complements `kattest`'s known-answer signature checks (which only exercise `bn_mod` at two fixed bit-widths on well-formed data) with general-case correctness. |
| `barrettfuzztest` | `kernel/bignum.c` | Property-based fuzz of the M1536 Barrett-reduction fast path (`bn_barrett_init`/`bn_barrett_reduce`, plus `bn_modexp` end-to-end now that it's internally Barrett-accelerated) against the same Python arbitrary-precision oracle: 604 reduce vectors (every real curve/RSA modulus size, the realistic `a=x*y` shape, boundary probes at `a=m²-1`) + 354 `bn_modexp` vectors (e=65537-shaped and ECDSA-n-2-shaped exponents at every real key size, plus the size-ceiling fallback-to-`bn_mod` path), 958 vectors total. `bn_mod` itself is untouched by M1536 (still covered by `bignumfuzztest` above) — this locks the NEW reciprocal-based arithmetic specifically. |
| `stringtest` | `kernel/lib/string.c` | Differential fuzz of `memcpy`/`memset`/`memmove` against a naive, obviously-correct-by-inspection reference (`#include`s the real `string.c`). `memmove` gets an exhaustive sweep of every `(n≤40, src-offset≤48, dst-offset≤48)` combination (98,441 cases — every overlapping-forward/overlapping-backward/disjoint shape at every alignment pairing) plus 20,000 random large-buffer cases; `memcpy`/`memset` each get 20,000 random cases. |
| `deflatetest` | `kernel/deflate.c` `kernel/inflate.c` | Round-trips the from-scratch DEFLATE/gzip compressor through the decoder (literal/fixed/dynamic-Huffman + LZ77 matches) and confirms byte-exact recovery; ASan/UBSan-clean. |
| `pngenctest` | `kernel/png_encode.c` `kernel/png.c` | Round-trips the PNG encoder through the decoder over assorted dimensions/patterns (filters + zlib wrapping), asserting pixel-exact recovery; ASan/UBSan-clean. |
| `ziptest` | `kernel/zip.c` `kernel/inflate.c` | Exact extraction of a multi-entry ZIP (stored + deflated, subdirs, empty/large files) vs the originals, plus a system-`zip`-built archive, plus fuzz: all truncated prefixes, single-byte corruptions, 80k multi-byte mutations, and random buffers must extract cleanly or fail without OOB. |
| `tartest` | `kernel/tar.c` | Exact extraction of a ustar archive vs the originals, plus truncation + single-byte-corruption + 20k random-buffer fuzz; corrupt input must never OOB. |
| `heaptest` | `user/umalloc.c` | Regression of the userspace first-fit allocator (malloc/free/calloc/realloc over an sbrk-backed arena): split/coalesce/reuse correctness, ASan/UBSan-clean. |
| `wavtest` | `kernel/wav.c` | The RIFF/WAVE header parser `wav_parse` (walks untrusted chunk data): valid mono/stereo headers parse correctly, plus a fuzz pass over truncated/corrupt RIFF chunks that must never OOB. |
| `acpiamltest` | `kernel/acpi_aml.c` | The AML bytecode namespace parser: hand-built `Alias`/`Field` DSDT fragments checked against the real `aml_has`/`aml_count` API, plus a fuzz pass over truncated/corrupted/random DSDT bytes that must never OOB. |
| `webptest` | `kernel/webp.c` | The VP8L (WebP Lossless) decoder: pixel-exact round-trips against real `cwebp`-encoded files (gradient/palette/noise/photo shapes, several sizes), plus a malformed-input fuzz pass. Pre-existing coverage that had never been wired into `make check` until M1689. |
| `elftest` | `kernel/elf.c` | The ELF64 loader (the ring-3 trust boundary). A known-good minimal ELF round-trips through `elf_load` (correct entry, file bytes copied to `p_vaddr`, `.bss` tail zeroed, via an mmap-backed guest-memory stub); the pure validators (`elf_check_header`/`elf_check_phdr`) are fuzzed over every truncated prefix, every single-byte header corruption, and 200k random buffers so a malformed ELF can never OOB-read or be accepted with a segment escaping the image or the user range; and **every shipped app binary** (all 29 — shell, the games, DOOM, Quake) is loaded through `elf_load` to guard against a linker/toolchain regression. |
| `httptest` | `kernel/http.c` | The HTTP/1.x response parsers that read untrusted server/CDN bytes. Regression: chunked bodies, hex/large chunk sizes, chunk extensions, truncation, case-insensitive header scans, and `Location:` extraction with buffer-truncation all produce the expected results. Fuzz: every truncated prefix, every single-byte corruption, and 400k random buffers — in-place de-chunking (which memmoves with attacker-controlled hex sizes) never OOBs or returns a length outside the input, and `find_loc` never overruns its output. |
| `kheaptest` | `kernel/kheap.c` | The kernel heap `kmalloc`/`kfree`/`kzalloc` (underlies every kernel allocation), run against a real mmap'd arena. 400k random alloc/free ops with a per-block byte pattern re-verified each pass (catches any overlap/corruption), `kzalloc` zeroing, repeated `grow_heap()`, and a free-list walk asserting the blocks tile `[base, heap_end)` exactly with no gaps or cycles; ASan/UBSan-clean. |
| `jsonfuzztest` | `kernel/js.c` (`nat_json_parse`) | The engine's `JSON.parse` parses untrusted server/API JSON in-kernel. Drives the parser directly (js.c #included with `JS_NO_MAIN`) over every truncated prefix + single-byte corruption of a rich document, 300k random punctuation-biased buffers, and 1..5000-deep bracket nesting (must hit the depth guard, not overflow); valid documents confirm correct parsing. Exactly-sized buffers so any over-read red-zones. |
| `regexfuzztest` | `kernel/js.c` (`re_compile`/`re_search`) | The regex engine compiles untrusted patterns and runs them on untrusted strings (historically the source of two critical matcher stack-overflows). ReDoS shapes (`(a+)+$`, `(a*)*`, deep groups, huge `{n,m}`, unterminated classes) against long `a` runs + 200k random pattern/subject pairs; the step-budget + depth guard must keep every run bounded with no OOB/overflow/hang. |
| `jssrcfuzztest` | `kernel/js.c` (`js_run_doc`) | The full parse+run pipeline on untrusted SOURCE — the browser's `<script>`/`javascript:`. Truncations + sampled corruptions of a rich script, 200k random token-biased buffers, and 1..4000-deep nesting through the lexer/parser (MAXDEPTH guard) and the loop/recursion/arena run guards; adversarial source must fail gracefully, never OOB/overflow/hang. |
| `htmlentfuzztest` | `kernel/htmlentity.c` (`decode_entity`) | The HTML character-reference decoder reads untrusted page bytes (`&amp;`, `&#NNN;`, `&#xHH;`, named). Known entities decode correctly; then every truncated prefix + single-byte corruption of a battery (incl. huge/overflowing numeric refs and bare `&`/`&#`/`&#x`) + 300k random entity-char-biased buffers, in exactly-sized buffers so any over-read red-zones. |
| `htmlattrtest` | `kernel/htmlattr.c` (`find_attr`/`has_attr`/`attr_int`/`find_href`) | The HTML attribute scanners the browser runs over a hostile server's tag bytes. Each takes a length-bounded slice `a[0..n)`; regression checks quoted/single-quoted/bare values, token-boundary matching (`href` not matched inside `data-href`), boolean attrs, and `attr_int` clamp/non-numeric. Then every truncated prefix + single-byte corruption of a tag battery + 400k random attribute-char-biased buffers, in exactly-sized buffers so any over-read past the slice red-zones. Split out of browser.c (M566) to be fuzzable in isolation. |
| `urltest` | `kernel/url.c` (`url_split`/`resolve_img_url`) | The URL splitter/resolver the browser runs over untrusted page bytes — the address bar, `<a href>`, `<img src>`, redirect `Location`. Both write into fixed caller buffers; regression checks host/path splitting, dir-/root-/protocol-relative `<img src>` resolution against a base, absolute-kept, and file:/data: rejection. Then truncations + 400k random URLs through both with **tiny** host/out buffers, so a too-long host or resolved URL that would overrun red-zones under ASan. Split out of browser.c (M580). |
| `colortest` | `kernel/color.c` (`parse_color`) | The CSS colour parser the browser runs over untrusted page bytes (a `style=""` attribute or `<style>` value): `#rgb`/`#rrggbb`, `rgb()/rgba()`, `hsl()/hsla()`, and named colours. Reads a length-bounded slice `v[0..vl)` with clamped rgb/hsl integer math; regression checks each form (incl. `50%`→127, case-insensitive names, alpha-ignored), then truncations + single-byte corruptions of a battery + 400k random colour-char buffers in exactly-sized buffers so any over-read red-zones. Split out of browser.c (M581). |
| `csstest` | `kernel/cssprop.c` (`style_prop`) | The inline-style declaration scanner the browser builds every per-property style helper (colour, font-weight, text-align, font-size, …) on. It walks an untrusted `style=""`/`<style>` slice `s[0..n)` for a `prop:` declaration at a property boundary (so `color` isn't matched inside `background-color`) and returns the trimmed value span. Regression checks boundary matching, value trimming, and shorthand; then truncations + single-byte corruptions of a battery + 400k random style buffers in exactly-sized buffers so any over-read red-zones. Split out of browser.c (M583). |
| `csseltest` | `kernel/include/cssel.h` (`sel_parse`) | The CSS simple-selector parser the browser runs over untrusted `<style>`/inline selectors — an optional tag name then any run of `.class` / `#id` / `[attr]` qualifiers (tag/attr lowercased, `=value` ignored), failing CLOSED on any unsupported combinator/pseudo. Regression pins the parse contract (incl. the 15-char-tag cap and >15 overflow → fail-closed); then a 400k fuzz over exactly-sized NUL-terminated selectors red-zones any read past the input and asserts each output field stays NUL-terminated within its fixed size. Extracted from browser.c (M688) so the bounds scan is host-testable like the kernel's other parsers. |
| `shgreptest` | `user/shgrep.h` (`gr_match`) | The shell `grep` regex matcher (`^ $ . *`, `[..]` classes with ranges/negation, `\` escapes, `-i` case fold; Kernighan/Pike style). A pattern with no metacharacters behaves like a literal substring search. 33 regression cases (literal/anchors/`.`/`*`/ranges/negation/`[..]*`/leading-dash/escape/case-insensitive) + 300k metachar-biased pattern×text fuzz, ASan/UBSan, asserting bounded reads. Extracted from shell.c (M671) so the most complex shell-only logic is host-tested like the kernel's parsers. |
| `svgtest`  | `kernel/svg.c` | The from-scratch integer-only SVG rasterizer (parses untrusted web XML in-kernel). 8 unit cases that must render correctly (rect, viewBox scaling, circle + cubic-bezier path, stroked polygon, named colors, **affine transforms** — `<g>`-group + per-shape `translate`/`scale`/`rotate`/`matrix`, nested-group composition, and the CTM correctly restored after `</g>` — **paint inheritance** — `fill`/`stroke` inherited from the root `<svg>`/enclosing `<g>`, per-shape override, the `inherit` keyword, and inherited paint restored after `</g>` — **and opacity** — `fill-opacity`/`opacity` per shape, group `<g opacity>` inherited, group×element compounding, and `in_alpha` restored after `</g>` — **and gradients** — a linear red→blue across the box + a radial white→black centre→edge, exercising the `<defs>` pre-pass, `fill=url(#id)` resolution and per-pixel evaluation) plus ~520k in-suite fuzz iterations: 100k random bytes, 100k mutations of valid SVG, 320k structured (random shape/path/attr/**transform**/**fill**/**opacity**/**gradient** trees), and adversarial inputs (deep nesting, huge coordinate counts, a huge-coordinate gradient that would overflow the projection's int64 intermediate if unclamped, truncation) — plus a separate **6M-iteration gradient-focused fuzz** run during review. Locks bounds-safety on the scanline-fill crossings buffer, the per-shape point list in caller scratch, the `<g>` transform + paint + opacity stacks, the gradient table/stop caps + the `grad_color_at` fixed-point, and `parse_num` against the UB bugs the author fuzz first caught (negative shifts, `num<<16` int64 overflow). |
| `boottest` | the **whole kernel + driver stack** (`tests/run-boot-tests.sh`) | Unlike every row above (which `#include`s one `.c` in isolation), this boots the *real* `build/kernel32.elf` headless under QEMU, captures COM1, and asserts all 11 required bring-up markers print in order with no crash: core bring-up (PMM/VMM/IDT), the preemptive scheduler, per-process address-space isolation, PCI enumeration, the **ACPI AML method-evaluation VM** (recursion/`If`/`While`), the **eBPF JIT** (bytecode compiled to native x86-64, validated == the interpreter), the e1000+ARP+ICMP stack (ping to the SLIRP gateway), FAT32 mount, AC'97 audio bring-up, USB UHCI+tablet, and reaching `desktop_run()`; and that no `panic`/`unhandled exception`/`page fault`/`#GP` appears anywhere. Two **internet-dependent** checks are informational (non-fatal — offline hosts stay green): a real HTTP GET to live example.com, and — exercising the whole **from-scratch TLS 1.3 stack** end to end — a real HTTPS GET whose `certverify=ok` confirms X25519 ECDHE + AEAD + X.509 chain validation to a trusted root + ECDSA/RSA `CertificateVerify`. Re-established now that QEMU runs again (a SIGSTKFLT launch failure had blocked in-guest verification for many milestones). |
| `gfxtest`  | the **compositor / framebuffer / font stack** (`desktop.c`/`fb.c`/`fbcon.c`/`font.c`/`vga.c`) | The serial boot above proves the kernel *reached* the desktop, not that anything *painted*. This boots headless, waits for the desktop hand-off, captures the emulated VGA framebuffer via the QEMU monitor's `screendump` (HMP over a unix socket driven by `socat`), and asserts the PPM looks like a real painted desktop: 1024×768 (the desktop mode-set ran, not the 640×480 console), ≥40 distinct colors, and no single color >98% (catches an all-black hang). Retries the screendump to absorb paint-timing jitter. |
| `browsertest` | the **browser HTML render pipeline** (`browser.c`'s `parse_html` + CSS + font/layout) | `parse_html` walks untrusted page bytes but is too coupled to `browser_t` to fuzz in isolation, so it's guarded end-to-end instead: boot, open the Apps menu (`sendkey f9`) and launch the Browser (`sendkey ret` — it's item 0), then assert its built-in **network-free** home page actually rendered — `screendump` shows ≥50k pure-white pixels (a white-backgrounded page), which the dark desktop never has (~900). Covers the menu→`spawn_browser`→`parse_html`→CSS→font/layout path. |

Beyond the suites tabled above, `make check` also runs a **device-driver fleet**
in-guest — each boots the real kernel headless with the device attached and
asserts its bring-up plus a read/write round-trip, with no fault: `gdbstubtest`
(GDB remote-serial stub: attach, read/symbolize regs, breakpoint, single-step,
memory round-trip), `rtl8139test`/`virtionettest` (NICs — driver bind, MAC read,
ARP+ICMP over the link), `virtioblktest`/`nvmetest`/`floppytest`/`idedmatest`/`parttest`/`blockdevtest`
(storage — known sectors read back + write round-trip; MBR/GPT parse; the block
registry), `raidtest` (device-mapper **RAID-0/1/5 + a linear LV** over 3 SATA
disks on an AHCI HBA — fan-out mirror, round-robin stripe, single-disk-fault
parity reconstruct, boundary-spanning concat), `virtiorngtest`/`virtioconsoletest`/`virtiogputest`/`svgatest`
(virtio entropy + console + GPU, and the VMware SVGA-II display), and
`usbstoragetest`/`usbkbdtest`/`ehcitest`/`xhcitest`/`hdatest` (USB BOT/SCSI mass
storage, USB HID keyboard, EHCI/xHCI host controllers, Intel HD-audio). Host-side
it also runs the **shell-helper** fuzz suites split out of `shell.c`/`calc.c`
(`shsedtest`, `shmathtest`, `shsplittest`, `shbracetest`, `shquotetest`,
`calctest`, `normpathtest`, `completetest`) and the `ext2test`/`xattrtest`/`iso9660test`
filesystem suites.

Two in-guest tests exercise the **inbound** side of the from-scratch TCP stack by
forwarding a host port into the guest and connecting from the host: `httpdtest`
(the one-shot HTTP server — dashboard, a file by path, a 404) and `netcontest`
(the **network debug console**, `-append netcon` — a *persistent* multi-command
session: `echo`/`mem`/`cpu`/`uptime`/`ip`/`ps`/`dmesg`/`pci`/`ls`/`cat` each
round-trips over one held connection, proving the real-hardware remote-console
lifeline works end to end).

## Validated to catch regressions

Each fuzz harness is **verified to fail** when its guard is removed:

- `imgtest` aborts (ASan) if the JPEG DRI `seglen >= 2` guard is removed; the deep-path fuzzes (M635-M637) abort (heap-buffer-overflow) on a planted over-write in each core — GIF `lzw_decode` (drop the `out < idx_cap` guard), JPEG `idct_block` (`out[stride*8]`), PNG output (`out + y*width*4 + 4`), animated GIF `gif_decode_anim` (drop the per-frame `il+iw>W || it+ih>H` bound) — each confirmed red-then-green (the tight per-image buffers are what make the masked-by-a-4MB-scratch write visible).
- `x509test` aborts if `tlv`'s `len > end-p` bound is removed.
- `nettest` aborts if `ooo_store`'s `off > OOO_CAP - dlen` bound is removed.
- `fstest` aborts (ASan stack-overflow) if fat32's dir-recursion depth caps are removed (a cyclic directory recurses unbounded); the M634 regressions go red if either fix is reverted — restore the unconditional `free_chain` on a non-empty dir and "rm of NON-EMPTY dir must be refused" fails; restore `dir_find`'s ieq-only match and "read 'dl.html' by long name" fails — both confirmed red-then-green.
- `kattest` is itself the regression check — any change to a primitive's output fails the byte-exact vector comparison; the AEAD forged-tag case also verifies the reject path.
- `jstest` diffs against the golden, so any output change fails.
- `svgtest` aborts (ASan/UBSan) if a bounds guard is removed (e.g. the scanline crossings cap or the point-list cap) and fails loudly if a unit case stops rendering its expected pixels; UBSan also re-catches the original `parse_num` negative-shift/overflow if reintroduced.
- `elftest` fails loudly if `elf_check_header`'s program-header-table bound is removed (a phdr read then runs past the image — the harness flags the broken in-bounds promise).
- `httptest` aborts (ASan stack-buffer-overflow) if `http_dechunk`'s `sz > room` truncation clamp is removed (the in-place memmove then runs past the body).
- `kheaptest` aborts (per-block pattern mismatch) if `kmalloc` stops marking a block used (`b->free = 0`) — the same block is handed out twice and the live allocations overlap.
- `jsonfuzztest` aborts (ASan heap-buffer-overflow at `jp_string`) if the string scanner's `jp_end` bound is removed (an unterminated string over-reads).
- `regexfuzztest` aborts (ASan stack-overflow in `re_run`) if the matcher's `depth>900` guard is removed (a pathological pattern recurses unbounded).
- `jssrcfuzztest` exercises the same ASan red-zone + termination-guard machinery proven by the two above on the full lexer/parser/eval pipeline.
- `htmlentfuzztest` aborts (ASan buffer-overflow in `decode_entity`) if its `n < maxlen` scan bound is removed (an entity with no `;` then reads past the input).
- `htmlattrtest` aborts (ASan heap-buffer-overflow in `find_attr`) if its `i + nl <= n` loop bound is loosened to `i < n` (the name compare then reads past the slice) — verified.
- `urltest` aborts (ASan heap-buffer-overflow in `url_split`) if its `hi < hostsz - 1` host bound is loosened to `hi < hostsz + 1` (a long host then writes past the buffer) — verified.
- `colortest` aborts (ASan heap-buffer-overflow in `parse_color`) if the `#hex` loop bound `i < vl` is loosened to `i <= vl` (it then reads one byte past the slice) — verified.
- `csstest` aborts (ASan heap-buffer-overflow in `style_prop`) if its `i + plen + 1 <= n` loop bound is loosened to `i + plen <= n` (the `s[i+plen]` colon check then reads at offset n) — verified.
- `shgreptest` fails the regression battery if a `gr_match` semantic regresses (e.g. dropping the `[..]` class branch, the `*` star, or an anchor), and the 300k fuzz aborts under ASan/UBSan on any over-read past the pattern/text.
- `csseltest` fires "tag field overran" if `sel_parse`'s tag loop bound `k<15` is loosened to `k<16` (the NUL then lands one past `tag[16]`), and the 400k fuzz aborts under ASan if any `while (s[i] && …)` drops its NUL check and reads past the exactly-sized selector — verified.
- `boottest` fails (lists the missing marker, exit 1) if any bring-up step stops printing its marker — verified by pointing `QEMU=true` at it (empty boot log → every marker MISSING).
- `gfxtest`'s `ppm_check.py` is verified as a real oracle: an all-black 1024×768 frame → FAIL (1 distinct color), a 640×480 console frame → FAIL (resolution below the desktop mode), a real painted desktop → PASS.
- `browsertest`'s white-pixel assertion is verified as a real oracle: a colorful-but-no-white frame (40k colors, passes the diversity/hang checks) → FAIL on `--white 50000` (0 white pixels); the rendered home page → PASS (~236k). So if the browser failed to launch/render, the still-dark desktop (~900 white) fails it.

## Not covered here

The symmetric/hash/KDF/DH crypto **and** the RSA/ECDSA signature-verify are now
correctness-locked by `kattest` (above); the `bignum` that backs them is further
exercised via `x509test`'s cert-chain validation and the live handshakes. `tls.c`'s handshake-message parsers are intentionally
*not* fuzzed by a committed harness: a naive random fuzz fast-fails at
`x509_parse` / bails without a seeded leaf key (so it exercises nothing), and a
meaningful one needs valid-DER + valid-key seeds — disproportionate for code
that the manual security review covered thoroughly and whose cert DER parser is
already deeply fuzzed by `x509test`. The handshake path *is* now exercised end
to end at every boot (and informationally by `boottest`): the kernel completes a
real TLS 1.3 HTTPS GET to example.com — full handshake, chain validation to a
trusted root, and `CertificateVerify` — so a regression that breaks the live
handshake is caught even though there's no committed record-layer fuzzer. See
[../docs/422-untrusted-input-security-audit.md](../docs/422-untrusted-input-security-audit.md).
