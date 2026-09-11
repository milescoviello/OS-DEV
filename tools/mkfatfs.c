/*
 * mkfatfs.c — a tiny host-side FAT32 image builder.
 *
 * Runs on the HOST (built with the system gcc), not in the kernel. It writes a
 * small but valid FAT32 filesystem image with a few files in the root
 * directory, which QEMU then attaches as a virtual disk. We build the image
 * ourselves (rather than mkfs.fat + mtools) so the project is self-contained
 * and the on-disk layout is guaranteed to match our kernel reader.
 *
 *   usage: mkfatfs <output.img>
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SECTOR        512
#define TOTAL_SECTORS 131072        /* 64 MiB image (DOOM IWAD ~4 MB + Quake pak ~18 MB + demos) */
/* Reserve a tail region OUTSIDE the FAT32 volume for the write-ahead journal +
 * its crash-recovery self-test (M1865). The image stays TOTAL_SECTORS, but the
 * FAT32 filesystem is told it only owns FS_SECTORS, so the last JOURNAL_SECTORS
 * sectors are physically present (ata can read/write them) yet the FS never
 * touches them — a safe home for the journal. 128 sectors (64 KiB) >> the
 * journal's minimum (JRNL_MINLEN=64) plus room for the self-test's target
 * blocks. The kernel finds this region as [boot-sector-total_sec, disk_sectors). */
#define JOURNAL_SECTORS 128
#define FS_SECTORS      (TOTAL_SECTORS - JOURNAL_SECTORS)
#define RESERVED      32
#define NUM_FATS      2
#define SPC           1             /* sectors per cluster */

static uint8_t *img;

static void put16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

/* The files baked into the root directory. Names are 8.3, space-padded to 11. */
static const struct {
    const char *name83;
    const char *content;
} files[] = {
    { "README  TXT", "OS-DEV: a from-scratch x86_64 OS.\nThis file lives on a FAT32 disk read by our own driver.\n" },
    { "HELLO   TXT", "Hello from a real file on a virtual disk!\n" },
    { "MOTD    TXT", "Milestone 10 reached: VFS + FAT32 + ATA driver.\nTry: ls   and   cat hello.txt\n" },
    { "PATCHME TXT", "line one\nline two\nline three\n" },   /* target for the `patch` command demo (M1731) */
    { "PATCHME PAT", "--- PATCHME.TXT\n+++ PATCHED\n@@ -1,3 +1,3 @@\n line one\n-line two\n+LINE TWO CHANGED\n line three\n" },
    { "DEMO    SH ", "# OS-DEV shell scripting demo -- run it with:  source DEMO.SH\n"
                     "echo == OS-DEV shell scripting ==\n"
                     "OS=OS-DEV\n"
                     "echo variable OS is $OS  (bare NAME=value, sh-style)\n"
                     "echo arithmetic six times seven is $((6 * 7))\n"
                     "echo ternary the larger of 8 and 3 is $((8 > 3 ? 8 : 3))\n"
                     "echo command substitution says $(echo it-works)\n"
                     "alias say=echo\n"
                     "say aliases work too\n"
                     "greet() { echo hello $1 -- from a function; }\n"
                     "greet world\n"
                     "args() { echo function got $# args: $@; }\n"
                     "args alpha beta gamma\n"
                     "pos() { if test $1 -gt 0; then return 0; fi; return 1; }\n"
                     "pos 5 && echo return-value works: 5 is positive\n"
                     "grade() { if test $1 -ge 90; then echo A; elif test $1 -ge 80; then echo B; else echo C; fi; }\n"
                     "echo elif: 85 grades $(grade 85)\n"
                     "case red in red) echo case: matched red;; *) echo case: other;; esac\n"
                     "echo default param is ${MISSING:-a-fallback}\n"
                     "path=/usr/local/bin\n"
                     "echo basename ${path##*/} dirname ${path%/*} length ${#path}\n"
                     "echo substitute all slashes: ${path//\\//-}\n"
                     "echo substring middle three: ${path:5:5}\n"
                     "echo assign-default: ${TMPDIR:=/tmp} then TMPDIR is now $TMPDIR\n"
                     "for n in 1 2 3; do echo for-loop n is $n; done\n"
                     "if test 10 -gt 3; then echo if-test ten is greater than three; fi\n"
                     "i=1\n"
                     "while test $i -le 3; do echo while-loop i is $i; i=$((i + 1)); done\n"
                     "for ((k=1; k<=3; k++)); do echo c-style-for k is $k; done\n"
                     "j=1\n"
                     "until test $j -gt 3; do echo until-loop j is $j; j=$((j + 1)); done\n"
                     "echo tilde: bare ~ expands to root and ~/docs to a path\n"
                     "set -x\n"
                     "echo this line is traced\n"
                     "set +x\n"
                     "((sq = 6 * 7)); echo arithmetic command: 6 times 7 is $sq\n"
                     "echo == demo complete -- type help for more ==\n" },
    { "WHRD    SH ", "# while read demo -- run it with:  source WHRD.SH\n"
                     "echo alpha > /tmp/LINES.TXT\n"
                     "echo beta >> /tmp/LINES.TXT\n"
                     "echo gamma >> /tmp/LINES.TXT\n"
                     "echo single var:\n"
                     "while read x; do echo got: $x; done < /tmp/LINES.TXT\n"
                     "echo one two three > /tmp/COLS.TXT\n"
                     "echo four five six >> /tmp/COLS.TXT\n"
                     "echo multi var:\n"
                     "while read a b; do echo a=$a b=$b; done < /tmp/COLS.TXT\n" },
    { "SEDI    SH ", "# sed -i (in-place edit) demo -- run it with:  source SEDI.SH\n"
                     "echo one two three > /tmp/SEDT.TXT\n"
                     "echo sedi before:; cat /tmp/SEDT.TXT\n"
                     "sed -i 's/two/TWO/' /tmp/SEDT.TXT\n"
                     "echo sedi after:; cat /tmp/SEDT.TXT\n" },
    { "HEREDOC SH ", "# here-doc / here-string demo -- run it with:  source HEREDOC.SH\n"
                     "NAME=world\n"
                     "echo == here-string ==\n"
                     "cat <<< \"hi $NAME\"\n"
                     "echo == here-doc expanded ==\n"
                     "cat << EOF\n"
                     "line one\n"
                     "hello $NAME\n"
                     "EOF\n"
                     "echo == quoted delim is literal ==\n"
                     "cat << 'Q'\n"
                     "literal $NAME here\n"
                     "Q\n"
                     "echo == dash strips leading tabs ==\n"
                     "cat <<- END\n"
                     "\tindented (tab gone)\n"
                     "END\n"
                     "echo == here-doc to a file ==\n"
                     "cat << D > /tmp/HD.TXT\n"
                     "saved A\n"
                     "saved B\n"
                     "D\n"
                     "cat /tmp/HD.TXT\n"
                     "echo == done ==\n" },
    { "GREPW   SH ", "# grep -w / -q demo -- run it with:  source GREPW.SH\n"
                     "echo cat > /tmp/G.TXT\n"
                     "echo category >> /tmp/G.TXT\n"
                     "echo bobcat >> /tmp/G.TXT\n"
                     "echo one cat two >> /tmp/G.TXT\n"
                     "echo == grep -w cat (whole word only) ==\n"
                     "grep -w cat /tmp/G.TXT\n"
                     "echo == grep -q cat ==\n"
                     "grep -q cat /tmp/G.TXT\n"
                     "echo status=$?\n"
                     "echo == grep -q dog ==\n"
                     "grep -q dog /tmp/G.TXT\n"
                     "echo status=$?\n" },
    { "SETE    SH ", "# set -e (errexit) demo -- run it with:  source SETE.SH\n"
                     "echo sete: start\n"
                     "set -e\n"
                     "if false; then echo unreached; fi\n"
                     "echo sete: a failing if-condition is exempt (still here)\n"
                     "false || echo sete: a guarded failure is exempt too\n"
                     "false\n"
                     "echo sete: THIS MUST NOT PRINT\n" },
    { "DEMO    C  ", "// DEMO.C -- compiled AND run inside OS-DEV by our own C compiler.\n"
                     "//   try it with:   cc DEMO.C\n"
                     "// c4 grammar: int/char, pointers, if/else, while, return, recursion, printf.\n"
                     "\n"
                     "int fact(int n) {\n"
                     "  if (n <= 1) return 1;\n"
                     "  return n * fact(n - 1);\n"
                     "}\n"
                     "\n"
                     "int fib(int n) {\n"
                     "  if (n < 2) return n;\n"
                     "  return fib(n - 1) + fib(n - 2);\n"
                     "}\n"
                     "\n"
                     "int main() {\n"
                     "  int i;\n"
                     "  int s;\n"
                     "  printf(\"Hello from a C program compiled INSIDE OS-DEV!\\n\");\n"
                     "  printf(\"5! = %d\\n\", fact(5));\n"
                     "  s = 0; i = 1;\n"
                     "  while (i <= 10) { s = s + i; i = i + 1; }\n"
                     "  printf(\"sum 1..10 = %d\\n\", s);\n"
                     "  printf(\"fib:\");\n"
                     "  i = 0;\n"
                     "  while (i < 10) { printf(\" %d\", fib(i)); i = i + 1; }\n"
                     "  printf(\"\\n\");\n"
                     "  return 0;\n"
                     "}\n" },
    { "PRE     HTM", "<h2>Preformatted</h2><p>This paragraph is normal flow: whitespace    collapses and the text wraps to the window width as usual.</p><pre>function hello() {\n    return 1 + 2;      // spaces   kept\n\n    blank line above is preserved\n}</pre><p>Back to normal flow after the pre block.</p>" },
    { "CSSWS   HTM", "<style>.code{white-space:pre}</style><h2>CSS white-space</h2><p>Normal flow:   these    spaces collapse\nand this newline becomes a single space, wrapping as usual.</p><div style=\"white-space:pre\">white-space:pre keeps    spaces\nAND\nnewlines   intact\n    (indented line too).</div><p style=\"white-space:pre-wrap\">pre-wrap:   spaces kept\nand the newline above is kept.</p><div class=\"code\">.code rule:   spaces kept\nand newline kept via a &lt;style&gt; class.</div><p>Back to normal collapsing flow after the white-space blocks.</p>" },
    { "MARGIN  HTM", "<style>.gap{margin-top:55px} .ind{margin-left:40px}</style><h2>CSS margins</h2><p>Para 1 &mdash; no margin, default spacing.</p><p style=\"margin-top:60px\">Para 2 has inline <b>margin-top:60px</b> &mdash; a big gap should sit above it.</p><p style=\"margin-top:10px\">Para 3 has margin-top:10px &mdash; a small gap.</p><p>Para 4 &mdash; no margin again.</p><p class=\"gap\">Para 5 uses a <b>&lt;style&gt; rule</b> <code>.gap{margin-top:55px}</code> &mdash; a big gap from a stylesheet rule, not inline.</p><p style=\"padding-top:45px\">Para 6 has <b>padding-top:45px</b> &mdash; inner top space (also lifts it down).</p><p style=\"margin-left:48px\">Para 7 has <b>margin-left:48px</b> &mdash; this whole paragraph is indented to the right, and wrapped lines stay indented too, just like a blockquote.</p><p class=\"ind\">Para 8 is indented by a <b>&lt;style&gt; rule</b> <code>.ind{margin-left:40px}</code> &mdash; a stylesheet class, not inline.</p><div style=\"margin:40px\">A div with <b>margin:40px</b> (all sides &mdash; spaced above AND indented).</div><p style=\"margin:6px 60px\">Para 9 uses the <b>margin:6px 60px</b> shorthand (vertical horizontal) &mdash; indented 60px from a 2-value shorthand.</p><div style=\"background:#cfe8ff\">This div has <b>background:#cfe8ff</b> &mdash; the colour fills the whole line band (a block background), not just behind the words.</div><p>An inline <span style=\"background:#ffe080\">highlighted span</span> background stays behind its text only.</p>" },
    { "BORDER  HTM", "<style>.card{border:2px solid #8800cc}</style><h2>CSS borders</h2><div style=\"border:2px solid #c00\">This div has <b>border:2px solid #c00</b>. It should be drawn as ONE red rectangle around the whole block &mdash; even though this sentence is long enough to wrap across several lines, the border must outline the entire box, not draw a separate box around each wrapped line.</div><p>A plain paragraph between the two bordered blocks (no border here).</p><div style=\"border:1px solid #0088cc\">A thinner blue 1px border box.<div style=\"border:3px solid #00aa00\">A nested green 3px border inside the blue one &mdash; nested boxes should each get their own outline.</div>Back in the blue box after the nested one.</div><div class=\"card\">This box gets its purple border from a <b>&lt;style&gt; rule</b> <code>.card{border:2px solid #8800cc}</code> &mdash; not an inline style, proving stylesheet-rule borders work too.</div><div style=\"border-bottom:2px solid #c00\">This div has only <b>border-bottom</b> &mdash; a divider line under the text, with nothing on the other three sides.</div><div style=\"border-top:3px solid #00aa00\">And this one has only <b>border-top</b> &mdash; a thick rule above the block.</div><div style=\"margin-left:50px;border:2px solid #cc8800\">This bordered div also has <b>margin-left:50px</b> &mdash; its border box should be indented to start 50px from the left, hugging the text, not span the full width.</div><div style=\"border:2px solid blue\">A box bordered with the <b>named colour</b> blue (not a #hex value) &mdash; named CSS colours work in borders too.</div>" },
    { "FLEX    HTM", "<style>.row{display:flex}</style><h2>Flexbox (display:flex)</h2><p>Three items in a <b>display:flex</b> row &mdash; they should sit side by side on one line, spaced by <b>gap:40px</b>:</p><div style=\"display:flex;gap:40px\"><div>Apple</div><div>Banana</div><div>Cherry</div></div><p>The same three divs <b>without</b> flex (default block flow) stack vertically instead:</p><div><div>Apple</div><div>Banana</div><div>Cherry</div></div><p>And a flex row from a <b>&lt;style&gt; rule</b> <code>.row{display:flex}</code> (not inline):</p><div class=\"row\"><div>Red</div><div>Green</div><div>Blue</div></div><p>A <b>flex-direction:column</b> flex stacks vertically (not a row):</p><div style=\"display:flex;flex-direction:column\"><div>Top</div><div>Middle</div><div>Bottom</div></div><p><b>justify-content:center</b> &mdash; the row is centred in the content area:</p><div style=\"display:flex;justify-content:center\"><div>One</div><div>Two</div><div>Three</div></div><p><b>justify-content:flex-end</b> &mdash; the row is pushed to the right:</p><div style=\"display:flex;justify-content:flex-end\"><div>One</div><div>Two</div><div>Three</div></div><p><b>justify-content:space-between</b> &mdash; items spread to the edges:</p><div style=\"display:flex;justify-content:space-between\"><div>Left</div><div>Middle</div><div>Right</div></div><p>Back to normal flow after the flex container.</p>" },
    { "MAXW    HTM", "<h2>max-width column</h2><p>This paragraph has no max-width, so its lines run the full width of the content area &mdash; long lines that are harder to read on a wide window, the way most of the body text on this OS renders by default.</p><div style=\"max-width:380px;margin:0 auto\"><p>This block sets <b>max-width:380px; margin:0 auto</b>, so its text wraps in a narrower column that is centred in the window with equal margins on each side &mdash; the readable-article pattern used by most blogs, docs and news sites. Notice the lines are shorter and the whole block sits in the middle.</p></div><p>And the text returns to full width again after the max-width container closes.</p>" },
    { "CSSIMP  HTM", "<style>.imp1{color:#c00 !important} #id1{color:#080} #id2{color:#080} .norm2{color:#c00} .impbg{background:#e88 !important} #id3{background:#8e8}</style><h2>CSS !important</h2><p>The <code>!important</code> flag makes a declaration win over normal rules <b>regardless of specificity or source order</b>.</p><p id=\"id1\" class=\"imp1\"><b>1.</b> This line must render <b>RED</b>. A low-specificity class rule <code>.imp1{color:#c00 !important}</code> beats a higher-specificity <code>#id1{color:#080}</code> id rule that appears <i>later</i> in the stylesheet &mdash; because it is <code>!important</code>.</p><p id=\"id2\" class=\"norm2\"><b>2.</b> Control: this line must render <b>GREEN</b>. Here neither rule is <code>!important</code>, so the higher-specificity <code>#id2{color:#080}</code> wins over <code>.norm2{color:#c00}</code> exactly as the normal cascade requires &mdash; proving the flag is what changed case 1, not a broken cascade.</p><div id=\"id3\" class=\"impbg\"><b>3.</b> This block must have a <b>RED background</b>: <code>.impbg{background:#e88 !important}</code> overrides the higher-specificity <code>#id3{background:#8e8}</code> green background.</div>" },
    { "DISPCAS HTM", "<style>.lo{display:none} #shown{display:flex;gap:30px}</style><h2>display cascade &mdash; specificity</h2><p>The div below matches <b>both</b> a low-specificity <code>.lo{display:none}</code> rule (specificity 10) and a higher-specificity <code>#shown{display:flex}</code> rule (specificity 100). <code>display:flex</code> wins on specificity, so the div must render as a <b>visible flex row</b> with LEFT and RIGHT side by side &mdash; not hidden. (Before M1789 a stale hidden flag from the losing <code>display:none</code> rule wrongly hid it.)</p><div id=\"shown\" class=\"lo\"><div>LEFT</div><div>RIGHT</div></div><p>This paragraph must appear <b>below</b> the visible LEFT / RIGHT flex row.</p>" },
    { "ATTRSEL HTM", "<style>p[data-k=a]{color:#c00} p[data-k=b]{color:#080} a[href^=https]{color:#08c} span[title$=end]{background:#ffe080}</style><h2>CSS attribute-value selectors</h2><p>These elements share attribute <b>names</b> but differ by <b>value</b>. Before M1793 the value was ignored (both <code>data-k</code> lines rendered the same); now the value is matched:</p><p data-k=\"a\">1. This line is <b>RED</b> &mdash; it matches <code>p[data-k=a]</code> (exact value).</p><p data-k=\"b\">2. This line is <b>GREEN</b> &mdash; it matches <code>p[data-k=b]</code>, not the red rule (proof the value, not just the name, is matched).</p><p><a href=\"https://example.com\">3. This link is BLUE</a> via <code>a[href^=https]</code> &mdash; the <b>^=</b> prefix operator.</p><p>4. This has a <span title=\"the end\">highlighted span</span> via <code>span[title$=end]</code> &mdash; the <b>$=</b> suffix operator.</p>" },
    { "CANVAS  HTM", "<h2>Canvas 2D drawing</h2><p>This 260&times;140 canvas is drawn entirely by a page script via the JS 2D context &mdash; <code>fillRect</code>, <code>strokeRect</code>, <code>clearRect</code> and <code>moveTo</code>/<code>lineTo</code> lines (M1796/M1797):</p><canvas id=\"c\" width=\"260\" height=\"140\"></canvas><script>var x=document.getElementById('c').getContext('2d'); x.fillStyle='#e0e0ff'; x.fillRect(0,0,260,140); x.fillStyle='#cc0000'; x.fillRect(20,20,60,40); x.clearRect(32,30,20,16); x.strokeStyle='#0000cc'; x.strokeRect(100,20,60,40); x.strokeStyle='#008800'; x.moveTo(180,18); x.lineTo(244,42); x.lineTo(180,42); x.lineTo(244,18); x.strokeStyle='#aa4400'; x.moveTo(20,74); x.lineTo(244,74); x.strokeStyle='#0000cc'; x.strokeRect(0,0,259,139); x.fillStyle='#000088'; x.fillText('Canvas 2D!',80,110); x.strokeStyle='#aa00aa'; x.lineWidth=3; x.arc(222,104,20,0,6.28); x.lineWidth=1; x.arc(222,104,10,0,6.28);</script><p>A red filled box (with a cleared white notch), a blue outlined box, a green zig-zag, a brown line, a bordered frame, the text &ldquo;Canvas 2D!&rdquo;, and two concentric magenta circles &mdash; the outer one drawn <b>3px thick</b> via <code>lineWidth</code> (M1801) &mdash; all in JavaScript.</p>" },
    { "LIST    HTM", "<h2>Lists</h2><p>An ordered list with a nested bullet list:</p><ol><li>First item<li>Second item<ul><li>nested bullet<li>another nested</ul><li>Third item</ol><p>And a plain bullet list:</p><ul><li>alpha<li>beta<li>gamma</ul><p>Ordered-list variants &mdash; <code>type</code> and <code>start</code>:</p><ol type=\"a\"><li>lower-alpha<li>second</ol><ol type=\"I\"><li>upper-roman<li>second<li>third</ol><ol start=\"8\"><li>starts at eight<li>nine</ol>" },
    { "LSTYLE  HTM", "<style> ul.menu { list-style: none } </style><h2>list-style-type</h2><p><b>list-style:none</b> (inline) &mdash; a nav menu, no bullets:</p><ul style=\"list-style:none\"><li><a href=\"file:index.htm\">Home</a><li><a href=\"file:list.htm\">Lists</a><li><a href=\"file:table.htm\">Tables</a></ul><p><b>list-style:none</b> via a <code>ul.menu</code> &lt;style&gt; rule &mdash; also no bullets:</p><ul class=\"menu\"><li>First<li>Second<li>Third</ul><p>Explicit bullet kinds &mdash; <b>disc / circle / square</b>:</p><ul style=\"list-style-type:disc\"><li>disc one<li>disc two</ul><ul style=\"list-style-type:circle\"><li>circle one<li>circle two</ul><ul style=\"list-style-type:square\"><li>square one<li>square two</ul><p>Default bullets vary by <b>nesting depth</b> (-, then *, then +):</p><ul><li>level one<ul><li>level two<ul><li>level three</ul></ul></ul><p><b>list-style:none</b> on an ordered list drops the numbers too:</p><ol style=\"list-style:none\"><li>no number here<li>nor here</ol>" },
    { "TABLE   HTM", "<h2>Table</h2><p>A small table renders as column-aligned rows (cells padded to each column's width in the fixed-width font) with bold headers:</p><table><tr><th>Name<th>Role<th>Year<tr><td>Alice<td>Engineer<td>2021<tr><td>Bob<td>Designer<td>2022<tr><td>Carol<td>Manager<td>2019</table><p>After the table. A wider example:</p><table><tr><th>Fruit<th>Colour<th>Price<tr><td>Apple<td>red<td>$1.20<tr><td>Blueberry<td>blue<td>$3.99<tr><td>Fig<td>purple<td>$0.50</table><p>Colspan (M1795) &mdash; a header cell spanning all three columns must stretch across the full width, and the data rows below must stay aligned under it:</p><table><tr><th colspan=\"3\">Quarterly Report</th><tr><th>Region<th>Sales<th>Growth<tr><td>North<td>1200<td>+8%<tr><td>South<td>950<td>+3%</table>" },
    { "NESTTBL HTM", "<h2>Nested table</h2><p>Before the table.</p><table><tr><td>Outer-A<td>Outer-B<tr><td><table><tr><td>Inner-1<td>Inner-2</table><td>Outer-D<tr><td>Outer-E<td>Outer-F</table><p>After the table (must render as a normal paragraph, not get swallowed by the outer table ending early at the nested table's own close tag).</p>" },
    { "ENT     HTM", "<h2>Entities</h2><p>Named: &lsquo;single&rsquo; and &ldquo;double&rdquo;, dash &mdash; here, ellipsis&hellip; bullet &bull; copy &copy;.</p><p>Symbols fold to ASCII: arrows &larr; &uarr; &rarr; &darr;, plus-minus &plusmn;, times &times; divide &divide;, degree &deg;, section &sect;, paragraph &para;, prime &prime;.</p><p>Numeric decimal: &#39;apos&#39; and &#8220;quote&#8221;.</p><p>Numeric hex: &#x27;hex-apos&#x27; and &#x2014; em-dash.</p>" },
    { "UTF8    HTM", "<h2>UTF-8</h2><p>Raw UTF-8 bytes (not entities): smart quotes “hello” and ‘hi’, em dash — here, ellipsis… bullet •.</p><p>Accents fold to ASCII: café, naïve, jalapeño, Über, straße.</p><p>Symbols: euro € and 30°C.</p><!-- a comment with a > and <b>markup</b> inside: none of THIS must render -->A<!--[if IE]><p>conditional</p><![endif]-->B<p>After comments.</p><svg width=\"12\" height=\"12\"><title>svgtitle-must-not-show</title><text x=\"0\" y=\"9\">SVGLEAK</text><path d=\"M0 0 L12 12\"/></svg><p>After svg.</p>" },
    { "ITER    JS ", "var s=Symbol(\"tag\");var range={from:1,to:4,[Symbol.iterator](){var cur=this.from,end=this.to;return{next(){if(cur<=end)return{value:cur++,done:false};return{value:0,done:true};}};}};var sum=0;for(var v of range)sum+=v;print(\"typeof \"+(typeof s)+\" sum \"+sum);print(\"spread \"+[...range].join(\"-\")+\" from \"+Array.from(range).length);" },
    { "PROXY   JS ", "var log=[];var p=new Proxy({},{get:function(t,k){return \"got:\"+k;},set:function(t,k,v){log.push(k+\"=\"+v);t[k]=v;}});p.foo=5;print(p.bar);print(log.join(\",\"));var base={deep:9};var c=base;for(var i=0;i<200;i++)c=new Proxy(c,{});print(\"chain \"+c.deep);" },
    { "IMG     HTM", "<h2>Images</h2><p>Local images render inline, decoded by our own PNG, GIF and JPEG code: <img src=\"file:test.png\" alt=\"the test image\"> and an icon <img src=\"file:icon.png\" alt=\"an icon\">. Here is a baseline JPEG photo, scaled with width=\"240\" (its natural size is 120): <img src=\"file:photo.jpg\" alt=\"a jpeg photo\" width=\"240\">. Remote images now decode inline too (PNG/GIF/JPEG/SVG).</p>" },
    { "IMGALIGNHTM", "<h2>Image alignment</h2><p>Left (default), then centred, then right &mdash; same image each time, scaled to width=64. The block <code>&lt;img&gt;</code> follows the enclosing <code>text-align</code>:</p><p>Left-aligned (default, must hug the left edge):</p><img src=\"file:test.png\" width=\"64\" alt=\"left\"><div style=\"text-align:center\"><p>Centred (text-align:center):</p><img src=\"file:test.png\" width=\"64\" alt=\"centre\"></div><div style=\"text-align:right\"><p>Right-aligned (text-align:right):</p><img src=\"file:test.png\" width=\"64\" alt=\"right\"></div>" },
    { "DATAIMG HTM", "<h2>Inline data: URI image</h2><p>This 16&times;16 image is embedded directly in the page as a <code>data:image/bmp;base64,&hellip;</code> URI &mdash; no separate file &mdash; decoded by our own base64 + BMP code, shown scaled to width=128:</p><p><img src=\"data:image/bmp;base64,Qk02AwAAAAAAADYAAAAoAAAAEAAAABAAAAABABgAAAAAAAADAAAAAAAAAAAAAAAAAAAAAAAA/wAA/wAA/wAA/wAA/wAA/wAA/wAA/wAAAP//AP//AP//AP//AP//AP//AP//AP///wAA/wAA/wAA/wAA/wAA/wAA/wAA/wAAAP//AP//AP//AP//AP//AP//AP//AP///wAA/wAA/wAA/wAA/wAA/wAA/wAA/wAAAP//AP//AP//AP//AP//AP//AP//AP///wAA/wAA/wAA/wAA/wAA/wAA/wAA/wAAAP//AP//AP//AP//AP//AP//AP//AP///wAA/wAA/wAA/wAA/wAA/wAA/wAA/wAAAP//AP//AP//AP//AP//AP//AP//AP///wAA/wAA/wAA/wAA/wAA/wAA/wAA/wAAAP//AP//AP//AP//AP//AP//AP//AP///wAA/wAA/wAA/wAA/wAA/wAA/wAA/wAAAP//AP//AP//AP//AP//AP//AP//AP///wAA/wAA/wAA/wAA/wAA/wAA/wAA/wAAAP//AP//AP//AP//AP//AP//AP//AP//AAD/AAD/AAD/AAD/AAD/AAD/AAD/AAD/AP8AAP8AAP8AAP8AAP8AAP8AAP8AAP8AAAD/AAD/AAD/AAD/AAD/AAD/AAD/AAD/AP8AAP8AAP8AAP8AAP8AAP8AAP8AAP8AAAD/AAD/AAD/AAD/AAD/AAD/AAD/AAD/AP8AAP8AAP8AAP8AAP8AAP8AAP8AAP8AAAD/AAD/AAD/AAD/AAD/AAD/AAD/AAD/AP8AAP8AAP8AAP8AAP8AAP8AAP8AAP8AAAD/AAD/AAD/AAD/AAD/AAD/AAD/AAD/AP8AAP8AAP8AAP8AAP8AAP8AAP8AAP8AAAD/AAD/AAD/AAD/AAD/AAD/AAD/AAD/AP8AAP8AAP8AAP8AAP8AAP8AAP8AAP8AAAD/AAD/AAD/AAD/AAD/AAD/AAD/AAD/AP8AAP8AAP8AAP8AAP8AAP8AAP8AAP8AAAD/AAD/AAD/AAD/AAD/AAD/AAD/AAD/AP8AAP8AAP8AAP8AAP8AAP8AAP8AAP8A\" width=\"128\" height=\"128\" alt=\"colour quadrants\"></p><p>Quadrants &mdash; red, green, blue, yellow &mdash; prove the BMP row-flip + BGR&rarr;RGBA path on a data: payload.</p><p><a href=\"file:index.htm\">Back to the demo index</a></p>" },
    { "README  MD ", "# OS-DEV\n\nA from-scratch **x86_64** operating system with its *own* web browser.\n\n## Features\n\n- A windowing **desktop** environment\n- A from-scratch **JavaScript** engine\n- A web browser over real **HTTPS**\n- A **scriptable shell** (for/if/while, pipes, command substitution)\n- A **text editor** (undo/redo, find & replace, clipboard)\n- A Markdown renderer (you are reading its output)\n\n## Building\n\nRun `make` to build, then `make run`. Inline `code` renders too.\n\n```\n$ make\n$ make run\n```\n\n> This blockquote is rendered by OS-DEV's own Markdown-to-HTML converter.\n\nLinks work: [the demo index](file:index.htm) and [example.com](https://example.com).\n\nAutolink: visit https://example.com directly, and ~~this text is struck through~~.\n\n---\n\n1. First item\n2. Second item\n3. Third item\n\n## A table\n\n| Feature | Status |\n|-----------|--------|\n| Browser | yes |\n| JavaScript | yes |\n| Shell | for/if/while + $() |\n| Editor | undo + find/replace |\n| Markdown | tables + images |\n\n## An image\n\n![a test image](file:test.png)\n\nRendered live from a .md file on the FAT32 disk.\n" },
    { "DATA    CSV", "Name,Role,Score\nAlice,Engineer,95\nBob,\"Designer, UX\",88\nCarol,Scientist,99\nDave,Intern,72\n" },
    /* Regression fixture for M1893: an HTML page that begins with a UTF-8 BOM
     * (EF BB BF) AND carries an inline <svg> in its first 512 bytes. decode_image
     * sniffs fetched content to decide if it is an image; it must skip the BOM to
     * see "<html"/"<!doctype" and classify this as HTML. While the BOM skip was
     * dead code (a signed-char comparison that could never be true) this page was
     * mis-detected as a standalone SVG and rendered as a tiny bitmap instead of a
     * document. Keep the <svg> early — that is what makes it discriminating. */
    { "BOMHTML HTM", "\xEF\xBB\xBF<!doctype html><html><h1>BOM + inline SVG</h1><svg width=\"40\" height=\"40\"><circle cx=\"20\" cy=\"20\" r=\"18\" fill=\"#39FF88\"/></svg><p>This document starts with a UTF-8 BOM and contains an inline SVG. If you can read this paragraph as TEXT, the BOM skip works (M1893) and the page was classified as HTML. If instead the whole page appears as one small image, decode_image mis-sniffed it as a standalone SVG.</p></html>" },
    /* M1896 fixture: the three §10.3.3 column cases the old always-centre
     * max-width hack could not express. Each block gets a background so its
     * solved content box is visible, which also checks that the background rect
     * and the text agree (both go through box_solve_column). */
    { "BOXW    HTM", "<h1>CSS width + auto margins</h1><div style=\"width:300px;background:#20304a\">A: width:300px with no margins. Per CSS 2.1 10.3.3 the box keeps its 300px and stays LEFT-aligned; the leftover space becomes margin-right.</div><p>&nbsp;</p><div style=\"width:300px;margin:0 auto;background:#3a2255\">B: width:300px; margin:0 auto. Both margins are auto so they split the slack evenly and this box is CENTRED.</div><p>&nbsp;</p><div style=\"width:300px;margin-left:auto;background:#20304a\">C: width:300px; margin-left:auto. Only the left margin is auto, so it absorbs all the slack and this box is pushed to the RIGHT edge.</div><p>&nbsp;</p><div style=\"max-width:420px;background:#3a2255\">D: max-width:420px with no margins stated. This keeps the deliberate M933 readable-column behaviour and stays centred.</div>" },
    /* M1897 fixture: horizontal padding as real box geometry. Backgrounds make the
     * box edges visible, so a background that hugs the text (the content box)
     * instead of extending around it (the padding box) is immediately obvious. */
    { "BOXPAD  HTM", "<h1>Block padding</h1><div style=\"padding:40px;background:#20304a\">E: padding:40px. The text must be inset 40px on BOTH sides, and the background must extend a clear 40px band all the way around it. Before M1897 padding-left became a plain text indent and padding-right was dropped entirely, so a long line like this one ran right up to the container edge.</div><p>&nbsp;</p><div style=\"width:400px;padding:20px;margin:0 auto;background:#3a2255\">F: width:400px; padding:20px; margin:0 auto. Padding is part of the 10.3.3 width constraint, so 400px is the CONTENT width and the padding sits inside a centred 440px box.</div><p>&nbsp;</p><div style=\"padding:40px;background:#20304a\"><p style=\"background:#7a1030\">G: a plain paragraph background nested inside the 40px-padded block. It must paint only the CONTENT box it actually occupies, NOT the padded parent's wider padding box.</p></div>" },
    /* Probe (M1901 investigation): does the border stroke agree with the background
     * and text once width/padding/margin are solved by the layout engine? */
    { "BOXBORD HTM", "<h1>Border vs box model</h1><div style=\"border:2px solid #39FF88;padding:30px;background:#20304a\">H: border + padding:30px + background. The green stroke should sit just OUTSIDE the blue background, which itself extends 30px around this text.</div><p>&nbsp;</p><div style=\"border:2px solid #FFB02B;width:360px;padding:20px;margin:0 auto;background:#3a2255\">I: border + width:360px + padding:20px + margin:0 auto. The amber stroke should hug the centred box.</div>" },
    /* LAYCHK.HTM — the machine-checked box-model fixture (M1902). Every case gets a
     * UNIQUE background colour so tests/run-layout-render-tests.sh can find its
     * bounding box in a framebuffer dump and assert the solved geometry. Keep the
     * text to one short line per block so all cases fit on one screen, and do NOT
     * reuse a colour: the checker keys on exact RGB. */
    { "LAYCHK  HTM", "<div style=\"padding:40px;background:#fe0606\"><p style=\"background:#fe0707\">six</p></div><div style=\"width:300px;background:#fe0101\">one</div><div style=\"width:300px;margin:0 auto;background:#fe0202\">two</div><div style=\"width:300px;margin-left:auto;background:#fe0303\">three</div><div style=\"width:400px;padding:20px;margin:0 auto;background:#fe0404\">four</div><div style=\"border:3px solid #01fe01;padding:30px;background:#fe0505\">five</div>" },
    /* Page 2 of the machine-checked fixture (M1904). Together these cases push
     * past the ~700px viewport, and the checker needs each colour to be actually
     * PRESENT in a dump (a block scrolled off screen is simply absent) — so they
     * get their own page and the checker merges boxes across both captures. */
    { "LAYCHK2 HTM", "<div style=\"width:400px;padding:20px;box-sizing:border-box;margin:0 auto;background:#fe0808\">seven</div><div style=\"width:200px;margin-bottom:60px;background:#fe0909\">eight</div><div style=\"width:200px;background:#fe0a0a\">nine</div><div style=\"width:200px;height:80px;background:#fe0b0b\">ten</div><div style=\"width:200px;height:80px;padding:15px;box-sizing:border-box;background:#fe0c0c\">eleven</div><div style=\"width:200px;min-height:70px;background:#fe0d0d\">twelve</div><div style=\"width:200px;min-height:20px;height:90px;background:#fe0e0e\">thirteen</div><div style=\"width:200px;background:#fe0f0f\">last</div>" },
    /* Page 3 of the machine-checked fixture (M1910): max-height. Its own page
     * because the runner never scrolls — every colour must be PRESENT in a dump of
     * the top of the page, and page 2 has no room left.
     *
     * Every clamped case is followed by a plain block, because the assertion that
     * matters is the FOLLOWER's top: max-height shrinks the flow advance, and only
     * the follower's position can prove the MAIN LOOP clamped rather than just the
     * background's forward scan (the M1905 lesson — a mutation that broke only the
     * main loop passed every background-derived height check). Do not measure these
     * by background height alone: glyphs paint their own background rect in the
     * block's colour, so spilled text below the cap still emits that colour. */
    { "LAYCHK3 HTM", "<div style=\"width:200px;max-height:40px;background:#fe1010\">This block sets max-height 40px and holds far more text than fits, so the box must stop at the cap while the rest spills out below it.</div><div style=\"width:200px;background:#fe1111\">after</div><div style=\"width:200px;max-height:400px;background:#fe1212\">loose</div><div style=\"width:200px;max-height:20px;min-height:70px;background:#fe1313\">minwins</div><div style=\"width:200px;max-height:60px;padding:10px;box-sizing:border-box;background:#fe1414\">Border-box max-height sixty with ten of padding and enough text to overflow it.</div><div style=\"width:200px;max-height:40px;overflow:hidden;background:#fe1616\"><span style=\"background:#fe1717\">Clipped: overflow hidden with max height forty, so this run of text must be cut off at the cap instead of spilling out below the box the way it would with overflow visible.</span></div><div style=\"width:200px;background:#fe1818\">aftercl</div><div style=\"width:200px;background:#fe1515\">tail</div>" },
    /* FLOAT.HTM (M1928): a floated image with text wrapping around it — the
     * case real pages overwhelmingly use floats for. */
    { "FLOAT   HTM", "<h1>Float</h1>"
      "<img src=\"file:LOGO.SVG\" width=\"96\" height=\"96\" style=\"float:left\">"
      "<p>This paragraph should WRAP around the floated image on its left rather than starting below it. Float takes the image out of the normal vertical flow and narrows every line box it overlaps, so these words begin to the right of the picture and only return to the full column width once the text has passed the bottom of the image. If floats did nothing, this text would begin underneath the picture instead, at the full column width from the very first line.</p>" },
    /* Page 4 of the machine-checked fixture (M1928): float + clear. The image
     * is located by LOGO.SVG's own blue rect (#3366cc); the wrapping text is
     * wrapped in a span so its BACKGROUND traces where the text actually sits,
     * which is the thing float changes. */
    { "LAYCHK4 HTM", "<img src=\"file:LOGO.SVG\" width=\"96\" height=\"96\" style=\"float:left\">"
      "<span style=\"background:#fe1919\">Text beside a left float must begin to the RIGHT of the image and overlap it vertically, rather than starting underneath it at the full column width. These extra words give the paragraph enough lines to span the whole height of the picture so the wrap region is unambiguous.</span>"
      "<div style=\"clear:both;background:#fe1a1a\">cleared</div>" },
    /* Page 5 of the machine-checked fixture (M1929): box geometry from a
     * STYLESHEET RULE rather than an inline style=, plus viewport units. Both
     * were unsupported until now, which is why real pages did not centre. */
    { "LAYCHK5 HTM", "<style>"
      "div.f{background:#fe2222}"
      "div.w{width:300px;margin:0 auto;background:#fe2020}"
      "div.v{width:40vw;background:#fe2121}"
      "div.pad{width:200px;padding:25px;background:#fe2424}"
      "div.ht{width:200px;height:70px;background:#fe2525}"
      "</style>"
      "<div class=\"f\">full width reference</div>"
      "<div class=\"w\">width + margin auto from a rule</div>"
      "<div class=\"v\">width in vw</div>"
      "<div class=\"pad\">padding from a rule</div>"
      "<div class=\"ht\">height from a rule</div>"
      "<ul><li><span style=\"background:#fe2626\">plain li</span></li></ul>"
      "<ul><li style=\"display:flex\"><span style=\"background:#fe2727\">flex li</span></li></ul>" },
    { "LOGO    SVG", "<svg width=\"64\" height=\"64\" viewBox=\"0 0 64 64\"><rect x=\"2\" y=\"2\" width=\"60\" height=\"60\" fill=\"#3366cc\"/><circle cx=\"32\" cy=\"32\" r=\"20\" fill=\"#ffcc00\"/><polygon points=\"32,12 52,52 12,52\" fill=\"#cc3333\"/></svg>" },
    { "XFORM   SVG", "<svg width=\"120\" height=\"120\" viewBox=\"0 0 120 120\"><rect width=\"120\" height=\"120\" fill=\"#eef\"/><g transform=\"translate(60,60)\"><rect x=\"0\" y=\"-6\" width=\"46\" height=\"12\" fill=\"#e33\"/><rect x=\"0\" y=\"-6\" width=\"46\" height=\"12\" fill=\"#3a3\" transform=\"rotate(90)\"/><rect x=\"0\" y=\"-6\" width=\"46\" height=\"12\" fill=\"#36c\" transform=\"rotate(180)\"/><rect x=\"0\" y=\"-6\" width=\"46\" height=\"12\" fill=\"#ec0\" transform=\"rotate(270)\"/></g><g transform=\"translate(22,98) scale(1.6)\"><circle cx=\"0\" cy=\"0\" r=\"7\" fill=\"#909\"/></g></svg>" },
    { "ICON    SVG", "<svg width=\"80\" height=\"80\" viewBox=\"0 0 24 24\" fill=\"#22aa77\"><path d=\"M12 2 L2 7 L2 17 L12 22 L22 17 L22 7 Z\"/><circle cx=\"12\" cy=\"12\" r=\"3.5\" fill=\"#ffffff\"/></svg>" },
    { "OPAC    SVG", "<svg width=\"110\" height=\"90\" viewBox=\"0 0 110 90\"><rect width=\"110\" height=\"90\" fill=\"#ffffff\"/><circle cx=\"42\" cy=\"34\" r=\"28\" fill=\"#ff0000\" opacity=\"0.5\"/><circle cx=\"68\" cy=\"34\" r=\"28\" fill=\"#00cc00\" opacity=\"0.5\"/><circle cx=\"55\" cy=\"58\" r=\"28\" fill=\"#0000ff\" opacity=\"0.5\"/></svg>" },
    { "SVGT    HTM", "<h1>SVG rendering</h1><p>A from-scratch SVG, rasterized inline by our own integer-only SVG decoder (no FPU):</p><img src=\"file:LOGO.SVG\" alt=\"a from-scratch SVG\"><p>The shapes above &mdash; a blue square, a yellow circle, a red triangle &mdash; are drawn from SVG <code>&lt;rect&gt;</code>/<code>&lt;circle&gt;</code>/<code>&lt;polygon&gt;</code> by svg.c.</p><p>Now with <b>transforms</b> &mdash; <code>&lt;g transform&gt;</code> groups, per-shape <code>transform=</code>, and translate/scale/rotate/matrix (all integer 16.16 math). This pinwheel needs translate + rotate to place its four arms:</p><img src=\"file:XFORM.SVG\" alt=\"a transformed SVG pinwheel\"><p>And <b>paint inheritance</b>: this icon sets <code>fill</code> once on the root <code>&lt;svg&gt;</code> &mdash; the hexagon inherits it (green) while the inner dot overrides to white:</p><img src=\"file:ICON.SVG\" alt=\"an inherited-fill SVG icon\"><p>And <b>opacity</b> &mdash; <code>opacity</code>/<code>fill-opacity</code> (per shape and inherited through <code>&lt;g&gt;</code>) composite with real alpha-blending. Three 50%-opaque circles overlap, so the overlaps blend:</p><img src=\"file:OPAC.SVG\" alt=\"three overlapping translucent circles\"><p>And <b>gradients</b> &mdash; <code>&lt;linearGradient&gt;</code>/<code>&lt;radialGradient&gt;</code> with multiple colour <code>&lt;stop&gt;</code>s, evaluated per pixel (all integer math). A vertical sky gradient behind a 3-stop radial sphere:</p><img src=\"file:GRAD.SVG\" alt=\"a linear-and-radial-gradient SVG\"><p>And <b>&lt;text&gt;</b> &mdash; SVG text is rendered with the kernel's bitmap font, scaled to <code>font-size</code> and coloured by <code>fill</code> (so charts, diagrams and labelled logos show their labels):</p><img src=\"file:TXTSVG.SVG\" alt=\"an SVG with text labels\"><p>And <b>&lt;use&gt;/&lt;symbol&gt;</b> reuse &mdash; a shape group is defined once in <code>&lt;defs&gt;</code> and instantiated several times by <code>&lt;use href=\"#id\" x= y=&gt;</code> at different offsets:</p><img src=\"file:USE.SVG\" alt=\"an SVG reusing a defined symbol via use\">" },
    { "USE     SVG", "<svg width=\"190\" height=\"60\" viewBox=\"0 0 190 60\"><rect width=\"190\" height=\"60\" fill=\"#f4f4ee\"/><defs><g id=\"star\"><circle cx=\"15\" cy=\"15\" r=\"13\" fill=\"#ffaa00\"/><circle cx=\"15\" cy=\"15\" r=\"6\" fill=\"#cc3300\"/></g></defs><use href=\"#star\" x=\"0\" y=\"5\"/><use href=\"#star\" x=\"45\" y=\"20\"/><use href=\"#star\" x=\"90\" y=\"5\"/><use href=\"#star\" x=\"135\" y=\"20\"/></svg>" },
    { "TXTSVG  SVG", "<svg width=\"180\" height=\"90\" viewBox=\"0 0 180 90\"><rect width=\"180\" height=\"90\" fill=\"#eef2fb\"/><text x=\"10\" y=\"32\" font-size=\"22\" fill=\"#2255cc\">Hello, SVG!</text><text x=\"10\" y=\"60\" font-size=\"15\" fill=\"#cc3333\">text labels work</text><circle cx=\"150\" cy=\"55\" r=\"24\" fill=\"#ffcc00\"/><text x=\"138\" y=\"60\" font-size=\"14\" fill=\"#333333\">OK</text></svg>" },
    { "GRAD    SVG", "<svg width=\"150\" height=\"96\" viewBox=\"0 0 150 96\"><defs><linearGradient id=\"sky\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\"><stop offset=\"0\" stop-color=\"#2a5db0\"/><stop offset=\"1\" stop-color=\"#bfe6ff\"/></linearGradient><radialGradient id=\"ball\"><stop offset=\"0\" stop-color=\"#ffffff\"/><stop offset=\"0.5\" stop-color=\"#ff8800\"/><stop offset=\"1\" stop-color=\"#5c2200\"/></radialGradient></defs><rect width=\"150\" height=\"96\" fill=\"url(#sky)\"/><circle cx=\"75\" cy=\"50\" r=\"34\" fill=\"url(#ball)\"/></svg>" },
    { "FORM    HTM", "<h1>Forms: type and process input</h1>"
        "<p>Fields are now editable: Tab/n to a field, Enter to focus it, type, Enter to finish. A button reads <code>.value</code> and does something with it.</p>"
        "<p>Your name: <input id=\"name\" placeholder=\"(click here, then type)\"></p>"
        "<p>Favourite number: <input id=\"num\" placeholder=\"a number\"></p>"
        "<p><button onclick=\"document.getElementById('out').textContent='Hello '+document.getElementById('name').value+'! Your number doubled is '+(parseInt(document.getElementById('num').value)*2)\">[ Greet &amp; compute ]</button></p>"
        "<p id=\"out\">(fill the fields, then click the button)</p>"
        "<p>The button reads each field's value via <code>getElementById(id).value</code>, computes, and writes the result into the paragraph &mdash; real input-&gt;process-&gt;output.</p>" },
    { "RPS     HTM", "<h1>Rock Paper Scissors</h1>"
        "<p>Tab/n to a button, Enter to play. The CPU's move is <code>Math.random(3)</code>; the score persists across clicks via the page's JS environment.</p>"
        "<p>You played: <b><span id=\"you\">-</span></b> &nbsp;&nbsp; CPU played: <b><span id=\"cpu\">-</span></b></p>"
        "<h2 id=\"result\">Make your move:</h2>"
        "<p><button onclick=\"play(0)\">[ Rock ]</button> &nbsp; <button onclick=\"play(1)\">[ Paper ]</button> &nbsp; <button onclick=\"play(2)\">[ Scissors ]</button></p>"
        "<p>Wins: <b><span id=\"w\">0</span></b> &nbsp; Losses: <b><span id=\"l\">0</span></b> &nbsp; Ties: <b><span id=\"t\">0</span></b></p>"
        "<script>\n"
        "var names=['Rock','Paper','Scissors'];\n"
        "var wins=0, losses=0, ties=0;\n"
        "function play(you){\n"
        "  var cpu=Math.random(3);\n"
        "  document.getElementById('you').textContent=names[you];\n"
        "  document.getElementById('cpu').textContent=names[cpu];\n"
        "  var out;\n"
        "  if(you==cpu){ ties=ties+1; out='Tie!'; }\n"
        "  else if(cpu==(you+2)%3){ wins=wins+1; out='You win!'; }\n"
        "  else { losses=losses+1; out='You lose.'; }\n"
        "  document.getElementById('result').textContent=out;\n"
        "  document.getElementById('w').textContent=wins;\n"
        "  document.getElementById('l').textContent=losses;\n"
        "  document.getElementById('t').textContent=ties;\n"
        "}\n"
        "</script>" },
    { "BASE    HTM", "<h1>Number Base Converter</h1>"
        "<p>Tab/n to the field, Enter to type a decimal number, Enter to finish, then Convert. Uses the JS engine's <code>parseInt</code> + <code>Number.toString(radix)</code>.</p>"
        "<p>Decimal: <input id=\"dec\" placeholder=\"e.g. 255\"></p>"
        "<p><button onclick=\"conv()\">[ Convert ]</button></p>"
        "<p>Binary: <b><span id=\"bin\">-</span></b></p>"
        "<p>Octal: &nbsp;<b><span id=\"oct\">-</span></b></p>"
        "<p>Hex: &nbsp;&nbsp;&nbsp;<b><span id=\"hex\">-</span></b></p>"
        "<script>\n"
        "function conv(){\n"
        "  var n=parseInt(document.getElementById('dec').value);\n"
        "  document.getElementById('bin').textContent=n.toString(2);\n"
        "  document.getElementById('oct').textContent=n.toString(8);\n"
        "  document.getElementById('hex').textContent='0x'+n.toString(16);\n"
        "}\n"
        "</script>" },
    { "GUESS   HTM", "<h1>Guess the Number</h1>"
        "<p>I'm thinking of a number from 1 to 100. Tab/n to the field, Enter, type a guess, Enter, then Guess. The secret persists across clicks.</p>"
        "<p>Your guess: <input id=\"g\"></p>"
        "<p><button onclick=\"guess()\">[ Guess ]</button> &nbsp; <button onclick=\"newgame()\">[ New game ]</button></p>"
        "<h2 id=\"msg\">Make your first guess!</h2>"
        "<p>Tries: <b><span id=\"cnt\">0</span></b></p>"
        "<script>\n"
        "var secret=Math.random(100)+1;\n"
        "var tries=0;\n"
        "function guess(){\n"
        "  var g=parseInt(document.getElementById('g').value);\n"
        "  tries=tries+1; document.getElementById('cnt').textContent=tries;\n"
        "  var m;\n"
        "  if(g==secret) m='Correct! '+secret+' in '+tries+' tries. (New game to replay)';\n"
        "  else if(g<secret) m=g+' is too LOW -- guess higher.';\n"
        "  else m=g+' is too HIGH -- guess lower.';\n"
        "  document.getElementById('msg').textContent=m;\n"
        "}\n"
        "function newgame(){\n"
        "  secret=Math.random(100)+1; tries=0;\n"
        "  document.getElementById('cnt').textContent=0;\n"
        "  document.getElementById('msg').textContent='New number chosen -- guess!';\n"
        "}\n"
        "</script>" },
    { "ASCII   HTM", "<h1>ASCII Table (printable 32-126)</h1>"
        "<p>Generated at page load by a JS loop &mdash; <code>String.fromCharCode</code> + <code>document.write</code>.</p>"
        "<script>\n"
        "document.write('<pre>');\n"
        "for(var c=32; c<127; c++){\n"
        "  var ch=String.fromCharCode(c);\n"
        "  if(c==60) ch='&lt;'; else if(c==62) ch='&gt;'; else if(c==38) ch='&amp;';\n"
        "  var cs=''+c; while(cs.length<3) cs=' '+cs;\n"
        "  document.write(cs+' '+ch+'   ');\n"
        "  if((c-31)%8==0) document.write('\\n');\n"
        "}\n"
        "document.write('</pre>');\n"
        "</script>" },
    { "LIFE    HTM", "<h1>Conway's Game of Life</h1>"
        "<p>A 24x12 grid, randomly seeded with <code>Math.random</code>. Tab/n to Step, Enter to advance one generation; Reseed for a new board.</p>"
        "<pre id=\"grid\"></pre>"
        "<p><button onclick=\"step()\">[ Step ]</button> &nbsp; <button onclick=\"seed()\">[ Reseed ]</button> &nbsp; <button onclick=\"glider()\">[ Glider ]</button></p>"
        "<p>Generation: <b><span id=\"gen\">0</span></b></p>"
        "<script>\n"
        "var W=24, H=12, g=[], gen=0;\n"
        "function seed(){\n"
        "  g=[]; for(var y=0;y<H;y++){ var row=[]; for(var x=0;x<W;x++) row.push(Math.random(100)<35?1:0); g.push(row); }\n"
        "  gen=0; render();\n"
        "}\n"
        "function glider(){\n"
        "  g=[]; for(var y=0;y<H;y++){ var row=[]; for(var x=0;x<W;x++) row.push(0); g.push(row); }\n"
        "  g[0][1]=1; g[1][2]=1; g[2][0]=1; g[2][1]=1; g[2][2]=1;\n"   /* the classic glider */
        "  gen=0; render();\n"
        "}\n"
        "function render(){\n"
        "  var s=''; for(var y=0;y<H;y++){ for(var x=0;x<W;x++) s+=g[y][x]?'#':'.'; s+='\\n'; }\n"
        "  document.getElementById('grid').textContent=s;\n"
        "  document.getElementById('gen').textContent=gen;\n"
        "}\n"
        "function step(){\n"
        "  var nn=[]; for(var y=0;y<H;y++){ var row=[]; for(var x=0;x<W;x++){\n"
        "    var c=0;\n"
        "    for(var dy=-1;dy<=1;dy++) for(var dx=-1;dx<=1;dx++){ if(dx==0&&dy==0) continue;\n"
        "      var ny=y+dy, nx=x+dx; if(ny>=0&&ny<H&&nx>=0&&nx<W&&g[ny][nx]) c=c+1; }\n"
        "    row.push((g[y][x] && (c==2||c==3)) || (!g[y][x] && c==3) ? 1 : 0);\n"
        "  } nn.push(row); }\n"
        "  g=nn; gen=gen+1; render();\n"
        "}\n"
        "seed();\n"
        "</script>" },
    { "SLOT    HTM", "<h1>Slot Machine</h1>"
        "<p>Tab/n to Spin, Enter to pull the lever. Match all three to hit the jackpot! (reels via <code>Math.random</code>)</p>"
        "<h1 id=\"reels\">[ ? | ? | ? ]</h1>"
        "<h2 id=\"msg\">Pull the lever!</h2>"
        "<p><button onclick=\"spin()\">[ Spin ]</button></p>"
        "<p>Spins: <b><span id=\"sp\">0</span></b> &nbsp; Jackpots: <b><span id=\"w\">0</span></b></p>"
        "<script>\n"
        "var sym=['7','$','#','@','*'], spins=0, wins=0;\n"
        "function spin(){\n"
        "  var a=sym[Math.random(5)], b=sym[Math.random(5)], c=sym[Math.random(5)];\n"
        "  document.getElementById('reels').textContent='[ '+a+' | '+b+' | '+c+' ]';\n"
        "  spins=spins+1;\n"
        "  var win=(a==b && b==c);\n"
        "  if(win) wins=wins+1;\n"
        "  document.getElementById('msg').textContent = win ? ('*** JACKPOT! three '+a+'s ***') : 'Try again...';\n"
        "  document.getElementById('sp').textContent=spins;\n"
        "  document.getElementById('w').textContent=wins;\n"
        "}\n"
        "</script>" },
    { "8BALL   HTM", "<h1>Magic 8-Ball</h1>"
        "<p>Think of a yes/no question, then Tab/n to the button and press Enter for the 8-Ball's answer.</p>"
        "<h1 id=\"ans\">. . .</h1>"
        "<p><button onclick=\"ask()\">[ Ask the 8-Ball ]</button></p>"
        "<script>\n"
        "var answers=['It is certain.','It is decidedly so.','Without a doubt.','Yes, definitely.','You may rely on it.','As I see it, yes.','Most likely.','Outlook good.','Yes.','Signs point to yes.','Reply hazy -- try again.','Ask again later.','Better not tell you now.','Cannot predict now.','Concentrate and ask again.','Do not count on it.','My reply is no.','My sources say no.','Outlook not so good.','Very doubtful.'];\n"
        "function ask(){ document.getElementById('ans').textContent = answers[Math.random(20)]; }\n"
        "</script>" },
    { "PASSGEN HTM", "<h1>Password Generator</h1>"
        "<p>Tab/n to Generate for a fresh random 16-character password (ambiguous characters like l/I/O/0/1 are omitted). Uses <code>Math.random</code> + <code>charAt</code>.</p>"
        "<h2 id=\"pw\">(click Generate)</h2>"
        "<p><button onclick=\"gen()\">[ Generate ]</button></p>"
        "<script>\n"
        "var cs='abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*';\n"
        "function gen(){\n"
        "  var p=''; for(var i=0;i<16;i++) p+=cs.charAt(Math.random(cs.length));\n"
        "  document.getElementById('pw').textContent=p;\n"
        "}\n"
        "</script>" },
    { "DICE    HTM", "<h1>Two-Dice Distribution</h1>"
        "<p>Tab/n to Roll: it throws 2d6 three hundred sixty times and draws the histogram &mdash; the classic bell curve peaking at 7 (shows <code>Math.random</code> is well-distributed).</p>"
        "<pre id=\"hist\">(click Roll)</pre>"
        "<p><button onclick=\"roll()\">[ Roll 360x ]</button></p>"
        "<script>\n"
        "function roll(){\n"
        "  var c=[]; for(var i=0;i<=12;i++) c.push(0);\n"
        "  for(var i=0;i<360;i++){ var s=(Math.random(6)+1)+(Math.random(6)+1); c[s]=c[s]+1; }\n"
        "  var out='';\n"
        "  for(var v=2;v<=12;v++){\n"
        "    var bar=''; var nb=c[v]/2; for(var b=0;b<nb;b++) bar+='#';\n"
        "    var vs=''+v; while(vs.length<2) vs=' '+vs;\n"
        "    out+=vs+': '+bar+' ('+c[v]+')\\n';\n"
        "  }\n"
        "  document.getElementById('hist').textContent=out;\n"
        "}\n"
        "</script>" },
    { "ROT13   HTM", "<h1>ROT13 Cipher</h1>"
        "<p>Tab/n to the field, Enter, type a message, Enter, then Encode. ROT13 is its own inverse, so the same button decodes too. Uses <code>charCodeAt</code> + <code>String.fromCharCode</code>.</p>"
        "<p>Text: <input id=\"t\"></p>"
        "<p><button onclick=\"rot()\">[ Encode / Decode ]</button></p>"
        "<h2 id=\"out\">. . .</h2>"
        "<script>\n"
        "function rot(){\n"
        "  var s=document.getElementById('t').value, r='';\n"
        "  for(var i=0;i<s.length;i++){\n"
        "    var c=s.charCodeAt(i);\n"
        "    if(c>=65 && c<=90) r+=String.fromCharCode((c-65+13)%26+65);\n"
        "    else if(c>=97 && c<=122) r+=String.fromCharCode((c-97+13)%26+97);\n"
        "    else r+=String.fromCharCode(c);\n"
        "  }\n"
        "  document.getElementById('out').textContent=r;\n"
        "}\n"
        "</script>" },
    { "UUID    HTM", "<h1>UUID Generator</h1>"
        "<p>Tab/n to Generate for a fresh random version-4 UUID (8-4-4-4-12 hex, with the version and variant bits set per RFC 4122).</p>"
        "<h2 id=\"u\">(click Generate)</h2>"
        "<p><button onclick=\"gen()\">[ Generate ]</button></p>"
        "<script>\n"
        "var hx='0123456789abcdef';\n"
        "function gen(){\n"
        "  var s='';\n"
        "  for(var i=0;i<36;i++){\n"
        "    if(i==8||i==13||i==18||i==23) s+='-';\n"
        "    else if(i==14) s+='4';\n"
        "    else if(i==19) s+=hx.charAt(8+Math.random(4));\n"
        "    else s+=hx.charAt(Math.random(16));\n"
        "  }\n"
        "  document.getElementById('u').textContent=s;\n"
        "}\n"
        "</script>" },
    { "FACTS   HTM", "<h1>Number Facts</h1>"
        "<p>Tab/n to the field, Enter, type a whole number, Enter, then Facts &mdash; computes its factorial, Fibonacci, square, and primality in JS.</p>"
        "<p>N: <input id=\"n\"></p>"
        "<p><button onclick=\"facts()\">[ Facts ]</button></p>"
        "<pre id=\"out\">. . .</pre>"
        "<script>\n"
        "function facts(){\n"
        "  var n=parseInt(document.getElementById('n').value), o='';\n"
        "  var f=1; for(var i=2;i<=n && i<=20;i++) f=f*i;\n"
        "  o+='Factorial: '+(n<=20?f:'(overflows 64-bit)')+'\\n';\n"
        "  var a=0,b=1; for(var i=0;i<n && i<90;i++){ var t=a+b; a=b; b=t; }\n"
        "  o+='Fibonacci: '+a+'\\n';\n"
        "  o+='Square:    '+(n*n)+'\\n';\n"
        "  var p=(n>=2); for(var d=2;d*d<=n;d++) if(n%d==0){ p=false; break; }\n"
        "  o+='Prime:     '+(p?'yes':'no')+'\\n';\n"
        "  document.getElementById('out').textContent=o;\n"
        "}\n"
        "</script>" },
    { "WEEKDAY HTM", "<h1>Day of the Week</h1>"
        "<p>Tab/n to the field, Enter, type a date as <b>YYYYMMDD</b> (e.g. 20000101), Enter, then Compute. Uses Sakamoto's algorithm &mdash; valid for any Gregorian date.</p>"
        "<p>Date: <input id=\"d\" placeholder=\"YYYYMMDD\"></p>"
        "<p><button onclick=\"dow()\">[ Compute ]</button></p>"
        "<h2 id=\"out\">. . .</h2>"
        "<script>\n"
        "function dow(){\n"
        "  var s=document.getElementById('d').value;\n"
        "  var y=parseInt(s.slice(0,4)), m=parseInt(s.slice(4,6)), dd=parseInt(s.slice(6,8));\n"
        "  if(m<1 || m>12){ document.getElementById('out').textContent='(use YYYYMMDD)'; return; }\n"
        "  var t=[0,3,2,5,0,3,5,1,4,6,2,4];\n"
        "  if(m<3) y=y-1;\n"
        "  var w=(y + y/4 - y/100 + y/400 + t[m-1] + dd) % 7;\n"
        "  var names=['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];\n"
        "  document.getElementById('out').textContent=names[w];\n"
        "}\n"
        "</script>" },
    { "PALETTE HTM", "<h1>Colour Palette</h1>"
        "<p>Tab/n to Generate for five random hex colour codes &mdash; a quick palette for design work.</p>"
        "<pre id=\"p\">(click Generate)</pre>"
        "<p><button onclick=\"gen()\">[ Generate ]</button></p>"
        "<script>\n"
        "var hx='0123456789ABCDEF';\n"
        "function gen(){\n"
        "  var s='';\n"
        "  for(var i=0;i<5;i++){\n"
        "    var c='#'; for(var j=0;j<6;j++) c+=hx.charAt(Math.random(16));\n"
        "    s+=c+'\\n';\n"
        "  }\n"
        "  document.getElementById('p').textContent=s;\n"
        "}\n"
        "</script>" },
    { "CLOCK   HTM", "<h1>Clock</h1>"
        "<p>Tab/n to Now for the current date and time, read from the system RTC through the JS <code>Date</code> object.</p>"
        "<h1 id=\"t\">. . .</h1>"
        "<p><button onclick=\"now()\">[ Now ]</button></p>"
        "<script>\n"
        "var mons=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];\n"
        "function p2(x){ return x<10 ? '0'+x : ''+x; }\n"
        "function now(){\n"
        "  var d=new Date();\n"
        "  document.getElementById('t').textContent = mons[d.getMonth()]+' '+d.getDate()+' '+d.getFullYear()+'   '+p2(d.getHours())+':'+p2(d.getMinutes())+':'+p2(d.getSeconds());\n"
        "}\n"
        "now();\n"
        "</script>" },
    { "SEARCH  HTM", "<h1>Search the web</h1>"
        "<p>A real working web search, from scratch. Type a query and follow <b>[Search]</b>: the browser builds <code>action?q=YOUR+QUERY</code>, URL-encodes it, and navigates over <b>HTTPS</b> to DuckDuckGo's HTML results &mdash; a genuine HTML GET form submission to the live web.</p>"
        "<form action=\"https://html.duckduckgo.com/html/\">"
        "<p>Query: <input id=\"q\" name=\"q\" placeholder=\"e.g. operating system\"></p>"
        "<p><button type=\"submit\">Search DuckDuckGo</button></p>"
        "</form>"
        "<p>How: Tab/n to the field, Enter to edit, type, Enter to finish; then Tab/n to <b>[Search]</b> and Enter. Spaces become <code>+</code> and specials are percent-encoded, so <code>?q=operating+system</code> is a valid request. The results page is itself a form &mdash; search again right from it.</p>"
        "<p>The same mechanism works with any GET form (try pointing <code>action</code> at example.com to watch the query string appear in the address bar).</p>" },
    { "LOGIN   HTM", "<h1>Password masking</h1>"
        "<p>A <code>type=\"password\"</code> field shows <code>*</code> on screen, but JavaScript still reads the real value. Tab/n to a field, Enter to edit, type, Enter to finish.</p>"
        "<p>User: <input id=\"user\" placeholder=\"name\"></p>"
        "<p>Pass: <input id=\"pw\" type=\"password\" placeholder=\"secret\"></p>"
        "<p><button onclick=\"document.getElementById('msg').textContent='Signed in as '+document.getElementById('user').value+' -- password had '+document.getElementById('pw').value.length+' chars'\">[ Sign in ]</button></p>"
        "<p id=\"msg\">(type a name and password, then Sign in)</p>"
        "<p>The password renders as <code>***</code>, but <code>getElementById('pw').value</code> returns the real text &mdash; here the button reports its length to prove it read the actual characters.</p>" },
    { "ATTR    HTM", "<h1>Reading &amp; writing attributes</h1>"
        "<p>JavaScript can read and change any element's HTML attributes with <code>getAttribute</code> / <code>setAttribute</code> &mdash; the href of a link, custom <code>data-*</code> values, a field's type, and so on.</p>"
        "<p>Here is a link: <a id=\"lnk\" href=\"https://example.com/page\" data-note=\"from-the-tag\">example link</a></p>"
        "<p><button onclick=\"var e=document.getElementById('lnk'); document.getElementById('out').textContent='href = '+e.getAttribute('href')+'   data-note = '+e.getAttribute('data-note')\">[ Read its attributes ]</button></p>"
        "<p><button onclick=\"var e=document.getElementById('lnk'); e.setAttribute('data-note','CHANGED-by-setAttribute'); document.getElementById('out').textContent='after setAttribute: data-note = '+e.getAttribute('data-note')\">[ Change data-note ]</button></p>"
        "<p id=\"out\">(read the link's attributes, or change one and read it back)</p>"
        "<p>Reading pulls values straight out of the page's HTML (a missing attribute returns <code>null</code>); <code>setAttribute</code> rewrites the tag in place, so reading it back shows the new value.</p>" },
    { "LOC     HTM", "<h1>window.location</h1>"
        "<p>Page JavaScript can read the current page's URL via <code>window.location</code> &mdash; how a search-results page knows what you searched for (its <code>?q=</code>).</p>"
        "<p><button onclick=\"var l=location; document.getElementById('out').innerHTML='href: '+l.href+'<br>protocol: '+l.protocol+'<br>host: '+(l.host||'(none)')+'<br>pathname: '+l.pathname+'<br>search: '+(l.search||'(none)')\">[ Show window.location ]</button></p>"
        "<p id=\"out\">(click to read the location)</p>"
        "<p>This page is <code>file:loc.htm</code>, so it has no host and no query. On <code>https://html.duckduckgo.com/html/?q=os</code>, <code>location.search</code> would be <code>?q=os</code>.</p>" },
    { "CHECK   HTM", "<h1>Checkboxes &amp; radios</h1>"
        "<p>Tab/n to a box and Enter to toggle it. A button reads each one's state via <code>.value</code> (<code>on</code> when checked, empty when not).</p>"
        "<p><input id=\"c1\" type=\"checkbox\" name=\"news\" checked> Subscribe to news</p>"
        "<p><input id=\"c2\" type=\"checkbox\" name=\"beta\"> Join the beta</p>"
        "<p>Plan: <input id=\"r1\" type=\"radio\" name=\"plan\"> Free &nbsp; <input id=\"r2\" type=\"radio\" name=\"plan\" checked> Pro</p>"
        "<p><button onclick=\"document.getElementById('out').textContent='news='+(document.getElementById('c1').value||'off')+'  beta='+(document.getElementById('c2').value||'off')+'  pro='+(document.getElementById('r2').value||'off')\">[ Read states ]</button></p>"
        "<p id=\"out\">(toggle the boxes, then read their states)</p>"
        "<p>A checked box submits <code>name=on</code> with the form; an unchecked one is omitted. Selecting a radio unchecks the others sharing its <code>name</code> (try Free, then Pro).</p>" },
    { "MFORM   HTM", "<h1>Two independent forms</h1>"
        "<p>Form A and Form B each have their own <code>plan</code> radio group and their own <code>who</code> field, sharing the same names by design. Checking a radio in one form must NOT uncheck the other form's radio of the same name, and submitting one form must NOT leak the other form's field values into the query string.</p>"
        "<form action=\"file:mform-a.htm\">"
        "<p>Form A &mdash; Plan: <input id=\"a1\" type=\"radio\" name=\"plan\" checked> Free &nbsp; <input id=\"a2\" type=\"radio\" name=\"plan\"> Pro</p>"
        "<p>Form A &mdash; Who: <input id=\"an\" name=\"who\" value=\"alice\"></p>"
        "<p><button type=\"submit\">Submit form A</button></p>"
        "</form>"
        "<form action=\"file:mform-b.htm\">"
        "<p>Form B &mdash; Plan: <input id=\"b1\" type=\"radio\" name=\"plan\" checked> Free &nbsp; <input id=\"b2\" type=\"radio\" name=\"plan\"> Pro</p>"
        "<p>Form B &mdash; Who: <input id=\"bn\" name=\"who\" value=\"bob\"></p>"
        "<p><button type=\"submit\">Submit form B</button></p>"
        "</form>" },
    { "CHKJS   HTM", "<h1>checkbox <code>.checked</code> (boolean DOM property)</h1>"
        "<p><input id=\"cb\" type=\"checkbox\" checked> Enabled</p>"
        "<p><button onclick=\"document.getElementById('o').textContent='checked='+document.getElementById('cb').checked\">[ read .checked ]</button> "
        "<button onclick=\"document.getElementById('cb').checked=true;document.getElementById('o').textContent='set true'\">[ set true ]</button> "
        "<button onclick=\"document.getElementById('cb').checked=false;document.getElementById('o').textContent='set false'\">[ set false ]</button></p>"
        "<p id=\"o\">click read .checked</p>"
        "<p>Reads return a real boolean (<code>true</code>/<code>false</code>), and assigning a boolean toggles the box.</p>" },
    { "PROPJS  HTM", "<h1>DOM attribute properties</h1>"
        "<p id=\"t\" class=\"hi there\">styled paragraph</p>"
        "<p><a id=\"lnk\" href=\"file:README.TXT\">a link</a></p>"
        "<p><button onclick=\"document.getElementById('o').textContent='cls=['+document.getElementById('t').className+'] href=['+document.getElementById('lnk').href+']'\">[ read props ]</button> "
        "<button onclick=\"var e=document.getElementById('t');e.className='changed';document.getElementById('o').textContent='now cls=['+e.className+']'\">[ set className ]</button></p>"
        "<p id=\"o\">click read props</p>"
        "<p>el.className/href/src/name/title/alt/placeholder/type now reflect their HTML attribute (read + write).</p>" },
    { "TAREA   HTM", "<h1>textarea</h1>"
        "<p>Click the box to focus it, then type. Enter adds a new line.</p>"
        "<textarea id=\"ta\" name=\"msg\">Hello there\nsecond line</textarea>"
        "<p><button onclick=\"document.getElementById('o').textContent='len='+document.getElementById('ta').value.length+' first='+document.getElementById('ta').value.split('\\n')[0]\">[ read .value ]</button></p>"
        "<p id=\"o\">click read .value</p>"
        "<p>The box's text is a real multi-line value: JS reads it via <code>.value</code> and a form submits <code>msg=</code>&lt;text&gt;.</p>" },
    { "TITLE   HTM", "<title>My Page</title>"
        "<h1>document.title</h1>"
        "<p>The window title bar shows this page's <code>&lt;title&gt;</code> (\"My Page\"). The buttons read and change <code>document.title</code> live.</p>"
        "<p><button onclick=\"document.getElementById('o').textContent='title=['+document.title+']'\">[ read title ]</button> "
        "<button onclick=\"document.title='Changed!';document.getElementById('o').textContent='now title=['+document.title+']'\">[ set title ]</button></p>"
        "<p id=\"o\">click read title</p>" },
    { "SEL     HTM", "<h1>select dropdown</h1>"
        "<p>Click the dropdown to cycle through its options.</p>"
        "<p>Fruit: <select id=\"f\" name=\"fruit\"><option value=\"a\">Apple</option><option value=\"b\" selected>Banana</option><option value=\"c\">Cherry</option></select></p>"
        "<p><button onclick=\"document.getElementById('o').textContent='value='+document.getElementById('f').value\">[ read .value ]</button></p>"
        "<p id=\"o\">click read .value</p>"
        "<p>The chosen option's <code>value</code> is the field's <code>.value</code> and submits as <code>fruit=</code>&lt;value&gt;.</p>" },
    { "ONCHG   HTM", "<h1>onchange handler</h1>"
        "<p>An input's <code>onchange</code> runs JavaScript the moment its value changes &mdash; no button needed. Tab/n to the box and Enter to toggle it:</p>"
        "<p><input id=\"agree\" type=\"checkbox\" onchange=\"document.getElementById('msg').textContent = document.getElementById('agree').value=='on' ? 'Thanks for agreeing!' : 'You unchecked it.'\"> I agree to the terms</p>"
        "<p id=\"msg\">(toggle the checkbox above)</p>"
        "<p>Text fields fire <code>onchange</code> when they lose focus (Enter or Esc). Name: <input id=\"nm\" onchange=\"document.getElementById('msg2').textContent='Hi, '+document.getElementById('nm').value+'!'\" placeholder=\"type, then Enter\"></p>"
        "<p id=\"msg2\">(type a name, then press Enter)</p>"
        "<p><code>oninput</code> fires on <i>every</i> keystroke (live). Search: <input id=\"live\" oninput=\"document.getElementById('echo').textContent='You typed: '+document.getElementById('live').value+' ('+document.getElementById('live').value.length+' chars)'\" placeholder=\"type here\"></p>"
        "<p id=\"echo\">(start typing &mdash; updates as you go)</p>"
        "<p>Toggling/blurring fires <code>onchange</code>; typing fires <code>oninput</code> &mdash; each reads the new <code>.value</code> and rewrites the page. Reactive forms, from scratch.</p>" },
    { "ANCHOR  HTM", "<h1 id=\"top\">In-page anchors</h1>"
        "<p>Links to <code>#id</code> jump to the element with that id &mdash; the way a table of contents or a &lsquo;back to top&rsquo; link works. Tab/n to a link, Enter to jump:</p>"
        "<ul><li><a href=\"#a\">Section A</a><li><a href=\"#b\">Section B</a><li><a href=\"#c\">Section C (bottom)</a><li><a href=\"#legacy\">Legacy target (&lt;a name&gt;)</a></ul>"
        "<h2 id=\"a\">Section A</h2>"
        "<p>This is section A. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls.</p>"
        "<p>More of section A. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls.</p>"
        "<h2 id=\"b\">Section B</h2>"
        "<p>This is section B. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls.</p>"
        "<p>More of section B. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls. Filler so the page scrolls.</p>"
        "<h2 id=\"c\">Section C</h2>"
        "<p>This is section C, the last one. Clicking the TOC link above jumped straight here.</p>"
        "<h2><a name=\"legacy\">Legacy target</a></h2>"
        "<p>This heading is an old-style <code>&lt;a name=\"legacy\"&gt;</code> anchor &mdash; the TOC link still jumps here.</p>"
        "<p><a href=\"#top\">Back to top</a></p>" },
    { "DETAILS HTM", "<h1>Collapsible details</h1>"
        "<p>Tab/n to a <b>[+]</b> summary and Enter to expand it (Enter again to collapse). The body shows/hides in place.</p>"
        "<details><summary>What is OS-DEV?</summary>"
        "<p>A from-scratch x86_64 operating system with its own kernel, TLS stack, JavaScript engine, and graphical web browser &mdash; all written in C. This text is hidden until you expand the section.</p></details>"
        "<details><summary>How do collapsible sections work here?</summary>"
        "<p>Each &lt;details&gt; gets an index; clicking its &lt;summary&gt; toggles a per-page open/closed bit, and the parser suppresses the body's tokens while it is collapsed.</p></details>"
        "<details open><summary>This one starts expanded</summary>"
        "<p>Because it has the <code>open</code> attribute, its body renders on load. Collapse it with Enter.</p></details>"
        "<p>Three independent sections &mdash; each toggles on its own.</p>" },
    { "COLOR   HTM", "<h2>Colours</h2><p>Text can be <font color=\"red\">red</font>, <font color=\"green\">green</font>, <font color=\"blue\">blue</font>, <font color=\"#E07000\">hex orange</font>, and <font color=\"purple\">purple</font>. Back to normal.</p>" },
    { "QSVAL   HTM", "<h1>querySelector on form fields (<code>.value</code> / <code>.checked</code>)</h1>"
        "<p>A position handle from a tag/class/attribute selector now reaches the id-keyed field store, so reading and writing <code>.value</code>/<code>.checked</code> works through <code>querySelector</code>, not just <code>getElementById</code>. This page runs on load and reports below:</p>"
        "<input id=\"x\" value=\"hi\"> "
        "<input id=\"cb\" class=\"box\" type=\"checkbox\"> "
        "<textarea id=\"ta\">a</textareas>b</textarea>"
        "<p id=\"out\">running&hellip;</p>"
        "<script>"
        "var r='';"
        "r+='read='+document.querySelector('input').value+' ';"          /* P1: read via TAG selector (position handle) */
        "document.querySelector('input').value='ZZ';"                    /* P1: write via position handle */
        "r+='write='+document.getElementById('x').value+' ';"
        "document.querySelector('.box').checked=true;"                   /* P1: .checked write via CLASS selector */
        "r+='chk='+document.getElementById('cb').checked+' ';"
        "r+='p2='+document.querySelector('textarea').value;"            /* P1 read + P2: a </textareas> inside must not close early */
        "document.getElementById('out').textContent=r;"
        "</script>"
        "<p>Expected: <code>read=hi write=ZZ chk=true p2=a&lt;/textareas&gt;b</code>. The last value proves a <code>&lt;/textareas&gt;</code> substring inside the textarea did not end it prematurely.</p>" },
    { "FBIG    HTM", "<h1>Form with more than 8 fields</h1>"
        "<p>The page can store up to 16 distinct field values now (was 8). This form has ten; the script fills them on load and reads four back &mdash; the 9th and 10th used to be silently dropped:</p>"
        "<input id=\"f1\"> <input id=\"f2\"> <input id=\"f3\"> <input id=\"f4\"> <input id=\"f5\"> "
        "<input id=\"f6\"> <input id=\"f7\"> <input id=\"f8\"> <input id=\"f9\"> <input id=\"f10\">"
        "<p id=\"out\">running&hellip;</p>"
        "<script>"
        "for(var i=1;i<=10;i++){document.getElementById('f'+i).value='v'+i;}"
        "document.getElementById('out').textContent='f1='+document.getElementById('f1').value+' f8='+document.getElementById('f8').value+' f9='+document.getElementById('f9').value+' f10='+document.getElementById('f10').value;"
        "</script>"
        "<p>Expected: <code>f1=v1 f8=v8 f9=v9 f10=v10</code> &mdash; all ten kept (before, f9/f10 read back empty).</p>" },
    { "TALEN   HTM", "<h1>Field values up to 255 chars</h1>"
        "<p>A field value holds up to 255 characters now (was 95) &mdash; enough for a real textarea. The script fills the box with 150 <code>x</code> on load; then click it and type, and <code>oninput</code> shows the live length (the longer value is read into the edit buffer without truncation or overflow):</p>"
        "<textarea id=\"ta\" oninput=\"document.getElementById('out').textContent='len='+document.getElementById('ta').value.length\"></textarea>"
        "<p id=\"out\">running&hellip;</p>"
        "<script>"
        "var s='';for(var i=0;i<150;i++)s+='x';"
        "document.getElementById('ta').value=s;"
        "document.getElementById('out').textContent='len='+document.getElementById('ta').value.length;"
        "</script>"
        "<p>Expected on load: <code>len=150</code> (before, it capped at 95). Each keystroke updates the count live.</p>" },
    { "INDEX   HTM", "<title>OS-DEV Demos</title><style> h1{color:#2C66D6} h2{color:#800080} </style><h1>OS-DEV Demo Index</h1><p>Local demo pages baked onto the FAT32 disk &mdash; select with Tab/n and press Enter:</p><ul><li><a href=\"file:pre.htm\">Preformatted text</a><li><a href=\"file:list.htm\">Lists (nested &amp; ordered)</a><li><a href=\"file:nested.htm\">Deeply nested lists</a><li><a href=\"file:lstyle.htm\">list-style-type (none / disc / circle / square)</a><li><a href=\"file:table.htm\">Tables</a><li><a href=\"file:ent.htm\">HTML entities</a><li><a href=\"file:img.htm\">Images</a><li><a href=\"file:imgalign.htm\">Image alignment (centred / right via text-align)</a><li><a href=\"file:dataimg.htm\">Inline data: URI image (base64 BMP)</a><li><a href=\"file:readme.md\">Markdown rendering (a .md file)</a><li><a href=\"file:data.csv\">CSV as a table (a .csv file)</a><li><a href=\"file:color.htm\">Coloured text</a><li><a href=\"file:style.htm\">Inline CSS &mdash; color, bold (font-weight), italic (font-style)</a><li><a href=\"file:css.htm\">CSS &lt;style&gt; blocks &mdash; tag / .class / #id rules</a><li><a href=\"file:nest.htm\">Nested style scopes &mdash; colours compose to any depth</a><li><a href=\"file:article.htm\">A styled article &mdash; the CSS engine on realistic prose</a><li><a href=\"file:code.htm\">Inline code</a><li><a href=\"file:anchor.htm\">In-page anchors (#id jump-to-section)</a><li><a href=\"file:details.htm\">Collapsible &lt;details&gt; sections</a></ul><h2>Interactive (JavaScript + DOM)</h2><ul><li><a href=\"file:dom.htm\">Interactive DOM &mdash; click to rewrite the page</a><li><a href=\"file:form.htm\">Editable forms &mdash; type, then process input</a><li><a href=\"file:rps.htm\">Rock Paper Scissors &mdash; a playable game (Math.random + a score that persists)</a><li><a href=\"file:base.htm\">Number base converter &mdash; decimal to binary/octal/hex (parseInt + toString)</a><li><a href=\"file:guess.htm\">Guess the Number &mdash; a game; the secret (Math.random) persists across guesses</a><li><a href=\"file:ascii.htm\">ASCII table &mdash; generated at load by a JS loop (fromCharCode + document.write)</a><li><a href=\"file:life.htm\">Conway's Game of Life &mdash; a JS simulation (2D arrays + Math.random) rendered in the DOM</a><li><a href=\"file:slot.htm\">Slot machine &mdash; Math.random reels, match three for the jackpot (persistent score)</a><li><a href=\"file:8ball.htm\">Magic 8-Ball &mdash; ask a yes/no question for a random answer (Math.random)</a><li><a href=\"file:passgen.htm\">Password generator &mdash; a random 16-char password (Math.random + charAt)</a><li><a href=\"file:dice.htm\">Two-dice distribution &mdash; a 2d6 histogram (Math.random's bell curve)</a><li><a href=\"file:rot13.htm\">ROT13 cipher &mdash; encode/decode text (charCodeAt + String.fromCharCode)</a><li><a href=\"file:uuid.htm\">UUID generator &mdash; a random RFC-4122 version-4 UUID (Math.random)</a><li><a href=\"file:facts.htm\">Number facts &mdash; factorial / Fibonacci / square / primality of a number</a><li><a href=\"file:weekday.htm\">Day of the week &mdash; Sakamoto's algorithm for any Gregorian date</a><li><a href=\"file:palette.htm\">Colour palette &mdash; five random hex colour codes (Math.random)</a><li><a href=\"file:clock.htm\">Clock &mdash; current date/time from the RTC via the JS Date object</a><li><a href=\"file:search.htm\">Web search &mdash; HTTPS form submit to DuckDuckGo</a><li><a href=\"file:login.htm\">Password masking &mdash; * on screen, real value to JS</a><li><a href=\"file:attr.htm\">get/setAttribute &mdash; JS reads &amp; writes HTML attributes</a><li><a href=\"file:loc.htm\">window.location &mdash; JS reads the page URL</a><li><a href=\"file:check.htm\">Checkboxes &amp; radios &mdash; toggle, read via .value</a><li><a href=\"file:onchg.htm\">onchange &mdash; a handler runs the moment a box toggles</a><li><a href=\"file:jstest.htm\">Page script (document.write)</a><li><a href=\"file:oop.htm\">Object-oriented page script</a><li><a href=\"file:jsnew.htm\">New engine features &mdash; operators, number literals, stdlib</a><li><a href=\"file:remove.htm\">element.remove() &mdash; JS removes an element from the page</a><li><a href=\"file:qsa.htm\">querySelector(All) &mdash; find elements by CSS selector</a><li><a href=\"file:qsaw.htm\">querySelector write &mdash; rewrite a matched element</a><li><a href=\"file:qsval.htm\">querySelector .value/.checked &mdash; read/write form fields by any selector</a><li><a href=\"file:domq.htm\">Live DOM query &mdash; onclick runs CSS selectors + classList</a><li><a href=\"file:persist.htm\">Persistent page JS &mdash; onclick calls load-defined functions</a><li><a href=\"file:todo.htm\">Persistent array state &mdash; a to-do list across clicks</a><li><a href=\"file:events.htm\">JS-assigned handlers &mdash; el.onclick=fn / addEventListener</a><li><a href=\"file:app.htm\">Mini task app &mdash; addEventListener + array + querySelectorAll</a><li><a href=\"file:schange.htm\">Scripted onchange &mdash; checkbox.onchange = fn</a><li><a href=\"file:evtarg.htm\">Event argument &mdash; e.type / e.target / this</a><li><a href=\"file:oncefn.htm\">Remove a handler &mdash; el.onclick = null</a><li><a href=\"file:matches.htm\">element.matches() &mdash; event-delegation selector test</a><li><a href=\"file:rmattr.htm\">removeAttribute &mdash; drop an attribute from an element</a><li><a href=\"file:closest.htm\">element.closest() &mdash; walk up to a matching ancestor</a><li><a href=\"file:children.htm\">element.children &mdash; the direct child elements</a><li><a href=\"file:create.htm\">createElement + appendChild &mdash; build DOM nodes</a><li><a href=\"file:parent.htm\">element.parentElement &mdash; the enclosing element</a><li><a href=\"file:domshow.htm\">DOM showcase &mdash; createElement + query + traverse together</a><li><a href=\"file:sibling.htm\">nextElementSibling / previousElementSibling</a><li><a href=\"file:tagname.htm\">element.tagName &mdash; the element's tag</a></ul><p>Backspace returns here. Press <b>h</b> for the start page.</p>" },
    { "CODE    HTM", "<h2>Inline code</h2><p>Run the <code>browse</code> command, then press <kbd>Enter</kbd> to follow a link. The call <code>memcpy(dst, src, n)</code> copies <samp>n</samp> bytes; configuration lives in <tt>/etc/config</tt>. Inline code renders in a distinct colour so it stands out from <b>bold</b> and <i>italic</i> text.</p><p>Edits show too: <del>this was removed</del> and <s>so was this</s>, but <b>this stays</b>. Price: <s>$50</s> now $30. And <mark>this part is highlighted</mark> like a marker pen.</p><p>Science: H<sub>2</sub>O, CO<sub>2</sub>, and E = mc<sup>2</sup>; see the footnote<sup>3</sup>.</p><p>Back to normal flow.</p>" },
    { "NESTED  HTM", "<h2>Deeply nested lists</h2><ol><li>Top one<ol><li>One-A<li>One-B<ul><li>bullet under 1-B<li>another bullet<ol><li>deep one<li>deep two</ol></ul></ol><li>Top two<ul><li>plain bullet<li>plain bullet</ul><li>Top three</ol><p>Numbering and indentation track the nesting depth.</p>" },
    { "GUIDE   TXT", "OS-DEV quick guide\n==================\nDesktop: Apps menu launches programs. Drag titlebars; drag edges to resize.\n  F2 cycle focus, F3 minimise, F4 maximise, F5/F6 tile left/right.\n  F12 saves a screenshot of the whole screen to SHOT0.PNG, SHOT1.PNG, ...\n  (view it with e.g. browse file:SHOT0.PNG). The shell 'screenshot [file]'\n  command saves a PNG for a .png name, else a BMP.\nBrowser: type a host, file:NAME, or a search query then Enter (a query that\n  isn't a URL searches DuckDuckGo). Tab/n/p pick links, Enter follows.\n  g/G top/bottom, h home, r reload, s save, u view-source, a bookmark, \\ find.\n  Interactive: Enter on a [field] to type into it (Enter/Esc when done);\n  follow a button/link to run the page's JavaScript (it can read fields and\n  rewrite the page live). See file:dom.htm and file:form.htm.\nShell: ls, cat, cd, tree, find, grep, df, gzip/gunzip/unzip/tar (archives),\n  run NAME.ELF, browse URL, wget URL.\nStart here: browse file:index.htm\n" },
    { "SAMPLE  JS ", "// sample.js  --  run with: js sample.js   (edit with: edit sample.js)\n"
        "print(\"FizzBuzz 1..15:\");\n"
        "var line = \"\";\n"
        "for (var i = 1; i <= 15; i = i + 1) {\n"
        "  if (i % 15 == 0) line += \"FizzBuzz\";\n"
        "  else if (i % 3 == 0) line += \"Fizz\";\n"
        "  else if (i % 5 == 0) line += \"Buzz\";\n"
        "  else line += i;\n"
        "  line += \" \";\n"
        "}\n"
        "print(line);\n"
        "function isPrime(n){ if (n < 2) return false; for (var d = 2; d*d <= n; d = d+1) if (n % d == 0) return false; return true; }\n"
        "var primes = \"\";\n"
        "for (var k = 2; k < 30; k = k+1) if (isPrime(k)) primes += k + \" \";\n"
        "print(\"primes < 30: \" + primes);\n"
        "var os = { name: \"OS-DEV\", lang: \"JavaScript\" };\n"
        "print(os.lang + \" running on \" + os.name + \"!\");\n" },
    { "JSTEST  HTM", "<h1>JavaScript in the browser</h1>"
        "<p>Everything below this line is generated <b>live</b> by JavaScript running inside the page (via document.write):</p>"
        "<script>\n"
        "for (var i = 1; i <= 5; i++) document.write(\"<p>Item \" + i + \": \" + i + \" squared = \" + (i*i) + \"</p>\");\n"
        "var sum = 0; for (var k = 1; k <= 100; k++) sum += k;\n"
        "document.write(\"<h2>Sum of 1..100 = \" + sum + \"</h2>\");\n"
        "console.log(\"page script ran; sum=\" + sum);\n"
        "</script>" },
    { "QSA     HTM", "<h1>querySelector &amp; querySelectorAll</h1>"
        "<p>This page has three &lt;p class=&quot;fruit&quot;&gt; items. A script finds them with CSS selectors (by <code>.class</code> and by <code>tag.class</code>), counts them, iterates with <code>for...of</code>, and writes what it found into the elements below (located by id):</p>"
        "<p class=\"fruit\">Apple</p>"
        "<p class=\"fruit\">Banana</p>"
        "<p class=\"fruit\">Cherry</p>"
        "<h2 id=\"title\">(first match appears here)</h2>"
        "<div id=\"out\">(the full list appears here)</div>"
        "<script>\n"
        "var items = document.querySelectorAll(\".fruit\");\n"
        "console.log(\"qsa .fruit count=\" + items.length);\n"
        "var names = \"\";\n"
        "for (var it of items) names += it.textContent + \" \";\n"
        "document.getElementById(\"out\").textContent = \"Found \" + items.length + \" fruit: \" + names;\n"
        "var first = document.querySelector(\"p.fruit\");\n"
        "console.log(\"first p.fruit=\" + first.textContent);\n"
        "document.getElementById(\"title\").textContent = \"First match: \" + first.textContent;\n"
        "console.log(\"missing selector -> \" + document.querySelector(\".nope\"));\n"
        "console.log(\"byTag p=\" + document.getElementsByTagName(\"p\").length);\n"
        "console.log(\"byClass fruit=\" + document.getElementsByClassName(\"fruit\").length);\n"
        "console.log(\"first fruit class=\" + document.querySelector(\"p.fruit\").getAttribute(\"class\"));\n"
        "console.log(\"byAttr [class]=\" + document.querySelectorAll(\"[class]\").length);\n"
        "console.log(\"byAttr p[class]=\" + document.querySelectorAll(\"p[class]\").length);\n"
        "console.log(\"hasAttr class=\" + document.querySelector(\"p.fruit\").hasAttribute(\"class\") + \" title=\" + document.querySelector(\"p.fruit\").hasAttribute(\"title\"));\n"
        "</script>" },
    { "QSAW    HTM", "<h1>querySelector write</h1>"
        "<p>A load-time script finds the first &lt;p class=&quot;msg&quot;&gt; by CSS selector, rewrites its text and sets an attribute on it, then the page re-renders &mdash; no reload. The position handle resolves to the element's byte span and splices the page source:</p>"
        "<p class=\"msg\">(original first paragraph)</p>"
        "<p class=\"msg\">(second paragraph &mdash; left unchanged)</p>"
        "<script>\n"
        "var first = document.querySelector(\"p.msg\");\n"
        "first.textContent = \"Rewritten via a querySelector position handle!\";\n"
        "first.setAttribute(\"data-done\", \"yes\");\n"
        "console.log(\"qsaw read-back=\" + document.querySelector(\"p.msg\").textContent);\n"
        "console.log(\"qsaw attr=\" + document.querySelector(\"p.msg\").getAttribute(\"data-done\"));\n"
        "first.classList.add(\"hi\"); first.classList.add(\"hi\"); first.classList.toggle(\"big\");\n"
        "console.log(\"qsaw classList=\" + document.querySelector(\"p.msg\").getAttribute(\"class\") + \" has-hi=\" + first.classList.contains(\"hi\"));\n"
        "</script>" },
    { "DOMQ    HTM", "<h1>Live DOM query &amp; classList</h1>"
        "<p>Each button's <code>onclick</code> runs a CSS-selector query against the list below, live &mdash; no reload. (The handler re-queries each click, so it always sees the current page.)</p>"
        "<ul><li class=\"task\">Buy milk</li><li class=\"task done\">Walk the dog</li><li class=\"task\">Write an OS</li></ul>"
        "<p><button onclick=\"var t=document.querySelectorAll('.task').length, d=document.querySelectorAll('.done').length; document.getElementById('out').textContent='Tasks: '+t+', done: '+d; console.log('count t='+t+' d='+d)\">Count tasks</button> "
        "<button onclick=\"var f=document.querySelector('li.task'); document.getElementById('out').textContent='First: '+f.textContent+' (done? '+f.classList.contains('done')+')'; console.log('first='+f.textContent+' done='+f.classList.contains('done'))\">Inspect first</button></p>"
        "<div id=\"out\">(click a button above)</div>" },
    { "PERSIST HTM", "<h1>Persistent page JS</h1>"
        "<p>The load script defines <code>greet()</code> and a counter <code>clicks</code>. The button's <code>onclick</code> calls the function and increments the counter &mdash; which works only because the page's JavaScript environment now <b>persists</b> across the load script and every click handler (the counter even survives between clicks, with no localStorage):</p>"
        "<button onclick=\"++clicks; var m=greet('Ada'); document.getElementById('out').textContent=m+' (clicks: '+clicks+')'; console.log('click '+clicks+': '+m)\">Greet</button>"
        "<div id=\"out\">(click the button)</div>"
        "<script>\n"
        "function greet(name){ return 'Hello, '+name+'!'; }\n"
        "var clicks = 0;\n"
        "console.log('load: greet+clicks defined');\n"
        "</script>" },
    { "TODO    HTM", "<h1>Persistent state: a to-do list</h1>"
        "<p>Each click pushes onto / pops from a JavaScript <b>array</b> that lives in the page's persistent environment &mdash; no localStorage, and the state is never read back from the DOM; the array object itself survives between clicks &mdash; then a load-defined <code>render()</code> redraws the list:</p>"
        "<button onclick=\"todos.push('Task #'+(todos.length+1)); render()\">Add a task</button> "
        "<button onclick=\"if(todos.length)todos.pop(); render()\">Remove last</button>"
        "<div id=\"list\">(no tasks yet)</div>"
        "<script>\n"
        "var todos = [];\n"
        "function render(){ document.getElementById('list').textContent = todos.length ? todos.join('  |  ') : '(no tasks yet)'; console.log('todos now: '+todos.length); }\n"
        "console.log('todo load: array+render defined');\n"
        "</script>" },
    { "EVENTS  HTM", "<h1>JS-assigned event handlers</h1>"
        "<p>The load script attaches handlers to the buttons below via <code>document.getElementById('go').onclick = function(){...}</code> and <code>.addEventListener('click', ...)</code> &mdash; there is <b>no</b> inline <code>onclick=</code> attribute. The handler function (defined at load) is stored and fires on click, its state persisting:</p>"
        "<button id=\"go\">Run onclick handler</button> "
        "<button id=\"add\">addEventListener button</button>"
        "<div id=\"out\">(no clicks yet)</div>"
        "<script>\n"
        "var n = 0;\n"
        "document.getElementById('go').onclick = function(){ n++; document.getElementById('out').textContent = 'onclick fired '+n+' time(s)'; console.log('go clicked: '+n); };\n"
        "document.getElementById('add').addEventListener('click', function(){ document.getElementById('out').textContent = 'addEventListener handler ran!'; console.log('add clicked'); });\n"
        "console.log('handlers attached');\n"
        "</script>" },
    { "APP     HTM", "<h1>Mini task app</h1>"
        "<p>Built entirely with this browser's from-scratch JS DOM &mdash; <code>addEventListener</code> handlers, a persistent array, <code>querySelectorAll</code>, and <code>innerHTML</code>, with no page reloads:</p>"
        "<button id=\"add\">Add task</button> <button id=\"count\">Count via querySelectorAll</button> <button id=\"clear\">Clear all</button>"
        "<div id=\"status\">(loading)</div>"
        "<ul id=\"list\"></ul>"
        "<script>\n"
        "var tasks = [];\n"
        "function draw(){\n"
        "  var h = '';\n"
        "  for (var i=0;i<tasks.length;i++) h += '<li class=\"task\">' + tasks[i] + '</li>';\n"
        "  document.getElementById('list').innerHTML = h || '<li>(no tasks)</li>';\n"
        "  document.getElementById('status').textContent = tasks.length + ' task(s)';\n"
        "}\n"
        "document.getElementById('add').addEventListener('click', function(){ tasks.push('Task ' + (tasks.length+1)); draw(); console.log('added; now ' + tasks.length); });\n"
        "document.getElementById('count').addEventListener('click', function(){ var n = document.querySelectorAll('.task').length; document.getElementById('status').textContent = 'querySelectorAll found ' + n + ' .task'; console.log('counted ' + n); });\n"
        "document.getElementById('clear').addEventListener('click', function(){ tasks = []; draw(); console.log('cleared'); });\n"
        "draw();\n"
        "console.log('app ready');\n"
        "</script>" },
    { "SCHANGE HTM", "<h1>Scripted onchange</h1>"
        "<p>The load script sets <code>checkbox.onchange = function(){...}</code> &mdash; there is no inline <code>onchange=</code> attribute. Toggling the box runs the JS-assigned handler (state persists):</p>"
        "<input type=\"checkbox\" id=\"cb\"> Enable feature"
        "<div id=\"out\">(toggle the box)</div>"
        "<script>\n"
        "var toggles = 0;\n"
        "document.getElementById('cb').onchange = function(){ toggles++; document.getElementById('out').textContent = 'onchange fired ' + toggles + ' time(s)'; console.log('onchange fired: ' + toggles); };\n"
        "console.log('scripted onchange attached');\n"
        "</script>" },
    { "EVTARG  HTM", "<h1>Event argument</h1>"
        "<p>The handler receives an <code>event</code> object (<code>e.type</code>, <code>e.target</code>) and runs with <code>this</code> bound to the element it fired on:</p>"
        "<button id=\"b\">Click me</button>"
        "<div id=\"out\">(click the button)</div>"
        "<script>\n"
        "document.getElementById('b').addEventListener('click', function(e){ var s = 'type=' + e.type + ' target.id=' + e.target.id + ' this.id=' + this.id; document.getElementById('out').textContent = s; console.log('evt ' + s); });\n"
        "console.log('event-arg handler attached');\n"
        "</script>" },
    { "ONCEFN  HTM", "<h1>Remove a handler (el.onclick = null)</h1>"
        "<p>This button's onclick removes itself after firing once (<code>el.onclick = null</code>), so a second click does nothing:</p>"
        "<button id=\"b\">Click (fires once)</button>"
        "<div id=\"out\">(click the button)</div>"
        "<script>\n"
        "var c = 0;\n"
        "document.getElementById('b').onclick = function(){ c++; document.getElementById('out').textContent = 'fired ' + c + ' time(s); handler now removed'; console.log('fired ' + c); document.getElementById('b').onclick = null; };\n"
        "console.log('once-handler attached');\n"
        "</script>" },
    { "MATCHES HTM", "<h1>element.matches()</h1>"
        "<p>The click handler tests <code>e.target.matches(selector)</code> against several selectors &mdash; the event-delegation idiom:</p>"
        "<button id=\"b\" class=\"btn\">Click me</button>"
        "<div id=\"out\">(click the button)</div>"
        "<script>\n"
        "document.getElementById('b').addEventListener('click', function(e){ var r = 'button=' + e.target.matches('button') + ' .btn=' + e.target.matches('.btn') + ' #b=' + e.target.matches('#b') + ' .x=' + e.target.matches('.x'); document.getElementById('out').textContent = r; console.log('matches ' + r); });\n"
        "console.log('matches handler attached');\n"
        "</script>" },
    { "RMATTR  HTM", "<h1>removeAttribute</h1>"
        "<p>The load script reads two attributes, removes one with <code>removeAttribute</code>, and re-reads &mdash; the removed one is now <code>null</code> while the other stays:</p>"
        "<p id=\"x\" data-foo=\"bar\" title=\"hi there\">A paragraph with attributes.</p>"
        "<div id=\"out\">?</div>"
        "<script>\n"
        "var p = document.getElementById('x');\n"
        "console.log('before: data-foo=' + p.getAttribute('data-foo') + ' title=' + p.getAttribute('title'));\n"
        "p.removeAttribute('data-foo');\n"
        "console.log('after: data-foo=' + p.getAttribute('data-foo') + ' title=' + p.getAttribute('title'));\n"
        "document.getElementById('out').textContent = 'data-foo=' + p.getAttribute('data-foo') + ', title=' + p.getAttribute('title');\n"
        "</script>" },
    { "CLOSEST HTM", "<h1>element.closest()</h1>"
        "<p>The click handler walks up from the clicked button to the nearest ancestor matching a selector &mdash; the event-delegation idiom (and shows that a matched element's <code>.id</code> is readable):</p>"
        "<div class=\"card\" id=\"card1\"><p>A card containing a button.</p><button id=\"b\">Click me</button></div>"
        "<div id=\"out\">(click the button)</div>"
        "<script>\n"
        "document.getElementById('b').addEventListener('click', function(e){ var c=e.target.closest('.card'); var r='closest .card id=' + (c?c.id:'null') + ', closest(button)=' + (e.target.closest('button')?'self':'null') + ', closest(.nope)=' + e.target.closest('.nope'); document.getElementById('out').textContent=r; console.log('closest: ' + r); });\n"
        "console.log('closest handler attached');\n"
        "</script>" },
    { "CHILDRENHTM", "<h1>element.children</h1>"
        "<p>The script reads the <b>direct</b> child elements of the list &mdash; the nested item is not a direct child, so the count is 3, not 4:</p>"
        "<ul id=\"list\"><li>One</li><li>Two<ul><li>Nested</li></ul></li><li>Three</li></ul>"
        "<div id=\"out\">?</div>"
        "<script>\n"
        "var c = document.getElementById('list').children;\n"
        "document.getElementById('out').textContent = 'count=' + c.length + ', first=' + c[0].textContent + ', last=' + c[c.length-1].textContent;\n"
        "console.log('children count=' + c.length + ' first=' + c[0].textContent + ' last=' + c[c.length-1].textContent);\n"
        "</script>" },
    { "CREATE  HTM", "<h1>createElement + appendChild</h1>"
        "<p>Each click builds a new &lt;li&gt; with <code>document.createElement</code>, sets its text and class, and <code>appendChild</code>s it to the list &mdash; real DOM node construction. The created items are then found by <code>querySelectorAll('.item')</code>, proving they're live elements:</p>"
        "<ul id=\"list\"></ul>"
        "<button id=\"add\">Add an item</button>"
        "<div id=\"out\">(click to add)</div>"
        "<script>\n"
        "var count = 0;\n"
        "document.getElementById('add').addEventListener('click', function(){ count++; var li=document.createElement('li'); li.textContent='Item '+count+' (created)'; li.className='item'; document.getElementById('list').appendChild(li); document.getElementById('out').textContent=count+' items added; '+document.querySelectorAll('.item').length+' match .item'; console.log('appended item '+count+', .item count='+document.querySelectorAll('.item').length); });\n"
        "console.log('createElement demo ready');\n"
        "</script>" },
    { "PARENT  HTM", "<h1>element.parentElement</h1>"
        "<p>The script reads the parent element of a nested paragraph &mdash; it finds the enclosing &lt;div&gt; by id:</p>"
        "<div id=\"outer\"><p id=\"inner\">A nested paragraph.</p></div>"
        "<div id=\"out\">?</div>"
        "<script>\n"
        "var inner = document.getElementById('inner');\n"
        "var p = inner.parentElement;\n"
        "document.getElementById('out').textContent = 'parent id = ' + (p ? p.id : 'null') + ', grandparent = ' + (p && p.parentElement ? p.parentElement.id || '(body)' : 'null');\n"
        "console.log('parentElement id=' + (p ? p.id : 'null'));\n"
        "</script>" },
    { "DOMSHOW HTM", "<h1>DOM showcase</h1>"
        "<p>The whole from-scratch DOM working together &mdash; <code>createElement</code>, <code>appendChild</code>, <code>querySelectorAll</code>, <code>element.children</code>, and <code>parentElement</code>, driven by <code>addEventListener</code>:</p>"
        "<button id=\"add\">Add item</button> <button id=\"info\">Inspect</button>"
        "<ul id=\"list\"></ul>"
        "<div id=\"out\">(Add a few items, then Inspect)</div>"
        "<script>\n"
        "var n = 0;\n"
        "document.getElementById('add').addEventListener('click', function(){ n++; var li=document.createElement('li'); li.textContent='Item '+n; li.className='item'; document.getElementById('list').appendChild(li); document.getElementById('out').textContent=document.querySelectorAll('.item').length+' items'; console.log('added '+n+', total '+document.querySelectorAll('.item').length); });\n"
        "document.getElementById('info').addEventListener('click', function(){ var items=document.querySelectorAll('.item'); var first=items.length?items[0]:null; document.getElementById('out').textContent='querySelectorAll .item='+items.length+', list.children='+document.getElementById('list').children.length+', first.parentElement.id='+(first?first.parentElement.id:'none'); console.log('inspect: qsa='+items.length+' children='+document.getElementById('list').children.length+' parent='+(first?first.parentElement.id:'none')); });\n"
        "console.log('DOM showcase ready');\n"
        "</script>" },
    { "SIBLING HTM", "<h1>nextElementSibling / previousElementSibling</h1>"
        "<p>The script reads the siblings of the middle list item &mdash; one before, one after:</p>"
        "<ul id=\"list\"><li id=\"a\">One</li><li id=\"b\">Two</li><li id=\"c\">Three</li></ul>"
        "<div id=\"out\">?</div>"
        "<script>\n"
        "var mid = document.getElementById('b');\n"
        "var nxt = mid.nextElementSibling, prv = mid.previousElementSibling;\n"
        "document.getElementById('out').textContent = 'next = ' + (nxt?nxt.textContent:'null') + ', prev = ' + (prv?prv.textContent:'null');\n"
        "console.log('sibling next=' + (nxt?nxt.textContent:'null') + ' prev=' + (prv?prv.textContent:'null'));\n"
        "</script>" },
    { "TAGNAME HTM", "<h1>element.tagName</h1>"
        "<p>The script reads the tag names of a few elements (uppercased, per the DOM), by id and by querySelector:</p>"
        "<p id=\"x\">a paragraph</p><div id=\"y\"><span id=\"z\">a span</span></div>"
        "<div id=\"out\">?</div>"
        "<script>\n"
        "var s = document.getElementById('x').tagName + ', ' + document.getElementById('y').tagName + ', ' + document.getElementById('z').tagName + ', qs(span)=' + document.querySelector('span').tagName;\n"
        "document.getElementById('out').textContent = s;\n"
        "console.log('tagNames: ' + s);\n"
        "</script>" },
    { "STYLE   HTM", "<title>Inline CSS</title><h1>Inline CSS</h1>"
        "<p>A small subset of CSS &mdash; the <code>color</code>, <code>font-weight</code> and <code>font-style</code> properties in an inline <code>style=\"...\"</code> attribute &mdash; now style text:</p>"
        "<p style=\"color: red\">This paragraph is red (a named colour).</p>"
        "<p style=\"color: #008000\">This one is green (a #hex colour).</p>"
        "<p>Normal text, then <span style=\"color: blue\">this span is blue</span>, then normal again &mdash; the colour scope ends at the span's close.</p>"
        "<p style=\"background-color: yellow; color: purple\">Purple text &mdash; <code>background-color</code> is ignored; only <code>color</code> applies.</p>"
        "<p style=\"font-weight: bold\">This paragraph is bold (font-weight: bold).</p>"
        "<p style=\"font-weight: 700\">Numeric weight 700 is bold too.</p>"
        "<p style=\"font-style: italic\">This one is italic (font-style: italic).</p>"
        "<p>Normal, then <span style=\"font-weight:bold; color:#cc0000\">bold red</span> (weight + colour together), then normal.</p>"
        "<p style=\"color: rgb(192, 20, 60)\">This uses <code>rgb(192, 20, 60)</code> &mdash; functional colour notation.</p>"
        "<p style=\"color: rgb(10%, 40%, 75%)\">And this is <code>rgb(10%, 40%, 75%)</code> &mdash; percentage components.</p>"
        "<p style=\"color: crimson\">Named colours expanded too: <span style=\"color:indigo\">indigo</span>, <span style=\"color:teal\">teal</span>, <span style=\"color:steelblue\">steelblue</span>, <span style=\"color:darkgreen\">darkgreen</span>.</p>"
        "<p>An <u>underlined</u> word (the <code>&lt;u&gt;</code> tag), and <span style=\"text-decoration: underline\">text-decoration: underline</span> set inline.</p>"
        "<p style=\"text-decoration: underline; color: #cc0000; font-weight: bold\">Underlined, red, <i>and</i> bold &mdash; all three compose on one element.</p>" },
    { "CSS     HTM", "<title>CSS style blocks</title><style>\n"
        "  h2 { color: #800080 }\n"
        "  p { color: #333333 }\n"
        "  .warn { color: red; font-weight: bold }\n"
        "  #lead { color: #008000; font-style: italic }\n"
        "  .b { font-weight: bold }\n"
        "  .hl { background-color: #ffe000 }\n"
        "  .code { background: #eaeaea; color: #a00000 }\n"
        "  .g1, .g2, em { color: #cc00cc; font-weight: bold }\n"
        "</style>"
        "<h1>CSS &lt;style&gt; blocks</h1>"
        "<p>A <code>&lt;style&gt;</code> block in the page now drives a small CSS engine: simple rules (<code>tag</code>, <code>.class</code>, <code>#id</code>) set <code>color</code> / <code>font-weight</code> / <code>font-style</code> / <code>background-color</code>, cascading under inline <code>style=</code>.</p>"
        "<h2>This heading is purple (h2 rule)</h2>"
        "<p id=\"lead\">This lead paragraph is green italic &mdash; matched by <code>#lead</code>.</p>"
        "<p>This paragraph is dark gray &mdash; matched by the bare <code>p</code> rule.</p>"
        "<p class=\"warn\">This is a bold red warning &mdash; <code>.warn</code> wins over <code>p</code> (later rule).</p>"
        "<p class=\"b\">This whole paragraph is bold <i>and</i> gray &mdash; the <code>.b</code> rule (bold) cascades with the <code>p</code> rule (gray) on one element.</p>"
        "<p style=\"color: #0000cc\">Inline <code>style=\"color:blue\"</code> overrides the <code>p</code> rule &mdash; this line is blue.</p>"
        "<p>A comma-grouped rule <code>.g1, .g2, em { color:#cc00cc; font-weight:bold }</code> colours all of: <span class=\"g1\">class g1</span>, <span class=\"g2\">class g2</span>, and <em>an em element</em> &mdash; magenta bold.</p>"
        "<p>Strikethrough: <span style=\"text-decoration:line-through\">struck via CSS</span>, and <s>via the &lt;s&gt; tag</s> &mdash; both get a line through.</p>"
        "<p>HSL colours: <span style=\"color:hsl(0,85%,45%)\">hsl red</span>, <span style=\"color:hsl(120,60%,35%)\">hsl green</span>, <span style=\"color:hsl(240,75%,55%)\">hsl blue</span>, and <span style=\"background:hsl(50,95%,80%)\">an hsl-yellow background</span>.</p>"
        "<p>Background colours: <span class=\"hl\">a .hl-highlighted run</span>, some <span class=\"code\">inline code</span> (grey bg, red text), an inline <span style=\"background-color:#b3e5ff\">light-blue span</span>, <span style=\"background:#222222;color:#ffffff\">white-on-dark</span>, and a <mark>&lt;mark&gt; element</mark>.</p>" },
    { "ALIGN   HTM", "<title>CSS text-align</title><style> .c{text-align:center} .r{text-align:right} </style>"
        "<h1 style=\"text-align:center\">Centered heading</h1>"
        "<p style=\"text-align:center\">This whole paragraph is centered via inline <code>text-align:center</code>, and it wraps across several lines so you can see that each wrapped line is individually centered within the content column rather than just the first.</p>"
        "<p style=\"text-align:right\">This paragraph is right-aligned (inline <code>text-align:right</code>), also wrapping to show each line flush to the right edge.</p>"
        "<p class=\"c\">Centered by a <code>.c</code> &lt;style&gt; class rule.</p>"
        "<p class=\"r\">Right-aligned by a <code>.r</code> class rule.</p>"
        "<center>The legacy &lt;center&gt; tag also centers.</center>"
        "<p align=\"right\">And the old <code>align=\"right\"</code> attribute works too.</p>"
        "<p>This last paragraph is normal left-aligned flow for comparison.</p>" },
    { "SIZE    HTM", "<title>CSS font-size</title>"
        "<p>Normal body text (1x). Then "
        "<span style=\"font-size:24px\">24px is 2x</span>, and "
        "<span style=\"font-size:34px\">34px is 3x</span>. "
        "Percentages: <span style=\"font-size:200%\">200%</span>. "
        "Ems: <span style=\"font-size:2em\">2em</span>. "
        "The legacy <big>&lt;big&gt; tag</big> and <font size=\"6\">&lt;font size=6&gt;</font> enlarge too. "
        "Small sizes such as <span style=\"font-size:10px\">10px</span> stay 1x &mdash; the bitmap font has no sub-1x. "
        "<span style=\"font-size:28px;color:#cc3300\">Large + coloured</span> compose.</p>" },
    { "HIDE    HTM", "<title>display:none</title><style> .gone{display:none} .big{font-size:30px} </style><h2>CSS display:none</h2>"
        "<p>1. This paragraph is visible.</p>"
        "<p style=\"display:none\">HIDDENP: this paragraph sets display:none and must NOT appear anywhere.</p>"
        "<div hidden><p>HIDDENDIV: hidden via the HTML5 hidden attribute.</p><ul><li>HIDDENLI a hidden list item</li></ul></div>"
        "<p class=\"gone\">HIDDENCLASS: hidden by a <code>.gone { display:none }</code> &lt;style&gt; rule.</p>"
        "<p>2. This paragraph is visible again, immediately after the hidden block.</p>"
        "<p>3. A visible span<span style=\"display:none\"> HIDDENSPAN</span> with a hidden inline span (the word HIDDENSPAN must not show).</p>"
        "<p class=\"big\">4. This paragraph is enlarged by a .big font-size rule.</p>"
        "<p style=\"visibility:hidden\">HIDDENVIS: visibility:hidden must NOT appear.</p>"
        "<p>5. Visible, and a hidden image <img src=\"file:LOGO.SVG\" style=\"display:none\"> follows here (it must not appear).</p>" },
    { "QUOTE   HTM", "<title>Blockquotes</title><h2>Blockquotes</h2>"
        "<p>A normal paragraph sits at the left margin for comparison.</p>"
        "<blockquote>This is a quoted block: it is indented from the left margin, and crucially, when it wraps across several lines every wrapped line stays indented under the quote &mdash; not only the first line.</blockquote>"
        "<p>Back at the normal margin.</p>"
        "<blockquote>An outer quote. <blockquote>A nested quote is indented one level further than its parent.</blockquote> And back out to the outer level again.</blockquote>"
        "<p>Normal flow resumes here.</p>" },
    { "NEST    HTM", "<title>Nested style scopes</title><style>\n"
        "  p { color: #333333 }\n"
        "  .red { color: #cc0000 }\n"
        "  .up { text-transform: uppercase }\n"
        "</style>"
        "<h1>Nested style scopes</h1>"
        "<p>Styled elements now <i>nest</i>: a colour applies to its element's content and the previous colour is restored at its close, to any depth.</p>"
        "<p>This paragraph is gray (the <code>p</code> rule), with a <span class=\"red\">red span</span> inside, then gray again.</p>"
        "<p style=\"color: #008000\">Green (inline) with a <span style=\"color:#0000cc\">blue span</span> nested inside, then green again &mdash; inline nesting composes too.</p>"
        "<p style=\"color: #800080\">Purple, with <b style=\"color:#cc0000\">bold red</b> nested, then <span style=\"font-style:italic\">italic purple</span>, then purple.</p>"
        "<p style=\"text-transform:uppercase\">text-transform: this line is rendered in UPPERCASE (the source stays lower-case).</p>"
        "<p style=\"text-transform:lowercase\">text-transform: THIS LINE is rendered in lowercase.</p>"
        "<p class=\"up\">and via a &lt;style&gt; rule (.up): this line is uppercased by the cascade.</p>" },
    { "ARTICLE HTM", "<title>A styled article</title>"
        "<style> h1 { color:#2c66d6 }  h2 { color:#800080 }  .lead { color:#555555; font-style:italic }  .tip { color:#006400; font-weight:bold } </style>"
        "<h1>Rendering CSS from scratch</h1>"
        "<p class=\"lead\">How a from-scratch OS browser styles text without a layout engine.</p>"
        "<p>This page is drawn by OS-DEV's own browser and styled by its own small CSS engine &mdash; no libraries, just a token-stream renderer with a per-element "
        "<span style=\"color:#cc0000\">colour</span> / <b>weight</b> / <span style=\"font-style:italic\">style</span> / <u>underline</u> scope that nests.</p>"
        "<h2>What works</h2>"
        "<p>Inline <code>style=</code> and <code>&lt;style&gt;</code> rules with <code>tag</code>, <code>.class</code> and <code>#id</code> selectors; a real cascade (rules &lt; inline, per property); and a scope stack so styled elements nest to any depth.</p>"
        "<p class=\"tip\">Tip: see style.htm, css.htm and nest.htm for the focused feature tests.</p>"
        "<h2>What doesn't (yet)</h2>"
        "<p>Layout &mdash; <code>font-size</code>, <code>text-align</code>, the box model &mdash; needs a real layout engine the flat token stream lacks. That's the honest boundary; the <i>machinery</i> of CSS (selectors, cascade, nesting) is here.</p>" },
    { "HELP    HTM", "<html><head><title>OS-DEV Help</title>"
        "<style> h1 { color:#2C66D6 }  h2 { color:#800080 }  dt { color:#b8860b; font-weight:bold }  .key { color:#006400; font-weight:bold } </style></head><body>"
        "<h1>OS-DEV Help</h1>"
        "<p>A quick guide to the system &mdash; this page is itself styled by the from-scratch CSS engine.</p>"
        "<h2>Apps</h2>"
        "<p>Open from the <b>Apps</b> menu (<span class=\"key\">F9</span>) or the shell with <code>run NAME</code>:</p>"
        "<dl>"
        "<dt>shell, clock, calc, editor</dt><dd>a terminal, a clock dashboard, a calculator (<code>+ - * / % ^ &amp; | &lt;&lt; &gt;&gt; ~</code>, parens, <code>0x</code> hex), a text editor</dd>"
        "<dt>games</dt><dd>snake, 2048, life, tetris, breakout, mines, sudoku, maze, hangman, ttt (tic-tac-toe vs an unbeatable AI), bj (blackjack), simon (a tone-memory game), c4 (Connect Four vs an AI), adv (a text adventure) &mdash; all in colour, several with saved best scores</dd>"
        "<dt>tools</dt><dd>calendar (month view), mandel (a Mandelbrot explorer), piano, jukebox (built-in tunes), matrix (a digital-rain screensaver), paint (an ASCII-art canvas, saves to PAINT.TXT), typing (a WPM speed test)</dd>"
        "<dt>productivity</dt><dd>sheet (a spreadsheet: live formulas, ~45 functions incl. MEDIAN/MODE/SUMIF, CSV, bar charts, copy/paste + fill with ref-adjustment, row sort, find, per-column number formats), plot (a graphing calculator: several curves at once, definite integral / derivative / roots, zoom + range, save to BMP), gpaint (a mouse pixel-paint with line/box/ellipse/flood-fill, 8-level undo/redo, BMP + PNG export), imgview (view PNG/GIF/JPEG/BMP/SVG/WebP; <span class=\"key\">s</span> saves the decoded image as BMP)</dd>"
        "<dt>developer tools</dt><dd>gjson (JSON validate / pretty-print / minify / save), gregex (a regex tester on the JS engine), gdiff (a visual line diff; <span class=\"key\">s</span> saves a unified-diff patch), garc (list a zip / tar / tgz), ghash (SHA-256/512, CRC-32 and Base64 of a file)</dd>"
        "</dl>"
        "<h2>Shell commands</h2>"
        "<p>Files: <code>ls cat head tail sort nl tac uniq cut edit write rm cp mv mkdir cd pwd tree find grep hexdump wc patch</code>. "
        "Net: <code>get URL</code>, <code>headers URL</code>, <code>wget URL FILE</code>, <code>browse URL</code>, <code>ping [HOST]</code>, <code>resolve HOST</code>, <code>ifconfig</code>. "
        "Crypto: <code>sha256 FILE</code>, <code>sha512 FILE</code>, <code>crypt</code>, <code>base64</code>. "
        "Also: <code>apps</code>, <code>js</code>, <code>cal</code>, <code>date</code>, <code>mem</code>, <code>ps</code>, <code>df</code>, <code>beep</code>, <code>morse TEXT</code>, <code>factor N</code>, <code>clear</code>. Type <code>help</code> in the shell for the full list.</p>"
        "<h2>Keyboard</h2>"
        "<p>Desktop: <span class=\"key\">F1</span> shortcut help, <span class=\"key\">F2</span> cycle windows, <span class=\"key\">F3</span> minimise, <span class=\"key\">F4</span> maximise, <span class=\"key\">F5</span>/<span class=\"key\">F6</span> tile left/right, <span class=\"key\">F8</span> close, <span class=\"key\">F9</span> Apps menu (type a letter to jump), <span class=\"key\">F12</span> screenshot to disk.</p>"
        "<p>Mouse: drag a title bar to move (double-click it, or drag to the top edge, to maximise; drag to a side edge to tile); drag the bottom-right corner to resize; click the clock for the calendar.</p>"
        "<p>Browser: <span class=\"key\">e</span>/<span class=\"key\">/</span> edit the address, <span class=\"key\">Tab</span>/<span class=\"key\">n</span> next link, <span class=\"key\">p</span> previous, <span class=\"key\">Enter</span> follow, <span class=\"key\">Backspace</span> back, <span class=\"key\">h</span> home, <span class=\"key\">s</span> save, <span class=\"key\">a</span> bookmark, <span class=\"key\">\\</span> find text.</p>"
        "<p>Files: <span class=\"key\">&uarr;</span>/<span class=\"key\">&darr;</span> or click to select, <span class=\"key\">Enter</span> open a file (or double-click a <b>folder</b> to enter it), <span class=\"key\">Backspace</span> up a directory. <span class=\"key\">d</span> delete (press again to confirm), <span class=\"key\">r</span> rename, <span class=\"key\">n</span> new folder, <span class=\"key\">c</span>/<span class=\"key\">x</span>/<span class=\"key\">v</span> copy/cut/paste a file across folders, <span class=\"key\">w</span> set an image as the wallpaper, <span class=\"key\">o</span> cycle the sort order. Each Files window has its own browse directory &mdash; independent of the shell's.</p>"
        "</body></html>" },
    { "JSDEEP  HTM", "<h1>Deep recursion guard</h1>"
        "<p>This page's script recurses 500 deep on purpose. The interpreter must"
        " stop it at the depth cap and report an error &mdash; <b>without</b> crashing"
        " the OS (the browser runs page scripts on the kernel stack, which has no"
        " guard page):</p>"
        "<script>\n"
        "function r(n){ return n <= 0 ? 0 : 1 + r(n - 1); }\n"
        "document.write(\"<p>r(500) = \" + r(500) + \"</p>\");\n"
        "</script>"
        "<p>If you can read this paragraph and the OS is still responsive, the guard held.</p>" },
    { "JSNEW   HTM", "<h1>New JS engine features</h1>"
        "<p>Every value below is computed <b>live</b> by the from-scratch JavaScript engine &mdash; operators, number-literal formats, and standard-library methods added recently:</p>"
        "<script>\n"
        "document.write(\"<h2>Operators</h2>\");\n"
        "document.write(\"<p>2 ** 10 = \" + (2 ** 10) + \" | 2 ** 3 ** 2 = \" + (2 ** 3 ** 2) + \" (right-associative)</p>\");\n"
        "document.write(\"<p>5 in [1,2,3,4,5] = \" + (5 in [1,2,3,4,5]) + \" | 12 ^ 10 = \" + (12 ^ 10) + \" | ~5 = \" + (~5) + \"</p>\");\n"
        "var o = {a:1, b:2, c:3}; delete o.b;\n"
        "document.write(\"<p>after delete o.b, keys = \" + Object.keys(o).join(\", \") + \"</p>\");\n"
        "class Animal { constructor(n){ this.n = n; } } class Dog extends Animal {}\n"
        "document.write(\"<p>new Dog() instanceof Animal = \" + (new Dog(\"Rex\") instanceof Animal) + \"</p>\");\n"
        "document.write(\"<h2>Number literals</h2>\");\n"
        "document.write(\"<p>0b1010 = \" + 0b1010 + \" | 0o17 = \" + 0o17 + \" | 0xFF = \" + 0xFF + \" | 1e3 = \" + 1e3 + \"</p>\");\n"
        "document.write(\"<h2>Standard library</h2>\");\n"
        "document.write(\"<p>Array.from({length:5}, i =&gt; i*i) = [\" + Array.from({length:5}, function(x,i){return i*i;}).join(\", \") + \"]</p>\");\n"
        "document.write(\"<p>[3,1,2,5,4].fill(0,1,3) = [\" + [3,1,2,5,4].fill(0,1,3).join(\", \") + \"]</p>\");\n"
        "document.write(\"<p>Math.hypot(3,4) = \" + Math.hypot(3,4) + \" | Math.cbrt(27) = \" + Math.cbrt(27) + \" | Math.log2(1024) = \" + Math.log2(1024) + \"</p>\");\n"
        "var fz = Object.freeze({x:1}); fz.x = 99;\n"
        "document.write(\"<p>Object.freeze({x:1}): after fz.x=99, x is still \" + fz.x + \"</p>\");\n"
        "document.write(\"<h2>Modern classes &amp; assignment</h2>\");\n"
        "class Pt { x = 0; y = 0; dist2(){ return this.x*this.x + this.y*this.y; } }\n"
        "var pt = new Pt(); pt.x = 3; pt.y = 4;\n"
        "document.write(\"<p>class fields + method: new Pt(), set x=3 y=4, dist2() = \" + pt.dist2() + \"</p>\");\n"
        "var cfg = {}; cfg.theme ||= \"dark\"; cfg.theme ||= \"light\";\n"
        "document.write(\"<p>logical assign: cfg.theme ||= dark then ||= light gives \" + cfg.theme + \"</p>\");\n"
        "class Counter { static total = 0; static add(){ Counter.total = Counter.total + 1; return Counter.total; } }\n"
        "document.write(\"<p>static counter: add() three times = \" + Counter.add() + \", \" + Counter.add() + \", \" + Counter.add() + \"</p>\");\n"
        "function hl(parts, v){ return parts[0] + \"[\" + v + \"]\" + parts[1]; }\n"
        "document.write(\"<p>tagged template (cooked strings + a ${6*7} value) = \" + hl`a ${6*7} b` + \"</p>\");\n"
        "document.write(\"<h2>Getters &amp; setters (M261)</h2>\");\n"
        "var temp = { _c: 20, get f(){ return this._c * 9 / 5 + 32; }, set f(v){ this._c = (v - 32) * 5 / 9; } };\n"
        "document.write(\"<p>object literal: get f() reads 20&deg;C as \" + temp.f + \"&deg;F</p>\");\n"
        "temp.f = 212;\n"
        "document.write(\"<p>then set f = 212 runs the setter, so _c is now \" + temp._c + \"&deg;C</p>\");\n"
        "class Circle { constructor(r){ this.r = r; } get area(){ return (314 * this.r * this.r) / 100; } }\n"
        "document.write(\"<p>class getter: new Circle(5).area = \" + new Circle(5).area + \" (using pi as 314/100 in the integer engine)</p>\");\n"
        "var counter = { _n: 5, get n(){ return this._n; }, set n(v){ this._n = v; } }; counter.n++;\n"
        "document.write(\"<p>counter.n++ routes through get+set, leaving the accessor intact: n = \" + counter.n + \"</p>\");\n"
        "document.write(\"<h2>Object.is &amp; immutable arrays (M259&ndash;260)</h2>\");\n"
        "document.write(\"<p>Object.is({},{}) = \" + Object.is({},{}) + \" (distinct objects) | Object.is(2,2) = \" + Object.is(2,2) + \"</p>\");\n"
        "var base = [3,1,2]; var sorted = base.toSorted();\n"
        "document.write(\"<p>[3,1,2].toSorted() = [\" + sorted.join(\", \") + \"], original still [\" + base.join(\", \") + \"] (immutable)</p>\");\n"
        "document.write(\"<p>[1,2,3].with(1, 9) = [\" + [1,2,3].with(1,9).join(\", \") + \"]</p>\");\n"
        "document.write(\"<h2>Prototype chain (M263)</h2>\");\n"
        "var animal = { describe: function(){ return this.name + \" says \" + this.sound; } };\n"
        "var dog = Object.create(animal); dog.name = \"Rex\"; dog.sound = \"woof\";\n"
        "document.write(\"<p>Object.create(animal): dog.describe() = \" + dog.describe() + \"</p>\");\n"
        "function Counter(){ this.n = 0; } Counter.prototype.inc = function(){ return ++this.n; };\n"
        "var c = new Counter();\n"
        "document.write(\"<p>new Counter() + Counter.prototype.inc(): \" + c.inc() + \", \" + c.inc() + \", \" + c.inc() + \"</p>\");\n"
        "document.write(\"<p>c instanceof Counter = \" + (c instanceof Counter) + \" | Object.getPrototypeOf(dog) === animal = \" + (Object.getPrototypeOf(dog) === animal) + \"</p>\");\n"
        "document.write(\"<h2>Metaprogramming &amp; collections (M262&ndash;279)</h2>\");\n"
        "var person={_name:\"Ada\"}; Object.defineProperty(person,\"name\",{get:function(){return this._name;},set:function(v){this._name=v;}});\n"
        "document.write(\"<p>Object.defineProperty accessor: person.name = \" + person.name + \"</p>\");\n"
        "document.write(\"<p>Reflect: has(name) = \" + Reflect.has(person,\"name\") + \", ownKeys = [\" + Reflect.ownKeys(person).join(\", \") + \"]</p>\");\n"
        "var wmap=new WeakMap(); var wkey={}; wmap.set(wkey,42);\n"
        "document.write(\"<p>WeakMap: set a key, get it back = \" + wmap.get(wkey) + \"</p>\");\n"
        "document.write(\"<p>Equality: two distinct {}=={} is \" + ({}=={}) + \" | loose 1 == (string)1 is \" + (1==\"1\") + \" | strict 1 === (string)1 is \" + (1===\"1\") + \"</p>\");\n"
        "document.write(\"<p>(1234567).toLocaleString() = \" + (1234567).toLocaleString() + \"</p>\");\n"
        "</script>"
        "<p><a href=\"file:index.htm\">Back to the demo index</a></p>" },
    { "REMOVE  HTM", "<h1>element.remove()</h1>"
        "<p>The middle paragraph is removed at load by JavaScript &mdash; only Alpha and Gamma should remain below:</p>"
        "<p id=\"a\">Alpha (kept)</p>"
        "<p id=\"b\">Beta (removed by JS)</p>"
        "<p id=\"c\">Gamma (kept)</p>"
        "<script>document.getElementById(\"b\").remove();</script>"
        "<p>Backspace or the link returns to the index.</p>"
        "<p><a href=\"file:index.htm\">Back to the demo index</a></p>" },
    { "DOM     HTM", "<h1>Interactive DOM</h1>"
        "<p>Each link runs JavaScript that updates the page <b>in place</b> by mutating an element through <code>document.getElementById</code> &mdash; no document.write. Tab/n to a link, Enter to run it:</p>"
        "<p>Counter: <b id=\"count\">0</b> &nbsp; fib(counter) = <b id=\"fib\">0</b></p>"
        "<p>Message: <span id=\"msg\">(click below)</span></p><ul>"
        "<li><a href=\"javascript:var c=parseInt(document.getElementById('count').textContent)+1; document.getElementById('count').textContent=''+c\">increment the counter</a></li>"
        "<li><a href=\"javascript:function f(k){return k<2?k:f(k-1)+f(k-2);} document.getElementById('fib').textContent=''+f(parseInt(document.getElementById('count').textContent))\">compute fib(counter) &mdash; DOM read, JS recursion, DOM write</a></li>"
        "<li><a href=\"javascript:document.getElementById('msg').textContent='Hello from a real DOM!'\">set the message text</a></li>"
        "<li><a href=\"javascript:document.getElementById('msg').innerHTML='now <b>bold</b> via innerHTML'\">set message HTML</a></li>"
        "<li><a href=\"javascript:document.getElementById('count').textContent='0'; document.getElementById('fib').textContent='0'; document.getElementById('msg').textContent='(reset)'\">reset</a></li>"
        "</ul>"
        "<p>And an inline <code>&lt;button onclick=...&gt;</code> (a real HTML event handler, not a javascript: link): "
        "<button onclick=\"document.getElementById('count').textContent='42'\">[ set counter to 42 ]</button></p>"
        "<p>The values above change when you click &mdash; the element is found by id, its content replaced (after computing), and the page re-renders.</p>" },
    { "OOP     HTM", "<h1>Object-oriented JavaScript in the browser</h1>"
        "<p>The list below is generated live by a page &lt;script&gt; using classes, inheritance, <code>super</code>, destructuring, spread and template literals:</p><ul>"
        "<script>\n"
        "class Shape {\n"
        "  constructor(name){ this.name = name; }\n"
        "  describe(){ return this.name; }\n"
        "}\n"
        "class Circle extends Shape {\n"
        "  constructor(r){ super(\"circle\"); this.r = r; }\n"
        "  describe(){ return super.describe() + \" r=\" + this.r + \" area=\" + (3*this.r*this.r); }\n"
        "}\n"
        "var shapes = [new Circle(2), new Circle(5)];\n"
        "for (var s of shapes) document.write(\"<li>\" + s.describe() + \"</li>\");\n"
        "var [first, ...others] = shapes;\n"
        "document.write(\"<p>first is a \" + first.describe() + \"; \" + others.length + \" others</p>\");\n"
        "var nums = [1, 2, 3];\n"
        "document.write(\"<p>spread: [\" + [0, ...nums, 4].join(\", \") + \"]</p>\");\n"
        "document.write(`<p>template literal: ${nums.length} numbers, max ${Math.max(...nums)}</p>`);\n"
        "</script>" },
    { "SHOWCASEJS ", "print(\"== OS-DEV from-scratch JavaScript ==\");\n"
        "var n = [5, 3, 8, 1, 9, 2, 7];\n"
        "print(\"squares: \" + n.map(x => x * x).join(\", \"));\n"
        "print(\"evens:   \" + n.filter(x => x % 2 == 0).join(\", \"));\n"
        "var s = 0; n.forEach(x => s += x); print(\"sum:     \" + s);\n"
        "function fib(k){ return k < 2 ? k : fib(k-1) + fib(k-2); }\n"
        "print(\"fib:     \" + [0,1,2,3,4,5,6,7,8,9,10].map(fib).join(\", \"));\n"
        "var d = { os: \"OS-DEV\", ms: 169, features: [\"TLS\", \"browser\", \"JS\"] };\n"
        "print(\"json:    \" + JSON.stringify(d));\n"
        "var back = JSON.parse(JSON.stringify(d));\n"
        "print(\"parse:   \" + back.os + \", \" + back.features.length + \" features, sqrt(2025)=\" + Math.sqrt(2025));\n" },
    { "JSCLICK HTM", "<h1>Interactive JavaScript</h1>"
        "<p>Each link runs JavaScript <b>in the page</b> when you click it (or Tab/n to select, then Enter). The result is appended below:</p><ul>"
        "<li><a href=\"javascript:var c=(parseInt(localStorage.getItem('c'))||0)+1; localStorage.setItem('c',c); document.write('<p><b>counter = '+c+'</b> (click again &mdash; it remembers, via localStorage)</p>')\">a stateful counter</a></li>"
        "<li><a href=\"javascript:document.write('<p><b>6 * 7 = '+(6*7)+'</b></p>')\">compute 6 * 7</a></li>"
        "<li><a href=\"javascript:var s=0; for(var i=1;i<=100;i++) s+=i; document.write('<p>sum 1..100 = '+s+'</p>')\">sum 1..100</a></li>"
        "<li><a href=\"javascript:document.write('<p>squares: '+[1,2,3,4,5].map(x=>x*x).join(', ')+'</p>')\">squares via map(x =&gt; x*x)</a></li>"
        "<li><a href=\"javascript:document.write('<p>primes up to 50: '+(function(){var r=[];for(var n=2;n<50;n++){var p=true;for(var d=2;d*d<=n;d++)if(n%d==0)p=false;if(p)r.push(n);}return r;})().join(', ')+'</p>')\">primes under 50</a></li>"
        "<li><a href=\"javascript:document.write('<p>8! = '+[1,2,3,4,5,6,7,8].reduce(function(a,b){return a*b;})+'</p>')\">8 factorial via reduce</a></li>"
        "<li><a href=\"javascript:document.write('<p>reversed: '+'OS-DEV rocks'.split('').reverse().join('')+'</p>')\">reverse a string</a></li>"
        "</ul><hr>" },
    { "CLASS   JS ", "// class.js  --  object-oriented JavaScript, from scratch.  Run: js class.js\n"
        "class Animal {\n"
        "  constructor(name){ this.name = name; }\n"
        "  speak(){ return this.name + \" makes a sound\"; }\n"
        "}\n"
        "class Dog extends Animal {\n"
        "  constructor(name){ super(name); this.sound = \"woof\"; }\n"
        "  speak(){ return super.speak() + \" (\" + this.sound + \")\"; }\n"
        "}\n"
        "var d = new Dog(\"Rex\");\n"
        "print(d.speak());\n"
        "print(\"name=\" + d.name + \" sound=\" + d.sound);\n"
        "// a little stack, with method chaining via `this`\n"
        "class Stack {\n"
        "  constructor(){ this.items = []; }\n"
        "  push(x){ this.items.push(x); return this; }\n"
        "  size(){ return this.items.length; }\n"
        "  top(){ return this.items[this.size() - 1]; }\n"
        "}\n"
        "var st = new Stack().push(10).push(20).push(30);\n"
        "print(\"stack size=\" + st.size() + \" top=\" + st.top());\n"
        "// three-level inheritance with super at each step\n"
        "class A { who(){ return \"A\"; } }\n"
        "class B extends A { who(){ return super.who() + \"B\"; } }\n"
        "class C extends B { who(){ return super.who() + \"C\"; } }\n"
        "print(\"chain=\" + new C().who());\n" },
    { "ES6     JS ", "// es6.js  --  modern JavaScript: spread, rest, destructuring.  Run: js es6.js\n"
        "var nums = [3, 1, 4, 1, 5, 9];\n"
        "var [head, ...rest] = nums;\n"
        "print(\"head=\" + head + \" rest=\" + rest.join(\",\"));\n"
        "print(\"spread: \" + [0, ...nums, 10].join(\",\"));\n"
        "print(\"max=\" + Math.max(...nums));\n"
        "function tag(first, ...others){ return first + \" + \" + others.length + \" more\"; }\n"
        "print(tag(\"a\", \"b\", \"c\", \"d\"));\n"
        "var person = { name: \"Ada\", role: \"pioneer\", year: 1843 };\n"
        "var { name, ...info } = person;\n"
        "print(\"name=\" + name + \" info=\" + JSON.stringify(info));\n"
        "var { role: job = \"x\" } = person;\n"
        "print(\"job=\" + job);\n"
        "for (var [k, v] of [[\"x\", 1], [\"y\", 2], [\"z\", 3]]) print(\"  \" + k + \" => \" + v);\n"
        "print(\"merged: \" + JSON.stringify({ ...person, role: \"legend\" }));\n" },
    { "COLLECT JS ", "// collect.js  --  Map, Set, optional chaining, nullish.  Run: js collect.js\n"
        "var words = \"the cat sat on the mat the cat ran\".split(\" \");\n"
        "var freq = new Map();\n"
        "for (var w of words) freq.set(w, (freq.get(w) ?? 0) + 1);\n"
        "for (var [word, count] of freq) print(word + \": \" + count);\n"
        "var nums = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5];\n"
        "var uniq = new Set(); nums.forEach(n => uniq.add(n));\n"
        "print(\"unique: \" + uniq.values().join(\",\") + \" (\" + uniq.size + \" of \" + nums.length + \")\");\n"
        "var cfg = { server: { port: 8080 } };\n"
        "print(\"port=\" + (cfg?.server?.port ?? 3000));\n"
        "print(\"host=\" + (cfg?.server?.host ?? \"localhost\"));\n"
        "print(\"missing=\" + (cfg?.db?.name ?? \"none\"));\n" },
    { "REGEX   JS ", "// regex.js  --  from-scratch regular expressions, with /literal/ syntax.  Run: js regex.js\n"
        "var prices = \"apples $3, bread $2, milk $4\";\n"
        "print(\"prices: \" + prices.match(/\\d+/g).join(\", \"));\n"
        "var ok = /^[a-z0-9_]+$/i;\n"
        "print(\"user_42 valid? \" + ok.test(\"user_42\"));\n"
        "print(\"bad name! valid? \" + ok.test(\"bad name!\"));\n"
        "print(\"ISO: \" + \"01/15/2024\".replace(/(\\d+)\\/(\\d+)\\/(\\d+)/, \"$3-$1-$2\"));\n"
        "print(\"tokens: \" + \"red,  green ,blue\".split(/\\s*,\\s*/).join(\" | \"));\n"
        "print(\"first word: \" + \"  Hello there\".match(/[A-Za-z]+/)[0]);\n"
        "print(\"collapsed: [\" + \"too   many    spaces\".replace(/\\s+/g,\" \") + \"]\");\n" },
    { "RXTEST  JS ", "// rxtest.js  --  regex hardening: pathological patterns fail gracefully, never crash.\n"
        "print(\"deep groups: \" + new RegExp(\"(\".repeat(1800)).test(\"x\"));\n"   /* parser depth-capped at 400 */
        "print(\"long match: \" + new RegExp(\"a+\").test(\"a\".repeat(2500)));\n"  /* matcher depth-capped at 900 */
        "print(\"redos: \" + new RegExp(\"(a+)+$\").test(\"aaaaaaaaaaaaaaaaaaaaX\"));\n"  /* step-budget, no hang */
        "print(\"normal: \" + \"id-42\".replace(new RegExp(\"(\\\\w+)-(\\\\d+)\"), \"$2:$1\"));\n"
        "print(\"SURVIVED\");\n" },
    { "SAMPLE  C  ", "/* sample.c -- open in the editor to see C syntax highlighting.\n"
                     "   keywords are blue, strings orange, comments grey,\n"
                     "   numbers purple, and #directives teal. */\n"
                     "#include <stdio.h>\n"
                     "#define MAX 100      // a line comment\n"
                     "\n"
                     "/* greet the world a few times, then sum 0..n-1 */\n"
                     "static int sum(int n) {\n"
                     "    int total = 0;\n"
                     "    for (int i = 0; i < n; i++)\n"
                     "        total += i;          /* running total */\n"
                     "    return total;\n"
                     "}\n"
                     "\n"
                     "int main(void) {\n"
                     "    const char *msg = \"hello, OS-DEV\\n\";\n"
                     "    for (int k = 0; k < 3; k++)\n"
                     "        printf(\"%s\", msg);\n"
                     "    printf(\"sum(10) = %d, MAX = %d\\n\", sum(10), MAX);\n"
                     "    return 0xFF & 1;\n"
                     "}\n" },
    { "SAMPLE  CSS", "/* sample.css -- open in the editor to see CSS highlighting:\n"
                     "   comments grey, strings orange, numbers + #hex colours purple. */\n"
                     "body {\n"
                     "    color: #33ff66;\n"
                     "    background: #101018;\n"
                     "    margin: 0 auto;\n"
                     "    max-width: 760px;\n"
                     "    font-family: \"monospace\";\n"
                     "}\n"
                     ".card {\n"
                     "    border: 2px solid #4090ff;\n"
                     "    padding: 12px;\n"
                     "}\n"
                     "#header { font-size: 24px; }\n" },
};
#define NUM_FILES (int)(sizeof(files) / sizeof(files[0]))
#define CLUSTER_BYTES (SPC * SECTOR)
#define DIR_PER_CLUSTER (CLUSTER_BYTES / 32)   /* 32-byte dir entries per cluster */

/* Files copied verbatim from a host path (e.g. a built ELF) so the OS can load
 * real programs from disk. Skipped with a warning if the path is missing. */
static const struct {
    const char *name83;
    const char *hostpath;
} hostfiles[] = {
    { "CALC    ELF", "build/calc.elf" },   /* run it in-OS with: run calc.elf */
    { "SUITE   JS ", "tests/js/suite.js" },/* the JS regression suite — run in-OS with: js suite.js */
    { "TEST    PNG", "tools/test.png" },   /* view in-OS with: browse file:test.png */
    { "TEST    WEB", "tools/test.webp" },  /* lossless (VP8L) WebP: run imgview TEST.WEB (FAT 8.3 clips .webp) */
    { "BIG     PNG", "tools/big.png" },    /* 113 KB image — needs the 128 KB fetch buffer */
    { "ICON    PNG", "tools/icon.png" },  /* palette + tRNS transparency */
    { "LOGO    GIF", "tools/logo.gif" },  /* GIF: LZW + transparency + interlace */
    { "PHOTO   JPG", "tools/photo.jpg" }, /* baseline JPEG (integer IDCT, 4:2:0) */
    { "INTER   PNG", "tools/inter.png" }, /* interlaced (Adam7) truecolour PNG */
    { "PPHOTO  JPG", "tools/pphoto.jpg" },/* PROGRESSIVE JPEG (multi-scan, integer) */
    { "ANIM    GIF", "tools/anim.gif" },  /* ANIMATED GIF (multi-frame, timer-driven) */
    { "HELLO   GZ ", "tools/hello.gz" },  /* a gzip file: decompress in-OS with: gunzip HELLO.GZ */
    { "TEST    ZIP", "tools/test.zip" },  /* a zip archive: extract in-OS with: unzip TEST.ZIP */
    { "TEST    TGZ", "tools/test.tgz" },  /* a .tar.gz tarball: extract in-OS with: tar TEST.TGZ */
    { "DOOM1   WAD", "tools/DOOM1.WAD" }, /* the shareware DOOM IWAD (~4 MB): play in-OS with: run doom */
    { "FREEDOM1WAD", "tools/freedoom1.wad" }, /* Freedoom Phase 1 (GPL/BSD, ~27 MB): a full libre Doom IWAD */
    { "MUSIC   WAV", "tools/MUSIC.WAV" }, /* a C-major-scale tune: play in-OS with: play MUSIC.WAV */
    { "TUNE2   WAV", "tools/TUNE2.WAV" }, /* an arpeggio (for the jukebox playlist) */
    { "TUNE3   WAV", "tools/TUNE3.WAV" }, /* a little melody (for the jukebox playlist) */
    { "WALL    PNG", "tools/WALL.PNG" },  /* the desktop wallpaper (1024x768), loaded by the WM */
    { "PAK0    PAK", "tools/PAK0.PAK" },  /* shareware Quake data (~18 MB): play in-OS with: run quake */
    { "NOVA    NES", "tools/nova.nes" },  /* Nova the Squirrel (GPLv3 homebrew NES game): play with: run nes */
    { "240P    NES", "tools/240p.nes" },  /* 240p test suite (GPLv3, by Tepples): a video/sound test ROM */
    { "LIBBET  GB ", "tools/libbet.gb" }, /* Libbet and the Magic Floor (Zlib, by Tepples): a Game Boy game */
    { "DLTEST  SO ", "build/dltest.so" }, /* a shared library for the userspace dynamic linker (M1263): dltest builtin dlopen()s it */
    { "DLBASE  SO ", "build/dlbase.so" }, /* cross-object dynamic linking (M1539): exports base_mul; loaded first */
    { "DLEXT   SO ", "build/dlext.so" },  /* imports base_mul from DLBASE.SO; dlxtest builtin dlopen()s both in order */
    { "TESTMOD KO ", "build/testmod.ko" }, /* the same ET_REL module module_load_builtin() incbins (M1261); insmodtest (M1595) loads THIS copy from a real file instead */
};
#define NUM_HOST (int)(sizeof(hostfiles) / sizeof(hostfiles[0]))

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <output.img>\n", argv[0]);
        return 1;
    }

    /* Solve for the FAT size (sectors) that covers the cluster count. */
    uint32_t fatsz = 1, clusters;
    for (;;) {
        uint32_t data = FS_SECTORS - RESERVED - NUM_FATS * fatsz;   /* FS owns FS_SECTORS; journal tail excluded */
        clusters = data / SPC;
        uint32_t need = ((clusters + 2) * 4 + SECTOR - 1) / SECTOR;
        if (need <= fatsz) break;
        fatsz = need;
    }

    uint32_t fat_start  = RESERVED;
    uint32_t data_start = RESERVED + NUM_FATS * fatsz;   /* cluster 2 lands here */

    img = calloc(TOTAL_SECTORS, SECTOR);
    if (!img) { perror("calloc"); return 1; }

    /* ---- boot sector / BPB ---- */
    uint8_t *b = img;
    b[0] = 0xEB; b[1] = 0x58; b[2] = 0x90;        /* jmp + nop */
    memcpy(b + 3, "OSDEV1.0", 8);                 /* OEM name */
    put16(b + 11, SECTOR);                        /* bytes per sector */
    b[13] = SPC;                                  /* sectors per cluster */
    put16(b + 14, RESERVED);                      /* reserved sectors */
    b[16] = NUM_FATS;                             /* number of FATs */
    put16(b + 17, 0);                             /* root entries (0 on FAT32) */
    put16(b + 19, 0);                             /* total16 (0 -> use total32) */
    b[21] = 0xF8;                                 /* media descriptor */
    put16(b + 22, 0);                             /* FAT size 16 (0 on FAT32) */
    put16(b + 24, 32);                            /* sectors per track */
    put16(b + 26, 2);                             /* heads */
    put32(b + 28, 0);                             /* hidden sectors */
    put32(b + 32, FS_SECTORS);                    /* total sectors 32 (FS volume; journal tail is beyond this) */
    put32(b + 36, fatsz);                         /* FAT size 32 */
    put16(b + 40, 0);                             /* ext flags */
    put16(b + 42, 0);                             /* fs version */
    put32(b + 44, 2);                             /* root cluster */
    put16(b + 48, 1);                             /* FSInfo sector */
    put16(b + 50, 6);                             /* backup boot sector */
    b[64] = 0x80;                                 /* drive number */
    b[66] = 0x29;                                 /* extended boot signature */
    put32(b + 67, 0x12345678);                    /* volume id */
    memcpy(b + 71, "OSDEV VOL  ", 11);            /* volume label */
    memcpy(b + 82, "FAT32   ", 8);                /* fs type */
    put16(b + 510, 0xAA55);                       /* boot signature */

    /* ---- FAT + directory + file data ---- */
    uint32_t *fat = calloc(clusters + 2, sizeof(uint32_t));
    fat[0] = 0x0FFFFFF8;          /* media in low byte */
    fat[1] = 0x0FFFFFFF;
    /* root directory FAT chain is set once we know the file count (below) */

    /* Build a unified list of {name, bytes, len}: inline strings first, then any
     * host files read from disk (e.g. build/calc.elf). */
    struct { const char *name83; const uint8_t *data; uint32_t len; } ent[NUM_FILES + NUM_HOST];   /* exact size: can't overflow, auto-grows */
    int ne = 0;
    for (int i = 0; i < NUM_FILES; i++)
        ent[ne++] = (typeof(ent[0])){ files[i].name83, (const uint8_t *)files[i].content,
                                      (uint32_t)strlen(files[i].content) };
    for (int i = 0; i < NUM_HOST && ne < NUM_FILES + NUM_HOST; i++) {
        FILE *hf = fopen(hostfiles[i].hostpath, "rb");
        if (!hf) { fprintf(stderr, "mkfatfs: skip %s (not found)\n", hostfiles[i].hostpath); continue; }
        fseek(hf, 0, SEEK_END); long sz = ftell(hf); fseek(hf, 0, SEEK_SET);
        uint8_t *buf = malloc(sz > 0 ? (size_t)sz : 1);
        if (fread(buf, 1, (size_t)sz, hf) != (size_t)sz) { fprintf(stderr, "mkfatfs: read %s failed\n", hostfiles[i].hostpath); fclose(hf); free(buf); continue; }
        fclose(hf);
        ent[ne++] = (typeof(ent[0])){ hostfiles[i].name83, buf, (uint32_t)sz };
    }

    /* The root directory itself spans as many clusters as it needs (16 dir
     * entries per 512-byte cluster), chained in the FAT.  We size it one slot
     * past the last entry so a zeroed end-of-directory marker always exists. */
    uint32_t rootcl = (uint32_t)ne / DIR_PER_CLUSTER + 1;
    if (rootcl > clusters) {   /* highest root cluster (1+rootcl) must be <= clusters+1 */
        fprintf(stderr, "mkfatfs: %u files need a %u-cluster root, volume holds %u\n",
                (unsigned)ne, rootcl, clusters);
        return 1;
    }
    for (uint32_t c = 0; c < rootcl; c++)
        fat[2 + c] = (c == rootcl - 1) ? 0x0FFFFFFF : (2 + c + 1);

    /* Lay each file out as a chain of clusters (multi-cluster supported),
     * starting right after the root directory clusters. */
    uint32_t next_cluster = 2 + rootcl;

    /* Stamp every baked file with the build date/time, packed in FAT format,
     * so `ls` and the Files app show a date for system files too (not just
     * runtime-created ones).  SOURCE_DATE_EPOCH is honoured for reproducible
     * builds; otherwise the wall-clock build time is used. */
    uint16_t fdate, ftime;
    {
        time_t now;
        const char *sde = getenv("SOURCE_DATE_EPOCH");
        if (sde && *sde) now = (time_t)strtoll(sde, NULL, 10);
        else             now = time(NULL);
        struct tm tmv, *tm = gmtime(&now);
        if (tm) tmv = *tm; else memset(&tmv, 0, sizeof tmv);
        int y = tmv.tm_year + 1900 - 1980;
        if (y < 0) y = 0;
        if (y > 127) y = 127;
        fdate = (uint16_t)((y << 9) | ((tmv.tm_mon + 1) << 5) | tmv.tm_mday);
        ftime = (uint16_t)((tmv.tm_hour << 11) | (tmv.tm_min << 5) | (tmv.tm_sec / 2));
    }

    for (int i = 0; i < ne; i++) {
        uint32_t len = ent[i].len;
        uint32_t need = len ? (len + CLUSTER_BYTES - 1) / CLUSTER_BYTES : 1;
        if (next_cluster + need - 1 > clusters + 1) {   /* would run past the last data cluster */
            fprintf(stderr, "mkfatfs: out of space writing %.11s (needs %u clusters)\n",
                    ent[i].name83, need);
            return 1;
        }
        uint32_t first = next_cluster;
        for (uint32_t c = 0; c < need; c++) {
            uint32_t cl = next_cluster++;
            fat[cl] = (c == need - 1) ? 0x0FFFFFFF : cl + 1;   /* chain, EOC on last */
            uint8_t *data = img + ((uint64_t)data_start + (cl - 2) * SPC) * SECTOR;
            uint32_t off = c * CLUSTER_BYTES, n = len - off;
            if (n > CLUSTER_BYTES) n = CLUSTER_BYTES;
            memcpy(data, ent[i].data + off, n);
        }
        /* directory entry, placed in the right root-directory cluster */
        uint8_t *de = img + ((uint64_t)data_start + (uint32_t)(i / DIR_PER_CLUSTER) * SPC) * SECTOR
                          + (i % DIR_PER_CLUSTER) * 32;
        memcpy(de, ent[i].name83, 11);
        de[11] = 0x20;                            /* attribute: archive */
        put16(de + 14, ftime);                    /* create time */
        put16(de + 16, fdate);                    /* create date */
        put16(de + 18, fdate);                    /* last access date */
        put16(de + 22, ftime);                    /* write time */
        put16(de + 24, fdate);                    /* write date */
        put16(de + 20, (uint16_t)(first >> 16));     /* first cluster high */
        put16(de + 26, (uint16_t)(first & 0xFFFF));  /* first cluster low */
        put32(de + 28, len);                      /* file size */
    }

    /* write both FAT copies (little-endian 32-bit entries) */
    for (int f = 0; f < NUM_FATS; f++) {
        uint8_t *dst = img + (uint64_t)(fat_start + f * fatsz) * SECTOR;
        for (uint32_t i = 0; i < clusters + 2; i++)
            put32(dst + i * 4, fat[i]);
    }

    FILE *out = fopen(argv[1], "wb");
    if (!out) { perror("fopen"); return 1; }
    fwrite(img, SECTOR, TOTAL_SECTORS, out);
    fclose(out);

    printf("mkfatfs: wrote %s (%d sectors, fatsz=%u, %d files)\n",
           argv[1], TOTAL_SECTORS, fatsz, ne);
    return 0;
}
