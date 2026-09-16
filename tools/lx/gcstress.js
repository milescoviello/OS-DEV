/* A managed-runtime memory-integrity test.
 *
 * JavaScriptCore's parallel marker crashes on garbage pointers ~30s into a
 * Claude Code run. That is a 230 MB binary driven through a TUI; this is the
 * smallest thing that exercises the same kernel surface -- many threads, a lot
 * of mmap, madvise decommit, and a collector that reads every word it ever
 * allocated -- and it CHECKS rather than hopes: a live object graph is walked
 * and verified after every round, so corruption is reported with the round and
 * the index rather than showing up as a fault somewhere else.
 */
const LIVE = 200000;          // long-lived objects, walked and verified
const GARBAGE = 400000;       // short-lived allocations per round, to force GCs
const ROUNDS = 40;

let live = new Array(LIVE);
for (let i = 0; i < LIVE; i++) live[i] = { i: i, tag: "t" + (i % 977), next: null, pad: i * 2654435761 % 4294967296 };
for (let i = 0; i < LIVE; i++) live[i].next = live[(i * 7 + 13) % LIVE];

let bad = 0, checked = 0;
const t0 = Date.now();
for (let r = 0; r < ROUNDS; r++) {
    let sink = null;
    for (let g = 0; g < GARBAGE; g++) {
        sink = { g: g, s: "g" + g, arr: (g % 64 === 0) ? new Array(32).fill(g) : null };
    }
    if (sink === null) console.log("GCSTRESS: unreachable");
    for (let i = 0; i < LIVE; i++) {
        const o = live[i];
        checked++;
        if (o.i !== i) { if (bad++ < 5) console.log("GCSTRESS: BAD round " + r + " index " + i + " has i=" + o.i); continue; }
        if (o.tag !== "t" + (i % 977)) { if (bad++ < 5) console.log("GCSTRESS: BAD round " + r + " index " + i + " tag=" + o.tag); continue; }
        if (o.pad !== i * 2654435761 % 4294967296) { if (bad++ < 5) console.log("GCSTRESS: BAD round " + r + " index " + i + " pad=" + o.pad); continue; }
        if (o.next.i !== (i * 7 + 13) % LIVE) { if (bad++ < 5) console.log("GCSTRESS: BAD round " + r + " index " + i + " next=" + o.next.i); continue; }
    }
    if (r % 5 === 0) console.log("GCSTRESS: round " + r + " ok, " + checked + " field checks, " + Math.round((Date.now() - t0) / 1000) + "s");
}
console.log("GCSTRESS: " + (bad ? "FAILED with " + bad + " corrupted field(s)" : "OK -- " + checked + " field checks across " + ROUNDS + " rounds"));
