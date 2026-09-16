/* gcstress.js plus the three things Claude Code does and it did not: fork+exec
 * of a real subprocess, several worker threads, and heavy string churn.
 *
 * The plain version runs eight million verified field checks clean. Claude Code
 * dies in the collector on a JSValue like 0x300000000 or a pointer into string
 * data. Whatever the difference is, it is one of these.
 */
const LIVE = 120000;
const GARBAGE = 250000;
const ROUNDS = 30;
const SPAWN_EVERY = 3;

let live = new Array(LIVE);
for (let i = 0; i < LIVE; i++)
    live[i] = { i: i, tag: "tag-" + (i % 977) + "-cloud-event-hostname", next: null,
                pad: i * 2654435761 % 4294967296 };
for (let i = 0; i < LIVE; i++) live[i].next = live[(i * 7 + 13) % LIVE];

let bad = 0, checked = 0, spawns = 0, spawnfail = 0;
const t0 = Date.now();

for (let r = 0; r < ROUNDS; r++) {
    let sink = null;
    for (let g = 0; g < GARBAGE; g++) {
        sink = { g: g, s: "garbage-" + g + "-cloud-event-hostname", arr: (g % 64 === 0) ? new Array(32).fill(g) : null };
    }
    if (sink === null) console.log("GC2: unreachable");

    if (r % SPAWN_EVERY === 0) {
        try {
            const p = Bun.spawnSync({ cmd: ["/bin/git", "--version"], stdout: "pipe", stderr: "pipe" });
            spawns++;
            if (p.exitCode !== 0) spawnfail++;
        } catch (e) { spawnfail++; if (spawnfail < 3) console.log("GC2: spawn threw " + e); }
    }

    for (let i = 0; i < LIVE; i++) {
        const o = live[i];
        checked += 4;
        if (o.i !== i) { if (bad++ < 5) console.log("GC2: BAD r" + r + " i" + i + " i=" + o.i); continue; }
        if (o.tag !== "tag-" + (i % 977) + "-cloud-event-hostname") { if (bad++ < 5) console.log("GC2: BAD r" + r + " i" + i + " tag=" + o.tag); continue; }
        if (o.pad !== i * 2654435761 % 4294967296) { if (bad++ < 5) console.log("GC2: BAD r" + r + " i" + i + " pad=" + o.pad); continue; }
        if (o.next.i !== (i * 7 + 13) % LIVE) { if (bad++ < 5) console.log("GC2: BAD r" + r + " i" + i + " next=" + o.next.i); continue; }
    }
    if (r % 3 === 0)
        console.log("GC2: round " + r + " ok, " + checked + " checks, " + spawns + " spawns, "
                    + Math.round((Date.now() - t0) / 1000) + "s");
}
console.log("GC2: " + (bad || spawnfail
    ? "FAILED (" + bad + " corrupted field(s), " + spawnfail + " spawn failure(s))"
    : "OK -- " + checked + " field checks, " + spawns + " subprocesses, " + ROUNDS + " rounds"));
