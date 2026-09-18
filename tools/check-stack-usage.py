#!/usr/bin/env python3
"""NO TASK'S DEEPEST CALL CHAIN MAY OUTGROW ITS KERNEL STACK (M2198).

WHY THIS EXISTS, AND WHY THE OBVIOUS VERSION OF IT IS USELESS.

app_core_dump declares `reg[2 + APP_MAXVMA]` on the stack. APP_MAXVMA was 16
when that was written and is 4096 now, so the frame measured 65,920 bytes --
and my first instinct was to compare that against STACK_SIZE (16,384) and call
it a four-times overflow. It is not. App tasks are created with a 256 KiB
stack, so it fits, and the successful "[core] wrote /tmp/core" lines in every
captured log were telling the truth.

That is the whole lesson: a per-function byte limit has no meaning without the
stack the function runs on, and this kernel uses six different sizes (16 KiB
default, 64 KiB net RX, 256 KiB apps and the browser worker, 512 KiB net
demo). A flat threshold flagged 58 functions, nearly all of them fine, which
is a gate nobody would keep.

So this walks the actual call graph from each task entry point and sums frames
along the deepest chain, against THAT entry point's own stack.

HONEST LIMITS, because an instrument that overstates its coverage is worse
than none:
  - Only DIRECT calls are visible. The kernel dispatches through function
    pointers (the VFS, the block layer), so every number here is a LOWER
    BOUND on the true depth.
  - Recursion is reported separately, not summed: a cycle has no finite
    worst case from this data alone.
  - Frame sizes are gcc's, at this -O2. A different optimisation level moves
    them.
A lower bound that exceeds the stack is still proof of an overflow. A lower
bound that fits is not proof of safety, and this prints the margin so a thin
one is visible rather than implied.
"""
import os, re, subprocess, sys, tempfile, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

CFLAGS = ("-std=gnu11 -ffreestanding -nostdlib -fno-stack-protector -fno-pic "
          "-fno-pie -mcmodel=kernel -mno-red-zone -mgeneral-regs-only -fwrapv "
          "-fno-omit-frame-pointer -Ikernel/include -O2").split()

def read_stack_size():
    m = re.search(r'^#define STACK_SIZE\s+(\d+)', open('kernel/task.c').read(), re.M)
    return int(m.group(1)) if m else None

def entry_points():
    """(entry, stack_bytes, where) for every task this kernel creates."""
    eps, default = [], read_stack_size()
    for f in glob.glob('kernel/*.c'):
        src = open(f, errors='replace').read()
        for m in re.finditer(r'task_create_stack\(\s*([A-Za-z_]\w*)\s*,[^;]*?,\s*([0-9*\s]+)\)', src):
            expr = m.group(2).strip()
            try:    size = eval(expr, {}, {})
            except Exception: continue
            eps.append((m.group(1), int(size), f))
        for m in re.finditer(r'\btask_create\(\s*([A-Za-z_]\w*)\s*,', src):
            if default: eps.append((m.group(1), default, f))
    # THE ROOTS ENTERED FROM ASSEMBLY, which no task_create call names and
    # which carry the deepest chains in the kernel:
    #
    #   linux_syscall_dispatch -- every Linux syscall. linux_entry.asm takes
    #       `mov rsp, [gs:0]`, and linux_abi_set_kernel_rsp is fed by
    #       tss_set_rsp0 on every context switch, so that IS the current
    #       task's kernel stack: 256 KiB for an app.
    #   isr_dispatch -- every interrupt, on WHOEVER'S stack was running. It
    #       must therefore fit the SMALLEST stack in the system, and on top of
    #       whatever that task had already spent. Rooted at the 16 KiB
    #       default, which is still optimistic for that reason.
    #   kmain -- the 256 KiB boot stack in boot/boot.asm (stack_bottom).
    for name, size in (('linux_syscall_dispatch', 262144),
                       # 256 KiB, not the 16 KiB default: isr_dispatch's deepest
                       # chain is the ring-3 PAGE FAULT (and the fault reporter),
                       # which by definition runs on the faulting APP's stack --
                       # the CPU takes rsp0 from the TSS. The case where an
                       # interrupt lands on a 16 KiB kernel task is covered
                       # instead by adding the registered-IRQ-handler depth to
                       # every task's own chain, above.
                       ('isr_dispatch', 262144),
                       ('kmain', 262144)):
        eps.append((name, size, 'entered from assembly'))
    # de-duplicate, keeping the SMALLEST stack any call site gives an entry
    best = {}
    for name, size, where in eps:
        if name not in best or size < best[name][0]: best[name] = (size, where)
    return best

def build(tmp):
    frames, edges = {}, {}
    for f in sorted(glob.glob('kernel/*.c')):
        obj = os.path.join(tmp, os.path.basename(f)[:-2] + '.o')
        if subprocess.run(['gcc', *CFLAGS, '-fstack-usage', '-c', '-o', obj, f],
                          capture_output=True).returncode != 0:
            continue
        su = obj[:-2] + '.su'
        if os.path.exists(su):
            for line in open(su):
                p = line.rstrip('\n').split('\t')
                if len(p) >= 2:
                    name = p[0].split(':')[-1].split('.')[0]
                    frames[name] = max(frames.get(name, 0), int(p[1]))
        # -r IS NOT OPTIONAL. A call to a function in ANOTHER translation unit
        # has no address yet, so it disassembles as `call 0 <caller+0x…>` --
        # naming the CALLER. Parsing that gives every cross-object call a
        # false self-edge, every function looks recursive, and the cycle
        # check then truncates every chain to nothing. The first version of
        # this script did exactly that and reported app_trampoline as needing
        # 16 bytes, which is how it was caught: a task entry point cannot
        # have a 16-byte worst case. The real target is in the relocation on
        # the following line.
        d = subprocess.run(['objdump', '-dr', '--no-show-raw-insn', obj],
                           capture_output=True, text=True).stdout
        cur, pending = None, False
        for line in d.splitlines():
            h = re.match(r'^[0-9a-f]+ <([^>]+)>:', line)
            if h:
                cur = h.group(1).split('.')[0]; edges.setdefault(cur, set())
                pending = False; continue
            rel = re.search(r'R_X86_64_(?:PLT32|PC32|32S|64)\s+([A-Za-z_]\w*)', line)
            if rel and pending and cur:
                edges[cur].add(rel.group(1).split('.')[0]); pending = False; continue
            c = re.search(r'\bcall\w*\s+', line)
            if c and cur:
                named = re.search(r'<([A-Za-z_][^>+]*)>\s*$', line)
                if named:
                    edges[cur].add(named.group(1).split('.')[0]); pending = False
                else:
                    pending = True          # target arrives as a relocation
                continue
            if line.strip() and not line.startswith('\t\t\t'): pending = False
    return frames, edges

def deepest(fn, frames, edges, memo, stack, cycles):
    if fn in stack:
        cycles.add(fn); return 0, [fn + ' (RECURSION)']
    if fn in memo: return memo[fn]
    own = frames.get(fn, 0)
    best, path = 0, []
    stack.add(fn)
    for callee in sorted(edges.get(fn, ())):
        c, p = deepest(callee, frames, edges, memo, stack, cycles)
        if c > best: best, path = c, p
    stack.discard(fn)
    memo[fn] = (own + best, [f'{fn} ({own})'] + path)
    return memo[fn]

def main():
    with tempfile.TemporaryDirectory() as tmp:
        frames, edges = build(tmp)
    if not frames:
        print('FAIL: nothing compiled'); return 1
    print(f'-- {len(frames)} functions, {sum(len(v) for v in edges.values())} direct call edges')
    eps = entry_points()
    print(f'-- {len(eps)} task entry points')
    fails, memo, cycles = [], {}, set()

    # AN INTERRUPT LANDS ON TOP OF WHATEVER WAS RUNNING, so a task's own
    # deepest chain is not the limit -- its chain PLUS the deepest interrupt
    # chain is. Measured separately because isr_dispatch's true worst case is
    # the ring-3 page-fault path (app_fault_handle -> vfs_pread -> ext2_pread,
    # three nested 4 KiB block buffers), and that can only ever run on the
    # faulting APP's 256 KiB stack -- never on a 16 KiB kernel task's. Cutting
    # that one edge gives the depth of an interrupt that CAN arrive while a
    # kernel task runs: the timer, the NIC, the keyboard.
    # Rooted at the functions actually REGISTERED as hardware IRQ handlers,
    # not at isr_dispatch with edges removed. isr_dispatch's own worst case is
    # the ring-3 page-fault and fault-REPORTING paths (app_fault_handle,
    # app_describe_addr -> vfs_pread -> ext2_pread), which run only on the
    # faulting app's 256 KiB stack. Cutting those edges by hand until the
    # number looks reasonable is motivated reasoning; "every function passed
    # to irq_install_handler" is a criterion the source decides, not me.
    irq_roots = set()
    for f in glob.glob('kernel/*.c'):
        for m in re.finditer(r'irq_install_handler\(\s*[^,]+,\s*([A-Za-z_]\w*)\s*\)',
                             open(f, errors='replace').read()):
            irq_roots.add(m.group(1))
    irq_only, irq_path, irq_who = 384, ['isr_dispatch (384)'], 'isr_dispatch alone'
    for root in sorted(irq_roots):
        t, pth = deepest(root, frames, edges, {}, set(), set())
        if t + 384 > irq_only:           # + isr_dispatch's own frame above it
            irq_only, irq_path, irq_who = t + 384, ['isr_dispatch (384)'] + pth, root
    print(f'-- {len(irq_roots)} registered IRQ handlers; deepest is {irq_who} '
          f'at {irq_only} bytes including isr_dispatch')
    for step in irq_path[:9]: print(f'     {step}')

    rows = []
    for name, (size, where) in sorted(eps.items()):
        total, path = deepest(name, frames, edges, memo, set(), cycles)
        # isr_dispatch is the interrupt itself; it does not nest inside itself.
        need = total if name == 'isr_dispatch' else total + irq_only
        rows.append((need, size, name, where, path, total))
    for need, size, name, where, path, own in sorted(rows, reverse=True):
        pct = (100 * need) // size if size else 0
        # 75%, NOT 100%. Failing only on need > size would have passed the
        # very bug this script was written for: wl_server_task measured 15,344
        # of 16,384 bytes, printed "thin", and exited 0. Every number here is
        # a LOWER bound -- calls through function pointers are invisible, and
        # this kernel dispatches the VFS and the block layer that way -- so
        # the margin is not slack, it is the part of the answer that could not
        # be measured. One guard page is all that sits below a stack.
        mark = 'FAIL' if (need > size or pct >= 75) else 'ok  ' 
        extra = '' if name == 'isr_dispatch' else f' (= {own} + {irq_only} for an interrupt)'
        print(f'   {mark} {name:<28} {need:>7} of {size:>7} bytes ({pct:>3}%){extra}  [{where}]')
        if mark == 'thin' or need > size:
            print('        deepest known chain:')
            for step in path[:16]: print(f'          {step}')
        if mark == 'FAIL':
            fails.append((name, need, size, path))
    if cycles:
        print(f'-- {len(cycles)} recursive function(s), NOT summed (no finite bound from this data):')
        for c in sorted(cycles): print(f'     {c}')
    if fails:
        print()
        for name, total, size, path in fails:
            print(f'FAIL: {name} needs at least {total} bytes of stack and has {size} '
                  f'({(100 * total) // size}%, and the limit is 75% because this is a lower bound).')
            print('      deepest known chain (direct calls only, so a lower bound):')
            for step in path[:14]: print(f'        {step}')
        return 1
    print('ok: every task entry point fits its stack on every chain visible here')
    return 0

sys.exit(main())
