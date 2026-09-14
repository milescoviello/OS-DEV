#!/usr/bin/env python3
"""ccdrive.py -- drive a LONG-LIVED OS-DEV VM over its QEMU monitor.

osdrive.py boots a VM, runs a script and kills it. A TUI needs the opposite:
one VM that stays up while you poke at it across many separate commands, look
at a screenshot, decide, and poke again. That is the loop Claude Code's
onboarding needed, and it is why this exists alongside osdrive.py rather than
inside it.

    tools/ccdrive.py --dir DIR boot [--append "lxdesktop"] [--pcap]
    tools/ccdrive.py --dir DIR click:800,300 key:f4 type:claude key:ret shot:a1
    tools/ccdrive.py --dir DIR kill

Commands: key:NAME[,NAME..]  type:TEXT  click:X,Y  dblclick:X,Y  sleep:SECS
          shot:NAME (writes DIR/NAME.png)  paste:TEXT (types it, slowly)
"""
import json, os, socket, subprocess, sys, time

_UN = {" ":"spc",".":"dot","/":"slash","-":"minus","=":"equal",";":"semicolon",
       "'":"apostrophe",",":"comma","`":"grave_accent","[":"bracket_left",
       "]":"bracket_right","\\":"backslash","\t":"tab"}
_SH = {":":"semicolon","?":"slash","_":"minus","+":"equal","\"":"apostrophe",
       "(":"9",")":"0","!":"1","@":"2","#":"3","$":"4","%":"5","^":"6","&":"7",
       "*":"8","<":"comma",">":"dot","~":"grave_accent","{":"bracket_left",
       "}":"bracket_right","|":"backslash"}
def keyname(c):
    if c.islower() or c.isdigit(): return c
    if c.isupper(): return "shift-" + c.lower()
    if c in _UN: return _UN[c]
    if c in _SH: return "shift-" + _SH[c]
    return None

class Mon:
    def __init__(s, p):
        s.s = socket.socket(socket.AF_UNIX); s.s.connect(p); s.s.settimeout(5)
        try: s.s.recv(65536)
        except OSError: pass
    def cmd(s, line):
        s.s.sendall((line + "\n").encode()); time.sleep(0.04)
        try: return s.s.recv(262144).decode(errors="replace")
        except OSError: return ""

class Qmp:
    def __init__(s, p):
        s.s = socket.socket(socket.AF_UNIX); s.s.connect(p)
        s.f = s.s.makefile("rw"); s.f.readline()
        s.send({"execute": "qmp_capabilities"})
    def send(s, o):
        s.f.write(json.dumps(o) + "\n"); s.f.flush()
        while True:
            l = s.f.readline()
            if not l: return None
            d = json.loads(l)
            if "return" in d or "error" in d: return d
    def click(s, x, y, dbl=False):
        s.send({"execute": "input-send-event", "arguments": {"events": [
            {"type":"abs","data":{"axis":"x","value":int(x*32767/1279)}},
            {"type":"abs","data":{"axis":"y","value":int(y*32767/959)}}]}})
        time.sleep(0.15)
        for _ in range(2 if dbl else 1):
            for down in (True, False):
                s.send({"execute":"input-send-event","arguments":{"events":[
                    {"type":"btn","data":{"down":down,"button":"left"}}]}})
                time.sleep(0.05)
            time.sleep(0.08)

def boot(d, append, pcap, mem="3G", smp="4"):
    os.makedirs(d, exist_ok=True)
    for n in ("mon.sock", "qmp.sock", "serial.log", "net.pcap"):
        try: os.unlink(os.path.join(d, n))
        except OSError: pass
    q = ["qemu-system-x86_64", "-cpu", "max", "-snapshot", "-no-reboot", "-no-shutdown",
         "-m", mem, "-smp", smp, "-kernel", "build/kernel32.elf", "-append", append,
         "-drive", "file=build/fat.img,format=raw,if=ide",
         "-drive", "file=build/ext2.img,format=raw,if=ide",
         "-netdev", "user,id=net0", "-device", "e1000,netdev=net0",
         "-device", "piix3-usb-uhci,id=uhci", "-device", "usb-tablet,bus=uhci.0",
         "-display", "none", "-serial", "file:" + os.path.join(d, "serial.log"),
         "-monitor", "unix:%s,server,nowait" % os.path.join(d, "mon.sock"),
         "-qmp", "unix:%s,server,nowait" % os.path.join(d, "qmp.sock")]
    if pcap:
        q += ["-object", "filter-dump,id=f1,netdev=net0,file=" + os.path.join(d, "net.pcap")]
    p = subprocess.Popen(q, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    open(os.path.join(d, "qemu.pid"), "w").write(str(p.pid))
    print("booted pid %d into %s" % (p.pid, d))

def main():
    a = sys.argv[1:]
    d = "."
    if a and a[0] == "--dir": d = a[1]; a = a[2:]
    if a and a[0] == "boot":
        append, pcap = "lxdesktop", False
        rest = a[1:]
        i = 0
        while i < len(rest):
            if rest[i] == "--append": append = rest[i+1]; i += 2
            elif rest[i] == "--pcap": pcap = True; i += 1
            else: i += 1
        boot(d, append, pcap); return 0
    if a and a[0] == "kill":
        try:
            pid = int(open(os.path.join(d, "qemu.pid")).read())
            os.kill(pid, 9); print("killed %d" % pid)
        except Exception as e: print("kill: %s" % e)
        return 0
    mon = Mon(os.path.join(d, "mon.sock")); qmp = Qmp(os.path.join(d, "qmp.sock"))
    for c in a:
        op, _, arg = c.partition(":")
        if op == "sleep": time.sleep(float(arg))
        elif op == "key":
            for k in arg.split(","): mon.cmd("sendkey " + k); time.sleep(0.06)
        elif op in ("type", "paste"):
            delay = 0.05 if op == "type" else 0.12
            for ch in arg:
                k = keyname(ch)
                if k: mon.cmd("sendkey " + k); time.sleep(delay)
        elif op == "click":
            x, y = arg.split(","); qmp.click(int(x), int(y))
        elif op == "dblclick":
            x, y = arg.split(","); qmp.click(int(x), int(y), dbl=True)
        elif op == "shot":
            ppm = os.path.join(d, arg + ".ppm")
            mon.cmd("screendump " + ppm); time.sleep(1.0)
            try:
                from PIL import Image
                Image.open(ppm).save(os.path.join(d, arg + ".png")); print("shot " + arg + ".png")
            except Exception as e: print("ppm only: %s" % e)
        else: print("?? " + c)
    return 0
sys.exit(main())
