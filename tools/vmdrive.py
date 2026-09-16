#!/usr/bin/env python3
"""vmdrive.py -- drive an ALREADY-RUNNING OS-DEV VM through its HMP monitor.

tools/osdrive.py boots a VM of its own, headless, with one FAT disk. That is
the wrong shape for the Linux-ABI work: those runs need the ext2 volume, 8 GiB
of RAM, several cores, a long-lived VM, and often a real window you can type
into yourself. So this attaches to a VM somebody else started.

    tools/vmrun.sh live 4 "lxdesktop lxout"          # start one (GTK window)
    tools/vmdrive.py <mon.sock> "click 700 300" "type claude" "key ret"
    tools/vmdrive.py <mon.sock> "shot /tmp/a.ppm"

Commands: key NAME | type TEXT | sleep SECS | shot PATH | click X Y | raw CMD.
Several may be given per argument, separated by ';'.

Lives in tools/ rather than a scratch directory on purpose: /tmp here is a
tmpfs on a dual-booting laptop, so anything left in it is gone after a reboot,
and this got rewritten from memory twice before that sank in.
"""
import socket, sys, time
KEYMAP = {' ':'spc','\n':'ret','-':'minus','=':'equal','[':'bracket_left',']':'bracket_right',
          ';':'semicolon',"'":'apostrophe','`':'grave_accent','\\':'backslash',',':'comma',
          '.':'dot','/':'slash','!':'shift-1','@':'shift-2','#':'shift-3','$':'shift-4',
          '%':'shift-5','^':'shift-6','&':'shift-7','*':'shift-8','(':'shift-9',')':'shift-0',
          '_':'shift-minus','+':'shift-equal','{':'shift-bracket_left','}':'shift-bracket_right',
          ':':'shift-semicolon','"':'shift-apostrophe','~':'shift-grave_accent','|':'shift-backslash',
          '<':'shift-comma','>':'shift-dot','?':'shift-slash'}
def keyname(ch):
    if ch in KEYMAP: return KEYMAP[ch]
    if ch.isdigit(): return ch
    if ch.isalpha(): return ('shift-'+ch.lower()) if ch.isupper() else ch
    raise ValueError('no key for %r'%ch)
SCREEN_W, SCREEN_H = 1280, 960     # OS-DEV's framebuffer

class Mon:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX); self.s.connect(path)
        self.s.settimeout(0.4); self.drain()
    def drain(self):
        out=b''
        try:
            while True:
                d=self.s.recv(65536)
                if not d: break
                out+=d
        except Exception: pass
        return out.decode('utf8','replace')
    def cmd(self, c):
        self.s.sendall((c+'\n').encode()); time.sleep(0.05); return self.drain()
if __name__=='__main__':
    path=sys.argv[1]; m=Mon(path)
    for line in sys.argv[2:]:
        for part in line.split(';'):
            part=part.strip()
            if not part: continue
            op,_,arg=part.partition(' ')
            if op=='key':      m.cmd('sendkey '+arg)
            elif op=='type':
                for ch in arg:
                    m.cmd('sendkey '+keyname(ch)); time.sleep(0.02)
            elif op=='sleep':  time.sleep(float(arg))
            elif op=='shot':   m.cmd('screendump '+arg)
            elif op=='click':
                # PIXELS, converted. With a usb-tablet (an ABSOLUTE pointing
                # device) HMP mouse_move takes 0..32767 in each axis, not
                # pixels -- so `click 700 300` moved the pointer to within a
                # few pixels of the top-left corner and clicked the desktop
                # background, which UNFOCUSED the window I was about to type
                # into. It looked exactly like sendkey not working.
                x,y=(int(v) for v in arg.split())
                ax = min(32767, max(0, x * 32767 // SCREEN_W))
                ay = min(32767, max(0, y * 32767 // SCREEN_H))
                m.cmd('mouse_move %d %d'%(ax,ay)); m.cmd('mouse_button 1'); time.sleep(0.05); m.cmd('mouse_button 0')
            elif op=='raw':    print(m.cmd(arg))
            else: print('?',part)
    print('done')
