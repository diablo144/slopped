import subprocess, re, struct, sys, bisect
d=open('/home/user/slopped/slopped-handout/peerctl','rb').read()
e_phoff=struct.unpack_from('<Q',d,0x20)[0]
e_phentsize=struct.unpack_from('<H',d,0x36)[0]
e_phnum=struct.unpack_from('<H',d,0x38)[0]
segs=[]
for k in range(e_phnum):
    off=e_phoff+k*e_phentsize
    if struct.unpack_from('<I',d,off)[0]!=1: continue
    segs.append((struct.unpack_from('<Q',d,off+16)[0], struct.unpack_from('<Q',d,off+8)[0], struct.unpack_from('<Q',d,off+32)[0]))
FUNCS=[]
for line in open('/home/user/slopped/tools/rev/funcs.txt'):
    a,n=line.split(' ',1); FUNCS.append((int(a,16), n.strip()))
FUNCS.sort(); FADDR=[a for a,_ in FUNCS]
def v2o(v):
    for va,fo,sz in segs:
        if va<=v<va+sz: return fo+(v-va)
def fname(v):
    i=bisect.bisect_right(FADDR,v)-1
    if i<0: return None
    a,n=FUNCS[i]
    if v-a < 0x4000: return n + ('' if v==a else '+%#x'%(v-a))
    return None
def s(v):
    o=v2o(v)
    if o is None: return None
    b=d[o:o+200]
    m=re.match(rb'[\x20-\x7e]{3,}',b)
    if m: return '"%s"'%m.group(0).decode()
    if b[:8]==b'\x00'*8: return None
    return b[:24].hex()
start=int(sys.argv[1],16); end=int(sys.argv[2],16)
r=subprocess.run(['objdump','-d','--start-address=0x%x'%start,'--stop-address=0x%x'%end,'/home/user/slopped/slopped-handout/peerctl'],capture_output=True,text=True)
out=[]
for line in r.stdout.splitlines():
    m=re.match(r'\s+([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t(.*)$',line)
    if not m: continue
    addr=int(m.group(1),16); ins=m.group(3)
    body=ins.split('#')[0].strip()
    ann=''
    cm=re.search(r'#\s*(0x[0-9a-f]+)',ins)
    if cm:
        v=int(cm.group(1),16); val=s(v)
        if val: ann=val
    tm=re.search(r'(call|jmp|jne|je|jb|ja|jbe|jae|jl|jg|jle|jge|jcc|jne)\s+0x([0-9a-f]+)',body)
    if tm:
        f=fname(int(tm.group(2),16))
        if f: ann=(ann+'  ' if ann else '')+'-> '+f
    out.append('%s: %-45s %s'%(m.group(1),body,ann))
print('\n'.join(out))
