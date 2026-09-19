import struct
d=open('/home/user/slopped/slopped-handout/peerctl','rb').read()
SEGS=[(0x401000,0x1000,0x484c31),(0x886000,0x486000,0x1e09d9),(0xa669e0,0x6669e0,0x3464),(0xa69e60,0x669e60,0x12e0),(0xd40960,0x940960,0x49a01),(0xd8a380,0x98a380,0x161f2)]
def v2f(v):
    for va,fo,sz in SEGS:
        if va<=v<va+sz: return fo+(v-va)
def nameinfo(ptr):
    o=v2f(ptr)
    if o is None: return None
    flags=d[o]; p=o+1; l=0; s=0
    while True:
        b=d[p]; p+=1; l|=(b&0x7f)<<s; s+=7
        if not b&0x80: break
    if l>200 or p+l>len(d): return None
    nm=d[p:p+l].decode('utf8','replace'); p+=l
    tag=''
    if flags&1:
        tl=0; s=0
        while True:
            b=d[p]; p+=1; tl|=(b&0x7f)<<s; s+=7
            if not b&0x80: break
        if tl<200: tag=d[p:p+tl].decode('utf8','replace')
    if not all(0x20<=ord(c)<0x7f for c in nm): return None
    return nm,tag,flags
def kind(typ):
    o=v2f(typ)
    if o is None: return '?'
    return d[o+23]&0x1f
KINDS={1:'bool',2:'int',3:'int8',4:'int16',5:'int32',6:'int64',7:'uint',8:'uint8',9:'uint16',10:'uint32',11:'uint64',12:'uintptr',13:'float32',14:'float64',15:'complex64',16:'complex128',17:'array',18:'chan',19:'func',20:'interface',21:'map',22:'ptr',23:'slice',24:'string',25:'struct',26:'unsafePointer'}
def dump_fields(arr_vaddr, n=20):
    o=v2f(arr_vaddr)
    for k in range(n):
        e=o+k*24
        nm=struct.unpack_from('<Q',d,e)[0]; tp=struct.unpack_from('<Q',d,e+8)[0]; oe=struct.unpack_from('<I',d,e+16)[0]
        info=nameinfo(nm)
        if not info: break
        print("  off=%-4d %-22s %-28s %s" % (oe, info[0], KINDS.get(kind(tp),kind(tp)), info[1]))
