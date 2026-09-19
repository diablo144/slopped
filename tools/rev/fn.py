import sys, subprocess, bisect
funcs=[]
for line in open('/home/user/slopped/tools/rev/funcs.txt'):
    a,n=line.split(' ',1); funcs.append((int(a,16), n.strip()))
funcs.sort(); addrs=[a for a,_ in funcs]
want=sys.argv[1]
for i,(a,n) in enumerate(funcs):
    if want in n:
        j=bisect.bisect_right(addrs,a)
        end=addrs[j] if j<len(addrs) else a+0x1000
        print("### %s  %#x-%#x" % (n,a,end), flush=True)
        print(subprocess.run(['python3','/tmp/dis.py',hex(a),hex(end)],capture_output=True,text=True).stdout, flush=True)
