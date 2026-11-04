#!/usr/bin/python3
import socket,json,subprocess
PORT=5000
AF_VSOCK=getattr(socket,"AF_VSOCK",40)
CID_ANY=getattr(socket,"VMADDR_CID_ANY",0xFFFFFFFF)
s=socket.socket(AF_VSOCK,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((CID_ANY,PORT))
s.listen(8)
while True:
    c,_=s.accept()
    try:
        f=c.makefile("rwb",buffering=0)
        line=f.readline()
        req=json.loads(line.decode() or "{}")
        cmd=req.get("cmd","")
        to=float(req.get("timeout",20))
        p=subprocess.run(cmd,shell=True,capture_output=True,timeout=to)
        out=(p.stdout+p.stderr).decode(errors="replace")[:65536]
        f.write((json.dumps({"rc":p.returncode,"out":out})+"\n").encode())
    except Exception as e:
        try:
            f.write((json.dumps({"rc":-1,"out":"agent: "+str(e)[:200]})+"\n").encode())
        except Exception: pass
    finally:
        c.close()
