#!/usr/bin/env python3
import os, sys, json, time, shutil, socket, subprocess, threading, uuid, hashlib, re, base64, hmac, signal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

FC="/opt/fc/release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64"
KERNEL="/opt/fc/vmlinux.bin"
BASE=os.environ.get("SHARD_BASE","/var/lib/shard-mvp")
TEMPLATE=os.environ.get("SHARD_TEMPLATE",os.path.join(BASE,"rootfs.ext4"))
WS=os.environ.get("SHARD_WS","/dev/shm/shard-mvp/ws")
RECEIPTS=os.path.join(BASE,"receipts.jsonl")
REG=os.path.join(BASE,"workspaces.json")
KEYF=os.path.join(BASE,"ed25519.key")
PORT=int(os.environ.get("SHARD_PORT","7150"))
VERSION="0.2.0"
START_TS=time.time()
TOKF=os.environ.get("SHARD_TOKEN_FILE",os.path.join(BASE,"token"))
ANSI=re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Cold boot: keep serial for diagnostics, but stop kernel/systemd chatter (less virtio-serial I/O).
BOOT_ARGS=os.environ.get("SHARD_BOOT_ARGS","console=ttyS0 quiet loglevel=3 systemd.show_status=0 rootfstype=ext4 reboot=k panic=1 pci=off root=/dev/vda rw tsc=reliable no_timer_check")
BOOT_TIMEOUT=float(os.environ.get("SHARD_BOOT_TIMEOUT","15"))
TIMING=os.environ.get("SHARD_TIMING","1")=="1"
BACKUP_LEVEL=os.environ.get("SHARD_BACKUP_LEVEL","1")
BACKUP_THREADS=os.environ.get("SHARD_BACKUP_THREADS","0")
VERIFY_SHA=os.environ.get("SHARD_VERIFY_SHA","0")=="1"
KEY_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
VMS_LOCK=threading.RLock()
MAX_WS=int(os.environ.get("SHARD_MAX_WORKSPACES","32"))
MIN_FREE_MB=int(os.environ.get("SHARD_MIN_FREE_MB","512"))
WS_MIN_FREE_MB=int(os.environ.get("SHARD_WS_MIN_FREE_MB","1200"))
BACKUP_ON_SUSPEND=os.environ.get("SHARD_BACKUP_ON_SUSPEND","0")=="1"
POOL_TARGET=int(os.environ.get("SHARD_POOL","1"))
RECEIPTS_MAX=int(float(os.environ.get("SHARD_RECEIPTS_MAX_MB","32"))*1024*1024)

# --- aggregate metrics (no keys, safe for /metrics) ---
_MET_LOCK=threading.Lock()
METRICS={"opens":0,"warm":0,"cold":0,"execs":0,"suspend":0,"resume":0,"errors":0,
         "open_ms_sum":0.0,"exec_ms_sum":0.0,"open_ms_max":0.0,"exec_ms_max":0.0}
def met(name,val=1):
    try:
        with _MET_LOCK:
            if name.endswith("_ms"):
                METRICS["open_ms_sum" if name=="open_ms" else "exec_ms_sum"]+=val
                key=("open_ms_max" if name=="open_ms" else "exec_ms_max")
                if val>METRICS[key]: METRICS[key]=val
            else:
                METRICS[name]=METRICS.get(name,0)+val
    except Exception: pass

def token():
    try: return open(TOKF).read().strip()
    except Exception: return os.environ.get("SHARD_TOKEN","")

def sha(b): return hashlib.sha256(b).hexdigest()

def load_key():
    os.makedirs(BASE,exist_ok=True)
    if os.path.exists(KEYF):
        return Ed25519PrivateKey.from_private_bytes(open(KEYF,"rb").read())
    k=Ed25519PrivateKey.generate()
    open(KEYF,"wb").write(k.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()))
    os.chmod(KEYF,0o600); return k

def api(sock, method, path, body=None, timeout=10):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(timeout); s.connect(sock)
    data=b"" if body is None else json.dumps(body).encode()
    req=(f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode()+data
    s.sendall(req); out=b""
    while b"\r\n\r\n" not in out:
        b=s.recv(65536)
        if not b: break
        out+=b
    head,bod=out.split(b"\r\n\r\n",1)
    m=re.search(rb"Content-Length:\s*(\d+)",head,re.I)
    n=int(m.group(1)) if m else 0
    while len(bod)<n:
        b=s.recv(65536)
        if not b: break
        bod+=b
    s.close()
    try: return json.loads(bod.decode() or "{}")
    except Exception: return {}

def wait_file(p, timeout=10):
    t=time.time()
    while time.time()-t<timeout:
        if os.path.exists(p): return True
        time.sleep(.01)
    return False

def wait_log(p, needle, timeout=25):
    t=time.time()
    while time.time()-t<timeout:
        try:
            if needle in open(p,"rb").read(): return True
        except FileNotFoundError: pass
        time.sleep(.02)
    return False

def copy_disk(src,dst):
    """Copy a rootfs image. cp(1) uses copy_file_range/sparse handling; fallback to shutil."""
    try:
        if os.path.exists(dst): os.remove(dst)
        r=subprocess.run(["cp","--sparse=always","--reflink=auto","--",src,dst],
                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if r.returncode==0 and os.path.exists(dst) and os.path.getsize(dst)==os.path.getsize(src): return
    except Exception:
        pass
    try: os.remove(dst)
    except OSError: pass
    shutil.copyfile(src,dst)

def file_sha(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(4<<20),b""): h.update(c)
    return h.hexdigest()
def free_mb(path):
    try: return shutil.disk_usage(path).free/(1024*1024)
    except Exception: return 0

class VM:
    def __init__(self,key,dir=None):
        self.key=key; self.dir=dir or os.path.join(WS,key); self.disk=os.path.join(self.dir,"rootfs.ext4")
        self.sock=os.path.join(self.dir,"fc.sock"); self.log=os.path.join(self.dir,"console.log")
        self.vsock=os.path.join(self.dir,"vsock-%s.sock"%uuid.uuid4().hex[:8])
        self.snap=os.path.join(self.dir,"snap.bin"); self.mem=os.path.join(self.dir,"mem.bin")
        self.proc=None; self.state="new"; self.created=time.time(); self.lock=threading.RLock()
        os.makedirs(self.dir,exist_ok=True)
        if COLD:
            for _p in (self.snap,self.mem):
                try: os.remove(_p)
                except OSError: pass
    def info(self):
        return {"key":self.key,"state":self.state,"dir":self.dir,"created":self.created,
                "snapshot":os.path.exists(self.snap),"pid":self.proc.pid if self.proc and self.proc.poll() is None else None}
    def _new_vsock(self):
        old=self.vsock
        try: os.remove(old)
        except OSError: pass
        self.vsock=os.path.join(self.dir,"vsock-%s.sock"%uuid.uuid4().hex[:8])
        return self.vsock
    def _start_cfg(self):
        self._new_vsock()
        for p in (self.sock,self.log):
            try: os.remove(p)
            except FileNotFoundError: pass
        cfg=os.path.join(self.dir,"cfg.json")
        json.dump({"boot-source":{"kernel_image_path":KERNEL,"boot_args":BOOT_ARGS},
                   "drives":[{"drive_id":"rootfs","path_on_host":self.disk,"is_root_device":True,"is_read_only":False,"cache_type":"Writeback"}],
                   "machine-config":{"vcpu_count":2,"mem_size_mib":512,"smt":False},
                   "vsock":{"guest_cid":3+(int(hashlib.sha256(self.key.encode()).hexdigest()[:6],16)%1000000),"uds_path":self.vsock}},open(cfg,"w"))
        t0=time.time()
        out=open(self.log,"wb")
        self.proc=subprocess.Popen([FC,"--api-sock",self.sock,"--config-file",cfg],stdin=subprocess.PIPE,stdout=out,stderr=subprocess.STDOUT,bufsize=0)
        if not wait_file(self.sock,10): raise RuntimeError("api sock nije otvoren")
        self.boot_api_ms=round((time.time()-t0)*1000,1)
        self.boot_vsock_ms=self.vsock_wait()
        self.boot_ms=round((time.time()-t0)*1000,1)
        self.state="running"
        if TIMING:
            print("shard: boot key=%s api=%sms vsock=%sms total=%sms"%(self.key,self.boot_api_ms,self.boot_vsock_ms,self.boot_ms),flush=True)
    def vsock_wait(self,timeout=None):
        # Poll the guest agent directly (it starts in basic.target, before getty/login).
        timeout=BOOT_TIMEOUT if timeout is None else timeout
        t=time.time()
        while time.time()-t<timeout:
            if self.proc is not None and self.proc.poll() is not None:
                raise RuntimeError("VM exited rc=%s" % self.proc.returncode)
            s=None
            try:
                s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(.25)
                s.connect(self.vsock); s.sendall(b"CONNECT 5000\n")
                if s.recv(64).startswith(b"OK"): return round((time.time()-t)*1000,1)
            except Exception:
                pass
            finally:
                try:
                    if s: s.close()
                except Exception: pass
            time.sleep(.02)
        raise RuntimeError("vsock agent nije spreman u %.1fs" % timeout)
    def _start_empty(self):
        self._new_vsock()
        for p in (self.sock,self.log):
            try: os.remove(p)
            except FileNotFoundError: pass
        out=open(self.log,"wb")
        self.proc=subprocess.Popen([FC,"--api-sock",self.sock],stdin=subprocess.PIPE,stdout=out,stderr=subprocess.STDOUT,bufsize=0)
        if not wait_file(self.sock,10): raise RuntimeError("api sock nije otvoren")
    def open(self):
        with self.lock:
            if self.state=="running" and self.proc and self.proc.poll() is None: return self.info()
            if self.state=="suspended": return self.resume()
            if not os.path.exists(self.disk):
                try: restore_vm(self)
                except Exception: pass
            if not os.path.exists(self.disk):
                if free_mb(WS) < WS_MIN_FREE_MB: raise RuntimeError("low /dev/shm space")
                copy_disk(TEMPLATE,self.disk)
            self._start_cfg(); return self.info()
    def _read_exact(self,s,n):
        b=b""
        while len(b)<n:
            x=s.recv(n-len(b))
            if not x: break
            b+=x
        return b
    def vsock_exec(self,cmd,timeout=20):
        t0=time.time()
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(min(timeout+0.4,20.4)); s.connect(self.vsock)
        s.sendall(b"CONNECT 5000\n")
        f=s.makefile("rb")
        hello=f.readline()
        if not hello.startswith(b"OK"): raise RuntimeError("vsock handshake: %r" % hello[:80])
        s.sendall(("T %.3f\n%s\n"%(min(max(float(timeout),0.1),20),cmd.replace("\n",";"))).encode())
        hdr=f.readline()
        m=__import__("re").match(rb"RC (-?\d+) (\d+)\n",hdr)
        if not m: raise RuntimeError("vsock header: %r" % hdr[:120])
        rc=int(m.group(1)); n=int(m.group(2)); out=f.read(n)
        s.close(); return rc,out.decode(errors="replace"),round((time.time()-t0)*1000,1)
    def exec(self,cmd,timeout=20):
        with self.lock:
            if self.state!="running" or not self.proc or self.proc.poll() is not None: self.resume()
            try:
                rc,out,ms=self.vsock_exec(cmd,timeout)
                return rc,out,ms if ms is not None else 0
            except Exception:
                pass
            tag=uuid.uuid4().hex[:8]; b=f"__B{tag}__"; e=f"__E{tag}:"
            script=f"printf '\\n{b}\\n'; ( {cmd} ) 2>&1; printf '\\n{e}%s__\\n' \"$?\"\n"
            try: pos=os.path.getsize(self.log)
            except OSError: pos=0
            self.proc.stdin.write(script.encode()); self.proc.stdin.flush()
            t0=time.time(); data=b""
            while time.time()-t0<timeout:
                try: data=open(self.log,"rb").read()[pos:]
                except OSError: data=b""
                m=re.search((re.escape(e)+r"(\d+)__").encode(),data)
                if m and b.encode() in data:
                    body=data.split(b.encode(),1)[1].split(m.group(0),1)[0]
                    return int(m.group(1)),ANSI.sub("",body.decode(errors="replace")).strip(),round((time.time()-t0)*1000,1)
                time.sleep(.02)
            return -1,"",round((time.time()-t0)*1000,1)
    def suspend(self):
        with self.lock:
            if self.state!="running" or not self.proc or self.proc.poll() is not None: return self.info()
            t0=time.time()
            if COLD:
                try: self.proc.kill(); self.proc.wait()
                except Exception: pass
                self.proc=None; self.state="suspended"
                ok=backup_vm(self) if BACKUP_ON_SUSPEND else True
                return {"ok":True,"key":self.key,"state":self.state,"cold":True,"snapshot_ms":round((time.time()-t0)*1000,1),"backup":os.path.join(BACKUP,self.key),"backup_ok":bool(ok)}
            api(self.sock,"PATCH","/vm",{"state":"Paused"})
            api(self.sock,"PUT","/snapshot/create",{"snapshot_type":"Full","snapshot_path":self.snap,"mem_file_path":self.mem})
            self.proc.kill(); self.proc.wait(); self.proc=None; self.state="suspended"
            ok=backup_vm(self) if BACKUP_ON_SUSPEND else True
            return {"ok":True,"key":self.key,"state":self.state,"snapshot_ms":round((time.time()-t0)*1000,1),"snapshot":self.snap,"mem":self.mem,"backup":os.path.join(BACKUP,self.key),"backup_ok":bool(ok)}
    def resume(self):
        with self.lock:
            if self.state=="running" and self.proc and self.proc.poll() is None: return self.info()
            if COLD:
                if not os.path.exists(self.disk): self.state="new"; return self.open()
                t0=time.time(); self._start_cfg()
                return {"ok":True,"key":self.key,"state":self.state,"cold":True,"resume_ms":round((time.time()-t0)*1000,1)}
            if not (os.path.exists(self.snap) and os.path.exists(self.mem)):
                self.state="new"; return self.open()
            t0=time.time()
            try:
                self._start_empty()
                api(self.sock,"PUT","/snapshot/load",{"snapshot_path":self.snap,"mem_backend":{"backend_path":self.mem,"backend_type":"File"},"resume_vm":True,"vsock_override":{"uds_path":self.vsock}})
                self.state="running"; self.vsock_wait(timeout=5)
                return {"ok":True,"key":self.key,"state":self.state,"resume_ms":round((time.time()-t0)*1000,1)}
            except Exception as e:
                try:
                    if self.proc and self.proc.poll() is None: self.proc.kill(); self.proc.wait()
                except Exception: pass
                self.state="new"; self._start_cfg()
                return {"ok":True,"key":self.key,"state":self.state,"cold":True,"fallback":"cold","err":type(e).__name__,"resume_ms":round((time.time()-t0)*1000,1)}
    def fork(self,newkey):
        with self.lock:
            if COLD:
                dst=VM(newkey); copy_disk(self.disk,dst.disk); dst.state="new"; dst.created=time.time()
                r=dst.open(); VMS[newkey]=dst; return r
            if self.state!="suspended": self.suspend()
            dst=VM(newkey)
            for src,d in ((self.disk,dst.disk),(self.snap,dst.snap),(self.mem,dst.mem)):
                if os.path.exists(src): shutil.copyfile(src,d)
            dst.state="suspended"; dst.created=time.time()
            r=dst.resume(); VMS[newkey]=dst; return r

REG_LOCK=threading.Lock(); VMS={}
COLD=os.environ.get("SHARD_COLD","0")=="1"
PREWARM_N=0 if COLD else POOL_TARGET
POOL=[]; POOL_LOCK=threading.Lock(); POOL_CREATING=[0]

def _make_slot():
    """Napravi jedan prewarmed snapshot slot i vrati ga u pool (thread-safe)."""
    k="pool-%d-%s"%(int(time.time()*1000),uuid.uuid4().hex[:6])
    v=VM(k)
    try:
        v.open(); time.sleep(0.8); v.suspend()
        if not (os.path.exists(v.snap) and os.path.exists(v.mem)):
            raise RuntimeError("slot bez snapshot-a")
        with POOL_LOCK: POOL.append(v)
        met("pool_created")
        return True
    except Exception as e:
        print("shard: pool slot fail %s %s"%(type(e).__name__,str(e)[:120]),flush=True)
        try:
            if v.proc and v.proc.poll() is None: v.proc.kill(); v.proc.wait()
        except Exception: pass
        shutil.rmtree(v.dir,ignore_errors=True)
        return False

def prewarm_worker():
    """Trajni refill: odrzava POOL na PREWARM_N (pool vise nije one-shot)."""
    while True:
        need=False
        with POOL_LOCK:
            need = len(POOL)+POOL_CREATING[0] < PREWARM_N
            if need: POOL_CREATING[0]+=1
        if need:
            try: _make_slot()
            finally:
                with POOL_LOCK: POOL_CREATING[0]=max(0,POOL_CREATING[0]-1)
            continue
        time.sleep(0.25)

def acquire_slot(key):
    """Uzmi slot i vezi ga na kljuc; snapshot ostaje u svom diru (FC snima putanju diska)."""
    with POOL_LOCK:
        while POOL:
            v=POOL.pop(0)
            if v.state=="suspended" and os.path.exists(v.snap) and os.path.exists(v.mem):
                nv=VM(key,v.dir); nv.state="suspended"; nv.disk=v.disk
                nv.snap=v.snap; nv.mem=v.mem; nv.sock=v.sock; nv.log=v.log; nv.vsock=v.vsock
                nv.created=v.created; met("warm")
                return nv
    return None
BACKUP=os.path.join(BASE,"backups")
def _z(src,dst,decompress=False):
    if not os.path.exists(src): return False
    if decompress:
        cmd=["zstd","-q","-d","-f"]
    else:
        # Level 1 + multithread: ~6x faster than -3 on a 1 GB rootfs, ~12% larger backup.
        cmd=["zstd","-q","-f","-%s"%BACKUP_LEVEL,"-T%s"%BACKUP_THREADS]
    try:
        r=subprocess.run(cmd+[src,"-o",dst],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if r.returncode!=0 and not decompress:
            # Some zstd builds lack multithread support / reject the level: retry single-thread -1.
            r=subprocess.run(["zstd","-q","-f","-1",src,"-o",dst],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return r.returncode==0 and os.path.exists(dst)
    except Exception:
        return False
def backup_vm(v):
    if v.key.startswith("pool-"): return False
    if not os.path.exists(v.disk): return False
    if free_mb(BASE) < MIN_FREE_MB: return False
    d=os.path.join(BACKUP,v.key)
    try:
        os.makedirs(d,exist_ok=True)
        z=os.path.join(d,"rootfs.ext4.zst"); tmp=z+".tmp"
        if not _z(v.disk,tmp,False): return False
        st=os.stat(v.disk); sha=file_sha(v.disk); os.replace(tmp,z)
        meta={"key":v.key,"ts":time.time(),"disk_path":v.disk,"rootfs_sha256":sha,"size":st.st_size,"mtime_ns":st.st_mtime_ns,"files":["rootfs.ext4.zst"]}
        mt=os.path.join(d,"meta.json.tmp")
        with open(mt,"w") as f: json.dump(meta,f); f.flush(); os.fsync(f.fileno())
        os.replace(mt,os.path.join(d,"meta.json"))
        for _p in (d,z,os.path.join(d,"meta.json")):
            try: os.chmod(_p,0o600 if _p!=d else 0o700)
            except OSError: pass
        return os.path.exists(z) and os.path.getsize(z)>0
    except Exception as e:
        print("shard: backup error key=%s %s"%(v.key,type(e).__name__),flush=True); return False

def restore_vm(v):
    d=os.path.join(BACKUP,v.key)
    if not os.path.isdir(d): return False
    try: meta=json.load(open(os.path.join(d,"meta.json")))
    except Exception: meta={}
    z=os.path.join(d,"rootfs.ext4.zst")
    if not os.path.exists(v.disk):
        if not os.path.exists(z): return False
        if not _z(z,v.disk,True): return False
    if not os.path.exists(v.disk): return False
    rsha=meta.get("rootfs_sha256")
    if VERIFY_SHA and rsha and file_sha(v.disk)!=rsha: raise RuntimeError("rootfs sha256 mismatch")
    for name in ("snap.bin","mem.bin"):
        try: os.remove(os.path.join(v.dir,name))
        except OSError: pass
    return True

def save_reg():
    with VMS_LOCK: data={k:v.info() for k,v in VMS.items()}
    tmp=REG+".tmp"
    try:
        with open(tmp,"w") as f: json.dump(data,f,indent=2); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,REG)
    except Exception: pass

def gc_backups():
    keep_days=float(os.environ.get("SHARD_BACKUP_KEEP_DAYS","7"))
    keep_count=int(os.environ.get("SHARD_BACKUP_KEEP","10"))
    removed=0
    try:
        dirs=[]
        for name in os.listdir(BACKUP):
            d=os.path.join(BACKUP,name)
            if os.path.isdir(d): dirs.append((os.path.getmtime(d),d))
        dirs.sort(reverse=True)
        for i,(m,d) in enumerate(dirs):
            try:
                if (time.time()-m)>keep_days*86400 or i>=keep_count:
                    shutil.rmtree(d,ignore_errors=True); removed+=1
            except Exception: pass
    except OSError: pass
    return removed

def cleanup_orphan_fc():
    killed=0
    try:
        import glob
        for d in glob.glob("/proc/[0-9]*"):
            try:
                cmd=open(d+"/cmdline","rb").read().replace(b"\x00",b" ").decode(errors="replace")
                if "firecracker" in cmd and (WS+"/" in cmd):
                    pid=int(d.rsplit("/",1)[1])
                    if pid!=os.getpid():
                        os.kill(pid,9); killed+=1
            except Exception: pass
    except Exception: pass
    if killed: print("shard: reaped orphan firecracker",killed,flush=True)
    return killed

def cleanup_pool_dirs():
    """Obrisi SAMO pool-* direktorije koji nisu vezani na registrovani workspace."""
    keep=set()
    try:
        for _k,info in (json.load(open(REG)) or {}).items():
            d=(info or {}).get("dir")
            if d: keep.add(os.path.realpath(d))
    except Exception: pass
    try:
        for name in os.listdir(WS):
            p=os.path.join(WS,name)
            if name.startswith("pool-") and os.path.realpath(p) not in keep:
                shutil.rmtree(p,ignore_errors=True)
    except OSError: pass

def reap_orphan(key, info):
    try:
        pid=info.get("pid")
        if not pid: return
        pid=int(pid); p=f"/proc/{pid}/cmdline"
        if not os.path.exists(p): return
        cmd=open(p,"rb").read().replace(b"\x00",b" ").decode(errors="replace")
        sock=os.path.join(str(info.get("dir","")),"fc.sock")
        if "firecracker" in cmd and sock in cmd:
            try: os.kill(pid,9)
            except OSError: pass
    except Exception: pass

def load_reg():
    try: data=json.load(open(REG))
    except Exception: return
    for k in data:
        try:
            reap_orphan(k,data.get(k) or {})
            d=(data.get(k) or {}).get("dir")
            v=VM(k,d if d and os.path.isdir(d) else None); restore_vm(v)
            if os.path.exists(v.snap) and os.path.exists(v.mem): v.state="suspended"
            elif os.path.exists(v.disk): v.state="suspended" if os.path.exists(v.snap) else "new"
            with VMS_LOCK: VMS[k]=v
        except Exception as e:
            print("shard: skip workspace",k,type(e).__name__,str(e)[:120],flush=True)

def get_vm(key):
    with VMS_LOCK:
        if key in VMS: return VMS[key]
        if len(VMS)>=MAX_WS: raise RuntimeError("max workspaces")
        v=acquire_slot(key)
        if v is not None: VMS[key]=v; return v
        v=VM(key); VMS[key]=v; met("cold"); return v

def sign_receipt(body):
    raw=json.dumps(body,sort_keys=True,separators=(",",":")).encode()
    sig=load_key().sign(raw).hex()
    pub=load_key().public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    rec=dict(body); rec["signature"]=sig; rec["public_key"]=pub
    try:
        if os.path.exists(RECEIPTS) and os.path.getsize(RECEIPTS)>RECEIPTS_MAX:
            keep=RECEIPTS+".bak"
            with open(RECEIPTS,"rb") as f:
                f.seek(max(0,os.path.getsize(RECEIPTS)-RECEIPTS_MAX//2))
                tail=f.read()
            with open(keep,"wb") as f: f.write(tail)
            os.replace(keep,RECEIPTS)
    except Exception: pass
    with open(RECEIPTS,"a") as f: f.write(json.dumps(rec,ensure_ascii=False)+"\n")
    return rec

class H(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    server_version="shard-mvp/%s"%VERSION
    def log_message(self,*a): pass
    def _send(self,code,obj):
        b=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(code)
        self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def _auth(self):
        t=self.headers.get("X-Token") or (self.headers.get("Authorization","").replace("Bearer ",""))
        exp=token()
        try: return bool(t and exp and hmac.compare_digest(str(t),str(exp)))
        except Exception: return False
    def do_GET(self):
        p=urlparse(self.path).path
        if p=="/health":
            with POOL_LOCK: pf=len(POOL)
            return self._send(200,{"ok":True,"svc":"shard-mvp","version":VERSION,
                                   "workspaces":len(VMS),"pool_free":pf,"pool_target":PREWARM_N,
                                   "uptime_s":round(time.time()-START_TS,1)})
        if p=="/metrics":
            return self._send(200,self._metrics_text())
        if p=="/v1/public-key":
            pub=load_key().public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            return self._send(200,{"ok":True,"public_key":pub})
        if p=="/v1/workspaces":
            if not self._auth(): return self._send(401,{"ok":False,"err":"token"})
            return self._send(200,{"ok":True,"workspaces":{k:v.info() for k,v in VMS.items()}})
        self._send(404,{"ok":False,"err":"not found"})
    def _metrics_text(self):
        with _MET_LOCK: m=dict(METRICS)
        with POOL_LOCK: pf=len(POOL)
        o=m.get("opens",0); e=m.get("execs",0)
        lines=[
            "# HELP shard_workspaces Registered workspaces", "# TYPE shard_workspaces gauge",
            "shard_workspaces %d"%len(VMS),
            "# HELP shard_pool_free Idle prewarmed slots", "# TYPE shard_pool_free gauge",
            "shard_pool_free %d"%pf,
            "# TYPE shard_pool_target gauge","shard_pool_target %d"%PREWARM_N,
            "# TYPE shard_opens_total counter","shard_opens_total %d"%o,
            "# TYPE shard_warm_opens_total counter","shard_warm_opens_total %d"%m.get("warm",0),
            "# TYPE shard_cold_opens_total counter","shard_cold_opens_total %d"%m.get("cold",0),
            "# TYPE shard_pool_created_total counter","shard_pool_created_total %d"%m.get("pool_created",0),
            "# TYPE shard_exec_total counter","shard_exec_total %d"%e,
            "# TYPE shard_suspend_total counter","shard_suspend_total %d"%m.get("suspend",0),
            "# TYPE shard_resume_total counter","shard_resume_total %d"%m.get("resume",0),
            "# TYPE shard_errors_total counter","shard_errors_total %d"%m.get("errors",0),
            "# TYPE shard_uptime_seconds gauge","shard_uptime_seconds %.1f"%(time.time()-START_TS),
        ]
        if o: lines.append("shard_open_ms_avg %.2f"%(m.get("open_ms_sum",0)/o))
        if e: lines.append("shard_exec_ms_avg %.2f"%(m.get("exec_ms_sum",0)/e))
        return "\n".join(lines)+"\n"
    def do_POST(self):
        if not self._auth(): return self._send(401,{"ok":False,"err":"token"})
        p=urlparse(self.path).path
        try:
            n=int(self.headers.get("Content-Length",0)); body=json.loads(self.rfile.read(n) or b"{}")
        except Exception as e: return self._send(400,{"ok":False,"err":str(e)})
        try:
            if p=="/v1/gc":
                removed=gc_backups(); orphan=cleanup_orphan_fc()
                return self._send(200,{"ok":True,"backups_removed":removed,"orphans_reaped":orphan})
            if p=="/v1/workspaces/open":
                key=str(body.get("key") or "").strip()
                if not key or not KEY_RE.fullmatch(key): return self._send(400,{"ok":False,"err":"key"})
                t0=time.time(); v=get_vm(key); info=v.open(); save_reg()
                ms=round((time.time()-t0)*1000,1); met("opens"); met("open_ms",ms)
                return self._send(200,{"ok":True,**info,"ms":ms})
            m=re.fullmatch(r"/v1/workspaces/([A-Za-z0-9_.-]{1,80})/(exec|suspend|resume|fork|backup)",p)
            if not m: return self._send(404,{"ok":False,"err":"not found"})
            key,op=m.group(1),m.group(2); v=get_vm(key)
            if op=="exec":
                cmd=str(body.get("cmd") or "").strip()
                if not cmd: return self._send(400,{"ok":False,"err":"cmd"})
                try:
                    to=float(body.get("timeout",20))
                    if not (to>0) or to!=to or to==float("inf"): to=20
                    to=min(max(to,0.1),20)
                except Exception: to=20
                rc,out,ms=v.exec(cmd,to); met("execs"); met("exec_ms",ms)
                rec=sign_receipt({"type":"exec","key":key,"cmd":cmd,"rc":rc,"stdout_sha256":sha(out.encode()),"ms":ms,"ts":time.time()})
                save_reg(); return self._send(200,{"ok":rc==0,"rc":rc,"out":out,"ms":ms,"receipt":rec})
            if op=="suspend": r=v.suspend(); met("suspend"); save_reg(); return self._send(200,{"ok":True,**r})
            if op=="backup":
                if v.state!="suspended": v.suspend()
                ok=backup_vm(v); save_reg()
                return self._send(200,{"ok":True,"key":key,"backup":os.path.join(BACKUP,key),"backup_ok":bool(ok)})
            if op=="resume": r=v.resume(); met("resume"); save_reg(); return self._send(200,{"ok":True,**r})
            if op=="fork":
                nk=str(body.get("key") or "").strip()
                if not nk or not KEY_RE.fullmatch(nk): return self._send(400,{"ok":False,"err":"new key"})
                r=v.fork(nk); save_reg()
                return self._send(200,{"ok":True,**r})
        except Exception as e:
            met("errors")
            return self._send(500,{"ok":False,"err":type(e).__name__+": "+str(e)[:300]})

    def do_DELETE(self):
        if not self._auth(): return self._send(401,{"ok":False,"err":"token"})
        p=urlparse(self.path).path
        m=re.fullmatch(r"/v1/workspaces/([A-Za-z0-9][A-Za-z0-9._-]{0,63})",p)
        if not m: return self._send(404,{"ok":False,"err":"not found"})
        key=m.group(1)
        with VMS_LOCK: v=VMS.pop(key,None)
        if v is None: return self._send(404,{"ok":False,"err":"workspace"})
        try:
            if v.proc and v.proc.poll() is None:
                try: v.proc.kill(); v.proc.wait(timeout=3)
                except Exception: pass
            shutil.rmtree(v.dir,ignore_errors=True)
            shutil.rmtree(os.path.join(BACKUP,key),ignore_errors=True)
        except Exception as e:
            return self._send(500,{"ok":False,"err":type(e).__name__})
        save_reg(); return self._send(200,{"ok":True,"key":key,"deleted":True})

def _shutdown(sig,frame):
    """Graceful stop: snapshot running workspace-e (mem se poravna s diskom), ugasi pool."""
    try:
        with VMS_LOCK: vms=list(VMS.values())
        for v in vms:
            try:
                if v.proc and v.proc.poll() is None: v.suspend()
            except Exception: pass
        with POOL_LOCK:
            pool=list(POOL); POOL.clear()
        for v in pool:
            try:
                if v.proc and v.proc.poll() is None: v.proc.kill()
            except Exception: pass
        cleanup_pool_dirs()
    except Exception: pass
    os._exit(0)

class Srv(ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=True

if __name__=="__main__":
    os.makedirs(WS,exist_ok=True); cleanup_orphan_fc(); cleanup_pool_dirs(); gc_backups(); load_reg()
    signal.signal(signal.SIGTERM,_shutdown); signal.signal(signal.SIGINT,_shutdown)
    threading.Thread(target=prewarm_worker,daemon=True).start()
    print(f"shard-mvp {VERSION} :{PORT} token={'yes' if token() else 'no'} ws={len(VMS)} pool={PREWARM_N}",flush=True)
    Srv(("0.0.0.0",PORT),H).serve_forever()
