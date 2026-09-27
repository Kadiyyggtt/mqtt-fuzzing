#!/usr/bin/env python3
"""
MQTT broker fuzzing kampanya harness'i (v3).
Mimari: Radamsa toplu mod (-o '%n' ile diske 2000 mutasyon/parti),
        gercek broker PID izleme, /sys/class/thermal sicaklik,
        dort oracle (O1 crash, O2 ASan, O3 hang, O4 events.csv'de isaretli).
"""
import argparse, os, sys, socket, subprocess, time, threading, glob, signal, json, random, shutil
from datetime import datetime

def utcnow():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z"

CONNECT_311 = bytes.fromhex("101000044d5154540402003c000474657374")
CONNECT_50  = bytes.fromhex("101100044d5154540502003c00000474657374")

def is_v5_seed(path):
    return "_50_" in os.path.basename(path)

def read_temp():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return f"{int(f.read().strip())/1000:.1f}"
    except Exception:
        return ""

def find_broker_pid(name):
    try:
        out = subprocess.check_output(["pgrep","-f",name],text=True).split()
        return int(out[-1]) if out else None
    except Exception:
        return None

class Monitor(threading.Thread):
    def __init__(self, pid_getter, outpath, interval=5.0):
        super().__init__(daemon=True)
        self.pid_getter, self.outpath, self.interval = pid_getter, outpath, interval
        self.running=True
    def run(self):
        with open(self.outpath,"w") as f:
            f.write("timestamp,cpu_pct,rss_kb,threads,swap_kb,temp_c\n")
            while self.running:
                pid=self.pid_getter(); cpu=rss=thr=swap=""
                if pid:
                    try:
                        o=subprocess.check_output(["ps","-p",str(pid),"-o","%cpu=,rss=,nlwp="],text=True).split()
                        cpu,rss,thr=o[0],o[1],o[2]
                    except Exception: pass
                    try:
                        with open(f"/proc/{pid}/status") as sf:
                            swap=next((l.split()[1] for l in sf if l.startswith("VmSwap")),"0")
                    except Exception: pass
                f.write(f"{utcnow()},{cpu},{rss},{thr},{swap},{read_temp()}\n"); f.flush()
                time.sleep(self.interval)
    def stop(self): self.running=False

def check_dmesg_oom(name, since):
    try:
        out=subprocess.check_output(["dmesg","--since",since],text=True,stderr=subprocess.DEVNULL)
        return [l for l in out.splitlines() if "killed process" in l.lower() and name.lower() in l.lower()]
    except Exception:
        return []

def liveness_ok(host,port,timeout=3.0):
    try:
        s=socket.create_connection((host,port),timeout=timeout); s.settimeout(timeout)
        s.sendall(CONNECT_311); s.recv(64)
        s.sendall(bytes([0xC0,0x00])); r=s.recv(8); s.close()
        return len(r)>=2 and r[0]==0xD0
    except Exception:
        return False

def send_one(host,port,connect,data,timeout=1.0):
    """CONNECT + mutasyona ugramis paket gonderir; yanit BEKLEMEZ (hiz icin).
    Amac brokerin ayristiricisini tetiklemek; yanit icerigi onemli degil."""
    try:
        s=socket.create_connection((host,port),timeout=timeout); s.settimeout(timeout)
        s.sendall(connect)
        s.sendall(data)
        s.close()
    except Exception:
        pass

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--broker",required=True)
    ap.add_argument("--broker-cmd",required=True)
    ap.add_argument("--tool",default="radamsa")
    ap.add_argument("--duration",type=int,required=True)
    ap.add_argument("--seed",type=int,required=True)
    ap.add_argument("--outdir",required=True)
    ap.add_argument("--seeddir",default=os.path.expanduser("~/mqtt-fuzzing/seeds/client"))
    ap.add_argument("--host",default="127.0.0.1")
    ap.add_argument("--port",type=int,default=1883)
    ap.add_argument("--asan",action="store_true")
    ap.add_argument("--batch",type=int,default=2000)
    args=ap.parse_args()

    os.makedirs(os.path.join(args.outdir,"crashes"),exist_ok=True)
    mutdir=os.path.join(args.outdir,"_mut"); os.makedirs(mutdir,exist_ok=True)
    random.seed(args.seed)
    seeds=sorted(glob.glob(os.path.join(args.seeddir,"*.bin")))
    if not seeds: print("HATA: tohum yok"); sys.exit(1)

    asan_log=os.path.join(args.outdir,"asan")
    env=dict(os.environ)
    if args.asan:
        env["ASAN_OPTIONS"]=f"log_path={asan_log}:abort_on_error=0:exitcode=99:detect_leaks=0"

    start_marker=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    shell=subprocess.Popen(args.broker_cmd,shell=True,env=env,
          stdout=open(os.path.join(args.outdir,"broker_stdout.log"),"w"),
          stderr=subprocess.STDOUT,preexec_fn=os.setsid)
    time.sleep(3)
    bpid=find_broker_pid(args.broker)
    if bpid is None: print("HATA: broker baslamadi"); sys.exit(1)
    state={"pid":bpid}

    mon=Monitor(lambda:state["pid"],os.path.join(args.outdir,"resources.csv")); mon.start()
    events=open(os.path.join(args.outdir,"events.csv"),"w")
    events.write("timestamp,event,detail\n")
    def log_event(ev,d=""): events.write(f"{utcnow()},{ev},{d}\n"); events.flush()

    manifest={"broker":args.broker,"tool":args.tool,"seed":args.seed,"duration_s":args.duration,
              "start_utc":utcnow(),"seed_count":len(seeds),"broker_cmd":args.broker_cmd,
              "broker_pid":bpid,"batch":args.batch}
    log_event("CAMPAIGN_START",f"seed={args.seed}")

    def broker_alive():
        return subprocess.call(["kill","-0",str(state["pid"])],stderr=subprocess.DEVNULL)==0

    def handle_crash():
        nonlocal start_marker
        oom=check_dmesg_oom(args.broker,start_marker)
        if oom: log_event("OOM_KILL","")
        else:
            log_event("O1_CRASH","broker sonlandi")
            for lg in glob.glob(asan_log+".*"):
                dst=os.path.join(args.outdir,"crashes",f"asan_{int(time.time())}_{os.path.basename(lg)}")
                os.rename(lg,dst); log_event("O2_ASAN",os.path.basename(dst))
        s2=subprocess.Popen(args.broker_cmd,shell=True,env=env,
            stdout=open(os.path.join(args.outdir,"broker_stdout.log"),"a"),
            stderr=subprocess.STDOUT,preexec_fn=os.setsid)
        time.sleep(2); np=find_broker_pid(args.broker)
        if np: state["pid"]=np
        start_marker=datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    t_end=time.time()+args.duration
    sent=anomalies=batch_ctr=0
    last_sent_blob=b""
    try:
        while time.time()<t_end:
            if not broker_alive():
                handle_crash(); anomalies+=1; continue
            # --- bir parti mutasyon uret (tek radamsa cagrisi) ---
            src=random.choice(seeds)
            connect=CONNECT_50 if is_v5_seed(src) else CONNECT_311
            for old in glob.glob(os.path.join(mutdir,"mut_*.bin")): os.remove(old)
            try:
                subprocess.check_output(
                    ["radamsa","-n",str(args.batch),"--seed",str(args.seed+batch_ctr),
                     "-o",os.path.join(mutdir,"mut_%n.bin"),src],timeout=120)
                batch_ctr+=1
            except Exception:
                continue
            for mf in sorted(glob.glob(os.path.join(mutdir,"mut_*.bin"))):
                if time.time()>=t_end: break
                if not broker_alive():
                    handle_crash(); anomalies+=1; continue
                try: data=open(mf,"rb").read()
                except Exception: continue
                send_one(args.host,args.port,connect,data)
                sent+=1
                if sent%500==0:
                    if not liveness_ok(args.host,args.port):
                        time.sleep(1)
                        if not liveness_ok(args.host,args.port) and broker_alive():
                            log_event("O3_HANG",f"sent={sent}"); anomalies+=1
                    shutil.copy(mf,os.path.join(args.outdir,"crashes",f"sample_{sent}.bin"))
    except KeyboardInterrupt:
        log_event("INTERRUPT")
    finally:
        mon.stop()
        log_event("CAMPAIGN_END",f"sent={sent} anomalies={anomalies}")
        manifest.update({"end_utc":utcnow(),"sent":sent,"anomalies":anomalies})
        json.dump(manifest,open(os.path.join(args.outdir,"manifest.json"),"w"),indent=2)
        try: shutil.rmtree(mutdir)
        except Exception: pass
        try: os.killpg(os.getpgid(shell.pid),signal.SIGTERM)
        except Exception: pass
        events.close()
        print(f"\nKampanya bitti: {sent} girdi gonderildi, {anomalies} anomali.")

if __name__=="__main__":
    main()
