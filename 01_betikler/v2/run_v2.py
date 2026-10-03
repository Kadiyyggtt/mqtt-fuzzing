#!/usr/bin/env python3
"""
MQTT broker fuzzing harness — Deney v2 (eşit girdi bütçesi).

v1'den farkları (hocanın eleştirilerine yanıt):
  1. Durma koşulu SÜRE değil GİRDİ SAYISI (--budget): her araç-broker çifti
     aynı sayıda test girdisi alır.
  2. Eşit paket türü dağılımı: iki araç da yalnızca üç türden üretir
     (CONNECT, saklama bayraklı PUBLISH, SUBSCRIBE) ve türler sırayla
     (round-robin) eşit paylaşılır.
       - Boofuzz: her girdi sırayla bir sonraki şablondan gelir.
       - Radamsa: her parti (--batch) sırayla bir sonraki türün tohumundan
         üretilir; türler arası fark en fazla bir parti olur.
  3. Tek CONNECT sürümü: her iki araç da her girdiden önce aynı sabit
     MQTT 3.1.1 CONNECT'i gönderir (v1'deki 5.0 CONNECT farkı kaldırıldı).
  4. Anlık CPU: izleyici /proc/<pid>/stat'tan aralık başına CPU yüzdesini
     de yazar (cpu_inst_pct). Birikimli ps %cpu da korunur.
  5. Boşta taban ölçümü: --idle-seconds N verilirse trafik göndermeden
     yalnızca broker izlenir.

Çıktılar (outdir): manifest.json, events.csv, resources.csv,
                   type_counts.json, broker_stdout.log, crashes/
"""
import argparse, os, sys, socket, subprocess, time, threading, glob, signal, json, random, shutil
from datetime import datetime, timezone

def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

CONNECT_311 = bytes.fromhex("101000044d5154540402003c000474657374")
TYPES = ["connect", "publish_retain", "subscribe"]
CLK = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

# ------------------------------------------------------------ izleme
def read_temp():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return f"{int(f.read().strip())/1000:.1f}"
    except Exception:
        return ""

def proc_ticks(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().rsplit(")", 1)[1].split()
        return int(parts[11]) + int(parts[12])          # utime + stime
    except Exception:
        return None

def broker_pid_of(popen):
    """setsid ile başlatılan kabuğun süreç grubundaki broker PID'i (sh değil, gerçek ikili)."""
    try:
        pids = [int(x) for x in subprocess.check_output(["pgrep", "-g", str(popen.pid)], text=True).split()]
    except Exception:
        return None
    cands = []
    for pid in pids:
        try:
            exe = os.path.basename(os.readlink(f"/proc/{pid}/exe"))
        except Exception:
            continue
        if exe not in ("sh", "dash", "bash"):
            cands.append(pid)
    return max(cands) if cands else None

class Monitor(threading.Thread):
    def __init__(self, pid_getter, outpath, interval=5.0):
        super().__init__(daemon=True)
        self.pid_getter, self.outpath, self.interval = pid_getter, outpath, interval
        self.running = True
    def run(self):
        last_pid = last_ticks = last_t = None
        with open(self.outpath, "w") as f:
            f.write("timestamp,cpu_pct,cpu_inst_pct,rss_kb,threads,swap_kb,temp_c\n")
            while self.running:
                pid = self.pid_getter(); cpu = inst = rss = thr = swap = ""
                if pid:
                    try:
                        o = subprocess.check_output(["ps", "-p", str(pid), "-o", "%cpu=,rss=,nlwp="], text=True).split()
                        cpu, rss, thr = o[0], o[1], o[2]
                    except Exception:
                        pass
                    try:
                        with open(f"/proc/{pid}/status") as sf:
                            swap = next((l.split()[1] for l in sf if l.startswith("VmSwap")), "0")
                    except Exception:
                        pass
                    ticks, now = proc_ticks(pid), time.monotonic()
                    if ticks is not None and pid == last_pid and last_ticks is not None and now > last_t:
                        inst = f"{100.0*(ticks-last_ticks)/CLK/(now-last_t):.1f}"
                    last_pid, last_ticks, last_t = pid, ticks, now
                f.write(f"{utcnow()},{cpu},{inst},{rss},{thr},{swap},{read_temp()}\n"); f.flush()
                time.sleep(self.interval)
    def stop(self):
        self.running = False

def check_dmesg_oom(name, since):
    try:
        out = subprocess.check_output(["dmesg", "--since", since], text=True, stderr=subprocess.DEVNULL)
        return [l for l in out.splitlines() if "killed process" in l.lower() and name.lower() in l.lower()]
    except Exception:
        return []

def liveness_ok(host, port, timeout=3.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout); s.settimeout(timeout)
        s.sendall(CONNECT_311); s.recv(64)
        s.sendall(bytes([0xC0, 0x00])); r = s.recv(8); s.close()
        return len(r) >= 2 and r[0] == 0xD0
    except Exception:
        return False

def send_one(host, port, data, timeout=1.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout); s.settimeout(timeout)
        s.sendall(CONNECT_311); s.sendall(data); s.close()
    except Exception:
        pass

# ------------------------------------------------------------ girdi üreticileri
def seed_groups(seeddir):
    """3.1.1 tohumlarını üç türe ayırır (5.0 özellikli tohumlar dışarıda)."""
    g = {t: [] for t in TYPES}
    for p in sorted(glob.glob(os.path.join(seeddir, "*.bin"))):
        if "_50_" in os.path.basename(p):
            continue
        b0 = open(p, "rb").read(1)[0]
        if b0 >> 4 == 1:
            g["connect"].append(p)
        elif b0 >> 4 == 3 and b0 & 0x01:
            g["publish_retain"].append(p)
        elif b0 >> 4 == 8:
            g["subscribe"].append(p)
    return g

def radamsa_stream(seeddir, mutdir, rng_seed, batch):
    groups = seed_groups(seeddir)
    for t in TYPES:
        if not groups[t]:
            sys.exit(f"HATA: '{t}' türünde tohum yok ({seeddir})")
    rng = random.Random(rng_seed); k = 0
    while True:
        t = TYPES[k % 3]; src = rng.choice(groups[t])
        for old in glob.glob(os.path.join(mutdir, "mut_*.bin")):
            os.remove(old)
        try:
            subprocess.check_output(["radamsa", "-n", str(batch), "--seed", str(rng_seed * 100000 + k),
                                     "-o", os.path.join(mutdir, "mut_%n.bin"), src], timeout=120)
        except Exception:
            k += 1; continue
        for mf in sorted(glob.glob(os.path.join(mutdir, "mut_*.bin"))):
            try:
                yield t, open(mf, "rb").read()
            except Exception:
                continue
        k += 1

def boofuzz_stream():
    from boofuzz import Request, Static, Bytes, Word, Byte, String
    from boofuzz.mutation_context import MutationContext
    def connect():
        return Request("connect", children=(
            Static(name="type", default_value=b"\x10"), Bytes(name="remlen", default_value=b"\x10", max_len=4),
            Word(name="proto_len", default_value=4, endian=">"), String(name="proto_name", default_value="MQTT"),
            Byte(name="proto_level", default_value=4), Byte(name="connect_flags", default_value=0x02),
            Word(name="keepalive", default_value=60, endian=">"), Word(name="cid_len", default_value=4, endian=">"),
            String(name="client_id", default_value="test")))
    def publish():
        return Request("publish", children=(
            Static(name="type", default_value=b"\x31"), Bytes(name="remlen", default_value=b"\x0c", max_len=4),
            Word(name="topic_len", default_value=4, endian=">"), String(name="topic", default_value="test"),
            String(name="msg", default_value="hello")))
    def subscribe():
        return Request("subscribe", children=(
            Static(name="type", default_value=b"\x82"), Bytes(name="remlen", default_value=b"\x09", max_len=4),
            Word(name="packet_id", default_value=1, endian=">"), Word(name="topic_len", default_value=4, endian=">"),
            String(name="topic", default_value="test"), Byte(name="qos", default_value=0)))
    builders = {"connect": connect, "publish_retain": publish, "subscribe": subscribe}
    def cycle(t):
        while True:
            req = builders[t](); base = req.render()
            for m in req.mutations(base):
                try:
                    yield req.render(MutationContext(m))
                except Exception:
                    continue
    gens = {t: cycle(t) for t in TYPES}; k = 0
    while True:
        t = TYPES[k % 3]; k += 1
        yield t, next(gens[t])

# ------------------------------------------------------------ ana döngü
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--broker", required=True)
    ap.add_argument("--broker-cmd", required=True)
    ap.add_argument("--tool", choices=["radamsa", "boofuzz", "idle"], required=True)
    ap.add_argument("--budget", type=int, default=500000, help="gönderilecek test girdisi sayısı")
    ap.add_argument("--idle-seconds", type=int, default=600)
    ap.add_argument("--max-hours", type=float, default=12.0, help="güvenlik için azami süre")
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--seeddir", default=os.path.expanduser("~/mqtt-fuzzing/seeds/client"))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--batch", type=int, default=600)
    args = ap.parse_args()

    os.makedirs(os.path.join(args.outdir, "crashes"), exist_ok=True)
    mutdir = os.path.join(args.outdir, "_mut"); os.makedirs(mutdir, exist_ok=True)
    asan_log = os.path.join(args.outdir, "asan")
    env = dict(os.environ, ASAN_OPTIONS=f"log_path={asan_log}:abort_on_error=0:exitcode=99:detect_leaks=0")

    def start_broker(mode):
        return subprocess.Popen(args.broker_cmd, shell=True, env=env,
                                stdout=open(os.path.join(args.outdir, "broker_stdout.log"), mode),
                                stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    def port_free(timeout=60):
        """Önceki broker portu bırakana kadar bekler."""
        t = time.time()
        while time.time() - t < timeout:
            try:
                c = socket.create_connection((args.host, args.port), timeout=1); c.close()
                time.sleep(2)
            except Exception:
                return True
        return False

    start_marker = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    shell = bpid = None
    for attempt in range(1, 4):                      # 3 deneme
        if not port_free():
            print(f"UYARI: {args.port} portu 60 sn içinde boşalmadı (deneme {attempt})")
        shell = start_broker("w" if attempt == 1 else "a"); time.sleep(3 + 2 * attempt)
        bpid = broker_pid_of(shell)
        if bpid is not None and liveness_ok(args.host, args.port):
            break
        try:
            os.killpg(shell.pid, signal.SIGTERM)
        except Exception:
            pass
        bpid = None; time.sleep(5)
    if bpid is None:
        sys.exit("HATA: broker 3 denemede başlamadı (broker_stdout.log'a bakın)")
    state = {"pid": bpid, "restarts": 0, "shell": shell}

    mon = Monitor(lambda: state["pid"], os.path.join(args.outdir, "resources.csv")); mon.start()
    events = open(os.path.join(args.outdir, "events.csv"), "w"); events.write("timestamp,event,detail\n")
    def log_event(ev, d=""):
        events.write(f"{utcnow()},{ev},{d}\n"); events.flush()

    manifest = {"version": "v2", "broker": args.broker, "tool": args.tool, "rep": args.rep, "seed": args.seed,
                "budget": args.budget, "types": TYPES, "connect": "MQTT 3.1.1 fixed", "batch": args.batch,
                "broker_cmd": args.broker_cmd, "broker_pid": bpid, "start_utc": utcnow(), "done": False}
    log_event("CAMPAIGN_START", f"tool={args.tool} rep={args.rep} budget={args.budget}")

    def alive():
        return subprocess.call(["kill", "-0", str(state["pid"])], stderr=subprocess.DEVNULL) == 0

    def handle_crash(last_type):
        nonlocal start_marker
        if check_dmesg_oom(args.broker, start_marker):
            log_event("OOM_KILL", "")
        else:
            log_event("O1_CRASH", f"last_type={last_type}")
            for lg in glob.glob(asan_log + ".*"):
                dst = os.path.join(args.outdir, "crashes", f"asan_{int(time.time())}_{os.path.basename(lg)}")
                os.rename(lg, dst); log_event("O2_ASAN", os.path.basename(dst))
        port_free(30)
        sh2 = start_broker("a"); time.sleep(2)
        np = broker_pid_of(sh2)
        if np:
            state["pid"] = np; state["shell"] = sh2
        state["restarts"] += 1
        start_marker = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sent = anomalies = 0; counts = {t: 0 for t in TYPES}; t0 = time.time()
    t_limit = t0 + args.max_hours * 3600
    try:
        if args.tool == "idle":
            while time.time() < t0 + args.idle_seconds:
                time.sleep(5)
        else:
            stream = radamsa_stream(args.seeddir, mutdir, args.seed, args.batch) if args.tool == "radamsa" else boofuzz_stream()
            last_type = ""
            while sent < args.budget and time.time() < t_limit:
                if not alive():
                    handle_crash(last_type); anomalies += 1; continue
                t, data = next(stream); last_type = t
                send_one(args.host, args.port, data)
                sent += 1; counts[t] += 1
                if sent % 500 == 0:
                    if not liveness_ok(args.host, args.port):
                        time.sleep(1)
                        if not liveness_ok(args.host, args.port) and alive():
                            log_event("O3_HANG", f"sent={sent}"); anomalies += 1
                    with open(os.path.join(args.outdir, "crashes", f"sample_{sent}.bin"), "wb") as f:
                        f.write(data)
                if sent % 50000 == 0:
                    log_event("PROGRESS", f"sent={sent}")
            if not alive():                       # son girdinin çökertip çökertmediği
                handle_crash(last_type); anomalies += 1
    except KeyboardInterrupt:
        log_event("INTERRUPT")
    finally:
        mon.stop(); elapsed = time.time() - t0
        complete = args.tool == "idle" or sent >= args.budget
        log_event("CAMPAIGN_END", f"sent={sent} anomalies={anomalies} restarts={state['restarts']}")
        manifest.update({"end_utc": utcnow(), "elapsed_s": round(elapsed, 1), "sent": sent,
                         "anomalies": anomalies, "restarts": state["restarts"], "type_counts": counts,
                         "rate_per_s": round(sent / elapsed, 2) if elapsed else 0, "done": complete})
        json.dump(manifest, open(os.path.join(args.outdir, "manifest.json"), "w"), indent=2)
        json.dump(counts, open(os.path.join(args.outdir, "type_counts.json"), "w"), indent=2)
        shutil.rmtree(mutdir, ignore_errors=True)
        for sh in {shell, state["shell"]}:
            try:
                os.killpg(sh.pid, signal.SIGTERM)
            except Exception:
                pass
        port_free(30)
        events.close()
        print(f"\nBitti [{args.tool}/{args.broker}/rep{args.rep}]: {sent} girdi, {anomalies} anomali, "
              f"{state['restarts']} yeniden başlatma, {elapsed/3600:.2f} saat. Tamamlandı={complete}")

if __name__ == "__main__":
    main()
