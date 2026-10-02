#!/usr/bin/env python3
"""Deney v2 sonuç özeti: runs_v2/ altındaki koşumlardan makale tablolarını üretir.
Kullanım: python3 ozet_v2.py ~/mqtt-fuzzing/runs_v2   (CSV'ler aynı dizine yazılır)"""
import sys, os, json, csv, glob, statistics as st

root = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/mqtt-fuzzing/runs_v2")
BROKERS, TOOLS = ["mosquitto", "nanomq", "flashmq"], ["radamsa", "boofuzz"]

def num(x):
    try: return float(x)
    except Exception: return None

def res_stats(d):
    rows = list(csv.DictReader(open(os.path.join(d, "resources.csv"))))
    rss = [num(r["rss_kb"]) for r in rows if num(r["rss_kb"]) is not None]
    inst = [num(r["cpu_inst_pct"]) for r in rows if num(r.get("cpu_inst_pct")) is not None]
    temp = [num(r["temp_c"]) for r in rows if num(r["temp_c"]) is not None]
    swap = [num(r["swap_kb"]) for r in rows if num(r["swap_kb"]) is not None]
    return {"rss_peak_mb": max(rss) / 1000 if rss else None,
            "rss_median_mb": st.median(rss) / 1000 if rss else None,
            "cpu_inst_median": st.median(inst) if inst else None,
            "cpu_inst_p95": sorted(inst)[int(0.95 * (len(inst) - 1))] if inst else None,
            "temp_max": max(temp) if temp else None, "swap_max_kb": max(swap) if swap else None,
            "samples": len(rows)}

def ms(v):
    v = [x for x in v if x is not None]
    if not v: return "—"
    return f"{st.mean(v):.1f}" if len(v) == 1 else f"{st.mean(v):.1f} ± {st.stdev(v):.1f}"

runs = {}
for d in sorted(glob.glob(os.path.join(root, "rep*_*_*"))):
    if not os.path.isdir(d): continue
    try: m = json.load(open(os.path.join(d, "manifest.json")))
    except Exception: continue
    if not m.get("done"): print("UYARI: tamamlanmamış koşum:", d); continue
    m.update(res_stats(d))
    m["crash"] = sum(1 for l in open(os.path.join(d, "events.csv")) if ",O1_CRASH," in l)
    m["asan"] = sum(1 for l in open(os.path.join(d, "events.csv")) if ",O2_ASAN," in l)
    m["hang"] = sum(1 for l in open(os.path.join(d, "events.csv")) if ",O3_HANG," in l)
    runs[(m["rep"], m["broker"], m["tool"])] = m

reps = sorted({k[0] for k in runs})
print(f"Tamamlanan koşum: {len(runs)}   tekrarlar: {reps}\n")

# Tablo A: kusur gözlemi (A1, A3)
print("TABLO A — Kusur gözlemi (eşit bütçe, eşit tür dağılımı)")
print(f"{'Broker':10} {'Araç':8} {'Girdi/tekrar':>12} {'O1 (ort ± ss)':>15} {'O1/10^5 girdi':>15} {'O2':>4} {'O3':>4} {'Hız (girdi/s)':>15}")
rowsA = []
for b in BROKERS:
    for t in TOOLS:
        R = [runs[(r, b, t)] for r in reps if (r, b, t) in runs]
        if not R: continue
        rate = [1e5 * x["crash"] / x["sent"] for x in R if x["sent"]]
        line = [b, t, int(st.mean([x["sent"] for x in R])), ms([x["crash"] for x in R]), ms(rate),
                sum(x["asan"] for x in R), sum(x["hang"] for x in R), ms([x["rate_per_s"] for x in R])]
        rowsA.append(line)
        print(f"{line[0]:10} {line[1]:8} {line[2]:>12} {line[3]:>15} {line[4]:>15} {line[5]:>4} {line[6]:>4} {line[7]:>15}")

# Tablo B: kaynak kullanımı, boşta tabana göre net (A2)
print("\nTABLO B — Kaynak kullanımı (her araç yükü altında; boşta tabana göre)")
print(f"{'Broker':10} {'Boşta RSS':>11} {'Tepe RSS':>13} {'Net artış':>13} {'Boşta CPU':>10} {'Yük CPU med':>12} {'Yük CPU p95':>12} {'Max °C':>7}")
rowsB = []
for b in BROKERS:
    I = [runs[(r, b, "idle")] for r in reps if (r, b, "idle") in runs]
    for t in TOOLS:
        L = [runs[(r, b, t)] for r in reps if (r, b, t) in runs]
        if not I or not L: continue
        net = [l["rss_peak_mb"] - i["rss_median_mb"] for i, l in zip(I, L)]
        line = [b + "/" + t, ms([i["rss_median_mb"] for i in I]), ms([l["rss_peak_mb"] for l in L]), ms(net),
                ms([i["cpu_inst_median"] for i in I]), ms([l["cpu_inst_median"] for l in L]),
                ms([l["cpu_inst_p95"] for l in L]), f"{max(l['temp_max'] or 0 for l in L):.1f}"]
        rowsB.append(line)
        print(f"{line[0]:18} {line[1]:>9} {line[2]:>13} {line[3]:>13} {line[4]:>10} {line[5]:>12} {line[6]:>12} {line[7]:>7}")

print("\nNot: RSS MB (1 MB=1000 kB). CPU 'cpu_inst' = aralık başına anlık CPU (%, tek çekirdek=100).")
print("Takas kullanımı (en yüksek):", max((x.get("swap_max_kb") or 0) for x in runs.values()), "kB")

with open(os.path.join(root, "tablo_A_kusur.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["broker", "arac", "girdi", "O1", "O1_per_1e5", "O2", "O3", "hiz"]); w.writerows(rowsA)
with open(os.path.join(root, "tablo_B_kaynak.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["broker_arac", "bosta_rss", "tepe_rss", "net_artis", "bosta_cpu", "yuk_cpu_med", "yuk_cpu_p95", "max_c"]); w.writerows(rowsB)
print("\nCSV:", os.path.join(root, "tablo_A_kusur.csv"), "ve tablo_B_kaynak.csv")
