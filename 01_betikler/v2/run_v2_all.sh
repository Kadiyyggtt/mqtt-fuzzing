#!/usr/bin/env bash
# ============================================================
# Deney v2 koordinatörü — eşit girdi bütçesi, eşit tür dağılımı, 3 tekrar
#   Her tekrar, her broker için:  boşta taban (10 dk) -> Radamsa -> Boofuzz
#   Kaldığı yerden devam eder: tamamlanmış koşumları (manifest done=true) atlar.
# Kullanım:  bash run_v2_all.sh [BUTCE] [TEKRAR]      (varsayılan 500000 3)
# Arka planda:  nohup bash ~/mqtt-fuzzing/scripts/v2/run_v2_all.sh > ~/v2.out 2>&1 &
# ============================================================
set -u
ROOT="$HOME/mqtt-fuzzing"; cd "$ROOT" || exit 1
# boofuzz venv içinde kurulu: varsa etkinleştir
[ -f "$ROOT/venv/bin/activate" ] && source "$ROOT/venv/bin/activate"
BUDGET=${1:-500000}; REPS=${2:-3}; IDLE=600
OUT="$ROOT/runs_v2"; mkdir -p "$OUT"
H="$ROOT/scripts/v2/run_v2.py"; SEEDS="$ROOT/seeds/client"
LOG="$OUT/koordinator.log"
say(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

declare -A CMD
CMD[mosquitto]="./builds/mosquitto-asan/src/mosquitto -p 1883"
CMD[nanomq]="./builds/nanomq-asan/build/nanomq/nanomq start --url nmq-tcp://0.0.0.0:1883"
CMD[flashmq]="./builds/flashmq-asan/build/flashmq --config-file ./scripts/flashmq.conf"
BI=(mosquitto nanomq flashmq)

# --- ön kontroller ---
command -v radamsa >/dev/null || { say "HATA: radamsa bulunamadı"; exit 1; }
python3 -c "import boofuzz" 2>/dev/null || { say "HATA: boofuzz kurulu değil (pip install boofuzz)"; exit 1; }
for b in "${BI[@]}"; do bin=${CMD[$b]%% *}; [ -x "$bin" ] || { say "HATA: $bin yok"; exit 1; }; done
[ -f "$ROOT/scripts/flashmq.conf" ] || { say "HATA: scripts/flashmq.conf yok"; exit 1; }
ss -ltn | grep -q ':1883 ' && { say "HATA: 1883 portu dolu — önce çalışan brokerı kapat"; exit 1; }

done_run(){ [ -f "$1/manifest.json" ] && grep -q '"done": true' "$1/manifest.json"; }
run(){  # tool broker rep seed
  local tool=$1 b=$2 rep=$3 seed=$4 d="$OUT/rep${3}_${2}_${1}"
  if done_run "$d"; then say "ATLA (tamam): $d"; return; fi
  rm -rf "$d"; say "BAŞLA: rep$rep  $b  $tool  (bütçe=$BUDGET)"
  ss -ltn | grep -q ':1883 ' && { say "UYARI: 1883 dolu, 10 sn bekleniyor"; sleep 10; }
  python3 "$H" --broker "$b" --broker-cmd "${CMD[$b]}" --tool "$tool" --budget "$BUDGET" \
     --idle-seconds "$IDLE" --rep "$rep" --seed "$seed" --outdir "$d" --seeddir "$SEEDS" >> "$d.log" 2>&1
  say "BİTTİ: $(tail -1 "$d.log")"
  sleep 5
}

say "=========== DENEY v2 BAŞLADI  bütçe=$BUDGET  tekrar=$REPS ==========="
for rep in $(seq 1 "$REPS"); do
  for i in 0 1 2; do b=${BI[$i]}
    run idle    "$b" "$rep" $((rep*1000 + i*10 + 0))
    run radamsa "$b" "$rep" $((rep*1000 + i*10 + 1))
    run boofuzz "$b" "$rep" $((rep*1000 + i*10 + 2))
  done
  tar czf "$OUT/yedek_rep${rep}.tgz" -C "$OUT" $(cd "$OUT" && ls -d rep${rep}_* 2>/dev/null | grep -v '\.log$') 2>/dev/null
  say "YEDEK: yedek_rep${rep}.tgz"
done
say "=========== DENEY v2 TAMAMLANDI ==========="
python3 "$ROOT/scripts/v2/ozet_v2.py" "$OUT" | tee "$OUT/OZET.txt"
