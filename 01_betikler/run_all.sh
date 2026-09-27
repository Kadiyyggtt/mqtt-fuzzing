#!/bin/bash
# ============================================================
# MQTT Fuzzing - Zincirleme Kampanya Koordinatoru
# 9 kampanya (3 arac x 3 broker) x DURATION saat, sirayla.
# Her kampanya: temiz broker, ayri seed, ayri cikti dizini.
# Ek: her broker icin kaynak profili kosumu (ASan'siz release).
# ============================================================
set -u
ROOT=~/mqtt-fuzzing
cd "$ROOT" || exit 1

DURATION=${1:-18000}          # varsayilan 5 saat (18000 sn)
PROFILE_DUR=7200              # kaynak profili: 2 saat

MOSQ_ASAN="./builds/mosquitto-asan/src/mosquitto -p 1883"
NANO_ASAN="./builds/nanomq-asan/build/nanomq/nanomq start --url nmq-tcp://0.0.0.0:1883"
FLASH_ASAN="./builds/flashmq-asan/build/flashmq --config-file ./scripts/flashmq.conf"

LOG="$ROOT/logs/orchestrator.log"
say(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG"; }

cleanup(){ pkill -f mosquitto 2>/dev/null; pkill -f nanomq 2>/dev/null; pkill -f flashmq 2>/dev/null; sleep 3; }

run_campaign(){
  local tool=$1 broker=$2 cmd=$3 seed=$4 outdir=$5
  say "BASLIYOR: $tool x $broker  (seed=$seed, sure=${DURATION}s) -> $outdir"
  cleanup
  python3 scripts/run_campaign.py \
     --broker "$broker" --broker-cmd "$cmd" \
     --tool "$tool" --duration "$DURATION" --seed "$seed" \
     --outdir "$outdir" --asan \
     >> "$outdir.log" 2>&1
  say "BITTI:    $tool x $broker  -> $(grep -o 'sent=[0-9]*' $outdir/events.csv | tail -1)"
  # her kampanya sonrasi yedek
  tar czf "$outdir.tar.gz" -C "$ROOT/runs" "$(basename $outdir)" 2>/dev/null
  say "YEDEK:    $outdir.tar.gz"
}

say "=========================================="
say "ZINCIRLEME KAMPANYA BASLANGICI (sure=${DURATION}s/kampanya)"
say "=========================================="

# --- RADAMSA x 3 broker ---
run_campaign radamsa mosquitto "$MOSQ_ASAN"  1001 "runs/radamsa_mosquitto"
run_campaign radamsa nanomq    "$NANO_ASAN"  1002 "runs/radamsa_nanomq"
run_campaign radamsa flashmq   "$FLASH_ASAN" 1003 "runs/radamsa_flashmq"

# --- AFLNet x 3 broker (arac kurulunca --asan yerine AFLNet cagrisi eklenecek) ---
# run_campaign aflnet mosquitto ...   (YARIN)
# run_campaign aflnet nanomq ...
# run_campaign aflnet flashmq ...

# --- BOOFUZZ x 3 broker (sablon yazilinca eklenecek) ---
# run_campaign boofuzz mosquitto ...  (YARIN)
# run_campaign boofuzz nanomq ...
# run_campaign boofuzz flashmq ...

say "=========================================="
say "TUM RADAMSA KAMPANYALARI TAMAMLANDI"
say "Toplam sonuc ozeti:"
for d in runs/radamsa_*/; do
  s=$(grep -o 'sent=[0-9]*' "$d/events.csv" 2>/dev/null | tail -1)
  a=$(grep -c -E 'O1_CRASH|O2_ASAN|O3_HANG' "$d/events.csv" 2>/dev/null)
  say "  $(basename $d): $s, anomali_olayi=$a"
done
say "=========================================="
cleanup
