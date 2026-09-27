#!/bin/bash
# ============================================================
# BOOFUZZ Zincirleme Kampanya — 3 broker x DURATION saat
# venv gerektirir (boofuzz). Radamsa harness'i ile ayni oracle/cikti.
# ============================================================
set -u
ROOT=~/mqtt-fuzzing
cd "$ROOT" || exit 1

# venv aktive et (boofuzz icin sart)
source "$ROOT/venv/bin/activate"

DURATION=${1:-18000}

MOSQ_ASAN="./builds/mosquitto-asan/src/mosquitto -p 1883"
NANO_ASAN="./builds/nanomq-asan/build/nanomq/nanomq start --url nmq-tcp://0.0.0.0:1883"
FLASH_ASAN="./builds/flashmq-asan/build/flashmq --config-file ./scripts/flashmq.conf"

LOG="$ROOT/logs/orchestrator_boofuzz.log"
say(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG"; }
cleanup(){ pkill -f mosquitto 2>/dev/null; pkill -f nanomq 2>/dev/null; pkill -f flashmq 2>/dev/null; sleep 3; }

run_bf(){
  local broker=$1 cmd=$2 outdir=$3
  say "BASLIYOR: boofuzz x $broker (sure=${DURATION}s) -> $outdir"
  cleanup
  python3 scripts/run_campaign_boofuzz.py \
     --broker "$broker" --broker-cmd "$cmd" \
     --duration "$DURATION" --outdir "$outdir" --asan \
     >> "$outdir.log" 2>&1
  say "BITTI:    boofuzz x $broker -> $(grep -o 'sent=[0-9]*' $outdir/events.csv | tail -1)"
  tar czf "$outdir.tar.gz" -C "$ROOT/runs" "$(basename $outdir)" 2>/dev/null
  say "YEDEK:    $outdir.tar.gz"
}

say "========== BOOFUZZ ZINCIRI BASLADI (${DURATION}s/kampanya) =========="
run_bf mosquitto "$MOSQ_ASAN"  "runs/boofuzz_mosquitto"
run_bf nanomq    "$NANO_ASAN"  "runs/boofuzz_nanomq"
run_bf flashmq   "$FLASH_ASAN" "runs/boofuzz_flashmq"
say "========== TUM BOOFUZZ KAMPANYALARI BITTI =========="
for d in runs/boofuzz_*/; do
  s=$(grep -o 'sent=[0-9]*' "$d/events.csv" 2>/dev/null | tail -1)
  a=$(grep -c -E 'O1_CRASH|O2_ASAN|O3_HANG' "$d/events.csv" 2>/dev/null)
  say "  $(basename $d): $s, anomali_olayi=$a"
done
cleanup
