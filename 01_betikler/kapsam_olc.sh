#!/usr/bin/env bash
# kapsam_yeniden.sh — Tablo 10'u doğru sürüm etiketlerinden yeniden ölçer.
#   1) builds/<b>-asan klonundan (aynı commit) builds/<b>-cov klonu çıkarır
#   2) --coverage -O0 -g ile derler
#   3) 39 istemci tohumunu gönderir (verify_seeds.py yordamı), gcovr ile filtreli ölçer
#   4) Her şeyi ~/zenodo_ek/kapsama_yeni/ altına yazar (komutlar dahil)
# Pi 3B+'da 1–2 saat sürebilir. nohup ile başlat, uyuyabilirsin.
set -uo pipefail
ROOT="$HOME/mqtt-fuzzing"; SEEDS="$ROOT/seeds/client"; OUT="$HOME/zenodo_ek/kapsama_yeni"
mkdir -p "$OUT"; exec > >(tee -a "$OUT/kapsam_yeniden.log") 2>&1
echo "=== kapsam_yeniden.sh  $(date -Is) ==="; J=$(nproc)

# --- ek kanıtlar: conf + parmak izi (ucuz, hemen) ---
mkdir -p "$HOME/zenodo_ek/config" "$HOME/zenodo_ek/parmak_izi"
cp -f "$ROOT/scripts/flashmq.conf" "$HOME/zenodo_ek/config/flashmq.conf"
L="$ROOT/runs/boofuzz_flashmq/broker_stdout.log"
{ echo "dosya: $L"; echo "toplam satir: $(wc -l < "$L")"
  echo "subscriptionstore.cpp:993 sayisi: $(grep -c 'subscriptionstore.cpp:993' "$L")"
  echo "Assertion iceren satir sayisi: $(grep -c 'Assertion' "$L")"
  echo "konum dagilimi:"; grep -o 'subscriptionstore.cpp:[0-9]*' "$L" | sort | uniq -c
  echo "farkli Assertion metinleri:"; grep -o "Assertion \`[^']*' failed" "$L" | sort | uniq -c
  echo "ilk 3 ornek:"; grep -m3 'subscriptionstore.cpp:993' "$L"; } > "$HOME/zenodo_ek/parmak_izi/flashmq_boofuzz_assert_ozet.txt"
grep -n 'Assertion' "$L" | head -2126 > "$HOME/zenodo_ek/parmak_izi/flashmq_boofuzz_assert_satirlari.txt"
echo "conf ve parmak izi kaydedildi."

# --- 1883 boş mu? ---
if ss -ltn 2>/dev/null | grep -q ':1883 '; then echo "HATA: 1883 portu dolu, önce çalışan brokerı durdur (ss -ltnp | grep 1883)"; exit 1; fi

# --- broker tanımları ---
declare -A BUILD BIN FILTER EXCL TAG
TAG[mosquitto]=v2.1.2; TAG[nanomq]=0.25.6; TAG[flashmq]=v1.27.1
BUILD[mosquitto]='make -j$J WITH_TLS=no WITH_WEBSOCKETS=no WITH_CJSON=no WITH_DOCS=no WITH_SRV=no CFLAGS="--coverage -O0 -g" LDFLAGS="--coverage"'
BIN[mosquitto]='src/mosquitto -p 1883'
BUILD[nanomq]='cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="--coverage -O0 -g" -DCMAKE_CXX_FLAGS="--coverage -O0 -g" -DCMAKE_EXE_LINKER_FLAGS="--coverage" -DCMAKE_SHARED_LINKER_FLAGS="--coverage" -DNNG_ENABLE_TLS=OFF && cmake --build build -j$J'
BIN[nanomq]='build/nanomq/nanomq start --url nmq-tcp://0.0.0.0:1883'
BUILD[flashmq]='cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="--coverage -O0 -g" -DCMAKE_EXE_LINKER_FLAGS="--coverage" && cmake --build build -j$J'
BIN[flashmq]="build/flashmq --config-file $ROOT/scripts/flashmq.conf"
# payda filtreleri: yalnızca brokerın kendi kaynakları
FILTER[mosquitto]='(src|lib|libcommon|common)/'; EXCL[mosquitto]='(apps|client|plugins|test|www|build)/'
FILTER[nanomq]='(nanomq|nng/src)/';              EXCL[nanomq]='(nanomq_cli|build|tests?|demo)/|CMakeFiles|/Users/'
FILTER[flashmq]='[^/]+\.(cpp|h)$';                EXCL[flashmq]='(build|FlashMQTests|tests?)/|CMakeFiles'

send_seeds() {
python3 - "$SEEDS" <<'PY'
import socket,sys,glob,os,time
conn=bytes.fromhex("101000044d5154540402003c000474657374"); n=0
for p in sorted(glob.glob(os.path.join(sys.argv[1],"*.bin"))):
    d=open(p,"rb").read()
    try:
        s=socket.create_connection(("127.0.0.1",1883),timeout=2); s.settimeout(2)
        if (d[0]>>4)!=1:
            s.sendall(conn)
            try: s.recv(64)
            except socket.timeout: pass
        s.sendall(d)
        try: s.recv(256)
        except socket.timeout: pass
        s.close(); n+=1
    except Exception as e: print("  hata",os.path.basename(p),e)
    time.sleep(0.05)
print(f"  {n} tohum gonderildi")
PY
}

for b in mosquitto nanomq flashmq; do
  echo; echo "################ $b  $(date +%H:%M) ################"
  SRC="$ROOT/builds/$b-asan"; COV="$ROOT/builds/$b-cov"
  if [ ! -d "$COV" ]; then
    git clone -q --shared "$SRC" "$COV" || { echo "HATA: klon"; continue; }
    ( cd "$COV" && git checkout -q "$(git -C "$SRC" rev-parse HEAD)" && git submodule update --init --recursive -q 2>/dev/null )
  fi
  echo "commit: $(git -C "$COV" rev-parse --short HEAD)  (asan: $(git -C "$SRC" rev-parse --short HEAD), etiket ${TAG[$b]})"
  if [ ! -x "$COV/${BIN[$b]%% *}" ]; then
    echo "derleniyor: ${BUILD[$b]}"
    ( cd "$COV" && eval "${BUILD[$b]}" ) > "$OUT/${b}_build.log" 2>&1 || { echo "HATA: derleme başarısız, bk. $OUT/${b}_build.log"; tail -20 "$OUT/${b}_build.log"; continue; }
  fi
  [ -x "$COV/${BIN[$b]%% *}" ] || { echo "HATA: ikili yok: ${BIN[$b]%% *}"; continue; }
  echo "gcno: $(find "$COV" -name '*.gcno' | wc -l)"
  find "$COV" -name '*.gcda' -delete
  ( cd "$COV" && ${BIN[$b]} > "$OUT/${b}_broker.log" 2>&1 ) & sleep 4
  pid=$(pgrep -n -f "${BIN[$b]%% *}") || { echo "HATA: broker başlamadı"; cat "$OUT/${b}_broker.log" | tail; continue; }
  send_seeds; sleep 1; kill -TERM "$pid"; sleep 3; pkill -f "${BIN[$b]%% *}" 2>/dev/null; sleep 1
  gcda=$(find "$COV" -name '*.gcda' | wc -l); echo "gcda: $gcda"
  [ "$gcda" -gt 0 ] || { echo "HATA: gcda yazılmadı"; continue; }
  mkdir -p "$OUT/${b}_gcovr_html"
  CMD="gcovr --root $COV --filter '$COV/${FILTER[$b]}' --exclude '$COV/.*${EXCL[$b]}' --exclude-unreachable-branches --print-summary --json $OUT/${b}_gcovr.json --txt $OUT/${b}_gcovr.txt --html-details $OUT/${b}_gcovr_html/index.html $COV"
  echo "$CMD" > "$OUT/${b}_gcovr_cmd.txt"; echo "KOMUT: $CMD"
  ( cd "$COV" && eval "$CMD" ) 2>&1 | tee "$OUT/${b}_ozet.txt" | tail -6
done

echo; echo "=================== TABLO 10 (yeni) ==================="
for b in mosquitto nanomq flashmq; do echo "-- $b"; grep -E '^(lines|functions|branches):' "$OUT/${b}_ozet.txt" 2>/dev/null || echo "   (ölçüm yok — logu kontrol et)"; done
echo "BITTI $(date -Is). Mac'e: scp -r kadir@192.168.1.103:~/zenodo_ek ~/Desktop/"
