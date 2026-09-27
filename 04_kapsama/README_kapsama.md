# Seed-corpus baseline coverage (Table 10)

Measured on 2026-09-27 with gcovr 7.2 / GCC 14.2.0 on the Raspberry Pi 3B+.
Each broker was cloned from the same commit used in the campaigns
(Mosquitto 99fa50f / v2.1.2, NanoMQ 926179e / 0.25.6, FlashMQ c371f4e / v1.27.1),
built with `--coverage -O0 -g`, started once, sent the 39 unmutated client seeds
(a valid MQTT 3.1.1 CONNECT precedes every non-CONNECT seed, as in verify_seeds.py),
and stopped with SIGTERM. Script: `01_betikler/kapsam_olc.sh`.

Denominator: only the broker's own source files. Excluded: helper programs
(apps/, client/, nanomq_cli/), test code, build directories, CMake-generated
files and system headers. The NanoMQ denominator includes the NNG library
sources that ship inside the NanoMQ tree. Exact commands: `*_gcovr_cmd.txt`.

| Broker | Lines | Functions | Branches |
|---|---|---|---|
| Mosquitto v2.1.2 | 22.5% (3596/15969) | 41.2% (331/803) | 13.7% (1834/13345) |
| NanoMQ 0.25.6 | 11.1% (6837/61401) | 15.6% (731/4697) | 8.2% (2267/27613) |
| FlashMQ v1.27.1 | 35.5% (4350/12257) | 53.0% (662/1248) | 16.7% (3171/18936) |

gcovr reported "negative hit" warnings for a few flex/bison-generated files
(gcov bug 68080); they were processed with `--gcov-ignore-parse-errors`.
Files: `<broker>_gcovr.json` (machine-readable), `<broker>_gcovr.txt` (per-file),
`<broker>_ozet.txt` (summary as printed), `<broker>_gcovr_html/` (browsable report).
