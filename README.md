# MQTT Broker Fuzzing on Raspberry Pi 3B+ — Replication Package

Replication data for the study *"Gömülü donanımda MQTT brokerlarının fuzzing ile
dayanıklılık ve kaynak kullanımı eğilimlerinin incelenmesi"* (Investigation of
resilience and resource usage trends of MQTT brokers on embedded hardware
through fuzzing).

**Author:** Abdulkadir Yiğit — ORCID 0009-0000-7699-9090
İnönü University, Institute of Science, Cyber Security

**Archived version (DOI):** https://doi.org/10.5281/zenodo.22845163 (concept DOI, resolves to the latest version; v2 = this repository at tag `v2.0`)
**Build logs** of the ASan binaries and the fuzzing tools are in `05_ortam/derleme_loglari/`.

---

## Contents

| Folder | Description |
|---|---|
| `01_betikler/` | Fuzzing harnesses (Python), orchestration scripts (Bash), seed tools, `flashmq.conf` used in the campaigns |
| `02_tohumlar/` | Seed corpus: 39 client-direction packets (used) + 12 server-direction packets (prepared for the O4 oracle, **not used** in the campaigns) |
| `03_kampanya_kayitlari/` | Six campaign folders (3 Radamsa + 3 Boofuzz): `events.csv`, `resources.csv`, `manifest.json`, `harness.log`, and `broker_stdout.log` truncated to the first and last 2000 lines |
| `03_kampanya_kayitlari/parmak_izi/` | Crash fingerprint evidence: count and sample lines of the `subscriptionstore.cpp:993` assertion from the full FlashMQ Boofuzz log |
| `04_kapsama/` | Seed-corpus coverage measured with gcovr on coverage builds of the same commits as the campaigns; per broker: gcovr JSON, text summary, HTML report and the exact gcovr command |
| `05_ortam/` | Environment record: kernel, OS, CPU, memory, compiler and tool versions |
| `SHA256SUMS.txt` | SHA-256 checksums of every file (`sha256sum -c SHA256SUMS.txt`) |

---

## Experimental summary

| Item | Value |
|---|---|
| Platform | Raspberry Pi 3 Model B+, BCM2837B0, 4 × Cortex-A53 @ 1.4 GHz, 1 GB RAM (892 MB available to the OS) |
| OS / kernel | Debian 13 (trixie) aarch64 / 6.12.107+deb13-arm64 (48-bit VA; required for AddressSanitizer) |
| Brokers | Eclipse Mosquitto v2.1.2 (99fa50f), NanoMQ 0.25.6 (926179e), FlashMQ v1.27.1 (c371f4e) |
| Build used in campaigns | GCC 14.2.0, `-fsanitize=address -fno-omit-frame-pointer -g -O1`, Debug (assertions enabled) |
| Tools | Radamsa 0.8a, Boofuzz 0.4.2 |
| Sessions | 6 independent sessions, 5 hours each (30 h total), one run per configuration |
| Test inputs | 10,621,437 mutated test inputs (harness counter `n`; the fixed CONNECT preceding each input is not counted) |
| Oracles applied | O1 process termination, O2 AddressSanitizer report, O3 unresponsiveness (O4 protocol violation was designed but not applied) |
| Finding | Reachable assertion (CWE-617) in `SubscriptionStore::setRetainedMessage()`, `subscriptionstore.cpp:993`, FlashMQ v1.27.1 assertion-enabled build; 2,137 O1 events |

### Per-session results

| Session | Test inputs | O1 events | Peak RSS (kB) |
|---|---|---|---|
| radamsa_mosquitto | 1,333,442 | 0 | 374,496 |
| radamsa_nanomq | 1,306,065 | 0 | 425,252 |
| radamsa_flashmq | 1,283,989 | 11 | 589,552 |
| boofuzz_mosquitto | 2,502,572 | 0 | 396,812 |
| boofuzz_nanomq | 2,499,837 | 0 | 466,032 |
| boofuzz_flashmq | 1,695,532 | 2,126 | 551,840 |

---

## Notes on the data

- Counts are harness-side counters of mutated application-layer inputs, not frames at the network interface. Each input is preceded by a fixed CONNECT on a fresh TCP connection; neither harness waits for CONNACK. No packet capture was performed.
- `resources.csv` is sampled every ~5 s by a monitor independent of the harness loop. `cpu_pct` is the cumulative average over the process lifetime; for FlashMQ it therefore covers only the period since the last restart. Rows with empty fields are samples taken while the broker process was down.
- Idle baselines were not measured. Resource values come from ASan-instrumented binaries and do not reflect a release build.
- Mosquitto and NanoMQ ran with default configuration except TLS/WebSocket disabled. FlashMQ requires a configuration file; the minimal file in `01_betikler/flashmq.conf` enables `allow_anonymous true`. FlashMQ's stock default rejects anonymous clients; the defect was observed only in the anonymous-enabled configuration.
- Coverage (`04_kapsama/`) is the baseline reached by the 39 unmutated client seeds on `--coverage -O0 -g` builds of the same commits as above, measured with gcovr; the denominator is restricted to each broker's own source files (helper programs, tests, build-system files excluded). It is not the coverage reached by the campaigns.
- Coverage-guided fuzzing was not applied: the brokers read from a network socket and the desocketing preload libraries tried did not work reliably on aarch64.
- Results are from a single run per configuration and should be read descriptively.

## Licence

- Code (`01_betikler/`): MIT Licence
- Data and documentation: Creative Commons Attribution 4.0 (CC BY 4.0)

## Responsible disclosure

The CWE-617 finding in FlashMQ v1.27.1 was reported to the maintainer on 19 September 2026, before public release of this dataset.
