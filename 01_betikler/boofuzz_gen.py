#!/usr/bin/env python3
"""
Boofuzz MQTT paket ureteci — protokol-farkindalikli mutasyonlari diske yazar.
run_campaign_boofuzz.py bunlari okuyup brokera gonderir.

Boofuzz 0.4.2 API'si: req.mutations(base) mutasyon listesi dondurur,
her biri MutationContext ile render() edilir.
"""
import argparse, os, sys
from boofuzz import Request, Static, Bytes, Word, Byte, String
from boofuzz.mutation_context import MutationContext

def build_connect():
    return Request("connect", children=(
        Static(name="type", default_value=b"\x10"),
        Bytes(name="remlen", default_value=b"\x10", max_len=4),
        Word(name="proto_len", default_value=4, endian=">"),
        String(name="proto_name", default_value="MQTT"),
        Byte(name="proto_level", default_value=4),
        Byte(name="connect_flags", default_value=0x02),
        Word(name="keepalive", default_value=60, endian=">"),
        Word(name="cid_len", default_value=4, endian=">"),
        String(name="client_id", default_value="test"),
    ))

def build_publish():
    # PUBLISH + retain (0x31) — FlashMQ subscriptionstore assertion hedefi
    return Request("publish", children=(
        Static(name="type", default_value=b"\x31"),
        Bytes(name="remlen", default_value=b"\x0c", max_len=4),
        Word(name="topic_len", default_value=4, endian=">"),
        String(name="topic", default_value="test"),
        String(name="msg", default_value="hello"),
    ))

def build_subscribe():
    return Request("subscribe", children=(
        Static(name="type", default_value=b"\x82"),
        Bytes(name="remlen", default_value=b"\x09", max_len=4),
        Word(name="packet_id", default_value=1, endian=">"),
        Word(name="topic_len", default_value=4, endian=">"),
        String(name="topic", default_value="test"),
        Byte(name="qos", default_value=0),
    ))

BUILDERS={"connect":build_connect,"publish":build_publish,"subscribe":build_subscribe}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--out",required=True)
    ap.add_argument("--count",type=int,default=2000)
    ap.add_argument("--packet",choices=list(BUILDERS),default="publish")
    ap.add_argument("--start",type=int,default=0)
    args=ap.parse_args()
    os.makedirs(args.out,exist_ok=True)

    req=BUILDERS[args.packet]()
    base=req.render()
    written=idx=0
    for mutation in req.mutations(base):
        if idx < args.start:
            idx+=1; continue
        try:
            data=req.render(MutationContext(mutation))
        except Exception:
            idx+=1; continue
        with open(os.path.join(args.out,f"boo_{idx:07d}.bin"),"wb") as f:
            f.write(data)
        written+=1; idx+=1
        if written>=args.count: break
    total=req.num_mutations(base) if hasattr(req,'num_mutations') else '?'
    print(f"{written} paket uretildi ({args.packet}), indeks {args.start}..{idx}, toplam mutasyon uzayi: {total}")

if __name__=="__main__":
    main()
