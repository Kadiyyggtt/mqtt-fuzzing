#!/usr/bin/env python3
"""Eksik MQTT paket turlerini elle, standarda uygun olarak uretir."""
import os, hashlib

outdir = os.path.expanduser("~/mqtt-fuzzing/seeds")
os.makedirs(outdir, exist_ok=True)

def remlen(n):
    out = bytearray()
    while True:
        b = n % 128; n //= 128
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def strf(s):
    b = s.encode(); return len(b).to_bytes(2,'big') + b

pkts = {}

body = (1).to_bytes(2,'big') + strf("test/konu") + strf("baska/konu")
pkts["unsubscribe_311_01"] = bytes([0xA2]) + remlen(len(body)) + body

body = (2).to_bytes(2,'big') + strf("abone/test")
pkts["unsubscribe_311_02"] = bytes([0xA2]) + remlen(len(body)) + body

props = bytes([0x11]) + (300).to_bytes(4,'big')
props_field = remlen(len(props)) + props
vh = strf("MQTT") + bytes([5]) + bytes([0x02]) + (60).to_bytes(2,'big') + props_field
pkts["connect_50_props_01"] = bytes([0x10]) + remlen(len(vh + strf("v5istemci"))) + vh + strf("v5istemci")

props = (bytes([0x11]) + (600).to_bytes(4,'big') +
         bytes([0x21]) + (20).to_bytes(2,'big') +
         bytes([0x26]) + strf("anahtar") + strf("deger"))
props_field = remlen(len(props)) + props
vh = strf("MQTT") + bytes([5]) + bytes([0x02]) + (60).to_bytes(2,'big') + props_field
pkts["connect_50_props_02"] = bytes([0x10]) + remlen(len(vh + strf("v5coklu"))) + vh + strf("v5coklu")

props = bytes([0x03]) + strf("text/plain") + bytes([0x26]) + strf("k") + strf("v")
props_field = remlen(len(props)) + props
vh = strf("v5/konu") + props_field
pkts["publish_50_props_01"] = bytes([0x30]) + remlen(len(vh + b"v5 yuk")) + vh + b"v5 yuk"

props = bytes([0x08]) + strf("geri/donus") + bytes([0x09]) + (4).to_bytes(2,'big') + b"\x01\x02\x03\x04"
props_field = remlen(len(props)) + props
vh = strf("v5/qos1") + (5).to_bytes(2,'big') + props_field
pkts["publish_50_props_02"] = bytes([0x32]) + remlen(len(vh + b"yuk")) + vh + b"yuk"

props = bytes([0x0B]) + remlen(10)
props_field = remlen(len(props)) + props
vh = (10).to_bytes(2,'big') + props_field
body = vh + strf("v5/abone/#") + bytes([0x00])
pkts["subscribe_50_props_01"] = bytes([0x82]) + remlen(len(body)) + body

for name, pkt in pkts.items():
    h = hashlib.sha256(pkt).hexdigest()[:12]
    fn = os.path.join(outdir, f"{name}_{h}.bin")
    with open(fn,'wb') as o: o.write(pkt)
    print(f"  {name:26s} {len(pkt):3d} bayt  {h}")
print(f"\n{len(pkts)} paket uretildi.")
