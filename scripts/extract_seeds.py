#!/usr/bin/env python3
"""pcap dosyasindan MQTT kontrol paketlerini ayiklar ve .bin dosyalarina yazar."""
import sys, os, struct, hashlib
from collections import defaultdict

MQTT_TYPES = {1:"connect",2:"connack",3:"publish",4:"puback",5:"pubrec",
              6:"pubrel",7:"pubcomp",8:"subscribe",9:"suback",10:"unsubscribe",
              11:"unsuback",12:"pingreq",13:"pingresp",14:"disconnect",15:"auth"}

def read_pcap(path):
    """pcap dosyasini okur, TCP yuklerini dondurur."""
    with open(path,'rb') as f:
        gh = f.read(24)
        if len(gh) < 24: return
        magic = struct.unpack('<I', gh[:4])[0]
        if magic == 0xa1b2c3d4: endian = '<'
        elif magic == 0xd4c3b2a1: endian = '>'
        else:
            print(f"Bilinmeyen pcap magic: {hex(magic)}"); return
        linktype = struct.unpack(endian+'I', gh[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16: break
            _,_,incl,_ = struct.unpack(endian+'IIII', ph)
            data = f.read(incl)
            if len(data) < incl: break
            off = 14 if linktype == 1 else 4          # Ethernet / Linux SLL
            if len(data) < off+20: continue
            ip = data[off:]
            if (ip[0] >> 4) != 4: continue            # sadece IPv4
            ihl = (ip[0] & 0x0F) * 4
            if ip[9] != 6: continue                   # sadece TCP
            tcp = ip[ihl:]
            if len(tcp) < 20: continue
            doff = (tcp[12] >> 4) * 4
            payload = tcp[doff:]
            if payload: yield payload

def split_mqtt(buf):
    """Bir TCP yukunu ardisik MQTT kontrol paketlerine ayirir."""
    i = 0
    while i < len(buf):
        ptype = buf[i] >> 4
        if ptype not in MQTT_TYPES: return
        mult, rl, j = 1, 0, i+1
        while j < len(buf):
            b = buf[j]; rl += (b & 0x7F) * mult; mult *= 128; j += 1
            if not (b & 0x80): break
            if mult > 128**3: return
        else:
            return
        end = j + rl
        if end > len(buf): return
        yield ptype, buf[i:end]
        i = end

def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/mqtt-fuzzing/seeds/capture.pcap")
    outdir = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser("~/mqtt-fuzzing/seeds")
    os.makedirs(outdir, exist_ok=True)
    seen, counts = set(), defaultdict(int)
    for payload in read_pcap(pcap):
        for ptype, pkt in split_mqtt(payload):
            h = hashlib.sha256(pkt).hexdigest()[:12]
            if h in seen: continue
            seen.add(h)
            name = MQTT_TYPES[ptype]
            counts[name] += 1
            fn = os.path.join(outdir, f"{name}_{counts[name]:02d}_{h}.bin")
            with open(fn,'wb') as o: o.write(pkt)
    print(f"\nToplam benzersiz paket: {len(seen)}\n")
    for k in sorted(counts): print(f"  {k:12s} {counts[k]:3d}")

if __name__ == "__main__":
    main()
