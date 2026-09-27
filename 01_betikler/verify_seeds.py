#!/usr/bin/env python3
"""Tohum paketlerini mutasyonsuz gonderip brokerin yanitini kaydeder."""
import socket, sys, os, glob, time

HOST, PORT = "127.0.0.1", 1883
TIMEOUT = 2.0

def send_seed(path, with_connect=True):
    """Paketi gonderir. CONNECT olmayan paketler icin once oturum acar."""
    data = open(path,'rb').read()
    ptype = data[0] >> 4
    try:
        s = socket.create_connection((HOST,PORT), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        pre = b""
        if with_connect and ptype not in (1,):
            # Once gecerli bir CONNECT gonder (oturum gerektiren paketler icin)
            conn = bytes.fromhex("101000044d5154540402003c000474657374")
            s.sendall(conn)
            try: pre = s.recv(64)
            except socket.timeout: pre = b""
        s.sendall(data)
        try: resp = s.recv(256)
        except socket.timeout: resp = b""
        s.close()
        return ptype, pre, resp, None
    except Exception as e:
        return ptype, b"", b"", str(e)

def main():
    seeds = sorted(glob.glob(os.path.expanduser("~/mqtt-fuzzing/seeds/client/*.bin")))
    ok = warn = err = 0
    for p in seeds:
        name = os.path.basename(p)
        ptype, pre, resp, exc = send_seed(p)
        if exc:
            print(f"  HATA    {name:45s} {exc}"); err += 1
        elif resp:
            print(f"  YANIT   {name:45s} <- {resp[:12].hex()}"); ok += 1
        else:
            print(f"  SESSIZ  {name:45s} (yanit yok)"); warn += 1
        time.sleep(0.05)
    print(f"\nToplam {len(seeds)} tohum: {ok} yanitli, {warn} sessiz, {err} hata")

if __name__ == "__main__":
    main()
