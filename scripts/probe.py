#!/usr/bin/env python3
"""Probe a single host passively (read-only). Usage: python3 probe.py https://host/"""
import ssl, sys, urllib.request, urllib.error, json, time

def probe(url, timeout=15):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (cfoptimizer-hunt passive probe)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(5000)
            ct = r.headers.get("Content-Type", "")
            return f"HTTP {r.status} | {ct} | {len(body)}B | {body[:200]!r}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code} | {e.read(300)[:200]!r}"
    except Exception as e:
        return f"ERR {str(e)[:100]}"

if __name__ == "__main__":
    for u in sys.argv[1:]:
        print(u)
        print("  ", probe(u))
        time.sleep(1)
