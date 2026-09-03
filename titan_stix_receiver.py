"""Standalone receiver for TITAN Endpoint's STIX Export "Send & Receive" feature.

Run this on the OTHER laptop (the one with OpenCTI) -- it does NOT need TITAN Endpoint
installed. It just listens for the POST that TITAN's own "Send" button already makes
(see GUI/src/TitanEndpoint.App/ViewModels/StixExportViewModel.cs: SendAsync), saves the
received STIX bundle to disk, and prints the address to type into TITAN's "Send" field.

No dependencies beyond the Python standard library. Requires Python 3.

Usage on the receiving laptop:
    python titan_stix_receiver.py

Then, on the SENDING laptop, paste the printed address into TITAN's STIX Export page,
"Send" card, target address field, and click Send.

This only moves the file across the network -- it does NOT import into OpenCTI. After a
bundle arrives here, open it through OpenCTI's own web UI (Data -> Import) as usual.
"""
import http.server
import json
import socket
import socketserver
from datetime import datetime, timezone
from pathlib import Path

# Candidate ports, tried in order until one actually binds. Windows reserves ranges of ports
# for Hyper-V/WSL2 (see `netsh int ipv4 show excludedportrange protocol=tcp`) that a normal,
# non-elevated process cannot bind to at all -- confirmed live on this exact machine, where
# 8766 (TITAN's own default) is one such excluded port. A laptop running Docker Desktop for
# OpenCTI is very likely to have WSL2 enabled too, so the same exclusion could easily recur
# there -- trying several candidates instead of hardcoding one avoids needing the receiving
# side to debug Windows internals just to run this.
CANDIDATE_PORTS = [8899, 8642, 47821, 51999, 8766]
SAVE_DIR = Path(__file__).resolve().parent / "received_stix"
SAVE_DIR.mkdir(exist_ok=True)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        token = self.headers.get("X-Titan-Token", "")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            print(f"[{ts}] {len(body):,} bytes from {self.client_address[0]} -- not valid JSON: {exc}")
            self.send_response(400)
            self.end_headers()
            return

        out_path = SAVE_DIR / f"titan_stix_received_{ts}.json"
        out_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        obj_count = len(parsed.get("objects", [])) if isinstance(parsed, dict) else 0

        print(f"[{ts}] Received {len(body):,} bytes ({obj_count} STIX objects) from {self.client_address[0]}"
              + (f" (token: {token[:8]}...)" if token else " (no token header)"))
        print(f"    Saved to: {out_path}")

        response = json.dumps({"status": "received", "objects": obj_count}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        msg = b"TITAN STIX receiver is running. POST a STIX bundle here.\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(msg)))
        self.end_headers()
        self.wfile.write(msg)

    def log_message(self, format, *args):
        pass  # quiet -- the lines printed in do_POST are clearer than the default access log


def get_lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packet actually sent; just picks the outbound-facing interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def start_server():
    last_error = None
    for port in CANDIDATE_PORTS:
        try:
            httpd = socketserver.ThreadingTCPServer(("0.0.0.0", port), Handler)
            return httpd, port
        except OSError as exc:
            last_error = exc
            print(f"Could not bind port {port} ({exc}) -- trying the next candidate...")
    raise SystemExit(f"None of the candidate ports could be bound. Last error: {last_error}\n"
                      f"Check `netsh int ipv4 show excludedportrange protocol=tcp` for reserved ranges, "
                      f"or edit CANDIDATE_PORTS at the top of this file to add a free one.")


if __name__ == "__main__":
    ip = get_lan_ip()
    httpd, bound_port = start_server()
    print("=" * 64)
    print("TITAN STIX Receiver")
    print("=" * 64)
    print(f"Listening on all interfaces, port {bound_port}.")
    print()
    print("On the SENDING laptop, in TITAN's STIX Export page (\"Send\" card),")
    print("enter this as the target address, then click Send:")
    print()
    print(f"    http://{ip}:{bound_port}/titan/report")
    print()
    print(f"Received bundles are saved into: {SAVE_DIR}")
    print("Both laptops must be on the same network/Wi-Fi for this address to be reachable.")
    print("If Windows Firewall prompts on first run, allow access on Private networks.")
    print("Press Ctrl+C to stop.")
    print("=" * 64)
    with httpd:
        httpd.serve_forever()
