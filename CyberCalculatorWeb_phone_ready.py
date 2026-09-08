from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
import secrets
import socket
import string
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlencode, urlparse, quote

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

PORTS = [
    (20, "TCP", "FTP Data"), (21, "TCP", "FTP Control"), (22, "TCP", "SSH"),
    (23, "TCP", "Telnet"), (25, "TCP", "SMTP"), (53, "TCP/UDP", "DNS"),
    (67, "UDP", "DHCP Server"), (68, "UDP", "DHCP Client"), (80, "TCP", "HTTP"),
    (110, "TCP", "POP3"), (123, "UDP", "NTP"), (143, "TCP", "IMAP"),
    (161, "UDP", "SNMP"), (389, "TCP/UDP", "LDAP"), (443, "TCP", "HTTPS"),
    (445, "TCP", "SMB"), (465, "TCP", "SMTPS"), (587, "TCP", "SMTP Submission"),
    (636, "TCP", "LDAPS"), (993, "TCP", "IMAPS"), (995, "TCP", "POP3S"),
    (3306, "TCP", "MySQL"), (3389, "TCP", "RDP"), (5432, "TCP", "PostgreSQL"),
    (6379, "TCP", "Redis"), (8080, "TCP", "HTTP Alternate"),
]

HTTP_CODES = [
    (100, "Continue"), (101, "Switching Protocols"), (200, "OK"), (201, "Created"),
    (204, "No Content"), (301, "Moved Permanently"), (302, "Found"), (304, "Not Modified"),
    (307, "Temporary Redirect"), (308, "Permanent Redirect"), (400, "Bad Request"),
    (401, "Unauthorized"), (403, "Forbidden"), (404, "Not Found"), (405, "Method Not Allowed"),
    (408, "Request Timeout"), (409, "Conflict"), (413, "Content Too Large"),
    (415, "Unsupported Media Type"), (422, "Unprocessable Content"), (429, "Too Many Requests"),
    (500, "Internal Server Error"), (501, "Not Implemented"), (502, "Bad Gateway"),
    (503, "Service Unavailable"), (504, "Gateway Timeout"),
]


def error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def vlsm_allocate(base: ipaddress.IPv4Network, requirements: list[int]):
    requirements = sorted(requirements, reverse=True)
    current = int(base.network_address)
    base_end = int(base.broadcast_address)
    results = []

    for req in requirements:
        needed = max(req + 2, 4)
        prefix = 32
        while prefix > base.prefixlen and (2 ** (32 - prefix)) < needed:
            prefix -= 1
        if (2 ** (32 - prefix)) < needed or prefix < base.prefixlen:
            raise ValueError("Requirements do not fit inside the base network")
        block = 2 ** (32 - prefix)
        if current % block:
            current += block - (current % block)
        end = current + block - 1
        if end > base_end:
            raise ValueError("Requirements exceed the available address space")
        net = ipaddress.ip_network(f"{ipaddress.IPv4Address(current)}/{prefix}")
        if prefix <= 30:
            first = str(net.network_address + 1)
            last = str(net.broadcast_address - 1)
            usable = net.num_addresses - 2
        else:
            first = str(net.network_address)
            last = str(net.broadcast_address)
            usable = net.num_addresses
        results.append({
            "requested": req, "network": str(net.network_address), "prefix": prefix,
            "mask": str(net.netmask), "broadcast": str(net.broadcast_address),
            "first": first, "last": last, "total": net.num_addresses, "usable": usable,
        })
        current = end + 1
    return results


def main():
    return render_template("index.html")


@app.get("/")
def index():
    return main()


@app.post("/api/execute")
def execute():
    data = request.get_json(silent=True) or {}
    tool = data.get("tool", "")
    op = data.get("op", "")

    try:
        if tool == "ipv4":
            iface = ipaddress.ip_interface(data["value"].strip())
            net = iface.network
            total = net.num_addresses
            if net.version != 4:
                raise ValueError("IPv4 only")
            if net.prefixlen <= 30:
                hosts = list(net.hosts())
                first, last, usable = str(hosts[0]), str(hosts[-1]), total - 2
            else:
                first = last = str(net.network_address)
                usable = total
            wildcard = ipaddress.IPv4Address(int(ipaddress.IPv4Address("255.255.255.255")) ^ int(net.netmask))
            return jsonify(ok=True, result={
                "IP Address": str(iface.ip), "Network": str(net.network_address),
                "Broadcast": str(net.broadcast_address), "Subnet Mask": str(net.netmask),
                "Wildcard Mask": str(wildcard), "CIDR": f"/{net.prefixlen}",
                "Total Addresses": total, "Usable Hosts": usable,
                "First Host": first, "Last Host": last,
                "Address Type": "Private" if iface.ip.is_private else "Public / Global" if iface.ip.is_global else "Special",
                "IP Version": iface.version,
            })

        if tool == "ipv6":
            iface = ipaddress.ip_interface(data["value"].strip())
            net = iface.network
            return jsonify(ok=True, result={
                "IP Address": str(iface.ip), "Network": str(net.network_address),
                "Prefix": f"/{net.prefixlen}", "First Address": str(net.network_address),
                "Last Address": str(net.broadcast_address), "Total Addresses": net.num_addresses,
                "Compressed": iface.ip.compressed, "Expanded": iface.ip.exploded,
            })

        if tool == "subnet":
            net = ipaddress.ip_network(data["network"].strip(), strict=False)
            new_prefix = int(data["prefix"])
            if net.version != 4:
                raise ValueError("IPv4 only")
            if new_prefix <= net.prefixlen or new_prefix > 32:
                raise ValueError("New prefix must be greater than the original prefix and <= 32")
            subs = list(net.subnets(new_prefix=new_prefix))
            result = []
            for s in subs:
                if s.prefixlen <= 30:
                    first, last, usable = str(s.network_address + 1), str(s.broadcast_address - 1), s.num_addresses - 2
                else:
                    first = last = str(s.network_address)
                    usable = s.num_addresses
                result.append({"network": str(s.network_address), "cidr": str(s), "mask": str(s.netmask),
                               "broadcast": str(s.broadcast_address), "first": first, "last": last,
                               "total": s.num_addresses, "usable": usable})
            return jsonify(ok=True, result=result)

        if tool == "vlsm":
            base = ipaddress.ip_network(data["network"].strip(), strict=False)
            if base.version != 4:
                raise ValueError("VLSM supports IPv4 only")
            reqs = [int(x) for x in re.split(r"[,\s]+", data["hosts"].strip()) if x]
            if not reqs or any(x < 1 for x in reqs):
                raise ValueError("Enter positive host requirements")
            return jsonify(ok=True, result=vlsm_allocate(base, reqs))

        if tool == "range":
            ip = ipaddress.ip_address(data["ip"].strip())
            net = ipaddress.ip_network(data["network"].strip(), strict=False)
            return jsonify(ok=True, result={"inside": ip in net, "ip": str(ip), "network": str(net)})

        if tool == "wildcard":
            prefix = int(str(data["prefix"]).replace("/", ""))
            net = ipaddress.ip_network(f"0.0.0.0/{prefix}")
            wildcard = ipaddress.IPv4Address(int(ipaddress.IPv4Address("255.255.255.255")) ^ int(net.netmask))
            return jsonify(ok=True, result={"cidr": f"/{prefix}", "mask": str(net.netmask), "wildcard": str(wildcard)})

        if tool == "bitwise":
            a, b = int(data["a"]), int(data["b"])
            if a < 0 or b < 0:
                raise ValueError("Use non-negative integers")
            bits = max(a.bit_length(), b.bit_length(), 1)
            return jsonify(ok=True, result={
                "A": a, "B": b, "A Binary": format(a, f"0{bits}b"), "B Binary": format(b, f"0{bits}b"),
                "AND": a & b, "OR": a | b, "XOR": a ^ b, "NOT A": ~a, "NOT B": ~b,
                "A << 1": a << 1, "A >> 1": a >> 1, "B << 1": b << 1, "B >> 1": b >> 1,
            })

        if tool == "mac":
            raw = re.sub(r"[^0-9A-Fa-f]", "", data["value"])
            if len(raw) != 12:
                raise ValueError("Enter 12 hexadecimal digits")
            upper = raw.upper()
            return jsonify(ok=True, result={
                "Colon": ":".join(upper[i:i+2] for i in range(0, 12, 2)),
                "Hyphen": "-".join(upper[i:i+2] for i in range(0, 12, 2)),
                "Cisco": ".".join(upper[i:i+4] for i in range(0, 12, 4)),
                "Raw": upper,
                "Unicast": not bool(int(upper[0], 16) & 1),
                "Locally Administered": bool(int(upper[0], 16) & 2),
            })

        if tool == "convert_number":
            base = data["base"]
            value = data["value"].strip().lower().replace("0x", "")
            if base == "decimal": num = int(value, 10)
            elif base == "binary": num = int(value, 2)
            elif base == "hex": num = int(value, 16)
            else: raise ValueError("Unknown base")
            if num < 0: raise ValueError("Positive values only")
            return jsonify(ok=True, result={"Decimal": str(num), "Binary": bin(num)[2:], "Hex": "0x" + hex(num)[2:].upper()})

        if tool == "hash":
            algo = data.get("algorithm", "sha256").lower().replace("-", "")
            if algo not in {"md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512"}:
                raise ValueError("Unsupported algorithm")
            value = data.get("value", "").encode("utf-8")
            return jsonify(ok=True, result={"algorithm": algo, "bytes": len(value), "hash": hashlib.new(algo, value).hexdigest()})

        if tool == "encoding":
            mode = data.get("mode", "base64").lower()
            action = data.get("action", "encode").lower()
            value = data.get("value", "")
            if action == "encode":
                if mode == "base64": out = base64.b64encode(value.encode()).decode()
                elif mode == "hex": out = value.encode().hex().upper()
                elif mode == "url": out = quote(value, safe="")
                else: raise ValueError("Unsupported mode")
            else:
                if mode == "base64": out = base64.b64decode(value, validate=True).decode()
                elif mode == "hex": out = bytes.fromhex(value).decode()
                elif mode == "url": out = unquote(value)
                else: raise ValueError("Unsupported mode")
            return jsonify(ok=True, result=out)

        if tool == "entropy":
            value = data.get("value", "")
            pool = 0
            categories = {
                "lower": bool(re.search(r"[a-z]", value)), "upper": bool(re.search(r"[A-Z]", value)),
                "digits": bool(re.search(r"\d", value)), "symbols": bool(re.search(r"[^A-Za-z0-9]", value)),
            }
            pool = 26 * categories["lower"] + 26 * categories["upper"] + 10 * categories["digits"] + 33 * categories["symbols"]
            bits = len(value) * math.log2(pool) if value and pool else 0
            return jsonify(ok=True, result={"length": len(value), "pool": pool, "entropy_bits": round(bits, 2), "categories": categories})

        if tool == "uuid":
            count = min(max(int(data.get("count", 1)), 1), 50)
            return jsonify(ok=True, result=[str(uuid.uuid4()) for _ in range(count)])

        if tool == "checksum":
            value = data.get("value", "").encode()
            return jsonify(ok=True, result={"MD5": hashlib.md5(value).hexdigest(), "SHA1": hashlib.sha1(value).hexdigest(),
                                             "SHA256": hashlib.sha256(value).hexdigest(), "SHA512": hashlib.sha512(value).hexdigest()})

        if tool == "timestamp":
            mode = data.get("mode", "now")
            if mode == "now":
                dt = datetime.now(timezone.utc)
                ts = int(dt.timestamp())
            elif mode == "from_timestamp":
                ts = int(data["value"]); dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            elif mode == "from_iso":
                raw = data["value"].strip().replace("Z", "+00:00")
                dt = datetime.fromisoformat(raw)
                if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
                ts = int(dt.timestamp())
            else: raise ValueError("Unknown timestamp mode")
            return jsonify(ok=True, result={"Unix": ts, "UTC": dt.astimezone(timezone.utc).isoformat()})

        if tool == "ascii":
            if op == "code_to_char":
                n = int(data["value"]); return jsonify(ok=True, result={"character": chr(n), "code": n})
            text = data.get("value", "")
            return jsonify(ok=True, result={"codes": [ord(c) for c in text]})

        if tool == "regex":
            pattern = data.get("pattern", "")
            text = data.get("value", "")
            matches = [m.group(0) for m in re.finditer(pattern, text)]
            return jsonify(ok=True, result={"count": len(matches), "matches": matches})

        if tool == "json":
            obj = json.loads(data.get("value", ""))
            pretty = json.dumps(obj, indent=2, ensure_ascii=False)
            compact = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
            return jsonify(ok=True, result={"pretty": pretty, "compact": compact})

        if tool == "url":
            parsed = urlparse(data.get("value", ""))
            return jsonify(ok=True, result={
                "scheme": parsed.scheme, "netloc": parsed.netloc, "hostname": parsed.hostname,
                "port": parsed.port, "path": parsed.path, "query": parsed.query, "fragment": parsed.fragment,
                "params": {k: v for k, v in parse_qs(parsed.query).items()},
            })

        if tool == "unit":
            kind = data["kind"]; value = float(data["value"]); from_u = data["from"]; to_u = data["to"]
            factors = {
                "length": {"m": 1, "km": 1000, "cm": 0.01, "mm": 0.001, "ft": 0.3048, "in": 0.0254},
                "data": {"bit": 1, "byte": 8, "kb": 8_000, "kib": 8_192, "mb": 8_000_000, "mib": 8_388_608},
                "time": {"s": 1, "ms": 0.001, "min": 60, "h": 3600, "day": 86400},
            }
            if kind not in factors or from_u not in factors[kind] or to_u not in factors[kind]:
                raise ValueError("Unsupported unit")
            result = value * factors[kind][from_u] / factors[kind][to_u]
            return jsonify(ok=True, result=result)

        if tool == "port_search":
            q = str(data.get("query", "")).lower()
            items = [{"port": p, "proto": proto, "service": svc} for p, proto, svc in PORTS if q in str(p) or q in svc.lower() or q in proto.lower()]
            return jsonify(ok=True, result=items)

        if tool == "http_search":
            q = str(data.get("query", "")).lower()
            items = [{"code": c, "reason": reason} for c, reason in HTTP_CODES if q in str(c) or q in reason.lower()]
            return jsonify(ok=True, result=items)

        if tool == "jwt":
            token = data.get("value", "").strip()
            parts = token.split(".")
            if len(parts) != 3: raise ValueError("JWT must contain three segments")
            def b64json(seg):
                pad = "=" * (-len(seg) % 4)
                return json.loads(base64.urlsafe_b64decode(seg + pad).decode())
            return jsonify(ok=True, result={"header": b64json(parts[0]), "payload": b64json(parts[1]), "signature": parts[2]})

        return error("Unknown tool")
    except Exception as exc:
        return error(str(exc))


@app.post("/api/file-hash")
def file_hash():
    file = request.files.get("file")
    algo = request.form.get("algorithm", "sha256").lower().replace("-", "")
    if not file or not file.filename:
        return error("No file uploaded")
    if algo not in {"md5", "sha1", "sha256", "sha512"}:
        return error("Unsupported algorithm")
    hasher = hashlib.new(algo)
    size = 0
    while True:
        chunk = file.stream.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        hasher.update(chunk)
    return jsonify(ok=True, result={"filename": file.filename, "bytes": size, "algorithm": algo, "hash": hasher.hexdigest()})


# ==========================================
# SERVICE WORKER
# ==========================================

from flask import send_from_directory


@app.get("/sw.js")
def service_worker():
    return send_from_directory(
        app.static_folder,
        "sw.js",
        mimetype="application/javascript"
    )


# ==========================================
# AUTO OPEN BROWSER + PHONE URL
# ==========================================

def get_lan_ip() -> str:
    """Best-effort local LAN IPv4 address for phone access."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packet needs to be sent; connect() selects the local interface.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def open_browser():
    import webbrowser
    webbrowser.open_new("http://127.0.0.1:5000/")


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":
    import threading

    lan_ip = get_lan_ip()

    print("=" * 60)
    print("             CYBER CALCULATOR WEB")
    print("=" * 60)
    print()
    print(f"PC browser : http://127.0.0.1:5000/")
    print(f"PHONE URL  : http://{lan_ip}:5000/")
    print()
    print("IMPORTANT:")
    print("1. Phone and PC must be on the same Wi-Fi.")
    print("2. Windows Firewall must allow TCP port 5000.")
    print("3. Open the PHONE URL on the phone.")
    print()
    print("Server     : 0.0.0.0:5000")
    print("=" * 60)

    threading.Timer(1.2, open_browser).start()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )

