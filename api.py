# api.py
from flask import Flask, request, jsonify
from ftplib import FTP, error_perm, all_errors
import socket
import time
import os

app = Flask(__name__)

# Simple FTP check function (anonymous login + list root)
def check_ftp_host(host_raw, timeout=6):
    """
    host_raw: "ftp.example.com" or "ftp.example.com:21" or "ftp://ftp.example.com/path"
    returns: dict { input, ok, reason, time_ms }
    """
    start = time.time()
    h = host_raw.strip()
    # normalize
    if h.startswith("ftp://"):
        h = h[6:]
    if "/" in h:
        h = h.split("/")[0]
    port = 21
    if ":" in h:
        try:
            parts = h.split(":")
            h = parts[0]
            port = int(parts[1])
        except:
            port = 21

    out = {"input": host_raw, "ok": False, "reason": "", "time_ms": None}
    ftp = FTP()
    ftp.sock = None
    try:
        # socket connect for faster fail
        sock = socket.create_connection((h, port), timeout=timeout)
        sock.close()
    except Exception as e:
        out["reason"] = f"tcp_fail: {str(e)}"
        out["time_ms"] = int((time.time()-start)*1000)
        return out

    try:
        ftp.connect(host=h, port=port, timeout=timeout)
        # try anonymous
        ftp.login(user="anonymous", passwd="anonymous@")
        # try list root
        try:
            files = ftp.nlst('/')  # simple listing; may throw permission errors
            out["ok"] = True
            out["reason"] = "anonymous_list_ok"
            out["sample_count"] = min(len(files), 10)
        except error_perm as ep:
            # some servers forbid nlst on root; still login ok
            out["ok"] = True
            out["reason"] = f"anonymous_login_only: {str(ep)}"
        except Exception as le:
            out["ok"] = True
            out["reason"] = f"login_but_list_failed: {str(le)}"
        ftp.quit()
    except all_errors as e:
        out["ok"] = False
        out["reason"] = f"ftp_err: {str(e)}"
    except Exception as e:
        out["ok"] = False
        out["reason"] = f"other_err: {str(e)}"
    finally:
        out["time_ms"] = int((time.time()-start)*1000)
        try:
            ftp.close()
        except:
            pass
    return out

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    POST JSON: { "links": ["ftp.example.com", "ftp://host:21/path", ...] }
    returns: { results: [ {input, ok, reason, time_ms, ...}, ... ] }
    """
    data = request.get_json(force=True, silent=True) or {}
    links = data.get("links") or []
    if not isinstance(links, list) or len(links) == 0:
        return jsonify({"error":"send JSON {links: [..]}"}), 400

    # limit to avoid abuse
    max_links = int(os.environ.get("MAX_LINKS", "50"))
    links = links[:max_links]

    results = []
    # simple serial scanning (if you want speed, we can use ThreadPool)
    for l in links:
        r = check_ftp_host(l, timeout=6)
        results.append(r)

    return jsonify({"results": results})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
