from zapv2 import ZAPv2
import time
import os
import socket
import ipaddress
import requests
from urllib.parse import urlparse

ZAP_URL = os.getenv("ZAP_BASE", "http://zap:8090")

zap = ZAPv2(apikey=None, proxies={
    "http": ZAP_URL,
    "https": ZAP_URL
})

scan_data = {
    "progress": 0,
    "alerts": [],
    "running": False,
    "phase": "idle",
    "error": None
}


def is_safe_target(url):
    """
    Blocks scans against loopback, link-local, private (RFC1918),
    and reserved IP ranges. Prevents the tool being used to hit
    internal infrastructure, cloud metadata endpoints, or itself.
    Resolves the hostname and checks every returned address, not
    just the first, since DNS can return multiple records.
    """
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False, "Could not parse hostname from URL."

        addr_infos = socket.getaddrinfo(hostname, None)
        for info in addr_infos:
            ip = ipaddress.ip_address(info[4][0])
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                return False, f"Target resolves to a disallowed address range ({ip})."

        return True, None

    except socket.gaierror:
        return False, "Could not resolve hostname."
    except ValueError as e:
        return False, f"Invalid address: {e}"


def start_scan(target):
    print(f"DEBUG: Received target URL: '{target}'", flush=True)

    scan_data["running"] = True
    scan_data["progress"] = 0
    scan_data["alerts"] = []
    scan_data["phase"] = "starting"
    scan_data["error"] = None

    if not target:
        print("ERROR: No target URL provided", flush=True)
        scan_data["running"] = False
        scan_data["phase"] = "idle"
        scan_data["error"] = "No target URL provided."
        return

    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    print(f"DEBUG: Cleaned target URL: '{target}'", flush=True)

    safe, reason = is_safe_target(target)
    if not safe:
        print(f"BLOCKED: {reason}", flush=True)
        scan_data["running"] = False
        scan_data["phase"] = "blocked"
        scan_data["error"] = reason
        return

    # Initial HTTP request so ZAP sees the traffic
    try:
        requests.get(target, timeout=10)
    except Exception as e:
        print(f"DEBUG: HTTP request failed: {e}", flush=True)

    # ── Phase 1: Spider (crawl the site) ─────────────────────────────────────
    scan_data["phase"] = "spidering"
    print("DEBUG: Starting spider scan", flush=True)
    spider_id = zap.spider.scan(target)
    time.sleep(2)

    while int(zap.spider.status(spider_id)) < 100:
        spider_progress = int(zap.spider.status(spider_id))
        scan_data["progress"] = int(spider_progress * 0.3)   # 0–30 %
        time.sleep(1)

    scan_data["progress"] = 30
    print("DEBUG: Spider complete", flush=True)

    # ── Phase 2: Passive scan (wait for queue to clear) ───────────────────────
    scan_data["phase"] = "passive_scan"
    while int(zap.pscan.records_to_scan) > 0:
        scan_data["progress"] = 35
        time.sleep(1)

    scan_data["progress"] = 40
    print("DEBUG: Passive scan complete", flush=True)

    # ── Phase 3: Active scan ──────────────────────────────────────────────────
    scan_data["phase"] = "active_scan"
    print("DEBUG: Starting active scan", flush=True)
    active_id = zap.ascan.scan(target)
    time.sleep(2)

    while int(zap.ascan.status(active_id)) < 100:
        active_progress = int(zap.ascan.status(active_id))
        scan_data["progress"] = 40 + int(active_progress * 0.55)  # 40–95 %
        time.sleep(2)

    scan_data["progress"] = 95
    print("DEBUG: Active scan complete", flush=True)

    # ── Collect & filter alerts ───────────────────────────────────────────────
    raw_alerts = zap.core.alerts(baseurl=target)

    risk_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}

    scan_data["alerts"] = sorted(
        [
            {
                "alert":       a.get("alert", "Unknown"),
                "risk":        a.get("risk", "Unknown"),
                "confidence":  a.get("confidence", "Unknown"),
                "url":         a.get("url", ""),
                "description": a.get("description", "No description available."),
                "solution":    a.get("solution", "No solution available."),
                "reference":   a.get("reference", ""),
                "cweid":       a.get("cweid", ""),
                "wascid":      a.get("wascid", ""),
            }
            for a in raw_alerts
            if a.get("risk") != "Informational"
        ],
        key=lambda x: risk_order.get(x["risk"], 99)
    )

    scan_data["progress"] = 100
    scan_data["running"] = False
    scan_data["phase"] = "complete"
    print(f"DEBUG: Scan finished. {len(scan_data['alerts'])} alerts found.", flush=True)


def get_status():
    return scan_data


def cancel_scan():
    try:
        zap.spider.stop_all_scans()
        zap.ascan.stop_all_scans()
    except Exception as e:
        print(f"DEBUG: Cancel error: {e}", flush=True)
    scan_data["running"] = False
    scan_data["phase"] = "cancelled"
    scan_data["progress"] = 0
    scan_data["error"] = None
