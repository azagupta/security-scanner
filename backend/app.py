from flask import Flask, request, jsonify, send_from_directory
import threading
from scan_manager import start_scan, get_status, cancel_scan, scan_data

app = Flask(__name__)

# Routes

@app.route("/")
def index():
    website_dir = "/app/website"
    return send_from_directory(website_dir, "security_scanner.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.json.get("url") if request.is_json else None

    if scan_data.get("running"):
        return jsonify({"status": "error", "message": "A scan is already running."}), 409

    if not target:
        return jsonify({"status": "error", "message": "No URL provided."}), 400

    # Run the scan in a background thread so /status polling
    # isn't blocked behind the scan itself.
    thread = threading.Thread(target=start_scan, args=(target,), daemon=True)
    thread.start()

    return jsonify({"status": "started"})


@app.route("/status")
def status():
    return jsonify(get_status())


@app.route("/cancel", methods=["POST"])
def cancel():
    cancel_scan()
    return jsonify({"status": "cancelled"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
