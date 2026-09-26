"""
app.py  -  Day 4 of the Phishing Email Analyzer  (the web page)

Start it:
    python app.py
Then your browser opens http://127.0.0.1:5000
Paste a link OR upload a .eml file -> see SAFE / SUSPICIOUS / PHISHING.
"""

import base64
import io
import json
import os
import sys
import tempfile
import threading
import webbrowser
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # draw charts without opening a window
import matplotlib.pyplot as plt
from flask import Flask, render_template, request, redirect, url_for, flash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR, "analyzer"))
from scorer import analyze_email_file, analyze_link   # Day 1 + 2 + 3 together

HISTORY_FILE = os.path.join(BASE_DIR, "data", "history.json")

app = Flask(__name__)
app.secret_key = os.urandom(16)                    # needed for flash messages
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # uploads up to 5 MB only


# ------------------------------------------------------------------ history
def load_history():
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_to_history(result):
    history = load_history()
    history.insert(0, {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "mode": result["mode"],
        "input": result["input"][:80],
        "verdict": result["verdict"],
        "score": result["score"],
    })
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history[:50], f, indent=2)  # keep the last 50 checks


# ------------------------------------------------------------------ chart
def make_chart(category_points):
    """Small bar chart: how many points came from Sender / Links / Content."""
    labels = list(category_points.keys())
    values = list(category_points.values())
    if not any(values):
        return None
    fig, ax = plt.subplots(figsize=(5, 2.2), dpi=110)
    bars = ax.barh(labels, values, color="#c0392b")
    ax.bar_label(bars, padding=3, fontsize=9)
    ax.set_xlabel("Risk points")
    ax.invert_yaxis()
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    fig.tight_layout()
    buffer = io.BytesIO()
    fig.savefig(buffer, format="png")
    plt.close(fig)
    return base64.b64encode(buffer.getvalue()).decode()


# ------------------------------------------------------------------ pages
@app.route("/")
def home():
    return render_template("index.html", history=load_history()[:8])


@app.route("/check-link", methods=["POST"])
def check_link():
    url = request.form.get("url", "").strip()
    if not url:
        flash("Please paste a link first.")
        return redirect(url_for("home"))
    result = analyze_link(url, use_whois=False)
    save_to_history(result)
    return render_template("result.html", r=result, chart=make_chart(result["category_points"]))


@app.route("/check-email", methods=["POST"])
def check_email():
    uploaded = request.files.get("email_file")
    if not uploaded or uploaded.filename == "":
        flash("Please choose a .eml file first.")
        return redirect(url_for("home"))
    if not uploaded.filename.lower().endswith(".eml"):
        flash("Only .eml files are allowed. In Gmail: open the email, click the 3 dots, then 'Download message'.")
        return redirect(url_for("home"))

    # Save to a temporary file, analyze it, then delete it (we never keep emails)
    handle, temp_path = tempfile.mkstemp(suffix=".eml")
    os.close(handle)
    try:
        uploaded.save(temp_path)
        result = analyze_email_file(temp_path, use_whois=False)
    except Exception:
        flash("Sorry, this file could not be read as an email.")
        return redirect(url_for("home"))
    finally:
        os.remove(temp_path)

    result["input"] = os.path.basename(uploaded.filename)
    save_to_history(result)
    return render_template("result.html", r=result, chart=make_chart(result["category_points"]))


@app.route("/clear-history", methods=["POST"])
def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
    return redirect(url_for("home"))


@app.errorhandler(413)
def too_big(_error):
    flash("That file is too big (limit 5 MB).")
    return redirect(url_for("home"))


if __name__ == "__main__":
    address = "http://127.0.0.1:5000"
    print(f"\n  Phishing Email Analyzer is running at {address}")
    print("  Press CTRL + C here to stop it.\n")
    threading.Timer(1.2, lambda: webbrowser.open(address)).start()
    # 127.0.0.1 = only YOUR computer can open it. debug=False = safer.
    app.run(host="127.0.0.1", port=5000, debug=False)
