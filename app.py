# app.py
import os
import re
import json
import hashlib
import datetime
from flask import Flask, request, render_template, redirect, url_for, send_file
from werkzeug.utils import secure_filename
from pathlib import Path
from bs4 import BeautifulSoup
import tldextract
import requests

# optional libs for parsing
from PyPDF2 import PdfReader
import docx
import email
from email import policy
from email.parser import BytesParser

# load .env if exists
from dotenv import load_dotenv
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")  # optional

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
ALLOWED_EXT = set([
    ".pdf", ".docx", ".doc", ".txt", ".eml", ".html", ".htm"
])

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- helpers ---
URL_RE = re.compile(
    r'((?:http|https)://[^\s"\'<>]+)', re.IGNORECASE
)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()

def file_sha256(path):
    with open(path, "rb") as f:
        return sha256_bytes(f.read())

def extract_urls_from_text(text):
    if not text:
        return [], []
    urls = URL_RE.findall(text)
    # also find naked domains e.g. example.com (simple)
    doms = set()
    for candidate in re.findall(r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', text):
        # filter some false positives
        if candidate.count('.') >= 1:
            doms.add(candidate)
    return list(set(urls)), list(doms)

def extract_emails_from_text(text):
    return re.findall(r'[\w\.-]+@[\w\.-]+', text)

def extract_ips_from_text(text):
    return IP_RE.findall(text)

def extract_text_from_pdf(path):
    try:
        r = PdfReader(path)
        out = []
        for p in r.pages:
            try:
                out.append(p.extract_text() or "")
            except Exception:
                continue
        return "\n".join(out)
    except Exception as e:
        return ""

def extract_text_from_docx(path):
    try:
        doc = docx.Document(path)
        return "\n".join([p.text for p in doc.paragraphs])
    except Exception:
        return ""

def extract_from_eml(path):
    """
    Returns the combined textual parts of the EML (subject/from/body) for generic text extraction.
    """
    try:
        with open(path, "rb") as f:
            msg = BytesParser(policy=policy.default).parsebytes(f.read())
        parts = []
        subj = msg.get("subject", "")
        frm = msg.get("from", "")
        parts.append(subj or "")
        parts.append(str(frm) or "")
        # body
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    parts.append(part.get_content() or "")
                elif ctype == "text/html":
                    # get text from html too
                    html = part.get_content() or ""
                    try:
                        soup = BeautifulSoup(html, "html.parser")
                        parts.append(soup.get_text())
                    except:
                        parts.append(html)
        else:
            # single part
            c = msg.get_content()
            if msg.get_content_type() == "text/html":
                try:
                    soup = BeautifulSoup(c, "html.parser")
                    parts.append(soup.get_text())
                except:
                    parts.append(c or "")
            else:
                parts.append(c or "")
        return "\n".join(parts)
    except Exception:
        return ""

# --- new: EML metadata parsing (Received headers, IPs, origin) ---
RECEIVED_HEADER_RE = re.compile(r'(?im)^received:\s*(.+?)(?=\n[A-Z0-9-]+:|\Z)', re.DOTALL)
IP_IN_HEADER_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def extract_eml_metadata(path):
    """
    Parse .eml headers to extract:
      - from_addr, subject
      - list of Received headers (as they appear, top-to-bottom)
      - list of IPs found in each Received header
      - probable_originating_ip (bottom-most Received header IP if exists)
    Returns dict with keys: from, subject, received (list), received_ips (list of lists), origin_ip
    """
    meta = {"from": None, "subject": None, "received": [], "received_ips": [], "origin_ip": None}
    try:
        with open(path, "rb") as f:
            raw = f.read()
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        meta['subject'] = msg.get('subject', '')
        meta['from'] = msg.get('from', '')

        # Compose headers string (preserve order)
        headers_lines = []
        for name, value in msg.items():
            # value may include folded lines, so keep as-is
            headers_lines.append(f"{name}: {value}")
        headers_str = "\n".join(headers_lines) + "\n"

        # Find Received headers with a relatively robust regex (multiline)
        recs = RECEIVED_HEADER_RE.findall(headers_str)
        # Normalize
        recs_clean = [r.strip().replace('\n',' ').replace('\r',' ') for r in recs]
        meta['received'] = recs_clean

        # Extract IPs per Received header
        all_ips = []
        for r in recs_clean:
            ips = IP_IN_HEADER_RE.findall(r)
            # basic validation: filter octets >255
            ips = [ip for ip in ips if all(0 <= int(o) <= 255 for o in ip.split('.'))]
            all_ips.append(ips)
        meta['received_ips'] = all_ips

        # Probable originating IP: bottom-most Received header that contains an IP
        origin_ip = None
        # Received headers are typically listed newest-first in the header block,
        # but as saved in file the first Received is oldest or newest depending on client.
        # We'll search from bottom to top for the first valid IP found.
        for ip_list in reversed(all_ips):
            if ip_list:
                # choose last IP in that header (commonly the connecting client IP)
                origin_ip = ip_list[-1]
                break
        meta['origin_ip'] = origin_ip
    except Exception:
        # if anything goes wrong, return what we have (possibly empty)
        pass
    return meta

def extract_text_generic(path):
    ext = Path(path).suffix.lower()
    if ext == ".pdf":
        return extract_text_from_pdf(path)
    if ext in [".docx", ".doc"]:
        return extract_text_from_docx(path)
    if ext == ".eml":
        return extract_from_eml(path)
    if ext in [".html", ".htm"]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                html = f.read()
                try:
                    soup = BeautifulSoup(html, "html.parser")
                    return soup.get_text()
                except:
                    return html
        except:
            return ""
    # fallback: try read as text
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except:
        return ""

# --- Threat Intel (VirusTotal simple example) ---
def vt_url_check(url):
    if not VT_API_KEY:
        return {"error": "No VT API key set"}
    try:
        # VirusTotal v3: POST /urls with url in body to get id, then GET analysis
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        if resp.status_code == 200:
            id = resp.json().get("data", {}).get("id")
            if id:
                analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers)
                return analysis.json()
        return {"error": f"VT responded {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# --- simple scoring heuristics ---
def score_from_indicators(urls, domains, ips, emails, text, eml_meta=None):
    score = 0
    reasons = []
    if len(urls) == 0 and len(domains) == 0:
        reasons.append("No URLs/domains found")
    # URL existence
    if len(urls) > 0:
        score += 30
        reasons.append(f"{len(urls)} URL(s) found")
    # suspicious words in text
    suspicious_words = ["login", "verify", "account", "bank", "password", "update", "confirm"]
    lw = [w for w in suspicious_words if w in text.lower()]
    if lw:
        score += 15
        reasons.append("Suspicious keywords found: " + ", ".join(lw))
    # many domains
    if len(domains) >= 2:
        score += 10
        reasons.append("Multiple domains present")
    # IP presence
    if len(ips) > 0:
        score += 10
        reasons.append(f"{len(ips)} IP(s) found")
    # short domain (typo-squatting check - naive)
    for d in domains:
        if len(d) < 8:
            score += 5
            reasons.append("Short domain detected: " + d)
    # EML-specific heuristics
    if eml_meta:
        # if origin_ip present, give slight weight (suspicious if IP not private)
        origin = eml_meta.get('origin_ip')
        if origin:
            # private IP ranges check
            if not (origin.startswith("10.") or origin.startswith("192.168.") or origin.startswith("172.")):
                score += 5
                reasons.append("Email origin IP appears public: " + origin)
    # final thresholds
    if score >= 60:
        severity = "Malicious"
    elif score >= 35:
        severity = "High Suspicion"
    elif score >= 15:
        severity = "Suspicious"
    else:
        severity = "Clean/Unknown"
    return {"score": score, "severity": severity, "reasons": reasons}

# --- main route ---
@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    if request.method == "POST":
        f = request.files.get("file")
        if not f:
            return redirect(request.url)
        fname = secure_filename(f.filename)
        ext = Path(fname).suffix.lower()
        if ext not in ALLOWED_EXT:
            return "File type not allowed. Allowed: " + ", ".join(ALLOWED_EXT)
        ts = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        savepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{ts}_{fname}")
        f.save(savepath)

        # extract text
        text = extract_text_generic(savepath)

        # extract indicators
        urls, doms = extract_urls_from_text(text)
        ips = extract_ips_from_text(text)
        emails = extract_emails_from_text(text)

        # if EML, extract metadata (received headers etc.)
        eml_meta = None
        if ext == ".eml":
            try:
                eml_meta = extract_eml_metadata(savepath)
            except Exception:
                eml_meta = None

        # score (pass eml_meta for extra heuristics)
        scoring = score_from_indicators(urls, doms, ips, emails, text, eml_meta=eml_meta)

        # optional VT checks (first URL only to keep simple)
        vt_info = None
        if urls and VT_API_KEY:
            try:
                vt_info = vt_url_check(urls[0])
            except Exception as e:
                vt_info = {"error": str(e)}

        # prepare report
        file_hash = file_sha256(savepath)
        report = {
            "file": fname,
            "saved_as": savepath,
            "sha256": file_hash,
            "uploaded_at_utc": ts,
            "urls": urls,
            "domains": doms,
            "ips": ips,
            "emails": emails,
            "eml_meta": eml_meta,
            "scoring": scoring,
            "vt_info": vt_info
        }
        # sign report (sha256 of report JSON)
        report_json = json.dumps(report, indent=2, sort_keys=True)
        report_hash = hashlib.sha256(report_json.encode()).hexdigest()
        report['report_signed_sha256'] = report_hash

        # save report to reports folder
        rname = f"report_{ts}_{fname}.json"
        rpath = os.path.join(REPORT_FOLDER, rname)
        with open(rpath, "w", encoding="utf-8") as rf:
            rf.write(report_json)

        return render_template("index.html", report=report, rpath=rpath)
    return render_template("index.html", report=None, rpath=None)

@app.route("/download/<path:rp>")
def download(rp):
    # serve saved report file
    if os.path.exists(rp):
        return send_file(rp, as_attachment=True)
    return "Not found", 404

if __name__ == "__main__":
    app.run(debug=True)
