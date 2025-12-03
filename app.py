import re
import tempfile
import os
from io import BytesIO

import streamlit as st
import pandas as pd
import extract_msg
from email.utils import parseaddr

st.set_page_config(page_title="MSG Header Analyzer (Enhanced)", layout="wide")

st.title("MSG Header Analyzer – Erweiterte Version")
st.markdown(
    """
    Lade `.msg`- oder `.eml`-Dateien hoch — die App extrahiert:
    - **DKIM Domain (d=)**
    - **DKIM Selector (s=)**
    - **From-Domain**
    - **Return-Path-Domain**
    - automatische Erkennung, ob vollständige Header vorhanden sind

    Unterstützt: **MSG + EML**
    """
)

uploaded_files = st.file_uploader(
    "Dateien hochladen (.msg oder .eml)", type=["msg", "eml"], accept_multiple_files=True
)

def extract_from_eml(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="ignore")
    except:
        text = raw.decode("latin1", errors="ignore")
    # return header section only (before the first blank line)
    return text.split("\\n\\n", 1)[0]

def extract_from_msg(path: str) -> str | None:
    """
    Versucht verschiedene Wege, um Header aus einer .msg (Outlook) Datei zu extrahieren.
    1) Benutzt extract_msg.Message und prüft mehrere Attribute
    2) Falls nicht vorhanden: versucht, die Rohbytes zu lesen und Header-ähnliche Sektion zu finden
    """
    try:
        m = extract_msg.Message(path)
    except Exception:
        return None

    candidates = []

    # Prüfe mehrere mögliche Attribute / Methoden auf dem Message-Objekt
    attrs_to_check = ("header", "headers", "get_headers", "get_header", "get_email_headers", "headers_string")
    for attr in attrs_to_check:
        if hasattr(m, attr):
            try:
                v = getattr(m, attr)
                h = v() if callable(v) else v
                if isinstance(h, dict):
                    # dict -> in Header-String umwandeln
                    h = "\\n".join(f"{k}: {v}" for k, v in h.items())
                if isinstance(h, bytes):
                    h = h.decode("latin1", "ignore")
                if isinstance(h, str) and h.strip():
                    candidates.append(h)
            except Exception:
                # ignore attribute if call fails
                pass

    # extract_msg has manchmal attribute msgHeaders or msg.header; check auch raw props
    try:
        # some versions expose msg.body or msg.original_message
        if hasattr(m, "raw_msg") and isinstance(m.raw_msg, (bytes, bytearray)):
            decoded = m.raw_msg.decode("latin1", "ignore")
            parts = decoded.split("\\n\\n", 1)
            if parts and parts[0].strip():
                candidates.append(parts[0])
    except Exception:
        pass

    if candidates:
        # nehme das längste candidate, weil das oft vollständiger ist
        candidates = sorted(candidates, key=lambda s: len(s or ""), reverse=True)
        return candidates[0]

    # Fallback: rohdaten aus Datei lesen und Header-Block heuristisch extrahieren
    try:
        with open(path, "rb") as f:
            raw = f.read()
        decoded = raw.decode("latin1", "ignore")
        # Suche nach einem Bereich, der wie Header aussieht: viele ":" Zeichen und Header-Namen
        # Wir nehmen alles bis zur ersten doppelten Zeileumbruch
        parts = re.split(r"\\r?\\n\\r?\\n", decoded, maxsplit=1)
        if parts and parts[0].strip():
            return parts[0]
    except Exception:
        pass

    return None

def parse_headers(headers_text: str) -> dict:
    res = {
        "dkim_domain": "",
        "dkim_selector": "",
        "from_domain": "",
        "returnpath_domain": "",
        "header_present": "yes" if headers_text else "no"
    }

    if not headers_text:
        return res

    # Normalize line endings
    headers_text = headers_text.replace("\\r\\n", "\\n").replace("\\r", "\\n")

    # DKIM: achte auf folded (mehrzeilige) Header — entferne Einrückungen vor dem Parsen
    # Wir extrahieren gesamten DKIM-Signature-Header (inkl. folded lines)
    dkim_match = re.search(r"(?mi)^dkim-signature:\\s*((?:[^\\n]|\\n[ \\t])*)", headers_text)
    if dkim_match:
        dkim = dkim_match.group(1)
        d_match = re.search(r"\\bd=([^;\\s]+)", dkim)
        s_match = re.search(r"\\bs=([^;\\s]+)", dkim)
        if d_match:
            res["dkim_domain"] = d_match.group(1).strip().strip('"')
        if s_match:
            res["dkim_selector"] = s_match.group(1).strip().strip('"')

    # From
    fm = re.search(r"(?mi)^from:\\s*(.*)", headers_text)
    if fm:
        _, addr = parseaddr(fm.group(1))
        if "@" in addr:
            res["from_domain"] = addr.split("@", 1)[1].lower()

    # Return-Path
    rp = re.search(r"(?mi)^return-path:\\s*(.*)", headers_text)
    if rp:
        _, addr = parseaddr(rp.group(1))
        if "@" in addr:
            res["returnpath_domain"] = addr.split("@", 1)[1].lower()

    return res

results = []

if uploaded_files:
    for up in uploaded_files:
        if up.name.lower().endswith(".eml"):
            headers = extract_from_eml(up.read())
        else:
            # schreibe temporär die MSG-Datei (extract_msg erwartet einen Pfad)
            with tempfile.NamedTemporaryFile(delete=False, suffix=".msg") as tmp:
                tmp.write(up.read())
                path = tmp.name
            headers = extract_from_msg(path)
            try:
                os.remove(path)
            except Exception:
                pass

        parsed = parse_headers(headers or "")

        results.append({
            "filename": up.name,
            **parsed
        })

    df = pd.DataFrame(results)
    st.dataframe(df)

    st.download_button(
        "CSV herunterladen",
        df.to_csv(index=False).encode("utf-8"),
        "header_analysis.csv",
        "text/csv"
    )
else:
    st.info("Bitte Dateien hochladen…")
