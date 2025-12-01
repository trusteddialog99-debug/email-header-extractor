
import streamlit as st
import extract_msg
import re
import pandas as pd

st.title("Email Header Extractor (.msg)")

uploaded_files = st.file_uploader("Lade mehrere .msg-Dateien hoch", type=["msg"], accept_multiple_files=True)

def extract_header_info(msg_file):
    msg = extract_msg.Message(msg_file)
    headers = msg.header
    # DKIM Domain
    dkim_domain = re.search(r"d=(\S+)", headers)
    dkim_domain = dkim_domain.group(1) if dkim_domain else "Not found"
    # DKIM Selector
    dkim_selector = re.search(r"s=(\S+)", headers)
    dkim_selector = dkim_selector.group(1) if dkim_selector else "Not found"
    # From Domain
    from_domain = re.search(r"From:.*@(\S+)", headers)
    from_domain = from_domain.group(1) if from_domain else "Not found"
    # Return-Path Domain
    return_path = re.search(r"Return-Path:.*@(\S+)", headers)
    return_path = return_path.group(1) if return_path else "Not found"
    return {
        "File": msg_file.name,
        "DKIM Domain": dkim_domain,
        "From Domain": from_domain,
        "DKIM Selector": dkim_selector,
        "Return-Path Domain": return_path
    }

if uploaded_files:
    data = []
    for file in uploaded_files:
        data.append(extract_header_info(file))
    df = pd.DataFrame(data)
    st.write("### Extrahierte Header-Informationen")
    st.dataframe(df)
    # Optional: Download als CSV
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button("Download CSV", csv, "header_info.csv", "text/csv")
