#!/usr/bin/env python3

import os
import json
import glob
import base64
import requests
import pandas as pd
from dash import Dash, dcc, html, dash_table, Input, Output, State
from flask import Flask
from datetime import datetime
import subprocess

UPLOAD_DIRECTORY = "/usr/local/zeek/pcap_uploads"
RESULTS_DIRECTORY = "/usr/local/zeek/llm_results"
ZEEK_LOG_DIR = "/usr/local/zeek/logs/current/"
ZEEK_BIN = "/usr/local/zeek/bin/zeek"
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
os.makedirs(RESULTS_DIRECTORY, exist_ok=True)

def load_zeek_logs(log_dir=ZEEK_LOG_DIR):
    print("[VERBOSE] Loading Zeek logs...")
    log_data = {}
    non_json_logs = {"loaded_scripts", "crash", "stderr", "stdout"}

    for log_file in glob.glob(f"{log_dir}/*.log"):
        base = os.path.basename(log_file)
        name = base.split(".")[0]
        print(f"[VERBOSE] Processing log file: {log_file}")
        if name in non_json_logs:
            continue

        try:
            with open(log_file, "r") as f:
                first_line = f.readline().strip()
                json.loads(first_line)
                f.seek(0)
                lines = [json.loads(line.strip()) for line in f if line.strip()]
                log_data[name] = pd.DataFrame(lines)
                print(f"[VERBOSE] Parsed {len(lines)} entries from {name}.log")
        except Exception as e:
            print(f"Skipping {log_file}: {e}")
    return log_data

def clean_log_entry(entry):
    for key in list(entry.keys()):
        if isinstance(entry[key], (list, dict)):
            entry[key] = json.dumps(entry[key])
    return entry

def build_generic_prompt(log_type, row):
    print(f"[VERBOSE] Building prompt for log type: {log_type}")
    field_summary = "\n".join([f"- {k}: {v}" for k, v in row.items()])
    return f"""You are assisting in a threat hunting and incident response operation.

This log entry is from Zeek’s {log_type}.log file:

{field_summary}

Tasks:
1. Determine if the activity is suspicious, and explain why.
2. If suspicious, assess the likely intent (e.g., scanning, exfiltration, lateral movement, C2).
3. Recommend an immediate response action (e.g., isolate host, collect memory, escalate).
4. Suggest what log(s) or artifact(s) to review next for pivoting or validation.
5. Assign a threat score between 0 (benign) and 100 (critical).

Keep the assessment concise and professional. Respond in JSON format with fields: 
- assessment
- intent
- action
- pivot
- threat_score
"""

def run_zeek_llm_analysis(prompt, model="mistral"):
    try:
        print("[VERBOSE] Sending prompt to LLM...")
        response = requests.post(
            "http://localhost:11434/api/generate",
            headers={"Content-Type": "application/json"},
            data=json.dumps({
                "model": model,
                "prompt": prompt,
                "stream": False
            })
        )
        output = response.json().get("response", "").strip()
        print(f"[VERBOSE] Received response from LLM: {output[:200]}...")
        result = json.loads(output)
        return result
    except Exception as e:
        print(f"[ERROR] LLM processing failed: {e}")
        return {
            "assessment": f"LLM error: {e}",
            "intent": "N/A",
            "action": "N/A",
            "pivot": "N/A",
            "threat_score": 0
        }

def analyze_logs():
    log_data = load_zeek_logs()
    all_results = []
    max_rows_per_log = 25
    for log_type, df in log_data.items():
        df_sample = df.head(max_rows_per_log)
        for _, row in df_sample.iterrows():
            row_dict = row.dropna().to_dict()
            row_dict = clean_log_entry(row_dict)
            prompt = build_generic_prompt(log_type, row_dict)
            response = run_zeek_llm_analysis(prompt)
            result_row = row_dict.copy()
            result_row.update(response)
            result_row["log_type"] = log_type
            result_row["timestamp"] = datetime.now().isoformat()
            all_results.append(result_row)

    df_llm = pd.DataFrame(all_results)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(RESULTS_DIRECTORY, f"llm_analysis_{timestamp}.csv")
    df_llm.to_csv(output_file, index=False)
    print(f"[VERBOSE] Saved results to disk: {output_file}")
    return df_llm

def process_pcap(file_path):
    try:
        print(f"[VERBOSE] Processing PCAP file with Zeek: {file_path}")
        subprocess.run([ZEEK_BIN, "-r", file_path], cwd=ZEEK_LOG_DIR, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Zeek failed to process {file_path}: {e}")

server = Flask(__name__)
app = Dash(__name__, server=server)
app.title = "Zeek LLM Question Answering"

df_llm = analyze_logs()

app.layout = html.Div([
    html.H1("LLM Threat Hunting & IR with Custom Questions"),
    dcc.Interval(id='interval-refresh', interval=60000, n_intervals=0),
    dcc.Upload(
        id='upload-pcap',
        children=html.Div(['Drag and Drop or ', html.A('Select PCAP Files')]),
        style={'width': '50%', 'height': '60px', 'lineHeight': '60px', 'borderWidth': '1px',
               'borderStyle': 'dashed', 'borderRadius': '5px', 'textAlign': 'center', 'margin': '10px'},
        multiple=True
    ),
    html.Div(id='upload-status'),
    dash_table.DataTable(
        id='llm-table',
        columns=[{"name": i, "id": i} for i in df_llm.columns],
        data=df_llm.to_dict("records"),
        style_table={'overflowX': 'auto', 'maxHeight': '600px', 'overflowY': 'auto'},
        style_cell={'textAlign': 'left', 'fontFamily': 'Arial', 'whiteSpace': 'normal'},
        page_size=25
    ),
    html.Hr(),
    html.H2("Ask a Question to the LLM"),
    dcc.Textarea(
        id='custom-question',
        placeholder='Ask about any patterns or observations in the logs...',
        style={'width': '100%', 'height': 100}
    ),
    html.Button('Submit Question', id='submit-question', n_clicks=0),
    html.Div(id='question-response', style={'whiteSpace': 'pre-wrap', 'marginTop': '20px', 'fontFamily': 'Courier'})
])

@app.callback(
    Output('llm-table', 'data'),
    Input('interval-refresh', 'n_intervals')
)
def refresh_data(n):
    print(f"[VERBOSE] Refreshing log analysis (interval #{n})...")
    df_refreshed = analyze_logs()
    return df_refreshed.to_dict("records")

@app.callback(
    Output('upload-status', 'children'),
    Input('upload-pcap', 'filename'),
    State('upload-pcap', 'contents')
)
def handle_upload(filenames, contents):
    if filenames is None or contents is None:
        return ""
    print(f"[VERBOSE] Handling upload of {len(filenames)} files...")
    for name, content in zip(filenames, contents):
        path = os.path.join(UPLOAD_DIRECTORY, name)
        content_string = content.split(",")[1]
        with open(path, "wb") as f:
            f.write(base64.b64decode(content_string))
        process_pcap(path)
    return f"Uploaded and processed {len(filenames)} PCAP file(s)."

@app.callback(
    Output('question-response', 'children'),
    Input('submit-question', 'n_clicks'),
    State('custom-question', 'value')
)
def answer_custom_question(n_clicks, question):
    if n_clicks == 0 or not question:
        return ""
    print(f"[VERBOSE] Handling custom question submission")
    logs = load_zeek_logs()
    summary = json.dumps({k: df.head(3).to_dict(orient="records") for k, df in logs.items()}, indent=2)
    full_prompt = f"You are analyzing Zeek logs. Here's a sample:\n{summary}\n\nQuestion: {question}"
    response = run_zeek_llm_analysis(full_prompt)
    return response.get("assessment", str(response))

if __name__ == "__main__":
    print("[VERBOSE] Starting Dash app on port 8052")
    app.run(debug=True, host="0.0.0.0", port=8052)
