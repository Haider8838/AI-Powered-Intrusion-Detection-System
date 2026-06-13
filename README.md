# AI-Powered Intrusion Detection System (IDS)

A fully functional, real-time Network Intrusion Detection System that uses Machine Learning to classify network traffic into attack categories and provides AI-generated threat analysis reports. Runs entirely on your local machine with a live browser dashboard.

---

## What This Project Does

This system monitors network traffic (real or simulated), extracts 31 statistical features from each connection flow, and uses trained ML models to decide whether that traffic is **normal** or an **attack**. When an attack is found, an AI language model (Gemini or Claude) writes a human-readable security report explaining what happened, how severe it is, and what to do about it.

Everything is shown live in a browser dashboard — no cloud service required, no external server.

---

## The 5 Attack Categories Detected

| Category | What It Is | Real-World Example |
|----------|-----------|-------------------|
| **Normal** | Legitimate network traffic | Web browsing, file transfers, email |
| **DoS** | Denial of Service — floods the target to exhaust resources | SYN flood, ICMP Smurf, UDP flood |
| **Probe** | Reconnaissance — scanning the network to find targets | Nmap port scan, OS fingerprinting |
| **R2L** | Remote-to-Local — attacker tries to gain local access from outside | FTP brute force, SSH credential stuffing |
| **U2R** | User-to-Root — attacker already inside tries to get admin/root | Buffer overflow exploit, sudo/rootkit abuse |

---

## Project Files — What Each One Does

### `server.py` — The Web Dashboard Server
The main file you run to use the project. It starts a local web server on port 5000 and serves the full browser dashboard.

**What it contains:**
- Flask web server + Socket.IO for real-time push events to the browser
- All REST API endpoints (`/api/status`, `/api/alerts`, `/api/simulate`, etc.)
- Live traffic capture worker (background thread using Scapy)
- ML model loading, prediction, and training logic
- LLM analysis function (calls Gemini or Claude API)
- The entire dashboard HTML/CSS/JavaScript embedded as a Python string
- Real-time alert feed: every detected connection pushed to the browser instantly

**Run it with:**
```
python server.py
```
Then open `http://localhost:5000`

---

### `ids_app.py` — The Command-Line Version
A standalone command-line script that does everything without a browser. Useful for servers, automation, or headless environments. Auto-installs all missing Python packages on first run.

**What it contains:**
- Same ML training, prediction, and LLM analysis as the server
- Live packet capture using Scapy (`--live` flag)
- Demo scenarios (runs attack simulations and prints results to terminal)
- Cross-platform interface detection (works on Windows, Linux, macOS)
- Saves trained model files (`.joblib`) that `server.py` then loads

**Run it with:**
```bash
python ids_app.py                          # train + run demo
python ids_app.py --live                   # train + capture real traffic
python ids_app.py --live --duration 120    # capture for 2 minutes
python ids_app.py --live-only              # skip demo, just capture
python ids_app.py --demo-only              # skip live capture, just demo
```

---

### `test_attacks.py` — Attack Simulation Test Suite
Sends 12 realistic attack scenarios to the running dashboard. Each scenario has realistic KDD-style feature values. Results appear live in the browser as the test runs.

**What it does:**
- Checks that the server is running before starting
- Sends attack feature data to `/api/simulate` via HTTP POST
- Displays colored terminal output showing detected class, confidence, probability bars, and LLM report preview
- Prints a final summary table showing expected vs detected for every scenario

**Run it with:**
```bash
python test_attacks.py              # run all 12 scenarios
python test_attacks.py --scenario dos   # only DoS attacks
python test_attacks.py --scenario probe # only Probe attacks
python test_attacks.py --open       # run all + open browser tab
python test_attacks.py --delay 0.3  # faster (0.3s between requests)
```

Available `--scenario` values: `all`, `normal`, `dos`, `probe`, `r2l`, `u2r`

---

### `AI_Powered_IDS_Fixed.ipynb` — Jupyter Notebook Version
The original project in notebook form, fixed to run locally (removed Google Colab dependencies, updated API SDK calls). Useful for exploring the data, visualising training, and understanding the ML pipeline step by step.

**Run it with:**
```bash
jupyter notebook "AI_Powered_IDS_Fixed.ipynb"
```
> **Note:** Jupyter requires Windows Long Path support. See setup instructions below.

---

### `requirements.txt` — Python Dependencies
Lists all required packages. Install everything at once with:
```bash
pip install -r requirements.txt
```

---

### `setup_windows.bat` — Windows First-Time Setup
Run this once on Windows to:
- Enable Windows Long Path support (required for Jupyter)
- Install all Python packages from `requirements.txt`
- Remind you to install Npcap (required for live traffic capture)
- Create your `.env` file from the template

```
Double-click setup_windows.bat  (or run as Administrator for Long Path fix)
```

---

### `setup_unix.sh` — Linux/macOS First-Time Setup
Equivalent setup script for Linux and macOS.
```bash
chmod +x setup_unix.sh && ./setup_unix.sh
```

---

### `.env.example` — API Keys Template
Copy this to `.env` and add your API key(s). The system works without any key — it uses built-in fallback threat reports instead.
```bash
copy .env.example .env    # Windows
cp .env.example .env      # Linux/macOS
```
Then edit `.env`:
```
ANTHROPIC_API_KEY=sk-ant-...your-key...
GOOGLE_API_KEY=AIza...your-key...
```

---

### Saved Model Files (`.joblib`)
These are generated automatically the first time you train. Once created, the server loads them instantly on startup without retraining.

| File | Contents |
|------|----------|
| `best_ids_model.joblib` | Trained Random Forest classifier (~62 MB) |
| `scaler.joblib` | StandardScaler fitted on training data |
| `le_dict.joblib` | LabelEncoders for categorical features |
| `le_target.joblib` | LabelEncoder for the target class column |
| `class_names.joblib` | List of class names: Normal, DoS, Probe, R2L, U2R |

---

### `confusion_matrix.png` and `feature_importance.png`
Charts saved automatically after training. Show how accurate the model is and which network features matter most for detection.

---

## The Machine Learning Pipeline

### Training Data
The model trains on a synthetic KDD Cup 1999-style dataset generated in memory — 50,000 connection records with realistic statistical distributions for each attack type. No external dataset file needed.

### The 31 Features Used
Each network connection is described by 31 numerical features:

| Feature | Meaning |
|---------|---------|
| `duration` | Length of connection in seconds |
| `protocol_type` | TCP / UDP / ICMP |
| `service` | Network service (http, ftp, ssh, telnet…) |
| `flag` | TCP connection status (SF=normal, S0=no response, REJ=rejected…) |
| `src_bytes` | Bytes sent from source to destination |
| `dst_bytes` | Bytes sent from destination to source |
| `land` | 1 if source and destination are the same host |
| `wrong_fragment` | Number of wrong fragments |
| `urgent` | Number of urgent packets |
| `hot` | Number of "hot" indicators (privileged commands accessed) |
| `num_failed_logins` | Number of failed login attempts |
| `logged_in` | 1 if user successfully logged in |
| `num_compromised` | Number of compromised conditions |
| `root_shell` | 1 if a root shell was obtained |
| `su_attempted` | 1 if `su root` was attempted |
| `num_root` | Number of root accesses |
| `num_file_creations` | Number of file creation operations |
| `num_shells` | Number of shell prompts |
| `num_access_files` | Number of accesses to control files |
| `num_outbound_cmds` | Outbound commands in FTP session |
| `is_host_login` | 1 if login is to the host |
| `is_guest_login` | 1 if login is guest |
| `count` | Connections to the same host in past 2 seconds |
| `srv_count` | Connections to the same service in past 2 seconds |
| `serror_rate` | % of connections with SYN errors |
| `srv_serror_rate` | % of same-service connections with SYN errors |
| `rerror_rate` | % of connections with REJ errors |
| `srv_rerror_rate` | % of same-service connections with REJ errors |
| `same_srv_rate` | % of connections to the same service |
| `diff_srv_rate` | % of connections to different services |
| `srv_diff_host_rate` | % of same-service connections to different hosts |

### Why These Features Detect Attacks
- **DoS** floods produce very high `count`, `serror_rate` (SYN flood), zero `dst_bytes`, flag `S0`
- **Probe** scans produce high `diff_srv_rate`, `srv_diff_host_rate`, flag `REJ`
- **R2L** attacks show high `num_failed_logins`, `src_bytes` without `logged_in`
- **U2R** exploits produce `root_shell=1`, `su_attempted=1`, high `num_root`

### The Three Trained Models
Three classifiers are trained and the best one (by cross-validation accuracy) is kept:

| Model | Strengths |
|-------|-----------|
| **Random Forest** | Best overall accuracy; handles high-dimensional data well; resistant to overfitting |
| **Decision Tree** | Fast, fully interpretable — you can see every decision rule |
| **Gradient Boosting** | Strong on imbalanced classes; catches subtle attack patterns |

Typically **Random Forest** wins and is saved as `best_ids_model.joblib`.

### Prediction Pipeline
```
Raw network features
    → Categorical encoding (LabelEncoder per column)
    → Feature scaling (StandardScaler — zero mean, unit variance)
    → Model.predict_proba() — returns probability for each of the 5 classes
    → argmax → predicted class + confidence score
```

---

## The LLM Threat Analysis

When an attack is detected, the system sends the connection features and the model's classification to an AI language model, which writes a structured security report:

```
1. THREAT SUMMARY      — 2-sentence description of what happened
2. SEVERITY            — CRITICAL / HIGH / MEDIUM / LOW / NONE
3. ATTACK MECHANISM    — How the attack works technically
4. EVIDENCE            — Which specific features triggered the alert
5. IMMEDIATE ACTIONS   — 3 concrete steps to take right now
6. RECOMMENDATIONS     — 2 longer-term security improvements
```

**Supported LLM providers:**
- **Google Gemini** (`gemini-2.0-flash`) — via `GOOGLE_API_KEY`
- **Anthropic Claude** (`claude-haiku-4-5-20251001`) — via `ANTHROPIC_API_KEY`
- **Built-in fallback** — if no API key is set, a pre-written template report is used. The ML detection still works perfectly.

---

## Live Traffic Capture (How It Works)

When live capture is enabled, Scapy intercepts every packet on the network interface. A `ConnectionTracker` reconstructs full TCP/UDP/ICMP flows from individual packets and computes the 31 KDD features per flow:

```
Network interface (Npcap/libpcap)
    → Scapy packet sniff loop
    → ConnectionTracker groups packets by 5-tuple (src_ip, dst_ip, src_port, dst_port, proto)
    → On FIN/RST or 60-second timeout → emit feature dict
    → predict_traffic() → ML classification
    → Socket.IO push → browser dashboard updates live
```

**Windows requirement:** Npcap must be installed for Scapy to capture packets.
Download from: https://npcap.com

---

## Dashboard Features (Browser UI)

The dashboard at `http://localhost:5000` has 6 sections:

| Tab | What It Shows |
|-----|--------------|
| **Overview** | Live stat cards (Total Alerts, Threats, Normal, Anomaly Rate), SOC terminal log, doughnut chart of alert distribution |
| **Live Feed** | Real-time alert cards as they arrive — colour-coded by severity, showing IP, protocol, service, confidence |
| **Alert History** | Searchable/sortable table of all alerts this session |
| **Analyzer** | Manual form — enter custom feature values and get an instant prediction |
| **Capture** | Start/stop live traffic capture, select network interface, set duration |
| **Settings** | Train models button with live progress bar, API key input for LLM providers |

---

## Quick Start

### Windows
```powershell
# 1. Install Npcap from https://npcap.com (required for live capture)

# 2. Install Python packages
pip install -r requirements.txt

# 3. (Optional) Add API keys
copy .env.example .env
notepad .env

# 4. Start the dashboard
python server.py

# 5. Open browser → http://localhost:5000
#    Go to Settings tab → click "Train Models"

# 6. Run attack simulations (separate terminal)
python test_attacks.py
```

### Linux / macOS
```bash
# 1. Install libpcap
sudo apt install libpcap-dev   # Debian/Ubuntu
brew install libpcap           # macOS

# 2. Install Python packages
pip install -r requirements.txt

# 3. (Optional) Add API keys
cp .env.example .env && nano .env

# 4. Start the dashboard (sudo needed for live capture)
sudo python server.py

# 5. Open browser → http://localhost:5000

# 6. Run attack simulations
python test_attacks.py
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard HTML |
| GET | `/api/status` | Server health, model state, LLM state, counters |
| GET | `/api/interfaces` | Available network interfaces |
| GET | `/api/alerts` | All alerts this session (JSON array) |
| POST | `/api/predict` | Classify a single traffic feature dict |
| POST | `/api/simulate` | Inject a test attack — classifies, pushes to dashboard |
| POST | `/api/set_keys` | Set API keys at runtime without restarting |
| POST | `/api/clear_alerts` | Reset all alerts and counters |

### Example: POST `/api/simulate`
```json
{
  "label": "My test",
  "traffic": {
    "duration": 0.0,
    "protocol_type": "tcp",
    "service": "http",
    "flag": "S0",
    "src_bytes": 0,
    "dst_bytes": 0,
    "count": 511,
    "serror_rate": 1.0,
    ...
  }
}
```

---

## Socket.IO Events

The browser dashboard subscribes to these real-time events:

| Event | Direction | Payload |
|-------|-----------|---------|
| `new_alert` | Server → Browser | Full alert object (class, confidence, IPs, report…) |
| `stats_update` | Server → Browser | `{ total, counts: {Normal:N, DoS:N, ...} }` |
| `capture_status` | Server → Browser | `{ capturing: bool, message: string }` |
| `train_progress` | Server → Browser | `{ percent: 0-100, message: string }` |
| `train` | Browser → Server | Start training |
| `start_capture` | Browser → Server | `{ interface, duration }` |
| `stop_capture` | Browser → Server | Stop live capture |

---

## Troubleshooting

**Model shows "not trained" on startup**
The `.joblib` files don't exist yet. Go to `http://localhost:5000` → Settings tab → click **Train Models**. Takes about 30–60 seconds.

**`eventlet` / threading errors**
Make sure you are running `server.py` directly with `python server.py`. Do not use `flask run`.

**Scapy / Npcap error on Windows**
Install Npcap from https://npcap.com with "WinPcap API compatibility mode" checked.

**Live capture shows no traffic**
Run the terminal as Administrator on Windows. On Linux/macOS, use `sudo python server.py`.

**LLM shows "checking…" or is disabled**
Either no API key is set (fine — fallback reports are used) or the key is invalid. Add/update keys in the Settings tab or in your `.env` file.

**UnicodeEncodeError on Windows terminal**
Run: `$env:PYTHONIOENCODING="utf-8"` in PowerShell before starting the server.

**`test_attacks.py` says model not trained**
Train the model in the dashboard first (Settings → Train Models), then rerun `test_attacks.py`.
