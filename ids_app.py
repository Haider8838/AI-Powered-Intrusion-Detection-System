"""
AI-Powered Intrusion Detection System (IDS)
============================================
Cross-platform standalone script — Windows / Linux / macOS.

Usage:
  python ids_app.py                     # train + run demo scenarios
  python ids_app.py --live              # train + capture real traffic
  python ids_app.py --live --duration 120 --interface eth0
  python ids_app.py --live --duration 60

API Keys (optional — LLM explanations):
  Set ANTHROPIC_API_KEY or GOOGLE_API_KEY in environment,
  or create a  .env  file in the same directory:
      ANTHROPIC_API_KEY=sk-ant-...
      GOOGLE_API_KEY=AIza...

Requirements:
  pip install -r requirements.txt
  Windows: also install Npcap from https://npcap.com (for live capture)
  Linux:   run with sudo for live capture
"""

# ── Force UTF-8 output on all platforms (handles emoji on Windows) ──────────
import sys, subprocess
import io
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
elif sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def _install(pkg):
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg, '-q'])

REQUIRED = [
    'anthropic', 'scikit-learn', 'pandas', 'numpy',
    'matplotlib', 'seaborn', 'plotly', 'joblib', 'scapy',
]
for pkg in REQUIRED:
    try:
        __import__(pkg.split('[')[0].replace('-', '_'))
    except ImportError:
        print(f"  Installing {pkg}...")
        _install(pkg)

try:
    from google import genai as _genai_test  # noqa
except ImportError:
    print("  Installing google-genai...")
    _install('google-genai')

try:
    from dotenv import load_dotenv  # noqa
except ImportError:
    _install('python-dotenv')

# ── 1. Load .env file (if present) ──────────────────────────────────────────
import os
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
except Exception:
    pass

# ── 2. Imports ───────────────────────────────────────────────────────────────
import argparse
import collections
import json
import platform
import threading
import time
import warnings
from datetime import datetime

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')          # headless-safe backend
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score
)
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings('ignore')

print("✅ All imports successful!")
print("🛡  AI-Powered IDS initialising …")

# ── 3. API Key configuration ─────────────────────────────────────────────────
GOOGLE_API_KEY     = os.getenv('GOOGLE_API_KEY', '')
ANTHROPIC_API_KEY  = os.getenv('ANTHROPIC_API_KEY', '')

GEMINI_LLM_ENABLED     = False
ANTHROPIC_LLM_ENABLED  = False
LLM_ENABLED            = False
gemini_client  = None
anthropic_client = None

# Try Gemini (new google-genai SDK)
if GOOGLE_API_KEY:
    try:
        from google import genai as google_genai
        gemini_client = google_genai.Client(api_key=GOOGLE_API_KEY)
        test_resp = gemini_client.models.generate_content(
            model='gemini-2.0-flash', contents='Reply with: API Connected!')
        print(f"✅ {test_resp.text.strip()}")
        GEMINI_LLM_ENABLED = True
        print("📌 Gemini LLM enabled.")
    except Exception as e:
        print(f"⚠️  Gemini API error: {e}")

# Try Anthropic
if ANTHROPIC_API_KEY and not ANTHROPIC_API_KEY.startswith('sk-ant-your'):
    try:
        import anthropic
        anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        test = anthropic_client.messages.create(
            model='claude-haiku-4-5-20251001',
            max_tokens=50,
            messages=[{'role': 'user', 'content': 'Reply with: API Connected!'}]
        )
        print(f"✅ {test.content[0].text.strip()}")
        ANTHROPIC_LLM_ENABLED = True
        print("📌 Anthropic LLM enabled.")
    except Exception as e:
        print(f"⚠️  Anthropic API error: {e}")

if GEMINI_LLM_ENABLED or ANTHROPIC_LLM_ENABLED:
    LLM_ENABLED = True
    print("✨ LLM functionality enabled.")
else:
    print("🔕 No LLM key found — using fallback mode (ML still works perfectly).")

# ── 4. Generate Synthetic KDD-style Dataset ──────────────────────────────────
print("\n📊 Generating KDD-style training dataset …")
np.random.seed(42)
n = 50000

attack_labels = (
    ['normal.']          * 20000 +
    ['neptune.']         * 10000 +
    ['smurf.']           * 8000  +
    ['satan.']           * 3000  +
    ['ipsweep.']         * 2500  +
    ['portsweep.']       * 2000  +
    ['nmap.']            * 1500  +
    ['back.']            * 1000  +
    ['warezclient.']     * 800   +
    ['guess_passwd.']    * 500   +
    ['buffer_overflow.'] * 400   +
    ['rootkit.']         * 300
)
np.random.shuffle(attack_labels)

df = pd.DataFrame({
    'duration':                   np.random.exponential(5, n),
    'protocol_type':              np.random.choice(['tcp','udp','icmp'], n, p=[0.6,0.2,0.2]),
    'service':                    np.random.choice(['http','ftp','smtp','ssh','telnet','dns','other'], n),
    'flag':                       np.random.choice(['SF','S0','REJ','RSTO','SH'], n, p=[0.6,0.2,0.1,0.06,0.04]),
    'src_bytes':                  np.random.exponential(5000, n),
    'dst_bytes':                  np.random.exponential(3000, n),
    'land':                       np.random.choice([0,1], n, p=[0.99,0.01]),
    'wrong_fragment':             np.random.choice([0,1,2,3], n, p=[0.97,0.01,0.01,0.01]),
    'urgent':                     np.zeros(n, dtype=int),
    'hot':                        np.random.poisson(0.5, n),
    'num_failed_logins':          np.random.choice([0,1,2,3], n, p=[0.95,0.03,0.01,0.01]),
    'logged_in':                  np.random.choice([0,1], n, p=[0.4,0.6]),
    'num_compromised':            np.random.poisson(0.1, n),
    'root_shell':                 np.random.choice([0,1], n, p=[0.99,0.01]),
    'su_attempted':               np.random.choice([0,1], n, p=[0.99,0.01]),
    'num_root':                   np.random.poisson(0.05, n),
    'num_file_creations':         np.random.poisson(0.1, n),
    'num_shells':                 np.zeros(n, dtype=int),
    'num_access_files':           np.zeros(n, dtype=int),
    'num_outbound_cmds':          np.zeros(n, dtype=int),
    'is_host_login':              np.zeros(n, dtype=int),
    'is_guest_login':             np.random.choice([0,1], n, p=[0.95,0.05]),
    'count':                      np.random.randint(1,512,n),
    'srv_count':                  np.random.randint(1,512,n),
    'serror_rate':                np.random.beta(0.5,5,n),
    'srv_serror_rate':            np.random.beta(0.5,5,n),
    'rerror_rate':                np.random.beta(0.5,5,n),
    'srv_rerror_rate':            np.random.beta(0.5,5,n),
    'same_srv_rate':              np.random.beta(5,1,n),
    'diff_srv_rate':              np.random.beta(1,5,n),
    'srv_diff_host_rate':         np.random.beta(1,5,n),
    'dst_host_count':             np.random.randint(1,256,n),
    'dst_host_srv_count':         np.random.randint(1,256,n),
    'dst_host_same_srv_rate':     np.random.beta(5,1,n),
    'dst_host_diff_srv_rate':     np.random.beta(1,5,n),
    'dst_host_same_src_port_rate':np.random.beta(2,3,n),
    'dst_host_srv_diff_host_rate':np.random.beta(1,5,n),
    'dst_host_serror_rate':       np.random.beta(0.5,5,n),
    'dst_host_srv_serror_rate':   np.random.beta(0.5,5,n),
    'dst_host_rerror_rate':       np.random.beta(0.5,5,n),
    'dst_host_srv_rerror_rate':   np.random.beta(0.5,5,n),
    'label':                      attack_labels,
})
print(f"✅ Dataset ready: {df.shape[0]:,} rows × {df.shape[1]} columns")

# ── 5. Preprocessing ─────────────────────────────────────────────────────────
ATTACK_MAP = {
    'normal.':'Normal',
    'back.':'DoS','land.':'DoS','neptune.':'DoS','pod.':'DoS',
    'smurf.':'DoS','teardrop.':'DoS','apache2.':'DoS',
    'udpstorm.':'DoS','processtable.':'DoS','mailbomb.':'DoS',
    'ipsweep.':'Probe','nmap.':'Probe','portsweep.':'Probe',
    'satan.':'Probe','mscan.':'Probe','saint.':'Probe',
    'ftp_write.':'R2L','guess_passwd.':'R2L','imap.':'R2L',
    'multihop.':'R2L','phf.':'R2L','spy.':'R2L','warezclient.':'R2L',
    'warezmaster.':'R2L','sendmail.':'R2L','named.':'R2L',
    'snmpgetattack.':'R2L','snmpguess.':'R2L','xlock.':'R2L',
    'xsnoop.':'R2L','worm.':'R2L',
    'buffer_overflow.':'U2R','loadmodule.':'U2R','perl.':'U2R',
    'rootkit.':'U2R','ps.':'U2R','sqlattack.':'U2R',
    'xterm.':'U2R','httptunnel.':'U2R',
}

def map_label(lbl):
    lbl_dot = lbl if lbl.endswith('.') else lbl + '.'
    return ATTACK_MAP.get(lbl_dot, ATTACK_MAP.get(lbl, 'Other'))

df['attack_category'] = df['label'].apply(map_label)

le_dict = {}
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    df[col + '_enc'] = le.fit_transform(df[col].astype(str))
    le_dict[col] = le

le_target = LabelEncoder()
df['target'] = le_target.fit_transform(df['attack_category'])
class_names = le_target.classes_

FEATURE_COLS = [
    'duration','protocol_type_enc','service_enc','flag_enc',
    'src_bytes','dst_bytes','land','wrong_fragment','urgent','hot',
    'num_failed_logins','logged_in','num_compromised','root_shell',
    'su_attempted','num_root','num_file_creations','num_shells',
    'num_access_files','is_guest_login','count','srv_count',
    'serror_rate','rerror_rate','same_srv_rate','diff_srv_rate',
    'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate',
    'dst_host_serror_rate','dst_host_rerror_rate',
]

X = df[FEATURE_COLS].fillna(0)
y = df['target']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)
print(f"✅ Preprocessing done — train:{X_train.shape[0]:,}  test:{X_test.shape[0]:,}  features:{X_train.shape[1]}")

# ── 6. Train ML Models ────────────────────────────────────────────────────────
print("\n🤖 Training ML models …")
MODELS = {
    'Random Forest': RandomForestClassifier(
        n_estimators=100, max_depth=20, random_state=42, n_jobs=-1),
    'Decision Tree': DecisionTreeClassifier(
        max_depth=15, random_state=42),
    'Gradient Boosting': GradientBoostingClassifier(
        n_estimators=50, learning_rate=0.1, max_depth=5, random_state=42),
}

results = {}
best_model      = None
best_model_name = ''
best_acc        = 0.0

for name, model in MODELS.items():
    print(f"  ⏳ Training {name} …", end=' ', flush=True)
    t0 = time.time()
    model.fit(X_train, y_train)
    elapsed = time.time() - t0
    y_pred  = model.predict(X_test)
    acc     = accuracy_score(y_test, y_pred)
    results[name] = {'model': model, 'accuracy': acc, 'predictions': y_pred, 'time': elapsed}
    if acc > best_acc:
        best_acc        = acc
        best_model      = model
        best_model_name = name
    print(f"acc={acc:.4f}  ({elapsed:.1f}s)")

print(f"\n🏆 Best model: {best_model_name}  accuracy={best_acc:.4f}")

# ── 6a. Save trained artefacts ───────────────────────────────────────────────
OUT_DIR = os.path.dirname(os.path.abspath(__file__))
joblib.dump(best_model, os.path.join(OUT_DIR, 'best_ids_model.joblib'))
joblib.dump(scaler,     os.path.join(OUT_DIR, 'scaler.joblib'))
joblib.dump(le_dict,    os.path.join(OUT_DIR, 'le_dict.joblib'))
joblib.dump(le_target,  os.path.join(OUT_DIR, 'le_target.joblib'))
joblib.dump(class_names,os.path.join(OUT_DIR, 'class_names.joblib'))
print("💾 Model artefacts saved.")

# ── 7. Evaluation ─────────────────────────────────────────────────────────────
print(f"\n📈 Evaluating {best_model_name} …")
y_pred_best = results[best_model_name]['predictions']
print(classification_report(y_test, y_pred_best, target_names=class_names, digits=4))

# Save confusion-matrix plot
cm = confusion_matrix(y_test, y_pred_best)
plt.figure(figsize=(8,6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=class_names, yticklabels=class_names)
plt.title(f'Confusion Matrix – {best_model_name}')
plt.ylabel('True'); plt.xlabel('Predicted')
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, 'confusion_matrix.png'), dpi=120)
plt.close()
print("✅ confusion_matrix.png saved.")

# Feature importance plot
if hasattr(best_model, 'feature_importances_'):
    fi  = pd.Series(best_model.feature_importances_, index=FEATURE_COLS)
    top = fi.nlargest(15).sort_values()
    plt.figure(figsize=(10,6))
    top.plot(kind='barh', color=plt.cm.RdYlGn(np.linspace(0.3,0.9,15)))
    plt.title('Top 15 Feature Importances')
    plt.xlabel('Importance Score')
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, 'feature_importance.png'), dpi=120)
    plt.close()
    print("✅ feature_importance.png saved.")

# ── 8. LLM Threat-Analysis Engine ────────────────────────────────────────────
def get_fallback_analysis(attack_type: str, confidence: float) -> str:
    templates = {
        'DoS':  {'severity':'CRITICAL',
                 'summary':'Denial of Service attack detected. Attacker is flooding the network to exhaust resources.',
                 'actions':['Block source IP immediately','Enable rate limiting on firewall','Notify NOC team']},
        'Probe':{'severity':'MEDIUM',
                 'summary':'Reconnaissance/port scanning detected. Attacker is mapping the network.',
                 'actions':['Log and monitor source IP','Enable port scan detection rules','Review exposed services']},
        'R2L':  {'severity':'HIGH',
                 'summary':'Remote-to-Local attack detected. Unauthorised remote access attempt.',
                 'actions':['Force password reset on affected accounts','Enable MFA','Review authentication logs']},
        'U2R':  {'severity':'CRITICAL',
                 'summary':'Privilege escalation attack detected. Attacker attempting root/admin access.',
                 'actions':['Isolate affected system immediately','Audit sudo/admin logs','Patch privilege escalation vulnerability']},
        'Normal':{'severity':'NONE',
                  'summary':'Normal traffic detected. No malicious activity identified.',
                  'actions':['Continue monitoring','Log for baseline analysis','No action required']},
    }
    t = templates.get(attack_type, templates['Probe'])
    return (f"THREAT SUMMARY: {t['summary']}\n"
            f"SEVERITY LEVEL: {t['severity']}\n"
            f"MODEL CONFIDENCE: {confidence:.1%}\n\n"
            f"IMMEDIATE ACTIONS:\n"
            f"  1. {t['actions'][0]}\n"
            f"  2. {t['actions'][1]}\n"
            f"  3. {t['actions'][2]}\n")


def get_llm_threat_analysis(traffic_data: dict, predicted_class: str, confidence: float) -> str:
    prompt = f"""You are a cybersecurity expert analysing network intrusion alerts.

A machine learning model flagged the following network connection:

TRAFFIC FEATURES:
- Protocol: {traffic_data.get('protocol_type','unknown')}
- Service:  {traffic_data.get('service','unknown')}
- Duration: {traffic_data.get('duration',0):.2f} seconds
- Source bytes: {traffic_data.get('src_bytes',0):,.0f}
- Destination bytes: {traffic_data.get('dst_bytes',0):,.0f}
- Failed logins: {traffic_data.get('num_failed_logins',0)}
- Root shell: {'Yes' if traffic_data.get('root_shell',0) else 'No'}
- Connection count: {traffic_data.get('count',0)}
- Error rate: {traffic_data.get('serror_rate',0):.2f}

ML DETECTION RESULT:
- Predicted Attack Type: {predicted_class}
- Model Confidence: {confidence:.1%}

Provide a structured security report:
1. THREAT SUMMARY (2 sentences)
2. SEVERITY LEVEL: [CRITICAL/HIGH/MEDIUM/LOW/NONE]
3. ATTACK MECHANISM (2–3 sentences)
4. EVIDENCE (bullet points)
5. IMMEDIATE ACTIONS (3 steps)
6. LONG-TERM RECOMMENDATIONS (2 points)

Keep it professional and concise."""

    if GEMINI_LLM_ENABLED and gemini_client:
        try:
            from google import genai as google_genai  # noqa (already imported above)
            resp = gemini_client.models.generate_content(
                model='gemini-2.0-flash', contents=prompt)
            return resp.text
        except Exception as e:
            return f"[Gemini error: {e}]\n" + get_fallback_analysis(predicted_class, confidence)

    if ANTHROPIC_LLM_ENABLED and anthropic_client:
        try:
            resp = anthropic_client.messages.create(
                model='claude-haiku-4-5-20251001',
                max_tokens=600,
                messages=[{'role':'user','content':prompt}]
            )
            return resp.content[0].text
        except Exception as e:
            return f"[Anthropic error: {e}]\n" + get_fallback_analysis(predicted_class, confidence)

    return get_fallback_analysis(predicted_class, confidence)


# ── 9. Single-flow predictor ──────────────────────────────────────────────────
def predict_traffic(traffic_dict: dict) -> dict:
    enc = traffic_dict.copy()
    for col in ['protocol_type', 'service', 'flag']:
        if col in le_dict:
            try:
                enc[col+'_enc'] = le_dict[col].transform([str(traffic_dict.get(col,'tcp'))])[0]
            except ValueError:
                enc[col+'_enc'] = 0

    fvec        = np.array([[enc.get(f,0) for f in FEATURE_COLS]])
    fvec_scaled = scaler.transform(fvec)
    pred_idx    = best_model.predict(fvec_scaled)[0]
    probas      = best_model.predict_proba(fvec_scaled)[0]
    confidence  = probas[pred_idx]
    pred_class  = class_names[pred_idx]
    report      = get_llm_threat_analysis(traffic_dict, pred_class, confidence)

    return {
        'predicted_class':     pred_class,
        'confidence':          confidence,
        'all_probabilities':   dict(zip(class_names, probas)),
        'threat_report':       report,
    }


# ── 10. Demo Scenarios ────────────────────────────────────────────────────────
def run_demo_scenarios():
    TEST_SCENARIOS = [
        {'name':'🟢 Normal Web Browsing',
         'traffic':{'duration':0.5,'protocol_type':'tcp','service':'http','flag':'SF',
                    'src_bytes':215,'dst_bytes':45076,'land':0,'wrong_fragment':0,
                    'urgent':0,'hot':0,'num_failed_logins':0,'logged_in':1,
                    'num_compromised':0,'root_shell':0,'su_attempted':0,'num_root':0,
                    'num_file_creations':0,'num_shells':0,'num_access_files':0,
                    'is_guest_login':0,'count':9,'srv_count':9,'serror_rate':0.0,
                    'rerror_rate':0.0,'same_srv_rate':1.0,'diff_srv_rate':0.0,
                    'dst_host_count':9,'dst_host_srv_count':9,
                    'dst_host_same_srv_rate':1.0,'dst_host_serror_rate':0.0,
                    'dst_host_rerror_rate':0.0}},
        {'name':'🔴 DoS Attack (Neptune SYN Flood)',
         'traffic':{'duration':0,'protocol_type':'tcp','service':'http','flag':'S0',
                    'src_bytes':0,'dst_bytes':0,'land':0,'wrong_fragment':0,
                    'urgent':0,'hot':0,'num_failed_logins':0,'logged_in':0,
                    'num_compromised':0,'root_shell':0,'su_attempted':0,'num_root':0,
                    'num_file_creations':0,'num_shells':0,'num_access_files':0,
                    'is_guest_login':0,'count':511,'srv_count':511,'serror_rate':1.0,
                    'rerror_rate':0.0,'same_srv_rate':1.0,'diff_srv_rate':0.0,
                    'dst_host_count':255,'dst_host_srv_count':255,
                    'dst_host_same_srv_rate':1.0,'dst_host_serror_rate':1.0,
                    'dst_host_rerror_rate':0.0}},
        {'name':'🟡 Probe / Port Scan (Nmap)',
         'traffic':{'duration':0,'protocol_type':'tcp','service':'other','flag':'REJ',
                    'src_bytes':0,'dst_bytes':0,'land':0,'wrong_fragment':0,
                    'urgent':0,'hot':0,'num_failed_logins':0,'logged_in':0,
                    'num_compromised':0,'root_shell':0,'su_attempted':0,'num_root':0,
                    'num_file_creations':0,'num_shells':0,'num_access_files':0,
                    'is_guest_login':0,'count':159,'srv_count':1,'serror_rate':0.0,
                    'rerror_rate':1.0,'same_srv_rate':0.01,'diff_srv_rate':0.99,
                    'dst_host_count':255,'dst_host_srv_count':1,
                    'dst_host_same_srv_rate':0.0,'dst_host_serror_rate':0.0,
                    'dst_host_rerror_rate':0.26}},
        {'name':'🔴 R2L Attack (Password Guessing)',
         'traffic':{'duration':2,'protocol_type':'tcp','service':'ftp','flag':'SF',
                    'src_bytes':772,'dst_bytes':0,'land':0,'wrong_fragment':0,
                    'urgent':0,'hot':0,'num_failed_logins':5,'logged_in':0,
                    'num_compromised':0,'root_shell':0,'su_attempted':0,'num_root':0,
                    'num_file_creations':0,'num_shells':0,'num_access_files':0,
                    'is_guest_login':0,'count':1,'srv_count':1,'serror_rate':0.0,
                    'rerror_rate':0.0,'same_srv_rate':1.0,'diff_srv_rate':0.0,
                    'dst_host_count':1,'dst_host_srv_count':1,
                    'dst_host_same_srv_rate':1.0,'dst_host_serror_rate':0.0,
                    'dst_host_rerror_rate':0.0}},
        {'name':'🔴 U2R Attack (Buffer Overflow)',
         'traffic':{'duration':0,'protocol_type':'tcp','service':'telnet','flag':'SF',
                    'src_bytes':721,'dst_bytes':18949,'land':0,'wrong_fragment':0,
                    'urgent':0,'hot':2,'num_failed_logins':0,'logged_in':1,
                    'num_compromised':1,'root_shell':1,'su_attempted':0,'num_root':0,
                    'num_file_creations':1,'num_shells':1,'num_access_files':0,
                    'is_guest_login':0,'count':1,'srv_count':1,'serror_rate':0.0,
                    'rerror_rate':0.0,'same_srv_rate':1.0,'diff_srv_rate':0.0,
                    'dst_host_count':1,'dst_host_srv_count':1,
                    'dst_host_same_srv_rate':1.0,'dst_host_serror_rate':0.0,
                    'dst_host_rerror_rate':0.0}},
    ]

    print("\n🚦 Running demo intrusion detection scenarios …")
    print("=" * 70)

    for sc in TEST_SCENARIOS:
        print(f"\n{'='*70}")
        print(f"📡 ANALYSING: {sc['name']}")
        print(f"{'='*70}")
        result = predict_traffic(sc['traffic'])
        icon   = '🔴' if result['predicted_class'] != 'Normal' else '🟢'
        print(f"{icon} DETECTION: {result['predicted_class'].upper()}")
        print(f"📊 CONFIDENCE: {result['confidence']:.1%}")
        print("\n📋 PROBABILITY BREAKDOWN:")
        for cls, prob in sorted(result['all_probabilities'].items(),
                                key=lambda x: x[1], reverse=True):
            bar = '█' * int(prob * 20)
            print(f"   {cls:10s}: {bar:<20s} {prob:.1%}")
        print("\n🧠 LLM THREAT ANALYSIS:")
        print("-" * 50)
        print(result['threat_report'])


# ── 11. Live Traffic Monitoring (Scapy) ──────────────────────────────────────

# Platform-aware interface detection
def _detect_interface():
    system = platform.system()

    if system == 'Windows':
        try:
            from scapy.arch.windows import get_windows_if_list
            from scapy.all import get_if_list
            npf_ifaces = get_if_list()           # \Device\NPF_{GUID}
            win_ifaces = get_windows_if_list()   # friendly info + IPs

            # Build GUID -> NPF name map
            guid_to_npf = {}
            for npf in npf_ifaces:
                for wi in win_ifaces:
                    if wi.get('guid','').lower() in npf.lower():
                        guid_to_npf[wi['guid']] = npf
                        break

            # Score: prefer interfaces that have a real (non-169.254) IPv4
            best_npf  = None
            best_score = -1
            skip_kw = ('loopback','virtual','pseudo','bluetooth','vpn','tunnel')

            for wi in win_ifaces:
                desc = wi.get('description','').lower()
                name = wi.get('name','').lower()
                if any(k in desc or k in name for k in skip_kw):
                    continue
                ips  = wi.get('ips', [])
                real_ipv4 = [ip for ip in ips
                             if '.' in ip and not ip.startswith('169.254')
                             and not ip.startswith('127.')]
                score = len(real_ipv4) * 10 + (1 if 'ethernet' in desc else 0)
                if score > best_score:
                    best_score = score
                    npf = guid_to_npf.get(wi.get('guid',''))
                    if npf:
                        best_npf = npf
                    else:
                        best_npf = wi.get('name')  # fallback to friendly name

            if best_npf:
                return best_npf
            # last resort: first non-loopback NPF interface
            for npf in npf_ifaces:
                if 'Loopback' not in npf:
                    return npf
            return npf_ifaces[0] if npf_ifaces else None
        except Exception:
            return None
    else:
        # Linux / macOS — prefer eth0, en0, ens*, etc.
        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
        except Exception:
            return None
        preferred = ['eth0','en0','ens3','ens4','ens5','wlan0','wlp2s0','enp3s0']
        for p in preferred:
            if p in ifaces:
                return p
        for iface in ifaces:
            if 'lo' not in iface.lower():
                return iface
        return ifaces[0] if ifaces else None


def _check_admin():
    """Returns True if running with sufficient privileges for packet capture."""
    system = platform.system()
    if system == 'Windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.getuid() == 0


class ConnectionTracker:
    FLOW_TIMEOUT = 5

    def __init__(self):
        self._flows   = {}
        self._lock    = threading.Lock()
        self._history = []
        self._window  = collections.deque()

    @staticmethod
    def _proto(pkt):
        from scapy.all import TCP, UDP, ICMP
        if   TCP  in pkt: return 'tcp'
        elif UDP  in pkt: return 'udp'
        elif ICMP in pkt: return 'icmp'
        return 'other'

    @staticmethod
    def _service(port):
        M = {80:'http',443:'http',21:'ftp',20:'ftp',25:'smtp',
             587:'smtp',22:'ssh',23:'telnet',53:'dns',
             110:'pop3',143:'imap',3306:'sql',5432:'sql',
             8080:'http',8443:'http',8888:'http'}
        return M.get(port, 'other')

    @staticmethod
    def _flag(pkt):
        from scapy.all import TCP
        if TCP not in pkt:
            return 'SF'
        f = pkt[TCP].flags
        if f == 0x02:        return 'S0'
        if f & 0x04:         return 'RSTO'
        if f & 0x01:         return 'RSTO'
        if f == 0x12:        return 'S1'
        if f & 0x10:         return 'SF'
        if f == 0x14:        return 'REJ'
        return 'OTH'

    def process(self, pkt):
        from scapy.all import IP, TCP, UDP
        if IP not in pkt:
            return None

        now      = time.time()
        src_ip   = pkt[IP].src
        dst_ip   = pkt[IP].dst
        proto    = self._proto(pkt)
        src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        service  = self._service(dst_port)
        flag     = self._flag(pkt)
        pkt_len  = len(pkt)
        key      = (src_ip, dst_ip, proto, src_port, dst_port)

        with self._lock:
            self._window.append((now, dst_ip, service))
            cutoff = now - WINDOW_SECONDS
            while self._window and self._window[0][0] < cutoff:
                self._window.popleft()

            if key not in self._flows:
                self._flows[key] = {
                    'start_ts':0,'last_ts':now,'src_ip':src_ip,'dst_ip':dst_ip,
                    'proto':proto,'service':service,'src_bytes':0,'dst_bytes':0,
                    'flag':flag,'land':int(src_ip==dst_ip and src_port==dst_port),
                    'wrong_fragment':0,'urgent':0,'hot':0,'num_failed_logins':0,
                    'logged_in':0,'num_compromised':0,'root_shell':0,
                    'su_attempted':0,'num_root':0,'num_file_creations':0,
                    'num_shells':0,'num_access_files':0,'is_guest_login':0,
                    'syn_errors':0,'rej_errors':0,'pkt_count':0,
                }
                self._flows[key]['start_ts'] = now

            flow = self._flows[key]
            flow['last_ts']   = now
            flow['pkt_count'] += 1
            flow['src_bytes'] += pkt_len

            if flag == 'S0':              flow['syn_errors'] += 1
            if flag in ('REJ','RSTO'):    flow['rej_errors'] += 1
            if flag != flow['flag'] and flag in ('SF','RSTO'):
                flow['flag'] = flag

            raw = bytes(pkt)
            if b'sudo' in raw or b'su -' in raw:       flow['su_attempted'] = 1
            if b'root' in raw:                         flow['hot'] += 1
            if b'/bin/sh' in raw or b'/bin/bash' in raw: flow['num_shells'] += 1

            done = False
            if TCP in pkt:
                tcp_flags = pkt[TCP].flags
                if tcp_flags & 0x01 or tcp_flags & 0x04:
                    done = True
            if (now - flow['start_ts']) > self.FLOW_TIMEOUT:
                done = True

            if done:
                feat = self._build_features(flow, now)
                self._history.append(feat)
                del self._flows[key]
                return feat

        return None

    def _build_features(self, flow, now):
        with self._lock:
            dst_ip  = flow['dst_ip']
            service = flow['service']
            wnd     = list(self._window)

        total    = max(len(wnd), 1)
        h_count  = sum(1 for ts,h,s in wnd if h == dst_ip)
        s_count  = sum(1 for ts,h,s in wnd if s == service)
        pkt_n    = max(flow['pkt_count'], 1)
        duration = max(flow['last_ts'] - flow['start_ts'], 0)
        ser      = flow['syn_errors'] / pkt_n
        rer      = flow['rej_errors'] / pkt_n
        ssr      = s_count / total
        dsr      = 1 - ssr

        return {
            'duration': duration,
            'protocol_type':flow['proto'],'service':service,'flag':flow['flag'],
            'src_bytes':flow['src_bytes'],'dst_bytes':flow['dst_bytes'],
            'land':flow['land'],'wrong_fragment':flow['wrong_fragment'],
            'urgent':flow['urgent'],'hot':flow['hot'],
            'num_failed_logins':flow['num_failed_logins'],
            'logged_in':flow['logged_in'],'num_compromised':flow['num_compromised'],
            'root_shell':flow['root_shell'],'su_attempted':flow['su_attempted'],
            'num_root':flow['num_root'],'num_file_creations':flow['num_file_creations'],
            'num_shells':flow['num_shells'],'num_access_files':flow['num_access_files'],
            'is_guest_login':flow['is_guest_login'],
            'count':h_count,'srv_count':s_count,'serror_rate':ser,'rerror_rate':rer,
            'same_srv_rate':ssr,'diff_srv_rate':dsr,
            'dst_host_count':h_count,'dst_host_srv_count':s_count,
            'dst_host_same_srv_rate':ssr,'dst_host_serror_rate':ser,
            'dst_host_rerror_rate':rer,
            '_src_ip':flow['src_ip'],'_dst_ip':dst_ip,
            '_ts':datetime.now().strftime('%H:%M:%S'),
        }

    def flush_timeouts(self):
        now     = time.time()
        emitted = []
        with self._lock:
            stale = [k for k,v in self._flows.items()
                     if now - v['last_ts'] > self.FLOW_TIMEOUT]
            for k in stale:
                feat = self._build_features(self._flows[k], now)
                emitted.append(feat)
                self._history.append(feat)
                del self._flows[k]
        return emitted


def classify_live_flow(feature_dict):
    enc = feature_dict.copy()
    for col in ['protocol_type','service','flag']:
        if col in le_dict:
            try:
                enc[col+'_enc'] = le_dict[col].transform(
                    [str(feature_dict.get(col,'tcp'))])[0]
            except ValueError:
                enc[col+'_enc'] = 0
        else:
            enc[col+'_enc'] = 0

    fvec        = np.array([[enc.get(f,0) for f in FEATURE_COLS]])
    fvec_scaled = scaler.transform(fvec)
    pred_idx    = best_model.predict(fvec_scaled)[0]
    probas      = best_model.predict_proba(fvec_scaled)[0]
    confidence  = probas[pred_idx]
    pred_cls    = class_names[pred_idx]
    return pred_cls, confidence, dict(zip(class_names, probas))


WINDOW_SECONDS     = 2
ALERT_ON_NORMAL    = False
MAX_ALERTS_DISPLAY = 50


def run_live_monitoring(duration=60, iface=None):
    """Capture real network traffic and classify each flow."""

    if not _check_admin():
        print("\n⚠️  WARNING: Live capture requires administrator / root privileges.")
        print("   Windows: right-click cmd/PowerShell → 'Run as administrator'")
        print("   Linux/Mac: run with  sudo python ids_app.py --live")
        print("   Attempting anyway (may fail with permission error) …\n")

    if iface is None:
        iface = _detect_interface()

    print("=" * 70)
    print(f"🌐 LIVE TRAFFIC MONITORING — {duration}s capture window")
    print(f"   Interface : {iface or 'auto (default)'}")
    print(f"   Model     : {best_model_name} (accuracy ~{best_acc:.1%})")
    print(f"   LLM       : {'✅ Enabled' if LLM_ENABLED else '⚠️  Fallback mode'}")
    print("=" * 70)

    try:
        import logging
        logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
        from scapy.all import sniff, conf as scapy_conf
        scapy_conf.verb = 0
    except ImportError:
        print("❌ Scapy not available. Install with: pip install scapy")
        print("   Windows also needs Npcap: https://npcap.com")
        return [], {}

    tracker = ConnectionTracker()
    alerts  = []
    stats   = collections.Counter()
    stop_ev = threading.Event()

    def _flusher():
        while not stop_ev.is_set():
            time.sleep(WINDOW_SECONDS)
            for feat in tracker.flush_timeouts():
                _handle_flow(feat)

    def _handle_flow(feat):
        cls, conf_val, probas = classify_live_flow(feat)
        stats[cls] += 1
        is_threat = (cls != 'Normal')
        if not is_threat and not ALERT_ON_NORMAL:
            return

        icon = '🔴' if is_threat else '🟢'
        ts   = feat.get('_ts', '??:??:??')
        src  = feat.get('_src_ip', '?')
        dst  = feat.get('_dst_ip', '?')
        svc  = feat.get('service', '?')
        flg  = feat.get('flag', '?')

        print(f"\n{'─'*70}")
        print(f"{icon} [{ts}]  {cls.upper():10s}  conf={conf_val:.1%}")
        print(f"   {src} → {dst}  |  proto={feat.get('protocol_type','?')}  "
              f"svc={svc}  flag={flg}")
        print(f"   bytes: src={feat.get('src_bytes',0):,}  "
              f"dst={feat.get('dst_bytes',0):,}  "
              f"count={feat.get('count',0)}  serror={feat.get('serror_rate',0):.2f}")

        top2 = sorted(probas.items(), key=lambda x: x[1], reverse=True)[:2]
        print(f"   📊 " + "  ".join(f"{k}:{v:.1%}" for k,v in top2))

        if is_threat and conf_val > 0.75 and LLM_ENABLED:
            print("   🧠 LLM analysis …")
            try:
                report = get_llm_threat_analysis(feat, cls, conf_val)
                short  = '\n'.join(report.strip().split('\n')[:6])
                print("   " + short.replace('\n','\n   '))
            except Exception as e:
                print(f"   ⚠️  LLM error: {e}")
        elif is_threat:
            fb = get_fallback_analysis(cls, conf_val)
            print("   " + fb.split('\n')[0])

        alerts.append({
            'Time':ts,'Class':cls,'Confidence':f"{conf_val:.1%}",
            'Src IP':src,'Dst IP':dst,'Service':svc,'Flag':flg,
            'Src Bytes':feat.get('src_bytes',0),
        })

    def _pkt_cb(pkt):
        try:
            feat = tracker.process(pkt)
            if feat:
                _handle_flow(feat)
        except Exception:
            pass

    flush_thread = threading.Thread(target=_flusher, daemon=True)
    flush_thread.start()

    print(f"\n⏳ Capturing for {duration}s … (Ctrl+C to stop early)\n")
    try:
        kwargs = dict(prn=_pkt_cb, timeout=duration, store=False, filter='ip')
        if iface:
            kwargs['iface'] = iface
        sniff(**kwargs)
    except PermissionError:
        print("\n❌ Permission denied — re-run as Administrator (Windows) or with sudo (Linux/Mac).")
    except KeyboardInterrupt:
        print("\n⛔ Capture interrupted by user.")
    except Exception as e:
        print(f"\n❌ Capture error: {e}")
        if 'Npcap' in str(e) or 'WinPcap' in str(e) or 'libpcap' in str(e):
            print("   Windows: install Npcap from https://npcap.com")
            print("   Linux:   sudo apt install libpcap-dev")
    finally:
        stop_ev.set()

    for feat in tracker.flush_timeouts():
        _handle_flow(feat)

    total = sum(stats.values()) or 1
    print("\n" + "=" * 70)
    print("📊 LIVE MONITORING SESSION COMPLETE")
    print("=" * 70)
    print(f"   Total flows analysed: {total}")
    for cls_name in ['Normal','DoS','Probe','R2L','U2R']:
        cnt = stats.get(cls_name, 0)
        pct = cnt/total*100
        bar = '█' * int(pct/4)
        icon = '🟢' if cls_name == 'Normal' else '🔴'
        print(f"   {icon} {cls_name:8s}: {cnt:4d}  ({pct:5.1f}%)  {bar}")
    print("=" * 70)

    if alerts:
        df_alerts = pd.DataFrame(alerts[:MAX_ALERTS_DISPLAY])
        print(f"\n🚨 ALERT TABLE (top {min(len(alerts),MAX_ALERTS_DISPLAY)}):")
        print(df_alerts.to_string(index=False))
    else:
        print("\n✅ No threats detected during this session.")

    return alerts, stats


# ── 12. CLI entry point ───────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='AI-Powered IDS — cross-platform intrusion detection system')
    parser.add_argument('--live', action='store_true',
                        help='Capture real network traffic after running demos')
    parser.add_argument('--live-only', action='store_true',
                        help='Skip demos and go straight to live capture')
    parser.add_argument('--duration', type=int, default=60,
                        help='Live capture duration in seconds (default: 60)')
    parser.add_argument('--interface', type=str, default=None,
                        help='Network interface name (auto-detected if omitted)')
    parser.add_argument('--demo-only', action='store_true',
                        help='Run demo scenarios only, no live capture')
    args = parser.parse_args()

    if not args.live_only:
        run_demo_scenarios()

    if args.live or args.live_only:
        run_live_monitoring(duration=args.duration, iface=args.interface)
    elif not args.demo_only:
        print("\n" + "="*70)
        print("💡 To capture REAL network traffic, run:")
        print("   Windows (Admin PowerShell): python ids_app.py --live")
        print("   Linux/Mac (sudo):           sudo python ids_app.py --live")
        print("   Custom duration:            python ids_app.py --live --duration 120")
        print("   Specific interface:         python ids_app.py --live --interface eth0")
        print("="*70)

    print("\n\n╔══════════════════════════════════════════════════════════════╗")
    print("║         🛡  AI-POWERED IDS — SESSION COMPLETE 🛡            ║")
    print("╚══════════════════════════════════════════════════════════════╝")
