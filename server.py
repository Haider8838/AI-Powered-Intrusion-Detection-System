# -*- coding: utf-8 -*-
"""
AI-Powered IDS — Web Dashboard Server
======================================
Run:  python server.py
Then open http://localhost:5000 in your browser.

Features:
  - Live traffic capture (start / stop)
  - Real-time alert feed via Socket.IO
  - Demo scenario runner
  - Threat analysis with LLM
  - Session statistics + doughnut chart
  - Alert history table
  - API key configuration panel
"""

# ── Force UTF-8 ──────────────────────────────────────────────────────────────
import sys, io
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ── Imports ──────────────────────────────────────────────────────────────────
import os, time, threading, collections, platform, logging, warnings
from datetime import datetime

import numpy as np
import pandas as pd
import joblib
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit

warnings.filterwarnings('ignore')
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)
logging.getLogger('socketio').setLevel(logging.ERROR)

# ── Load .env ────────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
except Exception:
    pass

# ── Flask + SocketIO app ─────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-secret-2025'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading',
                    logger=False, engineio_logger=False)

# ── Global state ─────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(BASE_DIR, 'best_ids_model.joblib')
SCALER_FILE= os.path.join(BASE_DIR, 'scaler.joblib')
LE_DICT_F  = os.path.join(BASE_DIR, 'le_dict.joblib')
LE_TGT_F   = os.path.join(BASE_DIR, 'le_target.joblib')
CN_FILE    = os.path.join(BASE_DIR, 'class_names.joblib')

state = {
    'model'        : None,
    'scaler'       : None,
    'le_dict'      : {},
    'le_target'    : None,
    'class_names'  : None,
    'feature_cols' : None,
    'best_model_name': 'Unknown',
    'best_acc'     : 0.0,
    'model_ready'  : False,
    # live capture
    'capturing'    : False,
    'capture_thread': None,
    'stop_event'   : None,
    # stats
    'total_flows'  : 0,
    'class_counts' : collections.Counter(),
    'alerts'       : [],
    # LLM
    'gemini_client'   : None,
    'anthropic_client': None,
    'llm_enabled'     : False,
    'llm_provider'    : 'none',
}

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
state['feature_cols'] = FEATURE_COLS

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

# ── LLM helpers ──────────────────────────────────────────────────────────────
def _init_llm():
    google_key    = os.getenv('GOOGLE_API_KEY','')
    anthropic_key = os.getenv('ANTHROPIC_API_KEY','')

    if google_key:
        try:
            from google import genai as google_genai
            state['gemini_client'] = google_genai.Client(api_key=google_key)
            state['gemini_client'].models.generate_content(
                model='gemini-2.0-flash', contents='Reply: OK')
            state['llm_enabled']  = True
            state['llm_provider'] = 'gemini'
            return
        except Exception:
            state['gemini_client'] = None

    if anthropic_key and not anthropic_key.startswith('sk-ant-your'):
        try:
            import anthropic as _ant
            state['anthropic_client'] = _ant.Anthropic(api_key=anthropic_key)
            state['anthropic_client'].messages.create(
                model='claude-haiku-4-5-20251001', max_tokens=10,
                messages=[{'role':'user','content':'Hi'}])
            state['llm_enabled']  = True
            state['llm_provider'] = 'anthropic'
        except Exception:
            state['anthropic_client'] = None


def get_llm_analysis(traffic_data, predicted_class, confidence):
    prompt = f"""You are a cybersecurity expert. A ML model flagged this network connection:
Protocol: {traffic_data.get('protocol_type','?')} | Service: {traffic_data.get('service','?')}
Duration: {traffic_data.get('duration',0):.2f}s | Src bytes: {traffic_data.get('src_bytes',0):,}
Dst bytes: {traffic_data.get('dst_bytes',0):,} | Failed logins: {traffic_data.get('num_failed_logins',0)}
Root shell: {'Yes' if traffic_data.get('root_shell',0) else 'No'} | Count: {traffic_data.get('count',0)}
Error rate: {traffic_data.get('serror_rate',0):.2f}

DETECTION: {predicted_class} (confidence {confidence:.1%})

Give a structured security report:
1. THREAT SUMMARY (2 sentences)
2. SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW/NONE]
3. ATTACK MECHANISM (2-3 sentences)
4. EVIDENCE (bullet points)
5. IMMEDIATE ACTIONS (3 steps)
6. RECOMMENDATIONS (2 points)
Keep it under 250 words."""

    if state['llm_enabled'] and state['gemini_client']:
        try:
            resp = state['gemini_client'].models.generate_content(
                model='gemini-2.0-flash', contents=prompt)
            return resp.text
        except Exception as e:
            pass

    if state['llm_enabled'] and state['anthropic_client']:
        try:
            resp = state['anthropic_client'].messages.create(
                model='claude-haiku-4-5-20251001', max_tokens=500,
                messages=[{'role':'user','content':prompt}])
            return resp.content[0].text
        except Exception as e:
            pass

    # fallback
    templates = {
        'DoS':  ('CRITICAL','Denial of Service attack — network flood detected.',
                 ['Block source IP','Enable rate limiting','Alert NOC team']),
        'Probe':('MEDIUM','Reconnaissance/port scanning — attacker mapping network.',
                 ['Log source IP','Enable scan-detection rules','Review exposed services']),
        'R2L':  ('HIGH','Remote-to-Local attack — unauthorised access attempt.',
                 ['Force password reset','Enable MFA','Review auth logs']),
        'U2R':  ('CRITICAL','Privilege escalation — attacker targeting root access.',
                 ['Isolate system','Audit sudo logs','Apply privilege escalation patch']),
        'Normal':('NONE','Normal traffic — no threat detected.',
                 ['Continue monitoring','Log baseline','No action needed']),
    }
    sev, summary, actions = templates.get(predicted_class, templates['Probe'])
    return (f"THREAT SUMMARY: {summary}\nSEVERITY: {sev}\n"
            f"CONFIDENCE: {confidence:.1%}\n\nIMMEDIATE ACTIONS:\n"
            + '\n'.join(f'  {i+1}. {a}' for i, a in enumerate(actions)))


# ── Model training ────────────────────────────────────────────────────────────
def train_models(emit_progress=True):
    """Train ML models on synthetic KDD data, save artefacts, update state."""
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score

    def _emit(msg, pct):
        if emit_progress:
            socketio.emit('train_progress', {'msg': msg, 'pct': pct})

    _emit('Generating KDD-style dataset…', 5)
    np.random.seed(42)
    n = 50000
    labels = (['normal.']*20000+['neptune.']*10000+['smurf.']*8000+
              ['satan.']*3000+['ipsweep.']*2500+['portsweep.']*2000+
              ['nmap.']*1500+['back.']*1000+['warezclient.']*800+
              ['guess_passwd.']*500+['buffer_overflow.']*400+['rootkit.']*300)
    np.random.shuffle(labels)

    df = pd.DataFrame({
        'duration':np.random.exponential(5,n),
        'protocol_type':np.random.choice(['tcp','udp','icmp'],n,p=[0.6,0.2,0.2]),
        'service':np.random.choice(['http','ftp','smtp','ssh','telnet','dns','other'],n),
        'flag':np.random.choice(['SF','S0','REJ','RSTO','SH'],n,p=[0.6,0.2,0.1,0.06,0.04]),
        'src_bytes':np.random.exponential(5000,n),
        'dst_bytes':np.random.exponential(3000,n),
        'land':np.random.choice([0,1],n,p=[0.99,0.01]),
        'wrong_fragment':np.random.choice([0,1,2,3],n,p=[0.97,0.01,0.01,0.01]),
        'urgent':np.zeros(n,dtype=int),
        'hot':np.random.poisson(0.5,n),
        'num_failed_logins':np.random.choice([0,1,2,3],n,p=[0.95,0.03,0.01,0.01]),
        'logged_in':np.random.choice([0,1],n,p=[0.4,0.6]),
        'num_compromised':np.random.poisson(0.1,n),
        'root_shell':np.random.choice([0,1],n,p=[0.99,0.01]),
        'su_attempted':np.random.choice([0,1],n,p=[0.99,0.01]),
        'num_root':np.random.poisson(0.05,n),
        'num_file_creations':np.random.poisson(0.1,n),
        'num_shells':np.zeros(n,dtype=int),
        'num_access_files':np.zeros(n,dtype=int),
        'is_guest_login':np.random.choice([0,1],n,p=[0.95,0.05]),
        'count':np.random.randint(1,512,n),
        'srv_count':np.random.randint(1,512,n),
        'serror_rate':np.random.beta(0.5,5,n),
        'rerror_rate':np.random.beta(0.5,5,n),
        'same_srv_rate':np.random.beta(5,1,n),
        'diff_srv_rate':np.random.beta(1,5,n),
        'dst_host_count':np.random.randint(1,256,n),
        'dst_host_srv_count':np.random.randint(1,256,n),
        'dst_host_same_srv_rate':np.random.beta(5,1,n),
        'dst_host_serror_rate':np.random.beta(0.5,5,n),
        'dst_host_rerror_rate':np.random.beta(0.5,5,n),
        'label':labels,
    })

    def map_label(l):
        k = l if l.endswith('.') else l+'.'
        return ATTACK_MAP.get(k, ATTACK_MAP.get(l,'Other'))

    df['attack_category'] = df['label'].apply(map_label)

    le_dict = {}
    for col in ['protocol_type','service','flag']:
        le = LabelEncoder()
        df[col+'_enc'] = le.fit_transform(df[col].astype(str))
        le_dict[col] = le

    le_target = LabelEncoder()
    df['target'] = le_target.fit_transform(df['attack_category'])
    class_names = le_target.classes_

    X = df[FEATURE_COLS].fillna(0)
    y = df['target']
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_train,X_test,y_train,y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y)

    models_to_train = {
        'Random Forest': RandomForestClassifier(
            n_estimators=100, max_depth=20, random_state=42, n_jobs=-1),
        'Decision Tree': DecisionTreeClassifier(max_depth=15, random_state=42),
        'Gradient Boosting': GradientBoostingClassifier(
            n_estimators=50, learning_rate=0.1, max_depth=5, random_state=42),
    }

    best_model=None; best_name=''; best_acc=0.0
    pct_steps = {'Random Forest':30,'Decision Tree':55,'Gradient Boosting':85}

    for name, mdl in models_to_train.items():
        _emit(f'Training {name}…', pct_steps[name]-5)
        mdl.fit(X_train, y_train)
        acc = accuracy_score(y_test, mdl.predict(X_test))
        _emit(f'{name}: {acc:.4f}', pct_steps[name])
        if acc > best_acc:
            best_acc=acc; best_name=name; best_model=mdl

    _emit('Saving artefacts…', 90)
    joblib.dump(best_model, MODEL_FILE)
    joblib.dump(scaler,     SCALER_FILE)
    joblib.dump(le_dict,    LE_DICT_F)
    joblib.dump(le_target,  LE_TGT_F)
    joblib.dump(class_names,CN_FILE)

    state.update({
        'model': best_model, 'scaler': scaler, 'le_dict': le_dict,
        'le_target': le_target, 'class_names': class_names,
        'best_model_name': best_name, 'best_acc': best_acc,
        'model_ready': True,
    })
    _emit(f'Done! Best: {best_name} ({best_acc:.4f})', 100)
    return best_acc, best_name


def load_saved_models():
    """Load previously saved model artefacts if they exist."""
    try:
        if all(os.path.exists(f) for f in [MODEL_FILE,SCALER_FILE,LE_DICT_F,LE_TGT_F,CN_FILE]):
            state['model']        = joblib.load(MODEL_FILE)
            state['scaler']       = joblib.load(SCALER_FILE)
            state['le_dict']      = joblib.load(LE_DICT_F)
            state['le_target']    = joblib.load(LE_TGT_F)
            state['class_names']  = joblib.load(CN_FILE)
            state['model_ready']  = True
            state['best_model_name'] = type(state['model']).__name__
            print('  Loaded saved model artefacts.')
            return True
    except Exception as e:
        print(f'  Could not load saved models: {e}')
    return False


# ── Traffic prediction ────────────────────────────────────────────────────────
def predict_traffic(traffic_dict):
    if not state['model_ready']:
        return None
    enc = traffic_dict.copy()
    for col in ['protocol_type','service','flag']:
        if col in state['le_dict']:
            try:
                enc[col+'_enc'] = state['le_dict'][col].transform(
                    [str(traffic_dict.get(col,'tcp'))])[0]
            except ValueError:
                enc[col+'_enc'] = 0
        else:
            enc[col+'_enc'] = 0
    fvec   = np.array([[enc.get(f,0) for f in FEATURE_COLS]])
    fscale = state['scaler'].transform(fvec)
    pidx   = state['model'].predict(fscale)[0]
    probas = state['model'].predict_proba(fscale)[0]
    pclass = state['class_names'][pidx]
    conf   = float(probas[pidx])
    return pclass, conf, {k:float(v) for k,v in zip(state['class_names'],probas)}


# ── Interface detection ───────────────────────────────────────────────────────
def detect_interface():
    if platform.system() == 'Windows':
        try:
            from scapy.arch.windows import get_windows_if_list
            from scapy.all import get_if_list
            npf   = get_if_list()
            wins  = get_windows_if_list()
            g2npf = {}
            for n in npf:
                for w in wins:
                    if w.get('guid','').lower() in n.lower():
                        g2npf[w['guid']] = n; break
            best=None; best_score=-1
            skip = ('loopback','virtual','pseudo','bluetooth','vpn','tunnel')
            for w in wins:
                desc=w.get('description','').lower(); name=w.get('name','').lower()
                if any(k in desc or k in name for k in skip): continue
                ips = w.get('ips',[])
                real = [ip for ip in ips if '.' in ip
                        and not ip.startswith('169.254')
                        and not ip.startswith('127.')]
                score = len(real)*10 + (1 if 'ethernet' in desc else 0)
                if score > best_score:
                    best_score = score
                    n2 = g2npf.get(w.get('guid',''))
                    best = n2 if n2 else w.get('name')
            if best: return best
            return [i for i in npf if 'Loopback' not in i][0] if npf else None
        except Exception:
            return None
    else:
        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
            for p in ['eth0','en0','ens3','ens4','wlan0','wlp2s0','enp3s0']:
                if p in ifaces: return p
            return next((i for i in ifaces if 'lo' not in i.lower()), None)
        except Exception:
            return None


def list_interfaces():
    try:
        if platform.system() == 'Windows':
            from scapy.arch.windows import get_windows_if_list
            wins = get_windows_if_list()
            skip = ('loopback','pseudo','bluetooth')
            out  = []
            for w in wins:
                desc = w.get('description','').lower()
                if any(k in desc for k in skip): continue
                ips = [ip for ip in w.get('ips',[]) if '.' in ip]
                out.append({'name':w['name'],'desc':w['description'],'ips':ips[:2]})
            return out
        else:
            from scapy.all import get_if_list
            return [{'name':i,'desc':i,'ips':[]} for i in get_if_list()]
    except Exception:
        return []


# ── Live capture ──────────────────────────────────────────────────────────────
WINDOW_SECONDS = 2

class ConnectionTracker:
    FLOW_TIMEOUT = 5
    def __init__(self):
        self._flows={};self._lock=threading.Lock()
        self._window=collections.deque()

    @staticmethod
    def _proto(pkt):
        from scapy.all import TCP,UDP,ICMP
        if TCP in pkt: return 'tcp'
        if UDP in pkt: return 'udp'
        if ICMP in pkt: return 'icmp'
        return 'other'

    @staticmethod
    def _service(port):
        M={80:'http',443:'http',21:'ftp',20:'ftp',25:'smtp',587:'smtp',
           22:'ssh',23:'telnet',53:'dns',110:'pop3',143:'imap',
           3306:'sql',5432:'sql',8080:'http',8443:'http'}
        return M.get(port,'other')

    @staticmethod
    def _flag(pkt):
        from scapy.all import TCP
        if TCP not in pkt: return 'SF'
        f=pkt[TCP].flags
        if f==0x02: return 'S0'
        if f&0x04:  return 'RSTO'
        if f&0x01:  return 'RSTO'
        if f==0x12: return 'S1'
        if f&0x10:  return 'SF'
        if f==0x14: return 'REJ'
        return 'OTH'

    def process(self, pkt):
        from scapy.all import IP,TCP,UDP
        if IP not in pkt: return None
        now=time.time()
        src=pkt[IP].src; dst=pkt[IP].dst
        proto=self._proto(pkt)
        sp=pkt[TCP].sport if TCP in pkt else(pkt[UDP].sport if UDP in pkt else 0)
        dp=pkt[TCP].dport if TCP in pkt else(pkt[UDP].dport if UDP in pkt else 0)
        svc=self._service(dp); flag=self._flag(pkt)
        key=(src,dst,proto,sp,dp)
        with self._lock:
            self._window.append((now,dst,svc))
            cut=now-WINDOW_SECONDS
            while self._window and self._window[0][0]<cut: self._window.popleft()
            if key not in self._flows:
                self._flows[key]={
                    'start_ts':now,'last_ts':now,'src_ip':src,'dst_ip':dst,
                    'proto':proto,'service':svc,'src_bytes':0,'dst_bytes':0,
                    'flag':flag,'land':int(src==dst and sp==dp),
                    'wrong_fragment':0,'urgent':0,'hot':0,
                    'num_failed_logins':0,'logged_in':0,'num_compromised':0,
                    'root_shell':0,'su_attempted':0,'num_root':0,
                    'num_file_creations':0,'num_shells':0,'num_access_files':0,
                    'is_guest_login':0,'syn_errors':0,'rej_errors':0,'pkt_count':0,
                }
            fl=self._flows[key]
            fl['last_ts']=now; fl['pkt_count']+=1; fl['src_bytes']+=len(pkt)
            if flag=='S0': fl['syn_errors']+=1
            if flag in('REJ','RSTO'): fl['rej_errors']+=1
            if flag!=fl['flag'] and flag in('SF','RSTO'): fl['flag']=flag
            raw=bytes(pkt)
            if b'sudo' in raw or b'su -' in raw: fl['su_attempted']=1
            if b'root' in raw: fl['hot']+=1
            if b'/bin/sh' in raw or b'/bin/bash' in raw: fl['num_shells']+=1
            done=False
            if TCP in pkt:
                tf=pkt[TCP].flags
                if tf&0x01 or tf&0x04: done=True
            if now-fl['start_ts']>self.FLOW_TIMEOUT: done=True
            if done:
                feat=self._build(fl,now)
                del self._flows[key]
                return feat
        return None

    def _build(self, fl, now):
        with self._lock:
            wnd=list(self._window); dst=fl['dst_ip']; svc=fl['service']
        tot=max(len(wnd),1)
        hc=sum(1 for _,h,_ in wnd if h==dst)
        sc=sum(1 for _,_,s in wnd if s==svc)
        pn=max(fl['pkt_count'],1)
        dur=max(fl['last_ts']-fl['start_ts'],0)
        ser=fl['syn_errors']/pn; rer=fl['rej_errors']/pn
        ssr=sc/tot; dsr=1-ssr
        return {
            'duration':dur,'protocol_type':fl['proto'],'service':svc,
            'flag':fl['flag'],'src_bytes':fl['src_bytes'],'dst_bytes':fl['dst_bytes'],
            'land':fl['land'],'wrong_fragment':fl['wrong_fragment'],
            'urgent':fl['urgent'],'hot':fl['hot'],
            'num_failed_logins':fl['num_failed_logins'],'logged_in':fl['logged_in'],
            'num_compromised':fl['num_compromised'],'root_shell':fl['root_shell'],
            'su_attempted':fl['su_attempted'],'num_root':fl['num_root'],
            'num_file_creations':fl['num_file_creations'],'num_shells':fl['num_shells'],
            'num_access_files':fl['num_access_files'],'is_guest_login':fl['is_guest_login'],
            'count':hc,'srv_count':sc,'serror_rate':ser,'rerror_rate':rer,
            'same_srv_rate':ssr,'diff_srv_rate':dsr,'dst_host_count':hc,
            'dst_host_srv_count':sc,'dst_host_same_srv_rate':ssr,
            'dst_host_serror_rate':ser,'dst_host_rerror_rate':rer,
            '_src_ip':fl['src_ip'],'_dst_ip':dst,
            '_ts':datetime.now().strftime('%H:%M:%S'),
        }

    def flush_timeouts(self):
        now=time.time(); out=[]
        with self._lock:
            stale=[k for k,v in self._flows.items() if now-v['last_ts']>self.FLOW_TIMEOUT]
            for k in stale:
                out.append(self._build(self._flows[k],now)); del self._flows[k]
        return out


def _live_capture_worker(iface, duration, stop_event):
    logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
    from scapy.all import sniff, conf as scapy_conf
    scapy_conf.verb = 0

    tracker = ConnectionTracker()

    def _flush_worker():
        while not stop_event.is_set():
            time.sleep(WINDOW_SECONDS)
            for feat in tracker.flush_timeouts():
                _handle(feat)

    def _handle(feat):
        result = predict_traffic(feat)
        if not result: return
        cls, conf, probas = result
        state['total_flows'] += 1
        state['class_counts'][cls] += 1

        is_threat = (cls != 'Normal')
        alert = {
            'id'        : state['total_flows'],
            'ts'        : feat.get('_ts','?'),
            'cls'       : cls,
            'conf'      : f'{conf:.1%}',
            'conf_raw'  : conf,
            'src'       : feat.get('_src_ip','?'),
            'dst'       : feat.get('_dst_ip','?'),
            'proto'     : feat.get('protocol_type','?'),
            'svc'       : feat.get('service','?'),
            'flag'      : feat.get('flag','?'),
            'src_bytes' : feat.get('src_bytes',0),
            'threat'    : is_threat,
            'probas'    : probas,
            'report'    : '',
        }

        if is_threat and conf > 0.60:
            alert['report'] = get_llm_analysis(feat, cls, conf)

        state['alerts'].insert(0, alert)
        if len(state['alerts']) > 500:
            state['alerts'] = state['alerts'][:500]

        socketio.emit('new_alert', alert)
        socketio.emit('stats_update', {
            'total'  : state['total_flows'],
            'counts' : dict(state['class_counts']),
        })

    def _pkt_cb(pkt):
        try:
            feat = tracker.process(pkt)
            if feat: _handle(feat)
        except Exception:
            pass

    threading.Thread(target=_flush_worker, daemon=True).start()

    socketio.emit('capture_status', {'status':'running','iface':iface or 'auto'})
    try:
        kwargs = dict(prn=_pkt_cb, timeout=duration, store=False, filter='ip')
        if iface: kwargs['iface'] = iface
        sniff(**kwargs)
    except Exception as e:
        socketio.emit('capture_status', {'status':'error','msg':str(e)})
        return
    finally:
        stop_event.set()
        state['capturing'] = False

    for feat in tracker.flush_timeouts():
        _handle(feat)
    socketio.emit('capture_status', {
        'status':'stopped',
        'total': state['total_flows'],
    })


# ── REST API ──────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return DASHBOARD_HTML

@app.route('/api/status')
def api_status():
    return jsonify({
        'model_ready'  : state['model_ready'],
        'model_name'   : state['best_model_name'],
        'model_acc'    : round(state['best_acc'],4),
        'capturing'    : state['capturing'],
        'llm_enabled'  : state['llm_enabled'],
        'llm_provider' : state['llm_provider'],
        'total_flows'  : state['total_flows'],
        'class_counts' : dict(state['class_counts']),
        'alert_count'  : len(state['alerts']),
    })

@app.route('/api/interfaces')
def api_interfaces():
    return jsonify(list_interfaces())

@app.route('/api/alerts')
def api_alerts():
    limit = int(request.args.get('limit', 100))
    return jsonify(state['alerts'][:limit])

@app.route('/api/predict', methods=['POST'])
def api_predict():
    if not state['model_ready']:
        return jsonify({'error': 'Model not trained yet'}), 400
    data = request.json or {}
    result = predict_traffic(data)
    if not result:
        return jsonify({'error': 'Prediction failed'}), 500
    cls, conf, probas = result
    report = get_llm_analysis(data, cls, conf)
    return jsonify({'class': cls, 'confidence': conf, 'probas': probas, 'report': report})

@app.route('/api/set_keys', methods=['POST'])
def api_set_keys():
    data = request.json or {}
    if data.get('anthropic_key'):
        os.environ['ANTHROPIC_API_KEY'] = data['anthropic_key']
    if data.get('google_key'):
        os.environ['GOOGLE_API_KEY'] = data['google_key']
    _init_llm()
    return jsonify({'llm_enabled': state['llm_enabled'],
                    'llm_provider': state['llm_provider']})

@app.route('/api/clear_alerts', methods=['POST'])
def api_clear_alerts():
    state['alerts'] = []
    state['total_flows'] = 0
    state['class_counts'] = collections.Counter()
    return jsonify({'ok': True})


@app.route('/api/simulate', methods=['POST'])
def api_simulate():
    """
    Inject a simulated attack into the dashboard.
    Runs ML prediction, pushes a real alert via Socket.IO,
    and returns the full result as JSON.
    Called by test_attacks.py.
    """
    if not state['model_ready']:
        return jsonify({'error': 'Model not trained yet — open dashboard and train first'}), 400

    data    = request.json or {}
    traffic = data.get('traffic', data)   # accept flat dict or {traffic:{...}}
    label   = data.get('label', 'Simulated')

    result = predict_traffic(traffic)
    if not result:
        return jsonify({'error': 'Prediction failed'}), 500

    cls, conf, probas = result
    is_threat = (cls != 'Normal')

    report = get_llm_analysis(traffic, cls, conf)

    state['total_flows'] += 1
    state['class_counts'][cls] += 1

    alert = {
        'id'       : state['total_flows'],
        'ts'       : datetime.now().strftime('%H:%M:%S'),
        'cls'      : cls,
        'conf'     : f'{conf:.1%}',
        'conf_raw' : conf,
        'src'      : traffic.get('_src_ip', '10.0.0.1'),
        'dst'      : traffic.get('_dst_ip', '192.168.1.1'),
        'proto'    : traffic.get('protocol_type', 'tcp'),
        'svc'      : traffic.get('service', 'http'),
        'flag'     : traffic.get('flag', 'SF'),
        'src_bytes': traffic.get('src_bytes', 0),
        'threat'   : is_threat,
        'probas'   : probas,
        'report'   : report,
        'label'    : label,
    }

    state['alerts'].insert(0, alert)
    if len(state['alerts']) > 500:
        state['alerts'] = state['alerts'][:500]

    # Push to every connected browser in real time
    socketio.emit('new_alert', alert)
    socketio.emit('stats_update', {
        'total' : state['total_flows'],
        'counts': dict(state['class_counts']),
    })

    return jsonify({
        'class'     : cls,
        'confidence': conf,
        'probas'    : probas,
        'report'    : report,
        'threat'    : is_threat,
        'alert_id'  : state['total_flows'],
    })


# ── Socket.IO events ──────────────────────────────────────────────────────────
@socketio.on('connect')
def on_connect():
    emit('status', {
        'model_ready': state['model_ready'],
        'capturing'  : state['capturing'],
        'llm_enabled': state['llm_enabled'],
        'llm_provider': state['llm_provider'],
    })

@socketio.on('train')
def on_train():
    if state['model_ready']:
        emit('train_progress', {'msg': 'Model already trained — retraining…', 'pct': 0})
    def _do_train():
        try:
            acc, name = train_models(emit_progress=True)
            socketio.emit('train_done', {
                'model_name': name, 'accuracy': acc,
                'msg': f'Trained! Best: {name} ({acc:.4f})'
            })
        except Exception as e:
            socketio.emit('train_error', {'msg': str(e)})
    threading.Thread(target=_do_train, daemon=True).start()

@socketio.on('start_capture')
def on_start_capture(data):
    if state['capturing']:
        emit('capture_status', {'status':'already_running'})
        return
    if not state['model_ready']:
        emit('capture_status', {'status':'error','msg':'Train the model first'})
        return
    iface    = data.get('iface') or detect_interface()
    duration = int(data.get('duration', 60))
    state['capturing'] = True
    state['stop_event'] = threading.Event()
    threading.Thread(target=_live_capture_worker,
                     args=(iface, duration, state['stop_event']),
                     daemon=True).start()
    emit('capture_status', {'status':'starting', 'iface': iface or 'auto', 'duration': duration})

@socketio.on('stop_capture')
def on_stop_capture():
    if state['stop_event']:
        state['stop_event'].set()
    state['capturing'] = False
    emit('capture_status', {'status':'stopped'})

@socketio.on('run_scenario')
def on_run_scenario(data):
    if not state['model_ready']:
        emit('scenario_result', {'error': 'Model not trained yet'})
        return
    traffic = data.get('traffic', {})
    name    = data.get('name', 'Custom')
    result  = predict_traffic(traffic)
    if not result:
        emit('scenario_result', {'error': 'Prediction failed'})
        return
    cls, conf, probas = result
    report = get_llm_analysis(traffic, cls, conf)
    emit('scenario_result', {
        'name'   : name,
        'class'  : cls,
        'conf'   : conf,
        'probas' : probas,
        'report' : report,
        'threat' : cls != 'Normal',
    })


# ── Embedded HTML Dashboard ───────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AI-Powered IDS Dashboard</title>
<script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{
  --navy:#060d1a;--panel:#0c1829;--card:#111f35;--border:#1e3a5f;
  --cyan:#00d4ff;--blue:#2e75b6;--green:#00e676;--amber:#ffb300;
  --red:#ff1744;--purple:#b388ff;--muted:#4a6080;--text:#e0ecf8;
  --sub:#7a9abb;--mono:'Courier New',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--navy);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;
     display:flex;min-height:100vh;font-size:14px}
/* ── Sidebar ── */
#sidebar{width:220px;min-width:220px;background:var(--panel);border-right:1px solid var(--border);
         display:flex;flex-direction:column;padding:0}
.logo{padding:20px 16px 16px;border-bottom:1px solid var(--border)}
.logo h1{font-size:15px;color:var(--cyan);font-weight:700;letter-spacing:.5px}
.logo p{font-size:11px;color:var(--muted);margin-top:3px}
nav{flex:1;padding:12px 8px}
nav a{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:6px;
      color:var(--sub);text-decoration:none;font-size:13px;margin-bottom:2px;
      cursor:pointer;transition:all .15s}
nav a:hover,nav a.active{background:var(--card);color:var(--cyan)}
nav a .icon{width:18px;text-align:center;font-size:15px}
.sidebar-status{padding:12px 16px;border-top:1px solid var(--border);font-size:11px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot.green{background:var(--green);box-shadow:0 0 6px var(--green)}
.dot.red{background:var(--red);box-shadow:0 0 6px var(--red)}
.dot.amber{background:var(--amber);box-shadow:0 0 6px var(--amber)}
.dot.grey{background:var(--muted)}
/* ── Main ── */
#main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.topbar{padding:14px 24px;border-bottom:1px solid var(--border);
        display:flex;align-items:center;justify-content:space-between;background:var(--panel)}
.topbar h2{font-size:16px;font-weight:600}
.topbar .time{font-size:12px;color:var(--muted);font-family:var(--mono)}
#content{flex:1;overflow-y:auto;padding:20px 24px}
/* ── Cards ── */
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px}
.stat-card .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px}
.stat-card .value{font-size:26px;font-weight:700;margin:6px 0 2px;font-family:var(--mono)}
.stat-card .sub{font-size:11px;color:var(--sub)}
.stat-card.cyan .value{color:var(--cyan)}
.stat-card.green .value{color:var(--green)}
.stat-card.red .value{color:var(--red)}
.stat-card.amber .value{color:var(--amber)}
/* ── Sections ── */
.section{display:none}
.section.active{display:block}
.panel{background:var(--card);border:1px solid var(--border);border-radius:8px;
       padding:18px;margin-bottom:16px}
.panel h3{font-size:13px;color:var(--cyan);font-weight:600;margin-bottom:14px;
          text-transform:uppercase;letter-spacing:.5px}
/* ── Buttons ── */
.btn{padding:8px 18px;border-radius:5px;border:none;cursor:pointer;
     font-size:13px;font-weight:600;transition:all .15s}
.btn-primary{background:var(--blue);color:#fff}
.btn-primary:hover{background:#3a8fd4}
.btn-success{background:#1a5c36;color:var(--green);border:1px solid var(--green)}
.btn-success:hover{background:#22743f}
.btn-danger{background:#5c1a1a;color:var(--red);border:1px solid var(--red)}
.btn-danger:hover{background:#742222}
.btn-amber{background:#5c3d00;color:var(--amber);border:1px solid var(--amber)}
.btn-sm{padding:5px 12px;font-size:12px}
.btn:disabled{opacity:.4;cursor:not-allowed}
/* ── Form inputs ── */
.form-row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin-bottom:12px}
.field{display:flex;flex-direction:column;gap:4px}
.field label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.field input,.field select{background:var(--panel);border:1px solid var(--border);
  color:var(--text);padding:7px 10px;border-radius:4px;font-size:13px;
  font-family:var(--mono);outline:none;min-width:120px}
.field input:focus,.field select:focus{border-color:var(--cyan)}
/* ── Progress bar ── */
.progress-wrap{margin:10px 0}
.progress-bar-bg{background:var(--panel);border-radius:4px;height:6px;overflow:hidden}
.progress-bar-fill{height:100%;background:linear-gradient(90deg,var(--blue),var(--cyan));
                   transition:width .3s;width:0%}
/* ── Alert feed ── */
#alert-feed{max-height:420px;overflow-y:auto;display:flex;flex-direction:column;gap:6px}
.alert-item{background:var(--panel);border:1px solid var(--border);border-radius:6px;
            padding:10px 14px;font-size:12px;font-family:var(--mono);
            animation:fadeIn .3s ease}
.alert-item.threat{border-left:3px solid var(--red)}
.alert-item.normal{border-left:3px solid var(--green)}
.alert-item .ah{display:flex;gap:12px;align-items:center;margin-bottom:4px}
.alert-item .cls{font-weight:700;font-size:13px}
.alert-item .cls.threat{color:var(--red)}
.alert-item .cls.normal{color:var(--green)}
.alert-item .conf{color:var(--amber)}
.alert-item .ips{color:var(--sub)}
.alert-item .report{margin-top:8px;color:var(--sub);white-space:pre-wrap;
                    border-top:1px solid var(--border);padding-top:6px;font-size:11px}
.report-btn{margin-top:6px;font-size:11px;padding:3px 8px;background:transparent;
            color:var(--cyan);border:1px solid var(--border);border-radius:3px;cursor:pointer}
/* ── Scenario buttons ── */
.scenario-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.scenario-btn{background:var(--panel);border:1px solid var(--border);border-radius:6px;
              padding:14px;cursor:pointer;text-align:left;transition:all .15s;color:var(--text)}
.scenario-btn:hover{border-color:var(--cyan);background:var(--card)}
.scenario-btn .sname{font-size:13px;font-weight:600;margin-bottom:4px}
.scenario-btn .sdesc{font-size:11px;color:var(--muted)}
.scenario-btn.normal{border-top:3px solid var(--green)}
.scenario-btn.dos{border-top:3px solid var(--red)}
.scenario-btn.probe{border-top:3px solid var(--amber)}
.scenario-btn.r2l{border-top:3px solid var(--purple)}
.scenario-btn.u2r{border-top:3px solid var(--red)}
/* ── Result box ── */
#scenario-result{background:var(--panel);border:1px solid var(--border);border-radius:6px;
                 padding:14px;margin-top:14px;font-family:var(--mono);font-size:12px;
                 white-space:pre-wrap;max-height:320px;overflow-y:auto;display:none}
/* ── Table ── */
.tbl{width:100%;border-collapse:collapse;font-size:12px}
.tbl th{text-align:left;padding:8px 10px;background:var(--panel);color:var(--muted);
        text-transform:uppercase;font-size:10px;letter-spacing:.6px;
        border-bottom:1px solid var(--border);position:sticky;top:0}
.tbl td{padding:7px 10px;border-bottom:1px solid rgba(255,255,255,.04)}
.tbl tr:hover td{background:rgba(255,255,255,.02)}
.badge{padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700}
.badge.DoS,.badge.U2R{background:#3d0000;color:var(--red)}
.badge.Probe{background:#3d2d00;color:var(--amber)}
.badge.R2L{background:#2d003d;color:var(--purple)}
.badge.Normal{background:#003d15;color:var(--green)}
.tbl-wrap{max-height:400px;overflow-y:auto;border-radius:6px;border:1px solid var(--border)}
/* ── Chart ── */
#chart-wrap{display:grid;grid-template-columns:200px 1fr;gap:16px;align-items:center}
/* ── SOC terminal ── */
#terminal{background:#000;border:1px solid var(--border);border-radius:6px;padding:14px;
          font-family:var(--mono);font-size:12px;max-height:300px;overflow-y:auto;
          color:#0f0}
#terminal .line{margin-bottom:2px}
#terminal .line.warn{color:var(--amber)}
#terminal .line.err{color:var(--red)}
#terminal .line.info{color:var(--cyan)}
/* ── Toast ── */
#toast{position:fixed;bottom:20px;right:20px;background:var(--card);border:1px solid var(--border);
       border-radius:8px;padding:12px 18px;font-size:13px;z-index:999;
       transform:translateY(80px);opacity:0;transition:all .3s;max-width:340px}
#toast.show{transform:translateY(0);opacity:1}
#toast.ok{border-left:3px solid var(--green)}
#toast.err{border-left:3px solid var(--red)}
#toast.info{border-left:3px solid var(--cyan)}
/* ── Terminal blink ── */
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
.cursor{animation:blink 1s step-end infinite;color:var(--cyan)}
@keyframes fadeIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
/* ── Probe bar ── */
.prob-row{display:flex;align-items:center;gap:8px;margin-bottom:5px;font-size:12px}
.prob-row .lbl{width:60px;color:var(--sub);text-align:right;font-family:var(--mono)}
.prob-row .bar{flex:1;height:4px;background:var(--panel);border-radius:2px;overflow:hidden}
.prob-row .fill{height:100%;background:var(--cyan);transition:width .4s}
.prob-row .pct{width:45px;color:var(--amber);font-family:var(--mono);text-align:right}
/* ── Scrollbar ── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
</style>
</head>
<body>

<!-- SIDEBAR -->
<div id="sidebar">
  <div class="logo">
    <h1>&#x1F6E1; AI-IDS</h1>
    <p>Intrusion Detection System</p>
  </div>
  <nav>
    <a href="#" class="active" onclick="showSection('dashboard');return false"><span class="icon">&#x1F4CA;</span>Dashboard</a>
    <a href="#" onclick="showSection('live');return false"><span class="icon">&#x1F30D;</span>Live Monitor</a>
    <a href="#" onclick="showSection('scenarios');return false"><span class="icon">&#x1F9EA;</span>Scenarios</a>
    <a href="#" onclick="showSection('alerts');return false"><span class="icon">&#x1F6A8;</span>Alert Log</a>
    <a href="#" onclick="showSection('custom');return false"><span class="icon">&#x1F527;</span>Custom Analyze</a>
    <a href="#" onclick="showSection('settings');return false"><span class="icon">&#x2699;&#xFE0F;</span>Settings</a>
  </nav>
  <div class="sidebar-status">
    <div style="margin-bottom:6px">
      <span class="dot" id="dot-model"></span>
      <span id="lbl-model">Model: checking…</span>
    </div>
    <div style="margin-bottom:6px">
      <span class="dot" id="dot-llm"></span>
      <span id="lbl-llm">LLM: checking…</span>
    </div>
    <div>
      <span class="dot" id="dot-capture"></span>
      <span id="lbl-capture">Capture: idle</span>
    </div>
  </div>
</div>

<!-- MAIN -->
<div id="main">
  <div class="topbar">
    <h2 id="section-title">Dashboard</h2>
    <div class="time" id="clock">--:--:--</div>
  </div>
  <div id="content">

    <!-- DASHBOARD SECTION -->
    <div class="section active" id="sec-dashboard">
      <div class="stat-row">
        <div class="stat-card cyan">
          <div class="label">Total Flows</div>
          <div class="value" id="stat-total">0</div>
          <div class="sub">analysed this session</div>
        </div>
        <div class="stat-card red">
          <div class="label">Threats Detected</div>
          <div class="value" id="stat-threats">0</div>
          <div class="sub">DoS + Probe + R2L + U2R</div>
        </div>
        <div class="stat-card green">
          <div class="label">Normal Traffic</div>
          <div class="value" id="stat-normal">0</div>
          <div class="sub">benign flows</div>
        </div>
        <div class="stat-card amber">
          <div class="label">Model Accuracy</div>
          <div class="value" id="stat-acc">--</div>
          <div class="sub" id="stat-model-name">not trained</div>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 320px;gap:16px">
        <div class="panel">
          <h3>&#x1F4FA; SOC Terminal</h3>
          <div id="terminal"><div class="line info">AI-Powered IDS Dashboard initialised.</div><div class="line info">Connect to server via Socket.IO…<span class="cursor">_</span></div></div>
        </div>
        <div class="panel">
          <h3>&#x1F4CA; Traffic Distribution</h3>
          <div id="chart-wrap">
            <canvas id="pieChart" width="190" height="190"></canvas>
            <div id="chart-legend"></div>
          </div>
        </div>
      </div>

      <div class="panel">
        <h3>&#x1F514; Recent Alerts</h3>
        <div id="alert-feed-dash"></div>
      </div>
    </div>

    <!-- LIVE MONITOR SECTION -->
    <div class="section" id="sec-live">
      <div class="panel">
        <h3>&#x1F30D; Live Traffic Capture</h3>
        <div class="form-row">
          <div class="field">
            <label>Interface</label>
            <select id="iface-select" style="width:260px">
              <option value="">Auto-detect</option>
            </select>
          </div>
          <div class="field">
            <label>Duration (seconds)</label>
            <input type="number" id="cap-duration" value="60" min="5" max="3600" style="width:100px"/>
          </div>
          <button class="btn btn-success" id="btn-start" onclick="startCapture()">&#x25B6; Start Capture</button>
          <button class="btn btn-danger" id="btn-stop" onclick="stopCapture()" disabled>&#x23F9; Stop</button>
        </div>
        <div id="cap-status" style="font-size:12px;color:var(--sub);margin-top:6px"></div>
      </div>

      <div class="panel">
        <h3>&#x26A1; Real-Time Alert Feed</h3>
        <div id="alert-feed"></div>
      </div>
    </div>

    <!-- SCENARIOS SECTION -->
    <div class="section" id="sec-scenarios">
      <div class="panel">
        <h3>&#x1F9EA; Demo Attack Scenarios</h3>
        <p style="font-size:12px;color:var(--sub);margin-bottom:14px">
          Click a scenario to run it through the trained ML model and get an AI threat analysis.
        </p>
        <div class="scenario-grid">
          <div class="scenario-btn normal" onclick="runScenario('normal')">
            <div class="sname">&#x1F7E2; Normal Traffic</div>
            <div class="sdesc">Standard HTTP web browsing session</div>
          </div>
          <div class="scenario-btn dos" onclick="runScenario('dos')">
            <div class="sname">&#x1F534; DoS Attack</div>
            <div class="sdesc">Neptune SYN flood — serror_rate=1.0</div>
          </div>
          <div class="scenario-btn probe" onclick="runScenario('probe')">
            <div class="sname">&#x1F7E1; Port Scan</div>
            <div class="sdesc">Nmap reconnaissance — diff_srv_rate=0.99</div>
          </div>
          <div class="scenario-btn r2l" onclick="runScenario('r2l')">
            <div class="sname">&#x1F7E3; R2L Attack</div>
            <div class="sdesc">Password guessing — failed_logins=5</div>
          </div>
          <div class="scenario-btn u2r" onclick="runScenario('u2r')">
            <div class="sname">&#x1F534; U2R Attack</div>
            <div class="sdesc">Buffer overflow — root_shell=1</div>
          </div>
        </div>
        <div id="scenario-result"></div>
      </div>
    </div>

    <!-- ALERTS TABLE SECTION -->
    <div class="section" id="sec-alerts">
      <div class="panel">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <h3 style="margin:0">&#x1F6A8; Alert History</h3>
          <button class="btn btn-sm btn-danger" onclick="clearAlerts()">Clear All</button>
        </div>
        <div class="tbl-wrap">
          <table class="tbl">
            <thead>
              <tr>
                <th>#</th><th>Time</th><th>Class</th><th>Confidence</th>
                <th>Src IP</th><th>Dst IP</th><th>Service</th><th>Flag</th><th>Bytes</th>
              </tr>
            </thead>
            <tbody id="alert-table-body"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- CUSTOM ANALYZE SECTION -->
    <div class="section" id="sec-custom">
      <div class="panel">
        <h3>&#x1F527; Custom Traffic Analyzer</h3>
        <p style="font-size:12px;color:var(--sub);margin-bottom:14px">
          Enter traffic features manually and get an ML prediction + LLM threat report.
        </p>
        <div class="form-row">
          <div class="field"><label>Protocol</label>
            <select id="c-proto"><option>tcp</option><option>udp</option><option>icmp</option></select></div>
          <div class="field"><label>Service</label>
            <select id="c-svc"><option>http</option><option>ftp</option><option>smtp</option>
              <option>ssh</option><option>telnet</option><option>dns</option><option>other</option></select></div>
          <div class="field"><label>Flag</label>
            <select id="c-flag"><option>SF</option><option>S0</option><option>REJ</option>
              <option>RSTO</option><option>SH</option></select></div>
          <div class="field"><label>Duration(s)</label>
            <input type="number" id="c-duration" value="0" min="0" style="width:80px"/></div>
        </div>
        <div class="form-row">
          <div class="field"><label>Src Bytes</label>
            <input type="number" id="c-src-bytes" value="0" min="0" style="width:110px"/></div>
          <div class="field"><label>Dst Bytes</label>
            <input type="number" id="c-dst-bytes" value="0" min="0" style="width:110px"/></div>
          <div class="field"><label>Count</label>
            <input type="number" id="c-count" value="1" min="0" style="width:80px"/></div>
          <div class="field"><label>Serror Rate</label>
            <input type="number" id="c-serr" value="0" min="0" max="1" step="0.01" style="width:100px"/></div>
          <div class="field"><label>Failed Logins</label>
            <input type="number" id="c-fail" value="0" min="0" style="width:100px"/></div>
        </div>
        <div class="form-row">
          <div class="field"><label>Logged In</label>
            <select id="c-logged"><option value="0">No</option><option value="1">Yes</option></select></div>
          <div class="field"><label>Root Shell</label>
            <select id="c-root"><option value="0">No</option><option value="1">Yes</option></select></div>
          <div class="field"><label>Dst Host Count</label>
            <input type="number" id="c-dhcount" value="1" min="0" style="width:120px"/></div>
          <div class="field"><label>Same Srv Rate</label>
            <input type="number" id="c-ssr" value="1.0" min="0" max="1" step="0.01" style="width:110px"/></div>
          <button class="btn btn-primary" onclick="runCustom()" style="align-self:flex-end">Analyze</button>
        </div>
        <div id="custom-result" style="display:none;margin-top:12px">
          <div id="custom-result-content"></div>
        </div>
      </div>
    </div>

    <!-- SETTINGS SECTION -->
    <div class="section" id="sec-settings">
      <div class="panel">
        <h3>&#x2699; Model Management</h3>
        <p style="font-size:12px;color:var(--sub);margin-bottom:14px">
          Train the ML models on synthetic KDD data. This takes ~2–3 minutes.
          Trained artefacts are saved and reloaded automatically next time.
        </p>
        <button class="btn btn-primary" onclick="trainModel()" id="btn-train">
          &#x1F916; Train Models Now
        </button>
        <div id="train-status" style="margin-top:12px;display:none">
          <div id="train-msg" style="font-size:12px;color:var(--sub);margin-bottom:6px"></div>
          <div class="progress-wrap">
            <div class="progress-bar-bg"><div class="progress-bar-fill" id="train-bar"></div></div>
          </div>
        </div>
      </div>

      <div class="panel">
        <h3>&#x1F511; LLM API Keys</h3>
        <p style="font-size:12px;color:var(--sub);margin-bottom:14px">
          Provide an API key to enable AI-generated threat explanations.
          Keys are stored in memory for this session only. For persistence, add to your .env file.
        </p>
        <div class="form-row">
          <div class="field" style="flex:1">
            <label>Anthropic API Key (Claude)</label>
            <input type="password" id="inp-anthropic" placeholder="sk-ant-…" style="width:100%"/>
          </div>
        </div>
        <div class="form-row">
          <div class="field" style="flex:1">
            <label>Google API Key (Gemini)</label>
            <input type="password" id="inp-google" placeholder="AIza…" style="width:100%"/>
          </div>
        </div>
        <button class="btn btn-primary" onclick="saveKeys()">Save &amp; Test Keys</button>
        <div id="key-status" style="margin-top:10px;font-size:12px"></div>
      </div>
    </div>

  </div><!-- /content -->
</div><!-- /main -->

<div id="toast"></div>

<script>
// ── Socket.IO ────────────────────────────────────────────────────────────────
const socket = io();
let alertCount = 0;
let chartData  = {Normal:0, DoS:0, Probe:0, R2L:0, U2R:0};
let pieChart   = null;

socket.on('connect', () => {
  term('info', 'Socket.IO connected to server.');
});
socket.on('disconnect', () => {
  term('warn', 'Socket.IO disconnected.');
});
socket.on('status', d => updateSidebarStatus(d));

socket.on('train_progress', d => {
  document.getElementById('train-msg').textContent = d.msg;
  document.getElementById('train-bar').style.width = d.pct + '%';
  document.getElementById('train-status').style.display = 'block';
  term('info', '[Train] ' + d.msg + ' (' + d.pct + '%)');
});
socket.on('train_done', d => {
  document.getElementById('btn-train').disabled = false;
  updateSidebarStatus({model_ready:true});
  document.getElementById('stat-acc').textContent = (d.accuracy*100).toFixed(1) + '%';
  document.getElementById('stat-model-name').textContent = d.model_name;
  toast('Model trained: ' + d.model_name + ' (' + (d.accuracy*100).toFixed(1) + '%)', 'ok');
  term('info', '[Train] Done — ' + d.msg);
  fetchStatus();
});
socket.on('train_error', d => {
  toast('Training failed: ' + d.msg, 'err');
  term('err', '[Train ERROR] ' + d.msg);
  document.getElementById('btn-train').disabled = false;
});

socket.on('capture_status', d => {
  const el = document.getElementById('cap-status');
  const dot = document.getElementById('dot-capture');
  const lbl = document.getElementById('lbl-capture');
  if (d.status === 'running' || d.status === 'starting') {
    el.textContent = '🟢 Capturing on ' + (d.iface||'auto') + ' for ' + (d.duration||'?') + 's…';
    dot.className='dot green'; lbl.textContent='Capture: live';
    document.getElementById('btn-start').disabled=true;
    document.getElementById('btn-stop').disabled=false;
    term('info', '[Live] Capture started on ' + (d.iface||'auto'));
  } else if (d.status === 'stopped') {
    el.textContent = '⏹ Capture stopped. Total flows: ' + (d.total||0);
    dot.className='dot grey'; lbl.textContent='Capture: idle';
    document.getElementById('btn-start').disabled=false;
    document.getElementById('btn-stop').disabled=true;
    term('info', '[Live] Capture stopped.');
  } else if (d.status === 'error') {
    el.textContent = '❌ Error: ' + d.msg;
    dot.className='dot red'; lbl.textContent='Capture: error';
    document.getElementById('btn-start').disabled=false;
    document.getElementById('btn-stop').disabled=true;
    toast('Capture error: ' + d.msg, 'err');
    term('err', '[Live ERROR] ' + d.msg);
  }
});

socket.on('new_alert', alert => {
  appendAlert(alert);
  updateStats(alert);
  term(alert.threat ? 'warn' : 'info',
    '[Alert] ' + alert.cls + ' (' + alert.conf + ') ' + alert.src + ' → ' + alert.dst);
});

socket.on('stats_update', d => {
  document.getElementById('stat-total').textContent = d.total;
  let threats = (d.counts.DoS||0)+(d.counts.Probe||0)+(d.counts.R2L||0)+(d.counts.U2R||0);
  document.getElementById('stat-threats').textContent = threats;
  document.getElementById('stat-normal').textContent = d.counts.Normal||0;
  Object.assign(chartData, d.counts);
  updateChart();
});

socket.on('scenario_result', d => {
  if (d.error) { toast(d.error,'err'); return; }
  showScenarioResult(d);
});

// ── Section navigation ────────────────────────────────────────────────────────
const TITLES = {
  dashboard:'Dashboard', live:'Live Monitor', scenarios:'Scenarios',
  alerts:'Alert Log', custom:'Custom Analyze', settings:'Settings'
};
function showSection(name) {
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
  document.querySelectorAll('nav a').forEach(a=>a.classList.remove('active'));
  document.getElementById('sec-'+name).classList.add('active');
  document.querySelectorAll('nav a').forEach(a=>{
    if(a.getAttribute('onclick')&&a.getAttribute('onclick').includes("'"+name+"'"))
      a.classList.add('active');
  });
  document.getElementById('section-title').textContent = TITLES[name]||name;
}

// ── Status fetch ──────────────────────────────────────────────────────────────
function fetchStatus() {
  fetch('/api/status').then(r=>r.json()).then(d => {
    updateSidebarStatus(d);
    document.getElementById('stat-acc').textContent = d.model_ready ? (d.model_acc*100).toFixed(1)+'%' : '--';
    document.getElementById('stat-model-name').textContent = d.model_ready ? d.model_name : 'not trained';
    document.getElementById('stat-total').textContent = d.total_flows;
    let threats = (d.class_counts.DoS||0)+(d.class_counts.Probe||0)+(d.class_counts.R2L||0)+(d.class_counts.U2R||0);
    document.getElementById('stat-threats').textContent = threats;
    document.getElementById('stat-normal').textContent = d.class_counts.Normal||0;
    Object.assign(chartData, d.class_counts);
    updateChart();
  });
}

function updateSidebarStatus(d) {
  const dm=document.getElementById('dot-model'),lm=document.getElementById('lbl-model');
  const dl=document.getElementById('dot-llm'),ll=document.getElementById('lbl-llm');
  if (d.model_ready) { dm.className='dot green'; lm.textContent='Model: ready'; }
  else               { dm.className='dot amber'; lm.textContent='Model: not trained'; }
  if (d.llm_enabled) { dl.className='dot green'; ll.textContent='LLM: '+d.llm_provider; }
  else               { dl.className='dot grey';  ll.textContent='LLM: fallback'; }
}

// ── Interfaces ────────────────────────────────────────────────────────────────
function loadInterfaces() {
  fetch('/api/interfaces').then(r=>r.json()).then(ifaces => {
    const sel = document.getElementById('iface-select');
    ifaces.forEach(i => {
      const opt = document.createElement('option');
      opt.value = i.name;
      opt.textContent = i.name + (i.ips.length ? ' ['+i.ips[0]+']' : '') + ' — '+i.desc;
      sel.appendChild(opt);
    });
  });
}

// ── Capture controls ──────────────────────────────────────────────────────────
function startCapture() {
  const iface    = document.getElementById('iface-select').value;
  const duration = parseInt(document.getElementById('cap-duration').value)||60;
  socket.emit('start_capture', {iface, duration});
  showSection('live');
}
function stopCapture() {
  socket.emit('stop_capture');
}

// ── Train model ───────────────────────────────────────────────────────────────
function trainModel() {
  document.getElementById('btn-train').disabled=true;
  document.getElementById('train-status').style.display='block';
  document.getElementById('train-bar').style.width='0%';
  socket.emit('train');
  toast('Model training started…','info');
  term('info','[Train] Starting model training…');
}

// ── Scenarios ─────────────────────────────────────────────────────────────────
const SCENARIOS = {
  normal:  {name:'Normal Web Browsing',
    traffic:{duration:0.5,protocol_type:'tcp',service:'http',flag:'SF',
      src_bytes:215,dst_bytes:45076,land:0,wrong_fragment:0,urgent:0,hot:0,
      num_failed_logins:0,logged_in:1,num_compromised:0,root_shell:0,su_attempted:0,
      num_root:0,num_file_creations:0,num_shells:0,num_access_files:0,is_guest_login:0,
      count:9,srv_count:9,serror_rate:0.0,rerror_rate:0.0,same_srv_rate:1.0,diff_srv_rate:0.0,
      dst_host_count:9,dst_host_srv_count:9,dst_host_same_srv_rate:1.0,
      dst_host_serror_rate:0.0,dst_host_rerror_rate:0.0}},
  dos:     {name:'DoS Attack (Neptune)',
    traffic:{duration:0,protocol_type:'tcp',service:'http',flag:'S0',src_bytes:0,dst_bytes:0,
      land:0,wrong_fragment:0,urgent:0,hot:0,num_failed_logins:0,logged_in:0,num_compromised:0,
      root_shell:0,su_attempted:0,num_root:0,num_file_creations:0,num_shells:0,num_access_files:0,
      is_guest_login:0,count:511,srv_count:511,serror_rate:1.0,rerror_rate:0.0,same_srv_rate:1.0,
      diff_srv_rate:0.0,dst_host_count:255,dst_host_srv_count:255,dst_host_same_srv_rate:1.0,
      dst_host_serror_rate:1.0,dst_host_rerror_rate:0.0}},
  probe:   {name:'Port Scan (Nmap)',
    traffic:{duration:0,protocol_type:'tcp',service:'other',flag:'REJ',src_bytes:0,dst_bytes:0,
      land:0,wrong_fragment:0,urgent:0,hot:0,num_failed_logins:0,logged_in:0,num_compromised:0,
      root_shell:0,su_attempted:0,num_root:0,num_file_creations:0,num_shells:0,num_access_files:0,
      is_guest_login:0,count:159,srv_count:1,serror_rate:0.0,rerror_rate:1.0,same_srv_rate:0.01,
      diff_srv_rate:0.99,dst_host_count:255,dst_host_srv_count:1,dst_host_same_srv_rate:0.0,
      dst_host_serror_rate:0.0,dst_host_rerror_rate:0.26}},
  r2l:     {name:'R2L (Password Guessing)',
    traffic:{duration:2,protocol_type:'tcp',service:'ftp',flag:'SF',src_bytes:772,dst_bytes:0,
      land:0,wrong_fragment:0,urgent:0,hot:0,num_failed_logins:5,logged_in:0,num_compromised:0,
      root_shell:0,su_attempted:0,num_root:0,num_file_creations:0,num_shells:0,num_access_files:0,
      is_guest_login:0,count:1,srv_count:1,serror_rate:0.0,rerror_rate:0.0,same_srv_rate:1.0,
      diff_srv_rate:0.0,dst_host_count:1,dst_host_srv_count:1,dst_host_same_srv_rate:1.0,
      dst_host_serror_rate:0.0,dst_host_rerror_rate:0.0}},
  u2r:     {name:'U2R (Buffer Overflow)',
    traffic:{duration:0,protocol_type:'tcp',service:'telnet',flag:'SF',src_bytes:721,dst_bytes:18949,
      land:0,wrong_fragment:0,urgent:0,hot:2,num_failed_logins:0,logged_in:1,num_compromised:1,
      root_shell:1,su_attempted:0,num_root:0,num_file_creations:1,num_shells:1,num_access_files:0,
      is_guest_login:0,count:1,srv_count:1,serror_rate:0.0,rerror_rate:0.0,same_srv_rate:1.0,
      diff_srv_rate:0.0,dst_host_count:1,dst_host_srv_count:1,dst_host_same_srv_rate:1.0,
      dst_host_serror_rate:0.0,dst_host_rerror_rate:0.0}},
};
function runScenario(key) {
  const sc = SCENARIOS[key];
  socket.emit('run_scenario', {name: sc.name, traffic: sc.traffic});
  document.getElementById('scenario-result').style.display='block';
  document.getElementById('scenario-result').textContent = 'Analysing '+sc.name+'…';
}
function showScenarioResult(d) {
  const el   = document.getElementById('scenario-result');
  const icon = d.threat ? '🔴' : '🟢';
  const bars = Object.entries(d.probas).sort((a,b)=>b[1]-a[1]).map(([k,v])=>
    `<div class="prob-row"><span class="lbl">${k}</span><div class="bar"><div class="fill" style="width:${v*100}%"></div></div><span class="pct">${(v*100).toFixed(1)}%</span></div>`
  ).join('');
  el.style.display='block';
  el.innerHTML = `<div style="margin-bottom:10px">
    <strong>${icon} ${d.name}</strong> →
    <span style="color:${d.threat?'var(--red)':'var(--green)'}">${d.class.toUpperCase()}</span>
    <span style="color:var(--amber);margin-left:8px">${(d.conf*100).toFixed(1)}% confidence</span>
  </div>
  <div style="margin-bottom:10px">${bars}</div>
  <div style="border-top:1px solid var(--border);padding-top:10px;font-size:12px;color:var(--sub);white-space:pre-wrap;">${d.report}</div>`;
}

// ── Custom analyzer ───────────────────────────────────────────────────────────
function runCustom() {
  const traffic = {
    duration        : parseFloat(document.getElementById('c-duration').value)||0,
    protocol_type   : document.getElementById('c-proto').value,
    service         : document.getElementById('c-svc').value,
    flag            : document.getElementById('c-flag').value,
    src_bytes       : parseInt(document.getElementById('c-src-bytes').value)||0,
    dst_bytes       : parseInt(document.getElementById('c-dst-bytes').value)||0,
    count           : parseInt(document.getElementById('c-count').value)||0,
    serror_rate     : parseFloat(document.getElementById('c-serr').value)||0,
    num_failed_logins: parseInt(document.getElementById('c-fail').value)||0,
    logged_in       : parseInt(document.getElementById('c-logged').value)||0,
    root_shell      : parseInt(document.getElementById('c-root').value)||0,
    dst_host_count  : parseInt(document.getElementById('c-dhcount').value)||0,
    same_srv_rate   : parseFloat(document.getElementById('c-ssr').value)||1.0,
    diff_srv_rate   : 1 - (parseFloat(document.getElementById('c-ssr').value)||1.0),
    rerror_rate     : 0, land:0, wrong_fragment:0, urgent:0, hot:0,
    num_compromised:0, su_attempted:0, num_root:0, num_file_creations:0,
    num_shells:0, num_access_files:0, is_guest_login:0, srv_count:1,
    dst_host_srv_count:1, dst_host_same_srv_rate:1.0,
    dst_host_serror_rate:0, dst_host_rerror_rate:0,
  };
  fetch('/api/predict', {method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(traffic)})
  .then(r=>r.json()).then(d => {
    if (d.error) { toast(d.error,'err'); return; }
    const icon = d.class!=='Normal' ? '🔴' : '🟢';
    const bars = Object.entries(d.probas).sort((a,b)=>b[1]-a[1]).map(([k,v])=>
      `<div class="prob-row"><span class="lbl">${k}</span><div class="bar"><div class="fill" style="width:${v*100}%"></div></div><span class="pct">${(v*100).toFixed(1)}%</span></div>`
    ).join('');
    document.getElementById('custom-result').style.display='block';
    document.getElementById('custom-result-content').innerHTML =
      `<div style="margin-bottom:8px">${icon} <strong>${d.class.toUpperCase()}</strong>
       <span style="color:var(--amber);margin-left:8px">${(d.confidence*100).toFixed(1)}% confidence</span></div>
       ${bars}
       <div style="border-top:1px solid var(--border);padding-top:10px;margin-top:10px;
           font-size:12px;color:var(--sub);white-space:pre-wrap;">${d.report}</div>`;
  });
}

// ── Alerts ────────────────────────────────────────────────────────────────────
function appendAlert(a) {
  alertCount++;
  const cls    = a.threat ? 'threat' : 'normal';
  const icon   = a.threat ? '🔴' : '🟢';
  const html   = `<div class="alert-item ${cls}" id="alert-${a.id}">
    <div class="ah">
      <span class="cls ${cls}">${icon} ${a.cls.toUpperCase()}</span>
      <span class="conf">${a.conf}</span>
      <span class="ips">${a.src} → ${a.dst}</span>
      <span style="color:var(--sub)">${a.proto} / ${a.svc} / ${a.flag}</span>
      <span style="color:var(--sub);margin-left:auto">${a.ts}</span>
    </div>
    <div style="font-size:11px;color:var(--muted)">${a.src_bytes.toLocaleString()} bytes</div>
    ${a.report ? `<button class="report-btn" onclick="toggleReport('ar-${a.id}')">Show AI Report</button>
    <div id="ar-${a.id}" class="report" style="display:none">${a.report}</div>` : ''}
  </div>`;

  // Live feed
  const feed = document.getElementById('alert-feed');
  feed.insertAdjacentHTML('afterbegin', html);
  if (feed.children.length > 100) feed.removeChild(feed.lastChild);

  // Dashboard feed (top 5 only)
  const dfeed = document.getElementById('alert-feed-dash');
  dfeed.insertAdjacentHTML('afterbegin', html.replace('id="alert-','id="d-alert-'));
  if (dfeed.children.length > 5) dfeed.removeChild(dfeed.lastChild);

  // Table row
  const tbody = document.getElementById('alert-table-body');
  const row = `<tr>
    <td>${a.id}</td><td>${a.ts}</td>
    <td><span class="badge ${a.cls}">${a.cls}</span></td>
    <td style="color:var(--amber)">${a.conf}</td>
    <td>${a.src}</td><td>${a.dst}</td>
    <td>${a.svc}</td><td>${a.flag}</td>
    <td>${(a.src_bytes||0).toLocaleString()}</td>
  </tr>`;
  tbody.insertAdjacentHTML('afterbegin', row);
  if (tbody.children.length > 200) tbody.removeChild(tbody.lastChild);
}

function toggleReport(id) {
  const el=document.getElementById(id);
  el.style.display=el.style.display==='none'?'block':'none';
}

function updateStats(a) {
  chartData[a.cls] = (chartData[a.cls]||0) + 1;
  updateChart();
}

function clearAlerts() {
  fetch('/api/clear_alerts', {method:'POST'}).then(() => {
    document.getElementById('alert-table-body').innerHTML='';
    document.getElementById('alert-feed').innerHTML='';
    document.getElementById('alert-feed-dash').innerHTML='';
    document.getElementById('stat-total').textContent='0';
    document.getElementById('stat-threats').textContent='0';
    document.getElementById('stat-normal').textContent='0';
    Object.keys(chartData).forEach(k=>chartData[k]=0);
    updateChart();
    toast('Alerts cleared','info');
  });
}

// ── Chart ─────────────────────────────────────────────────────────────────────
function initChart() {
  const ctx = document.getElementById('pieChart').getContext('2d');
  pieChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Normal','DoS','Probe','R2L','U2R'],
      datasets:[{data:[0,0,0,0,0], backgroundColor:['#00e676','#ff1744','#ffb300','#b388ff','#ff5722'],
        borderColor:'#0c1829', borderWidth:2}]
    },
    options:{
      plugins:{legend:{display:false}},
      cutout:'68%',
      animation:{duration:400},
    }
  });
}
function updateChart() {
  if (!pieChart) return;
  const vals=[chartData.Normal||0,chartData.DoS||0,chartData.Probe||0,chartData.R2L||0,chartData.U2R||0];
  pieChart.data.datasets[0].data = vals;
  pieChart.update();
  const total=vals.reduce((a,b)=>a+b,0)||1;
  const colors=['#00e676','#ff1744','#ffb300','#b388ff','#ff5722'];
  const labels=['Normal','DoS','Probe','R2L','U2R'];
  document.getElementById('chart-legend').innerHTML = labels.map((l,i)=>
    `<div style="display:flex;align-items:center;gap:6px;margin-bottom:5px;font-size:12px">
       <div style="width:10px;height:10px;border-radius:2px;background:${colors[i]}"></div>
       <span style="color:var(--sub);width:50px">${l}</span>
       <span style="color:var(--text);font-family:var(--mono)">${vals[i]}</span>
       <span style="color:var(--muted)">${(vals[i]/total*100).toFixed(0)}%</span>
     </div>`
  ).join('');
}

// ── Keys ──────────────────────────────────────────────────────────────────────
function saveKeys() {
  const anthropic_key = document.getElementById('inp-anthropic').value.trim();
  const google_key    = document.getElementById('inp-google').value.trim();
  fetch('/api/set_keys',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({anthropic_key, google_key})})
  .then(r=>r.json()).then(d=>{
    const status = document.getElementById('key-status');
    if(d.llm_enabled){
      status.innerHTML='<span style="color:var(--green)">✅ LLM enabled via '+d.llm_provider+'</span>';
      toast('LLM activated ('+d.llm_provider+')','ok');
    } else {
      status.innerHTML='<span style="color:var(--amber)">⚠️ Key invalid or API error — fallback mode</span>';
    }
    updateSidebarStatus(d);
  });
}

// ── Terminal ──────────────────────────────────────────────────────────────────
function term(type, msg) {
  const el = document.getElementById('terminal');
  const ts = new Date().toLocaleTimeString();
  const div = document.createElement('div');
  div.className='line '+(type==='warn'?'warn':type==='err'?'err':'info');
  div.textContent = '['+ts+'] '+msg;
  el.appendChild(div);
  if(el.children.length>200) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}

// ── Toast ─────────────────────────────────────────────────────────────────────
let toastTimer;
function toast(msg, type='info') {
  const el=document.getElementById('toast');
  el.textContent=msg; el.className='show '+(type||'info');
  clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>el.className='',3500);
}

// ── Clock ─────────────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock,1000); updateClock();

// ── Init ──────────────────────────────────────────────────────────────────────
initChart();
fetchStatus();
loadInterfaces();
</script>
</body>
</html>"""


# ── Startup ───────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='AI-IDS Web Dashboard')
    parser.add_argument('--port',    type=int, default=5000)
    parser.add_argument('--host',    type=str, default='0.0.0.0')
    parser.add_argument('--no-retrain', action='store_true',
                        help='Load saved model instead of retraining')
    args = parser.parse_args()

    print('\n' + '='*60)
    print('  🛡  AI-Powered IDS — Web Dashboard')
    print('='*60)

    _init_llm()
    print(f'  LLM: {"✅ " + state["llm_provider"] if state["llm_enabled"] else "⚠️  fallback mode"}')

    if load_saved_models():
        print(f'  Model: ✅ loaded ({state["best_model_name"]})')
    else:
        print('  Model: ⚠️  no saved model — train via the dashboard Settings tab')

    print(f'\n  🌐 Dashboard → http://localhost:{args.port}')
    print(f'  Press Ctrl+C to stop.\n' + '='*60 + '\n')

    socketio.run(app, host=args.host, port=args.port, debug=False,
                 use_reloader=False, allow_unsafe_werkzeug=True)
