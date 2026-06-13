"""
test_attacks.py  —  AI-Powered IDS Attack Simulator
=====================================================
Sends realistic attack scenarios to the running IDS dashboard,
shows detection results in the terminal, and pushes every alert
to the live browser dashboard via Socket.IO.

Usage:
    python test_attacks.py              # run all scenarios
    python test_attacks.py --open       # also opens browser tab
    python test_attacks.py --scenario dos  # run only DoS scenarios
    python test_attacks.py --delay 0.5  # seconds between requests

Requirements:
    pip install requests
    server.py must be running on http://localhost:5000
"""

import sys, time, json, argparse, urllib.request, urllib.error

# ── Terminal colour helpers (no extra deps) ───────────────────────────────────
RESET  = '\033[0m'
BOLD   = '\033[1m'
RED    = '\033[91m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
MAGENTA= '\033[95m'
WHITE  = '\033[97m'
DIM    = '\033[2m'

def _c(text, colour):
    """Wrap text in ANSI colour codes (skipped on Windows unless ANSI is enabled)."""
    if sys.platform == 'win32':
        # Enable virtual terminal processing on Windows
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            return text
    return f'{colour}{text}{RESET}'

def banner(title):
    width = 72
    print()
    print(_c('=' * width, CYAN))
    print(_c(f'  {title}', BOLD + CYAN))
    print(_c('=' * width, CYAN))

def section(title):
    print()
    print(_c(f'── {title} ', YELLOW) + _c('─' * (60 - len(title)), DIM))

# ── Scenario definitions ──────────────────────────────────────────────────────
# Each scenario is a dict with:
#   label   : human name shown in terminal
#   category: expected attack category
#   src_ip / dst_ip: shown in alert feed
#   traffic : the 31 KDD-style features sent to /api/simulate

SCENARIOS = [

    # ── Normal traffic ────────────────────────────────────────────────────────
    {
        'label': 'Normal HTTP Web Browse',
        'category': 'Normal',
        'src_ip': '192.168.1.100',
        'dst_ip': '93.184.216.34',
        'traffic': {
            'duration': 2.3, 'protocol_type': 'tcp', 'service': 'http',
            'flag': 'SF', 'src_bytes': 512, 'dst_bytes': 8192,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 1, 'num_failed_logins': 0, 'logged_in': 1,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
            'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            'count': 5, 'srv_count': 5, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        },
    },

    {
        'label': 'Normal FTP File Transfer',
        'category': 'Normal',
        'src_ip': '10.0.0.5',
        'dst_ip': '10.0.0.20',
        'traffic': {
            'duration': 45.1, 'protocol_type': 'tcp', 'service': 'ftp',
            'flag': 'SF', 'src_bytes': 4096, 'dst_bytes': 204800,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 2, 'num_failed_logins': 0, 'logged_in': 1,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
            'num_root': 0, 'num_file_creations': 1, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            'count': 3, 'srv_count': 3, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        },
    },

    # ── DoS — Denial of Service ───────────────────────────────────────────────
    {
        'label': 'DoS — SYN Flood (Neptune)',
        'category': 'DoS',
        'src_ip': '185.220.101.47',
        'dst_ip': '192.168.1.1',
        'traffic': {
            'duration': 0.0, 'protocol_type': 'tcp', 'service': 'http',
            'flag': 'S0', 'src_bytes': 0, 'dst_bytes': 0,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
            'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            'count': 511, 'srv_count': 511, 'serror_rate': 1.0,
            'srv_serror_rate': 1.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.02,
        },
    },

    {
        'label': 'DoS — ICMP Smurf Amplification',
        'category': 'DoS',
        'src_ip': '203.0.113.42',
        'dst_ip': '192.168.1.1',
        'traffic': {
            'duration': 0.0, 'protocol_type': 'icmp', 'service': 'eco_i',
            'flag': 'SF', 'src_bytes': 1032, 'dst_bytes': 0,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
            'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            'count': 511, 'srv_count': 511, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        },
    },

    {
        'label': 'DoS — UDP Flood',
        'category': 'DoS',
        'src_ip': '198.51.100.77',
        'dst_ip': '192.168.1.5',
        'traffic': {
            'duration': 0.0, 'protocol_type': 'udp', 'service': 'domain_u',
            'flag': 'SF', 'src_bytes': 28, 'dst_bytes': 0,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
            'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            'count': 511, 'srv_count': 511, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.01,
        },
    },

    # ── Probe — Reconnaissance ────────────────────────────────────────────────
    {
        'label': 'Probe — TCP Port Scan (portsweep)',
        'category': 'Probe',
        'src_ip': '10.0.0.50',
        'dst_ip': '192.168.1.1',
        'traffic': {
            'duration': 0.0, 'protocol_type': 'tcp', 'service': 'http',
            'flag': 'REJ', 'src_bytes': 0, 'dst_bytes': 0,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
            'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 1.0,
            'srv_rerror_rate': 1.0, 'same_srv_rate': 0.06,
            'diff_srv_rate': 0.07, 'srv_diff_host_rate': 1.0,
        },
    },

    {
        'label': 'Probe — Nmap OS Detection Scan',
        'category': 'Probe',
        'src_ip': '172.16.0.99',
        'dst_ip': '192.168.1.10',
        'traffic': {
            'duration': 1.0, 'protocol_type': 'tcp', 'service': 'finger',
            'flag': 'S1', 'src_bytes': 216, 'dst_bytes': 0,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
            'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            'count': 6, 'srv_count': 6, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.5,
            'srv_rerror_rate': 0.5, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.4,
        },
    },

    # ── R2L — Remote to Local ─────────────────────────────────────────────────
    {
        'label': 'R2L — FTP Brute Force Login',
        'category': 'R2L',
        'src_ip': '45.33.32.156',
        'dst_ip': '192.168.1.20',
        'traffic': {
            'duration': 8.7, 'protocol_type': 'tcp', 'service': 'ftp',
            'flag': 'SF', 'src_bytes': 3140, 'dst_bytes': 1842,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 1, 'num_failed_logins': 8, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
            'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            'count': 20, 'srv_count': 20, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        },
    },

    {
        'label': 'R2L — SSH Credential Stuffing',
        'category': 'R2L',
        'src_ip': '94.102.49.190',
        'dst_ip': '192.168.1.10',
        'traffic': {
            'duration': 0.3, 'protocol_type': 'tcp', 'service': 'ssh',
            'flag': 'SF', 'src_bytes': 2000, 'dst_bytes': 2000,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 0, 'num_failed_logins': 5, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
            'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            'count': 511, 'srv_count': 511, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 0.75,
            'diff_srv_rate': 0.06, 'srv_diff_host_rate': 0.0,
        },
    },

    # ── U2R — User to Root ────────────────────────────────────────────────────
    {
        'label': 'U2R — Buffer Overflow Exploit',
        'category': 'U2R',
        'src_ip': '192.168.1.50',
        'dst_ip': '192.168.1.1',
        'traffic': {
            'duration': 0.1, 'protocol_type': 'tcp', 'service': 'telnet',
            'flag': 'SF', 'src_bytes': 1440, 'dst_bytes': 4800,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 2, 'num_failed_logins': 0, 'logged_in': 1,
            'num_compromised': 1, 'root_shell': 1, 'su_attempted': 1,
            'num_root': 3, 'num_file_creations': 1, 'num_shells': 1,
            'num_access_files': 2, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        },
    },

    {
        'label': 'U2R — Rootkit / sudo Abuse',
        'category': 'U2R',
        'src_ip': '192.168.1.55',
        'dst_ip': '192.168.1.1',
        'traffic': {
            'duration': 2.0, 'protocol_type': 'tcp', 'service': 'telnet',
            'flag': 'SF', 'src_bytes': 3612, 'dst_bytes': 5688,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0,
            'hot': 4, 'num_failed_logins': 0, 'logged_in': 1,
            'num_compromised': 3, 'root_shell': 1, 'su_attempted': 1,
            'num_root': 6, 'num_file_creations': 2, 'num_shells': 2,
            'num_access_files': 3, 'num_outbound_cmds': 0,
            'is_host_login': 1, 'is_guest_login': 0,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0,
            'srv_serror_rate': 0.0, 'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
        },
    },
]

# ── Severity colour map ───────────────────────────────────────────────────────
SEV_COLOUR = {
    'Normal': GREEN,
    'DoS'   : RED,
    'Probe' : YELLOW,
    'R2L'   : MAGENTA,
    'U2R'   : RED + BOLD,
}

# ── HTTP helper (no requests dep) ────────────────────────────────────────────
SERVER = 'http://localhost:5000'

def _post(path, payload):
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        SERVER + path,
        data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

def _get(path):
    with urllib.request.urlopen(SERVER + path, timeout=10) as r:
        return json.loads(r.read().decode())

# ── Probability bar ───────────────────────────────────────────────────────────
def prob_bar(val, width=20):
    filled = int(val * width)
    bar    = '█' * filled + '░' * (width - filled)
    pct    = f'{val:5.1%}'
    return f'[{bar}] {pct}'

# ── Feature table printer ─────────────────────────────────────────────────────
def print_features(traffic):
    features = [
        ('protocol_type', 'Protocol  '), ('service',       'Service   '),
        ('flag',          'Flag      '), ('duration',      'Duration  '),
        ('src_bytes',     'Src Bytes '), ('dst_bytes',     'Dst Bytes '),
        ('logged_in',     'Logged In '), ('num_failed_logins', 'Failed Logins'),
        ('root_shell',    'Root Shell'), ('su_attempted',  'SU Attempt'),
        ('num_root',      'Root Cmds '), ('num_shells',    'Shells    '),
        ('count',         'Count     '), ('serror_rate',   'SYN Err % '),
        ('rerror_rate',   'REJ Err % '), ('same_srv_rate', 'Same SVC % '),
        ('diff_srv_rate', 'Diff SVC % '), ('srv_diff_host_rate', 'Diff Host %'),
    ]
    col_w = 30
    rows = []
    for key, name in features:
        val = traffic.get(key, 'n/a')
        if isinstance(val, float):
            val = f'{val:.4f}'
        rows.append((name.ljust(14), str(val).ljust(14)))

    print(_c('  KDD Feature Snapshot:', DIM))
    for i in range(0, len(rows), 2):
        left  = rows[i]
        right = rows[i+1] if i+1 < len(rows) else ('', '')
        print(f'    {_c(left[0], DIM)}: {left[1]}   '
              f'{_c(right[0], DIM)}: {right[1]}')

# ── Check server status ───────────────────────────────────────────────────────
def check_server():
    try:
        status = _get('/api/status')
        return status
    except Exception:
        return None

def wait_for_server(max_wait=60):
    """Poll /api/status until it responds or timeout expires."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        s = check_server()
        if s:
            return s
        time.sleep(2)
    return None

# ── Main simulation loop ──────────────────────────────────────────────────────
def run_scenarios(scenarios, delay=1.0):
    results = []

    for idx, sc in enumerate(scenarios, 1):
        category = sc['category']
        colour   = SEV_COLOUR.get(category, WHITE)

        section(f'Scenario {idx}/{len(scenarios)}: {sc["label"]}')
        print(f'  Expected  : {_c(category, colour)}')
        print(f'  Source IP : {sc["src_ip"]}  →  Dest: {sc["dst_ip"]}')

        # Build payload
        payload = {'traffic': sc['traffic'], 'label': sc['label']}
        payload['traffic']['_src_ip'] = sc['src_ip']
        payload['traffic']['_dst_ip'] = sc['dst_ip']

        print_features(sc['traffic'])

        try:
            resp = _post('/api/simulate', payload)
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            print(_c(f'  [HTTP {e.code}] {body}', RED))
            results.append({'label': sc['label'], 'expected': category,
                            'detected': 'ERROR', 'conf': 0.0, 'ok': False})
            continue
        except Exception as ex:
            print(_c(f'  [ERROR] {ex}', RED))
            results.append({'label': sc['label'], 'expected': category,
                            'detected': 'ERROR', 'conf': 0.0, 'ok': False})
            continue

        detected = resp.get('class', '?')
        conf     = resp.get('confidence', 0.0)
        probas   = resp.get('probas', {})
        threat   = resp.get('threat', False)
        aid      = resp.get('alert_id', '?')
        report   = resp.get('report', '')

        match    = (detected == category)
        icon     = _c('DETECTED', GREEN + BOLD) if match else _c('MISMATCH', YELLOW + BOLD)
        det_col  = SEV_COLOUR.get(detected, WHITE)

        print()
        print(f'  {icon}')
        print(f'  Detected  : {_c(detected, det_col)}  '
              f'(confidence {_c(f"{conf:.1%}", BOLD)})')
        print(f'  Alert ID  : #{aid}')

        # Probability bars
        if probas:
            print(_c('\n  Class Probabilities:', DIM))
            for cls_name in sorted(probas, key=lambda k: -probas[k]):
                bar_col = SEV_COLOUR.get(cls_name, WHITE)
                print(f'    {_c(cls_name.ljust(8), bar_col)} '
                      f'{_c(prob_bar(probas[cls_name]), bar_col)}')

        # LLM report snippet (first 3 lines)
        if report:
            lines = [l.strip() for l in report.strip().splitlines() if l.strip()][:4]
            print(_c('\n  LLM Analysis (preview):', DIM))
            for ln in lines:
                print(f'    {ln}')

        results.append({
            'label'   : sc['label'],
            'expected': category,
            'detected': detected,
            'conf'    : conf,
            'ok'      : match,
        })

        if delay > 0:
            time.sleep(delay)

    return results

# ── Summary table ─────────────────────────────────────────────────────────────
def print_summary(results, status_after):
    banner('Test Summary')
    hdr = f"{'#':<4}{'Label':<40}{'Expected':<10}{'Detected':<12}{'Conf':>7}  {'Match'}"
    print(_c(hdr, BOLD))
    print(_c('-' * 80, DIM))

    correct = 0
    for i, r in enumerate(results, 1):
        match_str = _c('[OK]', GREEN + BOLD) if r['ok'] else _c('[--]', YELLOW)
        if r['ok']:
            correct += 1
        exp_c = SEV_COLOUR.get(r['expected'], WHITE)
        det_c = SEV_COLOUR.get(r['detected'], WHITE)
        print(f"{str(i):<4}"
              f"{r['label'][:39]:<40}"
              f"{_c(r['expected'][:9], exp_c):<10}"
              f"{_c(r['detected'][:11], det_c):<12}"
              f"{r['conf']:>7.1%}  {match_str}")

    pct = correct / len(results) * 100 if results else 0
    print(_c('-' * 80, DIM))
    print(f'  Detection accuracy (expected vs detected): '
          f'{_c(f"{correct}/{len(results)}", BOLD)} '
          f'({_c(f"{pct:.0f}%", GREEN + BOLD if pct >= 80 else YELLOW)})')

    if status_after:
        print()
        total  = status_after.get('total_flows', 0)
        counts = status_after.get('class_counts', {})
        print(f'  Dashboard totals:')
        print(f'    Total alerts : {_c(str(total), BOLD)}')
        for cls_name, cnt in counts.items():
            col = SEV_COLOUR.get(cls_name, WHITE)
            print(f'    {_c(cls_name.ljust(8), col)}: {cnt}')

    print()
    print(_c('  All alerts are live on the dashboard  →  http://localhost:5000', CYAN))
    print()

# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    # Enable ANSI on Windows
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    parser = argparse.ArgumentParser(description='IDS Attack Simulator')
    parser.add_argument('--scenario', default='all',
                        choices=['all','normal','dos','probe','r2l','u2r'],
                        help='Run only a specific attack category')
    parser.add_argument('--delay', type=float, default=0.8,
                        help='Seconds between requests (default 0.8)')
    parser.add_argument('--open', action='store_true',
                        help='Open browser after running')
    args = parser.parse_args()

    banner('AI-Powered IDS  |  Attack Simulation Suite')
    print(f'  Target server : {SERVER}')
    print(f'  Scenarios     : {args.scenario}')
    print(f'  Inter-request : {args.delay}s')

    # ── Check server ──────────────────────────────────────────────────────────
    section('Checking IDS Server')
    status = check_server()
    if status is None:
        print(_c('  [!] Server not responding at ' + SERVER, RED + BOLD))
        print()
        print('  Start the server first:')
        print(_c('    python server.py', CYAN))
        print()
        print('  Then re-run this script.')
        sys.exit(1)

    model_ready  = status.get('model_ready', False)
    llm_enabled  = status.get('llm_enabled', False)

    print(_c(f'  [OK] Server running', GREEN + BOLD))
    print(f'  Model ready  : {_c("Yes", GREEN) if model_ready else _c("No  — train model in dashboard first!", RED)}')
    print(f'  LLM enabled  : {_c("Yes", GREEN) if llm_enabled else _c("No  (template reports will be used)", YELLOW)}')
    print(f'  Total flows  : {status.get("total_flows", 0)}')

    if not model_ready:
        print()
        print(_c('  Model is not trained. Open http://localhost:5000 → Settings → Train', YELLOW))
        print(_c('  then rerun this script.', YELLOW))
        sys.exit(1)

    # ── Filter scenarios ──────────────────────────────────────────────────────
    cat_map = {
        'normal': 'Normal', 'dos': 'DoS',
        'probe' : 'Probe',  'r2l': 'R2L', 'u2r': 'U2R',
    }
    if args.scenario == 'all':
        chosen = SCENARIOS
    else:
        target = cat_map[args.scenario]
        chosen = [s for s in SCENARIOS if s['category'] == target]

    print()
    print(f'  Running {len(chosen)} scenario(s) — watch the dashboard for live updates')

    # ── Run scenarios ─────────────────────────────────────────────────────────
    results = run_scenarios(chosen, delay=args.delay)

    # ── Summary ───────────────────────────────────────────────────────────────
    status_after = check_server()
    print_summary(results, status_after)

    # ── Open browser ──────────────────────────────────────────────────────────
    if args.open:
        import webbrowser
        webbrowser.open(SERVER)

if __name__ == '__main__':
    main()
