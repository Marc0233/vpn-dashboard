#!/usr/bin/env python3
from flask import Flask, jsonify, render_template_string, request, session, redirect
import subprocess, re, os, time, glob, json, hashlib, secrets, zipfile, io
from functools import wraps

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB for ZIP uploads

_CONFIG_FILE = '/opt/vpn-dashboard/config.json'
_cfg = {}
if os.path.exists(_CONFIG_FILE):
    try: _cfg = json.load(open(_CONFIG_FILE))
    except: pass
LAN_IFACE  = _cfg.get('lan_iface',  'eth0')
CONNECT_SH = _cfg.get('connect_sh', '/etc/openvpn/connect.sh')

_KEY_FILE = '/opt/vpn-dashboard/secret.key'
if os.path.exists(_KEY_FILE):
    app.secret_key = open(_KEY_FILE).read().strip()
else:
    _k = secrets.token_hex(32)
    open(_KEY_FILE, 'w').write(_k)
    app.secret_key = _k

DASHBOARD_AUTH_FILE = '/opt/vpn-dashboard/dashboard_auth.json'
PROVIDERS_DIR = '/etc/openvpn/providers'
os.makedirs(PROVIDERS_DIR, exist_ok=True)

def _hash_pw(p):
    return hashlib.sha256(f'vpndash2025:{p}'.encode()).hexdigest()

def get_dashboard_creds():
    if os.path.exists(DASHBOARD_AUTH_FILE):
        try: return json.load(open(DASHBOARD_AUTH_FILE))
        except: pass
    return {'username': 'admin', 'password_hash': _hash_pw('admin')}

def save_dashboard_creds(u, p):
    json.dump({'username': u, 'password_hash': _hash_pw(p)}, open(DASHBOARD_AUTH_FILE, 'w'))

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            if request.path.startswith('/api/'):
                return jsonify({'ok': False, 'error': 'Unauthorised', 'auth': False}), 401
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        creds = get_dashboard_creds()
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '')
        if u == creds['username'] and _hash_pw(p) == creds['password_hash']:
            session['logged_in'] = True
            session['username'] = u
            return redirect('/')
        error = 'Invalid username or password.'
    return render_template_string(LOGIN_HTML, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/api/change-dashboard-password', methods=['POST'])
@requires_auth
def api_change_dashboard_password():
    data = request.get_json() or {}
    u = (data.get('username') or '').strip()
    p = (data.get('password') or '').strip()
    if not u or not p: return jsonify({'ok': False, 'error': 'Both fields required'})
    if len(p) < 6: return jsonify({'ok': False, 'error': 'Password must be at least 6 characters'})
    save_dashboard_creds(u, p)
    session['username'] = u
    return jsonify({'ok': True, 'msg': 'Dashboard login updated.'})

# ── VPN status helpers ────────────────────────────────────────────────────────

def get_status():
    proc = subprocess.run(['pgrep', '-a', 'openvpn'], capture_output=True, text=True)
    running = proc.returncode == 0
    server = ''
    uptime_sec = 0
    if running:
        m = re.search(r'/([^/\s]+\.ovpn)', proc.stdout)
        if m:
            server = m.group(1).replace('.udp.ovpn','').replace('.tcp.ovpn','').replace('.ovpn','')
        pm = re.search(r'^(\d+)', proc.stdout.strip())
        if pm:
            pid = int(pm.group(1))
            try:
                fields = open(f'/proc/{pid}/stat').read().split()
                hz = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
                boot_time = int(open('/proc/stat').read().split('btime')[1].split()[0])
                uptime_sec = int(time.time() - (boot_time + int(fields[21]) / hz))
            except: pass

    tun_ip = lan_ip = ''
    try:
        r = subprocess.run(['ip','addr','show','tun0'], capture_output=True, text=True)
        m = re.search(r'inet (\S+)', r.stdout)
        if m: tun_ip = m.group(1).split('/')[0]
    except: pass
    try:
        r = subprocess.run(['ip','addr','show', LAN_IFACE], capture_output=True, text=True)
        m = re.search(r'inet (\S+)', r.stdout)
        if m: lan_ip = m.group(1).split('/')[0]
    except: pass

    rx = tx = 0
    try:
        for line in open('/proc/net/dev'):
            if 'tun0:' in line:
                p = line.split(); rx, tx = int(p[1]), int(p[9])
    except: pass

    route_server = ''
    try:
        r = subprocess.run(['ip','route'], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            m = re.match(r'(\d+\.\d+\.\d+\.\d+) via .* dev ' + re.escape(LAN_IFACE), line)
            if m: route_server = m.group(1)
    except: pass

    def fmt(b):
        for u in ['B','KB','MB','GB']:
            if b < 1024: return f'{b:.1f} {u}'
            b /= 1024
        return f'{b:.1f} TB'

    def fmt_up(s):
        if s < 60: return f'{s}s'
        if s < 3600: return f'{s//60}m {s%60}s'
        h = s//3600; m = (s%3600)//60
        if h < 24: return f'{h}h {m}m'
        return f'{h//24}d {h%24}h'

    return {
        'connected': running and bool(tun_ip), 'running': running,
        'server': server, 'tun_ip': tun_ip, 'lan_ip': lan_ip,
        'vpn_server_ip': route_server, 'rx': fmt(rx), 'tx': fmt(tx),
        'uptime': fmt_up(uptime_sec) if uptime_sec else '—',
    }

def get_logs(n=60):
    lines = []
    try:
        r = subprocess.run(['journalctl','-u','openvpn*','--no-pager','-n',str(n),'--output','short-iso'],
                           capture_output=True, text=True, timeout=5)
        lines = r.stdout.strip().splitlines()
    except: pass
    if not lines:
        try:
            r = subprocess.run(['grep','-h','openvpn','/var/log/syslog','/var/log/syslog.1'],
                               capture_output=True, text=True, timeout=5)
            lines = r.stdout.strip().splitlines()[-n:]
        except: pass
    if not lines:
        for f in glob.glob('/var/log/openvpn*.log') + ['/tmp/openvpn.log']:
            if os.path.exists(f):
                try: lines = open(f).readlines()[-n:]; break
                except: pass
    return [l.rstrip() for l in lines]

def get_kill_switch():
    try:
        r = subprocess.run(['iptables','-L','INPUT'], capture_output=True, text=True)
        return 'policy DROP' in (r.stdout.splitlines()[0] if r.stdout else '')
    except: return False

def get_active_provider():
    try:
        cmd = open(CONNECT_SH).read()
        m = re.search(r'--config\s+"?([^"\s]+)"?', cmd)
        if m:
            path = m.group(1)
            for slug in os.listdir(PROVIDERS_DIR):
                if os.path.join(PROVIDERS_DIR, slug) in path:
                    return slug
        return ''
    except: return ''

# ── Provider management ───────────────────────────────────────────────────────

COUNTRY_NAMES = {
    'ad':'Andorra','ae':'UAE','af':'Afghanistan','al':'Albania','am':'Armenia',
    'ao':'Angola','ar':'Argentina','at':'Austria','au':'Australia','az':'Azerbaijan',
    'ba':'Bosnia','bb':'Barbados','bd':'Bangladesh','be':'Belgium','bg':'Bulgaria',
    'bh':'Bahrain','bn':'Brunei','bo':'Bolivia','br':'Brazil','bs':'Bahamas',
    'bt':'Bhutan','bz':'Belize','ca':'Canada','ch':'Switzerland','ci':'Ivory Coast',
    'cl':'Chile','co':'Colombia','cr':'Costa Rica','cy':'Cyprus','cz':'Czech Republic',
    'de':'Germany','dk':'Denmark','do':'Dominican Rep','dz':'Algeria','ec':'Ecuador',
    'ee':'Estonia','eg':'Egypt','es':'Spain','et':'Ethiopia','fi':'Finland',
    'fj':'Fiji','fr':'France','ga':'Gabon','gb':'United Kingdom','ge':'Georgia',
    'gh':'Ghana','gr':'Greece','gt':'Guatemala','hk':'Hong Kong','hn':'Honduras',
    'hr':'Croatia','hu':'Hungary','id':'Indonesia','ie':'Ireland','il':'Israel',
    'in':'India','iq':'Iraq','is':'Iceland','it':'Italy','jm':'Jamaica','jo':'Jordan',
    'jp':'Japan','ke':'Kenya','kg':'Kyrgyzstan','kh':'Cambodia','kr':'South Korea',
    'kw':'Kuwait','kz':'Kazakhstan','la':'Laos','lb':'Lebanon','lk':'Sri Lanka',
    'lt':'Lithuania','lu':'Luxembourg','lv':'Latvia','ly':'Libya','ma':'Morocco',
    'md':'Moldova','mk':'North Macedonia','mn':'Mongolia','mo':'Macao','mt':'Malta',
    'mx':'Mexico','my':'Malaysia','mz':'Mozambique','ng':'Nigeria','nl':'Netherlands',
    'no':'Norway','np':'Nepal','nz':'New Zealand','om':'Oman','pa':'Panama',
    'pe':'Peru','ph':'Philippines','pk':'Pakistan','pl':'Poland','pr':'Puerto Rico',
    'pt':'Portugal','py':'Paraguay','qa':'Qatar','ro':'Romania','rs':'Serbia',
    'ru':'Russia','sa':'Saudi Arabia','se':'Sweden','sg':'Singapore','si':'Slovenia',
    'sk':'Slovakia','sn':'Senegal','sv':'El Salvador','th':'Thailand','tj':'Tajikistan',
    'tm':'Turkmenistan','tn':'Tunisia','tr':'Turkey','tt':'Trinidad','tw':'Taiwan',
    'tz':'Tanzania','ua':'Ukraine','ug':'Uganda','us':'United States','uy':'Uruguay',
    'uk':'United Kingdom','uz':'Uzbekistan','ve':'Venezuela','vn':'Vietnam','za':'South Africa','zm':'Zambia',
    'zw':'Zimbabwe',
}
FLAGS = {
    'ad':'🇦🇩','ae':'🇦🇪','al':'🇦🇱','am':'🇦🇲','ao':'🇦🇴','ar':'🇦🇷','at':'🇦🇹',
    'au':'🇦🇺','az':'🇦🇿','ba':'🇧🇦','bd':'🇧🇩','be':'🇧🇪','bg':'🇧🇬','bh':'🇧🇭',
    'bn':'🇧🇳','bo':'🇧🇴','br':'🇧🇷','bs':'🇧🇸','bt':'🇧🇹','bz':'🇧🇿','ca':'🇨🇦',
    'ch':'🇨🇭','ci':'🇨🇮','cl':'🇨🇱','co':'🇨🇴','cr':'🇨🇷','cy':'🇨🇾','cz':'🇨🇿',
    'de':'🇩🇪','dk':'🇩🇰','do':'🇩🇴','dz':'🇩🇿','ec':'🇪🇨','ee':'🇪🇪','eg':'🇪🇬',
    'es':'🇪🇸','et':'🇪🇹','fi':'🇫🇮','fj':'🇫🇯','fr':'🇫🇷','ga':'🇬🇦','gb':'🇬🇧',
    'ge':'🇬🇪','gh':'🇬🇭','gr':'🇬🇷','gt':'🇬🇹','hk':'🇭🇰','hn':'🇭🇳','hr':'🇭🇷',
    'hu':'🇭🇺','id':'🇮🇩','ie':'🇮🇪','il':'🇮🇱','in':'🇮🇳','iq':'🇮🇶','is':'🇮🇸',
    'it':'🇮🇹','jm':'🇯🇲','jo':'🇯🇴','jp':'🇯🇵','ke':'🇰🇪','kg':'🇰🇬','kh':'🇰🇭',
    'kr':'🇰🇷','kw':'🇰🇼','kz':'🇰🇿','la':'🇱🇦','lb':'🇱🇧','lk':'🇱🇰','lt':'🇱🇹',
    'lu':'🇱🇺','lv':'🇱🇻','ly':'🇱🇾','ma':'🇲🇦','md':'🇲🇩','mk':'🇲🇰','mn':'🇲🇳',
    'mo':'🇲🇴','mt':'🇲🇹','mx':'🇲🇽','my':'🇲🇾','mz':'🇲🇿','ng':'🇳🇬','nl':'🇳🇱',
    'no':'🇳🇴','np':'🇳🇵','nz':'🇳🇿','om':'🇴🇲','pa':'🇵🇦','pe':'🇵🇪','ph':'🇵🇭',
    'pk':'🇵🇰','pl':'🇵🇱','pr':'🇵🇷','pt':'🇵🇹','py':'🇵🇾','qa':'🇶🇦','ro':'🇷🇴',
    'rs':'🇷🇸','ru':'🇷🇺','sa':'🇸🇦','se':'🇸🇪','sg':'🇸🇬','si':'🇸🇮','sk':'🇸🇰',
    'sn':'🇸🇳','sv':'🇸🇻','th':'🇹🇭','tj':'🇹🇯','tm':'🇹🇲','tn':'🇹🇳','tr':'🇹🇷',
    'tt':'🇹🇹','tw':'🇹🇼','tz':'🇹🇿','ua':'🇺🇦','ug':'🇺🇬','us':'🇺🇸','uy':'🇺🇾',
    'uk':'🇬🇧','uz':'🇺🇿','ve':'🇻🇪','vn':'🇻🇳','za':'🇿🇦','zm':'🇿🇲','zw':'🇿🇼',
}

def detect_country(filename):
    name = re.sub(r'\.ovpn$', '', filename, flags=re.I).lower()
    # Pattern 1: starts with 2-letter code + digits (NordVPN: uk1602, us4962)
    m = re.match(r'^([a-z]{2})\d', name)
    if m and m.group(1) in COUNTRY_NAMES: return m.group(1)
    # Pattern 2: each segment split by separators — first 2-letter ISO match
    for seg in re.split(r'[-_.\s]', name):
        if len(seg) == 2 and seg.isalpha() and seg in COUNTRY_NAMES:
            return seg
    # Fall back: first 2 chars
    if len(name) >= 2 and name[:2] in COUNTRY_NAMES:
        return name[:2]
    return None

PROVIDERS = [
    {'slug':'expressvpn', 'name':'ExpressVPN', 'color':'#DA3940',
     'url':'https://www.expressvpn.com/setup#manual',          'note':'Download .ovpn from your account'},
    {'slug':'nordvpn',    'name':'NordVPN',    'color':'#4687FF',
     'url':'https://nordvpn.com/ovpn/',                        'note':'Download .ovpn from nordvpn.com/ovpn/'},
    {'slug':'surfshark',  'name':'Surfshark',  'color':'#1FC7C1',
     'url':'https://support.surfshark.com/hc/en-us/articles/360011051133', 'note':'Download .ovpn from Manual Setup'},
    {'slug':'protonvpn',  'name':'ProtonVPN',  'color':'#6D4AFF',
     'url':'https://account.protonvpn.com/downloads',          'note':'Download .ovpn from Downloads'},
    {'slug':'mullvad',    'name':'Mullvad',    'color':'#FFCC00',
     'url':'https://mullvad.net/en/account/#/openvpn-config',  'note':'Generate config at mullvad.net'},
    {'slug':'pia',        'name':'PIA',        'color':'#4CB649',
     'url':'https://www.privateinternetaccess.com/openvpn/openvpn.zip', 'note':'Download OpenVPN configs'},
    {'slug':'cyberghost', 'name':'CyberGhost', 'color':'#FFDA00',
     'url':'https://support.cyberghostvpn.com/hc/en-us/articles/213811745', 'note':'Download from My Devices'},
    {'slug':'ipvanish',   'name':'IPVanish',   'color':'#FF6600',
     'url':'https://www.ipvanish.com/software/configs/',        'note':'Download .ovpn configs'},
    {'slug':'windscribe', 'name':'Windscribe', 'color':'#55CBEB',
     'url':'https://windscribe.com/getconfig/openvpn',          'note':'Generate config in My Account'},
    {'slug':'custom',     'name':'Custom',     'color':'#8B949E',
     'url':'',                                                  'note':'Upload any OpenVPN .ovpn config file'},
]

def get_provider_configs(slug):
    d = os.path.join(PROVIDERS_DIR, slug)
    if not os.path.isdir(d): return []
    return sorted([f for f in os.listdir(d) if f.endswith('.ovpn')])

def get_provider_auth(slug):
    af = os.path.join(PROVIDERS_DIR, slug, 'auth.txt')
    if os.path.exists(af):
        lines = open(af).read().splitlines()
        return lines[0] if lines else ''
    return ''

@app.route('/api/providers')
def api_providers():
    active = get_active_provider()
    result = []
    for p in PROVIDERS:
        slug = p['slug']
        configs = get_provider_configs(slug)
        result.append({**p,
            'active': slug == active,
            'configured': len(configs) > 0,
            'configs': configs,
            'username': get_provider_auth(slug),
        })
    return jsonify(result)

@app.route('/api/providers/<slug>/upload', methods=['POST'])
@requires_auth
def api_provider_upload(slug):
    slug = re.sub(r'[^a-z0-9_-]', '', slug.lower())
    if 'file' not in request.files:
        return jsonify({'ok': False, 'error': 'No file'})
    f = request.files['file']
    if not f.filename.endswith('.ovpn'):
        return jsonify({'ok': False, 'error': 'File must be a .ovpn file'})
    dest = os.path.join(PROVIDERS_DIR, slug)
    os.makedirs(dest, exist_ok=True)
    safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', f.filename)
    f.save(os.path.join(dest, safe_name))
    return jsonify({'ok': True, 'msg': f'Uploaded {safe_name}', 'filename': safe_name})

@app.route('/api/providers/<slug>/upload-zip', methods=['POST'])
@requires_auth
def api_provider_upload_zip(slug):
    slug = re.sub(r'[^a-z0-9_-]', '', slug.lower())
    if 'file' not in request.files:
        return jsonify({'ok': False, 'error': 'No file'})
    f = request.files['file']
    if not f.filename.lower().endswith('.zip'):
        return jsonify({'ok': False, 'error': 'File must be a .zip archive'})
    dest = os.path.join(PROVIDERS_DIR, slug)
    os.makedirs(dest, exist_ok=True)
    try:
        with zipfile.ZipFile(io.BytesIO(f.read())) as zf:
            extracted = 0
            for name in zf.namelist():
                if name.lower().endswith('.ovpn'):
                    safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', os.path.basename(name))
                    if safe_name:
                        with zf.open(name) as src:
                            open(os.path.join(dest, safe_name), 'wb').write(src.read())
                        extracted += 1
        if extracted == 0:
            return jsonify({'ok': False, 'error': 'No .ovpn files found in ZIP'})
        return jsonify({'ok': True, 'msg': f'Extracted {extracted} config files', 'count': extracted})
    except zipfile.BadZipFile:
        return jsonify({'ok': False, 'error': 'Invalid ZIP file'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/providers/<slug>/countries')
def api_provider_countries(slug):
    slug = re.sub(r'[^a-z0-9_-]', '', slug.lower())
    by = {}
    for f in get_provider_configs(slug):
        cc = detect_country(f)
        by.setdefault(cc or '__other__', []).append(f)
    result = sorted(
        [{'code': cc,
          'name': (FLAGS.get(cc,'🌐') + ' ' + COUNTRY_NAMES.get(cc, 'Other')) if cc != '__other__' else '🌐 Other',
          'count': len(files)}
         for cc, files in by.items()],
        key=lambda x: COUNTRY_NAMES.get(x['code'], 'ZZZ Other')
    )
    return jsonify(result)

@app.route('/api/providers/<slug>/servers/<country>')
def api_provider_servers(slug, country):
    slug    = re.sub(r'[^a-z0-9_-]', '', slug.lower())
    country = re.sub(r'[^a-z0-9_-]', '', country.lower())
    configs = get_provider_configs(slug)
    if country == '__other__':
        return jsonify([f for f in configs if detect_country(f) is None])
    return jsonify([f for f in configs if detect_country(f) == country])

@app.route('/api/providers/<slug>/delete-config', methods=['POST'])
@requires_auth
def api_provider_delete_config(slug):
    slug = re.sub(r'[^a-z0-9_-]', '', slug.lower())
    data = request.get_json() or {}
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', data.get('filename', ''))
    path = os.path.join(PROVIDERS_DIR, slug, filename)
    if os.path.exists(path):
        os.remove(path)
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'File not found'})

@app.route('/api/providers/<slug>/credentials', methods=['POST'])
@requires_auth
def api_provider_credentials(slug):
    slug = re.sub(r'[^a-z0-9_-]', '', slug.lower())
    data = request.get_json() or {}
    u = (data.get('username') or '').strip()
    p = (data.get('password') or '').strip()
    if not u or not p: return jsonify({'ok': False, 'error': 'Both fields required'})
    dest = os.path.join(PROVIDERS_DIR, slug)
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, 'auth.txt'), 'w') as fh:
        fh.write(u + '\n' + p + '\n')
    return jsonify({'ok': True, 'msg': 'Credentials saved.'})

@app.route('/api/providers/<slug>/connect', methods=['POST'])
@requires_auth
def api_provider_connect(slug):
    slug = re.sub(r'[^a-z0-9_-]', '', slug.lower())
    data = request.get_json() or {}
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', data.get('config', ''))
    if not filename: return jsonify({'ok': False, 'error': 'No config specified'})
    conf = os.path.join(PROVIDERS_DIR, slug, filename)
    auth = os.path.join(PROVIDERS_DIR, slug, 'auth.txt')
    if not os.path.exists(conf): return jsonify({'ok': False, 'error': 'Config not found'})
    if not os.path.exists(auth): return jsonify({'ok': False, 'error': 'No credentials saved for this provider'})
    try:
        with open(CONNECT_SH, 'w') as fh:
            fh.write(f'openvpn --config "{conf}" --auth-user-pass "{auth}"\n')
        subprocess.run(['pkill', '-f', 'openvpn'], timeout=5)
        time.sleep(1)
        subprocess.Popen(['bash', CONNECT_SH],
                         stdout=open('/tmp/vpn_reconnect.log','w'), stderr=subprocess.STDOUT)
        return jsonify({'ok': True, 'msg': f'Connecting via {filename.replace(".ovpn","")}…'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

# ── VPN control routes ────────────────────────────────────────────────────────

@app.route('/api/status')
def api_status():
    return jsonify(get_status())

@app.route('/api/logs')
def api_logs():
    return jsonify({'lines': get_logs()})

@app.route('/api/restart', methods=['POST'])
@requires_auth
def api_restart():
    try:
        subprocess.run(['pkill','-f','openvpn'], timeout=5); time.sleep(1)
        subprocess.Popen(['bash', CONNECT_SH],
                         stdout=open('/tmp/vpn_reconnect.log','w'), stderr=subprocess.STDOUT)
        return jsonify({'ok': True, 'msg': 'Restarting VPN…'})
    except Exception as e: return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/stop', methods=['POST'])
@requires_auth
def api_stop():
    try:
        subprocess.run(['pkill','-f','openvpn'], timeout=5)
        return jsonify({'ok': True, 'msg': 'VPN stopped'})
    except Exception as e: return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/start', methods=['POST'])
@requires_auth
def api_start():
    try:
        subprocess.Popen(['bash', CONNECT_SH],
                         stdout=open('/tmp/vpn_reconnect.log','w'), stderr=subprocess.STDOUT)
        return jsonify({'ok': True, 'msg': 'Starting VPN…'})
    except Exception as e: return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/killswitch', methods=['GET'])
def api_killswitch_get():
    return jsonify({'enabled': get_kill_switch()})

@app.route('/api/killswitch', methods=['POST'])
@requires_auth
def api_killswitch_set():
    data = request.get_json() or {}
    enable = bool(data.get('enable', True))
    try:
        ipt = lambda a: subprocess.run(['iptables'] + a, check=False)
        if enable:
            port = str(_cfg.get('port', 8080))
            # Flush first, then add ACCEPT rules, then set DROP — never a lockout window
            ipt(['-F','INPUT']); ipt(['-F','OUTPUT']); ipt(['-F','FORWARD'])
            # Loopback
            ipt(['-A','INPUT','-i','lo','-j','ACCEPT'])
            ipt(['-A','OUTPUT','-o','lo','-j','ACCEPT'])
            # LAN: SSH + dashboard + ICMP + outbound
            ipt(['-A','INPUT','-i',LAN_IFACE,'-p','tcp','--dport','22','-j','ACCEPT'])
            ipt(['-A','INPUT','-i',LAN_IFACE,'-p','tcp','--dport',port,'-j','ACCEPT'])
            ipt(['-A','INPUT','-i',LAN_IFACE,'-p','icmp','-j','ACCEPT'])
            ipt(['-A','OUTPUT','-o',LAN_IFACE,'-j','ACCEPT'])
            # VPN tunnel interface
            ipt(['-A','INPUT','-i','tun0','-j','ACCEPT'])
            ipt(['-A','OUTPUT','-o','tun0','-j','ACCEPT'])
            # Allow outbound to common VPN ports so openvpn can (re)connect
            for proto, dport in [('udp','1194'),('tcp','1194'),('tcp','443'),('tcp','1234'),('udp','53')]:
                ipt(['-A','OUTPUT','-p',proto,'--dport',dport,'-j','ACCEPT'])
            # Allow return/established traffic
            ipt(['-A','INPUT','-m','state','--state','RELATED,ESTABLISHED','-j','ACCEPT'])
            # NOW set DROP — all exceptions are already in place
            for chain in ['INPUT','OUTPUT','FORWARD']:
                subprocess.run(['iptables','-P', chain, 'DROP'], check=True)
        else:
            for chain in ['INPUT','OUTPUT','FORWARD']:
                subprocess.run(['iptables','-P', chain, 'ACCEPT'], check=True)
            ipt(['-F','INPUT']); ipt(['-F','OUTPUT']); ipt(['-F','FORWARD'])
        return jsonify({'ok': True, 'enabled': enable, 'msg': f'Kill switch {"enabled" if enable else "disabled"}'})
    except Exception as e: return jsonify({'ok': False, 'error': str(e)})

@app.route('/')
@requires_auth
def index():
    return render_template_string(HTML, username=session.get('username',''))

# ══════════════════════════════════════════════════════════════════════════════
# LOGIN PAGE
# ══════════════════════════════════════════════════════════════════════════════

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0e17;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden}
canvas{position:fixed;inset:0;z-index:0;opacity:.35}
.wrap{position:relative;z-index:1;width:100%;max-width:400px;padding:20px}
.card{background:rgba(22,27,34,.85);border:1px solid rgba(88,166,255,.15);border-radius:16px;padding:44px 40px 36px;backdrop-filter:blur(12px);box-shadow:0 0 60px rgba(88,166,255,.08),0 24px 48px rgba(0,0,0,.5)}
.shield{display:flex;align-items:center;justify-content:center;width:64px;height:64px;background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.25);border-radius:16px;margin:0 auto 24px}
h1{text-align:center;font-size:22px;font-weight:700;margin-bottom:4px;letter-spacing:-.3px}
.sub{text-align:center;font-size:13px;color:#8b949e;margin-bottom:32px}
label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:#8b949e;margin-bottom:7px}
.input-wrap{position:relative;margin-bottom:18px}
input{width:100%;background:rgba(13,17,23,.8);color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:11px 14px;font-size:14px;outline:none;transition:border-color .2s,box-shadow .2s}
input:focus{border-color:#58a6ff;box-shadow:0 0 0 3px rgba(88,166,255,.12)}
.error{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);color:#f85149;border-radius:8px;padding:11px 14px;font-size:13px;margin-bottom:20px;display:flex;align-items:center;gap:8px}
button[type=submit]{width:100%;background:linear-gradient(135deg,#58a6ff 0%,#3d7de0 100%);color:#0a0e17;border:none;border-radius:8px;padding:12px;font-size:14px;font-weight:700;cursor:pointer;margin-top:6px;transition:opacity .15s,transform .1s;letter-spacing:.3px}
button[type=submit]:hover{opacity:.92;transform:translateY(-1px)}
.footer{text-align:center;font-size:12px;color:#484f58;margin-top:20px}
</style>
</head>
<body>
<canvas id="c"></canvas>
<div class="wrap">
  <div class="card">
    <div class="shield">
      <svg width="28" height="32" viewBox="0 0 28 32" fill="none">
        <path d="M14 0L0 5.5V16c0 8.284 5.966 16.017 14 18 8.034-1.983 14-9.716 14-18V5.5L14 0Z" fill="rgba(88,166,255,.15)" stroke="#58a6ff" stroke-width="1.5"/>
        <path d="M8 16l4 4 8-8" stroke="#58a6ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <h1>VPN Dashboard</h1>
    <p class="sub">Sign in to manage your VPN</p>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="post">
      <label>Username</label>
      <div class="input-wrap"><input type="text" name="username" autocomplete="username" autofocus required placeholder="Enter username"></div>
      <label>Password</label>
      <div class="input-wrap"><input type="password" name="password" autocomplete="current-password" required placeholder="Enter password"></div>
      <button type="submit">Sign In</button>
    </form>
  </div>
  <p class="footer">VPN Dashboard &mdash; LAN access only</p>
</div>
<script>
const c=document.getElementById('c'),ctx=c.getContext('2d');
let W,H,pts=[];
function resize(){W=c.width=innerWidth;H=c.height=innerHeight;pts=[];for(let i=0;i<80;i++)pts.push({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.3,vy:(Math.random()-.5)*.3});}
function draw(){
  ctx.clearRect(0,0,W,H);
  pts.forEach(p=>{p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>W)p.vx*=-1;if(p.y<0||p.y>H)p.vy*=-1;});
  for(let i=0;i<pts.length;i++){
    ctx.beginPath();ctx.arc(pts[i].x,pts[i].y,1.5,0,Math.PI*2);ctx.fillStyle='#58a6ff';ctx.fill();
    for(let j=i+1;j<pts.length;j++){
      const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,d=Math.sqrt(dx*dx+dy*dy);
      if(d<120){ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);
        ctx.strokeStyle='rgba(88,166,255,'+(1-d/120)*.3+')';ctx.lineWidth=.5;ctx.stroke();}
    }
  }
  requestAnimationFrame(draw);
}
resize();draw();window.addEventListener('resize',resize);
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════════════════════
# MAIN DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Dashboard</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--radius:10px;--mono:'SF Mono','Fira Code',monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh}
header{background:var(--surface);border-bottom:1px solid var(--border);padding:13px 24px;display:flex;align-items:center;gap:12px}
header h1{font-size:17px;font-weight:700;letter-spacing:-.3px}
.badge{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase}
.badge-on{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.badge-off{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
main{max-width:1000px;margin:0 auto;padding:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px}
.card-label{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:5px}
.card-value{font-size:20px;font-weight:700;font-family:var(--mono)}
.span2{grid-column:span 2}
.card-sub{font-size:11px;color:var(--muted);margin-top:3px}
.section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:18px}
.section-header{padding:13px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.section-header h2{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--muted)}
button{padding:8px 16px;border-radius:6px;border:1px solid var(--border);font-size:13px;font-weight:600;cursor:pointer;transition:all .15s;background:transparent;color:var(--text)}
button:disabled{opacity:.45;cursor:default}
.btn-g{background:rgba(63,185,80,.1);color:var(--green);border-color:rgba(63,185,80,.3)}.btn-g:hover:not(:disabled){background:rgba(63,185,80,.2)}
.btn-r{background:rgba(248,81,73,.1);color:var(--red);border-color:rgba(248,81,73,.3)}.btn-r:hover:not(:disabled){background:rgba(248,81,73,.2)}
.btn-b{background:rgba(88,166,255,.1);color:var(--accent);border-color:rgba(88,166,255,.3)}.btn-b:hover:not(:disabled){background:rgba(88,166,255,.2)}
.btn-sm{font-size:11px;padding:5px 11px}
.btn-ghost{background:transparent;color:var(--muted);font-size:12px;padding:5px 10px;border-color:transparent}
.controls{display:flex;gap:8px;flex-wrap:wrap;padding:16px 18px;align-items:center}
.ks-badge{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:600;padding:4px 11px;border-radius:20px}
.ks-on{background:rgba(248,81,73,.12);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.ks-off{background:rgba(210,153,34,.12);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}
.providers-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;padding:16px 18px}
.pcard{border:1px solid var(--border);border-radius:8px;padding:14px;cursor:pointer;transition:all .15s;position:relative;text-align:center}
.pcard:hover{border-color:var(--accent);background:rgba(88,166,255,.04)}
.pcard.active{border-color:var(--green);background:rgba(63,185,80,.05)}
.pcard.active::after{content:'Active';position:absolute;top:6px;right:6px;background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);border-radius:10px;font-size:9px;font-weight:700;padding:2px 6px;text-transform:uppercase;letter-spacing:.5px}
.pcard-logo{font-size:13px;font-weight:800;margin-bottom:4px;letter-spacing:-.3px}
.pcard-name{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.provider-panel{display:none;border-top:1px solid var(--border);padding:18px}
.provider-panel.open{display:block}
select,input[type=text],input[type=password]{width:100%;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:9px 12px;font-size:13px;outline:none;transition:border-color .2s}
select:focus,input:focus{border-color:var(--accent)}
.form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.form-group{flex:1;min-width:160px}
.form-group label{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:6px;font-weight:600}
.msg-box{margin-top:12px;font-size:13px;padding:8px 12px;border-radius:6px;display:none}
.msg-ok{background:rgba(63,185,80,.1);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.msg-err{background:rgba(248,81,73,.1);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.msg-inf{background:rgba(88,166,255,.1);color:var(--accent);border:1px solid rgba(88,166,255,.3)}
#log-box{padding:14px 18px;font-family:var(--mono);font-size:11px;color:var(--muted);max-height:340px;overflow-y:auto;line-height:1.7}
#log-box .ok{color:var(--green)}#log-box .err{color:var(--red)}#log-box .warn{color:var(--yellow)}
#log-box .line{border-bottom:1px solid rgba(48,54,61,.4);padding:1px 0}
.toast{position:fixed;bottom:22px;right:22px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 16px;font-size:13px;opacity:0;transition:opacity .3s;pointer-events:none;z-index:100}
.toast.show{opacity:1}
#conn-dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:6px;background:var(--muted);flex-shrink:0}
#conn-dot.on{background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse 2s infinite}
#conn-dot.off{background:var(--red)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.user-row{display:flex;align-items:center;gap:10px;font-size:12px}
a.logout{color:var(--muted);text-decoration:none;padding:4px 10px;border:1px solid var(--border);border-radius:5px;transition:all .15s}
a.logout:hover{border-color:var(--red);color:var(--red)}
.upload-row{display:flex;gap:8px;margin-top:12px}
.upload-zone{flex:1;border:2px dashed var(--border);border-radius:8px;padding:14px;text-align:center;cursor:pointer;transition:all .2s}
.upload-zone:hover{border-color:var(--accent);background:rgba(88,166,255,.04)}
.upload-zone input{display:none}
.upload-zone .uz-icon{font-size:18px;margin-bottom:4px}
.upload-zone .uz-label{font-size:12px;color:var(--muted)}
.upload-zone .uz-sub{font-size:10px;color:var(--border);margin-top:2px}
.picker-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:12px}
.picker-row .form-group{flex:1;min-width:160px}
</style>
</head>
<body>
<header>
  <span id="conn-dot"></span>
  <h1>VPN Dashboard</h1>
  <span id="status-badge" class="badge">—</span>
  <span style="flex:1"></span>
  <div class="user-row">
    <span id="last-update" style="color:var(--muted)"></span>
    <span style="color:var(--border)">|</span>
    <span>{{ username }}</span>
    <a href="/logout" class="logout">Sign out</a>
  </div>
</header>
<main>

  <div class="grid">
    <div class="card span2">
      <div class="card-label">Connected Server</div>
      <div class="card-value" id="server" style="font-size:15px">—</div>
      <div class="card-sub" id="vpn-server-ip"></div>
    </div>
    <div class="card"><div class="card-label">Tunnel IP</div><div class="card-value" id="tun-ip" style="font-size:15px">—</div></div>
    <div class="card"><div class="card-label">LAN IP</div><div class="card-value" id="lan-ip" style="font-size:15px">—</div></div>
    <div class="card"><div class="card-label">Uptime</div><div class="card-value" id="uptime">—</div></div>
    <div class="card"><div class="card-label">Downloaded</div><div class="card-value" id="rx">—</div></div>
    <div class="card"><div class="card-label">Uploaded</div><div class="card-value" id="tx">—</div></div>
  </div>

  <div class="section">
    <div class="section-header"><h2>Controls</h2></div>
    <div class="controls">
      <button class="btn-g" onclick="vpnAction('start')">▶ Start</button>
      <button class="btn-r" onclick="vpnAction('stop')">■ Stop</button>
      <button class="btn-b" onclick="vpnAction('restart')">↺ Restart</button>
      <span style="flex:1"></span>
      <span id="ks-status" class="ks-badge ks-off">⚪ Kill Switch: …</span>
      <button id="ks-btn" class="btn-sm btn-g" onclick="toggleKillSwitch()">Enable</button>
    </div>
  </div>

  <div class="section">
    <div class="section-header"><h2>VPN Provider</h2></div>
    <div class="providers-grid" id="providers-grid">
      <div style="color:var(--muted);font-size:13px;padding:8px">Loading…</div>
    </div>
    <div id="provider-panel" class="provider-panel"></div>
  </div>

  <div class="section">
    <div class="section-header"><h2>Dashboard Login</h2></div>
    <div style="padding:16px 18px">
      <div class="form-row">
        <div class="form-group"><label>New Username</label><input id="dash-user" type="text" autocomplete="off"></div>
        <div class="form-group"><label>New Password <span style="color:var(--muted);font-weight:400">(min 6 chars)</span></label>
          <div style="display:flex;gap:6px">
            <input id="dash-pass" type="password" style="flex:1" placeholder="New password">
            <button class="btn-ghost" onclick="toggleVis('dash-pass')" style="padding:9px 10px">👁</button>
          </div>
        </div>
        <button id="dash-btn" class="btn-b" onclick="saveDashboardLogin()">💾 Save</button>
      </div>
      <div id="dash-msg" class="msg-box"></div>
    </div>
  </div>

  <div class="section">
    <div class="section-header"><h2>Recent Logs</h2><button class="btn-ghost" onclick="loadLogs()">Refresh</button></div>
    <div id="log-box"><span>Loading…</span></div>
  </div>

</main>
<div class="toast" id="toast"></div>
<script>
function toast(msg,ok=true){const t=document.getElementById('toast');t.textContent=msg;t.style.borderColor=ok?'rgba(63,185,80,.4)':'rgba(248,81,73,.4)';t.classList.add('show');setTimeout(()=>t.classList.remove('show'),3000);}
function setMsg(id,html,type){const el=document.getElementById(id);el.style.display='block';el.innerHTML=html;el.className='msg-box msg-'+(type==='ok'?'ok':type==='err'?'err':'inf');}
function toggleVis(id){const f=document.getElementById(id);f.type=f.type==='password'?'text':'password';}

async function loadStatus(){
  try{
    const d=await fetch('/api/status').then(r=>r.json());
    const dot=document.getElementById('conn-dot'),badge=document.getElementById('status-badge');
    dot.className=d.connected?'on':'off';
    badge.className='badge '+(d.connected?'badge-on':'badge-off');
    badge.textContent=d.connected?'Connected':(d.running?'Connecting…':'Disconnected');
    document.getElementById('server').textContent=d.server||'—';
    document.getElementById('vpn-server-ip').textContent=d.vpn_server_ip?'IP: '+d.vpn_server_ip:'';
    document.getElementById('tun-ip').textContent=d.tun_ip||'—';
    document.getElementById('lan-ip').textContent=d.lan_ip||'—';
    document.getElementById('uptime').textContent=d.uptime||'—';
    document.getElementById('rx').textContent=d.rx||'—';
    document.getElementById('tx').textContent=d.tx||'—';
    document.getElementById('last-update').textContent=new Date().toLocaleTimeString();
  }catch(e){}
}
async function loadLogs(){
  try{
    const d=await fetch('/api/logs').then(r=>r.json());
    const box=document.getElementById('log-box');
    if(!d.lines||!d.lines.length){box.innerHTML='<span style="color:var(--muted)">No logs.</span>';return;}
    box.innerHTML=d.lines.reverse().map(l=>{
      let cls='line';
      if(/VERIFY OK|Initialization Sequence Completed|connected/i.test(l))cls+=' ok';
      else if(/error|fail|AUTH_FAILED/i.test(l))cls+=' err';
      else if(/warn|retry/i.test(l))cls+=' warn';
      return '<div class="'+cls+'">'+l.replace(/</g,'&lt;')+'</div>';
    }).join('');
  }catch(e){}
}
async function vpnAction(a){
  try{const r=await fetch('/api/'+a,{method:'POST'}).then(r=>r.json());if(r.auth===false){location.href='/login';return;}toast(r.msg||(r.ok?'Done':r.error),r.ok);setTimeout(loadStatus,2000);setTimeout(loadLogs,3000);}catch(e){toast('Request failed',false);}
}
async function loadKillSwitch(){try{const r=await fetch('/api/killswitch').then(r=>r.json());updateKsUI(r.enabled);}catch(e){}}
function updateKsUI(on){
  const badge=document.getElementById('ks-status'),btn=document.getElementById('ks-btn');
  if(on){badge.className='ks-badge ks-on';badge.innerHTML='🔴 Kill Switch: ON';btn.className='btn-sm btn-r';btn.textContent='Disable';}
  else{badge.className='ks-badge ks-off';badge.innerHTML='⚠ Kill Switch: OFF';btn.className='btn-sm btn-g';btn.textContent='Enable';}
}
async function toggleKillSwitch(){
  const btn=document.getElementById('ks-btn');
  const enable=btn.textContent.trim()==='Enable';
  if(!enable&&!confirm('Disabling the kill switch means internet traffic will flow even if the VPN drops. Continue?'))return;
  btn.disabled=true;
  try{const r=await fetch('/api/killswitch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enable})}).then(r=>r.json());if(r.auth===false){location.href='/login';return;}toast(r.msg||(r.ok?'Done':r.error),r.ok);if(r.ok)updateKsUI(r.enabled);}catch(e){toast('Request failed',false);}
  btn.disabled=false;
}

let providersData=[];
async function loadProviders(){
  try{providersData=await fetch('/api/providers').then(r=>r.json());renderProviders();}catch(e){}
}
function renderProviders(){
  const grid=document.getElementById('providers-grid');
  grid.innerHTML=providersData.map(p=>`<div class="pcard${p.active?' active':''}" onclick="selectProvider('${p.slug}')" style="border-color:${p.active?'var(--green)':'var(--border)'}"><div class="pcard-logo" style="color:${p.color}">${p.name}</div><div class="pcard-name">${p.configured?'Ready':'Set up'}</div></div>`).join('');
}
function selectProvider(slug){
  const p=providersData.find(x=>x.slug===slug);if(!p)return;
  const panel=document.getElementById('provider-panel');
  if(panel.dataset.slug===slug&&panel.classList.contains('open')){panel.classList.remove('open');panel.dataset.slug='';return;}
  panel.dataset.slug=slug;panel.classList.add('open');

  const hasCfgs = p.configs.length > 0;
  panel.innerHTML=`
    <p style="font-size:12px;color:var(--muted);margin-bottom:14px">${p.note}${p.url?' &mdash; <a href="'+p.url+'" target="_blank" style="color:var(--accent)">'+p.url.replace('https://','')+'</a>':''}</p>
    <div class="form-row" style="margin-bottom:14px">
      <div class="form-group"><label>Username</label><input type="text" id="prov-user-${slug}" value="${p.username||''}" placeholder="VPN username"></div>
      <div class="form-group"><label>Password</label>
        <div style="display:flex;gap:6px"><input type="password" id="prov-pass-${slug}" style="flex:1" placeholder="VPN password"><button class="btn-ghost" onclick="toggleVis('prov-pass-${slug}')" style="padding:9px 10px">👁</button></div>
      </div>
      <button class="btn-b btn-sm" onclick="saveProviderCreds('${slug}')">Save Credentials</button>
    </div>
    <div id="prov-cred-msg-${slug}" class="msg-box"></div>
    <div style="margin-top:16px">
      <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:10px">Server</div>
      ${hasCfgs ? `
      <div class="picker-row">
        <div class="form-group"><label>Country</label>
          <select id="prov-country-${slug}" onchange="loadProviderServers('${slug}')"><option>Loading…</option></select>
        </div>
        <div class="form-group"><label>Server</label>
          <select id="prov-server-${slug}"><option>Select country first</option></select>
        </div>
        <button class="btn-b" onclick="connectFromPicker('${slug}')">⇄ Connect</button>
        <button class="btn-b" style="opacity:.8" onclick="randomFromPicker('${slug}')">🎲 Random</button>
      </div>
      <div id="prov-connect-msg-${slug}" class="msg-box"></div>
      ` : `<p style="font-size:12px;color:var(--muted);margin-bottom:12px">Upload a config file or ZIP archive below to get started.</p>`}
      <div class="upload-row">
        <div class="upload-zone" onclick="document.getElementById('file-ovpn-${slug}').click()">
          <input type="file" id="file-ovpn-${slug}" accept=".ovpn" onchange="uploadConfig('${slug}',this)">
          <div class="uz-icon">📄</div>
          <div class="uz-label">Upload .ovpn</div>
          <div class="uz-sub">Single config file</div>
        </div>
        <div class="upload-zone" onclick="document.getElementById('file-zip-${slug}').click()">
          <input type="file" id="file-zip-${slug}" accept=".zip" onchange="uploadZip('${slug}',this)">
          <div class="uz-icon">📦</div>
          <div class="uz-label">Upload .zip</div>
          <div class="uz-sub">Bulk config archive</div>
        </div>
      </div>
      <div id="prov-upload-msg-${slug}" class="msg-box"></div>
    </div>`;

  if(hasCfgs) loadProviderCountries(slug);
}

async function loadProviderCountries(slug){
  const sel=document.getElementById('prov-country-'+slug);
  if(!sel)return;
  try{
    const countries=await fetch('/api/providers/'+slug+'/countries').then(r=>r.json());
    if(!countries.length){sel.innerHTML='<option>No configs found</option>';return;}
    sel.innerHTML='<option value="">— Select Country —</option>'+
      countries.map(c=>`<option value="${c.code}">${c.name} (${c.count})</option>`).join('');
    if(countries.length===1){sel.value=countries[0].code;loadProviderServers(slug);}
  }catch(e){sel.innerHTML='<option>Error loading</option>';}
}

async function loadProviderServers(slug){
  const cc=document.getElementById('prov-country-'+slug)?.value;
  const sel=document.getElementById('prov-server-'+slug);
  if(!sel)return;
  if(!cc){sel.innerHTML='<option value="">Select country first</option>';return;}
  sel.innerHTML='<option>Loading…</option>';
  try{
    const servers=await fetch('/api/providers/'+slug+'/servers/'+cc).then(r=>r.json());
    sel.innerHTML=servers.map(f=>{
      const label=f.replace(/\.ovpn$/i,'').replace(/[-_.]/g,' ');
      return `<option value="${f}">${label}</option>`;
    }).join('');
  }catch(e){sel.innerHTML='<option>Error loading</option>';}
}

async function connectFromPicker(slug){
  const config=document.getElementById('prov-server-'+slug)?.value;
  if(!config){setMsg('prov-connect-msg-'+slug,'⚠ Select a server first','err');return;}
  const btn=event.target;btn.disabled=true;btn.textContent='Connecting…';
  setMsg('prov-connect-msg-'+slug,'⟳ Connecting…','inf');
  try{
    const r=await fetch('/api/providers/'+slug+'/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({config})}).then(r=>r.json());
    if(r.auth===false){location.href='/login';return;}
    if(!r.ok){setMsg('prov-connect-msg-'+slug,'✗ '+(r.error||'Failed'),'err');btn.disabled=false;btn.textContent='⇄ Connect';return;}
    let tries=0;
    const poll=setInterval(async()=>{
      tries++;
      try{
        const s=await fetch('/api/status').then(r=>r.json());
        if(s.connected){
          clearInterval(poll);loadStatus();loadLogs();await loadProviders();
          setMsg('prov-connect-msg-'+slug,'✓ Connected — '+s.server,'ok');
          btn.disabled=false;btn.textContent='⇄ Connect';toast('Connected',true);
        }else if(tries>=15){
          clearInterval(poll);setMsg('prov-connect-msg-'+slug,'⚠ Still connecting — check logs','err');
          btn.disabled=false;btn.textContent='⇄ Connect';loadStatus();
        }else{setMsg('prov-connect-msg-'+slug,'⟳ Waiting… ('+tries*2+'s)','inf');}
      }catch(e){}
    },2000);
  }catch(e){setMsg('prov-connect-msg-'+slug,'✗ Request failed','err');btn.disabled=false;btn.textContent='⇄ Connect';}
}

async function randomFromPicker(slug){
  const cc=document.getElementById('prov-country-'+slug)?.value;
  if(!cc){setMsg('prov-connect-msg-'+slug,'⚠ Select a country first','err');return;}
  try{
    const servers=await fetch('/api/providers/'+slug+'/servers/'+cc).then(r=>r.json());
    if(!servers.length)return;
    const pick=servers[Math.floor(Math.random()*servers.length)];
    document.getElementById('prov-server-'+slug).value=pick;
    connectFromPicker(slug);
  }catch(e){}
}
async function saveProviderCreds(slug){
  const u=document.getElementById('prov-user-'+slug)?.value.trim(),p=document.getElementById('prov-pass-'+slug)?.value.trim();
  if(!u||!p){setMsg('prov-cred-msg-'+slug,'⚠ Both fields required','err');return;}
  try{const r=await fetch('/api/providers/'+slug+'/credentials',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})}).then(r=>r.json());setMsg('prov-cred-msg-'+slug,r.ok?'✓ '+r.msg:'✗ '+(r.error||'Failed'),r.ok?'ok':'err');if(r.ok){document.getElementById('prov-pass-'+slug).value='';loadProviders();}}catch(e){setMsg('prov-cred-msg-'+slug,'✗ Request failed','err');}
}
async function uploadConfig(slug,input){
  const file=input.files[0];if(!file)return;
  const fd=new FormData();fd.append('file',file);
  setMsg('prov-upload-msg-'+slug,'⟳ Uploading…','inf');
  try{const r=await fetch('/api/providers/'+slug+'/upload',{method:'POST',body:fd}).then(r=>r.json());setMsg('prov-upload-msg-'+slug,r.ok?'✓ '+r.msg:'✗ '+(r.error||'Upload failed'),r.ok?'ok':'err');if(r.ok){await loadProviders();selectProvider(slug);}}catch(e){setMsg('prov-upload-msg-'+slug,'✗ Upload failed','err');}
  input.value='';
}
async function uploadZip(slug,input){
  const file=input.files[0];if(!file)return;
  const fd=new FormData();fd.append('file',file);
  setMsg('prov-upload-msg-'+slug,'⟳ Uploading and extracting… (this may take a moment)','inf');
  try{
    const r=await fetch('/api/providers/'+slug+'/upload-zip',{method:'POST',body:fd}).then(r=>r.json());
    setMsg('prov-upload-msg-'+slug,r.ok?'✓ '+r.msg:'✗ '+(r.error||'Upload failed'),r.ok?'ok':'err');
    if(r.ok){await loadProviders();selectProvider(slug);}
  }catch(e){setMsg('prov-upload-msg-'+slug,'✗ Upload failed','err');}
  input.value='';
}
async function deleteConfig(slug,filename,btn){
  if(!confirm('Delete '+filename+'?'))return;btn.disabled=true;
  try{const r=await fetch('/api/providers/'+slug+'/delete-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename})}).then(r=>r.json());if(r.ok){await loadProviders();selectProvider(slug);}}catch(e){}btn.disabled=false;
}
async function connectProvider(slug,config){
  try{
    const r=await fetch('/api/providers/'+slug+'/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({config})}).then(r=>r.json());
    if(r.auth===false){location.href='/login';return;}
    toast(r.msg||(r.ok?'Connecting…':r.error),r.ok);
    if(r.ok){await loadProviders();setTimeout(loadStatus,3000);setTimeout(loadLogs,5000);}
  }catch(e){toast('Request failed',false);}
}
async function saveDashboardLogin(){
  const u=document.getElementById('dash-user').value.trim(),p=document.getElementById('dash-pass').value.trim(),btn=document.getElementById('dash-btn');
  if(!u||!p){setMsg('dash-msg','⚠ Both fields required','err');return;}
  btn.disabled=true;btn.textContent='Saving…';
  try{const r=await fetch('/api/change-dashboard-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})}).then(r=>r.json());if(r.auth===false){location.href='/login';return;}setMsg('dash-msg',r.ok?'✓ '+r.msg:'✗ '+(r.error||'Failed'),r.ok?'ok':'err');if(r.ok){document.getElementById('dash-pass').value='';document.getElementById('dash-user').value='';}}catch(e){setMsg('dash-msg','✗ Request failed','err');}
  btn.disabled=false;btn.textContent='💾 Save';
}

loadProviders();loadKillSwitch();loadStatus();loadLogs();
setInterval(loadStatus,5000);setInterval(loadLogs,30000);setInterval(loadKillSwitch,10000);
</script>
</body>
</html>"""

if __name__ == '__main__':
    port = int(_cfg.get('port', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
