# sherlock_nexus.py — SherloCK BLE Command Center with Nexus Mesh, Profiles, Training, Triangulation
# Keys: w/a/i/h/n/s | ENTER: Profile | x: Script | /: Command | m: Mode | R: restart scan | q: quit

import os, sys, time, math, csv, json, glob, socket, pathlib, asyncio, curses, subprocess, shutil, logging
from collections import defaultdict, deque, Counter
from hashlib import blake2b
import psutil
try:
    from bleak import BleakScanner
except Exception:
    BleakScanner = None

# ---------- bootstrap paths ----------
APP_ROOT   = pathlib.Path(os.getcwd())
DATA_DIR   = APP_ROOT / "data"
CONFIG_DIR = APP_ROOT / "config"
LOGS_DIR   = APP_ROOT / "logs"
TOOLS_DIR  = APP_ROOT / "tools"
BANNERS_DIR= APP_ROOT / "banners"
THREAT_DB  = APP_ROOT / "threat_db.csv"
TRAIN_DB   = APP_ROOT / "training_db.csv"
CRASH_LOG  = LOGS_DIR / "sherlock_crash.log"
for p in [DATA_DIR, CONFIG_DIR, LOGS_DIR, TOOLS_DIR, BANNERS_DIR]:
    try: p.mkdir(parents=True, exist_ok=True)
    except Exception: pass
logging.basicConfig(filename=str(CRASH_LOG), level=logging.DEBUG)

# ========================================
# ========= Mesh Manager (improved) ======
# ========================================
class MeshManager:
    """
    Nexus Mesh directory layout:
      status/<NODE_ID>.json   heartbeat/status
      inbox/<NODE_ID>.cmd     commands for this node
      training/               shared training CSV snapshots
    """
    def __init__(self, node_id: str):
        self.node_id   = node_id
        self.proto     = os.environ.get("MESH_PROTO", "auto").lower()
        self.seed      = os.environ.get("MESH_SEED", "rv2-1")
        self.mesh_dir  = os.environ.get("MESH_DIR", "/mnt/mesh")
        self.remote    = os.environ.get("MESH_REMOTE_DIR", "/srv/mesh")
        self.status_dir= os.path.join(self.mesh_dir, "status")
        self.inbox_dir = os.path.join(self.mesh_dir, "inbox")
        self.training_dir = os.path.join(self.mesh_dir, "training")
        self.auto      = os.environ.get("MESH_AUTO", "0") == "1"
        self.health    = {"state":"OFF","peers":0,"dir":self.mesh_dir,"writable":False,"mounted":False,"reason":""}
        self.ensure_dirs()

    def _run(self, args):
        try:
            return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
        except Exception as e:
            return type("R", (), {"returncode":1,"stdout":"","stderr":str(e)})

    def _mountpoint(self, path) -> bool:
        return self._run(["mountpoint","-q",path]).returncode == 0

    def _ping(self, host, timeout=1) -> bool:
        return self._run(["ping","-c","1","-W",str(timeout),host]).returncode == 0

    def ensure_dirs(self):
        for d in [self.status_dir, self.inbox_dir, self.training_dir]:
            try: os.makedirs(d, exist_ok=True)
            except Exception: pass

    def connect(self) -> bool:
        if self._mountpoint(self.mesh_dir): return True
        os.makedirs(self.mesh_dir, exist_ok=True)
        proto = self.proto if self.proto != "auto" else ("nfs" if shutil.which("mount") else "sshfs")
        if proto == "nfs":
            if not self._ping(self.seed):
                self.health["reason"] = f"seed {self.seed} unreachable"
                return False
            r = self._run(["sudo","mount","-t","nfs", f"{self.seed}:{self.remote}", self.mesh_dir])
            if r.returncode != 0:
                self.health["reason"] = f"nfs mount err: {r.stderr.strip()}"
                return False
            return True
        if proto == "sshfs":
            if not shutil.which("sshfs"):
                self.health["reason"] = "sshfs not installed"; return False
            if not self._ping(self.seed):
                self.health["reason"] = f"seed {self.seed} unreachable"; return False
            r = self._run(["sshfs", f"{self.seed}:{self.remote}", self.mesh_dir,
                           "-o","reconnect,ServerAliveInterval=15,ServerAliveCountMax=3"])
            if r.returncode != 0:
                self.health["reason"] = f"sshfs err: {r.stderr.strip()}"; return False
            return True
        return True  # local fallback

    def disconnect(self):
        if self._mountpoint(self.mesh_dir):
            self._run(["sudo","umount","-l", self.mesh_dir])

    def write_status(self, payload: dict) -> bool:
        self.ensure_dirs()
        p = os.path.join(self.status_dir, f"{self.node_id}.json")
        try:
            tmp = p + ".tmp"
            with open(tmp, "w") as f: json.dump(payload, f)
            os.replace(tmp, p)
            return True
        except Exception:
            logging.exception("mesh write_status"); return False

    def inbox_lines(self):
        p = os.path.join(self.inbox_dir, f"{self.node_id}.cmd")
        if not os.path.exists(p): return []
        try:
            with open(p) as f: lines = [ln.strip() for ln in f if ln.strip()]
            open(p, "w").close()
            return lines
        except Exception:
            logging.exception("mesh inbox_lines"); return []

    def _writable(self, path):
        try:
            os.makedirs(path, exist_ok=True)
            test = os.path.join(path, ".probe")
            with open(test, "w") as f: f.write(str(time.time()))
            os.remove(test)
            return True
        except Exception:
            return False

    def _peer_statuses(self):
        files = glob.glob(os.path.join(self.status_dir, "**", "*.json"), recursive=True)
        peers = []; now=time.time()
        for fp in files:
            try:
                with open(fp) as f: d=json.load(f)
                nid=d.get("node") or pathlib.Path(fp).stem
                if nid != self.node_id:
                    age = now - os.path.getmtime(fp)
                    peers.append((nid, age, d))
            except Exception:
                continue
        return peers

    def health_check(self):
        self.ensure_dirs()
        mounted  = self._mountpoint(self.mesh_dir)
        writable = self._writable(self.status_dir)
        peers    = self._peer_statuses()
        fresh    = [p for p,age,_ in peers if age < 5]
        state = "OK" if writable and (fresh or peers) else ("DEGRADED" if writable else "OFF")
        self.health.update(dict(
            state=state, peers=len(set(p for p,_,_ in peers)), dir=self.mesh_dir,
            writable=writable, mounted=mounted, reason=self.health.get("reason","")
        ))
        if self.auto and state == "OFF":
            if self.connect():
                mounted  = self._mountpoint(self.mesh_dir)
                writable = self._writable(self.status_dir)
                peers    = self._peer_statuses()
                state = "OK" if writable and peers else ("DEGRADED" if writable else "OFF")
                self.health.update(dict(state=state, peers=len(peers), writable=writable, mounted=mounted))
        return self.health

    # training CSV sync across mesh
    def publish_training_snapshot(self, src_csv_path: pathlib.Path):
        try:
            if not self._writable(self.training_dir): return False
            dst = pathlib.Path(self.training_dir) / f"{self.node_id}_training_db.csv"
            tmp = str(dst)+".tmp"
            with open(src_csv_path, "rb") as rf, open(tmp, "wb") as wf:
                shutil.copyfileobj(rf, wf)
            os.replace(tmp, dst)
            return True
        except Exception:
            logging.exception("mesh publish_training_snapshot"); return False

    def merge_training_into_local(self, local_db: dict):
        try:
            files = glob.glob(os.path.join(self.training_dir, "*.csv"))
            if not files: return 0
            merged = 0
            for fp in files:
                try:
                    with open(fp, newline="") as f:
                        r=csv.DictReader(f)
                        for row in r:
                            key=(row["name_norm"],row["oui"],row["uuids_sig"])
                            rec=local_db.get(key, {})
                            if rec:
                                rec["dtype"]=row.get("dtype") or rec.get("dtype","")
                                rec["label"]=row.get("label") or rec.get("label","")
                                rec["seen"]=str(int(rec.get("seen",0)) + int(row.get("seen",0) or 0))
                                rec["rssi_med"]=rec.get("rssi_med") or row.get("rssi_med","")
                                rec["rssi_min"]=rec.get("rssi_min") or row.get("rssi_min","")
                                rec["rssi_max"]=rec.get("rssi_max") or row.get("rssi_max","")
                                rec["last_seen"]=max(rec.get("last_seen") or "", row.get("last_seen") or "")
                                local_db[key]=rec
                            else:
                                local_db[key]={
                                    "dtype":row.get("dtype",""),"label":row.get("label",""),
                                    "seen":row.get("seen",0),"rssi_med":row.get("rssi_med",""),
                                    "rssi_min":row.get("rssi_min",""),"rssi_max":row.get("rssi_max",""),
                                    "last_seen":row.get("last_seen",""),
                                }
                            merged += 1
                except Exception:
                    logging.exception("mesh merge_training parse")
            return merged
        except Exception:
            logging.exception("mesh merge_training"); return 0

# ========================================
# ========= Typing dictionaries ==========
# ========================================
OUI_TO_VENDOR = {
    "00:1A:7D":"Apple","D0:37:45":"Apple","30:AE:A4":"Samsung","C0:98:E5":"Sony",
    "A4:C1:38":"Lenovo","DC:A6:32":"BMW","D8:A0:1D":"Toyota","64:6E:6C":"Honda","F4:F5:D8":"Microsoft"
}
NAME_TO_TYPE=[("airpods","headphones"),("beats","headphones"),("galaxy buds","headphones"),
              ("iphone","phone"),("ipad","tablet"),("galaxy","phone"),("pixel","phone"),
              ("huawei","phone"),("bmw","car"),("toyota","car"),("honda","car"),("ford","car"),
              ("mazda","car"),("watch","watch"),("mi band","fitness"),("fitbit","fitness"),
              ("ps4","game"),("ps5","game"),("nintendo","game"),("joy-con","game"),("switch","game"),
              ("printer","printer"),("tv","tv"),("chromecast","tv"),("roku","tv"),("apple tv","tv"),
              ("bose","headphones"),("jbl","headphones"),("anker","headphones"),
              ("sennheiser","headphones"),("earbuds","headphones"),("garmin","fitness"),
              ("suunto","fitness"),("industrial","iot"),("esp32","iot"),("raspberry","iot"),("xiaomi","iot")]
UUID_TO_TYPE=[("180a","deviceinfo"),("180f","battery"),("181d","fitness"),("180d","fitness"),
              ("fee7","xiaomi"),("fd6f","fitness"),("fee0","fitness"),("fd44","car"),
              ("1812","audio"),("fff0","audio"),("fd3a","car"),("f3fe","rogue")]

# ---------- helpers ----------
def normalize_name(name:str) -> str:
    if not name: return ""
    s=name.lower()
    for ch in ("_","-",".","(",")","[","]"): s=s.replace(ch," ")
    return " ".join(t for t in s.split() if not t.isdigit())

VENDOR_NAME_HINTS={"airpods":"apple","iphone":"apple","ipad":"apple","apple":"apple","beats":"apple",
                   "galaxy":"samsung","bud":"samsung","pixel":"google","chromecast":"google",
                   "bose":"bose","jbl":"jbl","anker":"anker","sennheiser":"sennheiser",
                   "bmw":"bmw","toyota":"toyota","honda":"honda","ford":"ford","mazda":"mazda"}

def implied_vendor_from_name(name:str):
    n=normalize_name(name)
    for h,v in VENDOR_NAME_HINTS.items():
        if h in n: return v
    return None

def robust_stats(vals):
    if not vals: return (None,None,None)
    v=sorted(vals); n=len(v)
    med=v[n//2] if n%2 else (v[n//2-1]+v[n//2])/2
    mad=sorted([abs(x-med) for x in v])[n//2]
    madn=mad*1.4826; rng=(max(v)-min(v)) if n>=2 else 0
    return med,madn,rng

def pearson_corr(a,b):
    n=min(len(a),len(b))
    if n<6: return None
    a=a[-n:]; b=b[-n:]; ma=sum(a)/n; mb=sum(b)/n
    num=sum((x-ma)*(y-mb) for x,y in zip(a,b))
    dena=sum((x-ma)**2 for x in a)**0.5; denb=sum((y-mb)**2 for y in b)**0.5
    if dena==0 or denb==0: return None
    return num/(dena*denb)

def adv_signature(local_name, uuids_list):
    name=(local_name or "").strip().lower()
    uu=",".join(sorted((uuids_list or [])))
    h=blake2b(digest_size=8); h.update(name.encode()); h.update(b"|"); h.update(uu.encode())
    return h.hexdigest()

def oui_prefix(mac): return ":".join(mac.upper().split(":")[:3])

def safe_addstr(win, y, x, text, attr=0):
    max_y,max_x=win.getmaxyx()
    try:
        s=str(text)
        if y<0 or x<0 or y>=max_y: return
        win.addstr(y, x, s[:max_x-x-1], attr)
    except curses.error:
        pass

def estimate_distance(rssi, tx_power=-59, n=2):
    if rssi is None or rssi==0 or (isinstance(rssi,float) and math.isnan(rssi)): return "?"
    try: return round(pow(10, (tx_power-rssi)/(10*n)), 1)
    except Exception: return "?"

def device_type_from_all(addr, name, uuids, vendor):
    t=None; ln=(name or "").lower()
    for patt,typ in NAME_TO_TYPE:
        if patt in ln: t=typ; break
    if not t:
        for patt,typ in UUID_TO_TYPE:
            if patt in (uuids or "").lower(): t=typ; break
    if not t:
        v=(vendor or "").lower()
        if any(car in v for car in ["toyota","bmw","ford","honda","mazda"]): t="car"
    if not t and vendor and "apple" in vendor.lower(): t="phone"
    return t or "unknown"

def _norm_uuid(u: str) -> str:
    if not u: return ""
    s = u.lower().replace("-", "")
    if len(s) == 4: return s
    if len(s) == 32:
        short = s[4:8]
        return short if all(ch in "0123456789abcdef" for ch in short) else s[:8]
    return s[:8]

def _fmt_hex(b: bytes, maxlen: int = 16) -> str:
    if not b: return ""
    s = "-".join(f"{x:02x}" for x in b[:maxlen])
    return s + ("…" if len(b) > maxlen else "")

def _count_unique_sets(history_deque) -> int:
    return len({t for _, t in history_deque})

def _summarize_uuid_counter(counter: Counter, k: int = 10) -> list:
    return [f"{u}:{n}" for u, n in counter.most_common(k)]

# ---------- UI helpers ----------
def draw_box(win, y, x, h, w, title=None, color=0):
    try:
        sub=win.derwin(h, w, y, x); sub.box()
        if title: safe_addstr(sub, 0, 2, f" {title} ", color | curses.A_BOLD)
        return sub
    except Exception:
        return win

def underline(win, y, x, text):
    safe_addstr(win, y, x, text, curses.A_UNDERLINE | curses.A_BOLD)

def format_columns(items, cols=2, colw=24):
    rows=max(1, (len(items)+cols-1)//cols); out=[""]*rows
    for i,it in enumerate(items):
        r=i%rows; out[r]+= (str(it)[:colw]).ljust(colw+2)
    return out

def draw_node_bubbles(win, peers:list, y, x, wmax):
    safe_addstr(win, y, x, "Nodes:", curses.A_BOLD); x += 8
    labels=[]
    for nid, age, _ in sorted(peers):
        filled = "●" if age < 5 else "○"
        labels.append(f"{filled} {nid}")
    line="  ".join(labels)
    safe_addstr(win, y, x, line[:max(0,wmax-x-2)])

def apply_color_brightness():
    return {0: 0, 1: curses.A_BOLD, 2: curses.A_BOLD | curses.A_STANDOUT}

# ---------- threat planning ----------
def confidence_score(mem):
    base = 1 + min(len(mem['events'])//5, 4)
    if mem.get('type','unknown') == "unknown": base = max(1, base-2)
    if "mac_cycling" in mem.get('patterns', []): base = min(5, base+1)
    if "shadow_follower" in mem.get('patterns', []): base = min(5, base+1)
    return base

def plan_action(mem):
    c = confidence_score(mem)
    if mem['threat_rating'] == 1: return "monitor" if c < 4 else "attack"
    if mem['threat_rating'] == 2: return "monitor"
    return "ignore"

def sparkline(seq, width=60, lo=-100, hi=-30):
    if not seq: return "-"*width
    chars=" ▁▂▃▄▅▆▇█"; vals=list(seq)[-width:]; out=[]
    for v in vals:
        v = lo if v is None else max(lo, min(hi, v))
        idx=int((v-lo)/(hi-lo)*(len(chars)-1)); out.append(chars[idx])
    return "".join(out).ljust(width)

def _truncate(s, n): s=str(s); return s if len(s)<=n else s[:max(0,n-3)]+"..."

PATTERN_GROUPS = {
    "Identity": {"double_ssid","name_clone","uuid_twin","name_vendor_mismatch"},
    "Dynamics": {"unstable_rssi","name_flap","uuid_flap","teleport","mac_cycling"},
    "Correlation": {"mirrored_rssi","shadow_follower","co_appearance"},
    "Policy": {"denylist","trained_rogue","trained_benign","known_safe","rogue_vendor","beacon_storm","storm_src"},
}
def group_patterns(pats:set):
    out=defaultdict(list)
    for p in sorted(pats):
        placed=False
        for g,S in PATTERN_GROUPS.items():
            if p in S: out[g].append(p); placed=True; break
        if not placed: out["Other"].append(p)
    return out

# ---------- triangulation skeleton ----------
class Triangulator:
    @staticmethod
    def laterate_rssi(anchors, pathloss_n=2.0, tx_power_dbm=-59):
        """
        anchors: [{ 'node':'id', 'pos':(x,y), 'rssi':-68 }]
        Returns ((x,y), meta) or (None, {'err':...})
        """
        try:
            import numpy as np
        except Exception:
            return None, {'err':'numpy not available'}
        pts=[]; dists=[]
        for a in anchors:
            if a.get('rssi') is None or a.get('pos') is None: continue
            d = 10 ** ((tx_power_dbm - a['rssi'])/(10*pathloss_n))
            pts.append(a['pos']); dists.append(d)
        if len(pts) < 3: return None, {'err':'need >=3 distances'}
        import numpy as np
        P=np.array(pts); d=np.array(dists)
        x1,y1=P[0]; A=[]; b=[]
        for (xi,yi),di in zip(P[1:],d[1:]):
            A.append([2*(xi-x1), 2*(yi-y1)])
            b.append(di**2 - d[0]**2 - xi**2 - yi**2 + x1**2 + y1**2)
        A=np.array(A); b=np.array(b)
        try:
            sol, *_ = np.linalg.lstsq(A,b,rcond=None)
            return (float(sol[0]), float(sol[1])), {'anchors':len(pts)}
        except Exception as e:
            return None, {'err':str(e)}

# ========================================
# ============== SherloCK ================
# ========================================
class SherloCKCPU:
    def __init__(self, stdscr):
        # Identity / Mesh
        self.stdscr = stdscr
        self.node_id = os.environ.get("NODE_ID") or socket.gethostname()
        self.mesh = MeshManager(self.node_id)
        self.mesh_dir = self.mesh.mesh_dir
        self.mesh_status_dir = self.mesh.status_dir
        self.mesh_inbox_dir = self.mesh.inbox_dir
        self.last_mesh_check = 0
        self.mesh_health = self.mesh.health_check()

        # Bootstrap files & defaults
        self._bootstrap_files()

        # UI & state
        self.beacons = {}
        self.status = "Idle"; self.alert = ""
        self.active_tab = "scan"
        self.running = True; self.last_draw = 0
        self.scan_selection = 0; self.scan_page = 0
        self.filter_min_rssi = -100; self.filter_max_rssi = 0
        self.script_dialog_open = False; self.script_input = ""; self.script_cursor = 0
        self.hotlist = set(); self.action_log = deque(maxlen=200)
        self.ai_command_prompt_open = False; self.ai_command_input = ""; self.ai_command_cursor = 0
        self.profile_mac = None
        self.color_brightness = 1  # 0..2
        self.ai_subtab = 1         # AI sub-tabs
        self.scan_num_input = ""   # numeric selection buffer
        self.scan_num_ts = 0.0

        # ticker settings
        self.ticker_msgs=[]; self.ticker_index=0; self.ticker_offset=0
        self.ticker_last=time.time(); self.ticker_speed=18.0
        self.banner_last_load=0.0
        self.ticker_color_name = os.environ.get("TICKER_COLOR","green")

        # --- session/usage timer ---
        self.session_start = time.time()
        self.session_last_update = self.session_start
        self.usage_path = CONFIG_DIR / "usage.json"
        self.total_usage_sec = 0
        self._load_usage()

        # Memories / state
        self.device_ai_memory = defaultdict(lambda:{
            'events':deque(maxlen=160),'attention':0,'status':'idle','patterns':set(),
            'notes':'','cluster':'benign','timeline':deque(maxlen=160),'ignore':False,
            'flag':False,'threat_rating':3,'type':'unknown','last_seen':time.time(),
            'last_dist':None,'last_dist_ts':None,'label':None,'user_tags':set()
        })
        self.device_clusters=defaultdict(list); self.case_file_summaries={}
        self.sherlock_pet_status="Investigating"; self.focused_mac=None
        self.rssi_history=defaultdict(lambda:deque(maxlen=80)); self.mac_lifetimes=defaultdict(lambda:deque(maxlen=500))
        self.known_safe=set(); self.active_ouis=set()

        # UUID/manufacturer/service-data capture
        self.uuid_history = defaultdict(lambda: deque(maxlen=120))   # (ts, tuple(uuids))
        self.uuid_counter = defaultdict(Counter)                      # uuid -> count
        self.mfr_history  = defaultdict(lambda: deque(maxlen=60))    # (ts, cid, bytes)
        self.mfr_last     = defaultdict(dict)                        # {'cid': int, 'len': int}
        self.svc_history  = defaultdict(lambda: deque(maxlen=60))    # (ts, uuid16, bytes)
        self.svc_last     = defaultdict(dict)

        # Correlation windows
        self.name_windows=defaultdict(lambda:deque(maxlen=600))
        self.uuid_windows=defaultdict(lambda:deque(maxlen=600))
        self.name_window_secs=300; self.co_appearance_secs=15

        # Storm & quarantine
        self.per_mac_events=defaultdict(lambda:deque(maxlen=512))
        self.per_sig_events=defaultdict(lambda:deque(maxlen=1024))
        self.global_events=deque(maxlen=2000)
        self.quarantine_until=defaultdict(float); self.quarantine_secs=45

        # Hunt
        self.hunt_best=None

        # Lists
        self.allowlist=set(); self.denylist=set(); self.load_lists()

        # Training DB
        self.training_db_path=str(TRAIN_DB); self.training_db={}; self.load_training_db(); self.last_train_save=0

        # AI modes
        self.prev_mode=None; self.ai_mode="normal"; self.tuning={}; self.apply_mode("normal")

        # Scanner
        self.scanner=None; self.scan_should_restart=False

        # Threat DB
        self.csv_file=str(THREAT_DB)
        self.csv_headers=["time","mac","name","rssi","uuids","vendor","type","detected_by","notes","threat_rating"]
        if not os.path.exists(self.csv_file):
            with open(self.csv_file,"w",newline="") as f: csv.writer(f).writerow(self.csv_headers)
        self.load_known_safe()

        # Housekeeping
        self.last_janitor=0

        # Cluster power knobs
        self.ai_workers = max(1, (os.cpu_count() or 1)//2)
        self.openblas_threads = self.ai_workers
        self.omp_threads = self.ai_workers
        self.affinity_mask = None
        self.cpu_governor = None

        # Triangulation anchors (persist)
        self.anchors_path = CONFIG_DIR / "anchors.json"
        self.anchors = {}  # node_id -> (x,y)
        self._load_anchors()
        self.tri_watch = set()  # macs to publish rssi for

    # ----- bootstrap -----
    def _bootstrap_files(self):
        try:
            for p in [APP_ROOT, DATA_DIR, CONFIG_DIR, LOGS_DIR, TOOLS_DIR, BANNERS_DIR]:
                p.mkdir(parents=True, exist_ok=True)
            if not THREAT_DB.exists():
                with open(THREAT_DB,"w",newline="") as f:
                    csv.writer(f).writerow(["time","mac","name","rssi","uuids","vendor","type","detected_by","notes","threat_rating"])
            if not TRAIN_DB.exists():
                with open(TRAIN_DB,"w",newline="") as f:
                    csv.writer(f).writerow(["name_norm","oui","uuids_sig","dtype","label","seen","rssi_med","rssi_min","rssi_max","last_seen"])
            cfg = CONFIG_DIR / "sherlock.json"
            if not cfg.exists():
                with open(cfg,"w") as f: json.dump({"version":3,"created":time.time()}, f)
            # banners
            sample = BANNERS_DIR / "00-welcome.txt"
            if not sample.exists():
                sample.write_text("Welcome to SherloCK by Machiware 2025  |  Node {node}  |  {time}  |  Uptime {uptime}\n")
            sched = BANNERS_DIR / "schedule.json"
            if not sched.exists():
                json.dump([
                    {"message": "Morning watch: BLE {ble_rate} — consider tri watch add <mac>", "when": {"hour_range":[6,10]}},
                    {"message": "Mode {mode}: RAM {ram} ({ram_pct}) cores:{cores} load1:{load1}", "when": {}},
                    {"message": "Heat alert: temp {temp_max} — reduce threads via 'compute threads <n>'", "when": {"temp_gt": 70}}
                ], open(sched, "w"))
        except Exception:
            logging.exception("bootstrap")

    # ----- uptime/usage helpers -----
    def _uptime_seconds(self) -> int:
        return int(time.time() - self.session_start)

    def _fmt_uptime(self, secs: int) -> str:
        d, r = divmod(secs, 86400)
        h, r = divmod(r, 3600)
        m, s = divmod(r, 60)
        if d > 0:
            return f"{d}d {h:02}:{m:02}:{s:02}"
        return f"{h:02}:{m:02}:{s:02}"

    def _load_usage(self):
        try:
            if self.usage_path.exists():
                data = json.load(open(self.usage_path))
                self.total_usage_sec = int(data.get("total_sec", 0))
        except Exception:
            logging.exception("usage load")

    def _save_usage(self, finalize: bool = False):
        try:
            now = time.time()
            self.total_usage_sec += int(now - self.session_last_update)
            self.session_last_update = now
            tmp = str(self.usage_path) + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"total_sec": self.total_usage_sec, "updated": now}, f)
            os.replace(tmp, self.usage_path)
        except Exception:
            logging.exception("usage save")

    # ----- system metrics & BLE rate -----
    def _read_temps(self):
        temps = {}
        try:
            st = psutil.sensors_temperatures()
            if st:
                for k, arr in st.items():
                    vals = [s.current for s in arr if getattr(s, "current", None) is not None]
                    if vals: temps[k] = max(vals)
        except Exception:
            pass
        if temps: return temps
        for p in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
            try:
                with open(p) as f:
                    mv = int(f.read().strip())
                temps[pathlib.Path(p).parent.name] = mv / 1000.0
            except Exception:
                pass
        return temps

    def _sys_metrics(self):
        v = psutil.virtual_memory()
        ram_used_mb = int(v.used / (1 << 20))
        ram_total_mb = int(v.total / (1 << 20))
        ram_pct = v.percent
        cores = os.cpu_count() or 1
        try:
            load1, load5, load15 = os.getloadavg()
        except Exception:
            load1 = load5 = load15 = 0.0
        temps = self._read_temps()
        temp_max = max(temps.values()) if temps else None
        return {
            "ram_pct": ram_pct,
            "ram_str": f"{ram_used_mb}/{ram_total_mb} MiB",
            "cores": cores,
            "load1": round(load1, 2),
            "load5": round(load5, 2),
            "load15": round(load15, 2),
            "temp_max": round(temp_max, 1) if temp_max is not None else None,
            "temps": temps,
        }

    def _ble_rate(self, window=15.0):
        now = time.time()
        return sum(1 for ts in self.global_events if now - ts <= window) / max(1.0, window)

    # ----- banners/ticker (scheduled + conditional) -----
    def _banner_tokens(self):
        m = self._sys_metrics()
        return {
            "node": self.node_id,
            "mode": self.ai_mode,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "uptime": self._fmt_uptime(self._uptime_seconds()),
            "ble_rate": f"{self._ble_rate(15):.1f}/s",
            "ram_pct": f"{m['ram_pct']:.0f}%",
            "ram": m["ram_str"],
            "cores": str(m["cores"]),
            "load1": f"{m['load1']:.2f}",
            "load5": f"{m['load5']:.2f}",
            "load15": f"{m['load15']:.2f}",
            "temp_max": f"{m['temp_max']:.1f}°C" if m["temp_max"] is not None else "n/a",
        }

    def _eval_schedule_condition(self, cond: dict) -> bool:
        try:
            now = time.localtime()
            hr = now.tm_hour
            dow = now.tm_wday  # 0=Mon
            if "hour_range" in cond:
                a, b = cond["hour_range"]
                if not (a <= hr < b): return False
            if "days" in cond and dow not in cond["days"]: return False
            if "mode" in cond and str(cond["mode"]).lower() != self.ai_mode: return False
            br = self._ble_rate(15.0)
            if "ble_rate_gt" in cond and not (br > float(cond["ble_rate_gt"])): return False
            if "ble_rate_lt" in cond and not (br < float(cond["ble_rate_lt"])): return False
            m = self._sys_metrics()
            if "temp_gt" in cond:
                t = m["temp_max"] if m["temp_max"] is not None else -1
                if not (t > float(cond["temp_gt"])): return False
            return True
        except Exception:
            return False

    def _render_message(self, template: str) -> str:
        tokens = self._banner_tokens()
        out = template
        for k, v in tokens.items():
            out = out.replace("{" + k + "}", str(v))
        return out

    def _load_banners(self):
        msgs=[]
        try:
            for p in sorted(BANNERS_DIR.glob("*.txt")):
                try:
                    txt = p.read_text(errors="ignore").strip()
                    if txt: msgs.append(self._render_message(txt.replace("\n","  ")))
                except Exception: pass
        except Exception:
            logging.exception("load banners (txt)")
        try:
            sched_path = BANNERS_DIR / "schedule.json"
            if sched_path.exists():
                data = json.load(open(sched_path))
                items = data if isinstance(data, list) else data.get("items", [])
                for item in items:
                    msg = item.get("message", "")
                    cond = item.get("when", {})
                    if msg and self._eval_schedule_condition(cond):
                        msgs.append(self._render_message(msg))
        except Exception:
            logging.exception("load banners (schedule)")
        msgs.append("Keys: w/a/i/h/n/s | ENTER profile | x script | / cmd | m mode | R restart | q quit")
        self.ticker_msgs = msgs or ["SherloCK ready."]
        self.banner_last_load = time.time()

    # color pairs for ticker; call from run()
    def _init_colors(self):
        self._color_pairs = {}
        try:
            curses.start_color(); curses.use_default_colors()
            base = {
                "green":   curses.COLOR_GREEN,
                "cyan":    curses.COLOR_CYAN,
                "yellow":  curses.COLOR_YELLOW,
                "magenta": curses.COLOR_MAGENTA,
                "white":   curses.COLOR_WHITE,
                "red":     curses.COLOR_RED,
            }
            pid = 20
            for name, col in base.items():
                curses.init_pair(pid, col, -1)
                self._color_pairs[name] = pid
                pid += 1
        except Exception:
            pass

    def _ticker_color_attr(self):
        pid = self._color_pairs.get(self.ticker_color_name, self._color_pairs.get("green", 0))
        attr = curses.color_pair(pid) if pid else 0
        attr |= apply_color_brightness()[self.color_brightness]
        return attr

    def _ticker_next_slice(self, width):
        if not self.ticker_msgs or (time.time()-self.banner_last_load) > 10:
            self._load_banners()
        msg = self.ticker_msgs[self.ticker_index % len(self.ticker_msgs)]
        msg_pad = f"   {msg}   "
        dt=time.time()-self.ticker_last; self.ticker_last=time.time()
        self.ticker_offset = (self.ticker_offset + max(1,int(self.ticker_speed*dt))) % len(msg_pad)
        s = (msg_pad + msg_pad)[self.ticker_offset:self.ticker_offset+max(10,width-4)]
        if self.ticker_offset==0: self.ticker_index += 1
        return s

    # ----- lists (allow/deny) -----
    def load_lists(self):
        paths = [(CONFIG_DIR / "allowlist.txt", self.allowlist),
                 (CONFIG_DIR / "denylist.txt",  self.denylist)]
        for fp, target in paths:
            try:
                if fp.exists():
                    with open(fp) as f:
                        for line in f:
                            mac = line.strip().upper()
                            if mac: target.add(mac)
            except Exception:
                logging.exception("list load")

    def save_list(self, which: str):
        try:
            if which == "allow":
                with open(CONFIG_DIR / "allowlist.txt", "w") as f:
                    f.write("\n".join(sorted(self.allowlist)) + "\n")
            elif which == "deny":
                with open(CONFIG_DIR / "denylist.txt", "w") as f:
                    f.write("\n".join(sorted(self.denylist)) + "\n")
        except Exception:
            logging.exception("list save")

    # ----- training DB helpers -----
    def training_key(self, mac, name, uuids_list):
        return (normalize_name(name or ""), oui_prefix(mac), ",".join(sorted((uuids_list or []))))

    def load_training_db(self):
        self.training_db = {}
        p = pathlib.Path(self.training_db_path)
        if not p.exists(): return
        try:
            with open(p, newline="") as f:
                r = csv.DictReader(f)
                for row in r:
                    key = (row["name_norm"], row["oui"], row["uuids_sig"])
                    self.training_db[key] = {
                        "dtype": row.get("dtype", ""),
                        "label": row.get("label", ""),
                        "seen": row.get("seen", 0),
                        "rssi_med": row.get("rssi_med", ""),
                        "rssi_min": row.get("rssi_min", ""),
                        "rssi_max": row.get("rssi_max", ""),
                        "last_seen": row.get("last_seen", ""),
                    }
        except Exception:
            logging.exception("load_training_db")

    def save_training_db(self):
        try:
            with open(self.training_db_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["name_norm","oui","uuids_sig","dtype","label","seen","rssi_med","rssi_min","rssi_max","last_seen"])
                for key, rec in self.training_db.items():
                    w.writerow([key[0], key[1], key[2],
                                rec.get("dtype",""), rec.get("label",""),
                                rec.get("seen",0), rec.get("rssi_med",""),
                                rec.get("rssi_min",""), rec.get("rssi_max",""),
                                rec.get("last_seen","")])
        except Exception:
            logging.exception("save_training_db")

    def update_training_from_current(self):
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        for mac,(rssi,uuids,name,_) in self.beacons.items():
            uuids_list=[u.strip() for u in (uuids.split(",") if uuids else []) if u.strip()]
            key=self.training_key(mac,name,uuids_list)
            mem=self.device_ai_memory[mac]
            vals=[rv for _,rv in self.rssi_history[mac] if rv is not None]
            med,_,_=robust_stats(vals); rmin=min(vals) if vals else ""; rmax=max(vals) if vals else ""
            rec=self.training_db.get(key, {"dtype":mem.get("type","unknown"),"label":(mem.get("label") or ""), "seen":0})
            rec["dtype"]=mem.get("type","unknown") or rec.get("dtype","")
            rec["label"]=(mem.get("label") or rec.get("label") or "")
            rec["seen"]=int(rec.get("seen",0))+1
            rec["rssi_med"]=med if med is not None else rec.get("rssi_med","")
            rec["rssi_min"]=rmin if rmin!="" else rec.get("rssi_min","")
            rec["rssi_max"]=rmax if rmax!="" else rec.get("rssi_max","")
            rec["last_seen"]=now
            self.training_db[key]=rec

    def apply_training_to_memory(self, mac, name, uuids_list, mem):
        key=self.training_key(mac,name,uuids_list)
        rec=self.training_db.get(key)
        if not rec: return
        label=(rec.get("label") or "").lower()
        if rec.get("dtype"): mem['type']=rec["dtype"]
        if label=="benign":
            self.known_safe.add(mac.upper()); mem['patterns'].add("trained_benign")
        elif label=="rogue":
            mem['patterns'].add("trained_rogue"); mem['attention']=max(mem.get('attention',0),3)

    def load_known_safe(self):
        try:
            if not os.path.exists(self.csv_file): return
            with open(self.csv_file, newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("mac") and int(row.get("threat_rating",3)) != 1 and self.ai_mode != "paranoid":
                        self.known_safe.add(row["mac"].upper())
        except Exception:
            logging.exception("Threat DB scan error")

    # ----- AI modes / tuning -----
    def apply_mode(self, mode):
        self.prev_mode, self.ai_mode = self.ai_mode, mode.lower()
        if self.prev_mode=="training" and self.ai_mode!="training":
            self.update_training_from_current(); self.save_training_db()
            self.action_log.append("Training knowledge saved.")
        if self.ai_mode=="paranoid":
            self.tuning=dict(rssi_step=4,unstable_mad=6,unstable_range=14,mirror_delta=2,
                             name_window=420,co_appearance=25,storm_thresh=60,
                             follower_corr=0.93,follower_avgdiff=2.5,teleport_speed=6.0,burst_rate=6)
        elif self.ai_mode=="relaxed":
            self.tuning=dict(rssi_step=6,unstable_mad=10,unstable_range=24,mirror_delta=3,
                             name_window=240,co_appearance=10,storm_thresh=100,
                             follower_corr=0.97,follower_avgdiff=1.8,teleport_speed=10.0,burst_rate=10)
        elif self.ai_mode=="training":
            self.tuning=dict(rssi_step=6,unstable_mad=11,unstable_range=26,mirror_delta=3,
                             name_window=240,co_appearance=12,storm_thresh=120,
                             follower_corr=0.98,follower_avgdiff=1.5,teleport_speed=12.0,burst_rate=12)
        else:
            self.tuning=dict(rssi_step=5,unstable_mad=8,unstable_range=18,mirror_delta=2,
                             name_window=300,co_appearance=15,storm_thresh=80,
                             follower_corr=0.95,follower_avgdiff=2.0,teleport_speed=8.0,burst_rate=8)
        self.name_window_secs=self.tuning["name_window"]
        self.co_appearance_secs=self.tuning["co_appearance"]

    def set_ai_mode(self, mode):
        self.apply_mode(mode); self.action_log.append(f"AI mode set to {self.ai_mode}")

    def cycle_ai_mode(self):
        order=["relaxed","normal","paranoid","training"]
        try: i=(order.index(self.ai_mode)+1)%len(order)
        except ValueError: i=1
        self.set_ai_mode(order[i])

    # ----- triangulation helpers -----
    def _parse_anchor_spec(self, tok: str):
        try:
            node, rest = tok.split(":", 1)
            if "," in rest and ":" in rest:
                xy, rssi = rest.split(":")
                x, y = xy.split(","); return {'node':node, 'pos':(float(x), float(y)), 'rssi': float(rssi)}
            rssi = float(rest)
            if node not in self.anchors: return None
            return {'node':node, 'pos':tuple(map(float, self.anchors[node])), 'rssi': rssi}
        except Exception:
            return None

    def collect_mesh_anchors_for_mac(self, mac: str):
        anchors=[]
        try:
            peers = self.mesh._peer_statuses()
            for nid, age, d in peers:
                a = d.get("anchor")
                wr = (d.get("watch_rssi") or {})
                rssi = wr.get(mac.upper()) or wr.get(mac.lower())
                if a and rssi is not None:
                    anchors.append({'node':nid, 'pos':tuple(a), 'rssi':float(rssi)})
        except Exception:
            logging.exception("collect_mesh_anchors")
        if self.node_id in self.anchors and mac in self.beacons:
            anchors.append({'node':self.node_id,'pos':self.anchors[self.node_id],'rssi':self.beacons[mac][0]})
        ded={}
        for a in anchors: ded[a['node']]=a
        return list(ded.values())

    def triangulate_target(self, anchors):
        return Triangulator.laterate_rssi(anchors)

    # ----- anchors & compute knobs (helpers) -----
    def _load_anchors(self):
        try:
            if self.anchors_path.exists():
                self.anchors = {k: tuple(v) for k,v in json.load(open(self.anchors_path)).items()}
        except Exception:
            logging.exception("load anchors")

    def _save_anchors(self):
        try:
            tmp = str(self.anchors_path)+".tmp"
            with open(tmp,"w") as f: json.dump(self.anchors, f)
            os.replace(tmp, self.anchors_path)
        except Exception:
            logging.exception("save anchors")

    def _set_env_threads(self):
        try:
            os.environ["OPENBLAS_NUM_THREADS"] = str(self.openblas_threads)
            os.environ["OMP_NUM_THREADS"] = str(self.omp_threads)
        except Exception:
            pass

    def _apply_affinity(self):
        try:
            if hasattr(psutil.Process(), "cpu_affinity") and self.affinity_mask is not None:
                psutil.Process(os.getpid()).cpu_affinity(self.affinity_mask)
        except Exception:
            logging.exception("affinity")

    def _read_governor(self):
        try:
            path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
            if os.path.exists(path):
                with open(path) as f: return f.read().strip()
        except Exception:
            pass
        return "unknown"

    def _set_governor(self, gov: str) -> bool:
        try:
            # best-effort via cpupower if present
            if shutil.which("cpupower"):
                r = subprocess.run(["sudo","cpupower","frequency-set","-g",gov], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return r.returncode==0
            # direct write (may require root)
            for p in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"):
                try:
                    with open(p,"w") as f: f.write(gov)
                except Exception:
                    pass
            return True
        except Exception:
            return False
    # ----- scanner -----
    def bleak_filters(self):
        rssi_floor=max(self.filter_min_rssi, -95)
        return {"Transport":"le","DuplicateData":False,"RSSI":rssi_floor}

    def create_scanner(self, callback):
        if BleakScanner is None:
            raise RuntimeError("bleak not available")
        try:
            return BleakScanner(callback, bluez={"filters": self.bleak_filters()})
        except TypeError:
            return BleakScanner(callback, filters=self.bleak_filters())

    def request_scan_restart(self):
        self.scan_should_restart=True
        self.action_log.append("Restarting scan to apply adapter filters...")

    async def ble_scan(self):
        def rate(dq):
            if len(dq)<2: return 0.0
            span=max(0.001, dq[-1]-dq[0]); return len(dq)/span

        def detection_callback(device, advertisement_data):
            try:
                uuids_list=getattr(advertisement_data, "service_uuids", None) or []
                uuids=", ".join(uuids_list)
                local_name=getattr(advertisement_data, "local_name", None) or device.name or ""
                device_rssi=getattr(advertisement_data,"rssi",None)
                if device_rssi is None: device_rssi=getattr(device,"rssi",None)
                ts=time.time(); mac=device.address; macU=mac.upper()

                # --- capture frames
                norm_uuids = tuple(sorted(_norm_uuid(u) for u in uuids_list if u))
                if norm_uuids:
                    self.uuid_history[mac].append((ts, norm_uuids))
                    for u in norm_uuids: self.uuid_counter[mac][u] += 1
                mfr = getattr(advertisement_data, "manufacturer_data", None) or {}
                if isinstance(mfr, dict) and mfr:
                    try:
                        cid, payload = next(iter(mfr.items()))
                        b = bytes(payload) if not isinstance(payload, (bytes, bytearray)) else bytes(payload)
                        self.mfr_history[mac].append((ts, int(cid), b[:24]))
                        self.mfr_last[mac] = {'cid': int(cid), 'len': len(b)}
                    except Exception: pass
                svc = getattr(advertisement_data, "service_data", None) or {}
                if isinstance(svc, dict) and svc:
                    try:
                        su, spayload = next(iter(svc.items()))
                        short = _norm_uuid(str(su))
                        sb = bytes(spayload) if not isinstance(spayload, (bytes, bytearray)) else bytes(spayload)
                        self.svc_history[mac].append((ts, short, sb[:24]))
                        self.svc_last[mac] = {'uuid': short, 'len': len(sb)}
                    except Exception: pass
                # --- END capture

                if macU in self.denylist:
                    mem=self.device_ai_memory[mac]; mem['patterns'].add("denylist")
                    self.quarantine_until[mac]=ts+max(self.quarantine_secs,300)
                    return
                if macU in self.allowlist: self.known_safe.add(macU)
                if ts < self.quarantine_until.get(mac,0.0): return

                self.global_events.append(ts)
                while self.global_events and ts-self.global_events[0]>2.0: self.global_events.popleft()
                self.per_mac_events[mac].append(ts)
                while self.per_mac_events[mac] and ts-self.per_mac_events[mac][0]>2.0: self.per_mac_events[mac].popleft()
                sig=adv_signature(local_name, uuids_list)
                self.per_sig_events[sig].append(ts)
                while self.per_sig_events[sig] and ts-self.per_sig_events[sig][0]>2.0: self.per_sig_events[sig].popleft()

                mac_rate=rate(self.per_mac_events[mac]); sig_rate=rate(self.per_sig_events[sig]); global_rate=rate(self.global_events)
                burst=self.tuning.get("burst_rate",8)
                if mac_rate>burst or sig_rate>(burst*1.2) or global_rate>(burst*3):
                    mem=self.device_ai_memory[mac]
                    mem['patterns'].add("beacon_storm"); mem['patterns'].add("storm_src")
                    mem['notes']=f"Quarantine {int(self.quarantine_secs)}s (mac={mac_rate:.1f}/s sig={sig_rate:.1f}/s)"
                    mem['attention']=max(mem.get('attention',0),3)
                    self.quarantine_until[mac]=ts+self.quarantine_secs
                    return

                self.beacons[mac]=(device_rssi, uuids, local_name, ts)
                self.rssi_history[mac].append((ts, device_rssi))
                if local_name:
                    self.mac_lifetimes[local_name.lower()].append((mac, ts))
                    norm=normalize_name(local_name); oui=oui_prefix(mac)
                    uuid_sig=tuple(sorted([u.strip().lower() for u in uuids_list])) if uuids_list else ()
                    self.name_windows[norm].append((mac, ts, oui, uuid_sig))
                    self._prune_deque_time(self.name_windows[norm], ts, self.name_window_secs)
                    if uuid_sig:
                        self.uuid_windows[uuid_sig].append((mac, ts, oui, norm))
                        self._prune_deque_time(self.uuid_windows[uuid_sig], ts, self.name_window_secs)

                self.active_ouis.add(oui_prefix(mac))
                self.apply_training_to_memory(mac, local_name, uuids_list, self.device_ai_memory[mac])

            except Exception:
                logging.exception("BLE callback error")
                self.alert = "BLE callback error."

        try:
            self.scanner=self.create_scanner(detection_callback)
            await self.scanner.start()
            while self.running:
                if self.scan_should_restart:
                    try: await self.scanner.stop()
                    except Exception: pass
                    self.scanner=self.create_scanner(detection_callback)
                    await self.scanner.start()
                    self.scan_should_restart=False
                await asyncio.sleep(0.3)
            await self.scanner.stop()
        except Exception as e:
            logging.exception("BLE SCAN ERROR")
            self.alert=f"BLE SCAN ERROR: {e}"

    def _prune_deque_time(self, dq:deque, now:float, horizon:float):
        while dq and (now - dq[0][1]) > horizon:
            dq.popleft()

    # ----- filtered list -----
    def filtered_beacons(self):
        try:
            now=time.time(); to_del=[]
            for addr,(_,_,_,last_seen) in list(self.beacons.items()):
                if now-last_seen>600: to_del.append(addr)
            for addr in to_del:
                self.beacons.pop(addr,None); self.device_ai_memory.pop(addr,None); self.rssi_history.pop(addr,None)
            items=[(addr,info) for addr,info in self.beacons.items()
                   if info[0] is not None and self.filter_min_rssi <= info[0] <= self.filter_max_rssi]
            def sort_key(x):
                addr,(rssi,_,_,last)=x
                mem=self.device_ai_memory.get(addr,{})
                rating=mem.get('threat_rating',3)
                return (0 if rating==1 else 1 if rating==2 else 2, -(rssi or -200), -last)
            return sorted(items, key=sort_key)
        except Exception:
            logging.exception("Filtering error"); return []

    # ----- threat model & investigation -----
    def rate_threat(self, mem, addr=None):
        """
        CRIT: storm OR (clone + mismatch/cycling) OR trained_rogue.
        WARN: single strong anomaly; OBS otherwise. Training mode: only storms escalate.
        """
        pats = mem.get('patterns', set())
        if addr and addr.upper() in self.known_safe and self.ai_mode != "paranoid": return 3
        if mem.get('ignore', False): return 99
        storm = ("beacon_storm" in pats) or ("storm_src" in pats)
        clone = ("name_clone" in pats) or ("double_ssid" in pats) or ("uuid_twin" in pats)
        mismatch = ("name_vendor_mismatch" in pats) or ("rogue_vendor" in pats)
        cycling = ("mac_cycling" in pats)
        trained_bad = ("trained_rogue" in pats)

        if self.ai_mode == "training":
            if storm: return 1
            if clone and (mismatch or cycling or trained_bad): return 2
            return 2 if len(pats) >= 1 else 3

        if storm or trained_bad: return 1
        if clone and (mismatch or cycling): return 1
        strong = {"mac_cycling","mirrored_rssi","shadow_follower","uuid_flap",
                  "name_flap","unstable_rssi","name_vendor_mismatch","uuid_twin"}
        if len(pats & strong) >= 1 or mismatch: return 2
        return 3

    def sherlock_agent_investigation(self):
        try:
            now=time.time()
            self.focused_mac=None; self.device_clusters.clear(); self.case_file_summaries.clear()
            ssid_map=defaultdict(list); rssi_groups=defaultdict(list); t=self.tuning

            # Pre-type
            for addr,(rssi,uuids,local_name,last_seen) in self.beacons.items():
                vendor=OUI_TO_VENDOR.get(oui_prefix(addr),"unknown")
                dtype=device_type_from_all(addr,local_name,uuids,vendor)
                mem=self.device_ai_memory[addr]; mem['type']=dtype; mem['last_seen']=last_seen

            for addr,(rssi,uuids,local_name,last_seen) in self.beacons.items():
                mem=self.device_ai_memory[addr]
                mem['timeline'].append((now, rssi, uuids, local_name))
                patterns=set(); vendor=OUI_TO_VENDOR.get(oui_prefix(addr),"unknown")

                if oui_prefix(addr) not in OUI_TO_VENDOR: patterns.add("rogue_vendor")

                hist=self.rssi_history[addr]; values=[r for _,r in hist if r is not None]
                med,madn,rng=robust_stats(values)
                if values and ((madn and madn>t["unstable_mad"]) or (rng and rng>t["unstable_range"])): patterns.add("unstable_rssi")

                if rssi is not None:
                    dist=estimate_distance(rssi)
                    if isinstance(dist,(int,float)):
                        if mem['last_dist'] is not None and mem['last_dist_ts'] is not None:
                            dt=max(0.1, now-mem['last_dist_ts']); speed=abs(dist-mem['last_dist'])/dt
                            if speed>t["teleport_speed"]: patterns.add("teleport")
                        mem['last_dist']=dist; mem['last_dist_ts']=now

                if local_name:
                    n=normalize_name(local_name); ssid_map[n].append(addr)
                    window=self.name_windows.get(n,[])
                    recent=[m for m,ts,_,_ in window if (now-ts)<=self.co_appearance_secs]
                    if len(set(recent))>=2: patterns.add("co_appearance")
                    implied=implied_vendor_from_name(local_name)
                    if implied and vendor!="unknown" and implied not in vendor.lower(): patterns.add("name_vendor_mismatch")
                    ouis={o for _,ts,o,_ in window if (now-ts)<=self.name_window_secs}
                    if len(ouis)>=2: patterns.add("name_clone")
                    names_recent=[nm for _,_,_,nm in list(mem['timeline'])[-20:] if nm]
                    if len(set(normalize_name(x) for x in names_recent))>=4: patterns.add("name_flap")

                b=int(round((rssi or -200)/t["rssi_step"]))*t["rssi_step"] if rssi is not None else None
                if b is not None:
                    rssi_groups[b].append(addr)
                    for other_addr in rssi_groups[b]:
                        if addr!=other_addr:
                            orssi=self.beacons[other_addr][0]
                            if orssi is not None and abs((rssi or 0)-(orssi or 0))<=t["mirror_delta"]:
                                patterns.add("mirrored_rssi")
                                a_vals=[rv for _,rv in self.rssi_history[addr] if rv is not None]
                                b_vals=[rv for _,rv in self.rssi_history[other_addr] if rv is not None]
                                corr=pearson_corr(a_vals[-20:], b_vals[-20:])
                                if corr is not None:
                                    k=min(len(a_vals),len(b_vals),12)
                                    if k>=6:
                                        diffs=[abs(a_vals[-i]-b_vals[-i]) for i in range(1,k+1)]
                                        avgdiff=sum(diffs)/len(diffs)
                                        if corr>=t["follower_corr"] and avgdiff<=t["follower_avgdiff"]:
                                            patterns.add("shadow_follower")
                                break

                if uuids:
                    sig=tuple(sorted([u.strip().lower() for u in uuids.split(",") if u.strip()]))
                    twin_window=self.uuid_windows.get(sig,[])
                    ouis_for_sig={o for _,ts,o,_ in twin_window if (now-ts)<=self.name_window_secs}
                    if len(ouis_for_sig)>=2: patterns.add("uuid_twin")
                if mem['timeline']:
                    recent_uuids=[tuple(sorted([u.strip().lower() for u in (uu or "").split(",") if u.strip()])) for _,_,uu,_ in list(mem['timeline'])[-20:]]
                    nonempty=[x for x in recent_uuids if x]
                    if len(set(nonempty))>=4: patterns.add("uuid_flap")

                if local_name:
                    name_deque=self.mac_lifetimes[local_name.lower()]
                    self._prune_deque_time(name_deque, now, self.name_window_secs)
                    macs_recent={m for m,_ in name_deque}
                    if len(macs_recent)>=3: patterns.add("mac_cycling")

                mem['patterns'] |= patterns

            for ssid, addrs in ssid_map.items():
                if len(set(addrs))>1:
                    for a in addrs:
                        mem=self.device_ai_memory[a]
                        mem['patterns'].add('double_ssid')
                        mem['events'].append((now, ['double_ssid']))
                        mem['notes']=f"Same name as others ({ssid})"
                        mem['attention']=min(mem['attention']+1, 3)
                        mem['status']='analyzing' if mem['attention']>=2 else 'watching'

            if len(self.beacons) > self.tuning["storm_thresh"]:
                for addr,mem in self.device_ai_memory.items(): mem['patterns'].add('beacon_storm')

            highest=-1
            for addr,mem in self.device_ai_memory.items():
                prev=mem['attention']; n=len(mem['patterns'])
                if n>0: mem['attention']=max(mem['attention'], n)
                if n==0 and prev>0 and (time.time()*1000)%10 < 1:
                    mem['attention']=max(0, prev-1)
                    if mem['attention']==0: mem['status']='idle'
                mem['status']='alarm' if mem['attention']>=3 else 'analyzing' if mem['attention']==2 else 'watching' if mem['attention']==1 else 'idle'
                mem['threat_rating']=self.rate_threat(mem, addr)
                label=tuple(sorted(mem['patterns'])) or ('benign',); mem['cluster']=label
                self.device_clusters[label].append(addr)
                mem['plan']=plan_action(mem); mem['confidence']=confidence_score(mem)
                self.case_file_summaries[addr]=self.summarize_case(addr, mem)
                if mem['threat_rating']!=1 and addr.upper() not in self.known_safe and self.ai_mode!="paranoid":
                    self.known_safe.add(addr.upper())
                if mem['attention']>highest: highest=mem['attention']; self.focused_mac=addr
        except Exception:
            logging.exception("AI agent error"); self.alert="AI agent error."

    def summarize_case(self, addr, mem):
        try:
            lines=[f"CASE FILE: {addr} ({mem.get('status','idle')})",
                   f"Type: {mem.get('type','unknown')} | Tags: {', '.join(sorted(mem.get('user_tags',[])))}",
                   f"Cluster: {', '.join(mem.get('cluster', []))}",
                   f"Attention: {mem.get('attention',0)} | Threat: {mem.get('threat_rating',3)} | Conf: {mem.get('confidence',1)} | Plan: {mem.get('plan','ignore')} | Label: {mem.get('label') or ''}",
                   f"Patterns: {', '.join(sorted(mem.get('patterns',[])))}",
                   f"Notes: {mem.get('notes','')}"]
            if mem['timeline']:
                t0=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mem['timeline'][0][0]))
                tN=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mem['timeline'][-1][0]))
                lines.append(f"Timeline: {t0} — {tN} ({len(mem['timeline'])} frames)")
            for t,ev in list(mem['events'])[-3:]:
                lines.append(f"  {time.strftime('%H:%M:%S', time.localtime(t))}: {', '.join(ev)}")
            return "\n".join(lines)
        except Exception:
            logging.exception("Case summary error"); return "CASE ERROR"

    # ----- janitor -----
    def janitor_tick(self):
        now=time.time()
        try:
            if int(now) % 30 == 0:
                self._save_usage()
        except Exception:
            pass
        try:
            if int(now) % 20 == 0:
                merged=self.mesh.merge_training_into_local(self.training_db)
                if merged:
                    self.action_log.append(f"Merged {merged} training rows from mesh")
                    self.save_training_db()
        except Exception:
            logging.exception("janitor merge")
        for addr,mem in list(self.device_ai_memory.items()):
            if addr.upper() in self.known_safe or addr.upper() in self.allowlist:
                mem['ignore']=True; mem['patterns'].add("known_safe")
            if "storm_src" in mem['patterns'] and (now - mem.get('last_seen', now) > 120):
                mem['patterns'].discard("storm_src")

    # ----- mesh heartbeat payload -----
    def write_mesh_status(self):
        try:
            watch_rssi={}
            for mac in self.tri_watch:
                macU=mac.upper()
                if mac in self.beacons:
                    watch_rssi[macU]=self.beacons[mac][0]
                else:
                    for m in self.beacons.keys():
                        if m.upper()==macU: watch_rssi[macU]=self.beacons[m][0]; break
            anchor_pos = self.anchors.get(self.node_id)
            snap={
                "node": self.node_id, "time": time.time(), "mode": self.ai_mode,
                "beacon_count": len(self.beacons),
                "anchor": anchor_pos,
                "watch_rssi": watch_rssi,
                "top_threats": sorted(
                    [{"mac":a,"threat":self.device_ai_memory[a].get("threat_rating",3),
                      "rssi": self.beacons[a][0],"name": self.beacons[a][2]} for a in self.beacons.keys()],
                    key=lambda x:(0 if x["threat"]==1 else 1 if x["threat"]==2 else 2, -(x["rssi"] or -200))
                )[:8]
            }
            self.mesh.write_status(snap)
        except Exception:
            logging.exception("mesh status write")

    def process_mesh_inbox(self):
        for line in self.mesh.inbox_lines():
            self.script_command(line)

    # ----- UI -----
    def _draw_mesh_gauge(self):
        mh=self.mesh_health
        tag={"OK":"OK","DEGRADED":"DEG","OFF":"OFF"}.get(mh["state"], mh["state"])
        return f"Mesh:{tag} peers:{mh['peers']} {'M' if mh['mounted'] else '-'} {'W' if mh['writable'] else '-'}"

    def get_cpu_usage(self):
        try: return psutil.Process(os.getpid()).cpu_percent(interval=0.05)
        except Exception: return 0.0

    def draw(self):
        try:
            max_y,max_x=self.stdscr.getmaxyx()
            self.stdscr.erase()
            cpu=self.get_cpu_usage()

            hdr = draw_box(self.stdscr, 0, 0, 4, max_x, "SherloCK — BLE Command Center")
            now_str = time.strftime('%Y-%m-%d %H:%M:%S')
            up_str  = self._fmt_uptime(self._uptime_seconds())
            bright_attr = apply_color_brightness()[self.color_brightness]
            safe_addstr(hdr, 1, 2,
                        f"Node: {self.node_id} | Mode: {self.ai_mode} | Status: {self.status} | AI Load: {cpu:.1f}%",
                        bright_attr)
            safe_addstr(hdr, 2, 2,
                        f"Time: {now_str} | Uptime: {up_str} | {_truncate(self._draw_mesh_gauge(), max_x-30)}",
                        bright_attr)

            peers=self.mesh._peer_statuses()
            draw_node_bubbles(hdr, peers, 1, max(54, max_x//2), max_x-2)

            tabs_box = draw_box(self.stdscr, 4, 0, 3, max_x, "Tabs")
            tabs=["[Scan:w]","[Analyze:a]","[Profile:ENTER]","[AI:i]","[Hunt:h]","[Mesh:n]","[Settings:s]","[Script:x]","[AIcmd:/]","[Mode:m]","[Restart:R]","[Quit:Q]"]
            x=2
            for t in tabs:
                name=t.split(":")[0].strip("[]").lower()
                attr=curses.A_REVERSE if ((name=="profile" and self.active_tab=="profile") or name==self.active_tab) else 0
                safe_addstr(tabs_box, 1, x, t, attr); x+=len(t)+2

            content = draw_box(self.stdscr, 7, 0, max_y-10, max_x, f"View: {self.active_tab.upper()}")

            if self.active_tab=="scan": self.draw_scan_tab(max_y,max_x, container=content)
            elif self.active_tab=="analyze": self.draw_analyze_tab(max_y,max_x, container=content)
            elif self.active_tab=="profile": self.draw_profile_tab(max_y,max_x, container=content)
            elif self.active_tab=="ai": self.draw_ai_tab(max_y,max_x, container=content)
            elif self.active_tab=="hunt": self.draw_hunt_tab(max_y,max_x, container=content)
            elif self.active_tab=="mesh": self.draw_mesh_tab(max_y,max_x, container=content)
            elif self.active_tab=="settings": self.draw_settings_tab(max_y,max_x, container=content)

            # scrolling ticker (bottom) — colorized
            ticker = draw_box(self.stdscr, max_y-3, 0, 3, max_x, "Info")
            slice_txt = self._ticker_next_slice(max_x-4)
            safe_addstr(ticker, 1, 2, slice_txt, self._ticker_color_attr())

            if self.script_dialog_open: self.draw_script_dialog(max_y,max_x)
            if self.ai_command_prompt_open: self.draw_ai_command_prompt(max_y,max_x)
            self.stdscr.refresh()
        except Exception:
            logging.exception("Draw error")

    def draw_scan_tab(self, max_y, max_x, container=None):
        win = container or self.stdscr
        try:
            beacons_list=self.filtered_beacons()
            per_page=max(1, (win.getmaxyx()[0]-6))
            total_pages=max(1, (len(beacons_list)+per_page-1)//per_page)
            underline(win,1,2,f"Detected BLE Beacons (RSSI {self.filter_min_rssi} → {self.filter_max_rssi} | mode {self.ai_mode})")
            safe_addstr(win,2,2," #  Addr                 RSSI  Dist(m)  Type         Threat  Conf  Plan      Name")
            if not beacons_list:
                safe_addstr(win,4,4,"No BLE devices found (filtered or out of range)."); return
            start=self.scan_page*per_page; end=start+per_page
            for idx,(addr,(rssi,uuids,local_name,last_seen)) in enumerate(beacons_list[start:end], start=start):
                mem=self.device_ai_memory.get(addr,{})
                rating=mem.get('threat_rating',3); threat_str={1:"CRIT",2:"WARN",3:"OBS",99:"IGNR"}.get(rating,"?")
                dtype=mem.get('type','unknown'); plan=mem.get('plan','ignore'); confidence=mem.get('confidence',1)
                obs="*" if addr.lower() in self.hotlist else " "
                est_dist=estimate_distance(rssi); est=f"{est_dist:>7}" if est_dist!="?" else "   ?   "
                line=f"{obs}{idx:>2}  {addr:20} {str(rssi):>6} {est}  {dtype:10}  {threat_str:>6}   {confidence:^3}   {plan:8}  {local_name[:18]}"
                y=3+(idx-start)
                if idx==self.scan_selection:
                    win.attron(curses.A_REVERSE); safe_addstr(win,y,2,line); win.attroff(curses.A_REVERSE)
                else: safe_addstr(win,y,2,line)
            buf = f"  |  select #: {self.scan_num_input}" if self.scan_num_input else ""
            safe_addstr(win, 3+per_page, 2, f"Page {self.scan_page+1}/{total_pages}{buf}")
        except Exception:
            logging.exception("Scan tab error")

    def draw_analyze_tab(self, max_y, max_x, container=None):
        win=container or self.stdscr
        try:
            beacons_list=self.filtered_beacons()
            underline(win,1,2,"Analyze — selected device")
            if not beacons_list: safe_addstr(win,3,2,"No device selected."); return
            idx=min(self.scan_selection, len(beacons_list)-1)
            addr,(rssi,uuids,local_name,_) = beacons_list[idx]
            mem=self.device_ai_memory.get(addr,{})
            safe_addstr(win,3,2,f"Device: {addr}")
            safe_addstr(win,4,2,f"RSSI: {rssi}   Dist: {estimate_distance(rssi)} m   Vendor: {OUI_TO_VENDOR.get(oui_prefix(addr),'unknown')}")
            safe_addstr(win,5,2,f"UUIDs: {uuids}")
            safe_addstr(win,6,2,f"Name: {local_name}")
            safe_addstr(win,7,2,f"Type: {mem.get('type','unknown')}")
            safe_addstr(win,8,2,f"Status: {mem.get('status','idle')}  Threat: {mem.get('threat_rating',3)}  Conf: {mem.get('confidence',1)}  Plan: {mem.get('plan','ignore')}")
            underline(win,10,2,"Patterns:")
            grouped = group_patterns(mem.get('patterns', set()))
            y = 11
            for g,items in grouped.items():
                safe_addstr(win,y,4,f"{g}:"); 
                for i,row in enumerate(format_columns(items, cols=3, colw=18)):
                    safe_addstr(win,y+1+i,6,row)
                y += 2 + max(1,(len(items)+2)//3)
            safe_addstr(win,y+1,2,f"Notes: {mem.get('notes','')}")
        except Exception:
            logging.exception("Analyze tab error")

    def draw_profile_tab(self, max_y, max_x, container=None):
        win=container or self.stdscr
        try:
            beacons_list=self.filtered_beacons()
            if not beacons_list: safe_addstr(win,1,2,"Profile: no device selected."); return
            if self.profile_mac is None:
                idx=min(self.scan_selection, len(beacons_list)-1)
                self.profile_mac=beacons_list[idx][0]
            addr=self.profile_mac
            if addr not in self.beacons: safe_addstr(win,1,2,"Device left range."); return
            rssi,uuids,local_name,last_seen=self.beacons[addr]
            mem=self.device_ai_memory[addr]
            underline(win,1,2,f"Device Profile — {addr}")
            safe_addstr(win,2,2,f"Name: {local_name}   Vendor: {OUI_TO_VENDOR.get(oui_prefix(addr),'unknown')}   Type: {mem.get('type','unknown')}")
            safe_addstr(win,3,2,f"Threat: {mem.get('threat_rating',3)}  Status: {mem.get('status')}  Plan: {mem.get('plan')}  Conf: {mem.get('confidence')}")
            safe_addstr(win,4,2,f"UUIDs(last adv): {uuids}")

            # RSSI history
            hist=[rv for _,rv in self.rssi_history[addr]]
            underline(win,6,2,"RSSI last 80:")
            safe_addstr(win,7,2,sparkline(hist, width=min(80,max_x-20)))
            med,madn,rng=robust_stats([v for v in hist if v is not None])
            if med is not None:
                safe_addstr(win,8,2, f"RSSI stats — median:{med}  MAD≈{madn:.1f}  range:{rng}")
            else:
                safe_addstr(win,8,2, "RSSI stats — (insufficient)")

            # UUID/mfr/service summaries
            underline(win,10,2,"Frames:")
            uhist=self.uuid_history.get(addr,[])
            uc=self.uuid_counter.get(addr,Counter())
            uniq_sets=_count_unique_sets(uhist)
            top_uu=_summarize_uuid_counter(uc, k=12)
            safe_addstr(win,11,4,f"UUID sets seen: {uniq_sets} | top: {', '.join(top_uu[:6])}")
            if self.mfr_last.get(addr):
                m=self.mfr_last[addr]; last_ts=self.mfr_history[addr][-1][0] if self.mfr_history[addr] else None
                safe_addstr(win,12,4,f"Manufacturer: cid=0x{m['cid']:04x} len={m['len']}  last={time.strftime('%H:%M:%S', time.localtime(last_ts)) if last_ts else '-'}")
                if self.mfr_history[addr]:
                    _, cid, sample = self.mfr_history[addr][-1]
                    safe_addstr(win,13,6,f"sample: {_fmt_hex(sample, 20)}")
            if self.svc_last.get(addr):
                s=self.svc_last[addr]; last_ts=self.svc_history[addr][-1][0] if self.svc_history[addr] else None
                safe_addstr(win,14,4,f"ServiceData: uuid={s['uuid']} len={s['len']}  last={time.strftime('%H:%M:%S', time.localtime(last_ts)) if last_ts else '-'}")
                if self.svc_history[addr]:
                    _, su, sp = self.svc_history[addr][-1]
                    safe_addstr(win,15,6,f"sample: {_fmt_hex(sp, 20)}")

            # patterns/tags
            underline(win,17,2,"Patterns:")
            grouped = group_patterns(mem.get('patterns', set()))
            y = 18
            for g,items in grouped.items():
                safe_addstr(win,y,4,f"{g}:"); 
                for i,row in enumerate(format_columns(items, cols=3, colw=18)):
                    safe_addstr(win,y+1+i,6,row)
                y += 2 + max(1,(len(items)+2)//3)
            safe_addstr(win, y+1,2,f"Tags: {', '.join(sorted(mem.get('user_tags', [])))}  | Label: {mem.get('label') or ''}")
            note=mem.get('notes','')
            for i,chunk in enumerate([note[i:i+max_x-8] for i in range(0,len(note),max_x-8)]):
                safe_addstr(win,y+3+i,4,chunk)
            safe_addstr(win, win.getmaxyx()[0]-2, 2, "Profile: b=back | /=AIcmd (note/tag/label)")
        except Exception:
            logging.exception("Profile tab error")

    def draw_ai_tab(self, max_y, max_x, container=None):
        win=container or self.stdscr
        try:
            underline(win,1,2,"SherloCK AI")
            tabs = ["[1 Overview]","[2 Patterns]","[3 Clusters]","[4 Focus]","[5 Tools]"]
            x=2
            for i,t in enumerate(tabs, start=1):
                attr=curses.A_REVERSE if self.ai_subtab==i else 0
                safe_addstr(win,2,x,t,attr); x+=len(t)+2

            if self.ai_subtab==1:
                pat_counts = Counter()
                for mem in self.device_ai_memory.values():
                    for p in mem.get('patterns', []): pat_counts[p]+=1
                top = [f"{p}:{c}" for p,c in pat_counts.most_common(12)]
                underline(win,4,2,"Top Patterns:")
                for i,row in enumerate(format_columns(top, cols=3, colw=18)): safe_addstr(win,5+i,4,row)
                underline(win,8,2,"Stats:")
                safe_addstr(win,9,4,f"Devices: {len(self.beacons)}  | Known Safe: {len(self.known_safe)}  | OUIs active: {len(self.active_ouis)}")

            elif self.ai_subtab==2:
                underline(win,4,2,"Patterns per device (first 60):")
                y=5
                for idx,(addr,mem) in enumerate(list(self.device_ai_memory.items())[:60]):
                    pats=sorted(mem.get('patterns', []))
                    cols=format_columns(pats, cols=4, colw=14)
                    safe_addstr(win,y,2,f"{_truncate(addr,17):<17} |")
                    for j,row in enumerate(cols):
                        safe_addstr(win,y+j,22,row)
                    y+=max(1,len(cols))+1
                    if y>win.getmaxyx()[0]-3: break

            elif self.ai_subtab==3:
                underline(win,4,2,"Clusters (by pattern signature)")
                y=5
                for label, devices in list(self.device_clusters.items())[:20]:
                    label_txt = ",".join(label) if label else "benign"
                    safe_addstr(win,y,2,f"{_truncate(label_txt,60):60} | {len(devices)} devs"); y+=1
                    if y>win.getmaxyx()[0]-3: break

            elif self.ai_subtab==4:
                underline(win,4,2,"Focused Case:")
                if self.focused_mac and self.focused_mac in self.case_file_summaries:
                    y=5
                    for line in self.case_file_summaries[self.focused_mac].splitlines():
                        safe_addstr(win, y, 4, line); y+=1
                        if y>win.getmaxyx()[0]-3: break
                else:
                    safe_addstr(win,6,4,"No current focus.")

            elif self.ai_subtab==5:
                underline(win,4,2,"Tools & Triangulation Quick Tips")
                safe_addstr(win,6,4,f"Place scripts under {TOOLS_DIR}/ and run: tool run <relpath>")
                safe_addstr(win,8,4,"Tri anchors: tri set r1 0 0 | tri set r2 10 0 | tri set r3 0 8")
                safe_addstr(win,9,4,"Manual solve: tri solve <mac> r1:-67 r2:-72 r3:-63")
                safe_addstr(win,10,4,"Mesh solve: tri watch add <mac> (on all nodes), set anchors per node, then tri meshsolve <mac>")

        except Exception:
            logging.exception("AI tab error")

    def draw_hunt_tab(self, max_y, max_x, container=None):
        win=container or self.stdscr
        try:
            beacons=self.filtered_beacons()
            if not beacons:
                safe_addstr(win,1,2,"Hunt Mode — select a device in Scan tab first (w), then press h."); return
            idx=min(self.scan_selection, len(beacons)-1)
            addr,(rssi,uuids,local_name,_) = beacons[idx]
            if self.hunt_best is None or (rssi is not None and rssi>self.hunt_best):
                self.hunt_best=rssi
                try: curses.beep()
                except Exception: pass
            underline(win,1,2,f"Hunt Mode — {addr}  name:{(local_name or '')[:18]}")
            scale_min,scale_max=-100,-30
            val=rssi if rssi is not None else scale_min
            frac=(max(scale_min,min(val,scale_max))-scale_min)/(scale_max-scale_min)
            bar_w=max_x-8; fill=int(frac*bar_w)
            safe_addstr(win,3,4,"["+"#"*fill+"-"*(bar_w-fill)+"]")
            safe_addstr(win,4,4,f"RSSI: {rssi} dBm   Best: {self.hunt_best} dBm")
            hist=[rv for _,rv in self.rssi_history[addr] if rv is not None]
            if hist:
                avg5=sum(hist[-5:])/min(5,len(hist)); avg10=sum(hist[-10:])/min(10,len(hist))
                safe_addstr(win,5,4,f"Avg(5): {avg5:.1f}   Avg(10): {avg10:.1f}")
            safe_addstr(win,7,4,"Tip: move toward stronger (less negative) RSSI. Beeps on new best.")
        except Exception:
            logging.exception("Hunt tab error")

    def draw_mesh_tab(self, max_y, max_x, container=None):
        win=container or self.stdscr
        mh=self.mesh_health
        underline(win,1,2,"Nexus Mesh — connectivity & control")
        safe_addstr(win,3,4,f"State: {mh['state']}   Peers: {mh['peers']}   Mounted: {mh['mounted']}   Writable: {mh['writable']}")
        safe_addstr(win,4,4,f"Dir: {mh['dir']}   Seed: {self.mesh.seed}   Proto: {self.mesh.proto}")
        if mh.get("reason"): safe_addstr(win,5,4,f"Reason: {mh['reason']}")
        files=glob.glob(os.path.join(self.mesh_status_dir,"**","*.json"), recursive=True)
        peers=[]; now=time.time()
        for p in files:
            try:
                with open(p) as f: d=json.load(f)
                nid=d.get("node") or pathlib.Path(p).stem
                if nid==self.node_id: continue
                age=now-os.path.getmtime(p)
                peers.append((nid,age,p))
            except Exception: continue
        row=7; underline(win,row,4,"Peers:")
        for nid,age,p in sorted(peers)[:10]:
            row+=1; safe_addstr(win,row,6,f"- {nid:<12} age:{age:4.1f}s  path:{p[:max_x-30]}")
        row+=2
        safe_addstr(win,row,4,"Commands: mesh connect | mesh disconnect | mesh seed <host> | mesh dir <path> | mesh proto <auto|nfs|sshfs> | mesh status")
        safe_addstr(win,row+1,4,"Tip: set NODE_ID and MESH_AUTO=1 for auto-reconnect.")

    def draw_settings_tab(self, max_y, max_x, container=None):
        win=container or self.stdscr
        try:
            underline(win,1,2,"Settings")
            safe_addstr(win,3,4,f"Filter Min RSSI: {self.filter_min_rssi} (adjust: < >)")
            safe_addstr(win,4,4,f"Filter Max RSSI: {self.filter_max_rssi} (adjust: [ ])")
            safe_addstr(win,5,4,f"Color brightness: {self.color_brightness}  (+/- to adjust)")

            underline(win,7,2,"Ticker")
            safe_addstr(win,8,4,f"Color: {self.ticker_color_name}   (script: ticker color <green|cyan|yellow|magenta|white|red>)")
            safe_addstr(win,9,4,f"Speed: {self.ticker_speed:.1f} chars/s   (script: ticker speed <float>)")

            underline(win,11,2,"System")
            m = self._sys_metrics()
            safe_addstr(win,12,4,f"Cores: {m['cores']}  | Load1: {m['load1']}  | RAM: {m['ram_str']} ({m['ram_pct']}%)")
            if m["temp_max"] is not None:
                safe_addstr(win,13,4,f"Max temp: {m['temp_max']}°C  | Sensors: " + ", ".join(f"{k}:{v:.1f}°C" for k,v in sorted(m['temps'].items())[:4]))
            total_h = self.total_usage_sec / 3600.0
            safe_addstr(win,14,4,f"Total usage: {total_h:.2f} h (across runs)")

            underline(win,16,2,"Compute / Cluster Power")
            safe_addstr(win,17,4,f"AI workers: {self.ai_workers}   (script: compute ai_workers <n>)")
            safe_addstr(win,18,4,f"OPENBLAS_NUM_THREADS: {self.openblas_threads}   OMP_NUM_THREADS: {self.omp_threads}")
            safe_addstr(win,19,4,f"CPU governor: {self._read_governor()} (script: compute governor performance|powersave|schedutil)")
            safe_addstr(win,20,4,f"Affinity: {self.affinity_mask if self.affinity_mask is not None else 'default'} (script: compute affinity 0-3,5)")

            underline(win,22,2,"Triangulation")
            safe_addstr(win,23,4,f"Anchors file: {self.anchors_path}")
            safe_addstr(win,24,4,"Set this node's anchor: tri set <NODE_ID> <x> <y>")
            safe_addstr(win,25,4,"Watch MACs to publish RSSI: tri watch add <mac>  | list/del")
        except Exception:
            logging.exception("Settings tab error")

    def draw_script_dialog(self, max_y, max_x):
        try:
            dialog_w = min(100, max_x - 4); dialog_h = 14
            start_x = (max_x - dialog_w) // 2; start_y = (max_y - dialog_h) // 2
            box = self.stdscr.derwin(dialog_h, dialog_w, start_y, start_x)
            try:
                curses.init_pair(10, curses.COLOR_BLACK, curses.COLOR_GREEN); bg = curses.color_pair(10)
            except Exception:
                bg = curses.A_REVERSE
            box.bkgd(' ', bg)
            for yy in range(dialog_h): box.addstr(yy, 0, " " * (dialog_w - 1), bg)
            box.box()
            safe_addstr(box, 0, 2, "Scripting/Automation (ESC to exit)")
            safe_addstr(box, 2, 2, "Command: ")
            disp = self.script_input[:dialog_w - 20]
            safe_addstr(box, 2, 12, disp)
            box.move(2, 12 + self.script_cursor)
            safe_addstr(box, 4, 2, f"Hotlist: {', '.join(list(self.hotlist)[:4])} ...")
            for i, l in enumerate(list(self.action_log)[-3:] if self.action_log else []):
                safe_addstr(box, 6 + i, 2, f"Log: {l}")
            safe_addstr(box, 10, 2, "Examples: note <mac> <text> | tag <mac> add|del <tag> | label <mac> benign|rogue | mesh connect")
            box.refresh()
        except Exception:
            logging.exception("Script dialog error")

    def draw_ai_command_prompt(self, max_y, max_x):
        try:
            dialog_w = min(100, max_x - 4); dialog_h = 14
            start_x = (max_x - dialog_w) // 2; start_y = (max_y - dialog_h) // 2
            box = self.stdscr.derwin(dialog_h, dialog_w, start_y, start_x)
            try:
                curses.init_pair(11, curses.COLOR_BLACK, curses.COLOR_CYAN); bg = curses.color_pair(11)
            except Exception:
                bg = curses.A_REVERSE
            box.bkgd(' ', bg)
            for yy in range(dialog_h): box.addstr(yy, 0, " " * (dialog_w - 1), bg)
            box.box()
            safe_addstr(box, 0, 2, "SherloCK Command (ESC to exit)")
            safe_addstr(box, 2, 2, "> " + self.ai_command_input)
            box.move(2, 4 + self.ai_command_cursor)
            safe_addstr(box, 3, 2, "ignore|unignore <mac> | flag <mac> | type <mac> <type> | note/tag/label | timer show/reset")
            safe_addstr(box, 4, 2, "mesh connect|disconnect|seed|dir|proto|status | mode paranoid|normal|relaxed|training | compute ... | tri ... | ticker ...")
            box.refresh()
        except Exception:
            logging.exception("AI cmd dialog error")
            
    # ----- export -----
    def export_snapshot(self):
        try:
            ts = time.strftime('%Y%m%d_%H%M%S')
            fname = f"snapshot_{ts}.csv"
            headers = ["time","mac","name","rssi","uuids","threat","confidence","plan","patterns"]
            with open(fname, "w", newline="") as f:
                w = csv.writer(f); w.writerow(headers)
                for addr,(rssi,uuids,name,_) in self.beacons.items():
                    mem = self.device_ai_memory.get(addr, {})
                    w.writerow([ts, addr, name, rssi, uuids,
                                mem.get("threat_rating",3),
                                mem.get("confidence",1),
                                mem.get("plan","ignore"),
                                "|".join(sorted(mem.get("patterns",[])))])
            self.action_log.append(f"Exported {fname}")
        except Exception:
            logging.exception("snapshot export error")

    # ----- commands -----
    def script_command(self, cmd, maxlen=120):
        out = ""
        try:
            cmd = cmd.strip()

            # --- Timer / usage ---
            if cmd in ("timer show", "usage show"):
                out = f"uptime {self._fmt_uptime(self._uptime_seconds())} | total {self.total_usage_sec//3600}h {(self.total_usage_sec//60)%60}m"
                self.action_log.append(out); return
            if cmd == "timer reset":
                self.total_usage_sec = 0
                self._save_usage()
                out = "timer: total usage reset"
                self.action_log.append(out); return

            # --- Ticker ---
            if cmd.startswith("ticker "):
                toks = cmd.split()
                if len(toks)>=3 and toks[1]=="color":
                    name=toks[2].lower()
                    if name in {"green","cyan","yellow","magenta","white","red"}:
                        self.ticker_color_name=name; out=f"ticker color -> {name}"
                    else:
                        out="colors: green|cyan|yellow|magenta|white|red"
                    self.action_log.append(out); return
                if len(toks)>=3 and toks[1]=="speed":
                    try:
                        self.ticker_speed=max(1.0,float(toks[2])); out=f"ticker speed -> {self.ticker_speed:.1f}"
                    except Exception:
                        out="ticker speed <float>"
                    self.action_log.append(out); return
                if len(toks)>=2 and toks[1]=="reload":
                    self._load_banners(); out="ticker reloaded"; self.action_log.append(out); return
                if len(toks)>=3 and toks[1]=="brightness":
                    try:
                        b=int(toks[2]); self.color_brightness=max(0,min(2,b)); out=f"ticker brightness -> {self.color_brightness}"
                    except Exception:
                        out="ticker brightness <0|1|2>"
                    self.action_log.append(out); return
                self.action_log.append("ticker color <name> | ticker speed <float> | ticker brightness <0..2> | ticker reload"); return

            # --- Triangulation & anchors
            if cmd.startswith("tri "):
                toks = cmd.split()

                if len(toks) == 5 and toks[1] == "set":
                    node, x, y = toks[2], float(toks[3]), float(toks[4])
                    self.anchors[node] = (x, y); self._save_anchors()
                    out = f"anchor set {node} -> ({x},{y})"; self.action_log.append(out); return

                if len(toks) == 3 and toks[1] == "del":
                    node = toks[2]; self.anchors.pop(node, None); self._save_anchors()
                    out = f"anchor deleted {node}"; self.action_log.append(out); return

                if len(toks) >= 2 and toks[1] == "list":
                    items = ", ".join(f"{k}=({v[0]},{v[1]})" for k,v in self.anchors.items()) or "(none)"
                    out = "anchors: " + items; self.action_log.append(out); return

                if len(toks) >= 3 and toks[1] == "solve":
                    mac = toks[2]; specs = toks[3:]; anchors=[]
                    for s in specs:
                        a = self._parse_anchor_spec(s)
                        if a: anchors.append({'node':a['node'], 'pos':a['pos'], 'rssi':a['rssi']})
                    if len(anchors) < 3:
                        out = "need >=3: tri solve <mac> n1:0,0:-65 n2:10,0:-70 n3:0,8:-62"; self.action_log.append(out); return
                    pos, meta = self.triangulate_target(anchors)
                    out = f"triangulated {mac} -> {pos if pos else 'n/a'} {meta}"; self.action_log.append(out); return

                if len(toks) >= 3 and toks[1] == "watch":
                    if toks[2] == "add" and len(toks) >= 4:
                        for mac in toks[3:]: self.tri_watch.add(mac)
                        out = "watch list: " + ", ".join(sorted(self.tri_watch)); self.action_log.append(out); return
                    if toks[2] == "del" and len(toks) >= 4:
                        for mac in toks[3:]: self.tri_watch.discard(mac)
                        out = "watch list: " + ", ".join(sorted(self.tri_watch)); self.action_log.append(out); return
                    if toks[2] == "list":
                        out = "watch list: " + (", ".join(sorted(self.tri_watch)) or "(empty)"); self.action_log.append(out); return

                if len(toks) >= 3 and toks[1] == "meshsolve":
                    mac = toks[2]; anchors = self.collect_mesh_anchors_for_mac(mac)
                    if len(anchors) < 3:
                        out = f"need >=3 anchors for {mac}; have {len(anchors)}"; self.action_log.append(out); return
                    pos, meta = self.triangulate_target(anchors)
                    out = f"mesh triangulated {mac} -> {pos if pos else 'n/a'} {meta} using {len(anchors)} anchors"
                    self.action_log.append(out); return

                out = ("tri set <node> <x> <y> | tri del <node> | tri list | "
                       "tri watch add|del|list <mac> [...] | "
                       "tri solve <mac> node:x,y:rssi [...] | tri meshsolve <mac>")
                self.action_log.append(out); return

            # --- Mesh
            if cmd.startswith("mesh "):
                toks = cmd.split()
                if len(toks) >= 2 and toks[1] == "connect":
                    ok = self.mesh.connect(); self.mesh_health = self.mesh.health_check()
                    out = f"mesh connect: {'ok' if ok else 'failed'}"
                elif len(toks) >= 2 and toks[1] == "disconnect":
                    self.mesh.disconnect(); self.mesh_health = self.mesh.health_check(); out = "mesh disconnect: done"
                elif len(toks) >= 3 and toks[1] == "seed":
                    self.mesh.seed = toks[2]; out = f"mesh seed -> {self.mesh.seed}"
                elif len(toks) >= 3 and toks[1] == "dir":
                    self.mesh.mesh_dir = toks[2]
                    self.mesh.status_dir  = os.path.join(self.mesh.mesh_dir,"status")
                    self.mesh.inbox_dir   = os.path.join(self.mesh.mesh_dir,"inbox")
                    self.mesh.training_dir= os.path.join(self.mesh.mesh_dir,"training")
                    self.mesh.ensure_dirs(); self.mesh_health = self.mesh.health_check()
                    out = f"mesh dir -> {self.mesh.mesh_dir}"
                elif len(toks) >= 3 and toks[1] == "proto":
                    self.mesh.proto = toks[2].lower(); out = f"mesh proto -> {self.mesh.proto}"
                elif len(toks) >= 2 and toks[1] == "status":
                    self.mesh_health = self.mesh.health_check(); out = str(self.mesh_health)
                else:
                    out = "mesh cmds: connect|disconnect|seed <h>|dir <p>|proto <auto|nfs|sshfs>|status"
                if len(out) > maxlen: out = out[:maxlen-3] + "..."
                self.action_log.append(out); return

            # --- External tools
            if cmd.startswith("tool run "):
                rel = cmd[len("tool run "):].strip()
                p = (TOOLS_DIR / rel).resolve()
                if not str(p).startswith(str(TOOLS_DIR.resolve())):
                    out = "ERR: path escapes tools/"
                elif not p.exists():
                    out = "ERR: tool not found"
                else:
                    try:
                        r = subprocess.run([str(p)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           text=True, timeout=15)
                        out = "TOOL: " + _truncate((r.stdout or "").replace("\n"," | "), maxlen)
                    except Exception as e:
                        out = f"ERR: {e}"
                self.action_log.append(out); return

            # --- Compute / cluster power knobs
            if cmd.startswith("compute "):
                toks = cmd.split()
                if len(toks) >= 3 and toks[1] == "ai_workers":
                    self.ai_workers = max(1, int(toks[2])); out = f"AI workers -> {self.ai_workers}"
                elif len(toks) >= 3 and toks[1] == "threads":
                    n = max(1, int(toks[2])); self.openblas_threads = n; self.omp_threads = n; self._set_env_threads()
                    out = f"Threads -> {n}"
                elif len(toks) >= 3 and toks[1] == "governor":
                    self.cpu_governor = toks[2]; ok = self._set_governor(self.cpu_governor)
                    out = f"governor -> {self.cpu_governor} ({'ok' if ok else 'needs root/cpupower'})"
                elif len(toks) >= 3 and toks[1] == "affinity":
                    mask = set()
                    for part in toks[2].split(","):
                        if "-" in part:
                            a,b = part.split("-"); mask.update(range(int(a), int(b)+1))
                        else:
                            mask.add(int(part))
                    self.affinity_mask = sorted(mask); self._apply_affinity()
                    out = f"affinity -> {self.affinity_mask}"
                else:
                    out = ("compute ai_workers <n> | compute threads <n> | "
                           "compute governor <g> | compute affinity <list>")
                self.action_log.append(out); return

            # --- Core short commands
            if cmd.startswith("observe "):
                mac = cmd.split()[1].strip().lower(); self.hotlist.add(mac); out = f"Added {mac} to hotlist."
            elif cmd.startswith("unobserve "):
                mac = cmd.split()[1].strip().lower(); self.hotlist.discard(mac); out = f"Removed {mac}."
            elif cmd.startswith("ignore "):
                mac = cmd.split()[1].strip().lower(); self.device_ai_memory[mac]['ignore'] = True; out = f"Ignoring {mac}"
            elif cmd.startswith("unignore "):
                mac = cmd.split()[1].strip().lower(); self.device_ai_memory[mac]['ignore'] = False; out = f"Stopped ignoring {mac}"
            elif cmd.startswith("flag "):
                mac = cmd.split()[1].strip().lower(); self.device_ai_memory[mac]['flag'] = True; out = f"Always flagging {mac}"
            elif cmd.startswith("type "):
                toks = cmd.split(); mac = toks[1].strip().lower(); typ = toks[2].strip().lower() if len(toks) > 2 else "unknown"
                self.device_ai_memory[mac]['type'] = typ; out = f"Set {mac} type to {typ}"
            elif cmd.startswith("label "):
                toks = cmd.split(); mac = toks[1].strip().lower(); lbl = toks[2].strip().lower()
                self.device_ai_memory[mac]['label'] = lbl; out = f"Labeled {mac} as {lbl}"
            elif cmd.startswith("tag "):
                toks = cmd.split(); mac = toks[1].strip().lower(); op  = toks[2]; tag = toks[3]
                tags = self.device_ai_memory[mac]['user_tags']
                if op == "add": tags.add(tag); out = f"Tagged {mac} +{tag}"
                elif op == "del": tags.discard(tag); out = f"Untagged {mac} -{tag}"
            elif cmd.startswith("note "):
                toks = cmd.split(maxsplit=2); mac = toks[1].strip().lower(); txt = toks[2] if len(toks) > 2 else ""
                self.device_ai_memory[mac]['notes'] = txt; out = "Noted."
            elif cmd.startswith("list hot"):
                out = "Hotlist: " + ", ".join(self.hotlist)
            elif cmd.startswith("list beacons"):
                beacons = list(self.filtered_beacons()); out = " ".join(f"{a}" for a,_ in beacons[:5])
            elif cmd.startswith("observe strong"):
                for addr,(rssi,_,_,_) in self.filtered_beacons():
                    if rssi is not None and rssi > -50: self.hotlist.add(addr.lower())
                out = "Added strong beacons."
            elif cmd.startswith("mode "):
                mode = cmd.split()[1].strip().lower()
                if mode not in {"relaxed","normal","paranoid","training"}: out = "Mode: relaxed|normal|paranoid|training"
                else: self.set_ai_mode(mode); out = f"AI mode -> {self.ai_mode}"
            elif cmd == "export snapshot":
                self.export_snapshot(); out = "Snapshot exported."
            elif cmd.startswith("quarantine "):
                toks = cmd.split(); mac  = toks[1].strip().lower(); secs = int(toks[2]) if len(toks)>2 else self.quarantine_secs
                self.quarantine_until[mac] = time.time() + max(5, secs); out = f"Quarantined {mac} for {secs}s."
            elif cmd.startswith("unquarantine "):
                mac = cmd.split()[1].strip().lower(); self.quarantine_until[mac] = 0.0; out = f"Unquarantined {mac}."
            elif cmd.startswith("allow "):
                mac = cmd.split()[1].strip().upper(); self.allowlist.add(mac); self.known_safe.add(mac); out = f"Allowlisted {mac}"
            elif cmd.startswith("deny "):
                mac = cmd.split()[1].strip().upper(); self.denylist.add(mac); out = f"Denylisted {mac}"
            elif cmd == "save allow":
                self.save_list("allow"); out = "allowlist saved."
            elif cmd == "save deny":
                self.save_list("deny"); out = "denylist saved."
            elif cmd == "train save":
                self.update_training_from_current(); self.save_training_db(); out = "Training DB saved."
            elif cmd == "train load":
                self.load_training_db(); out = "Training DB loaded."
            elif cmd == "train apply":
                for mac,(rssi,uuids,name,_) in list(self.beacons.items()):
                    self.apply_training_to_memory(mac, name, [u.strip() for u in (uuids.split(',') if uuids else [])], self.device_ai_memory[mac])
                out = "Training applied."
            elif cmd == "train clear":
                self.training_db = {}; self.save_training_db(); out = "Training DB cleared."
            else:
                out = ("Unknown cmd. Try: observe/unobserve/ignore/unignore/flag/type/label/tag/note, "
                       "mode <relaxed|normal|paranoid|training>, quarantine/unquarantine, allow/deny, "
                       "save allow|deny, train save|load|apply/clear, export snapshot, tool run <path>, "
                       "compute ai_workers|threads|governor|affinity, mesh connect|disconnect|seed|dir|proto|status, "
                       "tri set|del|list|watch|solve|meshsolve, ticker color|speed|brightness|reload, timer show/reset")
        except Exception as e:
            out = f"ERR: {e}"; logging.exception("Script command error")
        if len(out) > maxlen: out = out[:maxlen-3] + "..."
        self.action_log.append(out)

    # ----- main loop & runtime -----
    async def run(self):
        try:
            self._init_colors()
        except Exception:
            pass
        try:
            scan_task = asyncio.create_task(self.ble_scan()) if BleakScanner else None
            ai_timer  = time.time()
            while self.running:
                now = time.time()

                # mesh heartbeat & inbox
                if now - self.last_mesh_check > 1.0:
                    self.mesh_health = self.mesh.health_check()
                    self.write_mesh_status()
                    self.process_mesh_inbox()
                    self.last_mesh_check = now

                # draw + AI
                if now - self.last_draw > 0.15:
                    self.draw()
                    self.last_draw = now
                if now - ai_timer > (0.3 if len(self.beacons) < 400 else 2.0):
                    self.sherlock_agent_investigation()
                    ai_timer = now

                # janitor + training autosave
                if now - self.last_janitor > 5:
                    self.janitor_tick()
                    self.last_janitor = now
                if self.ai_mode == "training" and (now - self.last_train_save) > 30:
                    self.update_training_from_current()
                    self.save_training_db()
                    self.last_train_save = now

                # input
                self.stdscr.nodelay(True)
                try:
                    key = self.stdscr.getch()
                except Exception:
                    key = -1

                beacons_list = self.filtered_beacons()
                beacons_len  = len(beacons_list)
                per_page     = (self.stdscr.getmaxyx()[0] - 12)
                total_pages  = max(1, (beacons_len + per_page - 1) // per_page)

                # numeric buffer timeout
                if self.scan_num_input and (time.time() - self.scan_num_ts) > 4.0:
                    self.scan_num_input = ""

                # AI command prompt
                if self.ai_command_prompt_open:
                    if key in (27,):
                        self.ai_command_prompt_open = False; self.ai_command_input = ""; self.ai_command_cursor = 0
                    elif key in (curses.KEY_BACKSPACE,127,8):
                        if self.ai_command_cursor > 0:
                            self.ai_command_input = (self.ai_command_input[:self.ai_command_cursor-1] + self.ai_command_input[self.ai_command_cursor:])
                            self.ai_command_cursor -= 1
                    elif key in (curses.KEY_LEFT,):  self.ai_command_cursor = max(0, self.ai_command_cursor-1)
                    elif key in (curses.KEY_RIGHT,): self.ai_command_cursor = min(len(self.ai_command_input), self.ai_command_cursor+1)
                    elif key in (curses.KEY_ENTER,10,13):
                        self.script_command(self.ai_command_input)
                        self.ai_command_prompt_open = False; self.ai_command_input = ""; self.ai_command_cursor = 0
                    elif 32<=key<127:
                        ch=chr(key); self.ai_command_input = (self.ai_command_input[:self.ai_command_cursor]+ch+self.ai_command_input[self.ai_command_cursor:])
                        self.ai_command_cursor += 1
                    await asyncio.sleep(0.01); continue

                # Script dialog
                if self.script_dialog_open:
                    if key in (27,): self.script_dialog_open = False; self.script_input = ""; self.script_cursor = 0
                    elif key in (curses.KEY_BACKSPACE,127,8):
                        if self.script_cursor>0:
                            self.script_input=(self.script_input[:self.script_cursor-1]+self.script_input[self.script_cursor:]); self.script_cursor-=1
                    elif key in (curses.KEY_DC,):
                        if self.script_cursor<len(self.script_input):
                            self.script_input=(self.script_input[:self.script_cursor]+self.script_input[self.script_cursor+1:])
                    elif key in (curses.KEY_LEFT,):  self.script_cursor=max(0,self.script_cursor-1)
                    elif key in (curses.KEY_RIGHT,): self.script_cursor=min(len(self.script_input), self.script_cursor+1)
                    elif key in (curses.KEY_ENTER,10,13):
                        self.script_command(self.script_input); self.script_input=""; self.script_cursor=0
                    elif 32<=key<127:
                        ch=chr(key); self.script_input=(self.script_input[:self.script_cursor]+ch+self.script_input[self.script_cursor:]); self.script_cursor+=1
                    await asyncio.sleep(0.01); continue

                # global keys
                if key in (ord('q'), ord('Q')): self.running=False
                elif key==ord('w'): self.active_tab="scan"
                elif key==ord('a'): self.active_tab="analyze"
                elif key==ord('i'): self.active_tab="ai"
                elif key==ord('h'): self.active_tab="hunt"
                elif key==ord('n'): self.active_tab="mesh"
                elif key==ord('s'): self.active_tab="settings"
                elif key==ord('x'): self.script_dialog_open=True; self.script_input=""; self.script_cursor=0
                elif key==ord('/'): self.ai_command_prompt_open=True; self.ai_command_input=""; self.ai_command_cursor=0
                elif key==ord('m'): self.cycle_ai_mode()
                elif key==ord('R'): self.request_scan_restart()
                elif key==ord('+'): self.color_brightness = min(2, self.color_brightness + 1)
                elif key==ord('-'): self.color_brightness = max(0, self.color_brightness - 1)
                elif key in (ord('1'), ord('2'), ord('3'), ord('4'), ord('5')) and self.active_tab == "ai":
                    self.ai_subtab = int(chr(key))

                # numeric index entry on Scan tab (type digits, then Enter)
                if self.active_tab == "scan" and key in range(ord('0'), ord('9')+1):
                    if len(self.scan_num_input) < 5:
                        self.scan_num_input += chr(key); self.scan_num_ts = time.time()
                    await asyncio.sleep(0.01); continue
                elif key in (curses.KEY_ENTER,10,13) and self.active_tab == "scan" and self.scan_num_input:
                    try:
                        n = int(self.scan_num_input)
                        if beacons_len:
                            n = max(0, min(beacons_len-1, n))
                            self.scan_selection = n
                            self.scan_page = n // max(1, per_page)
                            self.profile_mac = self.filtered_beacons()[n][0]
                            self.active_tab = "profile"
                    finally:
                        self.scan_num_input = ""
                    await asyncio.sleep(0.01); continue

                elif key in (curses.KEY_ENTER,10,13):
                    if beacons_len:
                        idx = min(self.scan_selection, beacons_len-1)
                        self.profile_mac = beacons_list[idx][0]; self.active_tab = "profile"

                elif key==ord('b') and self.active_tab=="profile":
                    self.active_tab="scan"; self.profile_mac=None

                elif key==ord('<') and self.active_tab=="settings":
                    self.filter_min_rssi=min(self.filter_min_rssi+1, self.filter_max_rssi); self.request_scan_restart()
                elif key==ord('>') and self.active_tab=="settings":
                    self.filter_min_rssi=max(self.filter_min_rssi-1, -100); self.request_scan_restart()
                elif key==ord('[') and self.active_tab=="settings":
                    self.filter_max_rssi=max(self.filter_max_rssi-1, self.filter_min_rssi); self.request_scan_restart()
                elif key==ord(']') and self.active_tab=="settings":
                    self.filter_max_rssi=min(self.filter_max_rssi+1, 0); self.request_scan_restart()

                elif key in [curses.KEY_DOWN, ord('j')] and self.active_tab=="scan":
                    if beacons_len:
                        self.scan_selection=(self.scan_selection+1)%beacons_len
                        if self.scan_selection >= (self.scan_page+1)*max(1,per_page):
                            self.scan_page = min(self.scan_page+1, total_pages-1)

                elif key in [curses.KEY_UP, ord('k')] and self.active_tab=="scan":
                    if beacons_len:
                        self.scan_selection=(self.scan_selection-1)%beacons_len
                        if self.scan_selection < self.scan_page*max(1,per_page):
                            self.scan_page = max(self.scan_page-1, 0)

                elif key in [curses.KEY_NPAGE] and self.active_tab=="scan":
                    if beacons_len:
                        self.scan_page=min(self.scan_page+1, total_pages-1)
                        self.scan_selection=min(self.scan_selection+max(1,per_page), beacons_len-1)

                elif key in [curses.KEY_PPAGE] and self.active_tab=="scan":
                    if beacons_len:
                        self.scan_page=max(self.scan_page-1, 0)
                        self.scan_selection=max(self.scan_selection - max(1,per_page), 0)

                await asyncio.sleep(0.05)

            if scan_task:
                await scan_task
            # ensure final usage write
            self._save_usage(finalize=True)
        except Exception:
            logging.exception("Startup/main loop error")

# ========= main =========
def main(stdscr):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app = SherloCKCPU(stdscr)
    try:
        loop.run_until_complete(app.run())
    finally:
        loop.close()

if __name__ == "__main__":
    curses.wrapper(main)

