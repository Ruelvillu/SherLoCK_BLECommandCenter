# sherlock_nexus.py — SherloCK BLE Command Center with Nexus Mesh, Profiles, Training, Janitor
# Keys: w/a/i/h/n/s tabs | ENTER: Profile | x: Script | /: Command | m: cycle AI mode | R: restart scan | q: quit

import os, sys, time, math, csv, json, glob, socket, pathlib, asyncio, curses, subprocess, shutil, logging
from collections import defaultdict, deque, Counter
from hashlib import blake2b
import psutil
from bleak import BleakScanner

logging.basicConfig(filename="sherlock_crash.log", level=logging.DEBUG)

# ========= Mesh Manager =========
class MeshManager:
    """
    Nexus Mesh folder:
      status/<NODE_ID>.json  (heartbeat/status)
      inbox/<NODE_ID>.cmd    (commands for this node)

    Env:
      NODE_ID         : unique node id (default: hostname)
      MESH_DIR        : local mount point (default /mnt/mesh)
      MESH_REMOTE_DIR : remote export (default /srv/mesh)
      MESH_SEED       : seed host (default rv2-1)
      MESH_PROTO      : nfs|sshfs|auto (default auto)
      MESH_AUTO       : "1" to auto-connect when OFF
    """
    def __init__(self, node_id: str):
        self.node_id   = node_id
        self.proto     = os.environ.get("MESH_PROTO", "auto").lower()
        self.seed      = os.environ.get("MESH_SEED", "rv2-1")
        self.mesh_dir  = os.environ.get("MESH_DIR", "/mnt/mesh")
        self.remote    = os.environ.get("MESH_REMOTE_DIR", "/srv/mesh")
        self.status_dir= os.path.join(self.mesh_dir, "status")
        self.inbox_dir = os.path.join(self.mesh_dir, "inbox")
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
        try:
            os.makedirs(self.status_dir, exist_ok=True)
            os.makedirs(self.inbox_dir,  exist_ok=True)
        except Exception:
            pass

    def connect(self) -> bool:
        if self._mountpoint(self.mesh_dir):
            return True
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
                self.health["reason"] = "sshfs not installed"
                return False
            if not self._ping(self.seed):
                self.health["reason"] = f"seed {self.seed} unreachable"
                return False
            r = self._run(["sshfs", f"{self.seed}:{self.remote}", self.mesh_dir,
                           "-o","reconnect,ServerAliveInterval=15,ServerAliveCountMax=3"])
            if r.returncode != 0:
                self.health["reason"] = f"sshfs err: {r.stderr.strip()}"
                return False
            return True
        # local fallback
        return True

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
            logging.exception("mesh write_status")
            return False

    def inbox_lines(self):
        p = os.path.join(self.inbox_dir, f"{self.node_id}.cmd")
        if not os.path.exists(p):
            return []
        try:
            with open(p) as f:
                lines = [ln.strip() for ln in f if ln.strip()]
            # clear after reading
            open(p, "w").close()
            return lines
        except Exception:
            logging.exception("mesh inbox_lines")
            return []

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
        peers = []
        for fp in files:
            try:
                with open(fp) as f: d=json.load(f)
                nid = d.get("node") or pathlib.Path(fp).stem
                if nid != self.node_id:
                    peers.append((nid, os.path.getmtime(fp)))
            except Exception:
                continue
        return peers

    def health_check(self):
        self.ensure_dirs()
        mounted  = self._mountpoint(self.mesh_dir)
        writable = self._writable(self.status_dir)
        peers    = self._peer_statuses()
        fresh    = [p for p,t in peers if (time.time()-t) < 5]
        state = "OK" if writable and (fresh or peers) else ("DEGRADED" if writable else "OFF")
        self.health.update(dict(
            state=state, peers=len(set(p for p,_ in peers)), dir=self.mesh_dir,
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

# ========= Typing dictionaries / helpers =========
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

def safe_addstr(win, y, x, text):
    max_y,max_x=win.getmaxyx()
    try:
        win.addstr(y, x, str(text)[:max_x-x-1])
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
    chars=" ▁▂▃▄▅▆▇█"
    vals=list(seq)[-width:]; out=[]
    for v in vals:
        v = lo if v is None else max(lo, min(hi, v))
        idx=int((v-lo)/(hi-lo)*(len(chars)-1)); out.append(chars[idx])
    return "".join(out).ljust(width)

def _truncate(s, n): s=str(s); return s if len(s)<=n else s[:max(0,n-3)]+"..."

# ========= SherloCK =========
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

        # UI & state
        self.beacons = {}
        self.status = "Idle"; self.alert = ""
        self.active_tab = "scan"
        self.running = True; self.last_draw = 0
        self.scan_selection = 0; self.scan_page = 0
        self.filter_min_rssi = -100; self.filter_max_rssi = 0
        self.script_dialog_open = False; self.script_input = ""; self.script_cursor = 0
        self.hotlist = set(); self.action_log = []
        self.ai_command_prompt_open = False; self.ai_command_input = ""; self.ai_command_cursor = 0
        self.profile_mac = None

        # Memories
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
        self.training_db_path="training_db.csv"; self.training_db={}; self.load_training_db(); self.last_train_save=0

        # AI modes
        self.prev_mode=None; self.ai_mode="normal"; self.tuning={}; self.apply_mode("normal")

        # Scanner
        self.scanner=None; self.scan_should_restart=False

        # Threat DB
        self.csv_file="threat_db.csv"
        self.csv_headers=["time","mac","name","rssi","uuids","vendor","type","detected_by","notes","threat_rating"]
        if not os.path.exists(self.csv_file):
            with open(self.csv_file,"w",newline="") as f: csv.writer(f).writerow(self.csv_headers)
        self.load_known_safe()

        # Housekeeping
        self.last_janitor=0

    # ----- lists -----
    def load_lists(self):
        for fname, target in [("allowlist.txt", self.allowlist), ("denylist.txt", self.denylist)]:
            try:
                if os.path.exists(fname):
                    with open(fname) as f:
                        for line in f:
                            mac=line.strip().upper()
                            if mac: target.add(mac)
            except Exception: logging.exception("list load")

    def save_list(self, which):
        try:
            if which=="allow":
                with open("allowlist.txt","w") as f: f.write("\n".join(sorted(self.allowlist))+"\n")
            elif which=="deny":
                with open("denylist.txt","w") as f: f.write("\n".join(sorted(self.denylist))+"\n")
        except Exception: logging.exception("list save")

    # ----- training DB -----
    def training_key(self, mac, name, uuids_list):
        return (normalize_name(name or ""), oui_prefix(mac), ",".join(sorted((uuids_list or []))))

    def load_training_db(self):
        self.training_db={}
        if not os.path.exists(self.training_db_path): return
        try:
            with open(self.training_db_path, newline="") as f:
                r=csv.DictReader(f)
                for row in r:
                    key=(row["name_norm"],row["oui"],row["uuids_sig"])
                    self.training_db[key]=row
        except Exception: logging.exception("load_training_db")

    def save_training_db(self):
        try:
            with open(self.training_db_path,"w",newline="") as f:
                w=csv.writer(f)
                w.writerow(["name_norm","oui","uuids_sig","dtype","label","seen","rssi_med","rssi_min","rssi_max","last_seen"])
                for key,rec in self.training_db.items():
                    w.writerow([key[0],key[1],key[2],
                                rec.get("dtype",""),rec.get("label",""),rec.get("seen",0),
                                rec.get("rssi_med",""),rec.get("rssi_min",""),rec.get("rssi_max",""),rec.get("last_seen","")])
        except Exception: logging.exception("save_training_db")

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
            mem['patterns'].add("trained_rogue"); mem['attention']=max(mem['attention'],3)

    # ----- AI modes -----
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

    def set_ai_mode(self, mode): self.apply_mode(mode); self.action_log.append(f"AI mode set to {self.ai_mode}")
    def cycle_ai_mode(self):
        order=["relaxed","normal","paranoid","training"]
        try: i=(order.index(self.ai_mode)+1)%len(order)
        except ValueError: i=1
        self.set_ai_mode(order[i])

    # ----- DB helpers -----
    def load_known_safe(self):
        try:
            with open(self.csv_file, newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row["mac"] and int(row.get("threat_rating",3)) != 1 and self.ai_mode != "paranoid":
                        self.known_safe.add(row["mac"].upper())
        except Exception: logging.exception("Threat DB scan error")

    def get_cpu_usage(self):
        try: return psutil.Process(os.getpid()).cpu_percent(interval=0.05)
        except Exception: return 0.0

    def log_threat(self, mac, name, rssi, uuids, vendor, dtype, detected_by, notes, threat_rating=None):
        try:
            new_row=[time.strftime('%Y-%m-%d %H:%M:%S'), mac, name, rssi, uuids, vendor, dtype, detected_by, notes, threat_rating if threat_rating is not None else 3]
            with open(self.csv_file,"a",newline="") as f: csv.writer(f).writerow(new_row)
        except Exception: logging.exception("Threat log error")

    # ----- scanner -----
    def bleak_filters(self):
        rssi_floor=max(self.filter_min_rssi, -95)
        return {"Transport":"le","DuplicateData":False,"RSSI":rssi_floor}

    def create_scanner(self, callback):
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
                uuids_list=advertisement_data.service_uuids or []
                uuids=", ".join(uuids_list)
                local_name=advertisement_data.local_name or device.name or ""
                device_rssi=getattr(advertisement_data,"rssi",None)
                if device_rssi is None: device_rssi=getattr(device,"rssi",None)
                ts=time.time(); mac=device.address; macU=mac.upper()

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
                # apply training hints
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
        if addr and addr.upper() in self.known_safe and self.ai_mode!="paranoid": return 3
        if mem.get('ignore',False): return 99
        pats=mem.get('patterns',set())
        critical={"double_ssid","rogue_vendor","mac_cycling","beacon_storm","name_clone",
                  "name_vendor_mismatch","uuid_twin","shadow_follower","storm_src","teleport","trained_rogue"}
        has_critical=any(p in pats for p in critical)
        if self.ai_mode=="training": return 2 if has_critical else 3
        if "name_clone" in pats and ("name_vendor_mismatch" in pats or "rogue_vendor" in pats or "uuid_twin" in pats):
            return 1
        n_patterns=len(pats)
        if n_patterns>1 and has_critical: return 1
        if n_patterns==1 or any(p in pats for p in ["unstable_rssi","mirrored_rssi","co_appearance","name_flap","uuid_flap"]): return 2
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
                patterns=set()
                vendor=OUI_TO_VENDOR.get(oui_prefix(addr),"unknown")

                if oui_prefix(addr) not in OUI_TO_VENDOR: patterns.add("rogue_vendor")

                hist=self.rssi_history[addr]; values=[r for _,r in hist if r is not None]
                med,madn,rng=robust_stats(values)
                if values and ((madn and madn>t["unstable_mad"]) or (rng and rng>t["unstable_range"])): patterns.add("unstable_rssi")

                # teleport / unrealistic speed (distance drift)
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

                # mirrored RSSI + follower
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

                # UUID twin / flap
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

            # Evil twin by same name
            for ssid, addrs in ssid_map.items():
                if len(set(addrs))>1:
                    for a in addrs:
                        mem=self.device_ai_memory[a]
                        mem['patterns'].add('double_ssid')
                        mem['events'].append((now, ['double_ssid']))
                        mem['notes']=f"Same name as others ({ssid})"
                        mem['attention']=min(mem['attention']+1, 3)
                        mem['status']='analyzing' if mem['attention']>=2 else 'watching'

            # Global storm
            if len(self.beacons) > self.tuning["storm_thresh"]:
                for addr,mem in self.device_ai_memory.items(): mem['patterns'].add('beacon_storm')

            # Update threat, cluster, plan
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
            logging.exception("AI agent error")
            self.alert="AI agent error."

    def summarize_case(self, addr, mem):
        try:
            lines=[f"CASE FILE: {addr} ({mem.get('status','idle')})",
                   f"Type: {mem.get('type','unknown')} | Tags: {', '.join(sorted(mem.get('user_tags',[])))}",
                   f"Cluster: {', '.join(mem.get('cluster', []))}",
                   f"Attention: {mem.get('attention',0)} | Patterns: {', '.join(sorted(mem.get('patterns',[])))}",
                   f"Threat: {mem.get('threat_rating',3)} | Confidence: {mem.get('confidence',1)} | Plan: {mem.get('plan','ignore')} | Label: {mem.get('label') or ''}",
                   f"Notes: {mem.get('notes','')}"]
            if mem['timeline']:
                t0=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mem['timeline'][0][0]))
                tN=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mem['timeline'][-1][0]))
                lines.append(f"Timeline: {t0} — {tN} ({len(mem['timeline'])} frames)")
            for t,ev in list(mem['events'])[-3:]:
                lines.append(f"  {time.strftime('%H:%M:%S', time.localtime(t))}: {', '.join(ev)}")
            return "\n".join(lines)
        except Exception:
            logging.exception("Case summary error")
            return "CASE ERROR"

    # ----- janitor -----
    def janitor_tick(self):
        now=time.time()
        for addr,mem in list(self.device_ai_memory.items()):
            if addr.upper() in self.known_safe or addr.upper() in self.allowlist:
                mem['ignore']=True; mem['patterns'].add("known_safe")
            # decay storm tag if idle
            if "storm_src" in mem['patterns']:
                if now - mem.get('last_seen', now) > 120:
                    mem['patterns'].discard("storm_src")

    # ----- mesh helpers -----
    def write_mesh_status(self):
        try:
            snap={
                "node": self.node_id, "time": time.time(), "mode": self.ai_mode,
                "beacon_count": len(self.beacons),
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

    def draw(self):
        try:
            max_y,max_x=self.stdscr.getmaxyx()
            self.stdscr.erase()
            cpu=self.get_cpu_usage()
            safe_addstr(self.stdscr, 1, 2, f"SherloCK@{self.node_id}: {self.sherlock_pet_status} | Mode: {self.ai_mode} | {_truncate(self._draw_mesh_gauge(), max_x-20)}")
            safe_addstr(self.stdscr, 0, 2, f"BLE Command Center — Status: {self.status} — AI Load: {cpu:.1f}%")
            if self.alert: safe_addstr(self.stdscr,2,2,self.alert)
            tabs=["[Scan:w]","[Analyze:a]","[Profile:ENTER]","[AI:i]","[Hunt:h]","[Mesh:n]","[Settings:s]","[Script:x]","[AIcmd:/]","[Mode:m]","[Restart:R]","[Quit:Q]"]
            x=2
            for t in tabs:
                name=t.split(":")[0].strip("[]").lower()
                if (name=="profile" and self.active_tab=="profile") or name==self.active_tab:
                    self.stdscr.attron(curses.A_REVERSE)
                safe_addstr(self.stdscr,3,x,t)
                self.stdscr.attroff(curses.A_REVERSE)
                x+=len(t)+2

            if self.active_tab=="scan": self.draw_scan_tab(max_y,max_x)
            elif self.active_tab=="analyze": self.draw_analyze_tab(max_y,max_x)
            elif self.active_tab=="profile": self.draw_profile_tab(max_y,max_x)
            elif self.active_tab=="ai": self.draw_ai_tab(max_y,max_x)
            elif self.active_tab=="hunt": self.draw_hunt_tab(max_y,max_x)
            elif self.active_tab=="mesh": self.draw_mesh_tab(max_y,max_x)
            elif self.active_tab=="settings": self.draw_settings_tab(max_y,max_x)

            safe_addstr(self.stdscr, max_y-1, 2, "Arrows | ENTER:profile | w/a/i/h/n/s tabs | x:script | /:AIcmd | m:mode | R:restart-scan | q:quit")
            if self.script_dialog_open: self.draw_script_dialog(max_y,max_x)
            if self.ai_command_prompt_open: self.draw_ai_command_prompt(max_y,max_x)
            self.stdscr.refresh()
        except Exception:
            logging.exception("Draw error")

    def draw_scan_tab(self, max_y, max_x):
        try:
            beacons_list=self.filtered_beacons()
            per_page=max_y-11
            total_pages=max(1, (len(beacons_list)+per_page-1)//per_page)
            start=self.scan_page*per_page; end=start+per_page
            safe_addstr(self.stdscr,5,2,f"Detected BLE Beacons (RSSI {self.filter_min_rssi} {self.ai_mode})")
            safe_addstr(self.stdscr,6,2," #  Addr                 RSSI  Dist(m)  Type         Threat  Conf  Plan      Name")
            if not beacons_list:
                safe_addstr(self.stdscr,8,4,"No BLE devices found (filtered or out of range)."); return
            for idx,(addr,(rssi,uuids,local_name,last_seen)) in enumerate(beacons_list[start:end], start=start):
                mem=self.device_ai_memory.get(addr,{})
                rating=mem.get('threat_rating',3); threat_str={1:"CRIT",2:"WARN",3:"OBS",99:"IGNR"}.get(rating,"?")
                dtype=mem.get('type','unknown'); plan=mem.get('plan','ignore'); confidence=mem.get('confidence',1)
                obs="*" if addr.lower() in self.hotlist else " "
                est_dist=estimate_distance(rssi); est=f"{est_dist:>7}" if est_dist!="?" else "   ?   "
                line=f"{obs}{idx:>2}  {addr:20} {str(rssi):>6} {est}  {dtype:10}  {threat_str:>6}   {confidence:^3}   {plan:8}  {local_name[:18]}"
                y=7+(idx-start)
                if idx==self.scan_selection:
                    self.stdscr.attron(curses.A_REVERSE); safe_addstr(self.stdscr,y,2,line); self.stdscr.attroff(curses.A_REVERSE)
                else: safe_addstr(self.stdscr,y,2,line)
            safe_addstr(self.stdscr, 7+per_page, 2, f"Page {self.scan_page+1}/{total_pages}")
        except Exception:
            logging.exception("Scan tab error")

    def draw_analyze_tab(self, max_y, max_x):
        try:
            beacons_list=self.filtered_beacons()
            safe_addstr(self.stdscr,5,2,"Analyze Tab (selected device details below)")
            if not beacons_list: safe_addstr(self.stdscr,8,2,"No device selected."); return
            idx=min(self.scan_selection, len(beacons_list)-1)
            addr,(rssi,uuids,local_name,_) = beacons_list[idx]
            mem=self.device_ai_memory.get(addr,{})
            safe_addstr(self.stdscr,8,2,f"Device: {addr}")
            safe_addstr(self.stdscr,9,2,f"RSSI: {rssi}   Dist: {estimate_distance(rssi)} m   Vendor: {OUI_TO_VENDOR.get(oui_prefix(addr),'unknown')}")
            safe_addstr(self.stdscr,10,2,f"UUIDs: {uuids}")
            safe_addstr(self.stdscr,11,2,f"Name: {local_name}")
            safe_addstr(self.stdscr,12,2,f"Type: {mem.get('type','unknown')}")
            safe_addstr(self.stdscr,13,2,f"Status: {mem.get('status','idle')}  Threat: {mem.get('threat_rating',3)}  Conf: {mem.get('confidence',1)}  Plan: {mem.get('plan','ignore')}")
            safe_addstr(self.stdscr,14,2,f"Patterns: {', '.join(sorted(mem.get('patterns', [])))}")
            safe_addstr(self.stdscr,15,2,f"Notes: {mem.get('notes','')}")
        except Exception:
            logging.exception("Analyze tab error")

    def draw_profile_tab(self, max_y, max_x):
        try:
            beacons_list=self.filtered_beacons()
            if not beacons_list: safe_addstr(self.stdscr,5,2,"Profile: no device selected."); return
            if self.profile_mac is None:
                idx=min(self.scan_selection, len(beacons_list)-1)
                self.profile_mac=beacons_list[idx][0]
            addr=self.profile_mac
            if addr not in self.beacons: safe_addstr(self.stdscr,5,2,"Device left range."); return
            rssi,uuids,local_name,last_seen=self.beacons[addr]
            mem=self.device_ai_memory[addr]
            safe_addstr(self.stdscr,5,2,f"Device Profile — {addr}")
            safe_addstr(self.stdscr,6,2,f"Name: {local_name}   Vendor: {OUI_TO_VENDOR.get(oui_prefix(addr),'unknown')}   Type: {mem.get('type','unknown')}")
            safe_addstr(self.stdscr,7,2,f"Threat: {mem.get('threat_rating',3)}  Status: {mem.get('status')}  Plan: {mem.get('plan')}  Conf: {mem.get('confidence')}")
            safe_addstr(self.stdscr,8,2,f"UUIDs: {uuids}")
            hist=[rv for _,rv in self.rssi_history[addr]]
            safe_addstr(self.stdscr,10,2,"RSSI last 80: "+sparkline(hist, width=min(80,max_x-20)))
            med,madn,rng=robust_stats([v for v in hist if v is not None])
            if med is not None:
                safe_addstr(self.stdscr,11,2, f"RSSI stats — median:{med}  MAD≈{madn:.1f}  range:{rng}")
            else:
                safe_addstr(self.stdscr,11,2, "RSSI stats — (insufficient)")
            safe_addstr(self.stdscr,13,2,f"Patterns: {', '.join(sorted(mem.get('patterns', [])))}")
            safe_addstr(self.stdscr,14,2,f"Tags: {', '.join(sorted(mem.get('user_tags', [])))}  | Label: {mem.get('label') or ''}")
            note=mem.get('notes','')
            for i,chunk in enumerate([note[i:i+max_x-8] for i in range(0,len(note),max_x-8)]):
                safe_addstr(self.stdscr,16+i,4,chunk)
            safe_addstr(self.stdscr, max_y-2, 2, "Profile keys: b=back | /=AIcmd (note/tag/label)")
        except Exception:
            logging.exception("Profile tab error")

    def draw_ai_tab(self, max_y, max_x):
        try:
            safe_addstr(self.stdscr, 5, 2, "SherloCK AI: Case Map & Clusters")
            pat_counts = Counter()
            for mem in self.device_ai_memory.values():
                for p in mem.get('patterns', []):
                    pat_counts[p] += 1
            y = 7
            top_line = ", ".join(f"{p}:{c}" for p, c in pat_counts.most_common(6)) or "(no patterns yet)"
            safe_addstr(self.stdscr, y, 4, "Top Patterns: " + top_line)
            y += 2
            safe_addstr(self.stdscr, y, 4, "Clusters (last 4):")
            for label, devices in list(self.device_clusters.items())[-4:]:
                if y >= max_y - 3:
                    break
                y += 1
                label_txt = ",".join(label) if label else "benign"
                safe_addstr(self.stdscr, y, 6, f"{label_txt} | {len(devices)} devs")
                if devices:
                    safe_addstr(self.stdscr, y, 48, f"e.g. {devices[0]}")
            y += 2
            safe_addstr(self.stdscr, y, 4, "Focused Case:")
            if self.focused_mac and self.focused_mac in self.case_file_summaries:
                for line in self.case_file_summaries[self.focused_mac].splitlines():
                    y += 1
                    if y >= max_y - 2: break
                    safe_addstr(self.stdscr, y, 6, line)
            else:
                y += 1
                safe_addstr(self.stdscr, y, 6, "No current focus.")
        except Exception:
            logging.exception("AI tab error")

    def draw_hunt_tab(self, max_y, max_x):
        try:
            beacons=self.filtered_beacons()
            if not beacons:
                safe_addstr(self.stdscr,5,2,"Hunt Mode — select a device in Scan tab first (w), then press h."); return
            idx=min(self.scan_selection, len(beacons)-1)
            addr,(rssi,uuids,local_name,_) = beacons[idx]
            if self.hunt_best is None or (rssi is not None and rssi>self.hunt_best):
                self.hunt_best=rssi
                try: curses.beep()
                except Exception: pass
            safe_addstr(self.stdscr,5,2,f"Hunt Mode — {addr}  name:{(local_name or '')[:18]}")
            scale_min,scale_max=-100,-30
            val=rssi if rssi is not None else scale_min
            frac=(max(scale_min,min(val,scale_max))-scale_min)/(scale_max-scale_min)
            bar_w=max_x-8; fill=int(frac*bar_w)
            safe_addstr(self.stdscr,7,4,"["+"#"*fill+"-"*(bar_w-fill)+"]")
            safe_addstr(self.stdscr,8,4,f"RSSI: {rssi} dBm   Best: {self.hunt_best} dBm")
            hist=[rv for _,rv in self.rssi_history[addr] if rv is not None]
            if hist:
                avg5=sum(hist[-5:])/min(5,len(hist)); avg10=sum(hist[-10:])/min(10,len(hist))
                safe_addstr(self.stdscr,9,4,f"Avg(5): {avg5:.1f}   Avg(10): {avg10:.1f}")
            safe_addstr(self.stdscr,11,4,"Tip: move toward stronger (less negative) RSSI. Beeps on new best.")
        except Exception:
            logging.exception("Hunt tab error")

    def draw_mesh_tab(self, max_y, max_x):
        mh=self.mesh_health
        safe_addstr(self.stdscr,5,2,"Nexus Mesh — connectivity & control")
        safe_addstr(self.stdscr,7,4,f"State: {mh['state']}   Peers: {mh['peers']}   Mounted: {mh['mounted']}   Writable: {mh['writable']}")
        safe_addstr(self.stdscr,8,4,f"Dir: {mh['dir']}   Seed: {self.mesh.seed}   Proto: {self.mesh.proto}")
        if mh.get("reason"): safe_addstr(self.stdscr,9,4,f"Reason: {mh['reason']}")
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
        row=11; safe_addstr(self.stdscr,row,4,"Peers:")
        for nid,age,p in sorted(peers)[:10]:
            row+=1; safe_addstr(self.stdscr,row,6,f"- {nid:<12} age:{age:4.1f}s  path:{p[:max_x-30]}")
        row+=2
        safe_addstr(self.stdscr,row,4,"Commands: mesh connect | mesh disconnect | mesh seed <host> | mesh dir <path> | mesh proto <auto|nfs|sshfs> | mesh status")
        safe_addstr(self.stdscr,row+1,4,"Tip: set NODE_ID and MESH_AUTO=1 in env for auto-reconnect.")

    def draw_settings_tab(self, max_y, max_x):
        try:
            safe_addstr(self.stdscr,5,2,"Settings")
            safe_addstr(self.stdscr,8,4,f"Filter Min RSSI: {self.filter_min_rssi} (adjust: < >)")
            safe_addstr(self.stdscr,9,4,f"Filter Max RSSI: {self.filter_max_rssi} (adjust: [ ])")
            safe_addstr(self.stdscr,11,4,"Press R to restart scan and apply adapter filters immediately.")
        except Exception:
            logging.exception("Settings tab error")

    def draw_script_dialog(self, max_y, max_x):
        try:
            w=min(96,max_x-4); h=14
            x=(max_x-w)//2; y=(max_y-h)//2
            box=self.stdscr.derwin(h,w,y,x); box.box()
            safe_addstr(box,0,2,"Scripting/Automation (ESC to exit)")
            safe_addstr(box,2,2,"Command: ")
            disp=self.script_input[:w-20]; safe_addstr(box,2,12,disp); box.move(2,12+self.script_cursor)
            safe_addstr(box,4,2,f"Hotlist: {', '.join(list(self.hotlist)[:4])} ...")
            for i,l in enumerate(self.action_log[-3:] if self.action_log else []):
                safe_addstr(box,6+i,2,f"Log: {l}")
            safe_addstr(box,10,2,"Examples: note <mac> <text> | tag <mac> add <tag> | label <mac> benign|rogue | export snapshot | train save/load/apply/clear | mesh connect")
            box.refresh()
        except Exception:
            logging.exception("Script dialog error")

    def draw_ai_command_prompt(self, max_y, max_x):
        try:
            w=min(96,max_x-4); h=14
            x=(max_x-w)//2; y=(max_y-h)//2
            box=self.stdscr.derwin(h,w,y,x); box.box()
            safe_addstr(box,0,2,"SherloCK Command (ESC to exit)")
            safe_addstr(box,2,2,"> "+self.ai_command_input); box.move(2,4+self.ai_command_cursor)
            safe_addstr(box,3,2,"observe/unobserve/ignore/unignore/flag/type | mode | quarantine/unquarantine")
            safe_addstr(box,4,2,"allow/deny | save allow|deny | note <mac> <text> | tag <mac> add|del <tag> | label <mac> benign|rogue")
            safe_addstr(box,5,2,"train save|load|apply|clear | export snapshot | mesh connect|disconnect|seed|dir|proto|status")
            box.refresh()
        except Exception:
            logging.exception("AI cmd dialog error")

    # ----- export -----
    def export_snapshot(self):
        try:
            ts=time.strftime('%Y%m%d_%H%M%S'); fname=f"snapshot_{ts}.csv"
            headers=["time","mac","name","rssi","uuids","threat","confidence","plan","patterns"]
            with open(fname,"w",newline="") as f:
                w=csv.writer(f); w.writerow(headers)
                for addr,(rssi,uuids,name,_) in self.beacons.items():
                    mem=self.device_ai_memory.get(addr,{})
                    w.writerow([ts,addr,name,rssi,uuids,mem.get("threat_rating",3),mem.get("confidence",1),mem.get("plan","ignore"),"|".join(sorted(mem.get("patterns",[])))])
            self.action_log.append(f"Exported {fname}")
        except Exception:
            logging.exception("snapshot export error")

    # ----- commands -----
    def script_command(self, cmd, maxlen=80):
        out=""
        try:
            cmd=cmd.strip()
            # Mesh
            if cmd.startswith("mesh "):
                toks=cmd.split()
                if toks[1]=="connect":
                    ok=self.mesh.connect(); self.mesh_health=self.mesh.health_check(); out=f"mesh connect: {'ok' if ok else 'failed'}"
                elif toks[1]=="disconnect":
                    self.mesh.disconnect(); self.mesh_health=self.mesh.health_check(); out="mesh disconnect: done"
                elif toks[1]=="seed" and len(toks)>=3:
                    self.mesh.seed=toks[2]; out=f"mesh seed -> {self.mesh.seed}"
                elif toks[1]=="dir" and len(toks)>=3:
                    self.mesh.mesh_dir=toks[2]; self.mesh.status_dir=os.path.join(self.mesh.mesh_dir,"status"); self.mesh.inbox_dir=os.path.join(self.mesh.mesh_dir,"inbox")
                    self.mesh.ensure_dirs(); self.mesh_health=self.mesh.health_check(); out=f"mesh dir -> {self.mesh.mesh_dir}"
                elif toks[1]=="proto" and len(toks)>=3:
                    self.mesh.proto=toks[2].lower(); out=f"mesh proto -> {self.mesh.proto}"
                elif toks[1]=="status":
                    self.mesh_health=self.mesh.health_check(); out=str(self.mesh_health)
                else:
                    out="mesh cmds: connect|disconnect|seed <h>|dir <p>|proto <auto|nfs|sshfs>|status"
                if len(out)>maxlen: out=out[:maxlen-3]+"..."
                self.action_log.append(out); return

            # Core
            if cmd.startswith("observe "):
                mac=cmd.split()[1].strip().lower(); self.hotlist.add(mac); out=f"Added {mac} to hotlist."
            elif cmd.startswith("unobserve "):
                mac=cmd.split()[1].strip().lower(); self.hotlist.discard(mac); out=f"Removed {mac}."
            elif cmd.startswith("ignore "):
                mac=cmd.split()[1].strip().lower(); self.device_ai_memory[mac]['ignore']=True; out=f"Ignoring {mac}"
            elif cmd.startswith("unignore "):
                mac=cmd.split()[1].strip().lower(); self.device_ai_memory[mac]['ignore']=False; out=f"Stopped ignoring {mac}"
            elif cmd.startswith("flag "):
                mac=cmd.split()[1].strip().lower(); self.device_ai_memory[mac]['flag']=True; out=f"Always flagging {mac}"
            elif cmd.startswith("type "):
                toks=cmd.split(); mac=toks[1].strip().lower(); typ=toks[2].strip().lower() if len(toks)>2 else "unknown"
                self.device_ai_memory[mac]['type']=typ; out=f"Set {mac} type to {typ}"
            elif cmd.startswith("label "):
                toks=cmd.split(); mac=toks[1].strip().lower(); lbl=toks[2].strip().lower()
                self.device_ai_memory[mac]['label']=lbl; out=f"Labeled {mac} as {lbl}"
            elif cmd.startswith("tag "):
                toks=cmd.split(); mac=toks[1].strip().lower(); op=toks[2]; tag=toks[3]
                tags=self.device_ai_memory[mac]['user_tags']
                if op=="add": tags.add(tag); out=f"Tagged {mac} +{tag}"
                elif op=="del": tags.discard(tag); out=f"Untagged {mac} -{tag}"
            elif cmd.startswith("note "):
                toks=cmd.split(maxsplit=2); mac=toks[1].strip().lower(); txt=toks[2] if len(toks)>2 else ""
                self.device_ai_memory[mac]['notes']=txt; out="Noted."
            elif cmd.startswith("list hot"):
                out="Hotlist: "+", ".join(self.hotlist)
            elif cmd.startswith("list beacons"):
                beacons=list(self.filtered_beacons()); out=" ".join(f"{a}" for a,_ in beacons[:5])
            elif cmd.startswith("observe strong"):
                for addr,(rssi,_,_,_) in self.filtered_beacons():
                    if rssi is not None and rssi>-50: self.hotlist.add(addr.lower())
                out="Added strong beacons."
            elif cmd.startswith("mode "):
                mode=cmd.split()[1].strip().lower()
                if mode not in {"relaxed","normal","paranoid","training"}: out="Mode: relaxed|normal|paranoid|training"
                else: self.set_ai_mode(mode); out=f"AI mode -> {self.ai_mode}"
            elif cmd=="export snapshot":
                self.export_snapshot(); out="Snapshot exported."
            elif cmd.startswith("quarantine "):
                toks=cmd.split(); mac=toks[1].strip().lower(); secs=int(toks[2]) if len(toks)>2 else self.quarantine_secs
                self.quarantine_until[mac]=time.time()+max(5,secs); out=f"Quarantined {mac} for {secs}s."
            elif cmd.startswith("unquarantine "):
                mac=cmd.split()[1].strip().lower(); self.quarantine_until[mac]=0.0; out=f"Unquarantined {mac}."
            elif cmd.startswith("allow "):
                mac=cmd.split()[1].strip().upper(); self.allowlist.add(mac); self.known_safe.add(mac); out=f"Allowlisted {mac}"
            elif cmd.startswith("deny "):
                mac=cmd.split()[1].strip().upper(); self.denylist.add(mac); out=f"Denylisted {mac}"
            elif cmd=="save allow":
                self.save_list("allow"); out="allowlist saved."
            elif cmd=="save deny":
                self.save_list("deny"); out="denylist saved."
            elif cmd=="train save":
                self.update_training_from_current(); self.save_training_db(); out="Training DB saved."
            elif cmd=="train load":
                self.load_training_db(); out="Training DB loaded."
            elif cmd=="train apply":
                for mac,(rssi,uuids,name,_) in list(self.beacons.items()):
                    self.apply_training_to_memory(mac, name, [u.strip() for u in (uuids.split(',') if uuids else [])], self.device_ai_memory[mac])
                out="Training applied."
            elif cmd=="train clear":
                self.training_db={}; self.save_training_db(); out="Training DB cleared."
            else:
                out=("Unknown cmd. Try: observe/unobserve/ignore/unignore/flag/type/label/tag/note, "
                     "mode <relaxed|normal|paranoid|training>, quarantine/unquarantine, allow/deny, "
                     "save allow|deny, train save|load|apply/clear, export snapshot, mesh connect|disconnect|seed|dir|proto|status")
        except Exception as e:
            out=f"ERR: {e}"; logging.exception("Script command error")
        if len(out)>maxlen: out=out[:maxlen-3]+"..."
        self.action_log.append(out)

    # ----- main loop -----
    async def run(self):
        try:
            curses.start_color(); curses.use_default_colors(); curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
        except Exception:
            pass
        try:
            scan_task=asyncio.create_task(self.ble_scan())
            ai_timer=time.time()
            while self.running:
                now=time.time()
                # mesh heartbeat
                if now - self.last_mesh_check > 1.0:
                    self.mesh_health=self.mesh.health_check()
                    self.write_mesh_status()
                    self.process_mesh_inbox()
                    self.last_mesh_check=now
                # draw / AI
                if now - self.last_draw > 0.15:
                    self.draw(); self.last_draw=now
                if now - ai_timer > (0.3 if len(self.beacons) < 400 else 2.0):
                    self.sherlock_agent_investigation(); ai_timer=now
                # janitor + training autosave
                if now - self.last_janitor > 5:
                    self.janitor_tick(); self.last_janitor=now
                if self.ai_mode=="training" and (now - self.last_train_save)>30:
                    self.update_training_from_current(); self.save_training_db(); self.last_train_save=now

                # input
                self.stdscr.nodelay(True)
                try: key=self.stdscr.getch()
                except Exception: key=-1

                beacons_list=self.filtered_beacons(); beacons_len=len(beacons_list)
                per_page=self.stdscr.getmaxyx()[0]-11
                total_pages=max(1,(beacons_len+per_page-1)//per_page)

                if self.ai_command_prompt_open:
                    if key in (27,):
                        self.ai_command_prompt_open=False; self.ai_command_input=""; self.ai_command_cursor=0
                    elif key in (curses.KEY_BACKSPACE,127,8):
                        if self.ai_command_cursor>0:
                            self.ai_command_input=(self.ai_command_input[:self.ai_command_cursor-1]+self.ai_command_input[self.ai_command_cursor:])
                            self.ai_command_cursor-=1
                    elif key in (curses.KEY_LEFT,): self.ai_command_cursor=max(0,self.ai_command_cursor-1)
                    elif key in (curses.KEY_RIGHT,): self.ai_command_cursor=min(len(self.ai_command_input), self.ai_command_cursor+1)
                    elif key in (curses.KEY_ENTER,10,13):
                        self.script_command(self.ai_command_input); self.ai_command_prompt_open=False; self.ai_command_input=""; self.ai_command_cursor=0
                    elif 32<=key<127:
                        ch=chr(key); self.ai_command_input=(self.ai_command_input[:self.ai_command_cursor]+ch+self.ai_command_input[self.ai_command_cursor:]); self.ai_command_cursor+=1
                    await asyncio.sleep(0.01); continue

                if self.script_dialog_open:
                    if key in (27,): self.script_dialog_open=False; self.script_input=""; self.script_cursor=0
                    elif key in (curses.KEY_BACKSPACE,127,8):
                        if self.script_cursor>0:
                            self.script_input=(self.script_input[:self.script_cursor-1]+self.script_input[self.script_cursor:])
                            self.script_cursor-=1
                    elif key in (curses.KEY_DC,):
                        if self.script_cursor<len(self.script_input):
                            self.script_input=(self.script_input[:self.script_cursor]+self.script_input[self.script_cursor+1:])
                    elif key in (curses.KEY_LEFT,): self.script_cursor=max(0,self.script_cursor-1)
                    elif key in (curses.KEY_RIGHT,): self.script_cursor=min(len(self.script_input), self.script_cursor+1)
                    elif key in (curses.KEY_ENTER,10,13):
                        self.script_command(self.script_input); self.script_input=""; self.script_cursor=0
                    elif 32<=key<127:
                        ch=chr(key); self.script_input=(self.script_input[:self.script_cursor]+ch+self.script_input[self.script_cursor:]); self.script_cursor+=1
                    await asyncio.sleep(0.01); continue

                # global keys
                if key in (ord('q'),ord('Q')): self.running=False
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
                elif key in (curses.KEY_ENTER,10,13):
                    if beacons_len:
                        idx=min(self.scan_selection, beacons_len-1); self.profile_mac=beacons_list[idx][0]; self.active_tab="profile"
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
                        if self.scan_selection >= (self.scan_page+1)*per_page:
                            self.scan_page = min(self.scan_page+1, total_pages-1)
                elif key in [curses.KEY_UP, ord('k')] and self.active_tab=="scan":
                    if beacons_len:
                        self.scan_selection=(self.scan_selection-1)%beacons_len
                        if self.scan_selection < self.scan_page*per_page:
                            self.scan_page = max(self.scan_page-1, 0)
                elif key in [curses.KEY_NPAGE] and self.active_tab=="scan":
                    if beacons_len:
                        self.scan_page=min(self.scan_page+1, total_pages-1)
                        self.scan_selection=min(self.scan_selection+per_page, beacons_len-1)
                elif key in [curses.KEY_PPAGE] and self.active_tab=="scan":
                    if beacons_len:
                        self.scan_page=max(self.scan_page-1, 0)
                        self.scan_selection=max(self.scan_selection - per_page, 0)

                await asyncio.sleep(0.05)
            await scan_task
        except Exception:
            logging.exception("Startup/main loop error")

# ========= main =========
def main(stdscr):
    loop=asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    app=SherloCKCPU(stdscr)
    try:
        loop.run_until_complete(app.run())
    finally:
        loop.close()

if __name__=="__main__":
    curses.wrapper(main)

