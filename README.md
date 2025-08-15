# SherloCK — BLE Command Center (Nexus Mesh Edition)

SherloCK is a defensive tool for monitoring 2.4 GHz BLE advertisements on Linux SBCs. It is passive only. It detects spoofing, impersonation, and flooding, and presents explainable results in a terminal UI. Multiple nodes can be supervised through a shared-folder “Nexus Mesh” heartbeat.

## Features

* Passive detections: evil-twin/name clones, UUID twins/flaps, MAC cycling, mirrored RSSI and shadow followers, beacon storms, unstable RSSI, vendor/name mismatch, and “teleport” (implausible movement).
* Explainable outputs: pattern tags, threat level (CRIT/WARN/OBS), confidence, action plan.
* Operator UI: Scan, Analyze, Profile (per-device page), AI/Clusters, Hunt (signal meter), Mesh, Settings.
* Training mode: builds a CSV baseline of the local environment; can be applied later.
* Janitor: ignores known-safe devices and decays stale flags.
* Fleet heartbeat: each node writes `status/<NODE>.json` to a shared directory; Mesh tab shows connectivity and peers.

## Requirements

* Linux (Debian/Ubuntu/Raspberry Pi OS), Python 3.9+
* BlueZ: `sudo apt install -y bluez python3-venv`
* Optional Mesh transports:

  * sshfs: `sudo apt install -y sshfs`
  * nfs: server `nfs-kernel-server`, clients `nfs-common`

## Ethical

Use only in environments you own or have explicit permission to assess. The system is passive and intended for monitoring and defense. Do not jam or attempt unauthorized access. 
This software comes AS IS.

## Responsible Use

Use SherloCK only in environments you own or have explicit, written permission to assess. 
The system is passive and intended for monitoring and defense. Do not jam, disrupt, or seek 
unauthorized access to networks or devices. Always comply with applicable laws and organizational policies.

## Quick Start

```bash
git clone https://github.com/<you>/SherloCK_BLECommandCenter.git
cd SherloCK_BLECommandCenter
python3 -m venv .venv && source .venv/bin/activate
pip install bleak psutil
```

Environment (unique per node):

```bash
export NODE_ID=rv2-2
export MESH_DIR=/mnt/mesh
export MESH_SEED=rv2-1
export MESH_PROTO=sshfs    # or nfs
export MESH_AUTO=1
python3 sherlock_nexus.py
```

Seed preparation (run once on the seed host):

```bash
sudo mkdir -p /srv/mesh/status /srv/mesh/inbox
sudo chmod 1777 /srv/mesh/status /srv/mesh/inbox
```

Turn Mesh on from the agent (press `/` then run):

```
mesh seed rv2-1
mesh dir /mnt/mesh
mesh proto sshfs
mesh connect
mesh status
```

## Controls (TUI)

* Tabs: w=Scan, a=Analyze, ENTER=Profile, i=AI/Clusters, h=Hunt, n=Mesh, s=Settings
* Palettes: x=Script, /=Command box
* Mode: m (relaxed → normal → paranoid → training)
* Paging: arrows, PgUp/PgDn
* Restart BLE scan: R
* Quit: q

## Useful Commands (in `/` box)

```
note <mac> <text>
tag <mac> add|del <tag>
label <mac> benign|rogue
allow <mac> | deny <mac> | save allow | save deny
quarantine <mac> <secs> | unquarantine <mac>
mode paranoid|normal|relaxed|training
train save | train load | train apply | train clear
export snapshot
mesh connect | mesh disconnect | mesh seed <host> | mesh dir <path> | mesh proto <auto|sshfs|nfs> | mesh status
```

## Training Mode

1. Set mode to training (press m until “training”).
2. Observe the environment.
3. Run `train save` to write `training_db.csv`.
4. Later sessions: `train load` then `train apply`.

## Data Files

* `training_db.csv` — site baseline.
* `threat_db.csv` — detection log.
* `allowlist.txt`, `denylist.txt` — optional local policy.
* Mesh:

  * `<MESH_DIR>/status/<NODE>.json` — heartbeat.
  * `<MESH_DIR>/inbox/<NODE>.cmd` — remote commands.

## Troubleshooting

* Mesh OFF: ensure all nodes mount the same directory; run `mesh connect`; verify `ls -l /mnt/mesh/status` shows all node files.
* No devices: confirm BlueZ is running and the adapter is present; user has required permissions.
* Stale peers with sshfs: caching is disabled in code (`-o cache=no`). Increase freshness window if needed.



## License

MIT © 2025 Machi Reul
You may use, modify, and redistribute with attribution by preserving the copyright notice and this license text in copies or substantial portions of the Software.
Recommended header in source files:

```text
SPDX-License-Identifier: MIT
Copyright (c) 2025 Machi Reul
```

## Citation (optional)

If you use SherloCK in research or a product, please cite “Machi Reul — SherloCK: BLE Command Center (Nexus Mesh Edition)” or keep a link to this repository.
