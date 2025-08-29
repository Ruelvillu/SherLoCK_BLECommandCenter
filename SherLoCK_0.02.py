Code is in current review and editing for issues 

Potentially Sensitive or Security-Relevant Elements

Environment Variables

NODE_ID, MESH_SEED, MESH_PROTO, MESH_REMOTE_DIR
These could leak infrastructure layout or hostnames.

Mesh Network Configuration

sshfs, nfs, and potentially remote directories (/srv/mesh)

Mount commands use sudo for mount/umount: could be risky if exploited.

BLE Device Data Collection

MAC addresses, local names, UUIDs, RSSI values

Although not personally identifiable, under GDPR-like regimes, MACs are treated as pseudonymous data and might be considered sensitive.

Logging and Export

Writes logs and snapshots with device data to files:

sherlock_crash.log, threat_db.csv, training_db.csv, snapshot_*.csv

These files might contain detailed BLE metadata and inferred device behavior.

Scriptable Interface

Accepts commands via mesh inbox and a local script dialog

Could be exploited if the mesh filesystem or UI is exposed or compromised.
