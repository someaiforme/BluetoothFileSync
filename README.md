# BAWFSync
Bidirectional Android Windows File Sync

A tool for syncing files between an Android phone and Windows computer over Bluetooth

<img width="512" height="512" alt="bawfsync_logo" src="https://github.com/user-attachments/assets/36fdf08f-d00a-45f7-b5c7-71db4bfd7e8f" />


No wifi, no cable, no internet, totally offline

Use case is for smaller files, ie this isn't going to be practical for photos or videoes, this is because Classic Bluetooth RFCOMM tops out somewhere around 1–3 Mbps in practice (roughly 150–375 KB/s)

Real world testing results are 5MB takes 30 seconds

Python Windows script
Dependancy: Encryption

Two-way file synchronization

SHA-256 comparison

Conflict preservation on both sides

Backups before replacement

.btpart protection for interrupted transfers

Secure Bluetooth RFCOMM connection

First-time pairing/authentication

AES-256-GCM encrypted post-authentication traffic

HKDF-derived directional session keys

Counter-based nonces

Filename handling with spaces

Auto Sync

Bluetooth power restore behavior

Sync history

Details

What it does

It's a single-session Bluetooth RFCOMM file-sync server for Windows 11, meant to be one half of an Android↔Windows sync tool. On startup it:

Turns Bluetooth on if it was off (and restores the prior state on exit) via WinRT calls shelled out through PowerShell.

Opens an RFCOMM socket, binds it, and registers it in the Windows SDP database via raw ctypes calls into Ws2_32.dll (WSASetServiceW), so Android can discover the service by UUID.

Waits for one incoming connection, then runs a length-prefixed framed protocol (send_frame/receive_frame) with a simple text command layer: HELLO, LIST, GET, PUT, CONFLICT, PUT_CONFLICT, SYNC_DONE.

Authentication is a custom app-layer scheme: first-run pairing shows a 6-digit code, negotiates a 32-byte shared key over HMAC-SHA256 challenge/response, and stores the key DPAPI-encrypted at rest. Subsequent connections do a nonce/HMAC challenge instead of re-pairing.

File transfer uses a .btpart staging file, SHA-256 verification, and atomic os.replace into place; existing destination files are moved to a timestamped Backups/ copy before being overwritten, and there's a parallel Conflicts/ mechanism for divergent versions.

Path safety is done via (SYNC_FOLDER / relative).resolve() + relative_to(SYNC_FOLDER), which is actually the right pattern — it correctly rejects ../ traversal, absolute paths, and symlink escapes, since resolve() normalizes everything before the containment check.
binary-safe file transfers

