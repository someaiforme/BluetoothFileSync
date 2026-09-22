import socket
import struct
import hashlib
import hmac
import json
import base64
import ctypes
import secrets
import uuid
import re
import os
import shutil
import sys
import time
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROTOCOL_IDENTITY_FILE = Path(__file__).resolve().with_name("bluetoothfilesync_protocol.json")

def load_protocol_identity():
    try:
        data = json.loads(PROTOCOL_IDENTITY_FILE.read_text(encoding="utf-8"))
        service_name = str(data["service_name"]).strip()
        service_uuid = str(data["service_uuid"]).strip().lower()
        protocol_version = str(data["protocol_version"]).strip()
        channel = int(data["rfcomm_channel"])

        if service_name != "bluetoothfilesync":
            raise ValueError("invalid service name")
        uuid.UUID(service_uuid)
        if not re.fullmatch(r"[0-9]+", protocol_version):
            raise ValueError("invalid protocol version")
        if channel < 1 or channel > 30:
            raise ValueError("invalid RFCOMM channel")

        return service_name, service_uuid, protocol_version, channel
    except Exception as exc:
        raise RuntimeError(
            f"bluetoothfilesync protocol identity is missing or invalid: {exc}"
        ) from exc


SERVICE_NAME, SERVICE_UUID, PROTOCOL_VERSION, CHANNEL = load_protocol_identity()
AUTH_NONCE_BYTES = 32
MAX_FRAME_BYTES = 1 * 1024 * 1024
ALLOW_NEW_DEVICE = "--authorize-new-device" in sys.argv[1:]

SYNC_FOLDER = Path.home() / "SAVEDIR"
SYNC_FOLDER.mkdir(parents=True, exist_ok=True)

SYNC_HISTORY_DIR = SYNC_FOLDER / "SyncHistory"
AUTH_KEY_FILE = SYNC_HISTORY_DIR / "bluetoothfilesync_auth.dat"
SYNC_HISTORY_FILE = SYNC_HISTORY_DIR / "sync_history.log"
SYNC_HISTORY_BACKUP_FILE = SYNC_HISTORY_DIR / "sync_history.log.1"
MAX_HISTORY_BYTES = 256 * 1024
# Keep protocol/file progress prints off by default. They add console I/O
# during large batches without improving the sync result.
VERBOSE_PROTOCOL = False
HASH_CACHE_FILE = SYNC_HISTORY_DIR / "hash_cache.json"
HASH_CACHE_VERSION = 1

# bluetoothfilesync-owned namespaces. Client-supplied paths may never address these.
RESERVED_ROOT_DIRS = {"backups", "conflicts", "synchistory"}
BLUETOOTHFILESYNC_TEMP_PREFIX = ".bluetoothfilesync-"
BLUETOOTHFILESYNC_TEMP_SUFFIX = ".part"

current_session_id = "------------"
session_listed_hashes = {}
session_sync_listed = False
session_stats = {
    "android_to_windows": 0,
    "windows_to_android": 0,
    "conflicts": 0,
}
session_sync_started = False
session_transfer_started_at = None


# ============================================================
# BLUETOOTHFILESYNC SECURE RFCOMM SERVICE + APPLICATION AUTHENTICATION
# ============================================================

class GUID(ctypes.Structure):
    # Use explicit-width integer types so the layout is identical even when
    # this source is inspected/compiled on non-Windows systems.
    _pack_ = 1
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class SOCKADDR_BTH(ctypes.Structure):
    # Windows defines SOCKADDR_BTH as a packed 30-byte structure.
    # Match ws2bth.h exactly so getsockname()/WSASetServiceW see the
    # same layout as the native Windows Bluetooth APIs.
    _pack_ = 1
    _fields_ = [
        ("addressFamily", ctypes.c_uint16),
        ("btAddr", ctypes.c_ulonglong),
        ("serviceClassId", GUID),
        ("port", ctypes.c_uint32),
    ]


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [
        ("lpSockaddr", ctypes.POINTER(ctypes.c_ubyte)),
        ("iSockaddrLength", wintypes.INT),
    ]


class CSADDR_INFO(ctypes.Structure):
    _fields_ = [
        ("LocalAddr", SOCKET_ADDRESS),
        ("RemoteAddr", SOCKET_ADDRESS),
        ("iSocketType", wintypes.INT),
        ("iProtocol", wintypes.INT),
    ]


class WSAQUERYSETW(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("lpszServiceInstanceName", wintypes.LPWSTR),
        ("lpServiceClassId", ctypes.POINTER(GUID)),
        ("lpVersion", ctypes.c_void_p),
        ("lpszComment", wintypes.LPWSTR),
        ("dwNameSpace", wintypes.DWORD),
        ("lpNSProviderId", ctypes.POINTER(GUID)),
        ("lpszContext", wintypes.LPWSTR),
        ("dwNumberOfProtocols", wintypes.DWORD),
        ("lpafpProtocols", ctypes.c_void_p),
        ("lpszQueryString", wintypes.LPWSTR),
        ("dwNumberOfCsAddrs", wintypes.DWORD),
        ("lpcsaBuffer", ctypes.POINTER(CSADDR_INFO)),
        ("dwOutputFlags", wintypes.DWORD),
        ("lpBlob", ctypes.c_void_p),
    ]


def guid_from_uuid(text):
    value = uuid.UUID(text)
    fields = value.fields
    g = GUID()
    g.Data1 = fields[0]
    g.Data2 = fields[1]
    g.Data3 = fields[2]
    for index, byte in enumerate(value.bytes[8:]):
        g.Data4[index] = byte
    return g


def register_bluetooth_service(server):
    """Register the already-bound RFCOMM socket in Windows Bluetooth SDP."""
    if not hasattr(ctypes, "windll"):
        raise RuntimeError(
            "Windows Bluetooth service registration is only supported on Windows."
        )

    ws2_32 = ctypes.WinDLL("Ws2_32.dll", use_last_error=True)
    ws2_32.getsockname.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(SOCKADDR_BTH),
        ctypes.POINTER(wintypes.INT),
    ]
    ws2_32.getsockname.restype = ctypes.c_int

    ws2_32.WSASetServiceW.argtypes = [
        ctypes.POINTER(WSAQUERYSETW),
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    ws2_32.WSASetServiceW.restype = ctypes.c_int
    ws2_32.WSAGetLastError.argtypes = []
    ws2_32.WSAGetLastError.restype = ctypes.c_int

    # Windows requires the exact local SOCKADDR_BTH for the bound server
    # socket when constructing the SDP ProtocolDescriptorList.
    local = SOCKADDR_BTH()
    addr_len = wintypes.INT(ctypes.sizeof(SOCKADDR_BTH))
    if ws2_32.getsockname(
        ctypes.c_void_p(server.fileno()),
        ctypes.byref(local),
        ctypes.byref(addr_len),
    ) != 0:
        error = ws2_32.WSAGetLastError()
        raise OSError(
            error,
            f"getsockname failed with WinSock error {error}",
        )

    if addr_len.value < ctypes.sizeof(SOCKADDR_BTH):
        raise RuntimeError(
            f"Windows returned an incomplete SOCKADDR_BTH ({addr_len.value} bytes)."
        )

    class_info = guid_from_uuid(SERVICE_UUID)

    # For an SDP registration using WSAQUERYSET/CSADDR_INFO, Windows uses the
    # local address supplied here to construct the RFCOMM ProtocolDescriptorList.
    # The Microsoft sample supplies the bound local address for both endpoints.
    csaddr = CSADDR_INFO()
    csaddr.LocalAddr.lpSockaddr = ctypes.cast(
        ctypes.pointer(local),
        ctypes.POINTER(ctypes.c_ubyte),
    )
    csaddr.LocalAddr.iSockaddrLength = ctypes.sizeof(SOCKADDR_BTH)
    csaddr.RemoteAddr.lpSockaddr = ctypes.cast(
        ctypes.pointer(local),
        ctypes.POINTER(ctypes.c_ubyte),
    )
    csaddr.RemoteAddr.iSockaddrLength = ctypes.sizeof(SOCKADDR_BTH)
    csaddr.iSocketType = socket.SOCK_STREAM
    csaddr.iProtocol = socket.BTPROTO_RFCOMM

    service_name = ctypes.create_unicode_buffer("bluetoothfilesync")
    comment = ctypes.create_unicode_buffer(
        "Bidirectional Android Windows File Sync"
    )

    query = WSAQUERYSETW()
    query.dwSize = ctypes.sizeof(WSAQUERYSETW)
    query.lpszServiceInstanceName = ctypes.cast(
        service_name,
        wintypes.LPWSTR,
    )
    query.lpServiceClassId = ctypes.pointer(class_info)
    query.lpszComment = ctypes.cast(comment, wintypes.LPWSTR)
    query.dwNameSpace = 16  # NS_BTH
    query.dwNumberOfCsAddrs = 1
    query.lpcsaBuffer = ctypes.pointer(csaddr)

    result = ws2_32.WSASetServiceW(
        ctypes.byref(query),
        0,  # RNRSERVICE_REGISTER
        0,  # dwControlFlags must be zero
    )
    if result != 0:
        error = ws2_32.WSAGetLastError()
        raise OSError(
            error,
            f"WSASetServiceW failed with WinSock error {error}",
        )

    print(f"Bluetooth service UUID: {SERVICE_UUID}")
    print(
        "Bluetooth service advertised through Windows SDP "
        f"on RFCOMM channel {local.port}."
    )

    def unregister():
        delete_result = ws2_32.WSASetServiceW(
            ctypes.byref(query),
            2,  # RNRSERVICE_DELETE
            0,
        )
        if delete_result != 0:
            error = ws2_32.WSAGetLastError()
            print(
                f"Warning: could not remove Bluetooth SDP service ({error})."
            )

    return unregister


def _dpapi_crypt(data, protect):
    crypt32 = ctypes.WinDLL("Crypt32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    source = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source_blob = DATA_BLOB(
        len(data),
        ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)),
    )
    result_blob = DATA_BLOB()

    function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = function(
        ctypes.byref(source_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(result_blob),
    )
    if not ok:
        error = ctypes.get_last_error()
        action = "protect" if protect else "unprotect"
        raise OSError(error, f"DPAPI {action} failed with error {error}")

    try:
        return ctypes.string_at(result_blob.pbData, result_blob.cbData)
    finally:
        kernel32.LocalFree(result_blob.pbData)


def load_auth_key():
    if not AUTH_KEY_FILE.exists():
        return None
    try:
        raw = AUTH_KEY_FILE.read_bytes()
        key = _dpapi_crypt(raw, protect=False)
        if len(key) != 32:
            raise ValueError("stored key is not 32 bytes")
        return key
    except Exception as exc:
        raise RuntimeError(f"Authentication key file is invalid: {exc}") from exc


def save_auth_key(key):
    if len(key) != 32:
        raise ValueError("Authentication key must be 32 bytes.")
    AUTH_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    protected = _dpapi_crypt(key, protect=True)
    temporary = AUTH_KEY_FILE.with_suffix(".tmp")
    temporary.write_bytes(protected)
    os.replace(temporary, AUTH_KEY_FILE)


def hmac_sha256(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()


def send_auth_response(client, key, nonce, tag=b":windows"):
    proof = hmac_sha256(key, nonce + tag).hex()
    send_frame(client, f"AUTH_OK {proof}")


def constant_time_equal(a, b):
    return hmac.compare_digest(a, b)

def new_bluetoothfilesync_temp_path(directory):
    return directory / f"{BLUETOOTHFILESYNC_TEMP_PREFIX}{uuid.uuid4().hex}{BLUETOOTHFILESYNC_TEMP_SUFFIX}"


def is_bluetoothfilesync_temp_name(name):
    if not (name.startswith(BLUETOOTHFILESYNC_TEMP_PREFIX) and name.endswith(BLUETOOTHFILESYNC_TEMP_SUFFIX)):
        return False
    token = name[len(BLUETOOTHFILESYNC_TEMP_PREFIX):-len(BLUETOOTHFILESYNC_TEMP_SUFFIX)]
    return len(token) == 32 and all(c in "0123456789abcdef" for c in token)


def cleanup_stale_bluetoothfilesync_temp_files():
    """Remove abandoned bluetoothfilesync temporary files only."""
    removed = 0
    for path in SYNC_FOLDER.rglob(f"{BLUETOOTHFILESYNC_TEMP_PREFIX}*{BLUETOOTHFILESYNC_TEMP_SUFFIX}"):
        if not path.is_file() or not is_bluetoothfilesync_temp_name(path.name):
            continue
        try:
            path.unlink(missing_ok=True)
            removed += 1
        except OSError:
            pass
    if removed:
        print(f"Cleaned up {removed} abandoned bluetoothfilesync transfer file(s).")

print("Starting Bluetooth Sync server...")
print()
print("Sync folder:")
print(SYNC_FOLDER)
print()

# ============================================================
# WINDOWS 11 BLUETOOTH POWER
# ============================================================


def _run_powershell(script):
    import subprocess

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(
            f"PowerShell Bluetooth operation failed (code {result.returncode}). "
            + detail
        )

    return result.stdout.strip()


RADIO_COMMON = r'''Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() |
    Where-Object {
        $_.Name -eq 'AsTask' -and
        $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    } | Select-Object -First 1)
function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    return $netTask.Result
}
[Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
[Windows.Devices.Radios.RadioAccessStatus,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
[Windows.Devices.Radios.RadioState,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
$radios = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])
$bluetooth = $radios | Where-Object { $_.Kind -eq 'Bluetooth' } | Select-Object -First 1
if ($null -eq $bluetooth) { throw 'No Bluetooth radio was found.' }
'''


def bluetooth_status():
    script = RADIO_COMMON + r'''
if ($bluetooth.State -eq [Windows.Devices.Radios.RadioState]::On) {
    'ON'
} elseif ($bluetooth.State -eq [Windows.Devices.Radios.RadioState]::Off) {
    'OFF'
} else {
    throw ('Bluetooth radio is in state: ' + $bluetooth.State)
}
'''
    return _run_powershell(script).strip().upper()


def set_bluetooth(enabled):
    target = 'On' if enabled else 'Off'
    script = RADIO_COMMON + f'''
$access = Await ([Windows.Devices.Radios.Radio]::RequestAccessAsync()) ([Windows.Devices.Radios.RadioAccessStatus])
if ($access -ne [Windows.Devices.Radios.RadioAccessStatus]::Allowed) {{
    throw ('Bluetooth radio control access was not allowed: ' + $access)
}}
$result = Await ($bluetooth.SetStateAsync([Windows.Devices.Radios.RadioState]::{target})) ([Windows.Devices.Radios.RadioAccessStatus])
if ($result -ne [Windows.Devices.Radios.RadioAccessStatus]::Allowed) {{
    throw ('Bluetooth state change was not allowed: ' + $result)
}}
Start-Sleep -Milliseconds 700
$radios2 = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])
$bluetooth2 = $radios2 | Where-Object {{ $_.Kind -eq 'Bluetooth' }} | Select-Object -First 1
if ($null -eq $bluetooth2 -or $bluetooth2.State -ne [Windows.Devices.Radios.RadioState]::{target}) {{
    throw 'Bluetooth did not reach the requested state.'
}}
'''
    _run_powershell(script)


def prepare_bluetooth():
    was_on = bluetooth_status() == 'ON'

    if was_on:
        print('Bluetooth: ON (left unchanged)')
    else:
        print('Bluetooth: OFF — turning ON for this sync session...')
        set_bluetooth(True)
        print('Bluetooth: ON')

    return was_on


def restore_bluetooth(was_on):
    if was_on:
        print('Bluetooth: leaving ON (it was already ON)')
        return

    print('Bluetooth: turning OFF (it was OFF when the script started)...')
    set_bluetooth(False)
    print('Bluetooth: OFF')


def write_history(event, detail=""):
    try:
        SYNC_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().isoformat(timespec="milliseconds")
        line = f"{timestamp} | session={current_session_id} | {event}"
        if detail:
            safe_detail = str(detail).replace("\r", " ").replace("\n", " ").strip()[:500]
            line += f" | {safe_detail}"

        data = (line + "\n").encode("utf-8")
        existing_size = SYNC_HISTORY_FILE.stat().st_size if SYNC_HISTORY_FILE.exists() else 0

        # Rotate by size instead of reading and rewriting the full history
        # file after every event. One backup keeps total log storage bounded.
        if existing_size + len(data) > MAX_HISTORY_BYTES:
            if SYNC_HISTORY_BACKUP_FILE.exists():
                SYNC_HISTORY_BACKUP_FILE.unlink()
            if SYNC_HISTORY_FILE.exists():
                SYNC_HISTORY_FILE.replace(SYNC_HISTORY_BACKUP_FILE)

        with SYNC_HISTORY_FILE.open("ab") as file:
            file.write(data)
    except Exception as e:
        print("History log error:", repr(e))


bluetooth_was_on = None

# ============================================================
# FRAMED PROTOCOL
# ============================================================

def send_frame(client, data):

    if isinstance(data, str):
        data = data.encode("utf-8")

    header = struct.pack(
        ">I",
        len(data)
    )

    client.sendall(header)
    client.sendall(data)


def receive_exact(client, size):

    data = bytearray()

    while len(data) < size:

        chunk = client.recv(
            size - len(data)
        )

        if not chunk:
            raise ConnectionError(
                "Android disconnected."
            )

        data.extend(chunk)

    return bytes(data)


def receive_frame(client):

    header = receive_exact(
        client,
        4
    )

    size = struct.unpack(
        ">I",
        header
    )[0]

    if size > MAX_FRAME_BYTES:

        raise ValueError(
            f"Frame too large: {size}"
        )

    return receive_exact(
        client,
        size
    )


def receive_command(client):

    data = receive_frame(
        client
    )

    return data.decode(
        "utf-8",
        errors="replace"
    ).strip()


# ============================================================
# ENCRYPTED CHANNEL (post-authentication)
# ============================================================
#
# Everything up to and including the final AUTH_OK / PAIR confirmation
# frame is exchanged in the clear via send_frame/receive_command above,
# same as before. The moment authentication succeeds, both sides derive
# a pair of AES-256-GCM keys from the shared secret they already agreed
# on (the long-term auth key, or the freshly paired key) and switch to
# send_secure_frame/receive_secure_command for every command and every
# file byte for the rest of the session.
#
# Two independent keys are derived (one per direction) so the two ends
# never encrypt with the same key, which keeps nonce reuse impossible
# even though nonces are chosen at random rather than as a synchronized
# counter. Deriving from the per-session nonce (already exchanged during
# the handshake) means a fresh pair of keys is used every session, even
# though the long-term auth key itself is static across sessions.

def _hkdf_derive(key_material, salt, info):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(key_material)


class SecureChannel:

    NONCE_BYTES = 12
    TAG_BYTES = 16
    MAX_PLAINTEXT_BYTES = MAX_FRAME_BYTES - NONCE_BYTES - TAG_BYTES

    def __init__(self, auth_key, session_nonce, is_server):
        c2s_key = _hkdf_derive(auth_key, session_nonce, b"bluetoothfilesync c2s v" + PROTOCOL_VERSION.encode("ascii"))
        s2c_key = _hkdf_derive(auth_key, session_nonce, b"bluetoothfilesync s2c v" + PROTOCOL_VERSION.encode("ascii"))

        # Match Android exactly: both sides derive independent v2 keys and
        # authenticate direction + frame counter as additional data.
        if is_server:
            encrypt_key, self._encrypt_direction = s2c_key, "s2c"
            decrypt_key, self._decrypt_direction = c2s_key, "c2s"
        else:
            encrypt_key, self._encrypt_direction = c2s_key, "c2s"
            decrypt_key, self._decrypt_direction = s2c_key, "s2c"

        self._encryptor = AESGCM(encrypt_key)
        self._decryptor = AESGCM(decrypt_key)
        self._send_counter = 0
        self._receive_counter = 0

    @staticmethod
    def _nonce(counter):
        return b"\x00\x00\x00\x00" + struct.pack(">Q", counter)

    @staticmethod
    def _aad(direction, counter):
        return b"bluetoothfilesync-v" + PROTOCOL_VERSION.encode("ascii") + b"|" + direction.encode("ascii") + b"|" + struct.pack(">Q", counter)

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        if len(plaintext) > self.MAX_PLAINTEXT_BYTES:
            raise ValueError(
                f"Secure payload too large: {len(plaintext)} bytes."
            )
        counter = self._send_counter
        if counter >= 2**63 - 1:
            raise ValueError("Secure-channel frame counter exhausted.")
        nonce = self._nonce(counter)
        aad = self._aad(self._encrypt_direction, counter)
        ciphertext = self._encryptor.encrypt(nonce, plaintext, aad)
        self._send_counter += 1
        return nonce + ciphertext

    def decrypt(self, framed):
        if len(framed) < self.NONCE_BYTES + self.TAG_BYTES:
            raise ValueError("Encrypted frame too short.")
        if len(framed) > MAX_FRAME_BYTES:
            raise ValueError("Encrypted frame too large.")

        nonce = framed[: self.NONCE_BYTES]
        if nonce[:4] != b"\x00\x00\x00\x00":
            raise ValueError("Invalid secure-channel nonce.")

        counter = struct.unpack(">Q", nonce[4:])[0]
        if counter != self._receive_counter:
            raise ValueError(
                "Unexpected secure-channel frame counter: "
                f"{counter}; expected {self._receive_counter}."
            )

        ciphertext = framed[self.NONCE_BYTES :]
        aad = self._aad(self._decrypt_direction, counter)
        plaintext = self._decryptor.decrypt(nonce, ciphertext, aad)
        self._receive_counter += 1
        return plaintext


def send_secure_frame(client, secure, data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    send_frame(client, secure.encrypt(data))


def receive_secure_frame(client, secure):
    return secure.decrypt(receive_frame(client))


def receive_secure_command(client, secure):
    data = receive_secure_frame(client, secure)
    return data.decode("utf-8", errors="replace").strip()


# ============================================================
# SAFE PATH
# ============================================================

def safe_path(relative_path):

    requested = (
        SYNC_FOLDER / relative_path
    ).resolve()

    folder = (
        SYNC_FOLDER.resolve()
    )

    try:

        requested.relative_to(
            folder
        )

    except ValueError:

        return None

    return requested


def safe_sync_path(relative_path):
    """Resolve a client-supplied path in the normal sync namespace."""
    if not isinstance(relative_path, str):
        return None
    relative_path = relative_path.strip()
    if not relative_path:
        return None

    path = safe_path(relative_path)
    if path is None:
        return None

    try:
        relative = path.relative_to(SYNC_FOLDER.resolve())
    except ValueError:
        return None

    if relative.parts and relative.parts[0].lower() in RESERVED_ROOT_DIRS:
        return None
    if any(is_bluetoothfilesync_temp_name(part) for part in relative.parts):
        return None

    return path


# ============================================================
# FILE HASH / BACKUP HELPERS
# ============================================================

def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def make_backup(path):
    """
    Move the current destination version into:
        SAVEDIR/Backups/<relative parent>/<name>-TIMESTAMP.ext

    Returns the backup path, or None if there was no existing file.
    The original is moved only after the transfer has already completed
    successfully, so a failed transfer cannot destroy the current file.
    """

    if not path.exists():
        return None

    if not path.is_file():
        raise Exception("Destination exists but is not a file.")

    try:
        relative = path.relative_to(SYNC_FOLDER)
    except ValueError:
        raise Exception("Cannot create backup outside sync folder.")

    backup_dir = SYNC_FOLDER / "Backups" / relative.parent
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")

    stem = path.stem
    suffix = path.suffix

    backup_name = f"{stem}-{timestamp}{suffix}"
    backup_path = backup_dir / backup_name

    # Extremely unlikely, but guarantee uniqueness.
    counter = 1

    while backup_path.exists():
        backup_name = f"{stem}-{timestamp}-{counter}{suffix}"
        backup_path = backup_dir / backup_name
        counter += 1

    path.replace(backup_path)

    return backup_path


# ============================================================
# DIRECTORY LIST
# ============================================================

def load_hash_cache():
    try:
        data = json.loads(HASH_CACHE_FILE.read_text(encoding="utf-8"))
        if data.get("version") != HASH_CACHE_VERSION:
            return {}
        cache = data.get("files", {})
        return cache if isinstance(cache, dict) else {}
    except Exception:
        return {}


def save_hash_cache(cache):
    try:
        SYNC_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        temporary = new_bluetoothfilesync_temp_path(HASH_CACHE_FILE.parent)
        temporary.write_text(
            json.dumps(
                {"version": HASH_CACHE_VERSION, "files": cache},
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        temporary.replace(HASH_CACHE_FILE)
    except Exception as e:
        print("Hash cache write error:", repr(e))


def cached_sha256(path, relative_name, cache):
    stat = path.stat()
    cached = cache.get(relative_name)
    if (
        isinstance(cached, dict)
        and cached.get("size") == stat.st_size
        and cached.get("mtime_ns") == stat.st_mtime_ns
        and isinstance(cached.get("hash"), str)
        and len(cached["hash"]) == 64
    ):
        return cached["hash"]

    file_hash = sha256_file(path)
    cache[relative_name] = {
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "hash": file_hash,
    }
    return file_hash


def build_file_list():
    files = []
    cache = load_hash_cache()

    for path in SYNC_FOLDER.rglob("*"):
        if not path.is_file():
            continue

        # Do not advertise bluetoothfilesync temporary files or backup/conflict
        # copies as normal sync files.
        if is_bluetoothfilesync_temp_name(path.name):
            continue

        try:
            relative = path.relative_to(SYNC_FOLDER)

            # Backups and conflicts are intentionally excluded from the
            # normal synchronization set.
            if relative.parts and relative.parts[0].lower() in {
                "backups",
                "conflicts",
                "synchistory"
            }:
                continue

            stat = path.stat()

            relative_name = str(
                relative
            ).replace(
                "\\",
                "/"
            )

            file_hash = cached_sha256(
                path,
                relative_name,
                cache,
            )

            files.append(
                (
                    relative_name,
                    stat.st_size,
                    stat.st_mtime_ns,
                    file_hash
                )
            )

        except (OSError, ValueError):
            continue

    files.sort(
        key=lambda item:
        item[0].lower()
    )

    # Drop cache entries for files that no longer exist in the normal sync set.
    current_paths = {item[0] for item in files}
    cache = {key: value for key, value in cache.items() if key in current_paths}
    save_hash_cache(cache)

    return files


def send_file_list(client, secure):
    global session_listed_hashes, session_sync_listed

    files = build_file_list()
    session_listed_hashes = {item[0]: item[3] for item in files}
    session_sync_listed = True

    if not files:

        send_secure_frame(
            client,
            secure,
            "NO_FILES"
        )

        print(
            "Sent: NO_FILES"
        )

        return

    lines = []

    for path, size, modified, file_hash in files:

        lines.append(
            f"{path}|{size}|{modified}|{file_hash}"
        )

    response = "\n".join(
        lines
    )

    send_secure_frame(
        client,
        secure,
        response
    )

    print(
        f"Sent file list: {len(files)} file(s)"
    )
    print("Waiting for Android sync command...")


# ============================================================
# GET
# ============================================================

def send_file(
    client,
    secure,
    filename
):

    path = safe_sync_path(
        filename
    )

    if path is None:

        send_secure_frame(
            client,
            secure,
            "ERROR: invalid filename"
        )

        return False

    if not path.exists():

        send_secure_frame(
            client,
            secure,
            "ERROR: file not found"
        )

        return False

    if not path.is_file():

        send_secure_frame(
            client,
            secure,
            "ERROR: not a file"
        )

        return False

    try:

        size = path.stat().st_size

        if VERBOSE_PROTOCOL:
            print()
            print(
                f"Sending file: {filename}"
            )
            print(
                f"Size: {size} bytes"
            )

        send_secure_frame(
            client,
            secure,
            f"FILE {size}"
        )

        with path.open("rb") as file:

            while True:

                chunk = file.read(
                    SecureChannel.MAX_PLAINTEXT_BYTES
                )

                if not chunk:
                    break

                send_secure_frame(
                    client,
                    secure,
                    chunk
                )

        send_secure_frame(
            client,
            secure,
            "EOF"
        )

        if VERBOSE_PROTOCOL:
            print(
                "File sent successfully."
            )

        return size

    except Exception as e:

        print(
            "GET error:",
            repr(e)
        )

        try:

            send_secure_frame(
                client,
                secure,
                "ERROR: " + str(e)
            )

        except Exception:
            pass

        return False


# ============================================================
# PUT
# ============================================================

def receive_file(
    client,
    secure,
    filename,
    size,
    expected_hash=None,
    expected_base_hash=None
):

    path = safe_sync_path(
        filename
    )

    if path is None:

        send_secure_frame(
            client,
            secure,
            "ERROR: invalid filename"
        )

        return False

    parent = path.parent

    parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temporary = new_bluetoothfilesync_temp_path(path.parent)

    if VERBOSE_PROTOCOL:
        print()
        print(
            f"Receiving file: {filename}"
        )
        print(
            f"Expected size: {size} bytes"
        )

    received = 0
    transfer_digest = hashlib.sha256()

    try:

        with temporary.open(
            "wb"
        ) as file:

            while received < size:

                frame = receive_secure_frame(client, secure)

                # Termination is purely byte-count driven (Android never
                # sends a trailing EOF frame for a regular PUT), so a
                # legitimate data chunk that happens to equal the bytes
                # "EOF" is never mistaken for a sentinel. The size bound
                # below is what actually guards against a malformed or
                # over-length transfer.
                if received + len(frame) > size:
                    raise Exception(
                        "Received more data than expected."
                    )

                file.write(
                    frame
                )
                transfer_digest.update(frame)

                received += len(
                    frame
                )

        if received != size:

            raise Exception(
                f"Size mismatch: {received} / {size}"
            )

        file_hash = transfer_digest.hexdigest()

        if expected_hash is not None and file_hash.lower() != expected_hash.lower():
            raise Exception(
                "Upload hash mismatch: Android file changed during transfer."
            )

        # Re-check the Windows destination against the exact LIST snapshot
        # used to build the Android upload plan. None means it was absent.
        current_hash = None
        if path.exists():
            if not path.is_file():
                raise Exception("Destination exists but is not a file.")
            current_hash = sha256_file(path)

        if expected_base_hash is None:
            if current_hash is not None:
                raise Exception(
                    "Windows destination changed after the sync plan was created."
                )
        elif current_hash is None or not current_hash.lower() == expected_base_hash.lower():
            raise Exception(
                "Windows destination changed after the sync plan was created."
            )

        backup_path = None

        # The transfer is complete and verified before the existing
        # destination is moved out of the way.
        if path.exists():
            backup_path = make_backup(path)

        try:
            temporary.replace(path)
        except Exception:
            # Best effort rollback if replacement failed after a backup.
            if (
                backup_path is not None
                and not path.exists()
                and backup_path.exists()
            ):
                backup_path.replace(path)

            raise

        send_secure_frame(
            client,
            secure,
            f"PUT_OK {file_hash}"
        )

        if VERBOSE_PROTOCOL:
            print(
                "File received successfully."
            )
            if backup_path is not None:
                print(
                    f"Backup created: {backup_path}"
                )

        return received

    except Exception as e:

        primary_error = e

        try:
            temporary.unlink(
                missing_ok=True
            )

        except Exception:
            pass

        # Preserve the original transfer failure. A client that detects its
        # own source-file change may close the socket immediately, so trying
        # to send the error response can itself raise ConnectionError. That
        # secondary disconnect must never hide the real reason the PUT failed.
        if (
            expected_hash is not None
            and "Upload hash mismatch" in str(primary_error)
        ):
            friendly = (
                "Android file changed during upload; the SHA-256 hash of the "
                "transmitted data did not match the hash announced at the "
                "start of the transfer."
            )
        elif isinstance(primary_error, ConnectionError):
            friendly = "Android disconnected before the upload completed."
        else:
            friendly = str(primary_error)

        print()
        print(f"PUT failed: {filename}")
        print(f"Reason: {friendly}")

        try:
            write_history(
                "PUT_FAILED",
                f"path={filename} reason={friendly}"
            )
        except Exception:
            pass

        try:
            send_secure_frame(
                client,
                secure,
                "ERROR: " + friendly
            )
        except Exception as send_error:
            # This is expected when Android has already closed the socket
            # after detecting a local file change. Report it separately and
            # tell the caller to end the dead session instead of producing a
            # second generic "Client error" later.
            if isinstance(send_error, OSError):
                print(
                    "Android disconnected before Windows could send the transfer "
                    f"error response: {send_error!r}"
                )
                try:
                    write_history(
                        "PEER_DISCONNECTED_AFTER_TRANSFER_ERROR",
                        f"path={filename}"
                    )
                except Exception:
                    pass
                return "PEER_DISCONNECTED"

            print(
                "Windows could not send the transfer error response: "
                f"{send_error!r}"
            )

        return False


# ============================================================
# WINDOWS-SIDE CONFLICT COPY
# ============================================================

def save_conflict_copy(filename):
    """Preserve a stable snapshot of the current Windows version."""
    path = safe_sync_path(filename)
    if path is None:
        return False, "ERROR: invalid filename"
    if not path.exists() or not path.is_file():
        return False, "ERROR: conflict source file not found"

    relative = path.relative_to(SYNC_FOLDER)
    parent = relative.parent
    stem = path.stem
    suffix = path.suffix
    conflict_dir = SYNC_FOLDER / "Conflicts" / parent / stem
    conflict_dir.mkdir(parents=True, exist_ok=True)

    for _ in range(3):
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")
        conflict_path = conflict_dir / f"{stem}-Windows-{timestamp}{suffix}"
        counter = 1
        while conflict_path.exists():
            conflict_path = conflict_dir / f"{stem}-Windows-{timestamp}-{counter}{suffix}"
            counter += 1

        try:
            source_hash_before = sha256_file(path)
            shutil.copy2(path, conflict_path)
            copied_hash = sha256_file(conflict_path)
            source_hash_after = sha256_file(path)

            if source_hash_before == copied_hash == source_hash_after:
                write_history("CONFLICT", str(relative).replace("\\", "/"))
                return True, str(conflict_path)

            conflict_path.unlink(missing_ok=True)
        except OSError as e:
            conflict_path.unlink(missing_ok=True)
            return False, f"ERROR: could not preserve Windows conflict copy: {e}"

    return False, "ERROR: Windows file changed repeatedly while preserving conflict copy"


def receive_conflict_file(
    client,
    secure,
    filename,
    size
):
    """Receive the Android version of a conflicted file into the
    Windows Conflicts folder. The live Windows file is never touched."""

    source_path = safe_sync_path(filename)
    if source_path is None:
        send_secure_frame(client, secure, "ERROR: invalid filename")
        return

    relative = source_path.relative_to(SYNC_FOLDER)
    name = relative.name
    parent = relative.parent
    stem = source_path.stem
    suffix = source_path.suffix

    conflict_dir = SYNC_FOLDER / "Conflicts" / parent / stem
    conflict_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")
    final_path = conflict_dir / f"{stem}-Android-{timestamp}{suffix}"
    counter = 1
    while final_path.exists():
        final_path = conflict_dir / f"{stem}-Android-{timestamp}-{counter}{suffix}"
        counter += 1

    temporary = new_bluetoothfilesync_temp_path(final_path.parent)
    received = 0
    transfer_digest = hashlib.sha256()

    try:
        with temporary.open("wb") as file:
            while received < size:
                frame = receive_secure_frame(client, secure)
                # Byte-count driven, same as receive_file: the payload
                # itself is never inspected for a sentinel value, so a
                # coincidental data chunk equal to "EOF" is just data.
                if received + len(frame) > size:
                    raise Exception("Received more data than expected.")
                file.write(frame)
                transfer_digest.update(frame)
                received += len(frame)

        if received != size:
            raise Exception(f"Size mismatch: {received} / {size}")

        # Android sends a separate EOF frame after the conflict payload.
        # Consume it here so it cannot be mistaken for the next command.
        eof = receive_secure_frame(client, secure)
        if eof != b"EOF":
            raise Exception("Expected EOF after conflict file.")

        file_hash = transfer_digest.hexdigest()
        temporary.replace(final_path)
        write_history("CONFLICT_ANDROID", str(relative).replace("\\", "/"))
        send_secure_frame(client, secure, f"CONFLICT_PUT_OK {file_hash}")
        if VERBOSE_PROTOCOL:
            print("Android conflict copy created:", final_path)

    except Exception as e:
        try:
            temporary.unlink(missing_ok=True)
        except Exception:
            pass
        try:
            send_secure_frame(client, secure, "ERROR: " + str(e))
        except Exception:
            pass


# ============================================================
# COMMAND ARGUMENT PARSING
# ============================================================

def _is_hex64(token):
    return len(token) == 64 and all(
        c in "0123456789abcdefABCDEF" for c in token
    )


def parse_filename_and_size(rest, allow_hash):
    """
    Parse "<filename> <size> [hash]" where filename may itself contain
    spaces. Since size is always plain digits and hash (when present) is
    always a 64-char hex string, those trailing tokens are identified by
    shape and peeled off the right; whatever remains is the filename.

    Returns (filename, size, expected_hash) or None on malformed input.
    expected_hash is always None when allow_hash is False.
    """
    tokens = rest.split(" ")
    if len(tokens) < 2:
        return None

    expected_hash = None
    if allow_hash and len(tokens) >= 3 and _is_hex64(tokens[-1]):
        expected_hash = tokens[-1].lower()
        size_token = tokens[-2]
        filename = " ".join(tokens[:-2])
    else:
        size_token = tokens[-1]
        filename = " ".join(tokens[:-1])

    if not filename:
        return None

    try:
        size = int(size_token)
    except ValueError:
        return None

    if size < 0:
        return None

    return filename, size, expected_hash


# ============================================================
# COMMAND HANDLER
# ============================================================

def extract_session_id(message):
    for token in message.split()[4:]:
        if token.startswith("SESSION="):
            candidate = token.split("=", 1)[1].strip().upper()
            if len(candidate) == 12 and all(ch in "0123456789ABCDEF" for ch in candidate):
                return candidate
    return uuid.uuid4().hex[:12].upper()


def reset_session_stats():
    global session_stats, session_sync_started, session_listed_hashes, session_sync_listed, session_transfer_started_at
    session_stats = {
        "android_to_windows": 0,
        "windows_to_android": 0,
        "conflicts": 0,
        "bytes_uploaded": 0,
        "bytes_downloaded": 0,
    }
    session_transfer_started_at = None
    session_sync_started = False
    session_listed_hashes = {}
    session_sync_listed = False


def authenticate_client(client, message):
    if not message.startswith("HELLO "):
        write_history("AUTH_FAILED", "handshake required")
        send_frame(client, "ERROR: authentication handshake required")
        return None

    parts = message.split()
    if len(parts) < 4:
        write_history("AUTH_FAILED", "invalid HELLO")
        send_frame(client, "ERROR: invalid HELLO")
        return None

    service_uuid = parts[1].lower()
    version = parts[2]
    key_state = parts[3]

    if (
        service_uuid != SERVICE_UUID.lower()
        or version != PROTOCOL_VERSION
        or key_state not in {"KEY=0", "KEY=1"}
    ):
        write_history("AUTH_FAILED", "unsupported bluetoothfilesync service")
        send_frame(client, "ERROR: unsupported bluetoothfilesync service")
        return None

    existing_key = load_auth_key()
    nonce = secrets.token_bytes(AUTH_NONCE_BYTES)

    if existing_key is not None and key_state == "KEY=1":
        send_frame(client, "AUTH_CHALLENGE " + nonce.hex())
        response = receive_command(client)
        if not response.startswith("AUTH_RESPONSE "):
            send_frame(client, "ERROR: authentication required")
            return None

        supplied = response.split(" ", 1)[1].strip().lower()
        expected = hmac_sha256(existing_key, nonce).hex()
        if not constant_time_equal(supplied, expected):
            send_frame(client, "ERROR: authentication failed")
            write_history("AUTH_FAILED")
            return None

        send_auth_response(client, existing_key, nonce)
        write_history("AUTH_OK")
        return SecureChannel(existing_key, nonce, is_server=True)

    if existing_key is not None and key_state == "KEY=0" and not ALLOW_NEW_DEVICE:
        write_history("NEW_DEVICE_REJECTED", "explicit authorization required")
        send_frame(client, "ERROR: NEW_DEVICE_NOT_AUTHORIZED")
        return None

    if existing_key is not None and key_state == "KEY=0" and ALLOW_NEW_DEVICE:
        write_history("NEW_DEVICE_AUTHORIZATION", "replacement pairing allowed for this server run")

    # No Android key, or explicit one-time replacement pairing authorized.
    pairing_code = f"{secrets.randbelow(1_000_000):06d}"
    print()
    print("========================================")
    print("bluetoothfilesync pairing required")
    print(f"Pairing code: {pairing_code}")
    print("Enter this code in the Android app.")
    print("========================================")
    print()

    send_frame(client, "PAIR_REQUIRED " + nonce.hex())
    response = receive_command(client)
    if not response.startswith("PAIR_CODE "):
        write_history("PAIR_FAILED", "cancelled")
        send_frame(client, "ERROR: pairing cancelled")
        return None

    supplied = response.split(" ", 1)[1].strip()
    if not constant_time_equal(supplied.encode("ascii", errors="ignore"), pairing_code.encode("ascii")):
        send_frame(client, "ERROR: invalid pairing code")
        write_history("PAIR_FAILED")
        return None

    new_key = secrets.token_bytes(32)
    send_frame(client, "PAIR_KEY " + base64.b64encode(new_key).decode("ascii"))

    confirmation = receive_command(client)
    expected_confirmation = hmac_sha256(
        new_key,
        nonce + b":pair-confirm",
    ).hex()
    if not confirmation.startswith("PAIR_CONFIRM "):
        write_history("PAIR_FAILED", "confirmation missing")
        send_frame(client, "ERROR: pairing confirmation missing")
        return None

    supplied_confirmation = confirmation.split(" ", 1)[1].strip().lower()
    if not constant_time_equal(supplied_confirmation, expected_confirmation):
        write_history("PAIR_FAILED", "confirmation mismatch")
        send_frame(client, "ERROR: pairing confirmation failed")
        return None

    save_auth_key(new_key)
    send_auth_response(client, new_key, nonce)
    write_history("PAIRED")
    return SecureChannel(new_key, nonce, is_server=True)


def handle_file_command(
    client,
    secure,
    message
):
    global session_sync_started, session_stats, session_transfer_started_at

    if VERBOSE_PROTOCOL:
        print(
            "Received:",
            repr(message)
        )

    # Command-level diagnostics only. File data frames are intentionally not
    # logged, so transfer throughput is unaffected.
    if message != "HELLO":
        if len(message) <= 180:
            print(f"Android command: {message}")
        else:
            print(f"Android command: {message[:177]}...")

    if message == "HELLO":

        send_secure_frame(
            client,
            secure,
            "HELLO FROM WINDOWS"
        )

    elif message == "LIST":

        print("Building Windows file list...")
        send_file_list(
            client,
            secure
        )

    elif message.startswith(
        "GET "
    ):

        if not session_sync_started:
            session_sync_started = True
            write_history("SYNC_STARTED")

        filename = (
            message[4:].strip()
        )

        if session_transfer_started_at is None:
            session_transfer_started_at = time.monotonic()

        sent_size = send_file(
            client,
            secure,
            filename
        )
        if sent_size is not False:
            session_stats["windows_to_android"] += 1
            session_stats["bytes_downloaded"] += sent_size

    elif message.startswith("CONFLICT "):

        filename = message[9:].strip()
        ok, detail = save_conflict_copy(filename)
        if ok:
            if not session_sync_started:
                session_sync_started = True
                write_history("SYNC_STARTED")
            session_stats["conflicts"] += 1
            send_secure_frame(
                client,
                secure,
                "CONFLICT_OK"
            )
            if VERBOSE_PROTOCOL:
                print(
                    "Windows conflict copy created:",
                    detail
                )
        else:
            send_secure_frame(
                client,
                secure,
                detail
            )

    elif message.startswith("PUT_CONFLICT "):

        rest = message[len("PUT_CONFLICT "):]
        parsed = parse_filename_and_size(rest, allow_hash=False)
        if parsed is None:
            send_secure_frame(client, secure, "ERROR: invalid PUT_CONFLICT command")
            return

        filename, size, _ = parsed

        send_secure_frame(client, secure, "READY")
        receive_conflict_file(client, secure, filename, size)

    elif message == "SYNC_DONE":

        send_secure_frame(
            client,
            secure,
            "SYNC_DONE_OK"
        )

        transfer_bytes = (
            session_stats["bytes_uploaded"] +
            session_stats["bytes_downloaded"]
        )
        transfer_elapsed = (
            time.monotonic() - session_transfer_started_at
            if session_transfer_started_at is not None
            else 0.0
        )
        transfer_rate = (
            transfer_bytes / (1024.0 * 1024.0) / max(transfer_elapsed, 0.001)
            if transfer_bytes > 0
            else 0.0
        )

        if transfer_bytes > 0:
            print(
                "Transfer: " +
                f"{transfer_bytes / (1024.0 * 1024.0):.2f} MiB " +
                f"in {transfer_elapsed:.2f} s ({transfer_rate:.2f} MiB/s)"
            )
        else:
            print("Transfer: no regular file data transferred.")

        write_history(
            "SYNC_DONE",
            "android_to_windows=" + str(session_stats["android_to_windows"]) +
            " windows_to_android=" + str(session_stats["windows_to_android"]) +
            " conflicts=" + str(session_stats["conflicts"]) +
            " bytes_uploaded=" + str(session_stats["bytes_uploaded"]) +
            " bytes_downloaded=" + str(session_stats["bytes_downloaded"]) +
            " transfer_elapsed_ms=" + str(int(transfer_elapsed * 1000)) +
            " transfer_rate_mib_s=" + f"{transfer_rate:.2f}"
        )

        return "STOP"

    elif message.startswith(
        "PUT "
    ):

        if not session_sync_started:
            session_sync_started = True
            write_history("SYNC_STARTED")

        rest = message[4:]
        parsed = parse_filename_and_size(rest, allow_hash=True)

        if parsed is None:
            send_secure_frame(client, secure, "ERROR: invalid PUT command")
            return

        filename, size, expected_hash = parsed

        if not session_sync_listed:
            send_secure_frame(client, secure, "ERROR: LIST required before PUT")
            return

        expected_base_hash = session_listed_hashes.get(filename)

        send_secure_frame(
            client,
            secure,
            "READY"
        )

        if session_transfer_started_at is None:
            session_transfer_started_at = time.monotonic()

        receive_result = receive_file(
            client,
            secure,
            filename,
            size,
            expected_hash,
            expected_base_hash
        )

        if receive_result is not False and receive_result != "PEER_DISCONNECTED":
            session_stats["android_to_windows"] += 1
            session_stats["bytes_uploaded"] += receive_result
        elif receive_result == "PEER_DISCONNECTED":
            return "STOP"

    else:

        send_secure_frame(
            client,
            secure,
            "ERROR: unknown command"
        )


# ============================================================
# SERVER LOOP
# ============================================================

server = None
unregister_bluetooth_service = None

try:

    cleanup_stale_bluetoothfilesync_temp_files()
    bluetooth_was_on = prepare_bluetooth()

    server = socket.socket(
        socket.AF_BLUETOOTH,
        socket.SOCK_STREAM,
        socket.BTPROTO_RFCOMM
    )

    server.bind(
        (socket.BDADDR_ANY, CHANNEL)
    )

    server.listen(1)

    unregister_bluetooth_service = register_bluetooth_service(server)

    print("--------------------------------")
    print("Bluetooth Sync server started")
    print(f"RFCOMM channel: {CHANNEL}")
    print(f"Service UUID: {SERVICE_UUID}")
    print(f"Protocol version: {PROTOCOL_VERSION}")
    if ALLOW_NEW_DEVICE:
        print("NEW DEVICE AUTHORIZATION MODE: one replacement pairing permitted for this server run.")
    print("Waiting for Android...")
    print("--------------------------------")

    client = None

    try:

        client, address = server.accept()

        message = receive_command(client)
        current_session_id = extract_session_id(message)
        reset_session_stats()

        print()
        print("CONNECTED!")
        print("Android:", address)
        print()
        write_history("SESSION_CONNECTED", str(address))

        secure = authenticate_client(client, message)

        if secure is not None:
            while True:
                message = receive_secure_command(client, secure)
                action = handle_file_command(client, secure, message)
                if action == "STOP":
                    break

    except Exception as e:

        write_history("SESSION_FAILED", repr(e))
        print(
            "Client error:",
            repr(e)
        )

    finally:

        try:
            if client is not None:
                client.close()
        except Exception:
            pass

        print()
        write_history("SESSION_ENDED")
        print("Sync session ended.")

except KeyboardInterrupt:

    print()
    print("Server interrupted.")

except Exception as e:

    print()
    print(
        "Server error:",
        repr(e)
    )

finally:

    if unregister_bluetooth_service is not None:
        try:
            unregister_bluetooth_service()
        except Exception as e:
            print("Bluetooth service cleanup error:", repr(e))

    try:
        if server is not None:
            server.close()
    except Exception:
        pass

    if bluetooth_was_on is not None:
        try:
            restore_bluetooth(bluetooth_was_on)
        except Exception as e:
            print(
                "Bluetooth restore error:",
                repr(e)
            )

    print("Server stopped.")
