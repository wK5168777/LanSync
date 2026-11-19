# -*- coding: utf-8 -*-
"""
LanSync · 局域网协同通讯台
Flask + Flask-SocketIO 局域网通讯应用
"""
import os
import io
import sys
import json
import time
import uuid
import base64
import socket
import ssl
import threading
import urllib.request
import urllib.parse
import traceback
import hashlib
import subprocess
import ctypes
import shutil
from collections import deque
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory, send_file
from flask_socketio import SocketIO, emit, join_room, ConnectionRefusedError
from werkzeug.exceptions import HTTPException

# ✅ 关键：显式 import 异步驱动，PyInstaller 才会把这些动态加载的模块打进去
#    否则打包后 engineio 找不到 engineio.async_drivers.threading
#    → ValueError: Invalid async_mode specified
import engineio.async_drivers.threading  # noqa: F401

# ====== 视频/Apple 格式 MIME 补全 ======
# Windows 的 mimetypes 未必认识 .mov/.hevc 等，补上后下载/内联预览的类型才正确
import mimetypes
for _mime_ext, _mime_type in (
    (".mp4", "video/mp4"), (".mov", "video/quicktime"), (".m4v", "video/x-m4v"),
    (".hevc", "video/hevc"), (".h265", "video/hevc"), (".mkv", "video/x-matroska"),
    (".avi", "video/x-msvideo"), (".wmv", "video/x-ms-wmv"), (".flv", "video/x-flv"),
    (".3gp", "video/3gpp"), (".mts", "video/mp2t"), (".m2ts", "video/mp2t"),
    (".ts", "video/mp2t"), (".mpg", "video/mpeg"), (".mpeg", "video/mpeg"),
):
    mimetypes.add_type(_mime_type, _mime_ext)


# ====== 控制台编码兜底 ======
# windowed 打包版可能没有控制台（stdout 为 None），GBK 终端下打印中文/emoji 会抛
# UnicodeEncodeError，导致启动即被"Unhandled exception"打断。这里统一兜底。
class _NullStream:
    def write(self, s):
        return len(s)

    def flush(self):
        pass

    def isatty(self):
        return False


for _stream_name in ("stdout", "stderr"):
    _st = getattr(sys, _stream_name, None)
    if _st is None:
        setattr(sys, _stream_name, _NullStream())
    else:
        try:
            _st.reconfigure(errors="replace")
        except Exception:
            pass

# ====== 基础路径（兼容 PyInstaller 打包）======
def _base_dir():
    """PyInstaller 打包后 sys.frozen=True，资源在 sys._MEIPASS"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)  # exe 所在目录（uploads 写这里）
    return os.path.dirname(os.path.abspath(__file__))

def _resource_dir():
    """模板/静态文件目录（PyInstaller 解压到 _MEIPASS）"""
    if getattr(sys, "frozen", False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = _base_dir()
RES_DIR = _resource_dir()
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ============================================================# ============================================================
#  自动更新：版本号（每次重启 / 页面改动都会变）
# ============================================================
def _calc_app_version():
    import hashlib
    parts = [uuid.uuid4().hex[:10]]            # 每次启动唯一（保证客户端能感知更新）
    for f in ("templates/index.html", "app.py"):
        p = os.path.join(RES_DIR, f)
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "rb") as fh:
                parts.append(hashlib.md5(fh.read()).hexdigest()[:8])
        except Exception:
            pass
    return "-".join(parts)


APP_VERSION = _calc_app_version()
print(f"[Version] 本次页面版本: {APP_VERSION}")


# ============================================================
#  离线语音：自签证书（iOS 装一次后，断外网也能录音）
# ============================================================
HTTP_PORT = 5050
HTTPS_PORT = int(os.environ.get("LC_HTTPS_PORT", "5443"))
CERT_DIR = os.path.join(BASE_DIR, "certs")
CA_CERT = os.path.join(CERT_DIR, "ca.crt")
CA_KEY = os.path.join(CERT_DIR, "ca.key")
SRV_CERT = os.path.join(CERT_DIR, "server.crt")
SRV_KEY = os.path.join(CERT_DIR, "server.key")


def _lan_ips():
    ips = {"127.0.0.1"}
    try:
        ips.add(HOST_IP)
    except Exception:
        pass
    try:
        import socket as _s
        for info in _s.getaddrinfo(_s.gethostname(), None, _s.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    return sorted(ips)


def _diag(msg):
    """启动阶段诊断日志（打包后无控制台时用）"""
    try:
        with open(os.path.join(BASE_DIR, "LanSync-start.log"), "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    except Exception:
        pass

def _port_free(port):
    """端口是否可用：用连接探测（Windows 下 SO_REUSEADDR 会假阳性）"""
    import socket as _s
    try:
        c = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        c.settimeout(0.6)
        if c.connect_ex(("127.0.0.1", port)) == 0:
            c.close()
            return False       # 能连上 → 已被占用
        c.close()
        return True
    except Exception:
        return True


def _cert_has_ip(ip):
    """检查现有服务器证书是否包含指定 IP"""
    try:
        from cryptography import x509
        with open(SRV_CERT, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ips = [str(v.value) for v in san if isinstance(v, x509.IPAddress)]
        return ip in ips
    except Exception as e:
        print(f"[Cert] 检查失败: {e}")
        return False

def ensure_certs(force=False):
    """证书策略：
       1) exe 目录/certs 已有 → 直接用
       2) 没有 → 从内置资源(_MEIPASS)/certs 复制过来
       3) 都没有 → 尝试现场生成（开发环境有 cryptography 时）
    """
    import shutil
    _diag("ensure_certs 开始")
    try:
        os.makedirs(CERT_DIR, exist_ok=True)
        # IP 变了（换网络/路由器重启）→ 自动重签，避免 https 不匹配
        if all(os.path.isfile(p) for p in (CA_CERT, CA_KEY, SRV_CERT, SRV_KEY)):
            try:
                if not _cert_has_ip(HOST_IP):
                    _diag(f"IP 已变化（{HOST_IP}），尝试重签证书")
                    force = True
            except Exception:
                pass
        need = [CA_CERT, CA_KEY, SRV_CERT, SRV_KEY]
        if (not force) and all(os.path.isfile(p) for p in need):
            _diag("使用已存在的证书")
            return True

        # 从内置资源复制（打包后 certs 在 _MEIPASS/certs）
        bundled = os.path.join(RES_DIR, "certs")
        if os.path.isdir(bundled):
            for name in ("ca.crt", "ca.key", "server.crt", "server.key", "ca.der"):
                src = os.path.join(bundled, name)
                dst = os.path.join(CERT_DIR, name)
                if os.path.isfile(src) and not os.path.isfile(dst):
                    shutil.copyfile(src, dst)
            if all(os.path.isfile(p) for p in need):
                if (not force) and _cert_has_ip(HOST_IP):
                    _diag("已从内置资源复制证书（IP 匹配）")
                    print(f"[Cert] ✅ 使用内置证书：{CERT_DIR}")
                    return True
                # 强制重签 或 IP 不匹配 → 继续往下走
                _diag(f"需要重签证书（force={force}, 当前 IP={HOST_IP}）")
                force = True

        # 兜底：现场生成（需要 cryptography）
        from datetime import datetime, timedelta, timezone
        from ipaddress import ip_address
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        # ★ 优先复用已有 CA：IP 变化时只重签服务器证书，手机装的 CA 依然有效
        ca_key = None
        ca_cert = None
        ca_name = None
        reuse_ca = False
        try:
            if os.path.isfile(CA_KEY) and os.path.isfile(CA_CERT):
                with open(CA_KEY, "rb") as f:
                    ca_key = serialization.load_pem_private_key(f.read(), password=None)
                with open(CA_CERT, "rb") as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read())
                ca_name = ca_cert.subject
                reuse_ca = True
                _diag("复用已有 CA 签发新的服务器证书（手机无需重装证书）")
        except Exception as e:
            _diag(f"已有 CA 加载失败，将重新生成: {e}")
            ca_key = None

        if ca_key is None:
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LanSync Local CA")])
        now = datetime.now(timezone.utc)
        if ca_cert is None:
            ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                       .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(days=1))
                       .not_valid_after(now + timedelta(days=3650))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                       .sign(ca_key, hashes.SHA256()))

        srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        srv_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST_IP)])
        sans = [x509.DNSName("localhost"), x509.DNSName("lansync.local")]
        for ip in _lan_ips():
            try:
                sans.append(x509.IPAddress(ip_address(ip)))
            except Exception:
                pass
        srv_cert = (x509.CertificateBuilder().subject_name(srv_name).issuer_name(ca_name)
                    .public_key(srv_key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=1))
                    .not_valid_after(now + timedelta(days=3650))
                    .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .sign(ca_key, hashes.SHA256()))

        if not reuse_ca:
            # 只有新生成 CA 时才落盘；复用场景绝不覆盖手机已信任的 CA
            with open(CA_KEY, "wb") as f:
                f.write(ca_key.private_bytes(serialization.Encoding.PEM,
                                             serialization.PrivateFormat.TraditionalOpenSSL,
                                             serialization.NoEncryption()))
            with open(CA_CERT, "wb") as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        with open(SRV_KEY, "wb") as f:
            f.write(srv_key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))
        with open(SRV_CERT, "wb") as f:
            f.write(srv_cert.public_bytes(serialization.Encoding.PEM))
        with open(os.path.join(CERT_DIR, "ca.der"), "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.DER))
        _diag("已现场生成证书")
        print(f"[Cert] ✅ 已生成证书（含 IP：{', '.join(_lan_ips())}）")
        return True
    except Exception as e:
        _diag(f"证书准备失败: {type(e).__name__}: {e}")
        print(f"[Cert] 证书准备失败: {e}")
        return False


def build_mobileconfig():
    """生成 iOS 描述文件（直接读 ca.der，不依赖 cryptography）"""
    try:
        import base64
        der_path = os.path.join(CERT_DIR, "ca.der")
        if not os.path.isfile(der_path):
            # 退路：从 PEM 里剥出 base64 片段
            with open(CA_CERT, "r", encoding="utf-8") as f:
                pem = f.read()
            body = "".join(l.strip() for l in pem.splitlines() if "-----" not in l)
            b64 = body
        else:
            with open(der_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()

        cfg = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key><string>lansync-ca.cer</string>
      <key>PayloadContent</key><data>{b64}</data>
      <key>PayloadDescription</key><string>局域网通讯台本地根证书</string>
      <key>PayloadDisplayName</key><string>LanSync 本地 CA</string>
      <key>PayloadIdentifier</key><string>com.lansync.ca</string>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadUUID</key><string>6F1C2A90-0B7E-4C31-9C1F-1A2B3C4D5E01</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>LanSync 本地证书</string>
  <key>PayloadIdentifier</key><string>com.lansync.profile</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>B1D3F6A0-2C4E-4A77-8E11-1A2B3C4D5E02</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>"""
        return cfg.encode("utf-8")
    except Exception as e:
        _diag(f"mobileconfig 生成失败: {e}")
        print(f"[Cert] mobileconfig 生成失败: {e}")
        return b""


def _https_url():
    return f"https://{HOST_IP}:{HTTPS_PORT}"

# ====== Flask + SocketIO ======
app = Flask(__name__,
            static_folder=os.path.join(RES_DIR, "static"),
            template_folder=os.path.join(RES_DIR, "templates"))
app.config["SECRET_KEY"] = "lansync-secret-2026"

# ✅ WSGI 中间件：最暴力的 CORS（覆盖所有路由包括 SocketIO 内部路由）
class _CorsMiddleware:
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        def _patched_start_response(status, headers, exc_info=None):
            headers = list(headers)
            has_origin = any(h[0].lower() == "access-control-allow-origin" for h in headers)
            if not has_origin:
                headers.append(("Access-Control-Allow-Origin", "*"))
            headers.append(("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
            headers.append(("Access-Control-Allow-Headers", "Content-Type, Authorization"))
            # ⚠️ 不要加 Access-Control-Allow-Credentials: true（浏览器不允许和 * 共存）
            return start_response(status, headers, exc_info)
        # OPTIONS 预检直接返回
        if environ.get("REQUEST_METHOD") == "OPTIONS":
            return _cors_preflight(_patched_start_response)
        return self.app(environ, _patched_start_response)

def _cors_preflight(start_response):
    body = b""
    start_response("204 No Content", [
        ("Content-Type", "text/plain"),
        ("Content-Length", "0"),
    ])
    return [body]

# 包装 Flask app
app.wsgi_app = _CorsMiddleware(app.wsgi_app)

socketio = SocketIO(app,
                     cors_allowed_origins="*",
                     allow_credentials=False,   # 🔥 关键！不能和 * 共存
                     async_mode="threading",
                     binary=True,
                     max_http_buffer_size=2 * 1024 * 1024,   # 传输层 2MB 兜底（1MB 业务层拦截，避免直接断线）
                     ping_timeout=30,
                     ping_interval=20)

# ============================================================
#  企业级硬上限（写死，防止任何一端把服务搞崩）
# ============================================================
MAX_USERS = 30                 # 同时在线上限（安全区，硬性拦截）
MAX_TEXT_LEN = 2000            # 单条文字长度
MAX_IMAGE_B64 = 1 * 1024 * 1024   # 单张图片 base64 上限（约 750KB 原图）
MAX_VOICE_MS = 30000           # 单条语音最长 30 秒
MAX_VOICE_B64 = 3 * 1024 * 1024   # 单条语音 base64 上限（约 2MB）
MAX_HISTORY = 500              # 内存里保留的消息条数

_VOICE_OWNER = None  # 当前正在发言的 sid
_VOICE_START = 0     # 持麦开始时间（兜底释放用）
_BOUND_DEV = ""   # 启动后由 _load_bound_dev() 填充

# ============================================================
#  滑动窗口限流（借鉴 MiniMost ratelimit.py）
#  · 按动作分档：文字/图片/语音/连接/改名各有独立配额
#  · 线程安全，内存驻留，无需额外依赖
# ============================================================
# 各动作配额：(最大次数, 窗口秒数)
_RATE_LIMITS = {
    "text":    (30, 10),    # 10 秒内最多 30 条文字
    "image":   (10, 10),    # 10 秒内最多 10 张图
    "voice":   (15, 10),    # 10 秒内最多 15 条语音
    "connect": (5, 60),     # 1 分钟内最多 5 次连接（防重连轰炸）
    "name":    (5, 60),     # 1 分钟内最多改 5 次昵称
    "clip":    (20, 10),    # 10 秒内最多 20 次剪贴发送（防刷屏/防广播风暴）
}
_RATE_BUCKETS = {}    # (sid, action) -> deque(timestamps)
_RATE_LOCK = threading.Lock()


def _rate_ok(sid, action="text"):
    """滑动窗口限流：指定动作是否还在配额内"""
    limit, window = _RATE_LIMITS.get(action, (30, 10))
    now = time.time()
    key = (sid, action)
    with _RATE_LOCK:
        if len(_RATE_BUCKETS) > 512:      # 防止大量临时 IP 让字典无限膨胀
            for k in [k for k, v in _RATE_BUCKETS.items() if not v]:
                del _RATE_BUCKETS[k]
        dq = _RATE_BUCKETS.get(key)
        if dq is None:
            dq = deque()
            _RATE_BUCKETS[key] = dq
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


def _rate_cleanup(sid):
    """用户断开时清理其所有限流计数"""
    with _RATE_LOCK:
        for key in list(_RATE_BUCKETS.keys()):
            if key[0] == sid:
                del _RATE_BUCKETS[key]


# ============================================================
#  封禁系统（借鉴 Mumble Ban.cpp）
#  · 双维度封禁：IP + 设备 id（任一命中即拒绝）
#  · 带到期时间，到期自动解除
#  · 持久化到 bans.json（重启不丢）
# ============================================================
_BANS_FILE = os.path.join(BASE_DIR, "bans.json")


def _load_bans():
    try:
        if os.path.isfile(_BANS_FILE):
            with open(_BANS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except Exception:
        pass
    return {}


def _save_bans():
    try:
        with open(_BANS_FILE, "w", encoding="utf-8") as f:
            json.dump(_BANS, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[Ban] 保存失败: {e}")


_BANS = _load_bans()


def _is_banned(identifier):
    """检查 identifier（IP 或设备 id）是否在封禁期内"""
    if not identifier:
        return None
    b = _BANS.get(identifier)
    if not b:
        return None
    now = time.time()
    if b.get("until", 0) < now:
        _BANS.pop(identifier, None)
        _save_bans()
        return None
    return b


def _ban_identifier(identifier, duration_sec, reason, by_name):
    """封禁某个 identifier（IP 或 dev id），duration_sec=0 表示永久"""
    if not identifier:
        return False
    until = (time.time() + duration_sec) if duration_sec > 0 else 9999999999
    _BANS[identifier] = {"until": until, "reason": reason, "by": by_name}
    _save_bans()
    return True


def _unban_identifier(identifier):
    if identifier in _BANS:
        del _BANS[identifier]
        _save_bans()
        return True
    return False


def _ip_ban_safe(ip):
    """判断该 IP 是否可以安全封禁（避免误伤同 IP 的其他设备）
    TLS 转发 / 公网穿透模式下，服务端看到的所有手机 IP 都是同一个，
    此时封 IP 会连坐所有人 → 只封设备 id 即可
    """
    if not ip or ip in ("127.0.0.1", "::1", "localhost"):
        return False
    try:
        if ip == HOST_IP:            # 转发层回连用的就是服务器自己的局域网 IP
            return False
    except Exception:
        pass
    # 该 IP 上有多个在线用户 → 说明是共享出口，不能封
    try:
        same = sum(1 for x in users.values() if x.get("ip") == ip)
        if same > 1:
            return False
    except Exception:
        pass
    return True


def _voice_name(sid):
    u = users.get(sid)
    return u["name"] if u else "有人"


# ============================================================
#  💾 历史消息持久化（借鉴 WuKongIM SQLite 存储）
#  · 文件：BASE_DIR/history.db（与 exe 同级，备份方便）
#  · 存 text / image / voice / system 全部消息
#  · 每条媒体消息只存 base64 文本，不额外压缩
#  · 启动时自动加载最近 N 条进内存
#  · 写入用 WAL 模式 + 线程锁，避免多线程写冲突
# ============================================================
import sqlite3 as _sqlite3

_HISTORY_DB = os.path.join(BASE_DIR, "history.db")
_HISTORY_MAX_LOAD = 500   # 启动时从 DB 加载最近 500 条
_HISTORY_MAX_KEEP_DAYS = 30  # 超过 30 天的媒体消息自动清理（文字保留）
_HISTORY_LOCK = threading.Lock()
_HISTORY_CONN = None


def _history_init():
    """初始化 SQLite 连接 + 建表 + 加载内存 + 过期清理"""
    global _HISTORY_CONN, messages
    try:
        _HISTORY_CONN = _sqlite3.connect(_HISTORY_DB, check_same_thread=False, timeout=5)
        _HISTORY_CONN.execute("PRAGMA journal_mode=WAL;")
        _HISTORY_CONN.execute("PRAGMA synchronous=NORMAL;")
        _HISTORY_CONN.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                sender TEXT,
                sender_name TEXT,
                color TEXT,
                content TEXT,
                extra TEXT,      -- JSON: duration/omitted 等
                ts INTEGER NOT NULL
            )
        """)
        _HISTORY_CONN.commit()

        # 启动时加载最近消息进内存
        cur = _HISTORY_CONN.execute(
            "SELECT id, type, sender, sender_name, color, content, extra, ts "
            "FROM messages ORDER BY ts DESC LIMIT ?",
            (_HISTORY_MAX_LOAD,)
        )
        rows = cur.fetchall()
        for row in reversed(rows):   # 时间升序塞进 messages
            _m = {
                "id": row[0],
                "type": row[1],
                "from": row[2] or "",
                "name": row[3] or "有人",
                "color": row[4] or "#64748b",
                "ts": row[7],
            }
            if row[1] == "text":
                _m["text"] = row[5] or ""
            elif row[1] == "image":
                _m["image"] = row[5] or ""
            elif row[1] == "voice":
                _m["voice"] = row[5] or ""
                if row[6]:
                    try:
                        _m["duration"] = json.loads(row[6]).get("duration", 0)
                    except Exception:
                        pass
            messages.append(_m)
        if rows:
            print(f"[History] ✅ 从 DB 恢复 {len(rows)} 条历史消息")

        # 清理过期媒体（超过 30 天的 image/voice 清空 base64，保留元信息）
        cutoff = int(time.time() * 1000) - _HISTORY_MAX_KEEP_DAYS * 86400 * 1000
        _HISTORY_CONN.execute(
            "UPDATE messages SET content='', extra=NULL "
            "WHERE type IN ('image','voice') AND ts < ? AND content != ''",
            (cutoff,)
        )
        _HISTORY_CONN.commit()
    except Exception as e:
        print(f"[History] ❌ 初始化失败: {type(e).__name__}: {e}")
        _HISTORY_CONN = None


def _history_save(msg):
    """把单条消息写进 SQLite（从 chat_text/chat_image/chat_voice/system_msg 调用）"""
    if not _HISTORY_CONN:
        return
    try:
        _type = msg.get("type", "text")
        _content = ""
        _extra = None
        if _type == "text":
            _content = msg.get("text", "")
        elif _type == "image":
            _content = msg.get("image", "")
        elif _type == "voice":
            _content = msg.get("voice", "")
            _extra = json.dumps({"duration": msg.get("duration", 0)}, ensure_ascii=False)
        elif _type == "system":
            _content = msg.get("text", "")

        with _HISTORY_LOCK:
            _HISTORY_CONN.execute(
                "INSERT OR REPLACE INTO messages "
                "(id, type, sender, sender_name, color, content, extra, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (msg.get("id", ""), _type, msg.get("from", ""),
                 msg.get("name", "") or "", msg.get("color", "") or "#64748b",
                 _content, _extra, msg.get("ts", int(time.time() * 1000)))
            )
            _HISTORY_CONN.commit()
    except Exception as e:
        print(f"[History] 保存失败: {type(e).__name__}: {e}")


def _history_clear():
    """管理员清空消息时同步清空 DB"""
    if not _HISTORY_CONN:
        return
    try:
        with _HISTORY_LOCK:
            _HISTORY_CONN.execute("DELETE FROM messages")
            _HISTORY_CONN.commit()
        print("[History] ✅ DB 历史已清空")
    except Exception as e:
        print(f"[History] 清空失败: {e}")


# ====== 内存数据结构（单房间 "main"） ======
# { user_sid: { "id": str, "name": str, "color": str, "is_admin": bool, "muted": bool } }
users = {}
# [ { "id": str, "type": "text|image|voice|system", "from": str, "name": str, "color": str,
#     "text": str, "image": str(base64), "voice": str(base64), "ts": int } ]
messages = []

# ============================================================
#  人员在位管理：主动退出 / 空闲自动退出 / 心跳
# ============================================================
import os as _os
IDLE_TIMEOUT_MIN = float(_os.environ.get("LC_IDLE_MIN", "30"))   # 空闲多少分钟自动退出
IDLE_SWEEP_SEC = 60          # 每分钟扫一次
_LAST_ACTIVE = {}            # sid -> timestamp


def _touch(sid):
    _LAST_ACTIVE[sid] = time.time()


def _idle_worker():
    """后台线程：清理长时间无操作的用户"""
    while True:
        time.sleep(IDLE_SWEEP_SEC)
        try:
            now = time.time()
            # 麦克风被占用超过 45 秒 → 强制释放（防止有人没触发 voice_end）
            if _VOICE_OWNER and _VOICE_START and (now - _VOICE_START > 45):
                print("[Voice] 持麦超时，强制释放")
                _VOICE_OWNER = None
                _VOICE_START = 0
                try:
                    emit("voice_free", {}, room="main")
                except Exception:
                    pass
            for sid in list(users.keys()):
                last = _LAST_ACTIVE.get(sid, now)
                if now - last > IDLE_TIMEOUT_MIN * 60:
                    name = users[sid]["name"]
                    print(f"[Idle] {name} 空闲超时，自动退出")
                    try:
                        emit("idle_kick", {"text": f"你已连续 {int(IDLE_TIMEOUT_MIN)} 分钟未操作，自动退出"},
                             to=sid)
                    except Exception:
                        pass
                    try:
                        emit("system_msg", {"text": f"{name} 因长时间未操作已离开",
                                            "ts": int(time.time()*1000)}, room="main")
                    except Exception:
                        pass
                    try:
                        socketio.server.disconnect(sid)
                    except Exception:
                        pass
                    users.pop(sid, None)
                    _LAST_ACTIVE.pop(sid, None)
        except Exception as e:
            print(f"[Idle] 巡检异常: {e}")


def _stale_sweep():
    """清理僵尸会话（浏览器直接关掉、没发 disconnect 的情况）"""
    global _VOICE_OWNER
    while True:
        time.sleep(60)
        try:
            now = time.time()
            for sid in list(users.keys()):
                # 只有底层连接已经不存在（浏览器关了/网断了）才清理
                _alive = False
                try:
                    _alive = sid in socketio.server.eio.sockets
                except Exception:
                    _alive = True
                if (not _alive) or (now - _LAST_ACTIVE.get(sid, now) > 3600):
                    u = users.pop(sid, None)
                    _LAST_ACTIVE.pop(sid, None)
                    _rate_cleanup(sid)
                    _rtc_drop = _RTC_PEERS.pop(sid, None)
                    if _rtc_drop:
                        try:
                            emit("rtc_peer_left", {"sid": sid, "name": _rtc_drop["name"]}, room="main")
                        except Exception:
                            pass
                    if _VOICE_OWNER == sid:
                        _VOICE_OWNER = None
                        try:
                            emit("voice_free", {}, room="main")
                        except Exception:
                            pass
                    if u:
                        print(f"[Clean] 清理僵尸会话: {u.get('name')}")
                        try:
                            socketio.server.disconnect(sid)
                        except Exception:
                            pass
        except Exception:
            pass

def _start_idle_worker():
    threading.Thread(target=_idle_worker, daemon=True).start()
    print(f"[Idle] 空闲自动退出：{IDLE_TIMEOUT_MIN} 分钟")

# ====== 颜色池（头像/气泡用） ======
COLOR_POOL = [
    "#6366f1", "#ec4899", "#f59e0b", "#10b981", "#06b6d4",
    "#8b5cf6", "#ef4444", "#84cc16", "#f97316", "#14b8a6",
]

def pick_color():
    import random
    return random.choice(COLOR_POOL)

def get_lan_ip():
    """获取本机局域网 IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

HOST_IP = get_lan_ip()

# 🔒 可选 PIN 码：设置后客户端必须输入正确 PIN 才能加入（借鉴 LocalSend PIN 验证）
PIN_CODE = _load_flag("pin_code", "")   # config.json 里写字符串，空=不启用
if not isinstance(PIN_CODE, str):
    PIN_CODE = ""
print(f"[Config] ✅ 配置已加载" + (f" · PIN 码已启用" if PIN_CODE else " · PIN 码未启用"))


# ============================================================
#  自动内网穿透（给 iPhone / 安卓 用 https 访问 → 才能录音）
#  · 启动时后台跑 cloudflared，自动拿到 https 地址
#  · 没装 cloudflared 就自动下载到程序目录
# ============================================================
import subprocess
import shutil
import re

TUNNEL = {"url": "", "status": "idle", "error": "", "backend": ""}
_TUNNEL_PROC = None
_CF_URL = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"


def _cloudflared_path():
    """找 cloudflared.exe：程序目录 → exe 目录 → PATH"""
    for base in (os.path.dirname(os.path.abspath(__file__)), BASE_DIR, RES_DIR):
        p = os.path.join(base, "cloudflared.exe")
        if os.path.isfile(p):
            return p
    w = shutil.which("cloudflared") or shutil.which("cloudflared.exe")
    return w or ""


def _download_cloudflared():
    """自动下载（约 53MB），失败就返回空串"""
    target = os.path.join(BASE_DIR, "cloudflared.exe")
    tmp = target + ".part"
    try:
        print("[Tunnel] 首次运行，正在下载 cloudflared（约 53MB）...")
        req = urllib.request.Request(_CF_URL, headers={"User-Agent": "lansync"})
        with urllib.request.urlopen(req, timeout=180) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f, 1024 * 256)
        os.replace(tmp, target)
        print("[Tunnel] ✅ cloudflared 下载完成")
        return target
    except Exception as e:
        print(f"[Tunnel] ❌ 下载失败: {e}")
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return ""




def _read_tunnel_output(proc, backend):
    """逐行读隧道输出，抓 https 地址（支持 lhr.life / trycloudflare）"""
    pat = re.compile(r"https://[-\w.]+\.(?:lhr\.life|trycloudflare\.com)")
    try:
        for raw in proc.stdout:
            line = raw.decode("utf-8", "ignore") if isinstance(raw, bytes) else str(raw)
            m = pat.search(line)
            if m and not TUNNEL["url"]:
                TUNNEL["url"] = m.group(0)
                TUNNEL["status"] = "running"
                TUNNEL["backend"] = backend
                print(f"[Tunnel] ✅ 公网地址（{backend}）: {TUNNEL['url']}")
    except Exception as e:
        print(f"[Tunnel] 读取输出中断: {e}")


def _start_ssh_tunnel(port):
    """方案一：系统自带 OpenSSH + localhost.run（零下载，最快）"""
    ssh = shutil.which("ssh") or r"C:\Windows\System32\OpenSSH\ssh.exe"
    if not os.path.isfile(ssh) and not shutil.which("ssh"):
        return None
    print("[Tunnel] 尝试 SSH 穿透（localhost.run）...")
    return subprocess.Popen(
        [ssh, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL",
         "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=20",
         "-R", f"80:127.0.0.1:{port}", "nokey@localhost.run"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _start_cloudflared_tunnel(port):
    """方案二：cloudflared（需下载 53MB，慢但稳）"""
    cf = _cloudflared_path() or _download_cloudflared()
    if not cf:
        return None
    print("[Tunnel] 尝试 cloudflared 穿透...")
    return subprocess.Popen(
        [cf, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=BASE_DIR,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


# ============================================================
#  外网连通性自动检测（决定走公网隧道还是本地 HTTPS）
#  · 启动时探一次，之后每 8 秒巡检一次
#  · 外网通 → 隧道模式（扫码即用，无需证书）
#  · 外网断 → 自动切离线语音模式（本地 https:5443，手机装证书）
# ============================================================
NET = {"online": None, "checked_at": 0.0}
_NET_LOCK = threading.Lock()
_MAIN_PORT = 5050


def _check_online(timeout=2.0):
    """TCP 直连公共站点 443 端口，能连上即认为外网可用（同时验证 DNS）"""
    for host in ("www.baidu.com", "www.qq.com"):
        try:
            s = socket.create_connection((host, 443), timeout=timeout)
            s.close()
            return True
        except Exception:
            continue
    return False


def _probe_with_timeout(sec=3.0):
    """带总超时的探测：DNS 解析卡住时也不会拖住启动/巡检"""
    result = {"ok": False, "done": False}

    def _run():
        try:
            result["ok"] = _check_online()
        except Exception:
            result["ok"] = False
        result["done"] = True

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(sec)
    return result["ok"] if result["done"] else False


def _refresh_net_state(max_sec=2.0, wait=0.0):
    """立即探测一次外网并更新 NET；已有探测在跑时最多等 wait 秒"""
    if not _NET_LOCK.acquire(timeout=wait):
        return NET.get("online")
    try:
        # 刚探测过就直接复用，避免面板打开时重复探测
        if time.time() - NET.get("checked_at", 0) < 0.5:
            return NET.get("online")
        ok = _probe_with_timeout(max_sec)
        NET["online"] = ok
        NET["checked_at"] = time.time()
        return ok
    finally:
        _NET_LOCK.release()


def _net_mode():
    """当前生效模式：offline = 局域网直连（无隧道）/ online = 公网隧道"""
    if OFFLINE_VOICE or NO_TUNNEL:
        return "offline"
    online = NET.get("online")
    if online is None:
        return "offline"
    return "online" if online else "offline"


def _net_watch():
    """后台巡检：外网状态一变就切换模式"""
    global _TUNNEL_PROC
    if NO_TUNNEL:
        print("[Net] no_tunnel=true，跳过外网巡检")
        return
    while True:
        time.sleep(8)
        try:
            prev = NET.get("online")
            ok = _refresh_net_state(3.0)
            if prev is None or prev == ok:
                continue
            if ok:
                print("[Net] 外网已恢复 → 启动公网隧道")
                try:
                    if not _TUNNEL_PROC or _TUNNEL_PROC.poll() is not None:
                        threading.Thread(target=start_tunnel, args=(_MAIN_PORT,), daemon=True).start()
                except Exception:
                    pass
            else:
                print("[Net] 外网已断开 → 自动切离线语音模式（本地 https:5443）")
                stop_tunnel()
        except Exception:
            pass


def start_tunnel(port):
    """后台线程：优先 SSH localhost.run（秒起，免下载），cloudflared 作为可选项（
    用户提前把 cloudflared.exe 丢到 exe 同级目录即可启用更好的 WebSocket 隧道）。
    注意：SSH localhost.run 不支持 WebSocket Upgrade，前端对 .lhr.life 已强制 polling-only。"""
    if NO_TUNNEL:
        TUNNEL["status"] = "disabled"
        TUNNEL["error"] = "no_tunnel=true"
        return
    global _TUNNEL_PROC
    try:
        TUNNEL["status"] = "starting"
        TUNNEL["url"] = ""          # 清掉旧地址

        # ① 先试 cloudflared（如果用户已经提前装好 exe）—— 国内 GitHub 下载被墙，不自动拉
        cf_path = _cloudflared_path()
        proc = None
        backend = ""
        if cf_path:
            try:
                proc = _start_cloudflared_tunnel(port)
                backend = "cloudflared"
            except Exception as e:
                print(f"[Tunnel] cloudflared 启动失败: {e}")

        if proc is not None:
            _TUNNEL_PROC = proc
            threading.Thread(target=_read_tunnel_output, args=(proc, backend), daemon=True).start()
            # 最多等 15 秒（已有 exe 不用下载，正常 1~3 秒就出地址）
            for _ in range(30):
                if TUNNEL["url"]:
                    return
                time.sleep(0.5)
            print("[Tunnel] cloudflared 未拿到地址，切 SSH")
            try:
                proc.terminate()
            except Exception:
                pass

        # ② 兜底：SSH localhost.run（秒级启动，免下载；WebSocket 升级会被它返回 400，
        #     前端已做 .lhr.life → polling-only 处理）
        proc2 = None
        try:
            proc2 = _start_ssh_tunnel(port)
        except Exception as e:
            print(f"[Tunnel] SSH 启动失败: {e}")

        if proc2 is None:
            TUNNEL["status"] = "no_binary"
            TUNNEL["error"] = "cloudflared 与 SSH 都不可用"
            return
        _TUNNEL_PROC = proc2
        threading.Thread(target=_read_tunnel_output, args=(proc2, "ssh"), daemon=True).start()
    except Exception as e:
        TUNNEL["status"] = "error"
        TUNNEL["error"] = str(e)
        print(f"[Tunnel] ❌ 启动失败: {e}")


def _kill_proc(proc):
    """强杀子进程及其进程树（cloudflared / ssh）。
    先 terminate 给机会正常退出，2 秒不退出就用 taskkill /T 连子进程一起杀掉，
    避免窗口关闭后隧道进程变成孤儿继续占用网络与内存。"""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
    except Exception:
        pass
    try:
        proc.wait(timeout=2)
        return
    except Exception:
        pass
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def stop_tunnel():
    global _TUNNEL_PROC
    try:
        _kill_proc(_TUNNEL_PROC)
    except Exception:
        pass
    _TUNNEL_PROC = None
    TUNNEL["status"] = "stopped"
    TUNNEL["url"] = ""          # 清掉旧地址，避免恢复瞬间前端拿到已失效链接


def _shutdown_and_exit(code=0):
    """关窗退出兜底：停隧道并结束 cloudflared / ssh 子进程，再强制结束本进程。
    保证窗口关闭后任务管理器里不留 LanSync，也不留孤儿隧道进程。"""
    try:
        stop_tunnel()
    except Exception:
        pass
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    os._exit(code)


# ============================================================
#  图片选择器（应用内浏览文件夹 + 缩略图）
# ============================================================
IMG_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp")
_THUMB_CACHE = {}


def _img_cfg_path():
    return os.path.join(BASE_DIR, "config.json")


def _get_img_dir():
    """当前图片目录：config.json 里记住的 > 系统图片文件夹"""
    try:
        cfg = json.load(open(_img_cfg_path(), encoding="utf-8-sig"))
        d = (cfg.get("img_dir") or "").strip()
        if d and os.path.isdir(d):
            return d
    except Exception:
        pass
    for cand in (
        os.path.join(os.path.expanduser("~"), "Pictures"),
        os.path.join(os.path.expanduser("~"), "Desktop"),
        os.path.join(os.path.expanduser("~"), "Downloads"),
    ):
        if os.path.isdir(cand):
            return cand
    return BASE_DIR


def _set_img_dir(d):
    try:
        cfg = {}
        p = _img_cfg_path()
        if os.path.isfile(p):
            cfg = json.load(open(p, encoding="utf-8-sig")) or {}
        cfg["img_dir"] = d
        json.dump(cfg, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[Img] 保存目录失败: {e}")


def _safe_img_path(path):
    """只允许读取图片文件，且路径必须真实存在"""
    p = os.path.abspath(path or "")
    if not p or not os.path.isfile(p):
        return ""
    if os.path.splitext(p)[1].lower() not in IMG_EXTS:
        return ""
    return p


def _local_only():
    """只允许本机（回环地址）访问；局域网拒绝"""
    ip = (request.remote_addr or "").replace("::ffff:", "")
    return ip in ("127.0.0.1", "::1", "localhost")

@app.route("/api/img/list")
def api_img_list():
    if not _local_only():
        return jsonify({"ok": False, "msg": "本机才能浏览图片"}), 403
    d = request.args.get("dir") or _get_img_dir()
    d = os.path.abspath(d)
    if not os.path.isdir(d):
        return jsonify({"ok": False, "msg": "目录不存在", "dir": _get_img_dir()}), 404
    _set_img_dir(d)
    dirs, imgs = [], []
    try:
        for name in sorted(os.listdir(d)):
            full = os.path.join(d, name)
            if os.path.isdir(full):
                if not name.startswith("."):
                    dirs.append({"name": name, "path": full})
            elif os.path.splitext(name)[1].lower() in IMG_EXTS:
                try:
                    st = os.stat(full)
                except Exception:
                    continue
                imgs.append({
                    "name": name,
                    "path": full,
                    "size": st.st_size,
                    "mtime": int(st.st_mtime),
                    "thumb": f"/api/img/thumb?path={urllib.parse.quote(full)}",
                    "raw": f"/api/img/raw?path={urllib.parse.quote(full)}",
                })
        # 按修改时间倒序（最新的图在最前）
        imgs.sort(key=lambda x: x["mtime"], reverse=True)
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e), "dir": d}), 500

    parent = os.path.dirname(d)
    if parent == d:
        parent = ""
    return jsonify({"ok": True, "dir": d, "parent": parent, "dirs": dirs, "images": imgs})



@app.route("/api/img/shortcuts")
def api_img_shortcuts():
    if not _local_only():
        return jsonify({"ok": False, "msg": "本机才能浏览图片"}), 403
    home = os.path.expanduser("~")
    out = {}
    for k, name in (("pictures", "Pictures"), ("desktop", "Desktop"),
                    ("downloads", "Downloads"), ("documents", "Documents")):
        pth = os.path.join(home, name)
        if os.path.isdir(pth):
            out[k] = pth
    return jsonify({"ok": True, "home": home, "dirs": out})


@app.route("/api/img/thumb")
def api_img_thumb():
    if not _local_only():
        return jsonify({"ok": False, "msg": "本机才能浏览图片"}), 403
    path = _safe_img_path(request.args.get("path"))
    if not path:
        return ("", 404)
    size = int(request.args.get("size") or 240)
    key = (path, os.path.getmtime(path), size)
    if key in _THUMB_CACHE:
        return _THUMB_CACHE[key], 200, {"Content-Type": "image/jpeg", "Cache-Control": "max-age=600"}
    try:
        from PIL import Image
        im = Image.open(path)
        im.thumbnail((size, size))
        if im.mode not in ("RGB", "L"):
            im = im.convert("RGB")
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=82)
        data = buf.getvalue()
        if len(_THUMB_CACHE) > 300:
            _THUMB_CACHE.clear()
        _THUMB_CACHE[key] = data
        return data, 200, {"Content-Type": "image/jpeg", "Cache-Control": "max-age=600"}
    except Exception as e:
        print(f"[Img] 缩略图失败 {path}: {e}")
        return ("", 500)


@app.route("/api/img/raw")
def api_img_raw():
    if not _local_only():
        return jsonify({"ok": False, "msg": "本机才能浏览图片"}), 403
    path = _safe_img_path(request.args.get("path"))
    if not path:
        return ("", 404)
    return send_file(path)


# ====== 网络信息（前端引导用） ======
def _all_lan_ips():
    """列出所有局域网 IPv4（排除回环/链路本地/虚拟网卡）"""
    ips = []
    try:
        import socket as _s
        hostname = _s.gethostname()
        for info in _s.getaddrinfo(hostname, None, _s.AF_INET):
            ip = info[4][0]
            if ip.startswith(("127.", "169.254.")) or ip in ips:
                continue
            ips.append(ip)
    except Exception:
        pass
    if not ips:
        ips.append(HOST_IP)
    return ips










@app.route("/manifest.webmanifest")
def manifest_dynamic():
    """动态 manifest：把邀请码写进 start_url
       → iOS/安卓 添加到桌面后，打开时自带 ?inv=xxx"""
    inv = (request.args.get("inv") or INVITE.get("token") or "").strip()
    start = "/?inv=" + inv if inv else "/"
    data = {
        "name": "私域内网多端协同枢纽",
        "short_name": "协同枢纽",
        "start_url": start,
        "scope": "/",
        "display": "browser",
        "background_color": "#0b1220",
        "theme_color": "#0b1220",
        "icons": [
            {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png"},
        ],
    }
    from flask import Response
    return Response(json.dumps(data, ensure_ascii=False),
                    mimetype="application/manifest+json")

@app.route("/ca")
def ca_page():
    """证书安装引导页（同源，避免 iOS 拦截）"""
    if not os.path.isfile(CA_CERT):
        ensure_certs()
    host = HOST_IP
    html = f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>安装证书 · LanSync</title>
<style>
body{{margin:0;background:#0b1220;color:#cbd5e1;font-family:-apple-system,system-ui,sans-serif;padding:20px;line-height:1.8}}
.card{{max-width:420px;margin:0 auto;background:#111827;border:1px solid #1f2937;border-radius:18px;padding:22px}}
h1{{font-size:18px;color:#e5e7eb;margin:0 0 6px}}
p{{font-size:13px;color:#9ca3af;margin:8px 0}}
a.btn{{display:block;text-align:center;margin:16px 0;padding:15px;border-radius:13px;text-decoration:none;
font-size:16px;font-weight:800;background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff}}
ol{{font-size:13px;color:#cbd5e1;padding-left:20px;margin:10px 0}}
li{{margin:8px 0}}
code{{background:#1e293b;padding:2px 6px;border-radius:6px;font-size:12px;color:#7dd3fc;word-break:break-all}}
small{{display:block;margin-top:14px;font-size:11px;color:#4b5563;line-height:1.8}}
</style></head><body><div class="card">
<h1>🔐 安装证书（只需一次）</h1>
<p>装完这一步，苹果手机才能使用语音（断网也能用）。</p>
<a class="btn" href="/ca.mobileconfig">① 下载描述文件</a>
<ol>
  <li>点上面按钮 → 弹出“此网站正尝试下载配置描述文件” → 点<b>允许</b></li>
  <li>打开 <b>设置 → 通用 → VPN与设备管理</b></li>
  <li>点最上面的<b>已下载的描述文件</b> → 右上角<b>安装</b> → 输密码</li>
  <li>回到 <b>设置 → 通用 → 关于本机 → 证书信任设置</b></li>
  <li>把 <b>LanSync Local CA</b> 的开关打开</li>
  <li>回到浏览器刷新本页面即可</li>
</ol>
<p>如果上面的按钮没反应，请用 Safari 手动打开：</p>
<p><code>http://{host}:5050/ca.mobileconfig</code></p>
<small>本证书只用于本机局域网通讯，不联网、不上传任何数据。<br>
证书有效期 10 年，装一次长期有效。</small>
</div></body></html>"""
    return html

@app.route("/ca.mobileconfig")
def download_mobileconfig():
    if not os.path.isfile(CA_CERT):
        ensure_certs()
    data = build_mobileconfig()
    if not data:
        return "描述文件生成失败", 500
    return send_file(io.BytesIO(data), mimetype="application/x-apple-aspen-config",
                     as_attachment=True, download_name="lansync.mobileconfig")


@app.route("/https-info")
def https_info():
    _off = (_net_mode() == "offline")
    return jsonify({"ok": True, "https_url": _https_url(),
                    "offline_voice": _off,
        "voice_version": bool(VOICE_VERSION or _off),
        "mode": _net_mode(),
        "online": NET.get("online"),
        "invite_token": INVITE.get("token", ""),
        "local_domain": LOCAL_DOMAIN,
        "domain_url": _domain_url(),
        "https_port": HTTPS_PORT,
                    "ca_url": f"http://{HOST_IP}:{HTTP_PORT}/ca.mobileconfig"})

@app.route("/api/app-version")
def api_app_version():
    return jsonify({"ok": True, "version": APP_VERSION})





@app.route("/api/invite/new", methods=["POST"])
def api_invite_new():
    """电脑端刷新二维码（本机调用）"""
    tok = _invite_new()
    return jsonify({"ok": True, "token": tok})




@app.route("/api/invite/verify")
def api_invite_verify():
    inv = request.args.get("inv") or ""
    dev = request.args.get("dev") or ""
    try:
        ok, why = _invite_ok(inv, dev)
    except Exception as e:
        return jsonify({"ok": True, "reason": f"校验异常: {e}"})
    return jsonify({"ok": ok, "reason": why, "server_token": INVITE.get("token", "")})

@app.route("/api/invite/status")
def api_invite_status():
    used = bool(INVITE.get("dev"))
    return jsonify({"ok": True, "token": INVITE.get("token", ""), "used": used,
                    "expired": (time.time() - INVITE.get("ts", 0)) > INVITE_TTL if INVITE.get("token") else False})

@app.route("/api/capacity")
def api_capacity():
    """当前在线人数 / 上限（前端进房前自检）"""
    return jsonify({"ok": True, "online": len(users), "max": MAX_USERS,
                    "full": len(users) >= MAX_USERS})

@app.route("/api/net-info")
def api_net_info():
    port = int(request.args.get("port") or 5050)
    ips = _all_lan_ips()
    _off = (_net_mode() == "offline")
    return jsonify({
        "ok": True,
        "host_ip": HOST_IP,
        "voice_version": bool(VOICE_VERSION or _off),
        "mode": _net_mode(),
        "online": NET.get("online"),
        "no_tunnel": NO_TUNNEL,
        "invite_token": INVITE.get("token", ""),
        "ips": ips,
        "port": port,
        "offline_voice": _off,
        "https_url": TUNNEL.get("url", ""),
        "https_port": HTTPS_PORT,
        "local_https": f"https://{HOST_IP}:{HTTPS_PORT}",
        "local_domain": LOCAL_DOMAIN,
        "domain_url": _domain_url(),
        "tunnel": {"status": TUNNEL.get("status"), "error": TUNNEL.get("error", ""), "backend": TUNNEL.get("backend", "")},
        "scheme": "https" if request.is_secure else "http",
        "secure_context": request.is_secure,
        "urls": [f"http://{ip}:{port}" for ip in ips],
    })


@app.route("/api/net-check", methods=["POST"])
def api_net_check():
    """手机加入面板打开时强制刷新外网状态，避免等 8 秒巡检"""
    ok = _refresh_net_state(2.0, wait=2.0)
    return jsonify({"ok": True, "online": bool(ok), "mode": _net_mode(),
                    "checked_at": NET.get("checked_at", 0)})


# ============================================================
#  🔍 局域网自动发现（借鉴 LocalSend mDNS + HTTP 扫描 fallback）
#  · mDNS 已经在跑（lansync.local）
#  · 企业网 mDNS 经常被禁 → 这里做 HTTP 扫描兜底
#  · 扫描当前网段所有 IP 的 5050 端口，看哪些是 LanSync
#  · 超时极短（每个 IP 0.15 秒），30 秒网段约 4 秒完成
# ============================================================
def _scan_subnet():
    """扫描当前网段，找同网段上所有 LanSync 实例"""
    results = []
    try:
        import ipaddress
        # 从 HOST_IP 推导 /24 网段（最常见的家用/企业网段）
        my_ip = HOST_IP
        net = ipaddress.ip_network(f"{my_ip}/24", strict=False)
        my_parts = my_ip.split(".")
        my_prefix = ".".join(my_parts[:3]) + "."

        def _probe(ip):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.15)
                if s.connect_ex((ip, HTTP_PORT)) == 0:
                    s.close()
                    # 再发一个 HTTP GET 确认是 LanSync（不是别的服务占了 5050）
                    try:
                        ctx = ssl._create_unverified_context()
                        url = f"http://{ip}:{HTTP_PORT}/api/app-version"
                        req = urllib.request.Request(url, headers={"User-Agent": "LanSync-scan"})
                        with urllib.request.urlopen(req, timeout=1.0, context=None) as r:
                            body = r.read(200).decode("utf-8", errors="ignore")
                            if "app_version" in body.lower() or "ok" in body.lower():
                                return ip
                    except Exception:
                        # 退一步：能连上 5050 就算（有些版本可能没这个接口）
                        return ip
                s.close()
            except Exception:
                pass
            return None

        threads = []
        for i in range(1, 255):
            ip = my_prefix + str(i)
            if ip == my_ip:
                results.append({"ip": ip, "self": True, "port": HTTP_PORT})
                continue
            t = threading.Thread(target=lambda: results.append({"ip": _probe(ip), "self": False, "port": HTTP_PORT}) if _probe(ip) else None, daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=5)

        # 过滤 None，去重，排序
        seen = set()
        clean = []
        for r in results:
            if r.get("ip") and r["ip"] not in seen:
                seen.add(r["ip"])
                clean.append(r)
        clean.sort(key=lambda x: (not x.get("self", False), x["ip"]))
        return clean
    except Exception as e:
        print(f"[Scan] 扫描网段失败: {e}")
        return [{"ip": HOST_IP, "self": True, "port": HTTP_PORT}]


@app.route("/api/lan-scan")
def api_lan_scan():
    """局域网自动发现：返回同网段上所有 LanSync 实例（本机排第一）"""
    ips = _scan_subnet()
    # 同时也把静态枚举的 IP 列进去（给前端完整信息）
    all_ips = _all_lan_ips()
    return jsonify({
        "ok": True,
        "host_ip": HOST_IP,
        "discovered": ips,
        "all_ips": all_ips,
        "mdns_domain": LOCAL_DOMAIN,
        "port": HTTP_PORT,
    })



# ============================================================
#  指令隔离：任何单个用户的异常都不能拖垮整个服务
# ============================================================
from functools import wraps


def _safe_handler(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            try:
                _sid = getattr(request, "sid", "")
                print(f"[Safe] 处理 {fn.__name__} 出错（用户 {_sid[:6]}）: {type(e).__name__}: {e}")
                try:
                    import traceback as _tb
                    _diag(f"{fn.__name__} 异常: {type(e).__name__}: {e} | {_tb.format_exc()[-400:]}")
                except Exception:
                    pass
            except Exception:
                pass
            try:
                emit("muted_warning", {"text": "指令有误，请重试"}, to=request.sid)
            except Exception:
                pass
            return None
    return wrapper




@app.after_request
def _no_cache_html(resp):
    try:
        if resp.mimetype == "text/html":
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
    except Exception:
        pass
    return resp

# ====== 页面路由 ======
@app.route("/")
def index():
    return render_template("index.html", host_ip=HOST_IP, app_version=APP_VERSION, wechat_id=WECHAT_ID)

@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# ============================================================
#  💻 电脑端专属：文件 / 视频共享（流式落盘 · 原文件直传 · 不压缩）
#  · 上传：分块读取 request.files.stream → 写磁盘，绝不整块读进内存
#  · 下载：send_file 原样输出（不转码、不压缩），支持 Range 断点续传
#  · 手机端（Mobi/Android/iPhone/iPad…）一律 403，只能发文字和图片
# ============================================================
SHARED_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(SHARED_DIR, exist_ok=True)

# ---- 可调上限（均可用环境变量覆盖，默认值按“1 小时内视频”场景设定）----
MAX_UPLOAD_BYTES = int(float(os.environ.get("LC_MAX_UPLOAD_GB", "16")) * 1024 ** 3)
SHARE_QUOTA_BYTES = int(float(os.environ.get("LC_SHARE_QUOTA_GB", "100")) * 1024 ** 3)
MAX_CONCURRENT_UPLOADS = max(1, int(os.environ.get("LC_MAX_UPLOADS", "3")))
MIN_FREE_BYTES = int(float(os.environ.get("LC_MIN_FREE_GB", "2")) * 1024 ** 3)
MAX_VIDEO_SECONDS = int(float(os.environ.get("LC_MAX_VIDEO_HOURS", "2")) * 3600)
UPLOAD_CHUNK = 1024 * 1024          # 每次只读 1MB，内存占用恒定

# ---- 极速剪贴（手机也能传文件，限制更小）----
CLIP_MAX_TEXT = 10000                  # 单条文字上限
CLIP_HISTORY_MAX = 20                  # 历史保留条数
CLIP_MAX_FILE_BYTES = 10 * 1024 * 1024  # 手机单文件上限 10MB
CLIP_MAX_FILES = 9                      # 一次最多选 9 个文件
_UPLOAD_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_UPLOADS)
_SHARE_LOCK = threading.Lock()
_TEMP_PART_RE = re.compile(r"\.[0-9a-f]{8}\.part$")
_SHARE_BAD_CHARS = set('<>:"/\\|?*\r\n\t')


class _ShareError(Exception):
    """上传过程中的可预期失败（带 HTTP 状态码）"""

    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


def _size_text(n):
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.0f}GB"
    if n >= 1024 ** 2:
        return f"{n / 1024 ** 2:.0f}MB"
    return f"{n}B"


def _disk_free():
    """共享目录所在磁盘剩余空间（失败返回 None，不阻断上传）"""
    try:
        return shutil.disk_usage(SHARED_DIR).free
    except Exception:
        return None


def _shared_total_bytes():
    total = 0
    try:
        with os.scandir(SHARED_DIR) as it:
            for e in it:
                try:
                    if e.is_file() and not _is_temp_name(e.name) and not e.name.startswith("."):
                        total += e.stat().st_size
                except Exception:
                    pass
    except Exception:
        pass
    return total


def _is_temp_name(name):
    """只匹配本程序产生的半成品，避免误伤用户上传的 xxx.part 文件"""
    return bool(_TEMP_PART_RE.search(name)) or name.endswith(".reserve")


def _cleanup_stale_parts(max_age=6 * 3600):
    """清理异常退出/断电留下的 .part / .reserve，防止占满磁盘"""
    now = time.time()
    removed = 0
    try:
        with os.scandir(SHARED_DIR) as it:
            for e in it:
                try:
                    if e.is_file() and _is_temp_name(e.name) and now - e.stat().st_mtime > max_age:
                        os.remove(e.path)
                        removed += 1
                except Exception:
                    pass
    except Exception:
        pass
    if removed:
        print(f"[Share] 已清理残留半成品 {removed} 个")


def _is_mobile_ua(ua):
    """手机/平板判定（与前端 IS_PC 逻辑对齐：这些设备不允许上传/下载大文件）"""
    return bool(re.search(r"Mobi|Android|iPhone|iPad|iPod|Windows Phone|HarmonyOS",
                          ua or "", re.I))


def _safe_share_name(name):
    """清洗文件名：去路径、去非法字符，保留中文，限制长度"""
    name = os.path.basename((name or "").replace("\\", "/")).strip()
    name = "".join(ch for ch in name if ch >= " " and ch not in _SHARE_BAD_CHARS)
    name = name.strip(" .")
    if not name:
        name = f"file_{int(time.time())}"
    stem, ext = os.path.splitext(name)
    return stem[:120] + ext[:16]


def _reserve_share_name(name):
    """并发安全地确定最终文件名：用 .reserve 占位，避免两个同名上传互相覆盖"""
    with _SHARE_LOCK:
        stem, ext = os.path.splitext(name)
        cand, i = name, 1
        while (os.path.exists(os.path.join(SHARED_DIR, cand))
               or os.path.exists(os.path.join(SHARED_DIR, cand + ".reserve"))):
            cand = f"{stem}_{i}{ext}"
            i += 1
        try:
            with open(os.path.join(SHARED_DIR, cand + ".reserve"), "xb"):
                pass
        except Exception:
            pass
        return cand


def _release_reserve(name):
    try:
        os.remove(os.path.join(SHARED_DIR, name + ".reserve"))
    except Exception:
        pass


# 启动即清理上次异常退出留下的半成品（防止悄悄占满磁盘）
_cleanup_stale_parts()


def _share_meta(name):
    st = os.stat(os.path.join(SHARED_DIR, name))
    return {
        "name": name,
        "size": st.st_size,
        "time": int(st.st_mtime),
        "url": "/api/download/" + urllib.parse.quote(name),
    }


def _list_shared_files():
    _cleanup_stale_parts()
    out = []
    try:
        for n in os.listdir(SHARED_DIR):
            if n.startswith(".") or _is_temp_name(n):
                continue
            p = os.path.join(SHARED_DIR, n)
            if os.path.isfile(p):
                try:
                    out.append(_share_meta(n))
                except Exception:
                    continue
    except Exception as e:
        print(f"[Share] 列目录失败: {e}")
    out.sort(key=lambda x: x["time"], reverse=True)
    return out


@app.route("/api/files")
def api_files():
    """共享文件列表（仅电脑端）"""
    if _is_mobile_ua(request.headers.get("User-Agent")):
        return jsonify({"ok": False, "msg": "手机端仅支持文字和图片", "files": []}), 403
    return jsonify({
        "ok": True,
        "files": _list_shared_files(),
        "used": _shared_total_bytes(),
        "limits": {
            "max_file": MAX_UPLOAD_BYTES,
            "quota": SHARE_QUOTA_BYTES,
            "concurrency": MAX_CONCURRENT_UPLOADS,
            "max_video": MAX_VIDEO_SECONDS,
            "min_free": MIN_FREE_BYTES,
        },
    })


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """流式接收大文件/视频：分块写盘，内存恒定；原字节保存，不做任何压缩"""
    # 极速剪贴页带 X-LC-Clip: 1 请求头 → 手机也允许传文件（单文件 10MB）
    _is_clip = request.headers.get("X-LC-Clip") == "1"
    _mobile = _is_mobile_ua(request.headers.get("User-Agent"))
    if _mobile and not _is_clip:
        return jsonify({"ok": False, "msg": "手机端仅支持发送文字和图片"}), 403
    _limit = CLIP_MAX_FILE_BYTES if (_is_clip and _mobile) else MAX_UPLOAD_BYTES

    # ★ 必须在访问 request.files（触发接收请求体）之前完成限流与空间检查
    clen = request.content_length or 0
    if clen > _limit + 4 * 1024 * 1024:
        return jsonify({"ok": False, "msg": f"文件超过单文件上限（{_size_text(_limit)}）"}), 413
    if not _UPLOAD_SLOTS.acquire(blocking=False):
        return jsonify({"ok": False, "msg": f"同时上传已达上限（{MAX_CONCURRENT_UPLOADS} 个），请稍后再试"}), 429

    reserved = None
    tmp = None
    try:
        free = _disk_free()
        if free is not None and free < MIN_FREE_BYTES:
            return jsonify({"ok": False, "msg": "服务器磁盘空间不足，请先清理磁盘"}), 507
        used = _shared_total_bytes()
        if used >= SHARE_QUOTA_BYTES:
            return jsonify({"ok": False, "msg": f"共享区已满（上限 {_size_text(SHARE_QUOTA_BYTES)}），请删除旧文件"}), 507

        f = request.files.get("file")
        if f is None or not (f.filename or "").strip():
            return jsonify({"ok": False, "msg": "没有收到文件"}), 400

        reserved = _reserve_share_name(_safe_share_name(f.filename))
        dst = os.path.join(SHARED_DIR, reserved)
        tmp = dst + "." + uuid.uuid4().hex[:8] + ".part"
        total = 0
        next_disk_check = 64 * 1024 * 1024
        try:
            with open(tmp, "wb") as out:
                while True:
                    try:
                        chunk = f.stream.read(UPLOAD_CHUNK)   # ★ 1MB 分块，内存恒定
                    except Exception as e:
                        print(f"[Share] 读取中断（客户端可能断开）: {type(e).__name__}: {e}")
                        raise _ShareError(400, "上传中断，请重试")
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _limit:
                        raise _ShareError(413, f"文件超过单文件上限（{_size_text(_limit)}）")
                    if used + total > SHARE_QUOTA_BYTES:
                        raise _ShareError(507, f"共享区已满（上限 {_size_text(SHARE_QUOTA_BYTES)}）")
                    if total >= next_disk_check:
                        next_disk_check += 64 * 1024 * 1024
                        free = _disk_free()
                        if free is not None and free < MIN_FREE_BYTES:
                            raise _ShareError(507, "服务器磁盘空间不足，已中止上传")
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())                    # 确保真正落盘再改名
            if total == 0:
                raise _ShareError(400, "文件为空")
            os.replace(tmp, dst)
            tmp = None
        except OSError as e:
            print(f"[Share] 写盘失败: {type(e).__name__}: {e}")
            if getattr(e, "errno", None) in (28, 112):    # ENOSPC / ERROR_DISK_FULL
                raise _ShareError(507, "服务器磁盘已满，请清理后再试")
            raise _ShareError(500, "保存失败，请重试")
        finally:
            try:
                f.close()
            except Exception:
                pass

        meta = _share_meta(reserved)
        meta["uploader"] = (request.form.get("uploader") or "").strip()[:20] or "有人"
        print(f"[Share] ✅ {meta['uploader']} 上传 {reserved}（{total // 1024} KB）")
        # 实时推送到所有电脑端的共享文件列表
        try:
            socketio.emit("file_added", meta, room="main")
        except Exception:
            pass
        return jsonify({"ok": True, "file": meta})
    except _ShareError as e:
        return jsonify({"ok": False, "msg": e.msg}), e.code
    except HTTPException as e:
        # 客户端中途断开等协议级异常，不当作服务端故障
        return jsonify({"ok": False, "msg": "上传中断，请重试"}), e.code or 400
    except Exception as e:
        print(f"[Share] 上传失败: {type(e).__name__}: {e}")
        return jsonify({"ok": False, "msg": "保存失败，请重试"}), 500
    finally:
        if tmp:
            try:
                os.remove(tmp)                        # 失败/断连时删掉半成品
            except Exception:
                pass
        if reserved:
            _release_reserve(reserved)
        _UPLOAD_SLOTS.release()


@app.route("/api/download/<path:filename>")
def api_download(filename):
    """原文件下载：不转码、不二次压缩，视频下载后与上传前完全一致"""
    if _is_mobile_ua(request.headers.get("User-Agent")):
        return jsonify({"ok": False, "msg": "手机端仅支持文字和图片"}), 403
    try:
        name = _safe_share_name(filename)
        path = os.path.abspath(os.path.join(SHARED_DIR, name))
        if os.path.dirname(path) != os.path.abspath(SHARED_DIR) or not os.path.isfile(path):
            return jsonify({"ok": False, "msg": "文件不存在或已被删除"}), 404
        return send_file(path, as_attachment=True, download_name=name, conditional=True)
    except Exception as e:
        print(f"[Share] 下载失败: {type(e).__name__}: {e}")
        return jsonify({"ok": False, "msg": "文件不存在或已被删除"}), 404


# ============================================================
#  ⚡ 极速剪贴板（原 LAN-Clipboard 合并进主应用）
#  · 同一端口 / 同一页面 / 同一个二维码，不再需要扫第二个码
#  · 文字：写入本机 Windows 系统剪贴板 + 全员实时同步 + 最近 20 条历史
#  · 文件：复用 /api/upload（手机 ≤10MB、单次 ≤9 个），落到共享目录
# ============================================================
_CLIP_LOCK = threading.Lock()
_SYS_CLIP_LOCK = threading.Lock()   # 系统剪贴板同一时刻只能有一个操作，防并发抢占
_clip_latest = None
_clip_history = deque(maxlen=CLIP_HISTORY_MAX)
_WIN_CLIP_READY = False


def _win_clip_api():
    """初始化 Win32 剪贴板 API（64 位句柄必须声明 restype，否则会被截断）"""
    global _WIN_CLIP_READY
    k32, u32 = ctypes.windll.kernel32, ctypes.windll.user32
    if not _WIN_CLIP_READY:
        k32.GlobalAlloc.restype = ctypes.c_void_p
        k32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
        k32.GlobalLock.restype = ctypes.c_void_p
        k32.GlobalLock.argtypes = [ctypes.c_void_p]
        k32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        k32.GlobalFree.argtypes = [ctypes.c_void_p]
        u32.OpenClipboard.argtypes = [ctypes.c_void_p]
        u32.SetClipboardData.restype = ctypes.c_void_p
        u32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
        u32.GetClipboardData.restype = ctypes.c_void_p
        u32.GetClipboardData.argtypes = [ctypes.c_uint]
        _WIN_CLIP_READY = True
    return k32, u32


def _win_clip_set(text):
    """把文字写入 Windows 系统剪贴板（串行化，避免并发抢占失败）"""
    with _SYS_CLIP_LOCK:
        return _win_clip_set_locked(text)


def _win_clip_set_locked(text):
    """把文字写入 Windows 系统剪贴板（纯 ctypes，无第三方依赖）"""
    if os.name != "nt":
        return False
    try:
        k32, u32 = _win_clip_api()
        data = text.encode("utf-16-le") + b"\x00\x00"
        h = k32.GlobalAlloc(0x0042, len(data))       # GMEM_MOVEABLE | GMEM_ZEROINIT
        if not h:
            return False
        p = k32.GlobalLock(h)
        if not p:
            k32.GlobalFree(h)
            return False
        try:
            ctypes.memmove(p, data, len(data))
        finally:
            k32.GlobalUnlock(h)
        opened = False
        for _ in range(10):                          # 剪贴板可能被别的程序短暂占用
            if u32.OpenClipboard(None):
                opened = True
                break
            time.sleep(0.05)
        if not opened:
            k32.GlobalFree(h)
            return False
        try:
            u32.EmptyClipboard()
            if not u32.SetClipboardData(13, h):      # CF_UNICODETEXT
                k32.GlobalFree(h)                    # 失败时句柄还归我们
                return False
        finally:
            u32.CloseClipboard()
        return True
    except Exception as e:
        print(f"[Clip] 写入系统剪贴板失败: {type(e).__name__}: {e}")
        return False


def _win_clip_get():
    """读取 Windows 系统剪贴板文字（串行化，避免与写入互相抢占）"""
    with _SYS_CLIP_LOCK:
        return _win_clip_get_locked()


def _win_clip_get_locked():
    """读取 Windows 系统剪贴板文字（仅本机）"""
    if os.name != "nt":
        return ""
    try:
        k32, u32 = _win_clip_api()
        if not u32.OpenClipboard(None):
            return ""
        try:
            h = u32.GetClipboardData(13)
            if not h:
                return ""
            p = k32.GlobalLock(h)
            if not p:
                return ""
            try:
                return ctypes.wstring_at(p)
            finally:
                k32.GlobalUnlock(h)
        finally:
            u32.CloseClipboard()
    except Exception as e:
        print(f"[Clip] 读取系统剪贴板失败: {type(e).__name__}: {e}")
        return ""


def _clip_public(item):
    if not item:
        return None
    return {
        "id": item.get("id", ""),
        "text": item.get("text", ""),
        "time": item.get("time", 0),
        "from": item.get("from", ""),
        "clipboard": bool(item.get("clipboard")),
    }


@app.route("/api/clip/info")
def api_clip_info():
    return jsonify({
        "ok": True,
        "max_text": CLIP_MAX_TEXT,
        "history_max": CLIP_HISTORY_MAX,
        "max_files": CLIP_MAX_FILES,
        "max_file_size": CLIP_MAX_FILE_BYTES,
        "clipboard": os.name == "nt",     # 服务端能否写系统剪贴板
        "local": _local_only(),           # 是否电脑本机
    })


@app.route("/api/clip/history")
def api_clip_history():
    with _CLIP_LOCK:
        items = [_clip_public(x) for x in reversed(_clip_history)]
        latest = _clip_public(_clip_latest)
    return jsonify({"ok": True, "items": items, "latest": latest})


@app.route("/api/clip/latest")
def api_clip_latest():
    with _CLIP_LOCK:
        return jsonify({"ok": True, "latest": _clip_public(_clip_latest)})


@app.route("/api/clip/send", methods=["POST"])
def api_clip_send():
    global _clip_latest
    if not _rate_ok("ip:" + (request.remote_addr or "?"), "clip"):
        return jsonify({"ok": False, "msg": "发送太频繁，请稍后再试"}), 429
    data = request.get_json(silent=True)
    if not isinstance(data, dict):          # 防非对象 JSON（数组/字符串）导致 500
        data = {}
    text = str(data.get("text") or "").replace("\r\n", "\n").strip()
    if not text:
        return jsonify({"ok": False, "msg": "内容为空"}), 400
    if len(text) > CLIP_MAX_TEXT:
        return jsonify({"ok": False, "msg": f"文字超过 {CLIP_MAX_TEXT} 字上限"}), 413
    who = (data.get("name") or "").strip()[:20] or "有人"
    ok = _win_clip_set(text)
    item = {
        "id": uuid.uuid4().hex[:12],
        "text": text,
        "time": int(time.time()),
        "from": who,
        "clipboard": ok,
    }
    with _CLIP_LOCK:
        _clip_latest = item
        _clip_history.append(item)
    try:
        socketio.emit("clip_new", _clip_public(item), room="main")
    except Exception:
        pass
    print(f"[Clip] {who} 剪贴 {len(text)} 字 · 系统剪贴板{'已写入' if ok else '写入失败'}")
    return jsonify({"ok": True, "item": _clip_public(item), "clipboard": ok})


@app.route("/api/clip/clear", methods=["POST"])
def api_clip_clear():
    global _clip_latest
    with _CLIP_LOCK:
        _clip_history.clear()
        _clip_latest = None
    try:
        socketio.emit("clip_clear", {}, room="main")
    except Exception:
        pass
    return jsonify({"ok": True})


@app.route("/api/clip/paste")
def api_clip_paste():
    """电脑本机：读取系统剪贴板，方便一键同步到手机"""
    if not _local_only():
        return jsonify({"ok": False, "msg": "仅电脑本机可用"}), 403
    text = _win_clip_get()
    return jsonify({"ok": True, "text": text, "len": len(text)})


@app.route("/api/clip/files")
def api_clip_files():
    """极速剪贴的最近文件（手机也能看、能下载）"""
    return jsonify({
        "ok": True,
        "files": _list_shared_files()[:20],
        "max_files": CLIP_MAX_FILES,
        "max_file_size": CLIP_MAX_FILE_BYTES,
    })


@app.route("/api/clip/download/<path:filename>")
def api_clip_download(filename):
    """极速剪贴的文件下载：手机也能直接下载（/api/download 仅限电脑）"""
    try:
        name = _safe_share_name(filename)
        path = os.path.abspath(os.path.join(SHARED_DIR, name))
        if os.path.dirname(path) != os.path.abspath(SHARED_DIR) or not os.path.isfile(path):
            return jsonify({"ok": False, "msg": "文件不存在或已被删除"}), 404
        return send_file(path, as_attachment=True, download_name=name, conditional=True)
    except Exception as e:
        # 文件刚好被删除/被占用时不抛 500，给前端一个可读提示
        print(f"[Clip] 下载失败: {type(e).__name__}: {e}")
        return jsonify({"ok": False, "msg": "文件不存在或已被删除"}), 404


@app.before_request
def _clip_body_guard():
    """剪贴接口限制请求体大小，防止超大 JSON 在解析阶段占满内存"""
    if request.path.startswith("/api/clip/") and (request.content_length or 0) > 256 * 1024:
        return jsonify({"ok": False, "msg": "请求内容过大"}), 413


# ====== PWA 图标根路径（Safari 会兜底找 /apple-touch-icon.png 等） ======
@app.route("/apple-touch-icon.png")
@app.route("/apple-touch-icon-precomposed.png")
@app.route("/favicon.ico")
@app.route("/favicon.png")
@app.route("/apple-touch-icon-120x120.png")
def serve_pwa_icon():
    return send_from_directory(os.path.join(RES_DIR, "static"), "icon-192.png", mimetype="image/png")



@app.errorhandler(Exception)
def _handle_all_exceptions(e):
    # HTTP 错误（404/403 等）原样返回，不要变成 500
    try:
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return e
    except Exception:
        pass
    """任何未捕获异常都只返回 500，不让进程崩溃"""
    try:
        print(f"[Flask] 未捕获异常: {type(e).__name__}: {e}")
    except Exception:
        pass
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "msg": "服务端处理出错，请重试"}), 500
    return "服务端处理出错", 500

# ====== SocketIO 事件 ======

# ============================================================
#  一次性邀请码（手机扫码绑定）
#   · 每次电脑端刷新二维码 = 生成新 token
#   · 第一个扫码的手机绑定该 token，其它手机用同一 token 会被拒
#   · 同一部手机（同 device id）可重新进入
# ============================================================
import secrets

INVITE = {"token": "", "dev": "", "ts": 0}
INVITE_TTL = 3600 * 6          # 6 小时内有效


def _save_invite(token):
    """把 token 写进 config.json（重启不作废）"""
    try:
        p = os.path.join(BASE_DIR, "config.json")
        cfg = {}
        if os.path.isfile(p):
            try:
                cfg = json.load(open(p, encoding="utf-8-sig"))
            except Exception:
                cfg = {}
        cfg["invite_token"] = token
        with open(p, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[Invite] 保存失败: {e}")


def _load_invite():
    try:
        p = os.path.join(BASE_DIR, "config.json")
        if os.path.isfile(p):
            cfg = json.load(open(p, encoding="utf-8-sig"))
            v = str(cfg.get("invite_token") or "").strip()
            if v:
                return v
    except Exception:
        pass
    return ""

def _invite_new():
    INVITE["token"] = secrets.token_urlsafe(9)
    INVITE["dev"] = ""
    INVITE["ts"] = time.time()
    _save_invite(INVITE["token"])
    print(f"[Invite] 新二维码 token={INVITE['token']}")
    return INVITE["token"]


def _device_type(ua):
    """按 User-Agent 判断设备类型（仅用于显示标签）"""
    ua = (ua or "").lower()
    if "iphone" in ua or "ipad" in ua or "ipod" in ua:
        return "iOS"
    if "android" in ua:
        return "Android"
    return "PC"

def _load_bound_dev():
    """读取已绑定手机的设备 id（持久化）"""
    try:
        p = os.path.join(BASE_DIR, "config.json")
        if os.path.isfile(p):
            cfg = json.load(open(p, encoding="utf-8-sig"))
            return str(cfg.get("bound_dev") or "")
    except Exception:
        pass
    return ""


def _save_bound_dev(dev):
    """保存已绑定手机的设备 id"""
    try:
        p = os.path.join(BASE_DIR, "config.json")
        cfg = {}
        if os.path.isfile(p):
            try:
                cfg = json.load(open(p, encoding="utf-8-sig"))
            except Exception:
                cfg = {}
        cfg["bound_dev"] = dev or ""
        with open(p, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        print(f"[Bind] 已保存绑定设备: {dev[:10]}")
    except Exception as e:
        print(f"[Bind] 保存失败: {e}")

_BOUND_DEV = _load_bound_dev()


def _invite_ok(token, dev):
    """校验邀请码：
       · token 必须匹配（旧码立即失效）
       · 同一部手机（dev 相同）随时可进
       · 不同手机进来时：只要求"当前没有别的手机在线"
         → 不会因为手机清缓存/换浏览器而永久锁死
    """
    if not INVITE["token"]:
        return True, "no_invite"
    if time.time() - INVITE["ts"] > INVITE_TTL:
        return False, "二维码已过期，请在电脑端刷新二维码"
    if token != INVITE["token"]:
        return False, "二维码已更新，请重新扫码"

    dev = dev or ""
    bound = INVITE.get("dev") or ""

    if not dev:
        # 客户端没带设备 id（Safari 限制存储时常见）→ 直接放行
        return True, "no_dev"

    if not bound:
        INVITE["dev"] = dev
        return True, "bound"

    if dev == bound:
        return True, "same_device"

    # 不同设备：只有当"已绑定的那台确实还活着"时才拒绝
    # 关键：只算最近 120 秒内有活动的会话，避免僵尸连接挡住新手机
    _now = time.time()
    online_devs = set()
    for _sid, _u in users.items():
        _d = _u.get("dev")
        if _d and (_now - _LAST_ACTIVE.get(_sid, 0) < 120):
            online_devs.add(_d)
    if bound in online_devs:
        return False, "此二维码正在被另一台手机使用，请在电脑端刷新二维码"

    INVITE["dev"] = dev
    return True, "rebound"



@socketio.on("connect")
@_safe_handler
def on_connect(auth=None):
    # 人数上限（写死 30，硬性拦截）
    if len(users) >= MAX_USERS:
        print(f"[Limit] 在线已满 {MAX_USERS}，拒绝新连接")
        try:
            emit("room_full", {"text": f"会议室已满（安全上限 {MAX_USERS} 人），请稍后再试或联系管理员"})
        except Exception:
            pass
        return False

    _auth = auth if isinstance(auth, dict) else {}
    _inv = str(_auth.get("inv") or request.args.get("inv") or "")
    _dev = str(_auth.get("dev") or request.args.get("dev") or "")
    _ip = (request.remote_addr or "").replace("::ffff:", "")

    # 🔒 连接频率限制（按 IP，1 分钟最多 5 次，防爆连）
    if not _rate_ok(_ip, "connect"):
        print(f"[Limit] 连接过于频繁，拒绝：{_ip}")
        try:
            emit("rate_limited", {"text": "连接过于频繁，请 1 分钟后再试"})
        except Exception:
            pass
        return False

    # 🚫 封禁检查：IP 或设备 id 任一命中即拒绝
    _ban = _is_banned(_ip) or _is_banned(_dev)
    if _ban:
        remain = max(0, int(_ban.get("until", 0) - time.time()))
        reason = _ban.get("reason", "你已被封禁")
        print(f"[Ban] 拒绝被封禁用户连接：ip={_ip} dev={_dev[:8]} reason={reason}")
        try:
            emit("banned", {"text": reason, "remain_sec": remain})
        except Exception:
            pass
        return False
    # 只有"电脑窗口自己"（带 host=1）才算本机；
    # 手机经 TLS 转发进来时 IP 也是 127.0.0.1，不能靠 IP 判断
    # 本机 = 回环地址；手机走 TLS 转发时，转发层会从局域网 IP 连回来，
    # 所以这里可以安全地按 IP 判定，不再依赖 URL 参数（否则拷走 exe 可绕过保护）
    _is_local = _ip in ("127.0.0.1", "::1", "localhost")
    if _is_local:
        pass   # 本机永远放行（开源版已移除授权系统）
    else:
        # 🔒 PIN 码校验（只对局域网设备生效，本机不受限）
        if PIN_CODE:
            _pin = str(_auth.get("pin") or request.args.get("pin") or "")
            if _pin != PIN_CODE:
                print(f"[PIN] ❌ PIN 码错误，拒绝 {_ip}")
                raise ConnectionRefusedError({
                    "code": "pin_required",
                    "text": "需要 PIN 码才能加入",
                    "pin_length": len(PIN_CODE),
                })
        print(f"[Auth] ✅ 局域网设备放行：{_ip}")

    # ---- 邀请码校验（手机必须带有效 token，本机除外）----
    _is_host_phone = False
    if not _is_local:
        # 邀请码：有就校验并打标签；没有/失效也放行（否则客户直接进不去）
        if _inv:
            try:
                _ok, _why = _invite_ok(_inv, _dev)
            except Exception:
                _ok, _why = False, "error"
            if _ok and _why in ("bound", "same_device"):
                _is_host_phone = True
            elif not _ok:
                _diag(f"邀请码未通过但放行: {_why} | inv={_inv[:10]} dev={_dev[:8]}")
        else:
            _diag(f"无邀请码放行: ip={_ip} dev={_dev[:8]}")

        # ★ 已绑定手机按"设备 id"认人，并写入 config.json（重启不丢）
        global _BOUND_DEV
        if not _is_host_phone:
            if _BOUND_DEV and _dev and _dev == _BOUND_DEV:
                _is_host_phone = True                      # 就是那台手机回来了
            elif not _BOUND_DEV and _dev:
                _BOUND_DEV = _dev
                _is_host_phone = True
                _save_bound_dev(_dev)
                print(f"[Bind] 第一台手机已绑定并保存 dev={_dev[:10]}")
    sid = request.sid
    # 是否电脑端（前端用 ?pc=1 标记；手机不传）
    _is_pc = (request.args.get("pc") == "1")
    # 只有电脑端、且当前没有管理员在线时，才成为管理员
    has_admin = any(u.get("is_admin") for u in users.values())
    is_admin = bool(_is_pc and not has_admin)
    users[sid] = {
        "id": sid,
        "name": ("主机" if _is_local else ("主手机" if _is_host_phone else f"用户{len(users)+1}")),
        "color": pick_color(),
        "is_admin": is_admin,
        "is_pc": _is_pc,
        "dev": _dev,
        "ip": _ip,
        "device_type": _device_type(request.headers.get("User-Agent", "")),
        "is_host": _is_local,          # 主机电脑
        "is_host_phone": _is_host_phone,   # 主机绑定的手机（副号）
        "muted": False,
    }
    join_room("main")
    _touch(sid)
    u = users[sid]
    print(f"[+] {u['name']} ({sid[:6]}) 加入 · admin={is_admin}")

    # 告诉新人自己的信息
    emit("self_info", {"id": sid, **u})
    # 广播新人加入
    emit("system_msg", {"text": f"{u['name']} 加入了通讯台", "ts": int(time.time()*1000)}, room="main")
    # 给所有人刷新用户列表
    broadcast_users()
    # 给新人发送历史消息
    # 历史只下发给"最近 10 条含媒体"，更早的媒体替换成占位，避免一次几十 MB
    _hist = []
    _tail = messages[-200:]
    _cut = max(0, len(_tail) - 10)
    for _i, _m in enumerate(_tail):
        if _i < _cut and _m.get("type") in ("image", "voice"):
            _mm = {k: v for k, v in _m.items() if k not in ("image", "voice")}
            _mm["omitted"] = True
            _hist.append(_mm)
        else:
            _hist.append(_m)
    emit("history", {"messages": _hist})

@socketio.on("disconnect")
@_safe_handler
def on_disconnect(reason=None):
    global _VOICE_OWNER, _RTC_HOST
    sid = request.sid
    if _VOICE_OWNER == sid:
        _VOICE_OWNER = None
        emit("voice_free", {}, room="main")
    _LAST_ACTIVE.pop(sid, None)
    _rate_cleanup(sid)         # 清理该用户所有限流计数
    # 断线时自动退出实时语音，通知其他人拆掉这条 P2P 连接
    if sid == _RTC_HOST:
        _RTC_HOST = None       # Host 断线 → 清掉星形中心
    _rtc_info = _RTC_PEERS.pop(sid, None)
    if _rtc_info:
        try:
            emit("rtc_peer_left", {"sid": sid, "name": _rtc_info["name"],
                                   "was_host": (_RTC_HOST is None)},
                 room="main", include_self=False)
            emit("rtc_state", {"count": len(_RTC_PEERS)}, room="main")
        except Exception:
            pass
    if sid in users:
        u = users.pop(sid)
        print(f"[-] {u['name']} ({sid[:6]}) 离开")
        # 管理员退出 → 移交给下一个在线的电脑端用户
        if u.get("is_admin"):
            for _sid, _u in users.items():
                if _u.get("is_pc"):
                    _u["is_admin"] = True
                    try:
                        broadcast_users()
                        emit("system_msg", {"text": f"{_u['name']} 接任管理员", "ts": int(time.time()*1000)}, room="main")
                    except Exception:
                        pass
                    print(f"[Admin] 移交给 {_u['name']}")
                    break
        emit("system_msg", {"text": f"{u['name']} 离开了", "ts": int(time.time()*1000)}, room="main")
        broadcast_users()

MEDIA_BUDGET = 50 * 1024 * 1024   # 内存里媒体总字节上限（50MB）


def _trim_media():
    """媒体总量超预算时，从最旧的开始丢掉 base64（保留占位）"""
    try:
        total = 0
        for m in messages:
            if m.get("type") == "image":
                total += len(m.get("image") or "")
            elif m.get("type") == "voice":
                total += len(m.get("voice") or "")
        if total <= MEDIA_BUDGET:
            return
        for m in messages:
            if total <= MEDIA_BUDGET:
                break
            if m.get("type") == "image" and m.get("image"):
                total -= len(m["image"])
                m.pop("image", None)
                m["omitted"] = True
            elif m.get("type") == "voice" and m.get("voice"):
                total -= len(m["voice"])
                m.pop("voice", None)
                m["omitted"] = True
    except Exception:
        pass

def broadcast_users():
    """向 main 房间广播当前用户列表"""
    emit("user_list", {"users": list(users.values())}, room="main")

# ---------- 用户改昵称 ----------
@socketio.on("set_name")
@_safe_handler
def on_set_name(data):
    sid = request.sid
    _touch(sid)
    if sid not in users: return
    if not _rate_ok(sid, "name"):
        try:
            emit("name_invalid", {"msg": "改名太频繁，请稍后再试"})
        except Exception:
            pass
        return
    name = (data.get("name") or "").strip()
    # 只允许汉字，1~4 字
    if not re.fullmatch(r"[\u4e00-\u9fa5A-Za-z0-9]{1,6}", name or ""):
        try:
            emit("name_invalid", {"msg": "昵称只能是 1~6 个字符（汉字/字母/数字）"})
        except Exception:
            pass
        return
    old = users[sid]["name"]
    users[sid]["name"] = name
    broadcast_users()
    emit("self_info", {"id": sid, **users[sid]})
    emit("system_msg", {"text": f"{old} 改名为 {name}", "ts": int(time.time()*1000)}, room="main")



@socketio.on("leave_room")
def on_leave_room(data=None):
    """用户主动退出聊天室"""
    sid = request.sid
    u = users.get(sid)
    if u:
        print(f"[-] {u['name']} 主动退出")
        emit("system_msg", {"text": f"{u['name']} 离开了通讯台",
                            "ts": int(time.time()*1000)}, room="main")
        users.pop(sid, None)
        _LAST_ACTIVE.pop(sid, None)
        try:
            socketio.server.disconnect(sid)
        except Exception:
            pass

# ---------- 语音排队：同一时刻只允许一个人说话 ----------
@socketio.on("voice_start")
@_safe_handler
def on_voice_start(data=None):
    global _VOICE_OWNER
    sid = request.sid
    _touch(sid)
    if sid not in users:
        return {"ok": False, "msg": "你还没进房间"}
    if _VOICE_OWNER and _VOICE_OWNER != sid and _VOICE_OWNER in users:
        return {"ok": False, "msg": f"{_voice_name(_VOICE_OWNER)} 正在发言，请稍后", "owner": _voice_name(_VOICE_OWNER)}
    _VOICE_OWNER = sid
    try:
        global _VOICE_START
        _VOICE_START = time.time()
    except Exception:
        pass
    emit("voice_busy", {"name": _voice_name(sid)}, room="main", include_self=False)
    return {"ok": True}


@socketio.on("voice_end")
@_safe_handler
def on_voice_end(data=None):
    global _VOICE_OWNER
    sid = request.sid
    if _VOICE_OWNER == sid:
        _VOICE_OWNER = None
        _VOICE_START = 0
        emit("voice_free", {}, room="main", include_self=False)


# ============================================================
#  WebRTC 实时语音信令（借鉴 MiniMost calls.py）
#  · 星形拓扑：第一个加入 RTC 的人为 Host（主持人）
#  · Host 可以对任何成员发起一对一对讲
#  · 非 Host 只能对 Host 对讲（成员之间互不直通）
#  · 这样最多同时只有 1 条 P2P 连接，程序稳定不崩溃
#  服务器只转发 SDP / ICE，音频流走 P2P 直连，不占服务器带宽
# ============================================================
_RTC_PEERS = {}   # sid -> {"name": str, "muted": bool}
_RTC_HOST = None  # 星形拓扑的中心（第一个加入 RTC 的人）
_RTC_LOCK = threading.Lock()


@socketio.on("rtc_join")
@_safe_handler
def on_rtc_join(data=None):
    """加入实时语音频道；第一个加入的成为 Host（主持人）"""
    global _RTC_HOST
    sid = request.sid
    _touch(sid)
    u = users.get(sid)
    if not u:
        return {"ok": False, "msg": "你还没进房间"}
    with _RTC_LOCK:
        # 第一个加入的自动成为 Host
        if _RTC_HOST is None:
            _RTC_HOST = sid
            _host_msg = "你已成为对讲主持人"
            _is_host = True
        else:
            _is_host = False
            _host_msg = f"对讲主持人：{_RTC_PEERS.get(_RTC_HOST, {}).get('name', '主持人')}"
        existing = [{"sid": p, "name": v["name"], "muted": v.get("muted", False),
                     "color": v.get("color", "#64748b"),
                     "is_host": (p == _RTC_HOST)}
                    for p, v in _RTC_PEERS.items() if p != sid]
        _RTC_PEERS[sid] = {"name": u["name"], "muted": False,
                           "color": u.get("color", "#64748b")}
    # 新人通过 ack 拿到老成员列表（星形规则：成员列表里只有 Host 需要 offer）
    # 前端拿到 host_sid 后会自动：非 host → 只对 host offer；host → 对新人 offer
    emit("rtc_peer_joined", {"sid": sid, "name": u["name"],
                             "color": u.get("color", "#64748b"),
                             "is_host": _is_host},
         room="main", include_self=False)
    emit("system_msg", {"text": f"{u['name']} 加入了实时语音（{_host_msg}）",
                        "ts": int(time.time()*1000)}, room="main")
    emit("rtc_state", {"count": len(_RTC_PEERS)}, room="main")
    print(f"[RTC] {u['name']} 加入实时语音（host={'YES' if _is_host else 'no'} · 总 {len(_RTC_PEERS)} 人）")
    return {"ok": True, "peers": existing, "host_sid": _RTC_HOST, "is_host": _is_host}


@socketio.on("rtc_leave")
@_safe_handler
def on_rtc_leave(data=None):
    """离开实时语音频道；Host 退出不自动移交（其他人重新进 RTC 才能成为 Host）"""
    global _RTC_HOST
    sid = request.sid
    with _RTC_LOCK:
        info = _RTC_PEERS.pop(sid, None)
        if sid == _RTC_HOST:
            _RTC_HOST = None   # Host 退出 → 清掉，后续没人能对谁对讲
    if not info:
        return
    _was_host = (sid == _RTC_HOST or _RTC_HOST is None)
    emit("rtc_peer_left", {"sid": sid, "name": info["name"], "was_host": _was_host},
         room="main", include_self=False)
    emit("rtc_state", {"count": len(_RTC_PEERS)}, room="main")
    msg = {"text": f"{info['name']} 退出了实时语音", "ts": int(time.time()*1000)}
    emit("system_msg", msg, room="main")
    print(f"[RTC] {info['name']} 离开实时语音（was_host={_was_host}）")


@socketio.on("rtc_signal")
@_safe_handler
def on_rtc_signal(data):
    """信令中转 + 星形规则校验：
    · Host 可以发给任何人；任何人也可以发给 Host
    · 非 Host 之间互相发 → 直接拒绝（避免 mesh 连接爆炸）"""
    sid = request.sid
    _touch(sid)
    if sid not in _RTC_PEERS:
        return
    data = data or {}
    target = data.get("to")
    if target not in _RTC_PEERS:
        return
    # ★ 星形规则：非 Host 只能跟 Host 通信
    if sid != _RTC_HOST and target != _RTC_HOST:
        emit("rtc_signal_reject",
             {"reason": "non_host_no_p2p", "to": target}, to=sid)
        return
    payload = {"from": sid, "name": _RTC_PEERS.get(sid, {}).get("name", "")}
    if data.get("sdp"):
        payload["sdp"] = data["sdp"]
    if data.get("ice"):
        payload["ice"] = data["ice"]
    emit("rtc_signal", payload, to=target)


@socketio.on("rtc_mute")
@_safe_handler
def on_rtc_mute(data=None):
    """同步静音状态给其他通话成员"""
    sid = request.sid
    if sid not in _RTC_PEERS:
        return
    muted = bool((data or {}).get("muted"))
    with _RTC_LOCK:
        if sid in _RTC_PEERS:
            _RTC_PEERS[sid]["muted"] = muted
    emit("rtc_peer_mute",
         {"sid": sid, "name": _RTC_PEERS.get(sid, {}).get("name", ""), "muted": muted},
         room="main", include_self=False)



# ---------- 文字消息 ----------
@socketio.on("chat_text")
@_safe_handler
def on_chat_text(data):
    sid = request.sid
    _touch(sid)
    if sid not in users: return
    if not _rate_ok(sid, "text"):
        emit("muted_warning", {"text": "发送太频繁，请稍后再试"}, to=sid)
        return
    u = users[sid]
    if u["muted"]:
        emit("muted_warning", {"text": "你已被禁言"}, to=sid)
        return
    text = (data.get("text") or "").strip()[:2000]
    if not text: return
    msg = {
        "id": uuid.uuid4().hex[:12], "type": "text",
        "from": sid, "name": u["name"], "color": u["color"],
        "text": text, "ts": int(time.time()*1000),
    }
    messages.append(msg)
    if len(messages) > MAX_HISTORY: messages.pop(0)
    _trim_media()
    _history_save(msg)   # 💾 持久化
    emit("chat_msg", msg, room="main")

# ---------- 图片消息（base64 直传） ----------
@socketio.on("chat_image")
@_safe_handler
def on_chat_image(data):
    sid = request.sid
    _touch(sid)
    if sid not in users: return
    if not _rate_ok(sid, "image"):
        emit("muted_warning", {"text": "发图太频繁，请稍后再试"}, to=sid)
        return
    u = users[sid]
    if u["muted"]:
        emit("muted_warning", {"text": "你已被禁言"}, to=sid)
        return
    image = data.get("image") or ""
    # 写死：只接受图片（JPEG/PNG/WebP/GIF），其它一律丢弃
    _ALLOWED = ("data:image/jpeg;", "data:image/jpg;", "data:image/png;",
                "data:image/webp;", "data:image/gif;")
    if not image.startswith(_ALLOWED):
        print(f"[Image] 拦截非图片内容：{str(image)[:40]}")
        return
    # 防止超大图片撑爆内存 / 断线（前端已压缩，这里是兜底）
    if len(image) > MAX_IMAGE_B64:
        # 静默丢弃（前端已压到 200KB，这里是异常兜底，不打扰用户）
        print(f"[Image] 静默丢弃超大图片：{len(image)//1024} KB")
        return
    msg = {
        "id": uuid.uuid4().hex[:12], "type": "image",
        "from": sid, "name": u["name"], "color": u["color"],
        "image": image, "ts": int(time.time()*1000),
    }
    messages.append(msg)
    if len(messages) > MAX_HISTORY: messages.pop(0)
    _trim_media()
    _history_save(msg)   # 💾 持久化
    emit("chat_msg", msg, room="main")

# ---------- 语音对讲（二进制流） ----------
@socketio.on("voice_data")
@_safe_handler
def on_voice_data(data):
    """前端传来 base64 编码的音频 blob"""
    sid = request.sid
    _touch(sid)
    if sid not in users: return
    if not _rate_ok(sid, "voice"):
        emit("muted_warning", {"text": "发语音太频繁，请稍后再试"}, to=sid)
        return
    u = users[sid]
    if u["muted"]: return
    voice = data.get("voice") or ""  # base64 data URL
    duration = data.get("duration", 0)
    if not voice or duration <= 0 or duration > MAX_VOICE_MS:
        return
    if len(voice) > MAX_VOICE_B64:
        emit("muted_warning", {"text": "语音太长/太大，已丢弃"}, to=sid)
        return
    msg = {
        "id": uuid.uuid4().hex[:12], "type": "voice",
        "from": sid, "name": u["name"], "color": u["color"],
        "voice": voice, "duration": duration, "ts": int(time.time()*1000),
    }
    messages.append(msg)
    if len(messages) > MAX_HISTORY: messages.pop(0)
    _trim_media()
    _history_save(msg)   # 💾 持久化
    emit("chat_msg", msg, room="main")

# ---------- 管理员操作 ----------
@socketio.on("admin_kick")
@_safe_handler
def on_admin_kick(data):
    sid = request.sid
    if sid not in users or not users[sid]["is_admin"]: return
    target = data.get("target_id")
    if target in users and target != sid:
        emit("kicked", {"text": "你被管理员移出了"}, to=target)
        emit("system_msg", {"text": f"{users[target]['name']} 被移出了", "ts": int(time.time()*1000)}, room="main")
        # 让前端断开
        socketio.server.disconnect(target)

@socketio.on("admin_mute")
@_safe_handler
def on_admin_mute(data):
    sid = request.sid
    if sid not in users or not users[sid]["is_admin"]: return
    target = data.get("target_id")
    mute = bool(data.get("mute", True))
    if target in users:
        users[target]["muted"] = mute
        broadcast_users()
        emit("system_msg", {"text": f"{users[target]['name']} {'已禁言' if mute else '解除禁言'}", "ts": int(time.time()*1000)}, room="main")

@socketio.on("admin_clear")
@_safe_handler
def on_admin_clear(data=None):
    sid = request.sid
    if sid not in users or not users[sid]["is_admin"]: return
    messages.clear()
    _history_clear()   # 💾 同步清空 DB
    emit("chat_clear", {}, room="main")
    emit("system_msg", {"text": "管理员清空了聊天记录", "ts": int(time.time()*1000)}, room="main")

# ---------- 管理员封禁 / 解封 ----------
@socketio.on("admin_ban")
@_safe_handler
def on_admin_ban(data):
    """封禁某用户：封其 IP + 设备 id，默认 60 分钟"""
    sid = request.sid
    if sid not in users or not users[sid]["is_admin"]: return
    target = data.get("target_id")
    minutes = int(data.get("minutes", 60))
    if minutes < 0: minutes = 0  # 0 = 永久
    reason = (data.get("reason") or "违反规则").strip()[:60]
    if target not in users or target == sid:
        return
    tu = users[target]
    by_name = users[sid]["name"]
    # 双维度封禁：设备 id（必封）+ 局域网 IP（有条件封）
    t_ip = tu.get("ip", "")
    t_dev = tu.get("dev", "")
    if t_dev:
        _ban_identifier(t_dev, minutes * 60, reason, by_name)
    # IP 封禁要防连坐：TLS/穿透转发时所有手机在服务端看起来是同一个 IP
    if _ip_ban_safe(t_ip):
        _ban_identifier(t_ip, minutes * 60, reason, by_name)
    dur_text = "永久" if minutes == 0 else f"{minutes} 分钟"
    try:
        emit("banned", {"text": f"你已被封禁 {dur_text}：{reason}",
                         "remain_sec": minutes * 60}, to=target)
    except Exception:
        pass
    emit("system_msg", {"text": f"{tu['name']} 被封禁 {dur_text}（{reason}）",
                        "ts": int(time.time()*1000)}, room="main")
    print(f"[Ban] {by_name} 封禁 {tu['name']} ip={t_ip} dev={t_dev[:8]} {dur_text}")
    socketio.server.disconnect(target)
    broadcast_users()


@socketio.on("admin_unban")
@_safe_handler
def on_admin_unban(data):
    """解封（按 identifier：IP 或设备 id）"""
    sid = request.sid
    if sid not in users or not users[sid]["is_admin"]: return
    identifier = (data.get("identifier") or "").strip()
    if _unban_identifier(identifier):
        emit("system_msg", {"text": f"管理员解除了封禁",
                            "ts": int(time.time()*1000)}, room="main")


@socketio.on("admin_banlist")
@_safe_handler
def on_admin_banlist(data=None):
    """管理员查询当前封禁列表"""
    sid = request.sid
    if sid not in users or not users[sid]["is_admin"]: return
    now = time.time()
    active = {}
    for k, v in _BANS.items():
        remain = v.get("until", 0) - now
        if remain > 0:
            # IP 全显，dev id 截断显示
            show = k if ":" in k or "." in k else k[:12] + "…"
            active[k] = {"remain_sec": int(remain), "reason": v.get("reason", ""), "show": show}
    try:
        emit("ban_list", {"bans": active}, to=sid)
    except Exception:
        pass


# ---------- 正在输入（转发给其他人） ----------
@socketio.on("typing")
@_safe_handler
def on_typing(data):
    sid = request.sid
    _touch(sid)
    if sid not in users: return
    u = users[sid]
    _t = (data.get("text") or "").strip()
    if not _t:
        return          # 心跳保活不该被当成"正在输入"
    emit("typing", {
        "from": sid,
        "name": u["name"],
        "text": _t[:200],
    }, room="main", include_self=False)


# ============================================================
#  双端口启动：5443=HTTPS(主) / 5050=HTTP(证书下载 + 跳转)
# ============================================================
def run_https_main(port=None):
    port = port or HTTPS_PORT
    try:
        socketio.run(app, host="0.0.0.0", port=port,
                     debug=False, allow_unsafe_werkzeug=True,
                     ssl_context=(SRV_CERT, SRV_KEY))
    except Exception as e:
        print(f"[HTTPS] ❌ 启动失败: {e}")


def _build_http_helper():
    """HTTP 小站：只负责下载证书 + 跳转 https"""
    from flask import Flask as _F, send_file as _send
    helper = _F("http_helper")

    @helper.route("/ca.mobileconfig")
    def _ca_mc():
        if not os.path.isfile(CA_CERT):
            ensure_certs()
        data = build_mobileconfig()
        if not data:
            return "描述文件生成失败", 500
        return _send(io.BytesIO(data), mimetype="application/x-apple-aspen-config",
                     as_attachment=True, download_name="lansync.mobileconfig")

    @helper.route("/ca")
    def _ca_crt():
        if not os.path.isfile(CA_CERT):
            ensure_certs()
        with open(CA_CERT, "rb") as f:
            pem = f.read()
        return _send(io.BytesIO(pem), mimetype="application/x-x509-ca-cert",
                     as_attachment=True, download_name="lansync-ca.crt")

    @helper.route("/https-info")
    def _hi():
        _off = (_net_mode() == "offline")
        return {"ok": True, "offline_voice": _off, "https_url": _https_url(),
                "https_port": HTTPS_PORT, "mode": _net_mode(), "online": NET.get("online"),
                "ca_url": f"http://{HOST_IP}:{HTTP_PORT}/ca.mobileconfig"}

    return helper



# ============================================================
#  TLS 转发：5443 收 https 请求 → 转给本机 5050 的同一个服务
#  这样 http 和 https 的用户在同一个房间里（不会分家）
# ============================================================
LOCAL_DOMAIN = "lansync.local"


def _start_mdns():
    """广播 lansync.local → 本机 IP，iPhone 可直接访问该域名"""
    try:
        from zeroconf import Zeroconf, ServiceInfo
        import socket as _s

        ip = HOST_IP
        info = ServiceInfo(
            "_http._tcp.local.",
            "LanSync._http._tcp.local.",
            addresses=[_s.inet_aton(ip)],
            port=HTTPS_PORT,
            properties={"path": "/"},
            server=f"{LOCAL_DOMAIN}.",
        )
        zc = Zeroconf()
        zc.register_service(info)
        print(f"[mDNS] ✅ {LOCAL_DOMAIN} → {ip}（手机可用域名访问）")
        try:
            zc2 = Zeroconf()
            zc2.register_service(info, allow_name_change=True)
        except Exception:
            pass
        return zc
    except Exception as e:
        print(f"[mDNS] 广播失败: {e}")
        return None


def _domain_url():
    return f"https://{LOCAL_DOMAIN}:{HTTPS_PORT}"

def run_tls_proxy(listen_port=None, target_port=None):
    listen_port = listen_port or HTTPS_PORT
    target_port = target_port or HTTP_PORT
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(SRV_CERT, SRV_KEY)

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", listen_port))
        srv.listen(64)
        print(f"[TLS] ✅ https 转发已启动：https://{HOST_IP}:{listen_port} → 127.0.0.1:{target_port}")

        def pump(a, b):
            # 两条独立线程阻塞转发（长轮询/WebSocket 都不会被超时切断）
            def forward(src, dst):
                try:
                    while True:
                        data = src.recv(65536)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception:
                    pass
                finally:
                    for s_ in (src, dst):
                        try:
                            s_.shutdown(socket.SHUT_RDWR)
                        except Exception:
                            pass
                        try:
                            s_.close()
                        except Exception:
                            pass

            threading.Thread(target=forward, args=(a, b), daemon=True).start()
            threading.Thread(target=forward, args=(b, a), daemon=True).start()

        def handle(conn):
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                # 从局域网 IP 连回（让服务端看到的是"手机"而不是"本机"）
                try:
                    upstream = socket.create_connection((HOST_IP, target_port), timeout=6)
                except Exception:
                    upstream = socket.create_connection(("127.0.0.1", target_port), timeout=10)
                upstream.settimeout(None)      # 关键：长轮询/WebSocket 不能被 10 秒超时掐断
                try:
                    tls.settimeout(None)
                except Exception:
                    pass
                pump(tls, upstream)
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

        while True:
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except Exception as e:
                print(f"[TLS] accept 异常: {e}")
                time.sleep(0.5)
    except Exception as e:
        print(f"[TLS] ❌ 转发启动失败: {e}")


def run_http_helper():
    try:
        from werkzeug.serving import run_simple
        helper = _build_http_helper()
        run_simple("0.0.0.0", HTTP_PORT, helper, threaded=True, use_reloader=False)
    except Exception as e:
        print(f"[HTTP] ❌ 启动失败: {e}")

# ====== 程序启动 ======
def run_flask(port):
    """后台线程：启动 Flask-SocketIO"""
    try:
        socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
    except Exception as e:
        print(f"[Flask] ❌ 启动失败: {e}")

def wait_flask(port, timeout=15, https=False):
    """等 Flask 就绪（https 时忽略证书校验）"""
    deadline = time.time() + timeout
    scheme = "https" if https else "http"
    url = f"{scheme}://127.0.0.1:{port}/"
    _ctx = ssl._create_unverified_context() if https else None
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1, context=_ctx).read(10)
            return True
        except Exception:
            # 同时试试 127.0.0.1（某些机器 localhost 解析慢）
            try:
                urllib.request.urlopen(f"{scheme}://127.0.0.1:{port}/", timeout=1, context=_ctx).read(10)
                return True
            except Exception:
                time.sleep(0.3)
    return False

def _crash_log(msg):
    """frozen 模式下写崩溃日志到 exe 同级目录"""
    if getattr(sys, 'frozen', False):
        log_dir = os.path.dirname(sys.executable)
        log_path = os.path.join(log_dir, "LanSync-crash.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")

if __name__ == "__main__":
    try:
        port = int(sys.argv[1]) if len(sys.argv) > 1 else 5050
        _MAIN_PORT = port

        # 端口占用 → 直接退出，避免两个实例各服务一半
        if not _port_free(port):
            _diag(f"端口 {port} 已被占用 → 打开已有实例")
            # 已经在运行：直接打开现有页面，并提示用户（不再"点了没反应"）
            try:
                import webbrowser
                webbrowser.open(f"http://127.0.0.1:{port}/?host=1")
            except Exception:
                pass
            try:
                import ctypes
                # 2.5 秒自动关闭的提示框（不阻塞、不残留进程）
                ctypes.windll.user32.MessageBoxTimeoutW(
                    0,
                    "LanSync 已经在运行。\n已为你打开浏览器页面。\n\n（本提示 5 秒后自动关闭）\n"
                    f"若浏览器没打开，请手动访问 http://127.0.0.1:{port}/?host=1",
                    "LanSync", 0x40, 0, 5000)
            except Exception:
                pass
            sys.exit(0)

        _saved = _load_invite()
        if _saved:
            INVITE["token"] = _saved
            INVITE["ts"] = time.time()
            print(f"[Invite] 复用上次二维码 token={_saved}")
        else:
            _invite_new()   # 首次启动生成

        # ① HTTP 主服务（唯一聊天服务，所有端口共用这一套会话）
        _diag("main 开始")
        # 💾 历史消息持久化（借鉴 WuKongIM）
        _history_init()
        ensure_certs()
        threading.Thread(target=run_flask, args=(port,), daemon=True).start()
        # ★ 巡检线程（以前漏了启动，导致空闲踢人/僵尸清理形同虚设）
        try:
            # 空闲不自动踢人（踢人只归管理员）；只清理真正断开的连接
            threading.Thread(target=_stale_sweep, daemon=True).start()
            _diag("已启动：断线僵尸清理（不做空闲踢人）")
            print("[Clean] 断线清理线程已启动（空闲不踢人）")
        except Exception as e:
            print(f"[Idle] 巡检线程启动失败: {e}")
        # ①.2 外网探测 → 决定走公网隧道还是本地 HTTPS
        _online = _probe_with_timeout(3.0)
        NET["online"] = _online
        NET["checked_at"] = time.time()
        if NO_TUNNEL:
            print("🛑 配置 no_tunnel=true → 纯局域网模式（同 WiFi 直连，不绕公网）")
        elif OFFLINE_VOICE:
            print("🔐 配置强制离线语音模式（本地 https，需装证书）")
        elif _online:
            print("🌐 外网可用 → 公网隧道模式（扫码即用，无需证书）")
        else:
            print("🔌 外网不可用 → 自动切离线语音模式（本地 https:5443，手机需装证书）")

        # 本地 HTTPS 通道始终开启：断网时可立即切过去，联网时也不影响主服务
        threading.Thread(target=run_tls_proxy, daemon=True).start()
        threading.Thread(target=_start_mdns, daemon=True).start()

        # 外网可用且未禁用隧道时才起隧道；断网恢复由 _net_watch 补启
        if _online and not OFFLINE_VOICE and not NO_TUNNEL:
            def _boot_tunnel():
                time.sleep(3)
                _diag("tunnel 线程开始")
                ok = wait_flask(port, timeout=10)
                _diag(f"tunnel 探测 flask={ok}")
                if ok:
                    start_tunnel(port)
            threading.Thread(target=_boot_tunnel, daemon=True).start()

        # 外网状态巡检（8 秒一次，断网/恢复自动切换）
        threading.Thread(target=_net_watch, daemon=True).start()

        # ② 等 Flask 起来
        if not wait_flask(port, timeout=20):
            _crash_log("Flask 启动超时")
            sys.exit(1)

        url = f"http://127.0.0.1:{port}/?host=1"
        print("=" * 50)
        print("  📡 私域内网多端协同枢纽")
        print("=" * 50)
        print(f"  本机访问:   {url}")
        print(f"  局域网:     http://{HOST_IP}:{port}")
        if _net_mode() == "offline":
            print("  语音模式:   离线 https://%s:%s  (需装证书，断网也能用)" % (HOST_IP, HTTPS_PORT))
        else:
            print("  语音模式:   公网隧道（扫码即用，无需证书；断网自动切本地）")
        print(f"  装证书:     http://{HOST_IP}:{HTTP_PORT}/ca.mobileconfig")
        print(f"  局域网访问: http://{HOST_IP}:{port}")
        print(f"  第一个连接的用户 = 管理员")
        print("=" * 50)

        # ③ 打开桌面窗口（不再依赖浏览器）
        try:
            import webview
            print("🪟 正在打开桌面窗口…")
            webview.create_window(
                "私域内网多端协同枢纽",
                url,                      # 始终用本机 http，避免证书提示
                width=1280, height=860,
                min_size=(900, 600),
                text_select=True,
            )
            # private_mode=False + storage_path：保留 localStorage（卡密/设备 id 不丢）
            try:
                _wd = os.path.join(BASE_DIR, "webview_data")
                os.makedirs(_wd, exist_ok=True)
                webview.start(private_mode=False, storage_path=_wd)
            except TypeError:
                webview.start()
            print("窗口已关闭，程序退出")
            _shutdown_and_exit(0)
        except Exception as e:
            print(f"⚠️ 桌面窗口启动失败：{e}，回退到浏览器")
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:
                pass
            while True:
                time.sleep(3600)

    except Exception as e:
        _crash_log(f"未捕获异常: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        print(f"❌ 启动失败: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        stop_tunnel()
        print("\n👋 已退出")
