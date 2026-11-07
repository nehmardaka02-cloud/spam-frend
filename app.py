import asyncio
import httpx
from aiohttp import web
import time
import os
import re
import json
import random
import uuid
import jwt as pyjwt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from colorama import Fore, Style, init

from test import Codec, enc_ae, KEY, IV

API_KEY = "masjon"
API_HOST = "0.0.0.0"
API_PORT = int(os.environ.get("SERVER_PORT", "8572"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ACCS_FILE = os.path.join(BASE_DIR, "test.txt")
TOKEN_FILE = os.path.join(BASE_DIR, "data.json")

init(autoreset=True)
G = Fore.LIGHTGREEN_EX
W = Fore.WHITE
R = Fore.LIGHTRED_EX
C = Fore.LIGHTCYAN_EX
B = Style.BRIGHT

FR_ACCOUNTS = []
FR_TOKENS = {}
FR_READY_COUNT = 0
SPAM_RUN = {}
SPAM_STATS = {}
SPAM_TOTAL = 0
SPAM_LOCK = asyncio.Lock()

client = httpx.AsyncClient(
    verify=False,
    timeout=15.0,
    limits=httpx.Limits(max_connections=300, max_keepalive_connections=150)
)

headers = {
    'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Expect': '100-continue',
    'X-Unity-Version': '2018.4.12f1',
    'X-GA-SV': '1789535859',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB55'
}


def mk_major_payload(open_id, access_token, client_version="1.132.13"):
    fields = {
        3: time.strftime("%Y-%m-%d %H:%M:%S"),
        4: "free fire",
        5: 1,
        7: str(client_version),
        8: "Android OS 14 / API-34",
        9: "Handheld",
        10: "Mobilis",
        11: "WIFI",
        12: 1600,
        13: 900,
        14: "240",
        15: "x86-64 SSE3 SSE4.1 SSE4.2 AVX | 2865 | 6",
        16: 5944,
        17: "Adreno (TM) 750",
        18: "OpenGL ES 3.1 v1",
        19: f"Google|{uuid.uuid4()}",
        20: f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        21: "ar",
        22: str(open_id),
        23: "4",
        24: "Handheld",
        25: "samsung SM-N9860",
        26: "ME",
        29: str(access_token),
        30: 1,
        41: "Mobilis",
        42: "WIFI",
        57: "7428b253defc164018c604a1ebbfebdf",
        60: 52691,
        61: 48409,
        62: 2519,
        63: 70,
        64: 23306,
        65: 25131,
        66: 50733,
        67: 52691,
        73: 3,
        74: "/data/app/lib/arm64",
        76: 1,
        77: "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/base.apk",
        78: 3,
        79: 2,
        81: "64",
        83: "2019121229",
        85: 3,
        86: "OpenGLES2",
        87: 8191,
        88: 4,
        89: "KqsHT6dXfrd81vpmdClMMxZM3UCc59ys5/2cX5FVcMpI3tlWy8d0r8ZWGSBj+06/cGbBzY3JULeYT1rb5tBtz7+GCis6kpkGPjl2SSoYhrjsQOvA",
        92: 7303,
        93: "android",
        94: "KqsHT6dXfrd81vpmdClMMxZM3UCc59ys5/2cX5FVcMpI3tlWy8d0r8ZWGSBj+06/cGbBzY3JULeYT1rb5tBtz7+GCis6kpkGPjl2SSoYhrjsQOvA",
        95: 111207,
        96: '{"cur_rate":null,"support_etc2":false}',
        97: 1,
        98: 1,
        99: "4",
        100: "4",
        102: b"",
        104: 62270,
        105: 1,
        106: "https://dl.gmc.freefiremobile.com/live/ABHotUpdates/|https://core-gmc.freefiremobile.com/live/ABHotUpdates/|4a0070ac356973792f002e0b25b96c3b",
        107: "c8e41b7a93f02d56e1a94c7b8203f5d1",
    }
    raw = Codec.enc(fields)
    return enc_ae(raw, KEY, IV)


def parse_major(raw):
    for off in range(0, min(200, max(0, len(raw) - 32))):
        f = Codec.dec(raw[off:])
        if 8 in f:
            v = f[8][0]
            if isinstance(v, (bytes, bytearray)) and len(v) > 100 and bytes(v[:3]) == b'eyJ':
                return f
    return None


def Encrypt_ID(x):
    return Codec.vi(int(x)).hex()


def enc_friend_payload(target_id):
    return "08c8b5cfea1810" + Encrypt_ID(target_id) + "18012008"


def encrypt_hex(hex_str):
    return AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(bytes.fromhex(hex_str), AES.block_size)).hex()


def is_valid_token(tok):
    if not tok or not isinstance(tok, str):
        return False
    tok = tok.strip()
    if len(tok) < 20:
        return False
    if tok.lower() in ("error", "null", "none", "false", "undefined", "0"):
        return False
    return True


def load_tokens():
    tk = {}
    if not os.path.exists(TOKEN_FILE):
        return tk
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                uid, tok = line.split(":", 1)
                if uid.strip() and tok.strip():
                    tk[uid.strip()] = tok.strip()
    except Exception:
        pass
    return tk


def save_tokens(tk):
    try:
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            for uid, tok in tk.items():
                f.write(f"{uid}:{tok}\n")
    except Exception:
        pass


def read_accs(path):
    if not os.path.exists(path):
        return []
    accs = []
    seen = set()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r'[|:,\s]+', line, maxsplit=1)
            if len(parts) < 2:
                continue
            uid, pwd = parts[0].strip(), parts[1].strip()
            if uid and pwd and uid not in seen:
                seen.add(uid)
                accs.append((uid, pwd))
    return accs


class Net:
    @staticmethod
    async def oauth(u, p):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        hdrs = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B Build/SP1A.210812.016)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        data = {
            "uid": u,
            "password": p,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        for _ in range(5):
            try:
                response = await client.post(url, headers=hdrs, data=data)
                if response.status_code == 200:
                    j = response.json()
                    payload = j.get("data", j)
                    oid = payload.get("open_id")
                    at = payload.get("access_token")
                    if oid and at:
                        return oid, at
                if response.status_code == 429:
                    await asyncio.sleep(1)
                    continue
            except Exception:
                pass
            await asyncio.sleep(0.5)
        return None

    @staticmethod
    async def send_majorlogin(data, release_version, server_url):
        try:
            url = f"{server_url}MajorLogin" if server_url.endswith('/') else f"{server_url}/MajorLogin"
            hdrs = headers.copy()
            hdrs["ReleaseVersion"] = str(release_version)
            r = await client.post(url, headers=hdrs, data=data)
            return r.content if r.status_code == 200 else None
        except Exception:
            return None


async def send_friend_req_async(target_id, token):
    try:
        body = bytes.fromhex(encrypt_hex(enc_friend_payload(target_id)))
        r = await client.post(
            "https://clientbp.ppmainecoonghj.com/RequestAddingFriend",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB55",
                "Host": "clientbp.ppmainecoonghj.com",
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
                "Connection": "keep-alive",
                "Authorization": f"Bearer {token}",
                "X-Unity-Version": "2018.4.12f1",
                "Accept": "*/*",
            },
            content=body,
            timeout=10,
        )
        return r.status_code == 200
    except Exception:
        return False


async def spam_worker_friend(target_uid):
    global SPAM_TOTAL
    SPAM_RUN[target_uid] = True
    SPAM_STATS[target_uid] = {"success": 0, "failed": 0, "total": 0}
    try:
        while SPAM_RUN.get(target_uid, False):
            for uid, _ in FR_ACCOUNTS:
                if not SPAM_RUN.get(target_uid, False):
                    break
                tok = FR_TOKENS.get(str(uid))
                if not is_valid_token(tok):
                    continue
                ok = await send_friend_req_async(target_uid, tok)
                if ok:
                    SPAM_STATS[target_uid]["success"] += 1
                else:
                    SPAM_STATS[target_uid]["failed"] += 1
                SPAM_STATS[target_uid]["total"] += 1
                async with SPAM_LOCK:
                    SPAM_TOTAL += 1
                await asyncio.sleep(0.15)
    finally:
        SPAM_RUN[target_uid] = False


async def fetch_fr_token(uid, pwd):
    try:
        auth = await Net.oauth(uid, pwd)
        if not auth:
            return None, None
        open_id, access_token = auth
        payload = mk_major_payload(open_id, access_token, "1.132.13")
        raw = await Net.send_majorlogin(payload, "OB55", "https://loginbp.ppmainecoonghj.com")
        if not raw:
            return None, None
        f = parse_major(raw)
        if not f:
            return None, None
        jwt_tok = f[8][0].decode()
        dj = pyjwt.decode(jwt_tok, options={"verify_signature": False})
        return jwt_tok, int(dj.get("account_id"))
    except Exception:
        return None, None


async def init_fr_tokens():
    global FR_ACCOUNTS, FR_READY_COUNT
    try:
        FR_ACCOUNTS = read_accs(ACCS_FILE)
        if not FR_ACCOUNTS:
            print(f"No accounts found in test.txt")
            return
        saved = load_tokens()
        ready = 0
        for uid, pwd in FR_ACCOUNTS:
            if is_valid_token(saved.get(str(uid))):
                FR_TOKENS[str(uid)] = saved[str(uid)]
                ready += 1
                continue
            try:
                jwt_tok, acc_id = await asyncio.wait_for(fetch_fr_token(uid, pwd), timeout=20)
            except asyncio.TimeoutError:
                continue
            if is_valid_token(jwt_tok):
                FR_TOKENS[str(uid)] = jwt_tok
                ready += 1
            await asyncio.sleep(0.2)
        FR_READY_COUNT = ready
        save_tokens(FR_TOKENS)
        print(f"Accounts ready => {FR_READY_COUNT}/{len(FR_ACCOUNTS)}")
    except Exception as e:
        print(f"init_fr_tokens error: {e}")


def check_api_key(request):
    key = request.query.get("api_key") or request.headers.get("X-API-Key")
    return key == API_KEY


async def api_spam(request):
    if not check_api_key(request):
        return web.json_response({"ok": False, "error": "Invalid api_key"}, status=401)

    target_uid = request.query.get("uid", "").strip()
    if not target_uid or not target_uid.isdigit():
        return web.json_response({"ok": False, "error": "uid required (digits only)"}, status=400)

    if SPAM_RUN.get(target_uid):
        return web.json_response({
            "ok": True,
            "message": "Spam already running",
            "target": target_uid,
            "stats": SPAM_STATS.get(target_uid, {})
        })

    if not FR_ACCOUNTS:
        return web.json_response({"ok": False, "error": "No accounts in test.txt"}, status=400)

    if not any(is_valid_token(t) for t in FR_TOKENS.values()):
        return web.json_response({"ok": False, "error": "No valid tokens"}, status=400)

    asyncio.create_task(spam_worker_friend(target_uid))
    return web.json_response({
        "ok": True,
        "message": "Spam started",
        "target": target_uid,
        "accounts": FR_READY_COUNT,
    })


async def api_stop(request):
    if not check_api_key(request):
        return web.json_response({"ok": False, "error": "Invalid api_key"}, status=401)

    target_uid = request.query.get("uid", "").strip()
    if not target_uid or not target_uid.isdigit():
        return web.json_response({"ok": False, "error": "uid required (digits only)"}, status=400)

    if not SPAM_RUN.get(target_uid):
        return web.json_response({"ok": False, "error": "Spam not running for this uid"}, status=400)

    SPAM_RUN[target_uid] = False
    return web.json_response({
        "ok": True,
        "message": "Spam stopped",
        "target": target_uid,
        "stats": SPAM_STATS.get(target_uid, {}),
    })


async def api_status(request):
    if not check_api_key(request):
        return web.json_response({"ok": False, "error": "Invalid api_key"}, status=401)

    target_uid = request.query.get("uid", "").strip()
    if target_uid:
        return web.json_response({
            "ok": True,
            "target": target_uid,
            "running": bool(SPAM_RUN.get(target_uid)),
            "stats": SPAM_STATS.get(target_uid, {}),
            "accounts_ready": FR_READY_COUNT,
        })

    return web.json_response({
        "ok": True,
        "accounts_ready": FR_READY_COUNT,
        "accounts_total": len(FR_ACCOUNTS),
        "running": {k: bool(v) for k, v in SPAM_RUN.items() if v},
        "stats": SPAM_STATS,
    })


async def start_api_server():
    app = web.Application()
    app.router.add_get("/spam", api_spam)
    app.router.add_get("/stop", api_stop)
    app.router.add_get("/status", api_status)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, API_HOST, API_PORT)
    await site.start()

    print(f"{G}{B}API Online => http://{API_HOST}:{API_PORT}{W}")
    print(f"{C}  /spam?uid=TARGET_UID&api_key={API_KEY}{W}")
    print(f"{C}  /stop?uid=TARGET_UID&api_key={API_KEY}{W}")
    print(f"{C}  /status?api_key={API_KEY}{W}")
    print()


async def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    
    await init_fr_tokens()
    await start_api_server()

    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
