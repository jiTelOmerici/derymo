#!/usr/bin/env python3
"""3x-ui Telegram Bot — генерирует Clash/Sing-box конфиги"""

import asyncio, logging, random, string, os, io, json, base64, urllib.parse
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, BufferedInputFile
import aiohttp
import yaml

# ==================== CONFIG ====================
PANEL_URL  = os.getenv("PANEL_URL",  "")
API_TOKEN  = os.getenv("API_TOKEN",  "")
TG_TOKEN   = os.getenv("TG_TOKEN",   "")
ADMIN_IDS  = [int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()]
GROQ_KEY   = os.getenv("GROQ_KEY",   "")
SUB_URL    = os.getenv("SUB_URL",    "")
SUB_PATH   = os.getenv("SUB_PATH",   "/sub/")
CLASH_PATH = os.getenv("CLASH_PATH", "/clash/")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

bot = Bot(token=TG_TOKEN)
dp  = Dispatcher()

# in-memory state
user_states: dict[int, str] = {}
tickets: dict[int, dict]    = {}
ticket_seq = 0

# ==================== 3x-ui API ====================
async def api(path: str, method="GET") -> dict:
    async with aiohttp.ClientSession() as s:
        fn = s.get if method == "GET" else s.post
        async with fn(
            f"{PANEL_URL}/panel/api{path}",
            headers={"Authorization": f"Bearer {API_TOKEN}"},
            ssl=False, timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            return await r.json()

async def find_client(tg_id: int) -> dict | None:
    """Ищет клиента по tgId во всех инбаундах"""
    data = await api("/inbounds/list")
    if not data.get("success"):
        return None
    for inb in data.get("obj", []):
        settings = inb.get("settings", {})
        if isinstance(settings, str):
            try: settings = json.loads(settings)
            except: continue
        for c in settings.get("clients", []):
            if str(c.get("tgId", "")) == str(tg_id):
                return {"client": c, "inbound": inb,
                        "sub_id": c.get("subId", ""), "email": c.get("email", "")}
    return None

# ==================== UTILS ====================
def rand_pass(n=12) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def rand_port() -> int:
    return random.randint(20000, 50000)

def username_from(email: str) -> str:
    return email.split("_")[0].split("@")[0]

# ==================== SUB DOWNLOAD ====================
async def dl(url: str) -> str:
    async with aiohttp.ClientSession() as s:
        async with s.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status != 200:
                raise ValueError(f"HTTP {r.status}")
            return await r.text()

async def get_proxy_links(sub_id: str) -> list[str]:
    raw = await dl(f"{SUB_URL}{SUB_PATH}{sub_id}")
    try:
        decoded = base64.b64decode(raw.strip() + "==").decode()
        return [l.strip() for l in decoded.splitlines() if l.strip()]
    except:
        return [l.strip() for l in raw.splitlines() if l.strip()]

# ==================== CLASH ====================
async def make_clash(sub_id: str, user: str, pwd: str, port: int) -> str:
    raw = await dl(f"{SUB_URL}{CLASH_PATH}{sub_id}")
    cfg = yaml.safe_load(raw)
    if not cfg:
        raise ValueError("Пустой Clash конфиг")
    cfg["mixed-port"]      = port
    cfg["port"]            = 0
    cfg["socks-port"]      = 0
    cfg["authentication"]  = [f"{user}:{pwd}"]
    cfg["allow-lan"]       = False
    cfg["bind-address"]    = "127.0.0.1"
    cfg.setdefault("mode", "rule")
    cfg.setdefault("log-level", "info")
    cfg.setdefault("dns", {
        "enable": True, "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "nameserver": ["https://dns.cloudflare.com/dns-query","https://dns.google/dns-query"],
    })
    return yaml.dump(cfg, allow_unicode=True, default_flow_style=False)

# ==================== SING-BOX ====================
def parse_vless(uri: str) -> dict | None:
    try:
        p = urllib.parse.urlparse(uri)
        q = dict(urllib.parse.parse_qsl(p.query))
        tag = urllib.parse.unquote(p.fragment) or f"vless-{p.hostname}"
        ob = {
            "type": "vless", "tag": tag,
            "server": p.hostname, "server_port": p.port or 443,
            "uuid": p.username, "packet_encoding": "xudp",
        }
        if q.get("flow"): ob["flow"] = q["flow"]
        sec = q.get("security", "none")
        if sec in ("tls", "reality"):
            tls = {"enabled": True, "server_name": q.get("sni") or p.hostname}
            if q.get("fp"): tls["utls"] = {"enabled": True, "fingerprint": q["fp"]}
            if sec == "reality":
                tls["reality"] = {"enabled": True,
                                   "public_key": q.get("pbk",""), "short_id": q.get("sid","")}
            ob["tls"] = tls
        net = q.get("type","tcp")
        if net == "ws":
            ob["transport"] = {"type":"ws","path":q.get("path","/")}
        elif net in ("xhttp","splithttp"):
            ob["transport"] = {"type":"http","path":q.get("path","/")}
        elif net == "grpc":
            ob["transport"] = {"type":"grpc","service_name":q.get("serviceName","")}
        return ob
    except Exception as e:
        log.warning(f"vless parse: {e}")
        return None

def parse_hy2(uri: str) -> dict | None:
    try:
        p = urllib.parse.urlparse(uri)
        q = dict(urllib.parse.parse_qsl(p.query))
        tag = urllib.parse.unquote(p.fragment) or f"hy2-{p.hostname}"
        pwd = p.password or p.username or ""
        ob = {
            "type": "hysteria2", "tag": tag,
            "server": p.hostname, "server_port": p.port or 443,
            "password": pwd,
            "tls": {"enabled": True, "server_name": q.get("sni") or p.hostname, "alpn": ["h3"]},
        }
        if q.get("fp"): ob["tls"]["utls"] = {"enabled": True, "fingerprint": q["fp"]}
        if q.get("obfs") and q.get("obfs-password"):
            ob["obfs"] = {"type": q["obfs"], "password": q["obfs-password"]}
        return ob
    except Exception as e:
        log.warning(f"hy2 parse: {e}")
        return None

def make_singbox(links: list[str], user: str, pwd: str, port: int) -> dict:
    proxies, tags = [], []
    for l in links:
        ob = None
        if l.startswith("vless://"): ob = parse_vless(l)
        elif l.startswith(("hysteria2://","hy2://")): ob = parse_hy2(l)
        if ob:
            proxies.append(ob)
            tags.append(ob["tag"])
    if not proxies:
        raise ValueError("Нет поддерживаемых прокси")
    return {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag":"google","address":"tls://8.8.8.8","detour":"proxy"},
                {"tag":"local","address":"tls://223.5.5.5","detour":"direct"},
            ],
            "rules": [{"outbound":["any"],"server":"local"}],
            "final": "local", "independent_cache": True,
        },
        "inbounds": [{
            "type":"mixed","tag":"mixed-in",
            "listen":"127.0.0.1","listen_port":port,
            "users":[{"username":user,"password":pwd}],
            "set_system_proxy": False,
        }],
        "outbounds": [
            {"type":"selector","tag":"proxy","outbounds":["auto"]+tags,"default":"auto"},
            {"type":"urltest","tag":"auto","outbounds":tags,
             "url":"https://www.gstatic.com/generate_204","interval":"5m","tolerance":50},
            {"type":"direct","tag":"direct"},
            {"type":"block","tag":"block"},
        ] + proxies,
        "route": {
            "rules": [
                {"protocol":["dns"],"action":"hijack-dns"},
                {"ip_is_private":True,"outbound":"direct"},
            ],
            "final":"proxy","auto_detect_interface":True,
        }
    }

# ==================== GROQ ====================
async def ask_groq(q: str) -> tuple[str,bool]:
    if not GROQ_KEY:
        return "Ваш вопрос передан администратору.", True
    async with aiohttp.ClientSession() as s:
        async with s.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization":f"Bearer {GROQ_KEY}","Content-Type":"application/json"},
            json={"model":"llama-3.1-8b-instant","temperature":0.3,"max_tokens":400,
                  "messages":[
                      {"role":"system","content":
                       "Ты — техподдержка VPN. Отвечай кратко по-русски, 3-4 предложения. "
                       "Если проблема серверная — напиши 'Вопрос передан администратору'."},
                      {"role":"user","content":q}]},
            ssl=False, timeout=aiohttp.ClientTimeout(total=20)
        ) as r:
            if r.status != 200:
                return "Ваш вопрос передан администратору.", True
            d = await r.json()
    ans = d["choices"][0]["message"]["content"]
    return ans, "передан администратору" in ans.lower()

# ==================== KEYBOARDS ====================
def main_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⚙️ Clash",    callback_data="getclash"),
         InlineKeyboardButton(text="📦 Sing-box", callback_data="getsingbox")],
        [InlineKeyboardButton(text="💬 Поддержка", callback_data="support")],
    ])

# ==================== HANDLERS ====================
@dp.message(Command("start","help"))
async def h_start(m: types.Message):
    await m.answer(
        f"👋 Привет, <b>{m.from_user.first_name}</b>!\n\n"
        "Выберите действие или используйте команды:\n"
        "/getclash — Clash Meta конфиг\n"
        "/getsingbox — Sing-box конфиг\n"
        "/support — Техподдержка",
        parse_mode="HTML", reply_markup=main_kb())

# --- CLASH ---
async def do_clash(m: types.Message, tg_id: int):
    wait = await m.answer("⏳ Генерирую Clash конфиг...")
    try:
        ci = await find_client(tg_id)
        if not ci:
            return await wait.edit_text("❌ Профиль не найден. Обратитесь к администратору.")
        user, pwd, port = username_from(ci["email"]), rand_pass(), rand_port()
        data = await make_clash(ci["sub_id"], user, pwd, port)
        f = BufferedInputFile(data.encode(), "clash-config.yaml")
        cap = (f"✅ <b>Clash Meta конфиг</b>\n\n"
               f"📌 Порт: <code>{port}</code>\n"
               f"🔐 Логин: <code>{user}</code>\n"
               f"🔐 Пароль: <code>{pwd}</code>\n\n"
               f"<b>Инструкция:</b>\n1. Сохраните файл\n2. Clash Meta → Профили → Импорт\n3. Активируйте")
        await wait.delete()
        await m.answer_document(f, caption=cap, parse_mode="HTML")
    except Exception as e:
        await wait.edit_text(f"❌ Ошибка: {e}")

@dp.message(Command("getclash"))
async def h_getclash_cmd(m: types.Message): await do_clash(m, m.from_user.id)

@dp.callback_query(F.data == "getclash")
async def h_getclash_cb(cb: types.CallbackQuery):
    await cb.answer()
    await do_clash(cb.message, cb.from_user.id)

# --- SING-BOX ---
async def do_singbox(m: types.Message, tg_id: int):
    wait = await m.answer("⏳ Генерирую Sing-box конфиг...")
    try:
        ci = await find_client(tg_id)
        if not ci:
            return await wait.edit_text("❌ Профиль не найден. Обратитесь к администратору.")
        user, pwd, port = username_from(ci["email"]), rand_pass(), rand_port()
        links = await get_proxy_links(ci["sub_id"])
        if not links:
            return await wait.edit_text("❌ Не удалось получить прокси-ключи.")
        cfg = make_singbox(links, user, pwd, port)
        f = BufferedInputFile(json.dumps(cfg, ensure_ascii=False, indent=2).encode(), "singbox-config.json")
        cap = (f"✅ <b>Sing-box конфиг</b>\n\n"
               f"📌 Порт: <code>{port}</code>\n"
               f"🔐 Логин: <code>{user}</code>\n"
               f"🔐 Пароль: <code>{pwd}</code>\n\n"
               f"<b>Инструкция:</b>\n1. Сохраните файл\n2. Sing-box → Конфиги → Импорт\n3. Активируйте")
        await wait.delete()
        await m.answer_document(f, caption=cap, parse_mode="HTML")
    except Exception as e:
        await wait.edit_text(f"❌ Ошибка: {e}")

@dp.message(Command("getsingbox"))
async def h_getsingbox_cmd(m: types.Message): await do_singbox(m, m.from_user.id)

@dp.callback_query(F.data == "getsingbox")
async def h_getsingbox_cb(cb: types.CallbackQuery):
    await cb.answer()
    await do_singbox(cb.message, cb.from_user.id)

# --- SUPPORT ---
async def do_support(m: types.Message, question: str):
    global ticket_seq
    wait = await m.answer("⏳ Обрабатываю вопрос...")
    ans, escalate = await ask_groq(question)
    ticket_seq += 1
    tid = ticket_seq
    tickets[tid] = {"user_id": m.from_user.id, "question": question}
    text = f"🤖 <b>Ответ:</b>\n\n{ans}"
    if escalate:
        text += f"\n\n📨 Тикет #{tid} создан. Администратор ответит в ближайшее время."
    await wait.delete()
    await m.answer(text, parse_mode="HTML")
    if escalate:
        for aid in ADMIN_IDS:
            try:
                await bot.send_message(aid,
                    f"🎫 <b>Тикет #{tid}</b>\n\n"
                    f"👤 @{m.from_user.username or '—'} (<code>{m.from_user.id}</code>)\n\n"
                    f"❓ {question}\n\n🤖 {ans}\n\n"
                    f"Ответить: <code>/reply {tid} текст</code>",
                    parse_mode="HTML")
            except: pass

@dp.message(Command("support"))
async def h_support_cmd(m: types.Message):
    q = m.text.replace("/support","",1).strip()
    if q:
        await do_support(m, q)
    else:
        user_states[m.from_user.id] = "support"
        await m.answer("💬 <b>Техподдержка</b>\n\nНапишите ваш вопрос:", parse_mode="HTML")

@dp.callback_query(F.data == "support")
async def h_support_cb(cb: types.CallbackQuery):
    await cb.answer()
    user_states[cb.from_user.id] = "support"
    await cb.message.answer("💬 <b>Техподдержка</b>\n\nНапишите ваш вопрос:", parse_mode="HTML")

# --- REPLY (admin) ---
@dp.message(Command("reply"))
async def h_reply(m: types.Message):
    if m.from_user.id not in ADMIN_IDS:
        return
    parts = m.text.split(maxsplit=2)
    if len(parts) < 3:
        return await m.answer("❌ Формат: /reply <id> <текст>")
    try: tid = int(parts[1])
    except: return await m.answer("❌ Неверный ID")
    t = tickets.get(tid)
    if not t: return await m.answer(f"❌ Тикет #{tid} не найден")
    await bot.send_message(t["user_id"],
        f"📨 <b>Ответ от администратора на тикет #{tid}:</b>\n\n{parts[2]}",
        parse_mode="HTML")
    await m.answer(f"✅ Ответ отправлен на тикет #{tid}")

# --- CATCH-ALL ---
@dp.message()
async def h_any(m: types.Message):
    state = user_states.pop(m.from_user.id, None)
    if state == "support":
        await do_support(m, m.text)
    # иначе молчим

# ==================== MAIN ====================
async def main():
    log.info("Bot started")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
