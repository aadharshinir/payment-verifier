from fastapi import FastAPI, Request
from twilio.rest import Client
from dotenv import load_dotenv
from openai import OpenAI

import os
import httpx
import base64
import io
import re
from PIL import Image

load_dotenv()

app = FastAPI()

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_NUMBER = os.getenv("TWILIO_WHATSAPP_NUMBER")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
openai_client = OpenAI(api_key=OPENAI_API_KEY)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

def supabase_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json"
    }

# ── Demo blacklist (for hackathon demo only) ───────────────────────────────────
KNOWN_FRAUD_IDS = {
    "TXN123FAKE",
    "UTR000000000",
    "FRAUDTXN999",
}
# ─────────────────────────────────────────────────────────────────────────────

# Track which users are in "report mode"
pending_reports = set()

LANGUAGE_MAP = {
    "1": "English",
    "2": "Tamil",
    "3": "Hindi",
    "4": "Telugu",
    "5": "Malayalam"
}

def validate_transaction_id(txn_id: str) -> tuple[bool, str]:
    if not txn_id or txn_id == "NOT_FOUND":
        return False, "No transaction ID found in screenshot"
    txn_id = txn_id.strip().replace(" ", "")
    if re.fullmatch(r"[A-Za-z0-9]{12,20}", txn_id):
        return True, "Valid UPI/UTR transaction ID format"
    return False, f"Transaction ID '{txn_id}' does not match any known payment format"

def calculate_fraud_score(
    format_valid: bool,
    in_blacklist: bool,
    tamper_result: dict
) -> tuple[int, str, list[str]]:
    score = 0
    reasons = []

    if not format_valid:
        score += 40
        reasons.append("Transaction ID format is invalid or missing")

    if in_blacklist:
        score += 60
        reasons.append("Transaction ID is in the fraud blacklist")

    if tamper_result.get("is_tampered"):
        score += 30
        reasons.append(f"Screenshot appears edited: {tamper_result.get('reason', 'suspicious elements detected')}")

    score = min(score, 100)

    if score <= 30:
        verdict = "VERIFIED"
    elif score <= 59:
        verdict = "SUSPICIOUS"
    else:
        verdict = "FRAUD"

    return score, verdict, reasons

def hash_image(image_bytes: bytes) -> str:
    import hashlib
    return hashlib.md5(image_bytes).hexdigest()

def get_welcome_message() -> str:
    return (
        "👋 *Welcome to Payment Fraud Detector!*\n\n"
        "I can verify payment screenshots in under 3 seconds.\n\n"
        "Please select your language:\n"
        "1️⃣ English\n"
        "2️⃣ Tamil — தமிழ்\n"
        "3️⃣ Hindi — हिंदी\n"
        "4️⃣ Telugu — తెలుగు\n"
        "5️⃣ Malayalam — മലയാളം\n\n"
        "Reply with the number of your choice!"
    )

def get_help_message() -> str:
    return (
        "🤖 *Payment Fraud Detector — Help*\n\n"
        "Here's what I can do:\n\n"
        "📸 *Send a screenshot* → Verify if payment is real\n"
        "📋 *HISTORY* → See your last 5 verifications\n"
        "🚨 *REPORT* → Report a fraud payment\n"
        "🌐 *LANGUAGE* → Change your language preference\n"
        "📡 *STATUS* → Check if bot is online\n"
        "❓ *HELP* → Show this menu\n\n"
        "Simply send a payment screenshot from GPay, PhonePe, or Paytm and I'll verify it within 3 seconds!"
    )

def send_whatsapp_reply(to: str, message: str):
    twilio_client.messages.create(
        from_=TWILIO_WHATSAPP_NUMBER,
        to=f"whatsapp:{to}",
        body=message
    )

async def check_duplicate_screenshot(image_hash: str) -> tuple[bool, int]:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/screenshot_hashes",
                headers=supabase_headers(),
                params={"image_hash": f"eq.{image_hash}"}
            )
            data = r.json()
            if data:
                seen_count = data[0]["seen_count"] + 1
                await client.patch(
                    f"{SUPABASE_URL}/rest/v1/screenshot_hashes",
                    headers=supabase_headers(),
                    params={"image_hash": f"eq.{image_hash}"},
                    json={"seen_count": seen_count}
                )
                return True, seen_count
            else:
                await client.post(
                    f"{SUPABASE_URL}/rest/v1/screenshot_hashes",
                    headers=supabase_headers(),
                    json={"image_hash": image_hash, "first_reported_by": "system", "seen_count": 1}
                )
                return False, 1
    except Exception as e:
        print(f"[SUPABASE] Duplicate check error: {e}")
        return False, 1

async def check_blacklist(txn_id: str) -> tuple[bool, int]:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/fraud_ids",
                headers=supabase_headers(),
                params={"transaction_id": f"eq.{txn_id.upper().strip()}"}
            )
            data = r.json()
            if data:
                return True, data[0]["report_count"]
            return False, 0
    except Exception as e:
        print(f"[SUPABASE] Blacklist check error: {e}")
        return False, 0

async def add_to_blacklist(txn_id: str, reported_by: str, auto_flagged: bool = True):
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/fraud_ids",
                headers=supabase_headers(),
                params={"transaction_id": f"eq.{txn_id.upper().strip()}"}
            )
            data = r.json()
            if data:
                new_count = data[0]["report_count"] + 1
                await client.patch(
                    f"{SUPABASE_URL}/rest/v1/fraud_ids",
                    headers=supabase_headers(),
                    params={"transaction_id": f"eq.{txn_id.upper().strip()}"},
                    json={"report_count": new_count}
                )
                print(f"[BLACKLIST] Updated {txn_id} — count: {new_count}")
            else:
                await client.post(
                    f"{SUPABASE_URL}/rest/v1/fraud_ids",
                    headers=supabase_headers(),
                    json={
                        "transaction_id": txn_id.upper().strip(),
                        "reported_by": reported_by,
                        "report_count": 1,
                        "auto_flagged": auto_flagged
                    }
                )
                print(f"[BLACKLIST] Added {txn_id}")
    except Exception as e:
        print(f"[SUPABASE] Blacklist add error: {e}")

async def save_to_history(sender: str, txn_id: str, verdict: str, score: int, app_name: str):
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            await client.post(
                f"{SUPABASE_URL}/rest/v1/verification_history",
                headers=supabase_headers(),
                json={
                    "sender": sender,
                    "transaction_id": txn_id,
                    "verdict": verdict,
                    "fraud_score": score,
                    "app_name": app_name
                }
            )
            print(f"[HISTORY] Saved verification for {sender}")
    except Exception as e:
        print(f"[HISTORY] Save error: {e}")

async def get_history(sender: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/verification_history",
                headers=supabase_headers(),
                params={
                    "sender": f"eq.{sender}",
                    "order": "created_at.desc",
                    "limit": "5"
                }
            )
            data = r.json()

            if not data:
                return "📭 No verification history found.\n\nSend a payment screenshot to get started!"

            history_text = "📋 *Your Last 5 Verifications:*\n\n"
            for i, item in enumerate(data, 1):
                verdict = item.get("verdict", "UNKNOWN")
                score = item.get("fraud_score", 0)
                txn_id = item.get("transaction_id", "NOT_FOUND")
                app_name = item.get("app_name", "Unknown")
                created_at = item.get("created_at", "")[:10]

                if verdict == "VERIFIED":
                    emoji = "✅"
                elif verdict == "SUSPICIOUS":
                    emoji = "⚠️"
                else:
                    emoji = "🚨"

                history_text += (
                    f"{i}. {emoji} *{verdict}*\n"
                    f"   📊 Fraud Score: {score}%\n"
                    f"   📱 {app_name} | 🕐 {created_at}\n"
                    f"   💳 {txn_id}\n\n"
                )

            return history_text

    except Exception as e:
        print(f"[HISTORY] Fetch error: {e}")
        return "⚠️ Could not fetch history. Please try again."

async def get_user_language(phone_number: str):
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/user_preferences",
                headers=supabase_headers(),
                params={"phone_number": f"eq.{phone_number}"}
            )
            data = r.json()
            if data:
                return data[0]["language"]
            return None
    except Exception as e:
        print(f"[LANGUAGE] Get preference error: {e}")
        return None

async def save_user_language(phone_number: str, language):
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(
                f"{SUPABASE_URL}/rest/v1/user_preferences",
                headers=supabase_headers(),
                params={"phone_number": f"eq.{phone_number}"}
            )
            data = r.json()
            if data:
                if language is None:
                    await client.delete(
                        f"{SUPABASE_URL}/rest/v1/user_preferences",
                        headers=supabase_headers(),
                        params={"phone_number": f"eq.{phone_number}"}
                    )
                else:
                    await client.patch(
                        f"{SUPABASE_URL}/rest/v1/user_preferences",
                        headers=supabase_headers(),
                        params={"phone_number": f"eq.{phone_number}"},
                        json={"language": language}
                    )
            else:
                if language is not None:
                    await client.post(
                        f"{SUPABASE_URL}/rest/v1/user_preferences",
                        headers=supabase_headers(),
                        json={"phone_number": phone_number, "language": language}
                    )
            print(f"[LANGUAGE] Saved {language} for {phone_number}")
    except Exception as e:
        print(f"[LANGUAGE] Save preference error: {e}")

async def translate_reply(message: str, language: str) -> str:
    if not language or language.lower() == "english":
        return message

    response = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": f"""Translate this WhatsApp message to {language}.
Keep all emojis exactly as they are.
Keep *bold* formatting exactly as it is.
Only translate the text, nothing else.

Message:
{message}"""
            }
        ],
        max_tokens=500
    )

    translated = response.choices[0].message.content.strip()
    print(f"[TRANSLATE] Translated to {language}")
    return translated

async def download_image_from_twilio(image_url: str) -> bytes:
    async with httpx.AsyncClient(follow_redirects=True) as client:
        img_response = await client.get(
            image_url,
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            timeout=15.0
        )

    print(f"[IMAGE] Status code : {img_response.status_code}")
    print(f"[IMAGE] Size        : {len(img_response.content)} bytes")

    if img_response.status_code != 200:
        raise ValueError(f"Failed to download image: HTTP {img_response.status_code}")
    if len(img_response.content) == 0:
        raise ValueError("Downloaded image is empty (0 bytes)")

    return img_response.content

async def extract_transaction_details(image_base64: str) -> dict:
    response = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{image_base64}"}
                    },
                    {
                        "type": "text",
                        "text": """Analyze this payment screenshot and extract:
1. Transaction ID / UTR number
2. Payment app (GPay, PhonePe, Paytm etc)
3. Amount in numbers (e.g. 520)
4. Amount in words (e.g. Rupees Fifty Two Only)

Reply in this EXACT format:
TRANSACTION_ID: xxx
APP: xxx
AMOUNT_NUMBERS: xxx
AMOUNT_WORDS: xxx

If a field is not visible, write NOT_FOUND."""
                    }
                ]
            }
        ],
        max_tokens=150
    )

    raw = response.choices[0].message.content
    print(f"[OCR] Result:\n{raw}")

    details = {}
    for line in raw.strip().split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            details[key.strip()] = value.strip()

    return details

async def check_tamper(image_base64: str) -> dict:
    response = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{image_base64}"}
                    },
                    {
                        "type": "text",
                        "text": """You are a payment screenshot fraud analyst.
Analyze this payment screenshot for tampering. Pay special attention to:
- The payment amount — check if all digits look consistent in font, size, weight and spacing. 
  Scammers commonly change ₹52 to ₹520 or ₹100 to ₹1000 by appending digits.
- Text that appears overlaid or in a slightly different style than surrounding text
- Any digit that looks bolder, lighter, or sized differently than adjacent digits

Even subtle font inconsistencies in the amount field should be flagged.

Reply ONLY in this format:
IS_TAMPERED: yes/no
REASON: one short sentence"""
                    }
                ]
            }
        ],
        max_tokens=80
    )

    raw = response.choices[0].message.content
    print(f"[TAMPER] Result:\n{raw}")

    result = {}
    for line in raw.strip().split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()

    return {
        "is_tampered": result.get("IS_TAMPERED", "no").lower() == "yes",
        "reason": result.get("REASON", "No tampering detected")
    }

async def handle_report_screenshot(sender: str, media_url: str, user_language: str):
    """Handle screenshot sent in report mode — extract ID and add to blacklist."""
    try:
        raw_bytes = await download_image_from_twilio(media_url)
        img = Image.open(io.BytesIO(raw_bytes))
        img = img.convert("RGB")
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=90)
        image_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        details = await extract_transaction_details(image_base64)
        txn_id = details.get("TRANSACTION_ID", "NOT_FOUND")

        if txn_id == "NOT_FOUND":
            reply = "⚠️ Couldn't extract a transaction ID from that screenshot. Please try again."
        else:
            await add_to_blacklist(txn_id, sender, auto_flagged=False)
            reply = (
                f"✅ *Report Received!*\n\n"
                f"Thank you for helping protect other sellers.\n"
                f"💳 Transaction ID `{txn_id}` has been added to the fraud blacklist.\n\n"
                f"Other sellers will now be warned if they receive this screenshot."
            )
            print(f"[REPORT] User {sender} reported {txn_id}")

        reply = await translate_reply(reply, user_language)
        send_whatsapp_reply(sender, reply)

    except Exception as e:
        print(f"[REPORT ERROR] {e}")
        send_whatsapp_reply(sender, "⚠️ Something went wrong processing your report. Please try again.")

@app.get("/")
async def root():
    return {"status": "Payment Verifier Bot is running!"}

@app.get("/webhook")
async def verify_webhook(request: Request):
    return {"status": "ok"}

@app.post("/webhook")
async def receive_message(request: Request):
    form_data = await request.form()

    sender = form_data.get("From", "").replace("whatsapp:", "")
    message_type = form_data.get("MediaContentType0", "")
    media_url = form_data.get("MediaUrl0", "")
    message_body = form_data.get("Body", "").strip()
    message_body_upper = message_body.upper()

    print(f"\n[WEBHOOK] Message from : {sender}")
    print(f"[WEBHOOK] Media type   : {message_type}")
    print(f"[WEBHOOK] In report mode: {sender in pending_reports}")

    # Step 1 — Get user language from DB
    user_language = await get_user_language(sender)

    # Step 2 — Handle language number selection FIRST (1-5)
    if message_body in LANGUAGE_MAP and "image" not in message_type:
        selected_language = LANGUAGE_MAP[message_body]
        await save_user_language(sender, selected_language)
        help_msg = get_help_message()
        confirmation = await translate_reply(
            f"✅ Language set to *{selected_language}*!\n\n" + help_msg,
            selected_language
        )
        send_whatsapp_reply(sender, confirmation)
        return {"status": "ok"}

    # Step 3 — New user (no language set yet) → show welcome/language selection
    if user_language is None:
        send_whatsapp_reply(sender, get_welcome_message())
        return {"status": "ok"}

    # Step 4 — Safety fallback
    if not user_language:
        user_language = "English"

    # Step 5 — LANGUAGE command → reset and show language selection again
    if message_body_upper == "LANGUAGE":
        await save_user_language(sender, None)
        send_whatsapp_reply(sender, get_welcome_message())
        return {"status": "ok"}

    # Step 6 — User is in REPORT mode and sends a screenshot → handle report
    if sender in pending_reports and "image" in message_type:
        pending_reports.discard(sender)
        await handle_report_screenshot(sender, media_url, user_language)
        return {"status": "ok"}

    # Step 7 — Text commands
    if message_body_upper == "HELP":
        help_msg = await translate_reply(get_help_message(), user_language)
        send_whatsapp_reply(sender, help_msg)
        return {"status": "ok"}

    if message_body_upper == "STATUS":
        status_msg = await translate_reply("📡 *Bot is online and running!*\n\n✅ All systems operational.", user_language)
        send_whatsapp_reply(sender, status_msg)
        return {"status": "ok"}

    if message_body_upper == "REPORT":
        # Add sender to pending_reports so next screenshot goes to report handler
        pending_reports.add(sender)
        report_msg = await translate_reply(
            "🚨 *Report a Fraud Payment*\n\nPlease send the payment screenshot you want to report as fraud.",
            user_language
        )
        send_whatsapp_reply(sender, report_msg)
        return {"status": "ok"}

    if message_body_upper == "HISTORY":
        history = await get_history(sender)
        history = await translate_reply(history, user_language)
        send_whatsapp_reply(sender, history)
        return {"status": "ok"}

    # Step 8 — Image received → run fraud detection pipeline
    if "image" in message_type:
        send_whatsapp_reply(sender, "📸 Screenshot received! Analyzing... please wait.")

        try:
            # Download and convert image
            raw_bytes = await download_image_from_twilio(media_url)
            img = Image.open(io.BytesIO(raw_bytes))
            img = img.convert("RGB")
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG", quality=90)
            image_bytes = buffer.getvalue()
            image_base64 = base64.b64encode(image_bytes).decode("utf-8")

            # Duplicate screenshot check
            image_hash = hash_image(image_bytes)
            is_duplicate, seen_count = await check_duplicate_screenshot(image_hash)

            if is_duplicate:
                dup_msg = (
                    f"🚨 *FRAUD ALERT*\n\n"
                    f"📊 Fraud Score: 100%\n\n"
                    f"❌ This exact screenshot has been sent {seen_count} times before.\n"
                    f"🔁 Duplicate screenshots are a common scammer tactic.\n\n"
                    f"🚫 Do NOT release goods for this payment."
                )
                dup_msg = await translate_reply(dup_msg, user_language)
                send_whatsapp_reply(sender, dup_msg)
                return {"status": "ok"}

            # OCR
            details = await extract_transaction_details(image_base64)
            txn_id = details.get("TRANSACTION_ID", "NOT_FOUND")
            app_name = details.get("APP", "NOT_FOUND")

            # Blacklist check
            in_blacklist, report_count = await check_blacklist(txn_id)

            # Format validation
            format_valid, _ = validate_transaction_id(txn_id)

            # Tamper detection
            tamper_result = await check_tamper(image_base64)

            # Calculate fraud score
            score, verdict, reasons = calculate_fraud_score(
                format_valid, in_blacklist, tamper_result
            )

            # Amount cross-check (catches edited amounts like ₹52 → ₹520)
            amount_num = details.get("AMOUNT_NUMBERS", "NOT_FOUND")
            amount_words = details.get("AMOUNT_WORDS", "NOT_FOUND")

            if amount_num != "NOT_FOUND" and amount_words != "NOT_FOUND":
                verify_response = openai_client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{
                        "role": "user",
                        "content": f"Does the number {amount_num} match the words '{amount_words}'? Reply only YES or NO."
                    }],
                    max_tokens=5
                )
                match = verify_response.choices[0].message.content.strip().upper()
                print(f"[AMOUNT CHECK] {amount_num} vs '{amount_words}' → {match}")

                if match == "NO":
                    score = 100
                    verdict = "FRAUD"
                    reasons.insert(0, f"Amount mismatch: ₹{amount_num} does not match '{amount_words}'")

            # Auto blacklist if fraud
            if verdict == "FRAUD" and txn_id != "NOT_FOUND":
                await add_to_blacklist(txn_id, sender, auto_flagged=True)

            # Build reply
            if verdict == "VERIFIED":
                reply = (
                    f"✅ *PAYMENT VERIFIED*\n\n"
                    f"📊 Fraud Score: {score}%\n"
                    f"📱 App: {app_name}\n\n"
                    f"✔️ This payment appears legitimate."
                )

            elif verdict == "SUSPICIOUS":
                reply = (
                    f"⚠️ *SUSPICIOUS PAYMENT*\n\n"
                    f"📊 Fraud Score: {score}%\n"
                    f"📱 App: {app_name}\n\n"
                    f"🔍 Reason(s):\n"
                    + "\n".join([f"• {r}" for r in reasons])
                    + f"\n\n⚠️ Verify manually before proceeding.\n"
                    f"Reply *REPORT* if you confirm this is fraud."
                )

            else:
                reply = (
                    f"🚨 *FRAUD ALERT*\n\n"
                    f"📊 Fraud Score: {score}%\n"
                    f"📱 App: {app_name}\n\n"
                    f"❌ Reason(s):\n"
                    + "\n".join([f"• {r}" for r in reasons])
                    + f"\n\n🚫 Do NOT release goods for this payment."
                )

                if report_count > 1:
                    reply += f"\n⚠️ This ID has been reported {report_count} times by other sellers."

            print(f"[VERDICT] {verdict} — {score}% — {reasons}")

            # Save to history
            await save_to_history(sender, txn_id, verdict, score, app_name)

            # Translate and send
            reply = await translate_reply(reply, user_language)
            send_whatsapp_reply(sender, reply)

        except Exception as e:
            print(f"[ERROR] {e}")
            send_whatsapp_reply(
                sender,
                "⚠️ Something went wrong analyzing your screenshot. Please try again."
            )

    else:
        # Any unrecognized text → show help menu
        help_msg = await translate_reply(get_help_message(), user_language)
        send_whatsapp_reply(sender, help_msg)

    return {"status": "ok"}

