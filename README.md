# 💳 PayVerify — WhatsApp Payment Fraud Detector

A WhatsApp bot that verifies payment screenshots in under 3 seconds using AI-powered OCR, tamper detection, and a community-driven fraud blacklist.

## Problem
Sellers receive fake payment screenshots and release goods without realizing the payment never happened. This affects 95,000+ sellers annually in India.

## Solution
Forward any suspicious payment screenshot to our WhatsApp bot. Get back **VERIFIED**, **SUSPICIOUS**, or **FRAUD ALERT** in seconds — no app download, no website, no copy-paste.

## How It Works
1. Seller forwards payment screenshot to WhatsApp bot
2. Bot downloads and processes the image
3. GPT-4o OCR extracts transaction details
4. Format validation checks transaction ID
5. GPT-4o tamper detection checks if screenshot is edited
6. Community blacklist cross-checks fraud database
7. Fraud confidence score calculated
8. Verdict sent back instantly

## Fraud Detection Layers
| Layer | Method | Weight |
|-------|--------|--------|
| Format Validation | Regex pattern matching | +40% |
| Community Blacklist | Supabase dynamic database | +60% |
| Tamper Detection | GPT-4o Vision AI | +30% |

## Verdict System
| Score | Verdict |
|-------|---------|
| 0-29% | VERIFIED |
| 30-59% | SUSPICIOUS |
| 60-100% | FRAUD ALERT |

## Bot Commands
| Command | Action |
|---------|--------|
| Send screenshot | Verify payment |
| HELP | Show all commands |
| HISTORY | Last 5 verifications |
| REPORT | Report a fraud payment |
| LANGUAGE | Change language preference |
| STATUS | Check if bot is online |

## Multilingual Support
Supports English, Tamil, Hindi, Telugu, Malayalam

## Tech Stack
| Layer | Technology |
|-------|-----------|
| Messaging | Twilio WhatsApp API |
| Backend | FastAPI + Uvicorn |
| AI/OCR | GPT-4o Vision (OpenAI) |
| Tamper Detection | GPT-4o Vision (OpenAI) |
| Image Processing | Pillow + httpx |
| Format Validation | Regex (Python) |
| Database | Supabase (PostgreSQL) |
| Fraud Scoring | Custom Python Logic |

## Setup

### 1. Clone the repository
git clone https://github.com/aadharshinir/payment-verifier.git
cd payment-verifier/backend

### 2. Install dependencies
pip install -r requirements.txt

### 3. Create .env file
TWILIO_ACCOUNT_SID=your_twilio_sid
TWILIO_AUTH_TOKEN=your_twilio_token
TWILIO_WHATSAPP_NUMBER=whatsapp:+1XXXXXXXXXX
OPENAI_API_KEY=your_openai_key
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_key

### 4. Run the server
uvicorn main:app --reload

### 5. Start ngrok tunnel
ngrok http 8000

### 6. Update Twilio webhook URL
Set webhook to: https://your-ngrok-url.ngrok.io/webhook

## Supabase Tables Required
Run these in Supabase SQL Editor:

CREATE TABLE fraud_ids (
    id SERIAL PRIMARY KEY,
    transaction_id TEXT UNIQUE NOT NULL,
    reported_by TEXT,
    report_count INTEGER DEFAULT 1,
    auto_flagged BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE screenshot_hashes (
    id SERIAL PRIMARY KEY,
    image_hash TEXT UNIQUE NOT NULL,
    first_reported_by TEXT,
    seen_count INTEGER DEFAULT 1,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW()
);

CREATE TABLE verification_history (
    id SERIAL PRIMARY KEY,
    sender TEXT NOT NULL,
    transaction_id TEXT,
    verdict TEXT,
    fraud_score INTEGER,
    app_name TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE user_preferences (
    id SERIAL PRIMARY KEY,
    phone_number TEXT UNIQUE NOT NULL,
    language TEXT DEFAULT 'English',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    phone_number TEXT UNIQUE NOT NULL,
    state TEXT DEFAULT 'idle',
    updated_at TIMESTAMP DEFAULT NOW()
);

## Roadmap
| Phase | Feature | Status |
|-------|---------|--------|
| Phase 1 | WhatsApp bot, OCR, tamper detection | ✅ Done |
| Phase 2 | Chrome extension for WhatsApp Web | ⏳ Planned |
| Phase 3 | Android companion app | ⏳ Planned |
| Phase 4 | Razorpay API integration | ⏳ Planned |
| Phase 5 | Polygon blockchain fraud registry | ⏳ Planned |

## Team
Built at [Your Hackathon Name] 2026

## License
MIT License