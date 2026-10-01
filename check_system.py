import os
import time
import datetime
import random
import requests
import pymysql
from pathlib import Path

# ===== Load env =====
def load_env_file(path: str) -> dict:
    env = {}
    p = Path(path)
    if not p.exists():
        return env

    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        name, val = s.split("=", 1)
        name = name.strip()
        val = val.strip()

        # Remove optional surrounding quotes
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]

        env[name] = val

    # Export into process env so libraries can see them
    for k, v in env.items():
        os.environ.setdefault(k, v)

    return env


ENV_PATH = "/home/research/.env"

# ===== Config (from env) =====
DB_NAME = "research_researchChatAi"

# ===== OpenAI Configuration =====
OPENAI_CHAT_ENDPOINT = "https://api.openai.com/v1/chat/completions"
OPENAI_RESPONSES_ENDPOINT = "https://api.openai.com/v1/responses"

# Define models BEFORE using them
OPENAI_RESPONSES_MODELS = {
    "gpt-6-sol", "gpt-6-astra", "gpt-6-luna",
    "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna",
    "gpt-5", "gpt-5-mini",
}
OPENAI_CHAT_MODELS = {"gpt-4o", "gpt-4o-mini", "gpt-4", "gpt-4-turbo"}

# ===== OpenRouter Configuration =====
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODELS = [
    # The models suggested in the study settings (chat-backend-create.php)
    "anthropic/claude-haiku-4.5",
    "anthropic/claude-opus-5.5",
    "anthropic/claude-sonnet-5",
    "deepseek/deepseek-v4.1-flash",
    "google/gemini-3.1-flash-lite",
    "google/gemini-3.8-flash",
    "google/gemma-4-31b-it",
    "minimax/minimax-m3",
    "mistralai/mistral-small-2603",
    "moonshotai/kimi-k3",
    "nvidia/nemotron-3-ultra-550b-a55b",
    "openai/gpt-6-luna",
    "openai/gpt-6-sol",
    "qwen/qwen3.8-flash",
    "x-ai/grok-4.7",
    "xiaomi/mimo-v2.6-pro",
    "z-ai/glm-5.3",
]

# ===== Networking: timeouts, retries =====
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 60
REQUEST_TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)

_pending_rows = []


def should_retry(status, exc):
    # Retry on transport errors, 429, and 5xx (including 504 gateway timeouts)
    if exc is not None:
        return True
    return status in (429, 500, 502, 503, 504)


def post_with_retries(session, url, headers, payload, max_attempts=4):
    attempt = 0
    while True:
        attempt += 1
        exc = None
        resp = None
        status = None

        try:
            resp = session.post(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
            status = resp.status_code
        except Exception as e:
            exc = e

        if attempt >= max_attempts or not should_retry(status, exc):
            return resp, status, exc

        # Exponential backoff with jitter: 0.5, 1.0, 2.0 (+0–250ms)
        sleep_s = (0.5 * (2 ** (attempt - 1))) + random.uniform(0, 0.25)
        time.sleep(sleep_s)


# ===== DB helpers (batched inserts + error logging) =====
def insert_check(cursor, conn, provider_label, status, latency, when=None):
    when = when or datetime.datetime.utcnow()
    _pending_rows.append((provider_label, when, status, latency))
    if len(_pending_rows) >= 50:
        cursor.executemany(
            """INSERT INTO api_checks (provider, timestamp, status, latency)
               VALUES (%s, %s, %s, %s)""",
            _pending_rows,
        )
        conn.commit()
        _pending_rows.clear()


def flush_checks(cursor, conn):
    if _pending_rows:
        cursor.executemany(
            """INSERT INTO api_checks (provider, timestamp, status, latency)
               VALUES (%s, %s, %s, %s)""",
            _pending_rows,
        )
        conn.commit()
        _pending_rows.clear()


def insert_error(cursor, conn, provider_label, model, status, body, when=None):
    when = when or datetime.datetime.utcnow()
    body = (body or "")[:8000]
    cursor.execute(
        """INSERT INTO api_check_errors (provider, model, timestamp, status, body)
           VALUES (%s, %s, %s, %s, %s)""",
        (provider_label, model, when, str(status), body),
    )
    conn.commit()


# ===== Ping functions =====
def ping_openai_model(session, headers, model):
    t0 = time.time()

    if model in OPENAI_RESPONSES_MODELS:
        url = OPENAI_RESPONSES_ENDPOINT
        payload = {
            "model": model,
            "input": "ping",
            "max_output_tokens": 64,
            "reasoning": {"effort": "low"},
        }
    elif model in OPENAI_CHAT_MODELS:
        url = OPENAI_CHAT_ENDPOINT
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "ping"}],
            "temperature": 0.0,
        }
    else:
        return "invalid_model", None, "unsupported model", None

    try:
        resp, status, exc = post_with_retries(session, url, headers, payload)
        latency = round(time.time() - t0, 3)
        body = resp.text if resp is not None else (str(exc) if exc else "")
        return (str(status) if status else "error"), latency, ("exception" if exc else None), body
    except Exception as e:
        return "error", None, "exception", str(e)


def ping_openrouter_model(session, headers, model):
    t0 = time.time()
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "ping"}],
        "temperature": 0.0,
    }

    try:
        resp, status, exc = post_with_retries(session, OPENROUTER_ENDPOINT, headers, payload)
        latency = round(time.time() - t0, 3)
        body = resp.text if resp is not None else (str(exc) if exc else "")
        return (str(status) if status else "error"), latency, ("exception" if exc else None), body
    except Exception as e:
        return "error", None, "exception", str(e)


def main():
    env = load_env_file(ENV_PATH)

    DB_HOST = os.getenv("DB_SERVER")
    DB_USER = os.getenv("DB_USERNAME")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DB_CHARSET = os.getenv("DB_CHARSET", "utf8mb4")

    # Accept either OPENAI_API or OPENAI_API_KEY (same for OpenRouter)
    OPENAI_API_KEY = os.getenv("OPENAI_API") or os.getenv("OPENAI_API_KEY")
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API") or os.getenv("OPENROUTER_API_KEY")

    # Check required env vars (DB only; API keys are optional—tests are skipped if missing)
    missing = [k for k in ["DB_SERVER", "DB_USERNAME", "DB_PASSWORD"] if not os.getenv(k)]
    if missing:
        raise RuntimeError(f"Missing required env vars in {ENV_PATH}: {', '.join(missing)}")

    if not DB_NAME:
        raise RuntimeError("DB_NAME is empty")

    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset=DB_CHARSET,
        autocommit=False,
    )
    cursor = conn.cursor()
    session = requests.Session()

    try:
        # Ensure error-log table exists (stores non-200 bodies for forensics)
        # cursor.execute("""
        # CREATE TABLE IF NOT EXISTS api_check_errors (
        #   id BIGINT PRIMARY KEY AUTO_INCREMENT,
        #   provider VARCHAR(128) NOT NULL,
        #   model VARCHAR(255) NOT NULL,
        #   timestamp DATETIME NOT NULL,
        #   status VARCHAR(16) NOT NULL,
        #   body MEDIUMTEXT
        # ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        # """)
        # conn.commit()

        OPENAI_HEADERS = {
            "Authorization": f"Bearer {OPENAI_API_KEY}" if OPENAI_API_KEY else "",
            "Content-Type": "application/json",
        }

        OPENROUTER_HEADERS = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}" if OPENROUTER_API_KEY else "",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost",
            "X-Title": "API Monitor",
        }

        # ===== Run OpenAI Tests (guard if key missing) =====
        if OPENAI_API_KEY:
            openai_models = sorted(OPENAI_RESPONSES_MODELS | OPENAI_CHAT_MODELS)
            for model in openai_models:
                status, latency, kind, body = ping_openai_model(session, OPENAI_HEADERS, model)
                insert_check(cursor, conn, f"OpenAI - {model}", status, latency)
                if status != "200":
                    insert_error(cursor, conn, "OpenAI", model, status, body)
                time.sleep(0.2)  # small stagger to avoid thundering herd
        else:
            print("[warn] OPENAI_API/OPENAI_API_KEY missing: skipping OpenAI pings")

        # ===== Run OpenRouter Tests (guard if key missing) =====
        if OPENROUTER_API_KEY:
            for model in OPENROUTER_MODELS:
                status, latency, kind, body = ping_openrouter_model(session, OPENROUTER_HEADERS, model)
                insert_check(cursor, conn, f"OpenRouter - {model}", status, latency)
                if status != "200":
                    insert_error(cursor, conn, "OpenRouter", model, status, body)
                time.sleep(0.2)
        else:
            print("[warn] OPENROUTER_API/OPENROUTER_API_KEY missing: skipping OpenRouter pings")

        # ===== Flush batched rows =====
        flush_checks(cursor, conn)

        # ===== Summary =====
        cursor.execute("""
        SELECT provider,
               DATE(timestamp) as day,
               COUNT(*) as total,
               SUM(CASE WHEN status = '200' THEN 1 ELSE 0 END) as up_count,
               ROUND(SUM(CASE WHEN status = '200' THEN 1.0 ELSE 0 END) / COUNT(*), 2) as uptime_ratio
        FROM api_checks
        WHERE timestamp >= NOW() - INTERVAL 30 DAY
        GROUP BY provider, day
        ORDER BY day
        """)

        rows = cursor.fetchall()
        print("Uptime Summary (Last 30 Days):\n")
        for row in rows:
            ratio = float(row[4] or 0) * 100.0
            print(f"{row[0]} | {row[1]} | {ratio:.1f}% uptime")

    finally:
        try:
            flush_checks(cursor, conn)
        except Exception:
            pass
        session.close()
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()