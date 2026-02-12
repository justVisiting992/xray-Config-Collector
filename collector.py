import os
import json
import asyncio
import requests
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError

# --- Secrets ---
API_ID = os.environ.get('TELEGRAM_API_ID')
API_HASH = os.environ.get('TELEGRAM_API_HASH')
SESSION_STRING = os.environ.get('TELEGRAM_SESSION_STRING')
GIST_ID = os.environ.get('GIST_ID')
GIST_TOKEN = os.environ.get('GIST_TOKEN')

CHANNEL_USERNAME = 'persianvpnhub'
OUTPUT_FILE = 'telegram_dump.txt'

# --- Gist Helper Functions ---
def get_checkpoints():
    if not GIST_ID or not GIST_TOKEN:
        print("⚠️ GIST_ID or GIST_TOKEN missing. Defaulting to fresh start.")
        return {}
    
    headers = {"Authorization": f"token {GIST_TOKEN}"}
    try:
        resp = requests.get(f"https://api.github.com/gists/{GIST_ID}", headers=headers)
        resp.raise_for_status()
        files = resp.json().get("files", {})
        if "checkpoints.json" in files:
            content = files["checkpoints.json"]["content"]
            return json.loads(content)
    except Exception as e:
        print(f"⚠️ Failed to load checkpoints: {e}")
    return {}

def update_checkpoint(data):
    if not GIST_ID or not GIST_TOKEN:
        return
    
    headers = {
        "Authorization": f"token {GIST_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {
        "files": {
            "checkpoints.json": {
                "content": json.dumps(data, indent=2)
            }
        }
    }
    try:
        requests.patch(f"https://api.github.com/gists/{GIST_ID}", headers=headers, json=payload)
        print("💾 Checkpoint updated in Gist.")
    except Exception as e:
        print(f"❌ Failed to update Gist: {e}")

async def main():
    print(f"--- Starting Stateful Python Collector for {CHANNEL_USERNAME} ---")
    
    if not API_ID or not API_HASH or not SESSION_STRING:
        print("❌ Error: Telegram Secrets not found.")
        return

    # 1. Load Checkpoints
    checkpoints = get_checkpoints()
    last_id = checkpoints.get(CHANNEL_USERNAME, 0)
    print(f"🔍 Last processed Message ID: {last_id}")

    try:
        async with TelegramClient(StringSession(SESSION_STRING), int(API_ID), API_HASH) as client:
            messages_text = []
            max_id = last_id
            count = 0
            
            # 2. Fetch messages NEWER than last_id (reverse=True gets oldest first, which is good for history but here we want newest range)
            # Actually, min_id fetches messages with ID > min_id.
            async for message in client.iter_messages(CHANNEL_USERNAME, min_id=last_id, limit=500):
                if message.id > max_id:
                    max_id = message.id
                
                if message.text:
                    messages_text.append(message.text)
                    count += 1

            print(f"✅ Extracted {count} new messages.")

            # 3. Save Text Dump
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write("\n\n".join(messages_text))
            
            # 4. Update Gist if we found newer messages
            if max_id > last_id:
                checkpoints[CHANNEL_USERNAME] = max_id
                update_checkpoint(checkpoints)
            else:
                print("💤 No new messages found.")

    except FloodWaitError as e:
        print(f"⚠️ Telegram Rate Limit: Wait {e.seconds}s. Skipping...")
        open(OUTPUT_FILE, 'w').close()
    except Exception as e:
        print(f"⚠️ Unexpected error: {e}")
        open(OUTPUT_FILE, 'w').close()

if __name__ == '__main__':
    asyncio.run(main())
