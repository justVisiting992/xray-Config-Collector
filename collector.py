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
CHECKPOINT_FILE = 'telegram_checkpoint.txt'

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
            
            # 2. Fetch messages NEWER than last_id, OLDEST first
            # (reverse=True). Order matters because of the limit: with
            # newest-first iteration, a backlog of more than 500 new
            # messages would return the newest 500 and the checkpoint
            # would jump past the older excess, skipping it forever.
            # Oldest-first returns the first 500 after last_id, so the
            # checkpoint handed to Go is the 500th message's ID and the
            # next run continues exactly where this one stopped.
            async for message in client.iter_messages(CHANNEL_USERNAME, min_id=last_id, limit=500, reverse=True):
                if message.id > max_id:
                    max_id = message.id
                
                if message.text:
                    messages_text.append(message.text)
                    count += 1

            print(f"✅ Extracted {count} new messages.")

            # 3. Save Text Dump
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write("\n\n".join(messages_text))

            # 4. Do NOT advance the Gist checkpoint here. The checkpoint
            # used to be updated at this point — before the Go collector
            # had read, processed or published the dump — so a failed Go
            # step or git push lost those messages permanently. Instead,
            # hand the highest observed message ID to the Go collector
            # via a sidecar file; it merges the value into its checkpoint
            # map and persists it to the Gist only at the end of a
            # successful run, after all outputs are written.
            with open(CHECKPOINT_FILE, 'w', encoding='utf-8') as f:
                f.write(str(max_id))
            if max_id > last_id:
                print(f"💾 Checkpoint {max_id} handed to Go collector via {CHECKPOINT_FILE}.")
            else:
                print("💤 No new messages found.")

    except FloodWaitError as e:
        print(f"⚠️ Telegram Rate Limit: Wait {e.seconds}s. Skipping...")
        open(OUTPUT_FILE, 'w').close()
        # No advance: tell Go the checkpoint stays where it was.
        with open(CHECKPOINT_FILE, 'w', encoding='utf-8') as f:
            f.write(str(last_id))
    except Exception as e:
        print(f"⚠️ Unexpected error: {e}")
        open(OUTPUT_FILE, 'w').close()
        # No advance: tell Go the checkpoint stays where it was.
        with open(CHECKPOINT_FILE, 'w', encoding='utf-8') as f:
            f.write(str(last_id))

if __name__ == '__main__':
    asyncio.run(main())
