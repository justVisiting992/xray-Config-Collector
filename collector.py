import os
import datetime
import asyncio
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError

# --- Configuration using your Secret Names ---
API_ID = os.environ.get('TELEGRAM_API_ID')
API_HASH = os.environ.get('TELEGRAM_API_HASH')
SESSION_STRING = os.environ.get('TELEGRAM_SESSION_STRING')

CHANNEL_USERNAME = 'persianvpnhub'
OUTPUT_FILE = 'telegram_dump.txt'
HOURS_BACK = 2 

async def main():
    print(f"--- Starting Python Collector for {CHANNEL_USERNAME} ---")
    
    if not API_ID or not API_HASH or not SESSION_STRING:
        print("❌ Error: TELEGRAM_API_ID, TELEGRAM_API_HASH, or TELEGRAM_SESSION_STRING not found.")
        return

    try:
        # API_ID must be an integer for Telethon
        async with TelegramClient(StringSession(SESSION_STRING), int(API_ID), API_HASH) as client:
            cutoff_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=HOURS_BACK)
            print(f"📅 Fetching messages since: {cutoff_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")

            messages_text = []
            count = 0
            
            async for message in client.iter_messages(CHANNEL_USERNAME):
                if message.date < cutoff_time:
                    break
                
                if message.text:
                    messages_text.append(message.text)
                    count += 1

            print(f"✅ Extracted {count} messages.")

            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write("\n\n".join(messages_text))
            
            print(f"💾 Dump saved to {OUTPUT_FILE}")

    except FloodWaitError as e:
        print(f"⚠️ Telegram Rate Limit: A wait of {e.seconds} seconds is required. Skipping API pull...")
        # Create empty file so Go script has a file to read
        open(OUTPUT_FILE, 'w').close()
    except Exception as e:
        print(f"⚠️ An unexpected error occurred: {e}")
        open(OUTPUT_FILE, 'w').close()

if __name__ == '__main__':
    asyncio.run(main())
