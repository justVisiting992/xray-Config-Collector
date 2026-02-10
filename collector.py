import os
import re
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

# Load credentials from GitHub Secrets
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# Protocols to search for
regex = r"(vless|vmess|trojan|ss|hysteria2)://[A-Za-z0-9./:=?#-_@!%]+"

def get_channels():
    # Helper to pull channel list from your existing CSV
    with open('channels.csv', 'r') as f:
        return [line.split(',')[0].strip().split('/')[-1] for line in f if line.strip()]

channels = get_channels()

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    all_links = set() # Use set to auto-deduplicate
    
    for target in channels:
        print(f"📡 Scrutinizing: {target}")
        try:
            for message in client.iter_messages(target, limit=50):
                # Check text messages
                if message.text:
                    found = re.findall(regex, message.text, re.IGNORECASE)
                    for link in found: all_links.add(link)
                
                # Check files (The Magic Part)
                if message.file and (message.file.ext in ['.txt', '.json']):
                    path = client.download_media(message)
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        found_in_file = re.findall(regex, content, re.IGNORECASE)
                        for link in found_in_file: all_links.add(link)
                    os.remove(path)
        except Exception as e:
            print(f"⚠️ Skipped {target}: {e}")

    # Save for the Go Engine
    with open('raw_collected.txt', 'w') as f:
        f.write('\n'.join(all_links))
