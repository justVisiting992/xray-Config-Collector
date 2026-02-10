import os
import re
import csv
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

# Load credentials from GitHub Secrets
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# Protocols to search for
regex = r"(vless|vmess|trojan|ss|hysteria2)://[A-Za-z0-9./:=?#-_@!%]+"

def get_channels():
    channel_names = []
    try:
        with open('channels.csv', mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader) # Skip the header row: URL,AllMessagesFlag
            for row in reader:
                if row:
                    # Extracts 'username' from 'https://t.me/username'
                    url = row[0].strip().rstrip('/')
                    username = url.split('/')[-1]
                    if username:
                        channel_names.append(username)
    except Exception as e:
        print(f"❌ Error reading CSV: {e}")
    return list(set(channel_names)) # Remove duplicates from CSV list

channels = get_channels()

print(f"🚀 Starting Python Scout for {len(channels)} channels...")

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    all_links = set()
    
    for target in channels:
        print(f"📡 Scrutinizing: {target}")
        try:
            # We fetch the last 50 messages per channel
            for message in client.iter_messages(target, limit=50):
                # 1. Check text messages
                if message.text:
                    found = re.findall(regex, message.text, re.IGNORECASE)
                    for link in found:
                        all_links.add(link)
                
                # 2. Check inside .txt or .json files
                if message.file and (message.file.ext in ['.txt', '.json']):
                    try:
                        path = client.download_media(message)
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            found_in_file = re.findall(regex, content, re.IGNORECASE)
                            for link in found_in_file:
                                all_links.add(link)
                        os.remove(path)
                    except:
                        continue
        except Exception as e:
            print(f"⚠️ Skipped {target}: {e}")

    # Save findings for the Go Engine
    with open('raw_collected.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(all_links))
    
    print(f"✅ Python Scout finished. Found {len(all_links)} raw links.")
