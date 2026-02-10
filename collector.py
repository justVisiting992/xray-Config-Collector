import os
import re
import csv
import time
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# ULTRA-GREEDY REGEX: If it starts with a protocol, we take it.
regex = r"(vless|vmess|trojan|ss|hysteria2|hy2)://[^\s'\"<>\(\)\[\]]+"

def get_channels():
    channel_names = []
    try:
        with open('channels.csv', mode='r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip header or empty lines
                if not line or "URL,AllMessagesFlag" in line:
                    continue
                # Extract username: works for 'https://t.me/name' or 'name,false'
                part = line.split(',')[0].strip()
                username = part.split('/')[-1].replace('@', '')
                if username:
                    channel_names.append(username)
    except Exception as e:
        print(f"❌ CSV Read Error: {e}")
    return list(dict.fromkeys(channel_names)) # Unique while preserving order

channels = get_channels()
print(f"📡 Found {len(channels)} targets in CSV. Starting Engine...")

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    all_links = set()
    
    for target in channels:
        print(f"🔍 Checking: {target}...", end=" ", flush=True)
        count_before = len(all_links)
        try:
            # We use limit=200. Captions + Text + Files.
            for message in client.iter_messages(target, limit=200):
                content = ""
                if message.text: content += message.text + " "
                if message.caption: content += message.caption
                
                # Scrape text/caption
                if content:
                    matches = re.findall(regex, content, re.IGNORECASE)
                    for m in matches: all_links.add(m.strip())
                
                # Scrape files
                if message.file and any(ext in (message.file.ext or "").lower() for ext in ['.txt', '.json', '.conf']):
                    try:
                        path = client.download_media(message)
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            f_matches = re.findall(regex, f.read(), re.IGNORECASE)
                            for m in f_matches: all_links.add(m.strip())
                        os.remove(path)
                    except: continue
            
            print(f"Found {len(all_links) - count_before} new.")
            time.sleep(0.3) 
            
        except Exception as e:
            print(f"Error: {str(e)[:50]}")

    with open('raw_collected.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(all_links))
    
    print(f"🏁 TOTAL UNIQUE LINKS HARVESTED: {len(all_links)}")
