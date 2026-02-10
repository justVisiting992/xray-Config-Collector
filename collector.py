import os
import re
import csv
import time
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

# Credentials from GitHub Secrets
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# Greedier Regex to catch all variations
regex = r"(vless|vmess|trojan|ss|hysteria2|hy2)://[^\s'\"<>\(\)\[\]]+"

def get_channels():
    channel_names = []
    try:
        if not os.path.exists('channels.csv'):
            print("❌ channels.csv NOT FOUND in root!")
            return []
        with open('channels.csv', mode='r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or "URL,AllMessagesFlag" in line:
                    continue
                part = line.split(',')[0].strip()
                username = part.split('/')[-1].replace('@', '')
                if username:
                    channel_names.append(username)
    except Exception as e:
        print(f"❌ CSV Read Error: {e}")
    return list(dict.fromkeys(channel_names))

channels = get_channels()
print(f"📡 Found {len(channels)} targets. Starting Harvest...")

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    all_links = set()
    
    for target in channels:
        print(f"🔍 Checking: {target}...", end=" ", flush=True)
        count_before = len(all_links)
        try:
            # Iterating through last 200 messages
            for message in client.iter_messages(target, limit=200):
                # In Telethon, .text usually covers both the message body and the media caption
                content = message.text or ""
                
                # Double check: if there's media but no text, try to get the caption specifically
                if not content and message.media and hasattr(message.media, 'caption'):
                    content = message.media.caption or ""

                if content:
                    matches = re.findall(regex, content, re.IGNORECASE)
                    for m in matches:
                        all_links.add(m.strip())
                
                # Scrape Files (.txt, .json, .conf)
                if message.file and any(ext in (message.file.ext or "").lower() for ext in ['.txt', '.json', '.conf']):
                    try:
                        path = client.download_media(message)
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            f_matches = re.findall(regex, f.read(), re.IGNORECASE)
                            for m in f_matches:
                                all_links.add(m.strip())
                        os.remove(path)
                    except:
                        continue
            
            print(f"Found {len(all_links) - count_before} new.")
            time.sleep(0.5) 
            
        except Exception as e:
            print(f"Error: {type(e).__name__}") # Shows the specific error type

    # Final output for the Go Engine
    with open('raw_collected.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(all_links))
    
    print(f"🏁 TOTAL UNIQUE LINKS HARVESTED: {len(all_links)}")
