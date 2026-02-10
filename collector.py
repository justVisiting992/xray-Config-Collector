import os
import re
import csv
import time
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.messages import CheckChatInviteRequest

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# The most aggressive regex possible
regex = r"(vless|vmess|trojan|ss|hysteria2|hy2)://[^\s'\"<>\(\)\[\]]+"

def get_channels():
    channel_names = []
    try:
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
        print(f"❌ CSV Error: {e}")
    return list(dict.fromkeys(channel_names))

channels = get_channels()
print(f"📡 targets: {len(channels)}. Starting Super-Scraper...")

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    all_links = set()
    
    for target in channels:
        print(f"🔍 Scanning: {target}...", end=" ", flush=True)
        count_before = len(all_links)
        try:
            # Force the client to "recognize" the channel first
            entity = client.get_entity(target)
            
            for message in client.iter_messages(entity, limit=100):
                # Check Text & Captions
                content = message.text or ""
                if not content and message.media:
                    # Fallback for older Telethon versions or specific media types
                    content = getattr(message, 'caption', "") or ""

                if content:
                    matches = re.findall(regex, content, re.IGNORECASE)
                    for m in matches:
                        all_links.add(m.strip())
                
                # Check Files
                if message.file and any(ext in (message.file.ext or "").lower() for ext in ['.txt', '.json']):
                    try:
                        path = client.download_media(message)
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            f_matches = re.findall(regex, f.read(), re.IGNORECASE)
                            for m in f_matches:
                                all_links.add(m.strip())
                        os.remove(path)
                    except:
                        continue
            
            print(f"Success! (+{len(all_links) - count_before})")
            time.sleep(1) # Important: don't lower this or Telegram will block you
            
        except Exception as e:
            print(f"Failed. Reason: {type(e).__name__}")

    # Write to file
    with open('raw_collected.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(all_links))
    
    print(f"\n🏁 FINAL HARVEST: {len(all_links)} links saved to raw_collected.txt")
