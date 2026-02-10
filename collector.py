import os
import re
import time
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.channels import JoinChannelRequest

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# BROAD REGEX: Capture the protocol and EVERYTHING until a space, newline, or quote
# This ensures we don't just get 'vless://' but the whole string.
regex = r"(vless|vmess|trojan|ss|hysteria2|hy2)://[^\s\"'<>]+"

def get_channels():
    names = []
    try:
        with open('channels.csv', 'r') as f:
            for line in f:
                if "URL,AllMessagesFlag" in line or not line.strip(): continue
                u = line.split(',')[0].strip().split('/')[-1]
                if u: names.append(u)
    except: pass
    return list(dict.fromkeys(names))

channels = get_channels()
all_links = set()

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    for target in channels:
        print(f"📡 Scoping: {target}...", end=" ", flush=True)
        channel_links = 0
        try:
            # Get messages (limit 100 is enough for fresh configs)
            msgs = client.get_messages(target, limit=100)
            
            # If no messages, try to Join (often required for history visibility)
            if not msgs:
                try:
                    client(JoinChannelRequest(target))
                    time.sleep(1)
                    msgs = client.get_messages(target, limit=100)
                except: pass

            if msgs:
                for m in msgs:
                    # Search entire message object (text + entities)
                    content = (m.message or "") + " " + (getattr(m, 'caption', "") or "")
                    
                    # Core Regex Find
                    found = re.findall(regex, content, re.IGNORECASE)
                    for l in found:
                        clean_link = l.strip()
                        # Only add if it's long enough to be a real config
                        if len(clean_link) > 15:
                            all_links.add(clean_link)
                            channel_links += 1
                    
                    # Scrape Files (.txt and .json)
                    if m.file and any(ext in (m.file.ext or "").lower() for ext in ['.txt', '.json']):
                        try:
                            path = client.download_media(m)
                            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                                file_content = f.read()
                                file_found = re.findall(regex, file_content, re.IGNORECASE)
                                for fl in file_found:
                                    if len(fl) > 15:
                                        all_links.add(fl.strip())
                                        channel_links += 1
                            os.remove(path)
                        except: continue
            
            print(f"Done (+{channel_links})")
            time.sleep(1)
        except Exception as e:
            print(f"Failed: {type(e).__name__}")

# FINAL WRITE: This replaces the file with the master set
with open('raw_collected.txt', 'w', encoding='utf-8') as f:
    if all_links:
        f.write('\n'.join(sorted(list(all_links))))
    else:
        print("⚠️ WARNING: No valid configs found at all!")

print(f"🏁 MASTER TOTAL UNIQUE: {len(all_links)}")
