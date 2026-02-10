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

# The Regex
regex = r"(vless|vmess|trojan|ss|hysteria2|hy2)://[^\s'\"<>\(\)\[\]]+"

def get_channels():
    names = []
    with open('channels.csv', 'r') as f:
        for line in f:
            if "URL,AllMessagesFlag" in line or not line.strip(): continue
            u = line.split(',')[0].strip().split('/')[-1]
            if u: names.append(u)
    return list(dict.fromkeys(names))

channels = get_channels()
all_links = set() # This is our master vault

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    for target in channels:
        print(f"📡 Scoping: {target}...", end=" ", flush=True)
        current_channel_count = 0
        try:
            # Direct pull (If 0 found, we try a join)
            msgs = client.get_messages(target, limit=100)
            
            if not msgs:
                try:
                    client(JoinChannelRequest(target))
                    msgs = client.get_messages(target, limit=100)
                except: pass

            for m in msgs:
                # 1. Extract from Text/Caption
                text = (m.message or "") + " " + (getattr(m, 'caption', "") or "")
                if text:
                    links = re.findall(regex, text, re.IGNORECASE)
                    for l in links:
                        all_links.add(l.strip())
                        current_channel_count += 1
                
                # 2. Extract from Files
                if m.file and any(ext in (m.file.ext or "").lower() for ext in ['.txt', '.json']):
                    try:
                        path = client.download_media(m)
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            file_links = re.findall(regex, f.read(), re.IGNORECASE)
                            for l in file_links:
                                all_links.add(l.strip())
                                current_channel_count += 1
                        os.remove(path)
                    except: continue
            
            print(f"Done (+{current_channel_count})")
            time.sleep(1)

        except Exception as e:
            print(f"Skipped: {type(e).__name__}")

    # THE CRITICAL SAVE: Write the master vault to file
    with open('raw_collected.txt', 'w', encoding='utf-8') as f:
        # Filter out empty lines and sort for cleanliness
        clean_list = [l for l in all_links if len(l) > 10] 
        f.write('\n'.join(clean_list))

print(f"🏁 Final Master Harvest Total: {len(all_links)}")
