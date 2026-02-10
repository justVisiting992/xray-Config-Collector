import os
import re
import time
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# Updated Regex to be extremely permissive
regex = r"(vless|vmess|trojan|ss|hysteria2|hy2)://[^\s\"'<>]+"

def get_channels():
    names = []
    with open('channels.csv', 'r') as f:
        for line in f:
            if "URL,AllMessagesFlag" in line or not line.strip(): continue
            u = line.split(',')[0].strip().split('/')[-1]
            if u: names.append(u)
    return list(dict.fromkeys(names))

channels = get_channels()
all_links = set()

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    for target in channels:
        print(f"📡 Scoping: {target}...", end=" ", flush=True)
        channel_links = 0
        try:
            # removed JoinChannelRequest to avoid getting ghosted
            # Using iter_messages which is more 'human' than get_messages
            for m in client.iter_messages(target, limit=50):
                content = (m.message or "") + " " + (getattr(m, 'caption', "") or "")
                
                if content:
                    found = re.findall(regex, content, re.IGNORECASE)
                    for l in found:
                        if len(l) > 20: # Filtering out fragments
                            all_links.add(l.strip())
                            channel_links += 1

            print(f"Done (+{channel_links})")
            time.sleep(3) # Heavy sleep to prevent the '0' ghosting effect

        except FloodWaitError as e:
            print(f"Wait {e.seconds}s")
            time.sleep(e.seconds)
        except Exception as e:
            print(f"Skip: {type(e).__name__}")

# FINAL DISK WRITE
with open('raw_collected.txt', 'w', encoding='utf-8') as f:
    if all_links:
        f.write('\n'.join(all_links))
    else:
        # Emergency debug
        f.write("DEBUG: NO LINKS FOUND")

print(f"🏁 MASTER TOTAL: {len(all_links)}")
