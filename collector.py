import os, re, time
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# The Regex that is currently crushing it
regex = r"(vless|vmess|trojan|ss|hysteria2|hy2)://[^\s'\"<>\(\)\[\]]+"

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

# Start with a clean slate
with open('raw_collected.txt', 'w', encoding='utf-8') as f:
    f.write("")

channels = get_channels()
total_found = 0

print(f"🚀 STARTING FLOOD-PROOF HARVEST (Limit: 50 messages/channel)")

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    for target in channels:
        print(f"📡 Scoping: {target}...", end=" ", flush=True)
        channel_links = []
        try:
            # REDUCED LIMIT TO 50 AS REQUESTED
            msgs = client.get_messages(target, limit=50)
            
            if msgs:
                for m in msgs:
                    content = (m.message or "") + " " + (getattr(m, 'caption', "") or "")
                    found = re.findall(regex, content, re.IGNORECASE)
                    for l in found:
                        channel_links.append(l.strip())
            
            if channel_links:
                with open('raw_collected.txt', 'a', encoding='utf-8') as f:
                    f.write('\n'.join(channel_links) + '\n')
                count = len(channel_links)
                total_found += count
                print(f"Done (+{count})")
            else:
                print("0 found.")

        except FloodWaitError as e:
            # Instead of bypassing, we wait so the script can continue
            print(f"⚠️ FLOOD! Sleeping for {e.seconds}s...")
            time.sleep(e.seconds)
            # Optional: you could retry the current channel here, 
            # but usually it's better to just move to the next after a flood.
            continue
        except Exception as e:
            print(f"Error: {type(e).__name__}")
        
        # Consistent 1-second heartbeat to keep Telegram happy
        time.sleep(1)

print(f"\n🏁 HARVEST COMPLETE. TOTAL IN FILE: {total_found}")
