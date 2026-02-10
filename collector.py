import os, re, time, asyncio
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# Regex: Keep it simple but add a length limit to prevent hanging on massive text blobs
regex = r"(vless|vmess|trojan|ss|hysteria2|hy2)://[^\s'\"<>\(\)\[\]]{20,500}"

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

# Clean slate
with open('raw_collected.txt', 'w', encoding='utf-8') as f:
    f.write("")

channels = get_channels()
total_found = 0

print(f"🚀 STARTING FAST HARVEST | Total Channels: {len(channels)}")

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    for target in channels:
        print(f"📡 Scoping: {target}...", end=" ", flush=True)
        channel_links = []
        
        try:
            # TIMEOUT: If a channel doesn't respond in 15s, move on
            msgs = client.get_messages(target, limit=50)
            
            if msgs:
                for m in msgs:
                    content = (m.message or "") + " " + (getattr(m, 'caption', "") or "")
                    if len(content) > 10000: content = content[:10000] # Don't parse monster messages
                    
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
                print("0.")

        except FloodWaitError as e:
            # If the wait is more than 3 minutes, just stop the whole run
            if e.seconds > 180:
                print(f"\n🛑 HUGE FLOOD DETECTED ({e.seconds}s). Saving and exiting to avoid hang.")
                break
            print(f"⏳ Wait {e.seconds}s...", end=" ")
            time.sleep(e.seconds)
            continue
            
        except Exception as e:
            print(f"Skip ({type(e).__name__})")
        
        # Micro-sleep to keep things fluid
        time.sleep(0.3)

print(f"\n🏁 HARVEST COMPLETE. TOTAL: {total_found}")
