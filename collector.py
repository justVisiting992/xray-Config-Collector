import os, re, time, random
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# THE FIX: (?:...) makes it a NON-CAPTURING group so findall returns the WHOLE match
regex = r"(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s'\"<>\(\)\[\]]+"

def get_channels():
    names = []
    try:
        with open('channels.csv', 'r') as f:
            for line in f:
                if "URL,AllMessagesFlag" in line or not line.strip(): continue
                u = line.split(',')[0].strip().split('/')[-1]
                if u: names.append(u)
    except: pass
    names = list(dict.fromkeys(names))
    random.shuffle(names) # Randomize to avoid hitting the same "flood wall"
    return names

# Fresh start
with open('raw_collected.txt', 'w', encoding='utf-8') as f:
    f.write("")

channels = get_channels()
total_found = 0
processed_count = 0
MAX_CHANNELS = 50 # Batching to stay under the radar

print(f"🚀 COLLECTOR RELOADED | Batch Size: {MAX_CHANNELS}")

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    for target in channels:
        if processed_count >= MAX_CHANNELS: break
            
        print(f"📡 {processed_count+1}/{MAX_CHANNELS} | {target}...", end=" ", flush=True)
        try:
            msgs = client.get_messages(target, limit=50)
            channel_links = []
            
            if msgs:
                for m in msgs:
                    content = (m.message or "") + " " + (getattr(m, 'caption', "") or "")
                    # Extracting the FULL link now
                    found = re.findall(regex, content, re.IGNORECASE)
                    for l in found:
                        channel_links.append(l.strip())
            
            if channel_links:
                with open('raw_collected.txt', 'a', encoding='utf-8') as f:
                    f.write('\n'.join(channel_links) + '\n')
                print(f"+{len(channel_links)}")
                total_found += len(channel_links)
            else:
                print("0")

            processed_count += 1
            time.sleep(random.uniform(2, 4)) # Anti-spam jitter

        except FloodWaitError as e:
            print(f"\n🛑 FLOOD: {e.seconds}s. Saving and exiting.")
            break
        except Exception as e:
            print(f"Skip ({type(e).__name__})")

print(f"\n🏁 TOTAL FULL CONFIGS SAVED: {total_found}")
