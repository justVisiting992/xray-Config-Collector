import os, re, time
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# The Regex that actually caught the 6000+
regex = r"(vless|vmess|trojan|ss|hysteria2|hy2)://[^\s'\"<>\(\)\[\]]+"

def get_channels():
    names = []
    with open('channels.csv', 'r') as f:
        for line in f:
            if "URL,AllMessagesFlag" in line or not line.strip(): continue
            u = line.split(',')[0].strip().split('/')[-1]
            if u: names.append(u)
    return list(dict.fromkeys(names))

# 1. Start with a fresh file
with open('raw_collected.txt', 'w', encoding='utf-8') as f:
    f.write("")

channels = get_channels()
total_found = 0

print("🚀 STARTING HIGH-YIELD COLLECTOR...")

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    for target in channels:
        print(f"📡 Scoping: {target}...", end=" ", flush=True)
        channel_links = []
        try:
            # Reverting to the high-limit fetch
            msgs = client.get_messages(target, limit=100)
            
            if msgs:
                for m in msgs:
                    content = (m.message or "") + " " + (getattr(m, 'caption', "") or "")
                    found = re.findall(regex, content, re.IGNORECASE)
                    for l in found:
                        channel_links.append(l.strip())
            
            # 2. PERSISTENCE: Save immediately if links found
            if channel_links:
                with open('raw_collected.txt', 'a', encoding='utf-8') as f:
                    f.write('\n'.join(channel_links) + '\n')
                
                count = len(channel_links)
                total_found += count
                print(f"Done (+{count})")
            else:
                print("0 found.")

        except Exception as e:
            print(f"Bypassed: {type(e).__name__}")
        
        # 3. ANTI-GHOSTING: Slow down slightly to keep the session alive
        time.sleep(2)

print(f"\n🏁 HARVEST COMPLETE. TOTAL IN FILE: {total_found}")
