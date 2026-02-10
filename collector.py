import os, re, time
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# The most "Nuclear" regex: Catch anything that looks like a protocol
regex = r"(vless|vmess|trojan|ss|hy2|hysteria2)://[^\s'\"<>\(\)\[\]]+"

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

print("🏥 STARTING DIAGNOSTIC SCAN...")

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    for target in channels[:20]: # Only check first 20 for speed
        print(f"🔍 Checking: {target}")
        try:
            # We use get_messages directly
            msgs = client.get_messages(target, limit=10)
            
            if not msgs:
                print(f"   ⚠️  ZERO messages returned. Telegram is ghosting this channel.")
                continue

            # DEBUG: Show us what the API actually sees
            sample_text = msgs[0].message or "No text (Media?)"
            print(f"   ✅ First message snippet: {sample_text[:50]}...")

            for m in msgs:
                content = (m.message or "") + " " + (getattr(m, 'caption', "") or "")
                found = re.findall(regex, content, re.IGNORECASE)
                for l in found:
                    all_links.add(l.strip())
            
        except Exception as e:
            print(f"   ❌ API Error on {target}: {str(e)}")
        
        time.sleep(1)

    # Force a physical write and check
    print(f"\n💾 Attempting to write {len(all_links)} links to disk...")
    with open('raw_collected.txt', 'w', encoding='utf-8') as f:
        if all_links:
            f.write('\n'.join(all_links))
            f.flush()
            os.fsync(f.fileno())
        else:
            f.write("EMPTY_DATA_CHECK")

print(f"🏁 Final Master Total: {len(all_links)}")
