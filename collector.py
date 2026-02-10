import os, re, time
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# THE GREEDY REGEX: No more being picky. 
# It finds the protocol and takes everything until it hits a space or a quote.
regex = r"(vless|vmess|trojan|ss|hy2|hysteria2)://[^\s\"'<>]+"

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

print("🛰️  SYSTEM START: REGEX OVERHAUL")

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    for target in channels:
        print(f"📡 Scoping: {target}...", end=" ", flush=True)
        channel_links = []
        try:
            # Pulling a smaller limit (50) to keep it fast and fresh
            msgs = client.get_messages(target, limit=50)
            
            if not msgs:
                print("Empty.")
                continue

            for m in msgs:
                # Get the raw text
                content = m.message or ""
                if m.caption: content += " " + m.caption
                
                if content:
                    # Look for links
                    found = re.findall(regex, content, re.IGNORECASE)
                    for l in found:
                        if len(l) > 15: # Valid config length check
                            channel_links.append(l.strip())
                
                # Check for files (some admins upload .txt files with 1000s of configs)
                if m.file and any(ext in (m.file.ext or "").lower() for ext in ['.txt', '.json']):
                    try:
                        path = client.download_media(m)
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            file_found = re.findall(regex, f.read(), re.IGNORECASE)
                            channel_links.extend([fl.strip() for fl in file_found if len(fl) > 15])
                        os.remove(path)
                    except: continue

            if channel_links:
                unique_channel = set(channel_links)
                all_links.update(unique_channel)
                print(f"Done (+{len(unique_channel)})")
            else:
                # If we found messages but 0 links, show a sample to debug the Regex
                sample = msgs[0].message[:60].replace('\n', ' ') if msgs[0].message else "No Text"
                print(f"Zero. Sample: [{sample}...]")

        except Exception as e:
            print(f"Error: {type(e).__name__}")
        
        time.sleep(1)

# CRITICAL WRITE
print(f"\n💾 SAVING {len(all_links)} UNIQUE CONFIGS...")
with open('raw_collected.txt', 'w', encoding='utf-8') as f:
    if all_links:
        # Filter and sort
        sorted_links = sorted(list(all_links))
        f.write('\n'.join(sorted_links))
        print("✅ raw_collected.txt populated successfully.")
    else:
        print("❌ ERROR: Total count is 0. Check your sample messages above.")

print(f"🏁 HARVEST COMPLETE. TOTAL: {len(all_links)}")
