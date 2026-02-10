import os
import re
import time
from telethon.sync import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.errors import FloodWaitError

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# Greediest Regex
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

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    all_links = set()
    
    for target in channels:
        print(f"📡 Scoping: {target}...", end=" ", flush=True)
        try:
            # FORCE JOIN: This is the only way to guarantee message visibility
            try:
                client(JoinChannelRequest(target))
            except Exception:
                pass # Already joined or public enough
            
            # DIRECT PULL
            msgs = client.get_messages(target, limit=100)
            
            found_this_round = 0
            for m in msgs:
                # Combine text and file captions
                text = (m.message or "") + " " + (getattr(m, 'caption', "") or "")
                
                # Extract from Text
                links = re.findall(regex, text, re.IGNORECASE)
                for l in links: 
                    all_links.add(l.strip())
                    found_this_round += 1
                
                # Extract from Files
                if m.file and m.file.ext in ['.txt', '.json']:
                    path = client.download_media(m)
                    with open(path, 'r', errors='ignore') as f:
                        flinks = re.findall(regex, f.read(), re.IGNORECASE)
                        for l in flinks: 
                            all_links.add(l.strip())
                            found_this_round += 1
                    os.remove(path)
            
            print(f"Done (+{found_this_round})")
            time.sleep(2) # Prevent FloodWait

        except FloodWaitError as e:
            print(f"STOPPED: Telegram forced a wait for {e.seconds}s")
            break
        except Exception as e:
            print(f"Failed: {str(e)[:30]}")

    with open('raw_collected.txt', 'w') as f:
        f.write('\n'.join(all_links))

print(f"🏁 Harvest Total: {len(all_links)}")
