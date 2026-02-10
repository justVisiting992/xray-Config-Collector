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

# CREATE/WIPE THE FILE AT THE START
with open('raw_collected.txt', 'w', encoding='utf-8') as f:
    f.write("") 

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    for target in channels:
        print(f"📡 Scoping: {target}...", end=" ", flush=True)
        found_in_channel = []
        try:
            # Try to get messages
            msgs = client.get_messages(target, limit=100)
            
            # If blocked/empty, try to Join
            if not msgs:
                try:
                    client(JoinChannelRequest(target))
                    time.sleep(1)
                    msgs = client.get_messages(target, limit=100)
                except: pass

            if msgs:
                for m in msgs:
                    # Extract from Text
                    content = (m.message or "") + " " + (getattr(m, 'caption', "") or "")
                    links = re.findall(regex, content, re.IGNORECASE)
                    for l in links:
                        found_in_channel.append(l.strip())
                    
                    # Extract from Files
                    if m.file and any(ext in (m.file.ext or "").lower() for ext in ['.txt', '.json']):
                        try:
                            path = client.download_media(m)
                            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                                file_links = re.findall(regex, f.read(), re.IGNORECASE)
                                for l in file_links:
                                    found_in_channel.append(l.strip())
                            os.remove(path)
                        except: continue

            # IMMEDIATE APPEND TO FILE (The "Safety Net")
            if found_in_channel:
                with open('raw_collected.txt', 'a', encoding='utf-8') as f:
                    f.write('\n'.join(found_in_channel) + '\n')
                print(f"Done (+{len(found_in_channel)})")
            else:
                print("No links found.")
                
            time.sleep(1)

        except Exception as e:
            print(f"Error: {type(e).__name__}")

# Check final file size
if os.path.exists('raw_collected.txt'):
    size = os.path.getsize('raw_collected.txt')
    print(f"🏁 Final File Size: {size} bytes")                        all_links.add(l.strip())
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
