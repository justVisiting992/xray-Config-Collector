import os
import re
import time
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

# Credentials
api_id = int(os.environ['TELEGRAM_API_ID'])
api_hash = os.environ['TELEGRAM_API_HASH']
session_str = os.environ['TELEGRAM_SESSION_STRING']

# The simple, greedy regex that worked before
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
all_links = set() # THE MASTER VAULT

with TelegramClient(StringSession(session_str), api_id, api_hash) as client:
    for target in channels:
        print(f"📡 Scoping: {target}...", end=" ", flush=True)
        count_before = len(all_links)
        try:
            # Reverting to the simple get_messages that worked
            msgs = client.get_messages(target, limit=100)
            
            for m in msgs:
                # Get everything: message and caption
                content = (m.message or "") + " " + (getattr(m, 'caption', "") or "")
                
                # Extract links
                found = re.findall(regex, content, re.IGNORECASE)
                for l in found:
                    all_links.add(l.strip()) # .add() to a set handles deduplication automatically
            
            new_configs = len(all_links) - count_before
            print(f"Done (+{new_configs})")
            
        except Exception as e:
            print(f"Skipped: {type(e).__name__}")
        
        time.sleep(0.5) # Minimum delay just to be safe

# THE ONLY STEP THAT MATTERS: Writing the master vault to the file
with open('raw_collected.txt', 'w', encoding='utf-8') as f:
    if all_links:
        f.write('\n'.join(all_links))
        print(f"\n✅ SUCCESSFULLY WROTE {len(all_links)} LINKS TO raw_collected.txt")
    else:
        print("\n❌ ERROR: Vault is empty.")

print(f"🏁 Final Harvest Total: {len(all_links)}")
