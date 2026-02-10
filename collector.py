import os, re, time, random, requests

# The FIXED Regex (Full links, no protocol-only bullshit)
regex = r"(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s'\"<>\(\)\[\]]+"

def get_channels():
    names = []
    try:
        with open('channels.csv', 'r') as f:
            for line in f:
                if "URL,AllMessagesFlag" in line or not line.strip(): continue
                # Extract channel name from URL
                u = line.split(',')[0].strip().split('/')[-1]
                if u: names.append(u)
    except: pass
    return list(dict.fromkeys(names))

channels = get_channels()
random.shuffle(channels)
total_found = 0

# Fresh start for the raw file
with open('raw_collected.txt', 'w', encoding='utf-8') as f:
    f.write("")

print(f"🕵️  WEB-SURGE MODE | Bypassing API Ban | Channels: {len(channels)}")

# Use a common Browser User-Agent to avoid being blocked as a script
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

for i, target in enumerate(channels):
    print(f"🌐 {i+1}/{len(channels)} | {target}...", end=" ", flush=True)
    
    try:
        # We hit the public preview URL (t.me/s/CHANNELNAME)
        url = f"https://t.me/s/{target}"
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            content = response.text
            found = re.findall(regex, content, re.IGNORECASE)
            
            if found:
                links = [l.strip() for l in found]
                with open('raw_collected.txt', 'a', encoding='utf-8') as f:
                    f.write('\n'.join(links) + '\n')
                print(f"+{len(links)}")
                total_found += len(links)
            else:
                print("0")
        else:
            print(f"Fail ({response.status_code})")

    except Exception as e:
        print(f"Error ({type(e).__name__})")
    
    # Tiny sleep so we don't look like a DDOS attack
    time.sleep(random.uniform(1, 3))

print(f"\n🏁 WEB HARVEST COMPLETE. TOTAL LINKS: {total_found}")
