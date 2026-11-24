# 🚀 Xray Config Collector 🛰️

<div align="center">

| [فارسی (Persian)](README.md) | [English](README.en.md) |
| :---: | :---: |

</div>

***

## 🇬🇧 English Guide

This project is a high-speed engine designed to automatically scrape, test, and filter VLESS, VMESS, Trojan, Shadowsocks, and Hysteria 2 configurations from Telegram channels and hundreds of public subscription lists.

> **Quality Assurance:** Every configuration must pass a **live traffic test** before being published: a real HTTP request is sent through the proxy using an embedded Xray core, so only configs that demonstrably carry traffic — not just ones with an open port — are listed. The lists are rebuilt automatically **every 2 hours**.

***

## 🌐 Subscription Links

To use these, simply copy the desired URL and paste it into the "Subscription" or "Import" section of your VPN client.

| Protocol 🧩 | Subscription Link (Raw Version) 🔗 | Mobile Optimized 📱 |
| :--- | :--- | :---: |
| 🔵 **Vmess** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/vmess_iran.txt` | ✅ (Top 200) |
| 🟢 **Vless** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/vless_iran.txt` | ✅ (Top 200) |
| 🟡 **Trojan** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/trojan_iran.txt` | ✅ (Top 200) |
| 🟠 **ShadowSocks** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/ss_iran.txt` | ✅ (Top 200) |
| 🟣 **Hysteria 2** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/hy2_iran.txt` | ✅ (Top 200) |
| 🌈 **Mixed** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/mixed_iran.txt` | ❌ (Unlimited) |
| 💥 **Clash** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/clash.yaml` | Clash / Mihomo format |

### ⚠️ Important Notes
* 📱 **Categorized Lists (Top 200):** These lists contain only **live-verified** configs, capped at 200 and presented in **random order** — deliberately unranked, because the latency measured during testing only reflects the distance to the test server, not to you. This optimization is specifically for mobile devices to prevent apps like **v2rayNG** or **V2Box** from lagging or crashing during updates.
* 🌈 **Mixed List (Unlimited):** This file contains **every** live-verified configuration, with no cap. **It is recommended to use this link only on desktop clients** (Windows/Linux/Mac), as PC hardware can handle this volume of data without performance drops.

***

## 📥 Recommended Clients (Download & Features)

### 🤖 Android
| Icon | Client Name | Key Features | Supported Protocols | Download |
| :---: | :--- | :--- | :--- | :---: |
| 🟢 | **v2rayNG** | Most stable & popular Android client. | Vless, Vmess, Trojan, SS | [Google Play](https://play.google.com/store/apps/details?id=com.v2ray.ang) |
| 🔷 | **PattNG** | v2rayNG fork tuned for Iranian users, with an Aether core and extra TLS options. | Vless, Vmess, Trojan, SS, Hy2 | [GitHub](https://github.com/patterniha/PattNG/releases) |
| 🟠 | **NekoBox** | Massive protocol support & custom routing. | All + Hysteria 2, SSH, TUIC | [GitHub](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases) |
| 🛡️ | **Hiddify** | Minimalist UI with one-click connection. | All + Reality, Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| ⚡ | **V2Box** | Easy sub management & modern interface. | Vless, Vmess, Reality | [Google Play](https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box) |

### 🪟 Windows
| Icon | Client Name | Key Features | Supported Protocols | Download |
| :---: | :--- | :--- | :--- | :---: |
| 🔵 | **v2rayN** | Powerful Windows tool with Xray core settings. | Vless, Vmess, Trojan, SS | [GitHub](https://github.com/2dust/v2rayN/releases) |
| 🔶 | **PattN** | Cross-platform GUI client (Windows, Linux, macOS) with Xray & sing-box cores. | All + Hysteria 2, TUIC | [GitHub](https://github.com/patterniha/PattN/releases) |
| 🟣 | **Nekoray** | Best for gaming and using TUN Mode. | All + Hysteria 2, Reality | [GitHub](https://github.com/MatsuriDayo/nekoray/releases) |
| ⚙️ | **Hiddify-Next** | Modern, multi-language, cross-platform. | All + Hysteria 2, TUIC | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| 🏗️ | **Clash Verge** | Advanced traffic management via Rules. | Vless, Vmess, Trojan | [GitHub](https://github.com/zzzgydi/clash-verge/releases) |

### 🐧 Linux
| Icon | Client Name | Key Features | Supported Protocols | Download |
| :---: | :--- | :--- | :--- | :---: |
| 💻 | **Nekoray** | Native Linux build with full TUN support. | All + Hysteria 2 | [GitHub](https://github.com/MatsuriDayo/nekoray/releases) |
| 🔶 | **PattN** | Cross-platform GUI client with Xray & sing-box cores. | All + Hysteria 2, TUIC | [GitHub](https://github.com/patterniha/PattN/releases) |
| 🛠️ | **v2rayA** | Web-based UI that runs as a system service. | Vless, Vmess, Trojan, SS | [GitHub](https://github.com/v2rayA/v2rayA/releases) |
| 🌀 | **Hiddify** | Easy installation & unified interface. | All + Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |

### 🍏 iOS (iPhone & iPad)
| Icon | Client Name | Key Features | Supported Protocols | Download |
| :---: | :--- | :--- | :--- | :---: |
| 💠 | **FairVPN** | Simple, free, and great for beginners. | Vless, Vmess, Trojan | [App Store](https://apps.apple.com/us/app/fair-vpn/id1533873488) |
| 🚀 | **Shadowrocket** | (Paid) The most powerful client for iOS. | **All Protocols** | [App Store](https://apps.apple.com/us/app/shadowrocket/id932747118) |
| 🦊 | **FoXray** | Modern UI with native Reality/Hy2 support. | Vless, Vmess, Hy2, SS | [App Store](https://apps.apple.com/us/app/foxray/id6444898154) |
| 📦 | **V2Box** | Extremely stable on newer iOS versions. | Vless, Vmess, Reality | [App Store](https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690) |

### 🍎 macOS
| Icon | Client Name | Key Features | Supported Protocols | Download |
| :---: | :--- | :--- | :--- | :---: |
| 🦊 | **FoXray** | Optimized for Apple Silicon (M1/M2/M3). | Vless, Vmess, Reality | [App Store](https://apps.apple.com/us/app/foxray/id6444898154) |
| 🔶 | **PattN** | Cross-platform GUI client with Xray & sing-box cores. | All + Hysteria 2, TUIC | [GitHub](https://github.com/patterniha/PattN/releases) |
| ⚙️ | **Hiddify** | One-click connect with sleek Mac design. | All + Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| 💎 | **V2Free** | Native Mac client with very low resource usage. | Vless, Vmess, Trojan | [GitHub](https://github.com/v2free/v2free/releases) |

***

### 🛠️ Technical Features and Capabilities
[**Latest Status and Sources Report**](https://github.com/justVisiting992/xray-Config-Collector/blob/main/report.md)


This project has been rewritten using a combination of Python and Go to ensure maximum accuracy and speed in resource collection. Key features include:
1. **Dual Collection (API + Scraper):**
   - Uses **Telegram API** (Python) to directly extract messages from the largest config sources at high speed.
   - Uses a **Web Scraper** (Go) as a backup system to monitor over 100 additional Telegram channels.
   - Also harvests **200+ public subscription lists** from `subscriptions.txt`, fetched in parallel every run and merged into the same pool as the Telegram harvest.
   - Collection is **lossless**: per-channel checkpoints only advance after a run has fully processed what it fetched, and paging always resumes exactly where the previous run stopped — no message is ever skipped silently.
2. **Smart VMess Decoding:**
   - Unlike basic scripts, this code fully decodes VMess Base64 strings (including the URL-safe alphabet), analyzes the internal JSON, and verifies the address and port before testing.
3. **Live Traffic Testing (Real Proxy Verification):**
   - Passing a ping is not enough. Every config that survives the fast reachability screen is tested again by an **embedded Xray core** that sends a real HTTP request *through* the proxy. Only configs that actually carry traffic are published.
   - This includes **Hysteria 2**, which is verified with a genuine Hysteria session (including Salamander obfuscation) — not a DNS lookup.
   - Every failed test is **retried once**, so a transient network hiccup never silently drops a working config.
4. **Multi-threaded Health Checks:**
   - Simultaneous testing of tens of thousands of configs using Go's Goroutines.
5. **Geo-IP Tagging by True Exit IP:**
   - Configs are labelled with the country of the proxy's **real exit IP** (via the MaxMind database), not the entry server's address — so the flag shows where your traffic actually comes out.
6. **Full Hiddify & NapsternetV Compatibility:**
   - Automatically corrects naming formats (Fragment) to prevent errors in popular clients like Hiddify Next.
7. **Telegram Flood Error Handling:**
   - The intelligent Python Collector automatically steps out of the loop if it hits Telegram's rate limits, allowing the rest of the script to continue without interruption.
8. **Automatic Archiving (History Preservation):**
   - Old working configs are not deleted. They are re-tested with every update and remain in the list as long as they stay alive.
9. **Random Order (No Latency Ranking):**
   - Published lists are **shuffled**, not sorted. The latency measured during the live test is the latency from the test server (a GitHub runner), which says nothing about performance from a user's location — ranking by it would favour servers near the runner and starve distant ones. Every verified config gets an equal chance at the capped lists, re-randomized each run.
10. **Clash / Mihomo Output:**
    - Every run also publishes `clash.yaml`, a ready-to-import Clash-format subscription built from the same live-verified configs.
11. **Precise Deduplication:**
    - Configs are deduplicated by their full identity — server, credentials and transport settings — so transport variants of the same server (different TLS/SNI/path) are all kept, while true duplicates are removed.
12. **Safety Guards:**
    - If a test run ever produces an impossible result (e.g. zero passing configs), the previous list is kept instead of publishing an empty one.
13. **One Verified Pool:**
    - The whole pool is live-tested once, as the mixed list. Each protocol list is then drawn from that same verified pool — a random 200 of the protocol's verified configs — so a config can only reach *any* list by passing the real-traffic test, and every verified config is eligible for its protocol list.
14. **Informative Remarks & Transparent Report:**
    - Each config's remark shows its exit country plus its transport and encryption traits (e.g. `WS • TLS`, `TCP • Reality • Vision`, the Shadowsocks cipher); configs that would share the exact same remark are numbered (`01`, `02`, …) so every entry is unique — including in `clash.yaml`.
    - The status report names every source with a short linked name, and its live counts are the actual verified totals, so the per-protocol numbers add up exactly to the total.
