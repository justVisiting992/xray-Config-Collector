# 🚀 Xray Config Collector 🛰️

<div align="center">

| [پارسی (Persian)](README.md) | [English](README.en.md) |
| :---: | :---: |

</div>

***

## 🇬🇧 English Guide

This repo collects VLESS, VMess, Trojan, Shadowsocks and Hysteria 2 configs from Telegram channels and hundreds of public subscription lists, tests every single one, and publishes only the ones that actually work. The lists rebuild themselves every 2 hours — you just grab a link below and import it.

> **How we test:** an open port proves nothing, so every config has to pass a real traffic test first. An embedded Xray core sends an actual HTTP request through the proxy, and only the configs that carry it make the list.

***

## 🌐 Subscription Links

Copy the link for the protocol you want and paste it into your client's Subscription (or Import) box. That's all there is to it.

| Protocol 🧩 | Subscription Link (Raw Version) 🔗 | Mobile Optimized 📱 |
| :--- | :--- | :---: |
| 🔵 **Vmess** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/vmess_iran.txt` | ✅ (200) |
| 🟢 **Vless** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/vless_iran.txt` | ✅ (200) |
| 🟡 **Trojan** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/trojan_iran.txt` | ✅ (200) |
| 🟠 **ShadowSocks** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/ss_iran.txt` | ✅ (200) |
| 🟣 **Hysteria 2** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/hy2_iran.txt` | ✅ (200) |
| 🌈 **Mixed** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/mixed_iran.txt` | ❌ (Unlimited) |
| 💥 **Clash** | `https://raw.githubusercontent.com/justVisiting992/xray-Config-Collector/main/clash.yaml` | Clash / Mihomo format (500 configs) |

### ⚠️ Important Notes
* 📱 **Per-protocol lists (200 each):** Only configs that passed the live test, capped at 200 so mobile apps like **v2rayNG** and **V2Box** don't choke when they update. The order is random on purpose — the ping we measure is the distance to our test server, not to you, so ranking by it would be meaningless.
* 🌈 **Mixed list (unlimited):** Every verified config in one file, no cap. Great on desktop — on a phone it can get heavy, so stick to the per-protocol lists there.
* 💥 **Clash / Mihomo config:** A full Mihomo profile, ready to import — not just a bare proxy list. You get **500 verified configs**, roughly 100 of each protocol (VLESS, VMess, Trojan, Shadowsocks, Hysteria2), sorted into **country groups**: 🇺🇸 USA, 🇳🇱 Netherlands, 🇩🇪 Germany, 🇯🇵 Japan, 🇫🇷 France, 🇨🇦 Canada, 🇷🇺 Russia, 🇸🇬 Singapore, 🇪🇸 Spain, 🇬🇧 UK, 🇨🇭 Switzerland, 🇭🇰 Hong Kong, 🇫🇮 Finland, 🇸🇪 Sweden, 🇵🇱 Poland and 🇰🇷 South Korea, plus an auto-pick group that grabs a fast one for you. The routing is set up for Iran out of the box: Iranian sites, IPs and cloud ranges go direct; ads (Persian and global), malware, phishing, crypto miners, public trackers, Ponzi scam sites, Xiaomi telemetry and the free censored-movie download sites are blocked; Google Play, Google, Microsoft, Apple and Xiaomi services connect directly; and games go through the proxy.

***

## 📥 Recommended Clients (Download & Features)

### 🤖 Android
| Icon | Client Name | Key Features | Supported Protocols | Download |
| :---: | :--- | :--- | :--- | :---: |
| 🟢 | **v2rayNG** | Most stable & popular Android client. | Vless, Vmess, Trojan, SS | [GitHub](https://github.com/2dust/v2rayNG/releases) |
| 🔷 | **PattNG** | v2rayNG fork tuned for Iranian users, with an Aether core and extra TLS options. | Vless, Vmess, Trojan, SS, Hy2 | [GitHub](https://github.com/patterniha/PattNG/releases) |
| 🟠 | **Throne** | Successor to NekoBox on the sing-box core; massive protocol support & custom routing. | All + Hysteria 2, SSH, TUIC | [GitHub](https://github.com/throneproj/ThroneForAndroid/releases) |
| 🛡️ | **Hiddify** | Minimalist UI with one-click connection. | All + Reality, Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| ⚡ | **V2Box** | Easy sub management & modern interface. | Vless, Vmess, Reality | [Google Play](https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box) |
| 🌐 | **CMFA** | Official Mihomo (Clash Meta) client by MetaCubeX, with TUN mode and rule-based routing. | All (Mihomo) | [GitHub](https://github.com/MetaCubeX/ClashMetaForAndroid/releases) |
| 📦 | **Bettbox** | Mihomo client rebuilt from FlClash; smooth UI and low background power use, same app across desktop and Android TV. | All (Mihomo) | [GitHub](https://github.com/appshubcc/Bettbox/releases) |
| 🌟 | **Karing** | Cross-platform sing-box client with a simple UI and broad subscription format support. | All (sing-box) | [GitHub](https://github.com/KaringX/karing/releases) |

### 🪟 Windows
| Icon | Client Name | Key Features | Supported Protocols | Download |
| :---: | :--- | :--- | :--- | :---: |
| 🔵 | **v2rayN** | Powerful Windows tool with Xray core settings. | Vless, Vmess, Trojan, SS | [GitHub](https://github.com/2dust/v2rayN/releases) |
| 🔶 | **PattN** | Cross-platform GUI client (Windows, Linux, macOS) with Xray & sing-box cores. | All + Hysteria 2, TUIC | [GitHub](https://github.com/patterniha/PattN/releases) |
| 🟣 | **Throne** | Successor to Nekoray on the sing-box core; best for gaming and using TUN Mode. | All + Hysteria 2, Reality | [GitHub](https://github.com/throneproj/Throne/releases) |
| ⚙️ | **Hiddify-Next** | Modern, multi-language, cross-platform. | All + Hysteria 2, TUIC | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| 🏗️ | **Clash Verge** | Advanced traffic management via Rules. | Vless, Vmess, Trojan | [GitHub](https://github.com/zzzgydi/clash-verge/releases) |
| 📦 | **Bettbox** | Mihomo client rebuilt from FlClash; smooth UI and low background power use, same app across mobile and desktop. | All (Mihomo) | [GitHub](https://github.com/appshubcc/Bettbox/releases) |
| 🌟 | **Karing** | Cross-platform sing-box client with a simple UI and broad subscription format support. | All (sing-box) | [GitHub](https://github.com/KaringX/karing/releases) |

### 🐧 Linux
| Icon | Client Name | Key Features | Supported Protocols | Download |
| :---: | :--- | :--- | :--- | :---: |
| 💻 | **Throne** | Successor to Nekoray; native Linux build with full TUN support. | All + Hysteria 2 | [GitHub](https://github.com/throneproj/Throne/releases) |
| 🔶 | **PattN** | Cross-platform GUI client with Xray & sing-box cores. | All + Hysteria 2, TUIC | [GitHub](https://github.com/patterniha/PattN/releases) |
| 🛠️ | **v2rayA** | Web-based UI that runs as a system service. | Vless, Vmess, Trojan, SS | [GitHub](https://github.com/v2rayA/v2rayA/releases) |
| 🌀 | **Hiddify** | Easy installation & unified interface. | All + Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| 📦 | **Bettbox** | Mihomo client rebuilt from FlClash; smooth UI and low background power use, same app across mobile and desktop. | All (Mihomo) | [GitHub](https://github.com/appshubcc/Bettbox/releases) |
| 🌟 | **Karing** | Cross-platform sing-box client with a simple UI and broad subscription format support. | All (sing-box) | [GitHub](https://github.com/KaringX/karing/releases) |

### 🍏 iOS (iPhone & iPad)
| Icon | Client Name | Key Features | Supported Protocols | Download |
| :---: | :--- | :--- | :--- | :---: |
| 💠 | **FairVPN** | Simple, free, and great for beginners. | Vless, Vmess, Trojan | [App Store](https://apps.apple.com/us/app/fair-vpn/id1533873488) |
| 🚀 | **Shadowrocket** | (Paid) The most powerful client for iOS. | **All Protocols** | [App Store](https://apps.apple.com/us/app/shadowrocket/id932747118) |
| 🦊 | **FoXray** | Modern UI with native Reality/Hy2 support. | Vless, Vmess, Hy2, SS | [App Store](https://apps.apple.com/us/app/foxray/id6444898154) |
| 📦 | **V2Box** | Extremely stable on newer iOS versions. | Vless, Vmess, Reality | [App Store](https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690) |
| 🐱 | **Clash Mi** | Free, open-source Mihomo-core client by the KaringX team, with a built-in dashboard and full Meta features. | All (Mihomo) | [App Store](https://apps.apple.com/us/app/clash-mi/id6744321968) |
| 🌟 | **Karing** | Cross-platform sing-box client with a simple UI and broad subscription format support. | All (sing-box) | [App Store](https://apps.apple.com/us/app/karing/id6472431552) |

### 🍎 macOS
| Icon | Client Name | Key Features | Supported Protocols | Download |
| :---: | :--- | :--- | :--- | :---: |
| 🦊 | **FoXray** | Optimized for Apple Silicon (M1/M2/M3). | Vless, Vmess, Reality | [App Store](https://apps.apple.com/us/app/foxray/id6444898154) |
| 🔶 | **PattN** | Cross-platform GUI client with Xray & sing-box cores. | All + Hysteria 2, TUIC | [GitHub](https://github.com/patterniha/PattN/releases) |
| ⚙️ | **Hiddify** | One-click connect with sleek Mac design. | All + Hysteria 2 | [GitHub](https://github.com/hiddify/hiddify-next/releases) |
| 💎 | **V2Free** | Native Mac client with very low resource usage. | Vless, Vmess, Trojan | [GitHub](https://github.com/v2free/v2free/releases) |
| 📦 | **Bettbox** | Mihomo client rebuilt from FlClash; smooth UI and low background power use, same app across mobile and desktop. | All (Mihomo) | [GitHub](https://github.com/appshubcc/Bettbox/releases) |
| 🐱 | **Clash Mi** | Free, open-source Mihomo-core client by the KaringX team, with a built-in dashboard and full Meta features. | All (Mihomo) | [GitHub](https://github.com/KaringX/clashmi/releases) |
| 🌟 | **Karing** | Cross-platform sing-box client with a simple UI and broad subscription format support. | All (sing-box) | [GitHub](https://github.com/KaringX/karing/releases) |

***

### 🛠️ Technical Features and Capabilities
[**Latest Status and Sources Report**](https://github.com/justVisiting992/xray-Config-Collector/blob/main/report.md)


Under the hood it's a mix of Python and Go. Here's what it does, and why:
1. **Where the configs come from:**
   - A Python collector uses the **Telegram API** to pull messages straight from the biggest config channels.
   - A Go scraper watches **100+ more Telegram channels** on the web as a second source.
   - **200+ public subscription lists** from `subscriptions.txt` are fetched in parallel on every run and merged into the same pool.
   - Nothing gets lost on the way: a channel's checkpoint only moves forward once its messages have been fully processed, and the next run picks up exactly where the last one stopped.
2. **VMess links are decoded properly:**
   - VMess base64 (including the URL-safe flavour) is fully decoded, the JSON inside is parsed, and the address and port are checked before any testing happens.
3. **A real traffic test, not a ping:**
   - Anything that passes the first quick screen is tested again by an **embedded Xray core** that pushes a real HTTP request *through* the proxy. If traffic doesn't flow, the config doesn't get published.
   - **Hysteria 2** gets a real Hysteria session too (Salamander obfuscation included), not just a DNS lookup.
   - Every failed test is **retried once** — a momentary network glitch shouldn't kill a good config.
4. **Testing is parallel:**
   - Tens of thousands of configs are tested at the same time using Go goroutines.
5. **The flag is the exit country:**
   - Configs are labelled with the country of the proxy's **real exit IP** (MaxMind database), not the address you connect to — so the flag shows where your traffic actually comes out.
6. **Names that don't break clients:**
   - Remark formats are cleaned up automatically so popular clients like Hiddify Next don't choke on them.
7. **Telegram rate limits don't break the run:**
   - If Telegram throttles the Python collector, it backs off gracefully and lets the rest of the pipeline carry on.
8. **Old configs stick around:**
   - Working configs aren't thrown away. They're re-tested on every run and stay listed as long as they're alive.
9. **Shuffled, not ranked — on purpose:**
   - The latency we measure during testing is the distance from a GitHub runner to the server, which tells you nothing about how fast it'll be from your home or phone. Sorting by it would just favour whatever happens to sit near the runner. So the lists are shuffled, and every verified config gets an equal shot at the capped lists, re-randomized each run.
10. **Clash / Mihomo output:**
    - Every run also builds `clash.yaml`, a ready-to-import Mihomo profile made from the same verified configs.
11. **No duplicates:**
    - Configs are deduplicated by their full identity — server, credentials and transport settings. Variants of the same server with different TLS/SNI/path are different configs and all stay; only exact copies are removed.
12. **A safety net:**
    - If a run ever produces a nonsense result (say, zero working configs), the previous lists stay up instead of an empty file being published.
13. **One pool, tested once:**
    - The mixed list is live-tested as a whole, and each protocol list is then drawn from that same verified pool — a random 200 of the protocol's verified configs. A config can't reach any list without passing the real-traffic test first.
14. **Remarks that tell you something:**
    - Each remark shows the exit country plus the transport and encryption traits (`WS • TLS`, `TCP • Reality • Vision`, the Shadowsocks cipher, and so on). Configs that would end up with the exact same name are numbered (`01`, `02`, …) so every entry stays unique — including in `clash.yaml`.
    - The status report lists every source by a short linked name, and its counts are the real verified totals — the per-protocol numbers add up to the total exactly.
