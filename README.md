# 🚀 IP:Port Extractor

A high-performance, multi-threaded **IP:Port extractor** for Windows, designed for processing **very large files (GB+)** with minimal memory usage.

> ⚡ Fast | 🧵 Multi-threaded | 💾 Low RAM | 🪟 Windows optimized

---

## ✨ Features

* 🔥 **Streaming I/O** (handles huge files without RAM explosion)
* ⚡ **High performance parsers** (no heavy regex unless needed)
* 🧵 **Multi-threading support**
* 📦 **Supports multiple formats:**

  * Angry IP Scanner
  * Masscan
  * Nmap (Normal, Grepable, XML)
  * Generic IP:Port
  * Custom Regex
* 🎯 **Accurate IP validation (0–255 per octet)**
* 🖥️ Windows console UI with colors

---

## 🛠️ Build

### MinGW / MSYS2

```bash
g++ -O3 -std=c++17 -pthread -o ip_extractor.exe ip_extractor.cpp
```

### MSVC

```bash
cl /O2 /std:c++17 /EHsc ip_extractor.cpp /Fe:ip_extractor.exe
```

---
## 📥 Download

دانلود نرم افزار 

👉 [Download v1.0](https://github.com/mehdirzfx/IPExtractor/releases/tag/v1.0)

Releases:
👉 https://github.com/mehdirzfx/IPExtractor/releases

---

## ▶️ Usage

Run the program:

```bash
ip_extractor.exe
```

Then:

1. Select input format
2. Enter input file
3. Enter output file
4. Choose number of threads

---

## 📥 Supported Formats

| Mode | Description                   |
| ---- | ----------------------------- |
| 1    | Angry IP Scanner              |
| 2    | Masscan                       |
| 3    | Nmap Normal (-oN)             |
| 4    | Nmap Grepable (-oG)           |
| 5    | Nmap XML (-oX)                |
| 6    | Generic (auto-detect IP:Port) |
| 7    | Custom Regex                  |

---

## 🔍 Custom Regex

You can define your own parsing pattern.

Examples:

```regex
(\d+\.\d+\.\d+\.\d+):(\d+)
host=(\d+\.\d+\.\d+\.\d+)\s+port=(\d+)
open\s+\w+\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)
```

Supports:

* 2 groups → IP + Port
* 1 group → IP:Port
* 0 groups → full match = IP:Port

---

## ⚠️ Notes

* Some parsers are **stateful** → forced single-thread (e.g. Nmap XML/Normal)
* Designed for **speed over fancy parsing**
* Works best with clean scan outputs

---

## 🤝 Contributing

پروژه هنوز جای بهتر شدن خیلی داره 💪

اگر ایده داری یا میخوای کمک کنی:

* 🚀 اضافه کردن parser جدید
* ⚡ بهینه‌سازی performance
* 🧠 بهبود تشخیص فرمت‌ها
* 🧩 اضافه کردن exportهای جدید (مثلا JSON / Telegram proxy)

Pull Request بده یا Issue باز کن ✌️
