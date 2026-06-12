# flutter_ssl_patch

> Patch `ssl_verify_peer_cert` di binary Flutter (`libflutter.so`) menggunakan radare2 — tanpa Frida, tanpa root runtime.

---

## Cara kerja

Flutter menggunakan implementasi TLS internal dari BoringSSL. Fungsi `ssl_verify_peer_cert` bertanggung jawab memverifikasi sertifikat server. Script ini:

1. Membuka `libflutter.so` dengan radare2 dalam mode write (`-w`)
2. Menjalankan analisis call reference (`aac`)
3. Mencari offset `ssl_verify_peer_cert` via byte pattern matching (wildcard `/x`)
4. Mempatch opcode fungsi tersebut menjadi `ret0` atau `ret1` — sehingga verifikasi selalu dianggap sukses

Tidak ada dependency runtime selain Python 3 dan radare2. `r2pipe` di-install otomatis jika belum ada.

---

## Requirements

| Dependency | Versi minimum |
|---|---|
| Python | 3.10+ |
| radare2 | 5.x / 6.x |
| r2pipe | auto-install |

Install radare2:

```bash
# macOS
brew install radare2

# Debian / Ubuntu
sudo apt install radare2

# atau dari source
git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh
```

---

## Penggunaan

```
python3 fluttsl.py [-h] -f FILE [-x {arm,arm64,x86}] [--dry]
```

### Argumen

| Flag | Alias | Keterangan |
|---|---|---|
| `-f FILE` | `--file` | Path ke `libflutter.so` **(wajib)** |
| `-x ARCH` | `--arch` | Force arsitektur: `arm` \| `arm64` \| `x86` — auto-detect jika tidak diisi |
| `--dry` | — | Dry run: cari offset saja, **tidak** menulis patch |
| `-h` | `--help` | Tampilkan bantuan |

---

## Contoh

**Patch langsung (auto-detect arch):**
```bash
python3 fluttsl.py -f libflutter.so
```

**Patch dengan force arch arm64:**
```bash
python3 fluttsl.py -f libflutter.so -x arm64
```

**Dry run — cek offset tanpa patch:**
```bash
python3 fluttsl.py -f libflutter.so --dry
```

**Output sukses:**
```
  flutterSSL  ssl_verify_peer_cert patcher

[-] Opening binary: libflutter.so
[-] Running call analysis (aac) — may take a moment ...
[-] Scanning for ssl_verify_peer_cert ...
[-] Architecture : arm64
  offset   : 0x006f3abc
  pattern# : 1
  function : 0x006f3abc
[+] ssl_verify_peer_cert patched!  (wao ret0 @ 0x006f3abc)
```

**Output dry run:**
```
[-] Dry run — patch skipped  (wao ret0 would have been applied at 0x006f3abc)
```

**Output jika tidak ditemukan:**
```
[!] ssl_verify_peer_cert not found — no matching pattern in binary.
```

---

## Indikator output

| Prefix | Warna | Arti |
|---|---|---|
| `[+]` | Hijau | Sukses / operasi berhasil |
| `[-]` | Kuning | Info / proses berjalan |
| `[!]` | Merah | Error / gagal |

---

## Arsitektur & pattern yang didukung

| Arch | Jumlah pattern | Patch opcode |
|---|---|---|
| `arm64` | 5 | `wao ret0` (atau `ret1` untuk pattern #3) |
| `arm` | 1 | `wao ret0` |
| `x86` | 5 | `wao ret0` (atau `ret1` untuk pattern #5) |

Pattern bersumber dari [NVISOsecurity/disable-flutter-tls-verification](https://github.com/NVISOsecurity/disable-flutter-tls-verification).

> **Catatan pattern #3 (arm64) & #5 (x86):** pattern tersebut menarget `session_verify_cert_chain` bukan `ssl_verify_peer_cert` langsung, sehingga patch menggunakan `ret1` (bukan `ret0`).

---

## Cara mendapatkan libflutter.so

Dari APK Android:

```bash
# unzip APK
unzip target.apk -d target_apk/

# binary ada di:
# target_apk/lib/arm64-v8a/libflutter.so
# target_apk/lib/armeabi-v7a/libflutter.so
# target_apk/lib/x86_64/libflutter.so
```

Untuk iOS (`App.framework`), gunakan `lipo` untuk extract slice yang diinginkan sebelum menjalankan script.

---

## Setelah patch

Untuk Android — repack APK dan sign ulang:

```bash
# repack
zip -r patched.apk target_apk/

# sign dengan apksigner
apksigner sign --ks keystore.jks --out patched_signed.apk patched.apk
```

Lalu install ke device / emulator:

```bash
adb install patched_signed.apk
```

Konfirmasi bypass dengan intercept traffic via Burp Suite / mitmproxy.

---

## Disclaimer

Tool ini dibuat untuk keperluan **penetration testing, security research, dan bug bounty** pada aplikasi yang kamu miliki atau memiliki izin untuk diuji. Penggunaan terhadap aplikasi tanpa izin melanggar hukum. Gunakan secara bertanggung jawab.

---

## Credits
- TLS pattern source: [NVISOsecurity](https://github.com/NVISOsecurity/disable-flutter-tls-verification)
