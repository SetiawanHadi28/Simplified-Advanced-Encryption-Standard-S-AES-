# S-AES Simulator

Simulasi kriptografi **Simplified Advanced Encryption Standard (S-AES)** berbasis web,
dibangun menggunakan **Python Flask** (backend) dan **Bootstrap 5 + HTML5 + CSS3 + JavaScript**
(frontend). Seluruh algoritma S-AES diimplementasikan secara manual tanpa library kriptografi,
lengkap dengan visualisasi step-by-step untuk setiap tahapan proses.

## ✨ Fitur

- **Enkripsi & Dekripsi S-AES** 16-bit penuh (plaintext/ciphertext + key 16-bit biner)
- Output dalam format **biner** dan **heksadesimal**
- Validasi input real-time (hanya 0/1, panjang tepat 16 bit)
- **Visualisasi step-by-step** lengkap:
  - Key Expansion (w0–w5, RotWord, SubWord, RCON, K0/K1/K2)
  - Initial AddRoundKey
  - Round 1 (SubNibbles, ShiftRows, MixColumns + detail perkalian GF(2⁴), AddRoundKey)
  - Round 2 (SubNibbles, ShiftRows, AddRoundKey → Ciphertext)
  - Seluruh proses invers pada dekripsi
- Halaman **About S-AES** (teori & penjelasan tiap fungsi)
- Halaman **References** (tabel S-Box, Inverse S-Box, matriks MixColumns, RCON, penjelasan GF(2⁴))
- Desain modern, responsif, tema Dark Blue + White dengan Bootstrap Icons

## 🗂️ Struktur Proyek

```
saes_flask/
├── app.py                  # Entry point Flask + routing + Jinja filters
├── saes.py                 # Implementasi murni algoritma S-AES + trace langkah
├── requirements.txt
├── Procfile                 # Untuk deploy ke Railway
├── vercel.json               # Untuk deploy ke Vercel
├── railway.json
├── runtime.txt
├── templates/
│   ├── base.html            # Layout dasar (navbar + footer)
│   ├── _macros.html         # Macro Jinja untuk render state matrix & GF detail
│   ├── home.html
│   ├── encrypt.html
│   ├── decrypt.html
│   ├── about.html
│   ├── references.html
│   └── 404.html
└── static/
    ├── css/style.css        # Tema Dark Blue + White, kartu, animasi hover
    └── js/main.js            # Validasi input, random-fill, copy-to-clipboard
```

## ▶️ Menjalankan Secara Lokal

```bash
# 1. Buat virtual environment (opsional tapi disarankan)
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Jalankan aplikasi
python app.py
```

Buka browser ke `http://localhost:5000`.

## 🚀 Deploy

### Railway
1. Push proyek ini ke repository GitHub.
2. Buat project baru di [Railway](https://railway.app), hubungkan ke repo.
3. Railway akan otomatis mendeteksi `Procfile` / `railway.json` dan menjalankan
   `gunicorn app:app --bind 0.0.0.0:$PORT`.
4. Tambahkan custom domain (`.my.id`) melalui menu **Settings → Domains** pada project Railway,
   lalu arahkan DNS (CNAME) domain Anda sesuai instruksi yang diberikan Railway.

### Vercel
1. Push proyek ke GitHub.
2. Import project di [Vercel](https://vercel.com), Vercel akan membaca `vercel.json`
   dan builder `@vercel/python` secara otomatis.
3. Tambahkan custom domain `.my.id` melalui menu **Settings → Domains** pada project Vercel.

## 🧮 Parameter S-AES

| Parameter | Nilai |
|---|---|
| Ukuran blok | 16 bit |
| Ukuran key | 16 bit |
| Jumlah round | 2 |
| Field | GF(2⁴) |
| Polinomial irreducible | x⁴ + x + 1 (0x13) |
| RCON1 | 0x80 |
| RCON2 | 0x30 |

## 📚 Referensi

Musa, M. A., Schaefer, E. F., & Wedig, S. (2003). *A Simplified AES Algorithm and Its Linear
and Differential Cryptanalyses*. Cryptologia, 27(2), 148–177.

## 👤 Pembuat

Dibuat untuk keperluan pembelajaran mata kuliah Kriptografi — topik Simplified AES (S-AES).

---
&copy; 2026 S-AES Simulator.
