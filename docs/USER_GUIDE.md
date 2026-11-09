# Panduan Pengguna — TV Intelligence Scanner 1.0

Aplikasi Windows untuk mengenal pasti TV (termasuk TV tanpa jenama/model yang diketahui), menganalisis hardware dan
firmware, mencari firmware daripada sumber awam yang dibenarkan, menilai keserasian dan mengurus upgrade melalui
kaedah rasmi sahaja.

> **Prinsip utama:** aplikasi tidak mereka keputusan. Setiap nilai menunjukkan **sumber** dan **tahap keyakinan**;
> nilai yang tiada bukti dipaparkan sebagai *not determined / unknown*. Fail firmware asal tidak pernah diubah, dan
> aplikasi **tidak pernah menulis ke TV** (tiada flashing automatik).

---

## 1. Pemasangan
1. Jalankan `TVIntelligenceScanner-Setup-1.0.0.exe` (tidak perlu hak pentadbir).
2. Pilihan tambahan (disyorkan):
   * **Tesseract OCR** (UB-Mannheim) — untuk membaca label dan skrin TV daripada gambar.
   * **7-Zip** — untuk mengekstrak SquashFS/ext4/CramFS daripada firmware.
3. Semak pemasangan: *Settings* memaparkan alat yang dikesan.

Data anda (pangkalan data, perpustakaan firmware, laporan) disimpan di `%LOCALAPPDATA%\TVIntelligenceScanner` dan
**tidak dipadam** apabila aplikasi dinyahpasang. Untuk backup, salin keseluruhan folder itu.

## 2. Aliran kerja ringkas
| Langkah | Halaman | Hasil |
|---|---|---|
| 1 | New TV Project | Daftar TV (isi hanya maklumat yang pasti) |
| 2 | TV Identification | Tambah gambar label belakang / skrin *System Information* → **Run OCR** → terima/tolak nilai |
| 3 | Visual Scanner | Crop cip/papan → OCR → sahkan tanda cip & nombor PCB |
| 4 | Hardware Analyzer | Analisis komponen, datasheet, ringkasan board |
| 5 | Firmware Library → Firmware Analyzer | Import firmware → analisis struktur, metadata, ekstrak fail |
| 6 | Universal Firmware Finder | Cari firmware dalam talian (pilihan) → muat turun dengan semakan hash |
| 7 | Software Analyzer / Factory & Service Menu | OS, kernel, aplikasi, driver; menu servis yang didokumenkan |
| 8 | Compatibility Analyzer | Nilai firmware calon berbanding TV |
| 9 | Firmware Upgrade Manager | Upgrade melalui profil rasmi yang disahkan |
| 10 | Reports | Laporan PDF / XLSX / CSV / JSON / HTML |

## 3. Mengenal pasti TV
* **New TV Project**: nama projek wajib; medan lain boleh dibiarkan kosong jika tidak diketahui. Status: `unknown` →
  `partial` → `identified` → `verified`.
* **TV Identification**: tambah gambar (jenis: label belakang, label produk, menu System Information, mainboard,
  cip, PSU, T-Con, label panel). Klik **Run OCR on new evidence**. Tab *OCR candidates* memaparkan setiap nilai
  dengan keyakinan dan baris sumber. **Accept** menulis nilai ke projek; nilai lain bagi medan yang sama ditolak.
* Status **verified** hanya apabila jenama **dan** model diterima daripada bukti gambar.
* TV tanpa model: isi nombor mainboard/chassis — *Catalog matching* dan Firmware Finder boleh bekerja dengannya.

## 4. Visual Scanner & Hardware Analyzer
* Seret tetikus pada gambar untuk crop satu cip; pilih preset (*chip_marking*, *pcb_silkscreen*, ...) → **Run OCR**.
* Tab *Chip / PCB markings*: sahkan tanda yang betul (boleh betulkan nombor bahagian) → menjadi komponen hardware.
* **Hardware Analyzer → Analyze**: jenama/keluarga dari konvensyen nombor, kapasiti memori dari *decoder* pengeluar,
  fakta dari datasheet anda (import PDF di tab *Datasheet library*). Jumlah RAM/flash hanya dikira jika **semua** cip
  mempunyai bukti kapasiti.

## 5. Firmware
* **Firmware Library → Import**: fail disalin, disahkan SHA-256 dan disimpan *read-only*. Fail sumber anda tidak
  disentuh. Fail yang sama tidak disimpan dua kali.
* **Firmware Analyzer → Analyze**: imbasan struktur (uImage, SquashFS, ext4, UBI, JFFS2, Android, GPT, ...),
  entropi (penunjuk enkripsi), strings, metadata (kernel, CPU, OS, versi), pengekstrakan selamat, fail konfigurasi.
  Baris *original SHA-256 UNCHANGED ✔* membuktikan fail asal tidak berubah.
* *Compare*: bandingkan dua firmware. *Hex*: lihat bait mentah. *Extracted files → Import selected*: masukkan fail
  dalaman (contoh `upgrade.bin` dalam ZIP) ke perpustakaan dengan rekod asal-usul.

## 6. Universal Firmware Finder (dalam talian)
* Aplikasi bermula **offline**. Tandakan *Online search enabled* untuk membenarkan carian.
* **Load criteria from project** → semak senarai *Queries* → pilih penyedia → **Search**.
* Keputusan: `VERIFIED MATCH`, `HIGH CONFIDENCE MATCH`, `POSSIBLE MATCH`, `INCOMPATIBLE`, `INSUFFICIENT INFORMATION`,
  dengan skor dan risiko. **Hasil carian tidak pernah VERIFIED** — hanya selepas muat turun, hash sepadan dengan
  nilai yang diterbitkan sumber, dan analisis menemui model TV dalam fail.
* **Download Firmware**: hash disemak, fail diimbas Microsoft Defender, kemudian dimasukkan ke perpustakaan.
  Hash tidak sepadan → fail dikuarantin.
* API key (pilihan) disimpan dalam *Windows Credential Manager* melalui *Settings*.

## 7. Software Analyzer & Factory / Service Menu
* **Software Analyzer → Analyze software**: menggabungkan bukti firmware, foto skrin *System Information* dan nilai
  yang anda masukkan (rujukan wajib). Tab *Device (authorised)*: penemuan UPnP di LAN dan ADB baca-sahaja untuk
  Android TV — hanya selepas anda menulis kenyataan kebenaran.
* **Factory & Service Menu**: setiap rekod **wajib** memetik dokumentasi rasmi (manual servis + halaman / laman
  rasmi). Prosedur meneka kata laluan/brute-force ditolak. Tab *Service manual search* mencari petikan "service
  mode" dalam manual PDF anda.
* Mengubah tetapan kilang: **Plan** → **Record backup** (jika manual menyebut cara backup) → **Confirm** (taip
  `CHANGE <setting>`) → **Mark performed**. Aplikasi sendiri tidak mengubah tetapan TV.

## 7b. Sambungan ke TV (baca-sahaja)
Lokasi: **Software Analyzer → tab "Device (authorised)"**. Pilih projek TV dahulu. Isi medan *Authorisation*
(sekurang-kurangnya 10 aksara, contoh `TV sendiri, pemilik hadir`), barulah butang berfungsi.

**A. UPnP (kebanyakan Smart TV: Samsung, LG, Sony, TCL, Hisense, ...)**
1. TV dihidupkan dan disambung ke **rangkaian Wi-Fi/LAN yang sama** dengan PC.
2. Klik **Discover UPnP devices on LAN**. Jika Windows Firewall bertanya, benarkan rangkaian *Private*.
3. Pilih TV dalam senarai → **Link selected device to project**. Jenama, model dan nombor siri disimpan sebagai bukti.

**B. ADB (Android TV / Google TV sahaja)**
1. Pasang *Android SDK Platform-Tools* (https://developer.android.com/tools/releases/platform-tools), ekstrak dan
   tambah folder `platform-tools` ke PATH (atau ekstrak ke `C:\platform-tools`). Mulakan semula aplikasi.
2. Di TV: *Settings → Device Preferences → About* → klik **Build** 7 kali (Developer options aktif) →
   *Developer options* → hidupkan **USB debugging / Network debugging**.
3. Cari alamat IP TV: *Settings → Network → (rangkaian anda)*.
4. Dalam aplikasi, taip `IP:5555` (contoh `192.168.1.50:5555`) → **Collect via ADB (read-only)**.
5. Di TV, terima mesej **"Allow USB debugging?"** (tandakan *Always allow*), kemudian klik butang sekali lagi.

Hanya arahan baca-sahaja dibenarkan (getprop, uname, senarai pakej, saiz skrin, rangkaian, modul kernel).
TV bukan Android (Tizen, webOS, Linux biasa) **tidak** mempunyai ADB — gunakan UPnP, foto skrin *System Information*
dan analisis firmware. Aplikasi tidak menggunakan SSH/Telnet/UART dan tidak meneka kata laluan.

## 8. Keserasian dan Upgrade
* **Compatibility Analyzer**: pilih TV dan firmware calon (yang telah dianalisis). Baseline = firmware asal TV yang
  telah dianalisis (kategori *Original*). Setiap kriteria (model, board, SoC, CPU, RAM, flash, panel, bootloader,
  driver, partition, tandatangan, integriti) dipaparkan dengan bukti.
* **Firmware Upgrade Manager**:
  1. Tab *Upgrade profiles*: cipta profil daripada arahan rasmi pengeluar (dokumentasi wajib), kemudian
     **Mark as verified** (taip `VERIFIED <pengeluar>`).
  2. Tab *Upgrade session*: pilih TV, profil, firmware → **Start session** → langkah 1–8.
  3. Hanya **Official USB Upgrade** boleh dilaksanakan: aplikasi menyalin pakej ke USB (FAT32/nama/laluan seperti
     dalam manual) dan mengesahkan SHA-256. Masukkan USB ke TV dan ikut arahan pengeluar.
     **Jangan matikan TV semasa TV sedang mengemas kini.**
  4. Kaedah lain (rangkaian, service tool, UART, recovery) hanya menghasilkan arahan dan laporan untuk juruteknik.
  5. Selepas TV dikemas kini: **Verify** (versi, model, fungsi asas) dan **Recovery guidance**.

## 9. Laporan
*Reports*: pilih jenis laporan (10 jenis), subjek dan format (PDF, XLSX, CSV, JSON, HTML) → **Generate**. Setiap
laporan mempunyai tarikh, sumber, keputusan dan keyakinan, dan didaftarkan dengan SHA-256. HTML memaparkan gambar bukti.

## 10. Penyelesaian masalah
| Masalah | Penyelesaian |
|---|---|
| Butang OCR tidak aktif | Pasang Tesseract; semak *Settings → OCR engines* |
| SquashFS/ext4 tidak diekstrak | Pasang 7-Zip |
| Carian gagal: "Offline mode" | Tandakan *Online search enabled* |
| "rate limited; retry after N s" | Tunggu, atau masukkan token GitHub di *Settings* |
| UPnP tidak menemui TV | TV dan PC dalam rangkaian sama; benarkan aplikasi dalam Windows Firewall (rangkaian *Private*); hidupkan ciri berkongsi skrin/DLNA di TV |
| "adb not found" | Pasang Platform-Tools dan tambah ke PATH (lihat 7b) |
| "Could not connect to …:5555" | IP salah, TV dalam rangkaian lain, atau *Network debugging* tidak dihidupkan |
| "The TV has not authorised this computer" | Terima mesej di skrin TV, kemudian cuba semula |
| Log | `%LOCALAPPDATA%\TVIntelligenceScanner\logs\application.log` |
