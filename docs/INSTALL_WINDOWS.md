# Installing TV Intelligence Scanner on Windows 10/11 (64-bit)

## Option A — run from source (recommended during development)

1. Install **Python 3.11–3.13 (64-bit)** from python.org. Tick *“Add python.exe to PATH”*.
2. Open *PowerShell* in the project folder:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
3. Start the application:
   ```powershell
   python main.py
   ```
   Data is stored in `%LOCALAPPDATA%\TVIntelligenceScanner`. For a portable setup:
   `python main.py --data-dir D:\TVScanData`.
4. Check the installation without opening the GUI:
   ```powershell
   python main.py --self-check
   ```

## Option B — build a standalone EXE

```powershell
.\.venv\Scripts\Activate.ps1
installer\build_windows.bat
```
The script installs dev dependencies, runs the test suite (build aborts on failure),
runs PyInstaller and a `--self-check` of the produced executable. Output:
`dist\TVIntelligenceScanner\TVIntelligenceScanner.exe` (copy the whole folder).

## Running the tests
```powershell
pip install -r requirements-dev.txt
run_tests.bat
```

## Tesseract OCR (required for OCR, Phase 2)
1. Download the 64-bit installer from the UB-Mannheim Tesseract page (github.com/UB-Mannheim/tesseract/wiki).
2. Install to the default `C:\Program Files\Tesseract-OCR` (auto-detected). For another folder set
   `"tools": {"tesseract": "D:\\Tools\\Tesseract-OCR\\tesseract.exe"}` in `settings.json`.
3. Check: `python main.py --self-check` prints `OCR engines : tesseract 5.x`.
Without Tesseract the app runs normally, but the OCR buttons are disabled.

Optional second engine: `pip install paddleocr paddlepaddle` (large download; auto-detected).

## Online firmware search (Phase 5)
The application starts **offline**. Enable online search with the checkbox on the *Universal Firmware Finder*
page or in *Settings*. Optional API keys (stored in Windows Credential Manager, never in files):

| Key | Where to get it | Enables |
|---|---|---|
| GitHub token | github.com → Settings → Developer settings → fine-grained token (public read-only is enough) | higher rate limit, code search |
| GitLab token | gitlab.com → Preferences → Access tokens (`read_api`) | higher rate limit |
| Google Programmable Search key + engine id (cx) | programmablesearchengine.google.com + Google Cloud API key | official / community / documentation / SourceForge providers |
| Brave Search key | api.search.brave.com | same providers (can run alongside Google) |
| SearXNG URL | your own SearXNG instance with JSON output enabled | same providers, no key |

Microsoft Defender is used automatically to scan downloaded firmware.

## Device queries (Phase 6, optional)
* **UPnP discovery** needs no extra software; allow the application through the Windows firewall (private network)
  so SSDP replies on UDP 1900 can arrive.
* **ADB** (Android TVs only): install Google *Android SDK Platform-Tools* and put `adb.exe` on PATH. The TV owner must
  enable developer options / network debugging and accept the authorisation prompt on the TV.

## Optional external tools
Detected automatically on the *Settings* page.

| Tool | Used from | Install |
|---|---|---|
| 7-Zip | Phase 4 — **recommended** | https://www.7-zip.org (default path detected). Extracts SquashFS, ext2/3/4, CramFS, 7z on Windows |
| Binwalk | Phase 4 (optional) | WSL2: `sudo apt install binwalk`, then set `"binwalk": "wsl"` in settings.json |
| JFFS2 / UBI extraction | Phase 4 | Installed by `requirements.txt` (`jefferson`, `ubi_reader`) |
| Ghidra | Phase 4 (optional) | ghidra-sre.org + a supported JDK; set `GHIDRA_INSTALL_DIR` or `tools.ghidra_headless` to `support\analyzeHeadless.bat` |
| HxD | Phase 4 | mh-nexus.de |
| WSL2 | Phase 4 | `wsl --install` (admin PowerShell) |

Custom paths go in `%LOCALAPPDATA%\TVIntelligenceScanner\settings.json`, e.g.
```json
{ "tools": { "seven_zip": "D:\\Tools\\7-Zip\\7z.exe" } }
```

## Troubleshooting
* **App does not start / blank window** — update GPU drivers or run with `set QT_OPENGL=software`.
* **Logs** — `%LOCALAPPDATA%\TVIntelligenceScanner\logs\application.log`.
* **Read-only files in the library** are intentional (immutable originals). To delete one manually, clear the read-only attribute first.
