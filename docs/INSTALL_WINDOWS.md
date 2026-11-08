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

## Optional external tools
Not needed for Phase 1; detected automatically on the *Settings* page.

| Tool | Used from | Install |
|---|---|---|
| 7-Zip | Phase 4 | https://www.7-zip.org (default path is detected) |
| Tesseract OCR | Phase 2 | UB-Mannheim Windows build; default `C:\Program Files\Tesseract-OCR` |
| Binwalk | Phase 4 | Via WSL2 (`sudo apt install binwalk`) or binwalk v3 Windows build |
| Ghidra | Phase 4 | ghidra-sre.org; set `tools.ghidra_headless` to `support\analyzeHeadless.bat` |
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
