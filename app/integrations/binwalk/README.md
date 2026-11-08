# Binwalk integration

Optional second opinion next to the native scanner. Results are stored as components with
`source = 'binwalk'` and `validated = 0` (Binwalk's own signatures; the app does not re-validate them).

* **Detection order**: `settings.json → tools.binwalk` (a path, or the word `wsl`), `binwalk` on PATH,
  then on Windows `wsl binwalk` if WSL2 has it installed.
* **Versions**: v2.x text table is parsed; v3.x is run with `--log <file>.json` and the JSON is parsed
  (the v3 parser is tolerant but has **not been tested against a real v3 binary**).
* **WSL paths**: `C:\x\y.bin` → `/mnt/c/x/y.bin`.
* Binwalk is never run with `-e`; extraction is always done by the application's safe extractor.

Windows setup: `wsl --install`, then inside Ubuntu `sudo apt install binwalk`; set `"binwalk": "wsl"`.
Tested: Binwalk 2.3.3 on Linux.
