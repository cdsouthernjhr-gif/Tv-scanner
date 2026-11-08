# Software & OS Analyzer and Factory & Service Menu (Phase 6)

## Software & OS Analyzer (`app/modules/software_analyzer/`)
| Source (`software_facts.source_type`) | What it provides |
|---|---|
| `firmware_analysis` | Phase 4 metadata (OS family, Android version, kernel, build id/fingerprint/date, bootloader, platform, model) and the extracted file tree: applications (Android APK folders, Tizen `.wgt/.tpk`, webOS `appinfo.json`), system libraries (`lib*.so[.version]`), kernel modules (`*.ko`, name-based class: wifi, bluetooth, audio, display, network, tuner/demod, usb, storage), network interfaces named in configs, display/audio keys from panel/audio config files |
| `fingerprint` | `resources/data/os_fingerprints.json` rules (Android, Android TV via `android.software.leanback`, Google TV launcher package, Tizen release file, webOS `/usr/palm`, keywords for VIDAA/Roku, generic Linux) — indicators with stated basis |
| `system_menu_ocr` | OCR text of *System information menu* photos: software/firmware version, Android version, kernel, build, bootloader, resolution, MAC |
| `operator` | values typed by the technician — a reference is mandatory (e.g. "Settings > Support > About") |
| `upnp` | LAN SSDP discovery + device-description XML (manufacturer, model name/number, serial, friendly name) |
| `adb` | Android TVs only, after the owner enables debugging and accepts the prompt on the TV |

Rules:
* Nothing assumes ADB, SSH, Telnet or an API exists. Device queries run only when the operator starts them and
  types an authorisation statement (stored with the session in `device_sessions`).
* Device communication is **read-only**: ADB uses a fixed whitelist (`getprop`, `uname -a`, `pm list packages`,
  `pm list features`, `wm size`, `ip -brief address`, `cat /proc/modules`); arbitrary commands cannot be sent.
  UPnP/ADB over network are limited to private/link-local LAN addresses.
* Summary keeps all values with all sources; several OS families with ≥ 60 % confidence produce a *conflict*.
* Re-analysis replaces firmware/fingerprint/OCR facts and keeps operator and device facts.

## Factory & Service Menu (`app/modules/service_menu/`)
* Categories: Factory Menu, Service Menu, Hotel Mode, Panel Configuration, Picture Settings, Audio Settings, Tuner
  Settings, Network Diagnostics, Firmware Information, Hardware Diagnostics, Official Factory Reset Documentation.
* Record fields: manufacturer, model pattern (glob, e.g. `UA55AU*`), chassis, platform, firmware version, region,
  category, documented access procedure, function, access availability, configuration risk (low…critical),
  documented backup mechanism, **official documentation (mandatory)**, source type, optional document in the local
  library + page.
* Records describing password guessing, brute force, cracking or bypassing authentication are refused.
* The database ships **empty**: records come from the manufacturer's documentation you hold. Import/export JSON
  (`{"format": "tvis-service-menus-1", "records": [...]}`) or CSV with the same field names; undocumented records are
  rejected individually with the reason.
* **Service manual search** finds service-mode passages (service/factory/hotel/design/engineering mode, service
  remote, option code, white balance adjustment, self-diagnosis, factory reset) with page numbers in PDFs imported
  into the document library, and pre-fills the citation.
* **Service actions** (changing factory settings): plan (setting, current value, new value, reason) → record backup
  (mandatory when the documentation names a backup mechanism) → confirm by typing `CHANGE <setting>` → mark
  performed with the result. Every step is audited. The application itself never changes TV settings.

## Reports
* Operating System Report (PDF/JSON): summary with sources, conflicts, applications, libraries, drivers, network,
  display, audio, device sessions.
* Service Menu Report (PDF): documented menus applicable to the TV and all service actions.
