# Compatibility Analyzer & Firmware Upgrade Manager (Phase 7)

## Compatibility Analyzer (`app/modules/compatibility/analyzer.py`)
Inputs: project identification, confirmed hardware (SoC, RAM/flash totals, Wi-Fi/audio/T-Con parts), software
facts (drivers, bootloader), the **baseline** (the TV's own analysed `Original` firmware, chosen automatically or
explicitly) and the analysed **candidate**.

| Criterion | Evidence used | Hard mismatch? |
|---|---|---|
| model | `ro.product.model/device` in the candidate, else any mention | yes (different product model declared) |
| mainboard / PCB revision | mention in metadata, file names or firmware strings | no (absence ≠ proof) |
| SoC | mention; other SoCs named → soft concern | no |
| architecture | baseline vs candidate (uImage/ELF/kernel image) | yes |
| RAM | `mem=` in the kernel command line vs installed RAM (Phase 3 total) | yes (needs more than installed) |
| flash | end of the last partition vs flash size (full images only) | yes |
| panel | panel ID found in candidate; panel configs without it → soft concern | no (but blocks VERIFIED) |
| bootloader | U-Boot versions | no (different bootloader = soft concern) |
| display / audio / Wi-Fi drivers | loadable modules (`.ko`) on both sides | no (may be built into the kernel) |
| partition layout | GPT/MBR/mtdparts names + sizes vs baseline | yes (repartitioning only if documented) |
| signing | AVB vbmeta presence/algorithm; signed TV + unsigned candidate | yes (bypass not permitted) |
| hardware configuration | TV component part numbers named in the candidate | no |
| integrity | library SHA-256 re-check; published-hash match from the Finder | yes (hash changed) |
| source | Official category | no |

Verdict rules are in the module docstring; **VERIFIED COMPATIBLE** additionally requires an analysed baseline,
no soft concerns, a confirmed model and board/SoC, matching architecture, a confirmed layout (or an official
package where layout is not visible), and established integrity.

## Upgrade Manager (`app/modules/upgrade_manager/`)
### Profiles
`manufacturer + model pattern (+ chassis, mainboard pattern) + method`, with the **documentation reference
mandatory**, documented package file pattern, USB filesystem/path/name, power requirements, verification steps,
recovery procedure and whether rollback is documented. A profile starts **unverified**; an operator must type
`VERIFIED <manufacturer>` after checking it against the cited documentation (who/when recorded).

### Methods (plugin registry `adapters.METHODS`)
| Method | Executes? | What the application does |
|---|---|---|
| Official USB Upgrade | **yes** (only this) | pre-flight (filesystem, free space, removable, FAT32 4 GiB limit, documented file name/path), copy of the read-only library file to the stick via a temporary file, fsync, SHA-256 verification of the copy; partial files removed on cancel/error |
| Official Network Upgrade | no | instructions (started from the TV's own menu) |
| Manufacturer Service Tool | no | instructions + technician report |
| Authorised Serial/UART | no | instructions + technician report (critical risk) |
| Authorised USB Device | no | instructions + technician report (critical risk) |
| Vendor Recovery Interface | no | documented recovery instructions + report |

The application never writes to a TV, its flash chip, partitions or bootloader, never bypasses signatures and
never modifies bootloaders.

### Session steps
1. **Identification** — model, mainboard/chassis and current firmware version are required; SoC/panel/PCB rev. warn.
2. **Compatibility** — runs the analyzer; INCOMPATIBLE stops the session (later steps are blocked).
3. **Validation** — SHA-256, integrity, documented package name, metadata, format, signature presence,
   source reliability, compatibility verdict.
4. **Backup** — records the original version, whether a *full image* of the current firmware exists
   (otherwise states "NO — only metadata"), the official configuration export (if any) and a fresh Hardware Report.
5. **Preparation** — risks shown; power and connection confirmations; USB pre-flight; typed
   `UPGRADE <model>` confirmation. Executable only if: method executes, profile verified, VERIFIED COMPATIBLE,
   validation passed, and no failed check. Otherwise the session continues as *instructions only*.
6. **Execution** — USB preparation with progress/log, or instructions. Cancelling is possible only during the
   PC-side copy; the instructions warn never to interrupt the TV's own update.
7. **Verification** — version reported by the TV vs target version, model, panel, boot and basic functions; the
   project's firmware version is updated only when everything passes.
8. **Recovery** — documented recovery procedure; rollback stated as documented or *not documented*.

Every step is written to the session log and the audit log. Reports: Firmware Compatibility Report (PDF) and
Firmware Upgrade Report (PDF/JSON).
