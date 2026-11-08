# Ghidra (headless) integration

Runs `analyzeHeadless` on **one extracted binary** chosen in Firmware Analyzer → Extracted files →
"Run Ghidra on selected". The binary must be inside the analysis workspace (enforced).

```
analyzeHeadless <workspace>/ghidra_project tvis_tmp -import <binary>
    -scriptPath app/integrations/ghidra/scripts -postScript TVISSummary.java <out.json>
    -deleteProject -analysisTimeoutPerFile <s> [-processor <languageID>]
```
`scripts/TVISSummary.java` writes: program, language, compiler, executable format, image base,
function count, defined strings, libraries, external symbols, first 300 functions. The result is stored
as analyzer `ghidra` of the run and shown in the report.

Setup (Windows): install a JDK supported by your Ghidra version, unzip Ghidra, then either set the
environment variable `GHIDRA_INSTALL_DIR` or `settings.json → tools.ghidra_headless` to
`<ghidra>\support\analyzeHeadless.bat`.

Status: command construction, workspace guard and result handling are tested with a stand-in script that
follows the same CLI. **A real Ghidra installation was not available in the test environment — NOT TESTED
end-to-end**, including compilation of `TVISSummary.java` by Ghidra.
