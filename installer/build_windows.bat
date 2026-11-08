@echo off
REM Builds dist\TVIntelligenceScanner\ (EXE) and, if Inno Setup is installed, dist\installer\*.exe
REM Run from the repository root in a terminal where the venv is active.
setlocal
python -m pip install -r requirements-dev.txt || exit /b 1
set QT_QPA_PLATFORM=offscreen
python -m pytest -o addopts="" -q || (echo Tests failed - aborting build & exit /b 1)
set QT_QPA_PLATFORM=
pyinstaller installer\tv_intelligence_scanner.spec --noconfirm || exit /b 1
dist\TVIntelligenceScanner\TVIntelligenceScanner.exe --self-check || exit /b 1
dist\TVIntelligenceScanner\TVIntelligenceScanner.exe --smoke-test || exit /b 1
set ISCC="%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist %ISCC% (
  %ISCC% /DMyAppVersion=1.0.0 installer\tvis_setup.iss || exit /b 1
  echo Installer: dist\installer\
) else (
  echo Inno Setup 6 not found - skipping installer. Install from jrsoftware.org to build the setup EXE.
)
echo Build finished: dist\TVIntelligenceScanner\
endlocal
