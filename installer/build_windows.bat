@echo off
REM Builds dist\TVIntelligenceScanner\TVIntelligenceScanner.exe
REM Run from the repository root in a terminal where the venv is active.
setlocal
python -m pip install -r requirements-dev.txt || exit /b 1
set QT_QPA_PLATFORM=offscreen
python -m pytest || (echo Tests failed - aborting build & exit /b 1)
set QT_QPA_PLATFORM=
pyinstaller installer\tv_intelligence_scanner.spec --noconfirm || exit /b 1
dist\TVIntelligenceScanner\TVIntelligenceScanner.exe --self-check
echo Build finished: dist\TVIntelligenceScanner\
endlocal
