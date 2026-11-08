@echo off
set QT_QPA_PLATFORM=offscreen
python -m pytest %*
