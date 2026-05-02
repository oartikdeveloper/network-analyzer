@echo off
echo ===================================
echo   Network Analyzer - EXE Builder
echo ===================================
echo.

echo [1/3] Gereksinimler yukleniyor...
pip install psutil pyinstaller

echo.
echo [2/3] EXE olusturuluyor...
pyinstaller --onefile --windowed --name "NetworkAnalyzer" --icon=NONE network_analyzer.py

echo.
echo [3/3] Tamamlandi!
echo EXE dosyasi: dist\NetworkAnalyzer.exe
echo.
pause
