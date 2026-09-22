@echo off
:: extractor.bat
:: Usage: drag and drop any .exe onto this file
:: Output: same folder, .dat extension

if "%~1"=="" (
    echo [-] Drag and drop an exe onto this file
    pause
    exit /b 1
)

set "INPUT=%~1"
set "OUTPUT=%~dpn1.dat"

powershell -NoProfile -Command ^
    "$bytes = [IO.File]::ReadAllBytes('%INPUT%');" ^
    "$xored = $bytes | %% { $_ -bxor 0xAB };" ^
    "[IO.File]::WriteAllBytes('%OUTPUT%', $xored);"

echo [+] Encoded: %INPUT%
echo [+] Output:  %OUTPUT%
echo [+] Size:    done
pause