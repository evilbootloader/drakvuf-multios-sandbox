@echo off
rem Fixed guest workload of benchmark_drakvuf.sh. DRAKVUF's injector copies it into the
rem guest and starts it in every run; it loops until the guest is destroyed. Each round
rem touches files and the registry, starts processes (new DLLs for apimon) and pings localhost.
set dir=%PUBLIC%\drakvuf-workload
mkdir "%dir%" 2>nul
rem The plugins start after the injection; ping as sleep, timeout needs a console input
ping -n 4 127.0.0.1 >nul
set /a i=0
:loop
set /a i+=1
set /a n=i %% 16
echo iteration %i% >"%dir%\file-%n%.txt"
type "%SystemRoot%\System32\drivers\etc\hosts" >>"%dir%\file-%n%.txt"
copy /y "%dir%\file-%n%.txt" "%dir%\copy.txt" >nul
ren "%dir%\copy.txt" moved.txt
del /q "%dir%\moved.txt"
dir "%SystemRoot%\System32" >nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" >nul
tasklist >nul
ping -n 1 127.0.0.1 >nul
powershell -NoProfile -Command "Get-Process | Out-Null" >nul 2>&1
echo %i% >"%dir%\iterations.txt"
goto loop
