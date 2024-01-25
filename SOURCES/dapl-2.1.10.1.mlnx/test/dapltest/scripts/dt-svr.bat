@echo off
rem
rem DAPLtest server - usage: dt-svr dapl-provider [ -D [dbg-bit-mask] ]
rem
SETLOCAL

rem set DAT_OVERRIDE=C:\DAT\dat.conf
set DT=dapl2test.exe

%DT% -h > Nul 2>&1
if not "%ERRORLEVEL%" == "1" (
    echo %0: ERR - %DT% not in exec path?
    exit /B %ERRORLEVEL%
)
rem To debug dapl2test - use dapl2testd.exe with ibnic0v2d

rem which Dapl provider?

if "%1" == "" (
    echo usage: dt-svr dapl-provider [ -D [dbg-bit-mask] ]
    echo.
    echo Where: dapl-provider can be [ ibal, scm, cma or %SystemDrive%\DAT\dat.conf provider name ]
    exit /B 1
)

if "%1" == "ibal"   set DEV=ibnic0v2
if "%1" == "scm"    set DEV=ibnic0v2-scm
if "%1" == "cma"    set DEV=ibnic0v2-cma
if "%DEV%" == ""    set DEV=%1

rem '-D' enables full debug output?
rem '-D hex-bit-mask' enables selective debug output - see manual.htm for details.
if "%2" == "-D" (
    if "%3" == "" (
        set X=0xfffff
    ) else (
        set X=%3
    )
) else ( set X= )

if not "%X%" == "" (
    set DAT_OS_DBG_TYPE=%X%
    set DAT_DBG_LEVEL=%X%
    set DAT_DBG_TYPE=%X%
    set DAPL_DBG_TYPE=%X%
    set DAPL_DBG_LEVEL=%X%
) else (
    set DAT_DBG_TYPE=1
)

rem	start a dapltest server on the local node - server is waiting for
rem	dapltest 'client' to issue dapltest commands (dt-cli.bat).
rem	Client runs 'dt-cli provider IP-addr stop' to shutdown this dapltest server.

echo %DT% -T S -d -D %DEV%

%DT% -T S -D %DEV%

echo %0 - %DT% [%DEV%] server exit...

ENDLOCAL
exit /B %ERRORLEVEL%
