@echo off
rem
rem Sample DAPLtest client Usage: dt-cli.bat provider hostname testname [-D]
rem

SETLOCAL

rem cmd.exe /V:on (delayed environment variable expansion) is required!
rem restart with /V:on if necessary
set F=on
set F=off
if not "!F!" == "off" (
   %comspec% /E:on /V:on /C %0 %1 %2 %3 %4
   if ERRORLEVEL 2 (exit /B %ERRORLEVEL%) else (exit /B 0)
)

rem set DAT_OVERRIDE=D:\dapl2\dat.conf
rem favor DAT 2.0 (dapl2test.exe) over DAT 1.1 (dapltest.exe)

set DT=dapl2test.exe
%DT% -h > Nul 2>&1
if not "%ERRORLEVEL%" == "1" (
    echo %0: ERR - %DT% not in exec path?
    exit /B %ERRORLEVEL%
)
rem     To debug dapl2test - use dapl2testd.exe with ibnic0v2d

rem setup DAPL provider name: translate shorthand name or use name from dat.conf.
rem if DAPL provider name is incorrect, DAPL will fail correctly.

if "%1" == "" goto usage
if "%1" == "ibal"  set D=ibnic0v2
if "%1" == "ibal0" set D=ibnic0v2
if "%1" == "ibal1" set D=ibnic1v2
if "%1" == "scm"   set D=ibnic0v2-scm
if "%1" == "cma"   set D=ibnic0v2-cma
if "%D%" == ""     set D=%1

rem DaplTest server hostname
if "%2" == "" goto usage
set S=%2

rem Which test ?
if "%3" == "" goto usage
set T=%3

set LPS=5

rem Enable DEBUG?

if "%4" == "-D" (set X=0xffff) else set X=
if not "%X%" == "" (
    set DAT_OS_DBG_TYPE=%X%
    set DAT_DBG_TYPE=%X%
    set DAT_DBG_LEVEL=%X%
    set DAPL_DBG_LEVEL=%X%
    set DAPL_DBG_TYPE=%X%
) else (
rem    set DAT_DBG_TYPE=0x1
rem    set DAT_DBG_LEVEL=1
)

if "%4" == "-Q" ( set QUIET=1 ) else ( set QUIET=0 )

rem %DT% -T T -V -t 2 -w 2 -i 1000111 -s %S% -D %D% 
rem           client RW  4096 1    server RW  2048 4 
rem           client RR  1024 2    server RR  2048 2 
rem           client SR  1024 3 -f server SR   256 3 -f

rem %DT% -T T -P -t 1 -w 1 -i 1024 -s %S% -D %D%
rem             client RW  4096 1    server RW  2048 4 
rem             server RR  1024 2    client RR  2048 2 
rem             client SR  1024 3 -f server SR   256 3 -f

if "%T%" == "bench" (
    echo %T%: Threads[1] Endpoints[1] transactions[RW, RR, SR], 64K iterations
	set STIME=!DATE! !TIME!
    %DT% -T T -P -t 1 -w 1 -i 65536 -s %S% -D %D% client RW  4096 4 server RW  2048 4  server RR  4096 2 client RR 4096 2 client SR 1024 2 -f server SR 1024 2 -f
	set ETIME=!DATE! !TIME!
    goto xit
)

if "%T%" == "conn" (
    rem Connectivity test - client sends one buffer with one 4KB segments, one time.
    rem add '-d' for debug output.
    echo Simple Connectivity test
    set CMD=%DT% -T T -s %S% -D %D% -i 1 -t 1 -w 1 client SR 4096 server SR 4096
    goto xcmd
)

if "%T%" == "trans" (
    echo %T%: Transaction test - 8192 iterations, 1 thread, SR 4KB buffers
    set CMD=%DT% -T T -s %S% -D %D% -i 8192 -t 1 -w 1 client SR 4096 server SR 4096
    goto xcmd
)

if "%T%" == "transm" (
    echo %T%: Multiple RW, RR, SR transactions, 4096 iterations
    set CMD=%DT% -T T -P -t 1 -w 1 -i 4096 -s %S% -D %D% client RW 4096 1 server RW 2048 4  server RR  1024 2 client RR 2048 2 client SR 1024 3 -f server SR 256 3 -f
    goto xcmd
)

if "%T%" == "transt" (
    echo %T%: Threads[4] Transaction test - 4096 iterations, 1 thread, SR 4KB buffers
    set CMD=%DT% -T T -s %S% -D %D% -i 4096 -t 4 -w 1 client SR 8192 3 server SR 8192 3
    goto xcmd
)

if "%T%" == "transme" (
    echo %T%: 1 Thread Endpoints[4] transactions [RW, RR, SR], 4096 iterations
    set CMD=%DT% -T T -P -t 1 -w 4 -i 4096 -s %S% -D %D% client RW  4096 1 server RW  2048 4  server RR  1024 2 client RR 2048 2 client SR 1024 3 -f server SR 256 3 -f
    goto xcmd
)

if "%T%" == "transmet" (
    echo %T%: Threads[2] Endpoints[4] transactions[RW, RR, SR], 4096 iterations
    set CMD=%DT% -T T -P -t 2 -w 4 -i 4096 -s %S% -D %D% client RW  4096 1 server RW  2048 4  server RR  1024 2 client RR 2048 2 client SR 1024 3 -f server SR 256 3 -f
    goto xcmd
)

if "%T%" == "transmete" (
    echo %T%: Threads[4] Endpoints[4] transactions[RW, RR, SR], 8192 iterations
    set CMD=%DT% -T T -P -t 2 -w 4 -i 8192 -s %S% -D %D% client RW  4096 1 server RW  2048 4  server RR  1024 2 client RR 2048 2 client SR 1024 3 -f server SR 256 3 -f
    goto xcmd
)

if "%T%" == "EPA" (
	set STIME=!DATE! !TIME!
    FOR /L %%j IN (2,1,5) DO (
        FOR /L %%i IN (1,1,5) DO (
             echo %T%: Multi: Threads[%%j] Endpoints[%%i] Send/Recv test - 4096 iterations, 3 8K segs
             %DT% -T T -s %S% -D %D% -i 4096 -t %%j -w %%i client SR 8192 3 server SR 8192 3
             if ERRORLEVEL 1 exit /B %ERRORLEVEL% 
             echo %T%: Multi: Threads[%%j] Endpoints[%%i] Send/Recv test - 4096 iterations, 3 8K segs
             timeout /T 3
        )
    )
	set ETIME=!DATE! !TIME!
    goto xit
)

if "%T%" == "EP" (
    set TH=4
    set EP=3
    echo %T%: Multi: Threads[!TH!] endpoints[!EP!] Send/Recv test - 4096 iterations, 3 8K segs
    set CMD=%DT% -T T -s %S% -D %D% -i 4096 -t !TH! -w !EP! client SR 8192 3 server SR 8192 3
    goto xcmd
)

if "%T%" == "threads" (
    echo %T%: Multi Threaded[6] Send/Recv test - 4096 iterations, 3 8K segs
    set CMD=%DT% -T T -s %S% -D %D% -i 4096 -t 6 -w 1 client SR 8192 3 server SR 8192 3
    goto xcmd
)

if "%T%" == "threadsm" (
    set TH=5
    set EP=3
    echo %T%: Multi: Threads[!TH!] endpoints[!EP!] Send/Recv test - 4096 iterations, 3 8K segs
    set CMD=%DT% -T T -s %S% -D %D% -i 4096 -t !TH! -w !EP! client SR 8192 3 server SR 8192 3
    goto xcmd
)

if "%T%" == "perf" (
    rem echo Performance test
    set CMD=%DT% -T P %DBG% -s %S% -D %D% -i 2048 RW 4096 2
    goto xcmd
)

if "%T%" == "rdma-read" (
    echo %T% 4 32K segs
    set CMD=%DT% -T P -s %S% -D %D% -i 4096 RR 32768 4
    goto xcmd
)

if "%T%" == "rdma-write" (
    echo %T% 4 32K segs
    set CMD=%DT% -T P -s %S% -D %D% -i 4096 RW 32768 4
    goto xcmd
)

if "%T%" == "bw" (
    echo bandwidth 4096 iterations of 2 65K mesgs
    set CMD=%DT% -T P -s %S% -D %D% -i 4096 -p 16 -m p RW 65536 2 
    goto xcmd
)

if "%T%" == "latb" (
    echo latency test - block for completion events
    set CMD=%DT% -T P -s %S% -D %D% -i 8192 -p 1 -m b RW 4 1
    goto xcmd
)

if "%T%" == "latp" (
    echo latency test - poll completion events
    set CMD=%DT% -T P -s %S% -D %D% -i 8192 -p 1 -m p RW 4 1
    goto xcmd
)

if "%T%" == "lim" (
    echo Resource limit tests
	set STIME=!DATE! !TIME!
    %DT% -T L -D %D% -w 8 -m 100 limit_ia
    %DT% -T L -D %D% -w 8 -m 100 limit_pz
    %DT% -T L -D %D% -w 8 -m 100 limit_evd
    %DT% -T L -D %D% -w 8 -m 100 limit_ep
    %DT% -T L -D %D% -w 8 -m 100 limit_psp
    %DT% -T L -D %D% -w 8 -m 100 limit_lmr
    %DT% -T L -D %D% -w 8 -m 15 limit_rpost
	set ETIME=!DATE! !TIME!
    goto xit
)

if "%T%" == "regression" (
    rem run dapl regression tests - usage: dt-cli provider svr-IPaddr regression {loopCnt}
    if "%X%" == "" (
        if not "%4" == ""  set LPS=%4
    ) else (
        if not "%5" == ""  set LPS=%5
    )
    echo %T% testing in !LPS! Loops
    REM rdma-write, read, perf
    set RT=trans perf threads threadsm transm transt transme transmet transmete rdma-write rdma-read bw EP
	set STIME=!DATE! !TIME!
    FOR /L %%i IN (1,1,!LPS!) DO (
       for %%r in ( !RT! ) do (
           echo loop %%i - start test %%r
           call %0 %1 %2 %%r
           if !ERRORLEVEL! GTR 1 (
               echo Error !ERRORLEVEL! in regression test %%r
               exit /B !ERRORLEVEL!
           )
           echo loop %%i - Completed test %%r
           if not "%%r" == "EP"  timeout /T 3
       )
       echo +
       echo Finished %T% loop %%i of !LPS!
       if %%i LSS !LPS!  timeout /T 8
    )
	set ETIME=!DATE! !TIME!
    goto xit
)

if "%T%" == "interop" (
    REM test units from Nov-'07 OFA interop event. usage dt-cli server-IPaddr interop {LoopCount}
    if "%X%" == "" (
        if not "%4" == ""  set LPS=%4
    ) else (
        if not "%5" == ""  set LPS=%5
    )
    echo %T% testing in !LPS! Loops
    REM test units from Nov-'07 OFA interop event
	set STIME=!DATE! !TIME!
    FOR /L %%i IN (1,1,!LPS!) DO (
         echo %DT% -T T -s %S% -D %D% -i 4096 -t 1 -w 1 -R BE client SR 256 1 server SR 256 1
         %DT% -T T -s %S% -D %D% -i 4096 -t 1 -w 1 -R BE client SR 256 1 server SR 256 1
         if ERRORLEVEL 1 exit /B %ERRORLEVEL%
         timeout /T 3
         echo %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 1 -V -P -R BE client SR 1024 3 -f server SR 1536 2 -f
         %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 1 -V -P -R BE client SR 1024 3 -f server SR 1536 2 -f
         if ERRORLEVEL 1 exit /B %ERRORLEVEL%
         timeout /T 3
         echo %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 1 -V -P -R BE client SR 1024 1 server SR 1024 1
         %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 1 -V -P -R BE client SR 1024 1 server SR 1024 1
         if ERRORLEVEL 1 exit /B %ERRORLEVEL%
         timeout /T 3
         echo %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 10 -V -P -R BE client SR 1024 3 server SR 1536 2
         %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 10 -V -P -R BE client SR 1024 3 server SR 1536 2
         if ERRORLEVEL 1 exit /B %ERRORLEVEL%
         timeout /T 3
         echo %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 1 -V -P -R BE client SR 256 1 server RW 4096 1 server SR 256 1
         %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 1 -V -P -R BE client SR 256 1 server RW 4096 1 server SR 256 1
         if ERRORLEVEL 1 exit /B %ERRORLEVEL%
         timeout /T 3
         echo %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 1 -V -P -R BE client SR 256 1 server RR 4096 1 server SR 256 1
         %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 1 -V -P -R BE client SR 256 1 server RR 4096 1 server SR 256 1
         if ERRORLEVEL 1 exit /B %ERRORLEVEL%
         timeout /T 3
         echo %DT% -T T -s %S% -D %D% -i 100 -t 4 -w 8 -V -P -R BE client SR 256 1 server RR 4096 1 server SR 256 1 client SR 256 1 server RR 4096 1 server SR 256 1
         %DT% -T T -s %S% -D %D% -i 100 -t 4 -w 8 -V -P -R BE client SR 256 1 server RR 4096 1 server SR 256 1 client SR 256 1 server RR 4096 1 server SR 256 1
         if ERRORLEVEL 1 exit /B %ERRORLEVEL%
         timeout /T 3
         echo %DT% -T P -s %S% -D %D% -i 1024 -p 64 -m p RW 8192 2
         %DT% -T P -s %S% -D %D% -i 1024 -p 64 -m p RW 8192 2
         if ERRORLEVEL 1 exit /B %ERRORLEVEL%
         timeout /T 3
         echo %DT% -T P -s %S% -D %D% -i 1024 -p 64 -m p RW 4096 2
         %DT% -T P -s %S% -D %D% -i 1024 -p 64 -m p RW 4096 2
         if ERRORLEVEL 1 exit /B %ERRORLEVEL%
         timeout /T 3
         echo %DT% -T P -s %S% -D %D% -i 1024 -p 64 -m p RW 4096 1
         %DT% -T P -s %S% -D %D% -i 1024 -p 64 -m p RW 4096 1
         if ERRORLEVEL 1 exit /B %ERRORLEVEL%
         timeout /T 3
         echo %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 10 -V -P -R BE client SR 1024 3 server SR 1536 2
         %DT% -T T -s %S% -D %D% -i 100 -t 1 -w 10 -V -P -R BE client SR 1024 3 server SR 1536 2
         if ERRORLEVEL 1 exit /B %ERRORLEVEL%
         echo %%i %T% loops of !LPS! completed.
         if %%i LSS !LPS!  timeout /T 8
    )
	set ETIME=!DATE! !TIME!
    goto xit
)

if "%T%" == "stop" (
    %DT% -T Q -s %S% -D %D%
    goto rxt
)

:usage

echo.
echo usage: dt-cli dapl-provider dt-svr-hostname [testname [-D]]
echo.
echo where:
echo.
echo  dapl-provider: ibal, scm, cma or %SystemDrive%\DAT\dat.conf DAPL-provider name.
echo.
echo  dt-svr-hostname - IPv4 hostanme where the DaplTest server is running
echo.
echo  testname
echo    stop - request DAPLtest server to exit.
echo    conn - simple connection test with limited data transfer
echo    EP - Multiple EndPoints(7) and Threads(5) Transactions
echo    EPA - Increment EndPoints[1..5] while increasing threads[1-5]
echo    trans - single transaction test
echo    transm - transaction test: multiple transactions [RW SND, RDMA]
echo    transt - transaction test: multi-threaded
echo    transme - transaction test: multi-endpoints per thread 
echo    transmet - transaction test: multi-endpoints per thread, multiple threads
echo    transmete - transaction test: multi threads == endpoints
echo    perf - Performance test
echo    threads - multi-threaded single transaction test.
echo    threadsm - multi: threads and endpoints, single transaction test.
echo    rdma-write - RDMA write
echo    rdma-read - RDMA read
echo    bw - bandwidth
echo    latb - latency tests, blocking for events
echo    latp - latency tests, polling for events
echo    lim - limit tests.
echo    regression {loopCnt,default=%LPS%} - regression + stress.
echo    interop {loopCnt,default=%LPS%} - 2007 OFA interoperability event tests.
goto rxt

rem Execute the single daplest Command (CMD), observe -Q switch
:xcmd
    set STIME=!DATE! !TIME!
    if %QUIET% EQU 1 (
        %CMD% > nul
    ) else (
        %CMD%
    )
    set ETIME=!DATE! !TIME!

    rem fall thru...

:xit

if !ERRORLEVEL! EQU 0 (
	echo.
	echo %0 %*
	echo    Start %STIME% 
	echo    End   %ETIME%
)
:rxt
ENDLOCAL
exit /B !ERRORLEVEL!
