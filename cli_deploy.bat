@echo off
REM --------------------------------------------------------------------
REM Deploy Panorama set commands via SSH with scaling delay and retries
REM Requires Plink.exe (part of PuTTY)
REM --------------------------------------------------------------------

SET HOST=your.panorama.host
SET USER=your_username
SET PASS=your_password
SET COMMAND_FILE=panorama.set
SET RETRY_LIMIT=3
SET BASE_DELAY=0.05
SET SCALE_STEP=0.01

IF NOT EXIST "%COMMAND_FILE%" (
    ECHO Command file "%COMMAND_FILE%" not found.
    EXIT /B 1
)

REM --------------------------------------------------------------------
REM Function-like label: Send a single command and capture output
REM --------------------------------------------------------------------
:send_command
REM %1 = command string
REM Output goes to temp file for analysis
ECHO %~1 > _cmd.txt
plink.exe -ssh %USER%@%HOST% -pw %PASS% -m _cmd.txt > _out.txt 2>&1
DEL _cmd.txt
EXIT /B 0

REM --------------------------------------------------------------------
REM Main logic
REM --------------------------------------------------------------------
SET attempt=1

:retry_loop
SET failed_count=0
DEL _failed.txt >NUL 2>&1

ECHO.
ECHO Attempt %attempt%

SETLOCAL ENABLEDELAYEDEXPANSION
SET delay=%BASE_DELAY%

FOR /F "usebackq delims=" %%C IN ("%COMMAND_FILE%") DO (
    SET "cmd=%%C"
    IF NOT "!cmd!"=="" (
        ECHO Sending: !cmd!
        CALL :send_command "!cmd!"
        TYPE _out.txt
        FINDSTR /I "error invalid" _out.txt >NUL
        IF NOT ERRORLEVEL 1 (
            ECHO Error detected for command: !cmd!
            ECHO !cmd!>> _failed.txt
        )
        REM Sleep for current delay (PowerShell provides fractional seconds)
        powershell -Command "Start-Sleep -Seconds !delay!"
        FOR /F "usebackq tokens=1,2 delims=." %%a IN ('echo !delay!') DO (
            REM increment delay
        )
        powershell -Command "$d=[double](!delay!)+[double]('%SCALE_STEP%'); '{0:N2}' -f $d" > _newdelay.txt
        SET /P delay=< _newdelay.txt
        DEL _newdelay.txt
    )
)
ENDLOCAL

IF NOT EXIST _failed.txt (
    ECHO All commands applied successfully.
    DEL _out.txt
    EXIT /B 0
)

IF %attempt% GEQ %RETRY_LIMIT% (
    ECHO Some commands could not be applied after %RETRY_LIMIT% attempts:
    TYPE _failed.txt
    DEL _failed.txt
    DEL _out.txt
    EXIT /B 2
)

ECHO %failed_count% commands failed. Retrying in  seconds...
TIMEOUT /T 5 >NUL
COPY _failed.txt _retry.txt >NUL
MOVE /Y _retry.txt %COMMAND_FILE% >NUL
DEL _failed.txt
SET /A attempt+=1
GOTO retry_loop

