@echo off
setlocal enabledelayedexpansion
title Encrypt My Information

REM Owner-facing launcher. Pass --doctor to run the yearly health check:
REM     "Encrypt My Information-Windows.bat" --doctor

cd /d "%~dp0"

set "PYTHON="
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
if not defined PYTHON ( py -3 --version >nul 2>&1 && set "PYTHON=py -3" )
if not defined PYTHON ( python --version >nul 2>&1 && set "PYTHON=python" )

if not defined PYTHON (
    echo.
    echo   Python is not installed on this computer. Get it from
    echo   https://www.python.org/downloads/ and tick "Add python.exe to PATH".
    echo.
    pause
    exit /b 1
)

%PYTHON% "internals\scripts\encrypt.py" %*
set "EXITCODE=%ERRORLEVEL%"
if not "%EXITCODE%"=="0" (
    echo.
    pause
)
exit /b %EXITCODE%
