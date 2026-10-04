@echo off
setlocal enabledelayedexpansion
title Decrypt My Information

REM ---------------------------------------------------------------------
REM  Launcher for whoever needs to open the encrypted document.
REM
REM  Finds a usable Python, explains itself in plain words if there is
REM  none, and never closes the window on the way out: an error message
REM  nobody had time to read is the same as no message.
REM ---------------------------------------------------------------------

cd /d "%~dp0"

REM The copy given to beneficiaries carries a self-contained program, so
REM nothing needs installing. Python below is only the fallback.
if exist "internals\program\decrypt.exe" (
    "internals\program\decrypt.exe" %*
    goto :finished
)

set "PYTHON="

REM A virtual environment beside the project wins if the owner made one.
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"

REM Otherwise the py launcher, which ships with the python.org installer and
REM picks the newest interpreter present.
if not defined PYTHON (
    py -3 --version >nul 2>&1 && set "PYTHON=py -3"
)

REM Finally a plain `python`, but only a real one: the Windows Store stub
REM answers --version with nothing useful and would otherwise be accepted.
if not defined PYTHON (
    python --version >nul 2>&1 && set "PYTHON=python"
)

if not defined PYTHON (
    echo.
    echo   This computer does not have Python installed, and this program
    echo   needs it.
    echo.
    echo   1. Go to  https://www.python.org/downloads/
    echo   2. Download and run the installer for Windows.
    echo   3. Tick "Add python.exe to PATH" on the first screen.
    echo   4. Run this program again.
    echo.
    echo   Nothing has been damaged. Your encrypted document is untouched.
    echo.
    pause
    exit /b 1
)

%PYTHON% "internals\scripts\decrypt.py" %*

:finished
set "EXITCODE=%ERRORLEVEL%"

REM No `exit` here: the window stays open so any message can be read.
if not "%EXITCODE%"=="0" (
    echo.
    echo   The program stopped without finishing. The message above explains why.
    echo.
    pause
)
exit /b %EXITCODE%
