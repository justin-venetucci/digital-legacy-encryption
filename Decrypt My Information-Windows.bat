@echo off
setlocal enabledelayedexpansion
title Decrypt My Information

REM ---------------------------------------------------------------------
REM  Launcher for whoever needs to open the encrypted document.
REM
REM  The previous version of this file did three things that could leave a
REM  beneficiary staring at nothing:
REM    * it activated a .venv that nothing in the repository ever creates,
REM      so on any fresh copy the activate call failed;
REM    * it then ran `python`, which on a machine without Python opens the
REM      Microsoft Store instead of reporting anything;
REM    * it ended with `exit`, which closes the window -- taking every error
REM      message with it.
REM
REM  This version finds a usable Python, explains itself if it cannot, and
REM  never closes the window on the way out.
REM ---------------------------------------------------------------------

cd /d "%~dp0"

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
set "EXITCODE=%ERRORLEVEL%"

REM No `exit` here: the window stays open so any message can be read.
if not "%EXITCODE%"=="0" (
    echo.
    echo   The program stopped without finishing. The message above explains why.
    echo.
    pause
)
exit /b %EXITCODE%
