@echo off
title Digital Legacy Decryption Tool

call .venv\Scripts\activate.bat

python internals\scripts\decrypt.py

exit