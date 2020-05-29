@echo off
net session >nul 2>nul
if NOT %errorlevel% EQU 0 (
	PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0Change-Net.ps1""' -Verb RunAs}"
)

if %errorlevel% EQU 0 (
	PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '%~dp0Change-Net.ps1'"
)