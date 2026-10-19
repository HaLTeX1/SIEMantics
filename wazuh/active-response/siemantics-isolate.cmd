@echo off
rem SIEMantics gep izolalas (Wazuh active response, Windows): a PowerShell script kapja a Wazuh JSON uzenetet.
rem A Wazuh agent 32 bites: a 64 bites PowerShellt inditjuk (msg.exe es a tuzfal parancsok miatt), ha van.
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0siemantics-isolate.ps1"
