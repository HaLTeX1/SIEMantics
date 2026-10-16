@echo off
rem SIEMantics gep izolalas (Wazuh active response, Windows): a PowerShell script kapja a Wazuh JSON uzenetet.
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0siemantics-isolate.ps1"
