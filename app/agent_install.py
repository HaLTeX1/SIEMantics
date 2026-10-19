# Wazuh agent telepito parancsok: hivatalos csomag + a SIEMantics izolalo script, SHA-256 ellenorzessel.

import hashlib
import re
from pathlib import Path
from urllib.parse import urlparse

from app.config import settings

AR_DIR = Path(__file__).resolve().parent.parent / "wazuh" / "active-response"
# A kiszolgalhato fajlok (mas nem): a Linux script es a Windows indito + PowerShell script.
AR_FILES = ("siemantics-isolate", "siemantics-isolate.cmd", "siemantics-isolate.ps1")

# A parancsba kerulo ertekek: semmi, ami shellben / PowerShellben kiterhetne.
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_GROUPS_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}(,[A-Za-z0-9._-]{1,64})*$")
_MANAGER_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


class InstallError(ValueError):
    pass


def ar_file(name: str) -> bytes:
    if name not in AR_FILES:
        raise InstallError("unknown file")
    return (AR_DIR / name).read_bytes()


def sha256(name: str) -> str:
    return hashlib.sha256(ar_file(name)).hexdigest()


def default_manager() -> str:
    host = urlparse(settings.wazuh_api_url).hostname if settings.wazuh_api_url else None
    return settings.wazuh_manager_address or host or ""


def validate(name: str, group: str, manager: str, version: str) -> None:
    if name and not _NAME_RE.match(name):
        raise InstallError("agent name: letters, digits, dot, dash and underscore only (max 64)")
    if group and not _GROUPS_RE.match(group):
        raise InstallError("group: comma-separated names of letters, digits, dot, dash and underscore")
    if not _MANAGER_RE.match(manager or ""):
        raise InstallError("manager address must be an IP or host name")
    if not _VERSION_RE.match(version or ""):
        raise InstallError("version must look like 4.14.5")


def linux_script(base_url: str, manager: str, version: str) -> str:
    return _LINUX_TEMPLATE.format(base=base_url, manager=manager, version=version,
                                  sha=sha256("siemantics-isolate"))


def windows_script(base_url: str, manager: str, version: str) -> str:
    return _WINDOWS_TEMPLATE.format(base=base_url, manager=manager, version=version,
                                    sha_cmd=sha256("siemantics-isolate.cmd"), sha_ps1=sha256("siemantics-isolate.ps1"))


def command(os_name: str, base_url: str, name: str, group: str, manager: str, version: str) -> str:
    # Egysoros parancs; minden ertek validalt, ezert az idezojelek kozott nem tud kitorni.
    validate(name, group, manager, version)
    query = f"manager={manager}&version={version}"
    if os_name == "linux":
        args = "".join(f" --{k} '{v}'" for k, v in (("name", name), ("group", group)) if v)
        return f"curl -fsSL '{base_url}/agent-install/linux.sh?{query}' | sudo bash -s --{args}"
    if os_name == "windows":
        args = "".join(f" -{k} '{v}'" for k, v in (("Name", name), ("Group", group)) if v)
        return ("powershell -NoProfile -ExecutionPolicy Bypass -Command \"[Net.ServicePointManager]::SecurityProtocol = "
                "[Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing "
                f"'{base_url}/agent-install/windows.ps1?{query}').Content)){args}\"")
    raise InstallError("os must be linux or windows")


_LINUX_TEMPLATE = r"""#!/bin/bash
# SIEMantics: Wazuh agent telepites (ha meg nincs) es a SIEMantics izolalo script kirakasa / frissitese.
# Tobbszor is futtathato: telepitett agentnel csak a scriptet frissiti.
set -euo pipefail

MANAGER="{manager}"
VERSION="{version}"
BASE="{base}"
ISOLATE_SHA256="{sha}"
NAME=""
GROUP=""

while [ $# -gt 0 ]; do
    case "$1" in
        --name) NAME="$2"; shift 2 ;;
        --group) GROUP="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || {{ echo "run it as root (sudo)" >&2; exit 1; }}

fetch() {{
    if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$2" "$1"; else wget -q -O "$2" "$1"; fi
}}

if [ -x /var/ossec/bin/wazuh-control ]; then
    echo "Wazuh agent already installed: only the SIEMantics script is updated"
else
    export WAZUH_MANAGER="$MANAGER"
    [ -n "$NAME" ] && export WAZUH_AGENT_NAME="$NAME"
    [ -n "$GROUP" ] && export WAZUH_AGENT_GROUP="$GROUP"
    tmp=$(mktemp -d)
    arch=$(uname -m)
    if command -v dpkg >/dev/null 2>&1; then
        case "$arch" in x86_64) a=amd64 ;; aarch64|arm64) a=arm64 ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac
        pkg="wazuh-agent_${{VERSION}}-1_${{a}}.deb"
        fetch "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/$pkg" "$tmp/$pkg"
        dpkg -i "$tmp/$pkg"
    elif command -v rpm >/dev/null 2>&1; then
        case "$arch" in x86_64) a=x86_64 ;; aarch64|arm64) a=aarch64 ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac
        pkg="wazuh-agent-${{VERSION}}-1.${{a}}.rpm"
        fetch "https://packages.wazuh.com/4.x/yum/$pkg" "$tmp/$pkg"
        rpm -ihv "$tmp/$pkg"
    else
        echo "neither dpkg nor rpm found" >&2; exit 1
    fi
    rm -rf "$tmp"
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
    echo "Wazuh agent $VERSION installed (manager: $MANAGER)"
fi

# Az izolalo script: csak ellenorzott tartalommal kerul a helyere.
target=/var/ossec/active-response/bin/siemantics-isolate
tmpf=$(mktemp)
fetch "$BASE/agent-install/files/siemantics-isolate" "$tmpf"
if ! echo "$ISOLATE_SHA256  $tmpf" | sha256sum -c - >/dev/null 2>&1; then
    rm -f "$tmpf"; echo "checksum mismatch, the SIEMantics script was not installed" >&2; exit 1
fi
install -o root -g wazuh -m 750 "$tmpf" "$target"
rm -f "$tmpf"
echo "SIEMantics isolation script installed: $target"
"""

_WINDOWS_TEMPLATE = r"""# SIEMantics: Wazuh agent telepites (ha meg nincs) es a SIEMantics izolalo script kirakasa / frissitese.
# Adminkent futtatando; tobbszor is futtathato: telepitett agentnel csak a scripteket frissiti.
param([string]$Name = "", [string]$Group = "")
$ErrorActionPreference = "Stop"

$Manager = "{manager}"
$Version = "{version}"
$Base = "{base}"
$Hashes = @{{ "siemantics-isolate.cmd" = "{sha_cmd}"; "siemantics-isolate.ps1" = "{sha_ps1}" }}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    throw "Run it in an elevated (Run as administrator) PowerShell."
}}

if (-not (Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue)) {{
    $msi = Join-Path $env:TEMP "wazuh-agent-$Version-1.msi"
    Invoke-WebRequest -UseBasicParsing "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version-1.msi" -OutFile $msi
    $arguments = @("/i", "`"$msi`"", "/q", "WAZUH_MANAGER=$Manager")
    if ($Name) {{ $arguments += "WAZUH_AGENT_NAME=$Name" }}
    if ($Group) {{ $arguments += "WAZUH_AGENT_GROUP=$Group" }}
    $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {{ throw "msiexec failed with exit code $($process.ExitCode)" }}
    Start-Service -Name WazuhSvc
    Write-Output "Wazuh agent $Version installed (manager: $Manager)"
}} else {{
    Write-Output "Wazuh agent already installed: only the SIEMantics scripts are updated"
}}

$root = ${{env:ProgramFiles(x86)}}
if (-not $root) {{ $root = $env:ProgramFiles }}
$bin = Join-Path $root "ossec-agent\active-response\bin"
foreach ($file in $Hashes.Keys) {{
    # Bajtra pontos letoltes (a .ps1 UTF-8 BOM-ja megmarad), csak ellenorzott tartalommal.
    $dest = Join-Path $bin $file
    $tmp = "$dest.download"
    Invoke-WebRequest -UseBasicParsing "$Base/agent-install/files/$file" -OutFile $tmp
    if ((Get-FileHash -Path $tmp -Algorithm SHA256).Hash.ToLower() -ne $Hashes[$file]) {{
        Remove-Item $tmp -Force
        throw "checksum mismatch: $file was not installed"
    }}
    Move-Item -Path $tmp -Destination $dest -Force
}}
Write-Output "SIEMantics isolation scripts installed: $bin"
"""
