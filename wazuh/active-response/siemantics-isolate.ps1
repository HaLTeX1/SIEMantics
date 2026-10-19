# SIEMantics gep izolalas (Wazuh active response, Windows): csak a megadott cimek (Wazuh manager) erhetok el.
# A SIEMantics az extra_args-ban kuldi: "isolate <IP>..." vagy "release". A lejaratkor (delete) mindig felold.
# Tilto szabalyokat hasznal (Windowson a tilto szabaly erosebb barmely meglevo engedelyezonel), sajat csoportban.
# Helye az agenten: C:\Program Files (x86)\ossec-agent\active-response\bin\ (a .cmd inditoval egyutt).

$ErrorActionPreference = "Stop"
$Group = "SIEMantics isolation"
$ArDir = Split-Path -Parent $PSScriptRoot
$LogFile = Join-Path $ArDir "active-responses.log"
$StateFile = Join-Path $ArDir "siemantics-isolation-profiles.json"

function Write-ArLog([string]$Message) {
    $line = "{0} siemantics-isolate: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $Message
    Add-Content -Path $LogFile -Value $line
}

function ConvertTo-UInt32([string]$Ip) {
    $bytes = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertTo-Ip([uint32]$Value) {
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-BlockRanges([string[]]$Allowed) {
    # Az IPv4 cimter a megengedett cimek nelkul, "elso-utolso" tartomanyokkent.
    $points = $Allowed | ForEach-Object { ConvertTo-UInt32 $_ } | Sort-Object -Unique
    $ranges = @()
    [uint64]$start = 0
    foreach ($p in $points) {
        if ([uint64]$p -gt $start) { $ranges += "{0}-{1}" -f (ConvertTo-Ip ([uint32]$start)), (ConvertTo-Ip ([uint32]($p - 1))) }
        $start = [uint64]$p + 1
    }
    if ($start -le [uint32]::MaxValue) { $ranges += "{0}-255.255.255.255" -f (ConvertTo-Ip ([uint32]$start)) }
    return $ranges
}

function Show-Notice([string]$Text) {
    # Felugro ablak minden bejelentkezett felhasznalonak (a SYSTEM nem nyithat kozvetlenul ablakot).
    $msg = Join-Path $env:SystemRoot "Sysnative\msg.exe"
    if (-not (Test-Path $msg)) { $msg = Join-Path $env:SystemRoot "System32\msg.exe" }
    if (-not (Test-Path $msg)) {
        # Windows Home kiadason nincs msg.exe: az izolalas ettol fuggetlenul megtortenik.
        Write-ArLog "notice skipped: msg.exe not available"
        return
    }
    try {
        & $msg "*" "/TIME:86400" $Text
    } catch {
        Write-ArLog ("notice failed: " + $_.Exception.Message)
    }
}

function Format-Until([string[]]$Extra) {
    # A SIEMantics "until=<unix ido>" argumentuma helyi idokent.
    $arg = $Extra | Where-Object { $_ -match '^until=\d+$' } | Select-Object -First 1
    if (-not $arg) { return $null }
    $local = [DateTimeOffset]::FromUnixTimeSeconds([int64]($arg -replace '^until=', '')).LocalDateTime
    return $local.ToString("yyyy.MM.dd. HH:mm")
}

function Get-IsolationNotice([string]$Until) {
    $end = if ($Until) { "Az elkülönítés várható vége: $Until, vagy amíg a vizsgálat le nem zárul." } else { "Az elkülönítés a vizsgálat lezárultáig tart." }
    return @(
        "BIZTONSÁGI FIGYELMEZTETÉS: a számítógép hálózatilag el lett különítve",
        "",
        "Egy lehetséges biztonsági incidens miatt az informatikai biztonsági csapat ezt a gépet ideiglenesen leválasztotta a hálózatról. Ez nem a te hibád.",
        "",
        "Mit jelent ez: a gép most nem éri el az internetet, a levelezést, a hálózati meghajtókat és a belső rendszereket. A helyi programok és a helyi fájlok továbbra is működnek.",
        "",
        "Kérjük, ne kapcsold ki és ne indítsd újra a gépet, ne húzd ki a hálózati kábelt, és ne próbáld megkerülni a korlátozást, mert ez akadályozhatja a vizsgálatot.",
        "",
        $end
    ) -join "`r`n"
}

function Invoke-Release {
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if (Test-Path $StateFile) {
        # A tuzfal profilok eredeti be-/kikapcsolt allapota.
        foreach ($p in (Get-Content $StateFile -Raw | ConvertFrom-Json)) {
            Set-NetFirewallProfile -Name $p.Name -Enabled ([bool]$p.Enabled)
        }
        Remove-Item $StateFile -Force
    }
    Write-ArLog "released"
    Show-Notice "A számítógép hálózati elkülönítése megszűnt, a gép újra eléri a hálózatot."
}

function Invoke-Isolate([string[]]$Allowed, [string]$Until) {
    if (-not $Allowed -or $Allowed.Count -eq 0) {
        Write-ArLog "refused: no allowed address given"
        exit 1
    }
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if (-not (Test-Path $StateFile)) {
        Get-NetFirewallProfile | Select-Object Name, @{n = "Enabled"; e = { [bool]$_.Enabled } } |
            ConvertTo-Json | Set-Content $StateFile
    }
    Set-NetFirewallProfile -All -Enabled True
    $ranges = Get-BlockRanges $Allowed
    foreach ($dir in "Inbound", "Outbound") {
        New-NetFirewallRule -DisplayName "SIEMantics isolation IPv4 $dir" -Group $Group -Direction $dir -Action Block `
            -RemoteAddress $ranges -Profile Any | Out-Null
        New-NetFirewallRule -DisplayName "SIEMantics isolation IPv6 $dir" -Group $Group -Direction $dir -Action Block `
            -RemoteAddress "::/0" -Profile Any | Out-Null
    }
    Write-ArLog ("isolated, allowed: " + ($Allowed -join " "))
    Show-Notice (Get-IsolationNotice $Until)
}

try {
    $message = [Console]::In.ReadLine() | ConvertFrom-Json
    $command = [string]$message.command
    $extra = @($message.parameters.extra_args | ForEach-Object { [string]$_ })
    $mode = if ($extra.Count -gt 0) { $extra[0] } else { "" }
    # Csak ervenyes IPv4 cim kerulhet a szabalyokba.
    $allowed = @($extra | Where-Object {
        $parsed = $null
        $_ -match '^(\d{1,3}\.){3}\d{1,3}$' -and [System.Net.IPAddress]::TryParse($_, [ref]$parsed)
    })
    switch ($command) {
        "add" { if ($mode -eq "release") { Invoke-Release } else { Invoke-Isolate $allowed (Format-Until $extra) } }
        "delete" { Invoke-Release }
        default { Write-ArLog "ignored command: $command" }
    }
} catch {
    Write-ArLog ("error: " + $_.Exception.Message)
    exit 1
}
exit 0
