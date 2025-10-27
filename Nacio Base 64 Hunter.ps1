<#
  Nacio BASE64 HUNTER
  Made by Nacio - https://discord.gg/H9aWqxTKJG

 PowerShell: Prepare list of suspicious files for analysis
 Script DOES NOT execute any files.
#>

# ASCII banner
$banner = @'
███╗   ██╗ █████╗  ██████╗██╗ ██████╗     ██████╗  █████╗ ███████╗███████╗ ██████╗ ██╗  ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
████╗  ██║██╔══██╗██╔════╝██║██╔═══██╗    ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝ ██║  ██║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██╔██╗ ██║███████║██║     ██║██║   ██║    ██████╔╝███████║███████╗█████╗  ███████╗ ███████║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║╚██╗██║██╔══██║██║     ██║██║   ██║    ██╔══██╗██╔══██║╚════██║██╔══╝  ██╔═══██╗╚════██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║ ╚████║██║  ██║╚██████╗██║╚██████╔╝    ██████╔╝██║  ██║███████║███████╗╚██████╔╝     ██║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝╚═╝ ╚═════╝     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝      ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                                                                                                   
                                                                                  
Nacio BASE64 HUNTER
Made by Nacio - https://discord.gg/H9aWqxTKJG
'@

Write-Host $banner

# Automatically prepares extracted_base64 from dump.txt
# =========================

# === CONFIG ===
$dumpFile = 'C:\SS1\dump.txt'                   # dump z bstrings/magnet
$sourceDir = 'C:\SS1\extracted_base64'
$targetDir = 'C:\SS1\to_analyze'
$outTxt = 'C:\SS1\analysis_candidates.txt'
$outCsv = 'C:\SS1\extracted_summary.csv'

# thresholds
$printableThreshold = 0.6
$entropyThreshold = 6.5
$sizeThreshold = 1000

# === UTILS ===
function Get-Entropy([byte[]]$data) {
    if ($null -eq $data -or $data.Length -eq 0) { return 0.0 }
    $counts = @{}
    foreach ($b in $data) { if ($counts.ContainsKey($b)) { $counts[$b]++ } else { $counts[$b] = 1 } }
    $entropy = 0.0
    foreach ($v in $counts.Values) { $p = [double]$v / $data.Length; $entropy -= $p * [Math]::Log($p,2) }
    return [Math]::Round($entropy,4)
}

# === PREPARE FOLDERS ===
if (-not (Test-Path $sourceDir)) { New-Item -ItemType Directory -Path $sourceDir | Out-Null }
if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir | Out-Null }

# === EXTRACT BASE64 FROM DUMP ===
if (-not (Test-Path $dumpFile)) {
    Write-Error "Dump file not found: $dumpFile"
    exit 1
}

# clear previous extracted files
Get-ChildItem $sourceDir -File | Remove-Item -Force

$dumpContent = Get-Content $dumpFile -Raw
$matches = [regex]::Matches($dumpContent, '[A-Za-z0-9+/]{40,}={0,2)')
$i = 0
foreach ($m in $matches) {
    $i++
    $m.Value | Out-File (Join-Path $sourceDir "file_$i.b64") -Encoding ascii
}
Write-Output "Extracted $i Base64 sequences to $sourceDir"

# === CLEAR OUTPUT FILES ===
"" | Out-File $outTxt -Encoding UTF8
"Name,Length,SHA256,HexStart,IsMZ,PrintableRatio,Entropy,Reason" | Out-File $outCsv -Encoding UTF8

# === SCAN FILES ===
Get-ChildItem -Path $sourceDir -File | ForEach-Object {
    $file = $_
    $path = $file.FullName
    try { $bytes = [System.IO.File]::ReadAllBytes($path) } catch { "$($file.Name): Read error: $_" | Out-File $outTxt -Append -Encoding UTF8; return }

    $len = $bytes.Length
    $sha = ""
    try { $sha = (Get-FileHash -Path $path -Algorithm SHA256).Hash } catch { $sha = "ERROR" }

    $hexStart = -join (($bytes[0..([Math]::Min(15,$len-1))]) | ForEach-Object { '{0:X2}' -f $_ })
    $isMZ = ($len -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A)
    $printableCount = ($bytes | Where-Object { $_ -ge 32 -and $_ -le 126 }).Count
    $printableRatio = if ($len -gt 0) { [Math]::Round($printableCount / $len,4) } else { 0 }
    $entropy = Get-Entropy $bytes

    $reasons = @()
    if ($isMZ) { $reasons += "MZ header (PE exe/dll)" }
    if ($printableRatio -ge $printableThreshold) { $reasons += "High printable ratio ($printableRatio)" }
    if ($entropy -ge $entropyThreshold) { $reasons += "High entropy ($entropy)" }
    if ($len -ge $sizeThreshold) { $reasons += "Size>=$sizeThreshold ($len bytes)" }

    $susWords = @("Invoke-Expression","IEX","powershell","DownloadString","DownloadFile","rundll32","CreateRemoteThread","WriteProcessMemory","VirtualAllocEx","LoadLibrary","ReflectiveLoader","schtasks","regsvr32","This program cannot be run in DOS mode","CobaltStrike","beacon","meterpreter")
    if ($printableRatio -gt 0.1) {
        $ascii = -join ($bytes | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { ' ' } })
        foreach ($w in $susWords) { if ($ascii.IndexOf($w, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $reasons += "Contains:$w" } }
    }

    $reasonText = if ($reasons.Count -gt 0) { ($reasons -join "; ") } else { "OK - nothing suspicious by rules" }

    "$($file.Name),$len,$sha,$hexStart,$isMZ,$printableRatio,$entropy,$reasonText" | Out-File $outCsv -Append -Encoding UTF8

    if ($reasons.Count -gt 0) {
        $dest = Join-Path $targetDir $file.Name
        try { Copy-Item -Path $path -Destination $dest -Force } catch { "$($file.Name): copy error: $_" | Out-File $outTxt -Append -Encoding UTF8 }

        "------------------------------------------------------------" | Out-File $outTxt -Append -Encoding UTF8
        "File: $($file.Name)" | Out-File $outTxt -Append -Encoding UTF8
        "Path: $path" | Out-File $outTxt -Append -Encoding UTF8
        "Size: $len bytes" | Out-File $outTxt -Append -Encoding UTF8
        "SHA256: $sha" | Out-File $outTxt -Append -Encoding UTF8
        "HexStart (first up to 16 bytes): $hexStart" | Out-File $outTxt -Append -Encoding UTF8
        "IsMZ: $isMZ" | Out-File $outTxt -Append -Encoding UTF8
        "PrintableRatio: $printableRatio" | Out-File $outTxt -Append -Encoding UTF8
        "Entropy: $entropy" | Out-File $outTxt -Append -Encoding UTF8
        "Reasons: $reasonText" | Out-File $outTxt -Append -Encoding UTF8

        if ($printableRatio -gt 0.01) {
            $strings = $ascii -split '\s{2,}' | Where-Object { $_.Length -ge 4 } | Select-Object -Unique -First 40
            "Strings (first matches):" | Out-File $outTxt -Append -Encoding UTF8
            foreach ($s in $strings) { $s -replace '"','' | Out-File $outTxt -Append -Encoding UTF8 }
        } else {
            "Strings: (not enough readable ASCII)" | Out-File $outTxt -Append -Encoding UTF8
        }

        "" | Out-File $outTxt -Append -Encoding UTF8
    }
}

Write-Output "Scanning completed."
Write-Output "CSV summary: $outCsv"
Write-Output "Suspicious candidates TXT: $outTxt"
Write-Output "Copied suspicious files to analysis folder: $targetDir"



