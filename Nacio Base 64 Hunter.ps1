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

# =========================
# PowerShell: Prepare list of suspicious files for analysis
# Run in a safe environment (VM/sandbox). Script DOES NOT execute any files.
# =========================

$sourceDir = 'C:\SS1\extracted_base64'
$targetDir = 'C:\SS1\to_analyze'
$outTxt = 'C:\SS1\analysis_candidates.txt'
$outCsv = 'C:\SS1\extracted_summary.csv'

# thresholds — edit if needed
$printableThreshold = 0.6    # >= treated as mostly text (scripts)
$entropyThreshold = 6.5      # >= treated as high entropy (packed/encrypted)
$sizeThreshold = 1000        # bytes >= treated as "larger files" (likely binaries/scripts)

# helper function to calculate entropy
function Get-Entropy([byte[]]$data) {
    if ($null -eq $data -or $data.Length -eq 0) { return 0.0 }
    $counts = @{}
    foreach ($b in $data) {
        if ($counts.ContainsKey($b)) { $counts[$b]++ } else { $counts[$b] = 1 }
    }
    $entropy = 0.0
    foreach ($v in $counts.Values) {
        $p = [double]$v / $data.Length
        $entropy -= $p * [Math]::Log($p,2)
    }
    return [Math]::Round($entropy,4)
}

# prepare directories and output files
if (-not (Test-Path $sourceDir)) {
    Write-Error "Source directory does not exist: $sourceDir"
    break
}
New-Item -Path $targetDir -ItemType Directory -Force | Out-Null

# clear output files
"" | Out-File $outTxt -Encoding UTF8
"Name,Length,SHA256,HexStart,IsMZ,PrintableRatio,Entropy,Reason" | Out-File $outCsv -Encoding UTF8

# scan files
Get-ChildItem -Path $sourceDir -File | ForEach-Object {
    $file = $_
    $path = $file.FullName
    try {
        $bytes = [System.IO.File]::ReadAllBytes($path)
    } catch {
        "$($file.Name): Read error: $_" | Out-File $outTxt -Append -Encoding UTF8
        return
    }

    $len = $bytes.Length
    $sha = ""
    try { $sha = (Get-FileHash -Path $path -Algorithm SHA256).Hash } catch { $sha = "ERROR" }

    $hexStart = -join (($bytes[0..([Math]::Min(15,$len-1))]) | ForEach-Object { '{0:X2}' -f $_ })
    $isMZ = ($len -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A)
    $printableCount = ($bytes | Where-Object { $_ -ge 32 -and $_ -le 126 }).Count
    $printableRatio = if ($len -gt 0) { [Math]::Round($printableCount / $len,4) } else { 0 }
    $entropy = Get-Entropy $bytes

    # decision rules — suspicious if:
    # - PE header (MZ) OR
    # - mostly text (likely script) OR
    # - high entropy (packed/encrypted) OR
    # - large size (above threshold)
    $reasons = @()
    if ($isMZ) { $reasons += "MZ header (PE exe/dll)" }
    if ($printableRatio -ge $printableThreshold) { $reasons += "High printable ratio ($printableRatio)" }
    if ($entropy -ge $entropyThreshold) { $reasons += "High entropy ($entropy)" }
    if ($len -ge $sizeThreshold) { $reasons += "Size>=$sizeThreshold ($len bytes)" }

    # extra heuristics: search suspicious keywords in readable text
    $susWords = @("Invoke-Expression","IEX","powershell","DownloadString","DownloadFile","rundll32","CreateRemoteThread","WriteProcessMemory","VirtualAllocEx","LoadLibrary","ReflectiveLoader","schtasks","regsvr32","This program cannot be run in DOS mode","CobaltStrike","beacon","meterpreter")
    if ($printableRatio -gt 0.1) {
        $ascii = -join ($bytes | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { ' ' } })
        foreach ($w in $susWords) {
            if ($ascii.IndexOf($w, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $reasons += "Contains:$w"
            }
        }
    }

    $reasonText = if ($reasons.Count -gt 0) { ($reasons -join "; ") } else { "OK - nothing suspicious by rules" }

    # save summary to CSV
    "$($file.Name),$len,$sha,$hexStart,$isMZ,$printableRatio,$entropy,$reasonText" | Out-File $outCsv -Append -Encoding UTF8

    # if suspicious, copy to analysis folder and write details to TXT
    if ($reasons.Count -gt 0) {
        $dest = Join-Path $targetDir $file.Name
        try { Copy-Item -Path $path -Destination $dest -Force } catch { "$($file.Name): copy error: $_" | Out-File $outTxt -Append -Encoding UTF8 }

        # write details to TXT
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

        # first ASCII strings (max 40)
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




