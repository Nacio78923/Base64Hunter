$dump = 'C:\SS1\NacioDump.txt'
$outdir = 'C:\SS1\extracted_base64'
New-Item -Path $outdir -ItemType Directory -Force | Out-Null
$candidates = Select-String -Path $dump -Pattern "[A-Za-z0-9+/]{100,}={0,2}" -AllMatches

$idx=0
foreach ($match in $candidates) {
  foreach ($m in $match.Matches) {
    $b64 = $m.Value -replace '\s+',''   # usuń spacje/enter
    try {
      $bytes = [System.Convert]::FromBase64String($b64)
      $fname = Join-Path $outdir ("extracted_{0}.bin" -f $idx)
      [System.IO.File]::WriteAllBytes($fname, $bytes)
      "$($match.Filename):$($match.LineNumber) -> $fname (size: $($bytes.Length) bytes)" | Out-File C:\SS1\extraction_log.txt -Append
      $idx++
    } catch {
      # niepoprawny base64
      "$($match.Filename):$($match.LineNumber) -> invalid base64" | Out-File C:\SS1\extraction_log.txt -Append
    }
  }
}
Write-Output "Done. Extracted to $outdir. Log: C:\SS1\extraction_log.txt"
