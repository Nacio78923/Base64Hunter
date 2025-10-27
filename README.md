# Base64Hunter
Base64Hunter is a small PowerShell helper that automates quick triage of files extracted from large text dumps (for example produced by bstrings run against MagnetProcessCapture output). It flags likely PE files, scripts, and high-entropy blobs, copies them to a safe folder and produces CSV + human-readable TXT reports so you can continue analysis.
## Example Usage
Run bstrings on a MagnetProcessCapture dump to extract printable strings and Base64 fragments:
`bstrings.exe -d MagnetProcessCapture-20251027-121245 -s --ls .exe -o C:\SS1\NacioDump.txt`

# Base64Hunter

**PowerShell tool for triaging files extracted from MagnetProcessCapture dumps**

Base64Hunter helps analysts quickly identify suspicious files after running `bstrings` on memory or process dumps captured with MagnetProcessCapture. Large `bstrings` outputs often contain thousands of lines and Base64 blobs, making manual inspection time-consuming. This script automates the triage process and produces actionable results.

## What it does

After decoding Base64 fragments from a `bstrings` dump (e.g., `C:\SS1\extracted_base64`), Base64Hunter:

- Computes **SHA256**, **file size**, **entropy**, and **printable character ratio** for each file.  
- Detects **PE headers** (`MZ`) to flag EXE/DLL files.  
- Identifies **high-entropy** or **mostly-text files** (likely scripts or packed binaries).  
- Searches for **suspicious keywords**, including PowerShell commands, reflective loaders, cheat terms, and other potential malware indicators.  
- Automatically copies flagged files to a safe folder (`C:\SS1\to_analyze`) for further analysis.
- Generates:
  - `extracted_summary.csv` — full per-file metrics, sortable and filterable.  
  - `analysis_candidates.txt` — human-readable report with reasons each file was flagged, plus example strings and hex preview.

This allows you to **quickly focus on files worth further investigation** without manually inspecting huge `bstrings` outputs.

## How to use

1. Run `bstrings` on the MagnetProcessCapture dump:
`bstrings.exe -d MagnetProcessCapture-20251027-121245 -s --ls .exe -o C:\SS1\NacioDump.txt`

2. In the next step you need to use this command to export the necessary data to use the next (last script)
```
  powershell -Command "iex (iwr https://raw.githubusercontent.com/Nacio78923/Base64Hunter/main/Decoding%20base64.ps1)"
```

## Decode Base64 fragments from the dump into a folder, e.g.:
`C:\SS1\extracted_base64`
          ^   
you will create such a file

At the very end you use the last script remember to use cd in cmd
## Run Base64Hunter on the extracted files:
```
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Nacio78923/Base64Hunter/refs/heads/main/Nacio%20Base%2064%20Hunter.ps1')"

```


## Check the outputs:

* extracted_summary.csv → sortable summary of all files
* analysis_candidates.txt → detailed report for suspicious files
* to_analyze/ → folder containing flagged files ready for safe VM/sandbox analysis

## Default heuristics

The script flags files if any of the following are true:

- **MZ header** → PE executable (EXE/DLL)  
- **Printable ratio ≥ 0.6** → mostly text or script  
- **Entropy ≥ 6.5** → likely packed/encrypted  
- **File size ≥ 1000 bytes** → significant file  
- **Contains suspicious keywords** → PowerShell commands, cheat/malware indicators  

> These thresholds can be adjusted in the script to be more or less sensitive.

## Why it's useful

- Speeds up **DFIR and threat hunting** workflows.  
- Helps identify potential cheats, malware, or other malicious artifacts in memory dumps.  
- Reduces noise from large `bstrings` outputs, letting analysts focus on **actionable files**.  
- Prepares outputs in a **safe, repeatable, and organized** way.

💬 Author NACIO © 2025 NACIO — All rights reserved.
