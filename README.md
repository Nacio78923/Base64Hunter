# Base64Hunter
Base64Hunter is a small PowerShell helper that automates quick triage of files extracted from large text dumps (for example produced by bstrings run against MagnetProcessCapture output). It flags likely PE files, scripts, and high-entropy blobs, copies them to a safe folder and produces CSV + human-readable TXT reports so you can continue analysis.
