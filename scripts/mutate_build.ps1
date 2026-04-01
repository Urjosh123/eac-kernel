$binaryPath = "kdmapper.exe"
if (-Not (Test-Path $binaryPath)) { Exit }

$fileBytes = [System.IO.File]::ReadAllBytes($binaryPath)
$random = New-Object System.Random

$junkSize = $random.Next(1024, 4096)
$junkBytes = New-Object byte[] $junkSize
$random.NextBytes($junkBytes)

$newFileBytes = $fileBytes + $junkBytes
[System.IO.File]::WriteAllBytes($binaryPath, $newFileBytes)

Write-Host "[+] Mutant Build: Junk-Injected and Randomized Binary Signature Created."
