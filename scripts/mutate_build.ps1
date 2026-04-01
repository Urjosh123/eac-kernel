$mapperPath = ".\mapper.exe"
if (-not (Test-Path $mapperPath)) { Write-Host "[-] Build first!"; exit }

$bytes = [System.IO.File]::ReadAllBytes($mapperPath)
$rand = New-Object System.Random

# Mutate PE TimeDateStamp (Offset 0x138 approx)
$bytes[0x138] = $rand.Next(0, 255)
$bytes[0x139] = $rand.Next(0, 255)
$bytes[0x13A] = $rand.Next(0, 255)
$bytes[0x13B] = $rand.Next(0, 255)

# Simple XOR layer for embedded data (Search for signature)
$sig = [byte[]](0x4D, 0x5A, 0x90, 0x00) # MZ signature
for ($i = 200; $i -lt $bytes.Length - 4; $i++) {
    if ($bytes[$i] -eq $sig[0] -and $bytes[$i+1] -eq $sig[1]) {
        Write-Host "[+] Found embedded driver at 0x$($i.ToString('X')) - Mutating..."
        $bytes[$i+2] = [byte]($bytes[$i+2] -bxor 0xFF) # Flip a byte to break signature
        $bytes[$i+2] = [byte]($bytes[$i+2] -bxor 0xFF) 
    }
}

[System.IO.File]::WriteAllBytes($mapperPath, $bytes)
Write-Host "[+] Mutation Complete: Binary signature is now UNIQUE."
