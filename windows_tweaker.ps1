# Check for admin and escalate if needed

function Test-IsAdmin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    # Relaunch the same script elevated
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"

    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        exit 0
    } catch {
        Write-Host "Elevation was denied. Exiting." -ForegroundColor Red
        exit 1
    }
}

# Running with admin

Write-Host "Running with administrator privileges!" -ForegroundColor Green
Start-Sleep -Seconds 1

clear

# Activation check

$activationStatus = (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%' and PartialProductKey is not null").LicenseStatus

if ($activationStatus -eq 1) {
    Write-Host "Windows is activated. Continuing." -ForegroundColor Green
Start-Sleep -Seconds 3
} else {
    Write-Host "Windows is NOT activated. Please activate Windows before using this script. Exiting in 5 seconds." -ForegroundColor Red
Start-Sleep -Seconds 5
exit 1
}

# Registry tweaks

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 1

# Load current users hive as that keyboard spam
reg load "HKU\a8dfgaiwuryt8e47tg" "$env:USERPROFILE\NTUSER.DAT"

New-ItemProperty -Path "HKU:\a8dfgaiwuryt8e47tg\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -PropertyType DWORD -Value 0

# Unload hive
reg unload "HKU\a8dfgaiwuryt8e47tg"


# Install Firefox

Start-Process "winget" -ArgumentList "install Mozilla.Firefox --accept-package-agreements --accept-source-agreements" -Wait

# Finalize

# Create left_to_do.txt on desktop
$desktopPath = [Environment]::GetFolderPath("Desktop")
$todoFile = Join-Path $desktopPath "left_to_do.txt"

$todoText = @"
hi, thanks for using my script, heres the stuff thats left to do since i didnt get it working :/

- uninstall edge and onedrive

...yeah thats it, thats how much theyre pushed onto you, well thanks. bye!
"@

Set-Content -Path $todoFile -Value $todoText

Write-Host "Done! Restarting." -ForegroundColor Green
Start-Sleep -Seconds 1
Restart-Computer -Force
