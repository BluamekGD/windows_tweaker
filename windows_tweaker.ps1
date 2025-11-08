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

# Ask for the target username
$u = Read-Host "Please enter the username of your account (case-sensitive!)"

# Find the user’s SID and profile path
$sid = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
    Where-Object {(Get-ItemProperty $_.PSPath).ProfileImagePath -like "*\$u"}).PSChildName
$profile = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid").ProfileImagePath

# Load the user hive
reg load "HKU\TempUserHive" "$profile\NTUSER.DAT"

# Disable Recommended section
New-ItemProperty -Path "HKU:\TempUserHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -PropertyType DWORD -Value 0 -Force

# Unload the hive
reg unload "HKU\TempUserHive"


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

