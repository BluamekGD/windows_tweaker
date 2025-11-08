# ---- Elevation check & relaunch if needed ----
function Test-IsAdmin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        exit 0
    } catch {
        Write-Host "Elevation denied. Exiting." -ForegroundColor Red
        exit 1
    }
}

# ---- Small pause/clear so user sees message ----
Write-Host "Running with administrator privileges!" -ForegroundColor Green
Start-Sleep -Seconds 1
Clear-Host

# ---- Activation check ----
try {
    $activationStatus = (Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "Name like 'Windows%' and PartialProductKey is not null").LicenseStatus
} catch {
    $activationStatus = $null
}
if ($activationStatus -ne 1) {
    Write-Host "Windows is NOT activated or activation check failed. Exiting in 5s." -ForegroundColor Red
    Start-Sleep -Seconds 5
    exit 1
}
Write-Host "Windows activated. Continuing..." -ForegroundColor Green
Start-Sleep -Seconds 1

# ---- System-wide registry tweaks (HKLM / current Admin HKCU where intended) ----
try {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Force
} catch {
    Write-Host "Failed to set current user's theme keys. (Non-fatal)" -ForegroundColor Yellow
}

try {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
} catch {
    Write-Host "Failed to set telemetry policy. (Non-fatal)" -ForegroundColor Yellow
}

try {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 1 -Force
} catch {
    Write-Host "Failed to set VerboseStatus. (Non-fatal)" -ForegroundColor Yellow
}

# ---- Prompt loop for target username (case-sensitive) ----
while ($true) {
    $u = Read-Host "Please enter the username of your account (case-sensitive!). Enter blank to cancel"
    if ([string]::IsNullOrWhiteSpace($u)) {
        Write-Host "Cancelled by user." -ForegroundColor Yellow
        break
    }

    $profileKey = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue |
        Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath -like "*\$u" }

    if (-not $profileKey) {
        Write-Host "Username not found. Try again." -ForegroundColor Red
        continue
    }

    $sid = $profileKey.PSChildName
    $profile = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction Stop).ProfileImagePath
    if (-not (Test-Path "$profile\NTUSER.DAT")) {
        Write-Host "NTUSER.DAT not found for that profile ($profile). Try another user." -ForegroundColor Red
        continue
    }

    # Determine if hive already loaded under HKU\<sid>
    $hivePath = "HKU:\$sid"
    $loadedHive = Get-ChildItem HKU: -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq $sid }
    $needUnload = $false
    try {
        if ($loadedHive) {
            Write-Host "User hive already loaded under HKU\$sid — using it." -ForegroundColor Green
            $targetHive = $hivePath
        } else {
            # Use a safe temp name that avoids collisions
            $tempName = "TgHive_$([guid]::NewGuid().ToString('N').Substring(0,8))"
            reg load "HKU\$tempName" "$profile\NTUSER.DAT" 2>$null
            if ($LASTEXITCODE -ne 0) {
                Write-Host "Failed to load user hive. They may be logged in or file locked. Try running without that user logged in." -ForegroundColor Red
                # cleanup if something partially loaded
                try { reg unload "HKU\$tempName" } catch {}
                continue
            }
            $targetHive = "HKU:\$tempName"
            $needUnload = $true
            Write-Host "Loaded hive as $tempName." -ForegroundColor Green
        }

        # Write the Start_TrackDocs and theme keys into the target user hive
        try {
            New-Item -Path "$targetHive\Software\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null
            New-Item -Path "$targetHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
            New-ItemProperty -Path "$targetHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -PropertyType DWord -Value 0 -Force | Out-Null

            New-Item -Path "$targetHive\Software\Microsoft\Windows\CurrentVersion\Themes" -Force | Out-Null
            New-Item -Path "$targetHive\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
            New-ItemProperty -Path "$targetHive\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -Path "$targetHive\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -PropertyType DWord -Value 0 -Force | Out-Null

            Write-Host "Tweaks applied to $u (SID $sid)." -ForegroundColor Green
        } catch {
            Write-Host "Failed to write tweak keys to target hive: $_" -ForegroundColor Red
        }

    } finally {
        if ($needUnload) {
            try {
                reg unload "HKU\$($tempName)" 2>$null
                Write-Host "Unloaded temporary hive." -ForegroundColor Green
            } catch {
                Write-Host "Failed to unload temporary hive. You may need to unload it manually." -ForegroundColor Yellow
            }
        }
    }

    break
}

# ---- Install Firefox via winget if available ----
if (Get-Command winget -ErrorAction SilentlyContinue) {
    try {
        Start-Process "winget" -ArgumentList "install Mozilla.Firefox --accept-package-agreements --accept-source-agreements" -Wait
    } catch {
        Write-Host "winget install failed. Skipping." -ForegroundColor Yellow
    }
} else {
    Write-Host "winget not found. Skipping Firefox install." -ForegroundColor Yellow
}

# ---- Create left_to_do.txt on Desktop of the account currently running this script (Admin) ----
$desktopPath = [Environment]::GetFolderPath("Desktop")
$todoFile = Join-Path $desktopPath "left_to_do.txt"
$todoText = @"
hi, thanks for using my script, heres the stuff thats left to do since i didnt get it working :/

- uninstall edge and onedrive

...yeah thats it, thats how much they're pushed onto you, well thanks. bye!
"@
try { Set-Content -Path $todoFile -Value $todoText -Force } catch {}

Write-Host "Done. Restarting now." -ForegroundColor Green
Start-Sleep -Seconds 1
Restart-Computer -Force
