# ================================================================
# USB EVIDENCE COLLECTOR v2.0
# Academic Forensics Project — Collect evidence FROM USB devices
# Usage: Run as Administrator in PowerShell
# ================================================================

param(
    [switch]$Consent,
    [string]$OutputDir = ".\usb-evidence",
    [switch]$Help
)

# ── Banner ─────────────────────────────────────────────────────────
function Show-Banner {
    Write-Host ""
    Write-Host "  ██╗   ██╗███████╗██████╗    ███████╗██╗   ██╗██╗██████╗ " -ForegroundColor Cyan
    Write-Host "  ██║   ██║██╔════╝██╔══██╗   ██╔════╝██║   ██║██║██╔══██╗" -ForegroundColor Cyan
    Write-Host "  ██║   ██║███████╗██████╔╝   █████╗  ██║   ██║██║██║  ██║" -ForegroundColor Cyan
    Write-Host "  ██║   ██║╚════██║██╔══██╗   ██╔══╝  ╚██╗ ██╔╝██║██║  ██║" -ForegroundColor Cyan
    Write-Host "  ╚██████╔╝███████║██████╔╝   ███████╗ ╚████╔╝ ██║██████╔╝" -ForegroundColor Cyan
    Write-Host "   ╚═════╝ ╚══════╝╚═════╝    ╚══════╝  ╚═══╝  ╚═╝╚═════╝ " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  USB FORENSIC EVIDENCE COLLECTOR  v2.0" -ForegroundColor White
    Write-Host "  Academic Project — Authorised Use Only" -ForegroundColor Yellow
    Write-Host ""
}

if ($Help) {
    Show-Banner
    Write-Host "  USAGE:" -ForegroundColor Cyan
    Write-Host "    .\collect-usb-forensics.ps1 -Consent [-OutputDir <path>]"
    Write-Host ""
    Write-Host "  OPTIONS:"
    Write-Host "    -Consent      Required: explicit consent to collect evidence"
    Write-Host "    -OutputDir    Where to save reports (default: .\usb-evidence)"
    Write-Host "    -Help         Show this help"
    Write-Host ""
    Write-Host "  EXAMPLE:"
    Write-Host "    .\collect-usb-forensics.ps1 -Consent -OutputDir C:\forensics\usb" -ForegroundColor Green
    Write-Host ""
    exit 0
}

# ── Require consent ────────────────────────────────────────────────
if (-not $Consent) {
    Write-Host ""
    Write-Host "  ╔═════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║       CONSENT REQUIRED — CANNOT PROCEED                 ║" -ForegroundColor Red
    Write-Host "  ╚═════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "  This script collects forensic evidence from USB devices." -ForegroundColor Yellow
    Write-Host "  Only use it on devices you own or have written authorisation to examine." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Re-run with: .\collect-usb-forensics.ps1 -Consent" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

Show-Banner
Write-Host "  [✔] Consent confirmed" -ForegroundColor Green
Write-Host ""

# ── Setup output ───────────────────────────────────────────────────
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$SessionDir = Join-Path $OutputDir "session_$Timestamp"
New-Item -ItemType Directory -Path $SessionDir -Force | Out-Null
$ReportPath = Join-Path $SessionDir "usb_evidence_$Timestamp.json"
$LogPath    = Join-Path $SessionDir "collection.log"

function Log($msg) {
    "[$((Get-Date -Format 'HH:mm:ss'))] $msg" | Out-File -Append -FilePath $LogPath
}
function Step($msg) { Write-Host "  ▸ $msg" -ForegroundColor Cyan;  Log "STEP: $msg" }
function Ok($msg)   { Write-Host "  ✔ $msg" -ForegroundColor Green; Log "OK:   $msg" }
function Warn($msg) { Write-Host "  ⚠ $msg" -ForegroundColor Yellow;Log "WARN: $msg" }

Log "=== USB EVIDENCE COLLECTION STARTED ==="
Log "Operator: $env:USERNAME | Host: $env:COMPUTERNAME | Timestamp: $Timestamp"

# ── Phase 1: Enumerate USB devices ────────────────────────────────
Write-Host "  ── Phase 1: USB Device Enumeration ─────────────────────" -ForegroundColor White

Step "Detecting USB storage devices..."
$UsbDrives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }

if ($UsbDrives.Count -eq 0) {
    Warn "No USB drives detected. Insert a USB drive and re-run."
    Log "No USB drives found — exiting."
    exit 0
}
Ok "$($UsbDrives.Count) USB drive(s) detected"

# ── Phase 2: Device metadata ───────────────────────────────────────
Write-Host ""
Write-Host "  ── Phase 2: Device Metadata Collection ─────────────────" -ForegroundColor White

Step "Collecting USB device registry history..."
$UsbHistory = @()
try {
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
    if (Test-Path $RegPath) {
        $Devices = Get-ChildItem $RegPath -ErrorAction SilentlyContinue
        foreach ($Device in $Devices) {
            $DeviceInstances = Get-ChildItem $Device.PSPath -ErrorAction SilentlyContinue
            foreach ($Instance in $DeviceInstances) {
                $Props = Get-ItemProperty $Instance.PSPath -ErrorAction SilentlyContinue
                $UsbHistory += @{
                    device_class    = $Device.PSChildName
                    instance_id     = $Instance.PSChildName
                    friendly_name   = $Props.FriendlyName
                    manufacturer    = $Props.Mfg
                    device_desc     = $Props.DeviceDesc
                    driver          = $Props.Driver
                }
            }
        }
        Ok "$($UsbHistory.Count) historical USB device(s) found in registry"
    } else {
        Warn "USBSTOR registry key not accessible"
    }
} catch {
    Warn "Registry read failed: $_"
}

# ── Phase 3: Per-drive evidence collection ─────────────────────────
Write-Host ""
Write-Host "  ── Phase 3: Drive Evidence Collection ──────────────────" -ForegroundColor White

$AllDriveEvidence = @()

foreach ($Drive in $UsbDrives) {
    $Letter = $Drive.DeviceID
    Write-Host ""
    Write-Host "  ┌─ Drive: $Letter ──────────────────────────────────────────" -ForegroundColor Blue

    $DriveEvidence = @{
        drive_letter      = $Letter
        volume_name       = $Drive.VolumeName
        file_system       = $Drive.FileSystem
        size_gb           = [math]::Round($Drive.Size / 1GB, 2)
        free_space_gb     = [math]::Round($Drive.FreeSpace / 1GB, 2)
        serial_number     = $Drive.VolumeSerialNumber
        root_files        = @()
        recent_files      = @()
        executable_files  = @()
        autorun_present   = $false
        autorun_content   = $null
        suspicious_items  = @()
        file_count        = 0
        directory_count   = 0
    }

    # Root directory listing
    Step "Listing root contents of $Letter..."
    try {
        $RootItems = Get-ChildItem -Path "$Letter\" -Force -ErrorAction SilentlyContinue
        $DriveEvidence.root_files = $RootItems | Select-Object -First 50 | ForEach-Object {
            @{
                name          = $_.Name
                type          = if ($_.PSIsContainer) {"directory"} else {"file"}
                size_bytes    = if (-not $_.PSIsContainer) { $_.Length } else { 0 }
                created       = $_.CreationTime.ToString("o")
                modified      = $_.LastWriteTime.ToString("o")
                hidden        = ($_.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0
                readonly      = ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0
            }
        }
        Ok "$($RootItems.Count) root items found"
    } catch {
        Warn "Could not read root of $Letter : $_"
    }

    # autorun.inf detection (forensic finding, not creation)
    Step "Checking for autorun.inf..."
    $AutorunPath = "$Letter\autorun.inf"
    if (Test-Path $AutorunPath) {
        $DriveEvidence.autorun_present = $true
        try {
            $DriveEvidence.autorun_content = Get-Content $AutorunPath -Raw -Encoding ASCII -ErrorAction Stop
            Warn "autorun.inf FOUND — content captured as evidence"
        } catch {
            $DriveEvidence.autorun_content = "ERROR READING: $_"
        }
        $DriveEvidence.suspicious_items += "autorun.inf present"
    } else {
        Ok "No autorun.inf"
    }

    # Recently modified files (last 7 days)
    Step "Finding recently modified files (last 7 days)..."
    try {
        $Recent = Get-ChildItem -Path "$Letter\" -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
            Select-Object -First 50
        $DriveEvidence.recent_files = $Recent | ForEach-Object {
            @{
                path     = $_.FullName.Replace($Letter, "")
                size     = $_.Length
                modified = $_.LastWriteTime.ToString("o")
                hidden   = ($_.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0
            }
        }
        Ok "$($Recent.Count) recently modified file(s)"
    } catch {
        Warn "Recent file scan failed: $_"
    }

    # Executable files (forensically significant)
    Step "Scanning for executable files..."
    try {
        $Executables = Get-ChildItem -Path "$Letter\" -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match "^\.(exe|dll|sh|bat|cmd|ps1|vbs|py|rb|elf|com|scr|jar)$" } |
            Select-Object -First 30
        $DriveEvidence.executable_files = $Executables | ForEach-Object {
            @{
                path      = $_.FullName.Replace($Letter, "")
                extension = $_.Extension
                size      = $_.Length
                modified  = $_.LastWriteTime.ToString("o")
            }
        }
        if ($Executables.Count -gt 0) {
            Warn "$($Executables.Count) executable(s) found"
            $DriveEvidence.suspicious_items += "$($Executables.Count) executables on USB"
        } else {
            Ok "No executables found"
        }
    } catch {
        Warn "Executable scan failed: $_"
    }

    # File / dir counts
    Step "Counting files and directories..."
    try {
        $AllItems = Get-ChildItem -Path "$Letter\" -Recurse -Force -ErrorAction SilentlyContinue
        $DriveEvidence.file_count      = ($AllItems | Where-Object { -not $_.PSIsContainer }).Count
        $DriveEvidence.directory_count = ($AllItems | Where-Object { $_.PSIsContainer }).Count
        Ok "Files: $($DriveEvidence.file_count) | Directories: $($DriveEvidence.directory_count)"
    } catch {
        Warn "Count failed: $_"
    }

    $AllDriveEvidence += $DriveEvidence
}

# ── Phase 4: Windows USB event log ────────────────────────────────
Write-Host ""
Write-Host "  ── Phase 4: System Event Log (USB Connections) ─────────" -ForegroundColor White

Step "Reading USB connection events from System log..."
$UsbEvents = @()
try {
    $Events = Get-WinEvent -LogName System -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in @(20001, 20003, 43, 400) } |
        Select-Object -First 20
    $UsbEvents = $Events | ForEach-Object {
        @{
            event_id    = $_.Id
            time        = $_.TimeCreated.ToString("o")
            message     = $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))
            provider    = $_.ProviderName
        }
    }
    Ok "$($UsbEvents.Count) USB-related event(s) found"
} catch {
    Warn "Event log read failed (may need admin): $_"
}

# ── Phase 5: Build JSON report ─────────────────────────────────────
Write-Host ""
Write-Host "  ── Phase 5: Saving Evidence Report ─────────────────────" -ForegroundColor White

Step "Writing JSON evidence report..."

$Report = @{
    meta = @{
        tool           = "USB Forensic Evidence Collector"
        version        = "2.0"
        timestamp      = (Get-Date -Format "o")
        operator       = $env:USERNAME
        hostname       = $env:COMPUTERNAME
        consent        = $true
        academic_project = $true
        purpose        = "Collect forensic evidence from USB devices — not modification"
    }
    usb_history        = $UsbHistory
    drives             = $AllDriveEvidence
    system_usb_events  = $UsbEvents
    summary = @{
        drives_examined = $AllDriveEvidence.Count
        total_files     = ($AllDriveEvidence | Measure-Object -Property file_count -Sum).Sum
        suspicious_items = ($AllDriveEvidence | ForEach-Object { $_.suspicious_items } | Where-Object {$_}).Count
    }
}

$Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
Ok "Report saved: $ReportPath"

# ── Summary ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔═════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║           COLLECTION COMPLETE                           ║" -ForegroundColor Cyan
Write-Host "  ╚═════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Drives examined : $($AllDriveEvidence.Count)" -ForegroundColor White
Write-Host "  USB history     : $($UsbHistory.Count) historical devices" -ForegroundColor White
Write-Host "  Event logs      : $($UsbEvents.Count) USB connection events" -ForegroundColor White
$Suspicious = ($AllDriveEvidence | ForEach-Object { $_.suspicious_items } | Where-Object { $_ }).Count
if ($Suspicious -gt 0) {
    Write-Host "  Suspicious items: $Suspicious" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  Report : $ReportPath" -ForegroundColor Green
Write-Host "  Log    : $LogPath" -ForegroundColor Green
Write-Host ""
Log "=== COLLECTION COMPLETE ==="
