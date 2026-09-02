#requires -Version 5.1

<#
.SYNOPSIS
    Empties the Windows Standby Memory List.

.DESCRIPTION
    Uses NtSetSystemInformation from ntdll.dll to request that Windows
    purge the Standby Memory List.

    The script can:
      - Empty the standby list once.
      - Empty the standby list repeatedly on a timer.
      - Automatically request Administrator privileges.
      - Log operations and errors.
      - Display memory information before and after cleanup.

.PARAMETER Once
    Performs one standby list cleanup and then exits.

.PARAMETER IntervalSeconds
    Performs standby list cleanup repeatedly at the specified interval.

.PARAMETER NoLog
    Disables logging.

.EXAMPLE
    .\RAMStandbyCleanerV3.ps1 -Once

.EXAMPLE
    .\RAMStandbyCleanerV3.ps1 -IntervalSeconds 300

.NOTES
    Administrator privileges are required.
#>

[CmdletBinding()]
param(
    [switch]$Once,

    [ValidateRange(1, 86400)]
    [int]$IntervalSeconds = 300,

    [switch]$NoLog
)


# ============================================================
# GLOBAL SETTINGS
# ============================================================

$ErrorActionPreference = "Stop"

$ScriptName = "RAMStandbyCleanerV3"

# Determine where the script is located.
# If running from a script file, $PSScriptRoot will contain the path.
# If somehow unavailable, fall back to the current directory.

if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $ScriptDirectory = (Get-Location).Path
}
else {
    $ScriptDirectory = $PSScriptRoot
}

$LogFile = Join-Path `
    -Path $ScriptDirectory `
    -ChildPath "StandbyCleaner.log"


# ============================================================
# LOGGING FUNCTION
# ============================================================

function Write-Log {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet(
            "INFO",
            "SUCCESS",
            "WARNING",
            "ERROR"
        )]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $LogLine = "[$Timestamp] [$Level] $Message"

    # Display on screen
    switch ($Level) {

        "SUCCESS" {
            Write-Host $LogLine -ForegroundColor Green
        }

        "WARNING" {
            Write-Host $LogLine -ForegroundColor Yellow
        }

        "ERROR" {
            Write-Host $LogLine -ForegroundColor Red
        }

        default {
            Write-Host $LogLine -ForegroundColor Gray
        }
    }

    # Write to log file
    if (-not $NoLog) {

        try {

            Add-Content `
                -Path $LogFile `
                -Value $LogLine `
                -ErrorAction Stop

        }
        catch {

            Write-Host ""
            Write-Host `
                "WARNING: Could not write to log file." `
                -ForegroundColor Yellow

            Write-Host `
                $_.Exception.Message `
                -ForegroundColor Yellow
        }
    }
}


# ============================================================
# ADMINISTRATOR CHECK
# ============================================================

function Test-IsAdministrator {

    try {

        $CurrentIdentity = `
            [Security.Principal.WindowsIdentity]::GetCurrent()

        $Principal = `
            New-Object Security.Principal.WindowsPrincipal(
                $CurrentIdentity
            )

        return $Principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )

    }
    catch {

        throw `
            "Unable to determine Administrator status. $($_.Exception.Message)"
    }
}


# ============================================================
# RESTART SCRIPT AS ADMINISTRATOR
# ============================================================

function Start-Elevated {

    Write-Host ""
    Write-Host "Administrator privileges are required." `
        -ForegroundColor Yellow

    Write-Host "Requesting Administrator access..." `
        -ForegroundColor Yellow

    Write-Host ""

    try {

        # Build argument list for the new PowerShell process.

        $ArgumentList = @(
            "-NoProfile"
            "-ExecutionPolicy"
            "Bypass"
            "-File"
            "`"$PSCommandPath`""
        )

        # Preserve -Once
        if ($Once) {

            $ArgumentList += "-Once"
        }

        # Preserve timer interval
        if (-not $Once) {

            $ArgumentList += "-IntervalSeconds"
            $ArgumentList += $IntervalSeconds
        }

        # Preserve logging setting
        if ($NoLog) {

            $ArgumentList += "-NoLog"
        }


        Write-Host "Starting elevated PowerShell process..." `
            -ForegroundColor Gray

        Start-Process `
            -FilePath "powershell.exe" `
            -ArgumentList $ArgumentList `
            -Verb RunAs `
            -ErrorAction Stop

        # The non-elevated copy can now exit.
        exit 0

    }
    catch {

        Write-Host ""
        Write-Host "FAILED TO REQUEST ADMINISTRATOR ACCESS" `
            -ForegroundColor Red

        Write-Host ""
        Write-Host $_.Exception.Message `
            -ForegroundColor Red

        Write-Host ""

        Read-Host `
            "Press Enter to close"

        exit 1
    }
}


# ============================================================
# CHECK ADMINISTRATOR PRIVILEGES
# ============================================================

try {

    if (-not (Test-IsAdministrator)) {

        Start-Elevated
    }

}
catch {

    Write-Host ""
    Write-Host "ADMINISTRATOR CHECK FAILED" `
        -ForegroundColor Red

    Write-Host ""
    Write-Host $_.Exception.Message `
        -ForegroundColor Red

    Write-Host ""

    Read-Host `
        "Press Enter to close"

    exit 1
}


# ============================================================
# WINDOWS API DEFINITION
# ============================================================

try {

    # Only add the C# type if it doesn't already exist.

    if (-not ("StandbyMemory.NativeMethods" -as [type])) {

    Add-Type -TypeDefinition @"

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace StandbyMemory
{
    public static class NativeMethods
    {
        // SystemMemoryListInformation
        private const int SystemMemoryListInformation = 80;

        // MemoryPurgeStandbyList
        private const int MemoryPurgeStandbyList = 4;

        // Required privilege
        private const string SeProfileSingleProcessPrivilege =
            "SeProfileSingleProcessPrivilege";

        private const uint TOKEN_QUERY = 0x0008;

        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;

        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        [DllImport(
            "advapi32.dll",
            SetLastError = true
        )]
        private static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle
        );

        [DllImport(
            "advapi32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true
        )]
        private static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            out LUID lpLuid
        );

        [DllImport(
            "advapi32.dll",
            SetLastError = true
        )]
        private static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            uint BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength
        );

        [DllImport(
            "kernel32.dll",
            SetLastError = true
        )]
        private static extern bool CloseHandle(
            IntPtr hObject
        );

        [DllImport(
            "ntdll.dll",
            SetLastError = false
        )]
        private static extern int NtSetSystemInformation(
            int SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength
        );


        public static void EnableRequiredPrivilege()
        {
            IntPtr TokenHandle = IntPtr.Zero;

            try
            {
                IntPtr ProcessHandle =
                    System.Diagnostics.Process.GetCurrentProcess().Handle;

                if (!OpenProcessToken(
                    ProcessHandle,
                    TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                    out TokenHandle))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "OpenProcessToken failed."
                    );
                }


                LUID Luid;

                if (!LookupPrivilegeValue(
                    null,
                    SeProfileSingleProcessPrivilege,
                    out Luid))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "LookupPrivilegeValue failed."
                    );
                }


                TOKEN_PRIVILEGES TokenPrivileges =
                    new TOKEN_PRIVILEGES();

                TokenPrivileges.PrivilegeCount = 1;

                TokenPrivileges.Privileges =
                    new LUID_AND_ATTRIBUTES();

                TokenPrivileges.Privileges.Luid = Luid;

                TokenPrivileges.Privileges.Attributes =
                    SE_PRIVILEGE_ENABLED;


                if (!AdjustTokenPrivileges(
                    TokenHandle,
                    false,
                    ref TokenPrivileges,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "AdjustTokenPrivileges failed."
                    );
                }


                int LastError =
                    Marshal.GetLastWin32Error();

                // ERROR_NOT_ALL_ASSIGNED = 1300
                if (LastError == 1300)
                {
                    throw new InvalidOperationException(
                        "The SeProfileSingleProcessPrivilege privilege " +
                        "could not be assigned to this process."
                    );
                }
            }
            finally
            {
                if (TokenHandle != IntPtr.Zero)
                {
                    CloseHandle(TokenHandle);
                }
            }
        }


        public static int EmptyStandbyList()
        {
            IntPtr Buffer = IntPtr.Zero;

            try
            {
                Buffer =
                    Marshal.AllocHGlobal(sizeof(int));

                Marshal.WriteInt32(
                    Buffer,
                    MemoryPurgeStandbyList
                );

                return NtSetSystemInformation(
                    SystemMemoryListInformation,
                    Buffer,
                    sizeof(int)
                );
            }
            finally
            {
                if (Buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(Buffer);
                }
            }
        }
    }
}

"@ -ErrorAction Stop
}

}
catch {

    Write-Host ""
    Write-Host "FAILED TO LOAD WINDOWS MEMORY API" `
        -ForegroundColor Red

    Write-Host ""
    Write-Host $_.Exception.Message `
        -ForegroundColor Red

    Write-Host ""

    Read-Host `
        "Press Enter to close"

    exit 1
}


# ============================================================
# MEMORY INFORMATION
# ============================================================

function Get-MemoryInformation {
    try {
        $memory = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop

        $totalBytes = [double]$memory.TotalVisibleMemorySize * 1KB
        $freeBytes  = [double]$memory.FreePhysicalMemory * 1KB
        $usedBytes  = $totalBytes - $freeBytes

        # Query standby-cache counters through CIM/WMI instead of Get-Counter.
        $cache = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop

        $normalBytes  = [double]$cache.StandbyCacheNormalPriorityBytes
        $reserveBytes = [double]$cache.StandbyCacheReserveBytes
        $coreBytes    = [double]$cache.StandbyCacheCoreBytes

        $standbyBytes = $normalBytes + $reserveBytes + $coreBytes

        return [PSCustomObject]@{
            TotalBytes = $totalBytes
            UsedBytes  = $usedBytes
            FreeBytes  = $freeBytes

            TotalGB = $totalBytes / 1GB
            UsedGB  = $usedBytes / 1GB
            FreeGB  = $freeBytes / 1GB

            StandbyNormalGB  = $normalBytes / 1GB
            StandbyReserveGB = $reserveBytes / 1GB
            StandbyCoreGB    = $coreBytes / 1GB

            StandbyGB = $standbyBytes / 1GB
}
    }
    catch {
        Write-Log "[WARNING] Could not retrieve memory information: $($_.Exception.Message)"
        return $null
    }
}
# ============================================================
# EMPTY STANDBY LIST
# ============================================================

function Invoke-EmptyStandbyList {

    try {

        Write-Host ""
        Write-Host "============================================" `
            -ForegroundColor Cyan

        Write-Host "       STANDBY MEMORY CLEANUP" `
            -ForegroundColor Cyan

        Write-Host "============================================" `
            -ForegroundColor Cyan


        # ----------------------------------------------------
        # GET MEMORY BEFORE CLEANUP
        # ----------------------------------------------------

        $Before = Get-MemoryInformation


        if ($null -ne $Before) {

            Write-Host ""

            Write-Host "Memory before cleanup:" `
                -ForegroundColor Gray

            Write-Host `
                ("  Total Memory       : {0:N2} GB" -f $Before.TotalGB)

            Write-Host `
                ("  Used Memory        : {0:N2} GB" -f $Before.UsedGB)

            Write-Host `
                ("  Free Memory        : {0:N2} GB" -f $Before.FreeGB)

            Write-Host `
                ("  Standby Cache      : {0:N2} GB" -f $Before.StandbyGB)

            Write-Host `
                ("    Normal Priority  : {0:N2} GB" -f $Before.StandbyNormalGB)

            Write-Host `
                ("    Reserve          : {0:N2} GB" -f $Before.StandbyReserveGB)

            Write-Host `
                ("    Core             : {0:N2} GB" -f $Before.StandbyCoreGB)
        }


        # ----------------------------------------------------
        # CALL WINDOWS API
        # ----------------------------------------------------

        Write-Host ""

        Write-Host `
            "Requesting Windows to purge the Standby List..." `
            -ForegroundColor Yellow

Write-Host ""
Write-Host "Enabling required Windows privilege..." `
    -ForegroundColor Yellow

[StandbyMemory.NativeMethods]::EnableRequiredPrivilege()

Write-Host `
    "Required privilege enabled successfully." `
    -ForegroundColor Green

Write-Host ""

$Status = `
    [StandbyMemory.NativeMethods]::EmptyStandbyList()

        # ----------------------------------------------------
        # SAFELY CONVERT NTSTATUS TO HEX
        # ----------------------------------------------------

        $StatusBytes = `
            [BitConverter]::GetBytes(
                [int]$Status
            )

        $UnsignedStatus = `
            [BitConverter]::ToUInt32(
                $StatusBytes,
                0
            )

        $HexStatus = `
            "0x{0:X8}" -f $UnsignedStatus


        # ----------------------------------------------------
        # CHECK NTSTATUS
        # ----------------------------------------------------

        if ($Status -eq 0) {

            Write-Log `
                "Standby list purge completed successfully. NTSTATUS: $HexStatus" `
                -Level "SUCCESS"

        }
        else {

            Write-Log `
                "Windows API returned NTSTATUS: $HexStatus" `
                -Level "ERROR"

            Write-Host ""

            Write-Host `
                "The Windows API did not report STATUS_SUCCESS." `
                -ForegroundColor Red

            Write-Host `
                "NTSTATUS: $HexStatus" `
                -ForegroundColor Red

            Write-Host ""

            # Do NOT throw here.
            # This allows the script to continue and report
            # the memory information after the API call.
        }


        # ----------------------------------------------------
        # WAIT BRIEFLY
        # ----------------------------------------------------

        Start-Sleep `
            -Milliseconds 1500


        # ----------------------------------------------------
        # GET MEMORY AFTER CLEANUP
        # ----------------------------------------------------

        $After = Get-MemoryInformation


        if ($null -ne $After) {

            Write-Host ""

            Write-Host "Memory after cleanup:" `
                -ForegroundColor Gray

            Write-Host `
                ("  Total Memory       : {0:N2} GB" -f $After.TotalGB)

            Write-Host `
                ("  Used Memory        : {0:N2} GB" -f $After.UsedGB)

            Write-Host `
                ("  Free Memory        : {0:N2} GB" -f $After.FreeGB)

            Write-Host `
                ("  Standby Cache      : {0:N2} GB" -f $After.StandbyGB)

            Write-Host `
                ("    Normal Priority  : {0:N2} GB" -f $After.StandbyNormalGB)

            Write-Host `
                ("    Reserve          : {0:N2} GB" -f $After.StandbyReserveGB)

            Write-Host `
                ("    Core             : {0:N2} GB" -f $After.StandbyCoreGB)


            if ($null -ne $Before) {

                $FreeMemoryChange = `
                    $After.FreeGB - $Before.FreeGB

                Write-Host ""

                if ($FreeMemoryChange -gt 0) {

                    Write-Host `
                        ("Free physical memory increased by {0:N2} GB." `
                        -f $FreeMemoryChange) `
                        -ForegroundColor Green

                }
                elseif ($FreeMemoryChange -lt 0) {

                    Write-Host `
                        ("Free physical memory decreased by {0:N2} GB." `
                        -f [Math]::Abs($FreeMemoryChange)) `
                        -ForegroundColor Yellow

                }
                else {

                    Write-Host `
                        "No measurable change in free physical memory." `
                        -ForegroundColor Gray
                }


                $StandbyMemoryChange = `
                    $After.StandbyGB - $Before.StandbyGB

                Write-Host ""

                if ($StandbyMemoryChange -lt 0) {

                    Write-Host `
                        ("Standby Cache decreased by {0:N2} GB." `
                        -f [Math]::Abs($StandbyMemoryChange)) `
                        -ForegroundColor Green
                }
                elseif ($StandbyMemoryChange -gt 0) {

                    Write-Host `
                        ("Standby Cache increased by {0:N2} GB." `
                        -f $StandbyMemoryChange) `
                        -ForegroundColor Yellow
                }
                else {

                    Write-Host `
                        "Standby Cache showed no measurable change." `
                        -ForegroundColor Gray
                }

            }
        }


        Write-Host ""

        Write-Host "============================================" `
            -ForegroundColor Cyan

        Write-Host ""

    }
    catch {

        Write-Log `
            "Unexpected error during standby list cleanup: $($_.Exception.Message)" `
            -Level "ERROR"

        Write-Host ""

        Write-Host "FULL ERROR DETAILS:" `
            -ForegroundColor Red

        Write-Host $_ `
            -ForegroundColor Red

        Write-Host ""
    }
}
# ============================================================
# MAIN PROGRAM
# ============================================================

try {

    Clear-Host


    Write-Host ""
    Write-Host "============================================" `
        -ForegroundColor Cyan

    Write-Host "       WINDOWS STANDBY MEMORY CLEANER" `
        -ForegroundColor Cyan

    Write-Host "============================================" `
        -ForegroundColor Cyan

    Write-Host ""


    Write-Log `
        "StandbyCleaner started."

    Write-Log `
        "Computer: $env:COMPUTERNAME"

    Write-Log `
        "PowerShell Version: $($PSVersionTable.PSVersion)"

    Write-Log `
        "Running as Administrator."

    Write-Log `
        "Script Directory: $ScriptDirectory"


    # ========================================================
    # ONE-TIME MODE
    # ========================================================

    if ($Once) {

        Write-Log `
            "Running in one-time cleanup mode."

        Invoke-EmptyStandbyList

        Write-Host ""

        Write-Host "One-time cleanup completed." `
            -ForegroundColor Green

        Write-Host ""

        Write-Host `
            "Press Enter to close this window..." `
            -ForegroundColor Yellow

        Read-Host

        exit 0
    }


    # ========================================================
    # TIMER MODE
    # ========================================================

    Write-Log `
        "Running in timer mode."

    Write-Log `
        "Cleanup interval: $IntervalSeconds seconds."


    Write-Host ""

    Write-Host `
        "The Standby List will be emptied every $IntervalSeconds seconds." `
        -ForegroundColor Green

    Write-Host ""

    Write-Host `
        "Press Ctrl+C to stop the program." `
        -ForegroundColor Yellow

    Write-Host ""


    # ========================================================
    # TIMER LOOP
    # ========================================================

    while ($true) {

        try {

            Invoke-EmptyStandbyList

        }
        catch {

            Write-Host ""

            Write-Host `
                "ERROR DURING CLEANUP." `
                -ForegroundColor Red

            Write-Host ""

            Write-Host `
                $_.Exception.Message `
                -ForegroundColor Red

            Write-Log `
                "Cleanup iteration failed: $($_.Exception.Message)" `
                -Level "ERROR"

            Write-Host ""

            Write-Host `
                "The program will continue running." `
                -ForegroundColor Yellow
        }


        $NextRun = `
            (Get-Date).AddSeconds(
                $IntervalSeconds
            )


        Write-Host ""

        Write-Host `
            ("Next cleanup: {0}" `
            -f $NextRun.ToString("yyyy-MM-dd HH:mm:ss")) `
            -ForegroundColor Cyan

        Write-Host `
            ("Waiting {0} seconds..." `
            -f $IntervalSeconds) `
            -ForegroundColor Gray

        Write-Host ""


        Start-Sleep `
            -Seconds $IntervalSeconds
    }

}
catch {

    # ========================================================
    # TOP-LEVEL ERROR HANDLER
    # ========================================================

    Write-Host ""
    Write-Host "============================================" `
        -ForegroundColor Red

    Write-Host "       FATAL SCRIPT ERROR" `
        -ForegroundColor Red

    Write-Host "============================================" `
        -ForegroundColor Red

    Write-Host ""

    Write-Host "Error Message:" `
        -ForegroundColor Yellow

    Write-Host `
        $_.Exception.Message `
        -ForegroundColor Red

    Write-Host ""

    Write-Host "Full Error:" `
        -ForegroundColor Yellow

    Write-Host `
        $_ `
        -ForegroundColor Red


    if (-not $NoLog) {

        try {

            $Timestamp = `
                Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            Add-Content `
                -Path $LogFile `
                -Value "[$Timestamp] [FATAL] $($_)" `
                -ErrorAction SilentlyContinue

        }
        catch {
            # Ignore logging failure.
        }
    }


    Write-Host ""

    Write-Host `
        "The script encountered a fatal error." `
        -ForegroundColor Red

    Write-Host ""

    Read-Host `
        "Press Enter to close"

    exit 1
}

finally {

    # This block executes when the script exits normally
    # or when an exception is handled.

    Write-Log `
        "StandbyCleaner execution ended." `
        -Level "INFO"
}
