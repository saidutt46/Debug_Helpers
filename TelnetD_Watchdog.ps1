<# 
    Script Name: TelnetD_Watchdog.ps1
    Description: 
        This PowerShell watchdog script continuously monitors all processes named "telnetd.exe" 
        on the system. It calculates the increase in CPU time over a defined sampling interval.
        If any TelnetD process’s CPU usage exceeds the specified threshold (indicating abnormal 
        behavior, e.g. high CPU usage due to being hung), the script will automatically kill that process.
    
    Usage:
        1. Open PowerShell as Administrator.
        2. Navigate to the folder where you have saved this script.
        3. Run the script:
             .\TelnetD_Watchdog.ps1
        4. The script will log output to both the console and to a log file (configured below).
    
    Configuration Parameters:
        - $sampleIntervalSeconds: How often (in seconds) to check the CPU usage.
        - $cpuThresholdIncrease: The CPU time (in seconds) increase over the sampling interval that is considered too high.
        - $logFile: The full path to a log file where events will be recorded.
        
    Expected Output:
        - The script will display log messages with timestamps indicating:
            • The CPU increase for each TelnetD process.
            • A message when a process exceeds the threshold.
            • A message when a process is successfully killed or if an error occurs during termination.
        - The log file will contain the same messages for future reference.
        
    Notes:
        - This script uses the CPU property from Get-Process, which is the total CPU time (in seconds) 
          that the process has used since it started.
        - Ensure the log folder exists (you can change $logFile to a valid path on your system).
        - This script is designed for testing. Thoroughly review and test it in your environment before deploying in production.
#>

# --- Configuration Parameters ---
$sampleIntervalSeconds = 5      # Sampling interval in seconds (adjust as needed)
$cpuThresholdIncrease = 1       # CPU time increase threshold in seconds (e.g., 1 second increase over the sample interval)
$logFile = "C:\Logs\TelnetDWatchdog.log"  # Path to log file (ensure this directory exists)

# --- Create Log Directory If Not Exists ---
$logDir = Split-Path $logFile
if (!(Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory | Out-Null
}

# --- Function to Log Messages ---
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$timestamp - $message"
    Write-Host $line
    Add-Content -Path $logFile -Value $line
}

# --- Initialize the Hashtable for Storing Previous CPU Times ---
$previousCpuTimes = @{}

Log-Message "Starting TelnetD watchdog monitoring..."
Log-Message "Sample Interval: $sampleIntervalSeconds seconds, CPU threshold increase: $cpuThresholdIncrease second(s)."

# --- Main Monitoring Loop ---
while ($true) {
    try {
        # Retrieve all telnetd.exe processes
        $telnetdProcesses = Get-Process telnetd -ErrorAction SilentlyContinue

        # Loop through each TelnetD process
        foreach ($proc in $telnetdProcesses) {
            # Retrieve current total CPU time in seconds
            $currentCpu = $proc.CPU

            # If we have a previous CPU value for this process, calculate the delta
            if ($previousCpuTimes.ContainsKey($proc.Id)) {
                $previousCpu = $previousCpuTimes[$proc.Id]
                $deltaCpu = $currentCpu - $previousCpu

                # Calculate approximate CPU usage percentage for this interval:
                # (deltaCpu / sampleIntervalSeconds) * 100 gives the percent of one CPU core used.
                $cpuUsagePercent = ($deltaCpu / $sampleIntervalSeconds) * 100

                # Log the current CPU usage increase for the process
                Log-Message "Process ID $($proc.Id) increased CPU by $deltaCpu sec (approx. $([math]::Round($cpuUsagePercent,2))% over $sampleIntervalSeconds seconds)."

                # Check if the delta exceeds our threshold
                if ($deltaCpu -ge $cpuThresholdIncrease) {
                    Log-Message "High CPU usage detected in TelnetD process ID $($proc.Id). Initiating termination..."
                    try {
                        Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                        Log-Message "Process ID $($proc.Id) terminated successfully."
                    } catch {
                        Log-Message "Error terminating process ID $($proc.Id): $_"
                    }
                }
            }

            # Update the stored CPU time for this process
            $previousCpuTimes[$proc.Id] = $currentCpu
        }

        # Clean up the hashtable: remove entries for processes that no longer exist
        $currentPids = $telnetdProcesses | ForEach-Object { $_.Id }
        foreach ($key in $previousCpuTimes.Keys) {
            if (-not ($currentPids -contains $key)) {
                $previousCpuTimes.Remove($key) | Out-Null
            }
        }
    } catch {
        Log-Message "Error in monitoring loop: $_"
    }
    
    # Wait for the specified sampling interval before checking again
    Start-Sleep -Seconds $sampleIntervalSeconds
}
