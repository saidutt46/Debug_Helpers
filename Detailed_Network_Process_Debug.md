# Network and Process Debugging Guide

<div align="center">
  
![Network Debugging Banner](https://raw.githubusercontent.com/gist/LukeMacAulay/32c93a0b7f9bd045b4b08336c97f0300/raw/9a3930b2fd2eda2f33251732a5b639398d4f7c66/terminal_banner.svg)

**A comprehensive reference for software engineers to diagnose network connections, process issues, and system performance**

</div>

<details>
<summary>📋 Table of Contents</summary>

- [Process Monitoring](#process-monitoring)
  - [Windows Command Prompt](#windows-command-prompt)
  - [PowerShell](#powershell)
  - [Identifying Orphaned Processes](#identifying-orphaned-processes)
- [Network Analysis](#network-analysis)
  - [View Active Connections](#view-active-connections)
  - [Filter and Analyze Network States](#filter-and-analyze-network-states)
  - [Map Ports to Processes](#map-ports-to-processes)
- [CPU and Resource Monitoring](#cpu-and-resource-monitoring)
  - [Overall System Load](#overall-system-load)
  - [Per-Process Resource Usage](#per-process-resource-usage)
  - [Advanced Performance Metrics](#advanced-performance-metrics)
- [Cross-Platform Commands](#cross-platform-commands)
  - [Linux Commands](#linux-commands)
  - [macOS Commands](#macos-commands)
- [Process Termination and Cleanup](#process-termination-and-cleanup)
  - [Windows](#windows)
  - [Linux/macOS](#linuxmacos)
  - [Automation Scripts](#automation-scripts)
- [Modern Debugging Tools](#modern-debugging-tools)
  - [Windows Admin Center](#windows-admin-center)
  - [PowerShell Core Modules](#powershell-core-modules)
  - [Docker and Container Tools](#docker-and-container-tools)
- [Troubleshooting Common Scenarios](#troubleshooting-common-scenarios)
  - [Port Conflicts](#port-conflicts)
  - [High CPU Usage](#high-cpu-usage)
  - [Memory Leaks](#memory-leaks)
  - [Network Connectivity Issues](#network-connectivity-issues)
- [Quick Reference Cheat Sheet](#quick-reference-cheat-sheet)

</details>

## Process Monitoring

### Windows Command Prompt

```cmd
# List all running processes
tasklist

# Find specific process by name
tasklist /FI "IMAGENAME eq process.exe"

# Verbose process information (CPU time, window title, etc.)
tasklist /V

# Filter multiple process attributes
wmic process where "name='process.exe'" get ProcessId,ParentProcessId,CommandLine
```

> **💡 Tip:** The `/FI` (filter) option supports wildcards, e.g., `tasklist /FI "IMAGENAME eq *chrome*"` finds all Chrome processes.

### PowerShell

```powershell
# List all running processes
Get-Process

# Find specific process by name
Get-Process -Name "process"

# Detailed process info
Get-Process -Name "process" | Format-List *

# Custom output format
Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet | Sort-Object -Property CPU -Descending

# Get process command line
Get-WmiObject Win32_Process -Filter "Name='process.exe'" | Select-Object ProcessId, CommandLine
```

> **💡 Tip:** PowerShell provides more filtering options and can export results: `Get-Process | Export-Csv -Path processes.csv`

### Identifying Orphaned Processes

Orphaned processes have no parent or their parent has terminated:

```powershell
# PowerShell - List all processes with their parent process ID
Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine |
Sort-Object -Property ParentProcessId

# Find orphaned processes (where parent doesn't exist)
$processes = Get-WmiObject Win32_Process
$processes | Where-Object { 
    $_.ParentProcessId -ne 0 -and 
    -not ($processes | Where-Object { $_.ProcessId -eq $_.ParentProcessId }) 
} | Select ProcessId, ParentProcessId, Name
```

## Network Analysis

### View Active Connections

```cmd
# Display all connections and listening ports
netstat -ano

# Display connection statistics periodically (refresh every 5 seconds)
netstat -ano 5
```

```powershell
# PowerShell equivalent with better formatting
Get-NetTCPConnection | Format-Table -AutoSize
```

### Filter and Analyze Network States

```cmd
# Filter connections by port
netstat -ano | findstr ":80"

# Filter by connection state
netstat -ano | findstr "ESTABLISHED"
netstat -ano | findstr "LISTENING"
netstat -ano | findstr "TIME_WAIT"
netstat -ano | findstr "CLOSE_WAIT"
```

> **🔍 Connection States Explained:**
> - **LISTENING**: Process waiting for incoming connections
> - **ESTABLISHED**: Active connection between two endpoints
> - **CLOSE_WAIT**: Remote side closed connection, local side waiting to close
> - **TIME_WAIT**: Local side closed, waiting to ensure all packets delivered 
> - **SYN_SENT**: Connection attempt in progress
> - **FIN_WAIT**: Connection shutdown in progress

### Map Ports to Processes

```cmd
# Show executables using network connections (requires admin)
netstat -bano

# Filter by PID and get process name
for /f "tokens=5" %i in ('netstat -ano ^| findstr ":80"') do @echo %i | findstr /v "[a-z]" | tasklist /FI "PID eq %i"
```

```powershell
# PowerShell - Map TCP connections to process names
Get-NetTCPConnection | 
  Select-Object LocalPort, RemoteAddress, State, OwningProcess, @{
    Name="ProcessName"; Expression={(Get-Process -Id $_.OwningProcess).Name}
  } | Format-Table -AutoSize
```

## CPU and Resource Monitoring

### Overall System Load

```cmd
# Check CPU usage (cmd)
wmic cpu get loadpercentage

# Check available memory (cmd)
wmic OS get FreePhysicalMemory,TotalVisibleMemorySize
```

```powershell
# PowerShell - Overall CPU load
Get-WmiObject win32_processor | Measure-Object -property LoadPercentage -Average | Select Average

# PowerShell - Memory usage
Get-WmiObject win32_operatingsystem | Select-Object @{
    Name="MemoryUsage(%)";
    Expression={"{0:N2}" -f ((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) / $_.TotalVisibleMemorySize) * 100)}
}
```

### Per-Process Resource Usage

```cmd
# Find high CPU processes (cmd)
tasklist /FI "CPUTIME gt 00:01:00"

# Sort by memory usage (WMIC)
wmic process get name,workingsetsize /format:list | sort
```

```powershell
# Find top 10 CPU-consuming processes
Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 10 ProcessName, CPU, Id

# Find top 10 memory-consuming processes (MB)
Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 10 ProcessName, @{
    Name="Memory(MB)"; Expression={"{0:N2}" -f ($_.WS / 1MB)}
}, Id
```

### Advanced Performance Metrics

```powershell
# Real-time CPU usage percentages by process (PowerShell)
Get-Counter '\Process(*)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | 
  Where-Object { $_.InstanceName -ne "_total" -and $_.InstanceName -ne "idle" } | 
  Sort-Object -Property CookedValue -Descending | Select-Object -First 10 |
  Format-Table InstanceName, @{Name="CPU(%)"; Expression={"{0:N2}" -f ($_.CookedValue/100)}}

# Monitor disk I/O by process
Get-WmiObject Win32_PerfFormattedData_PerfProc_Process | 
  Select-Object Name, IOReadBytesPersec, IOWriteBytesPersec |
  Sort-Object -Property IOReadBytesPersec -Descending | 
  Select-Object -First 10
```

## Cross-Platform Commands

### Linux Commands

```bash
# Process list (similar to tasklist)
ps aux

# Find specific process
ps aux | grep process_name

# Network connections (similar to netstat)
ss -tuln
# Or traditional
netstat -tuln

# List processes by resource usage
top
# Interactive resource viewer
htop

# Display opened files and network connections
lsof -i :port
lsof -p PID

# Trace system calls
strace -p PID
```

### macOS Commands

```bash
# Process monitoring
ps aux | grep process_name
top -o cpu  # Sort by CPU
Activity Monitor (GUI)

# Network connections
netstat -anv | grep LISTEN
lsof -i :port

# System statistics
vm_stat  # Memory stats
iostat   # Disk stats
```

## Process Termination and Cleanup

### Windows

```cmd
# Kill process by PID (cmd)
taskkill /PID pid /F

# Kill process by name (cmd)
taskkill /IM process.exe /F

# Kill process tree (including children)
taskkill /PID pid /F /T
```

```powershell
# Kill process by name (PowerShell)
Stop-Process -Name "process" -Force

# Kill process by ID (PowerShell)
Stop-Process -Id pid -Force

# Kill all processes matching a pattern
Get-Process | Where-Object {$_.ProcessName -like "*chrome*"} | Stop-Process -Force
```

### Linux/macOS

```bash
# Kill by PID
kill -9 PID

# Kill by name
pkill process_name
killall process_name

# Kill based on resource usage 
# (kills most CPU-intensive process)
kill -9 $(ps aux | sort -nrk 3,3 | head -n 1 | awk '{print $2}')
```

### Automation Scripts

#### Windows PowerShell Cleanup Script

```powershell
# Script to kill orphaned processes
param(
    [Parameter(Mandatory=$true)]
    [string]$ProcessName,
    
    [Parameter()]
    [int]$OlderThanMinutes = 60
)

$cutoffTime = (Get-Date).AddMinutes(-$OlderThanMinutes)

Get-Process -Name $ProcessName | 
    Where-Object { $_.StartTime -lt $cutoffTime } | 
    ForEach-Object {
        Write-Host "Killing $($_.ProcessName) (PID: $($_.Id)) running since $($_.StartTime)"
        Stop-Process -Id $_.Id -Force
    }
```

#### Linux Bash Cleanup Script

```bash
#!/bin/bash
# Kill processes older than specified time
process_name=$1
min_age_minutes=${2:-60}

for pid in $(pgrep $process_name); do
  start_time=$(ps -o lstart= -p $pid)
  start_seconds=$(date -d "$start_time" +%s)
  current_seconds=$(date +%s)
  age_seconds=$((current_seconds - start_seconds))
  age_minutes=$((age_seconds / 60))
  
  if [ $age_minutes -gt $min_age_minutes ]; then
    echo "Killing $process_name (PID: $pid) running for $age_minutes minutes"
    kill -9 $pid
  fi
done
```

## Modern Debugging Tools

### Windows Admin Center

Windows Admin Center provides a modern web-based interface for managing servers, including process and performance monitoring.

- Access it at https://localhost:port after installation
- Provides visualizations for CPU, memory, disk, and network usage
- Can manage multiple servers from a single interface

### PowerShell Core Modules

```powershell
# Install ProcessExplorer module
Install-Module -Name ProcessExplorer

# Generate process tree visualization
Get-ProcessTree | Out-ConsoleGraphs

# Monitor performance with dashboard
Install-Module -Name ThreadJob
Install-Module -Name PSImaging
Install-Module -Name ImportExcel

# Example of PSImaging to visualize CPU graph
Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 60 |
    Select-Object -ExpandProperty CounterSamples |
    ForEach-Object { $_.CookedValue } |
    ConvertTo-LineGraph -Title "CPU Usage" -ShowLegend
```

### Docker and Container Tools

For containerized applications:

```bash
# List running containers
docker ps

# Container resource usage stats
docker stats

# Inspect container logs
docker logs container_id

# Get into a container for debugging
docker exec -it container_id /bin/bash
```

## Troubleshooting Common Scenarios

### Port Conflicts

1. **Identify what's using the port**
   ```powershell
   Get-NetTCPConnection -LocalPort port | 
     Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, 
       @{Name="Process"; Expression={(Get-Process -Id $_.OwningProcess).Name}}
   ```

2. **Resolve by terminating or reconfiguring the conflicting process**
   ```powershell
   # Get PID of process using port 8080
   $pid = (Get-NetTCPConnection -LocalPort 8080).OwningProcess
   # Kill that process
   Stop-Process -Id $pid -Force
   ```

### High CPU Usage

1. **Identify high CPU processes**
   ```powershell
   Get-Counter '\Process(*)\% Processor Time' | 
     Select-Object -ExpandProperty CounterSamples | 
     Where-Object { $_.InstanceName -ne "_total" -and $_.InstanceName -ne "idle" } | 
     Sort-Object -Property CookedValue -Descending | 
     Select-Object -First 5 InstanceName, CookedValue
   ```

2. **Investigate process details**
   ```powershell
   Get-Process -Name "highCpuProcess" | Format-List *
   ```

3. **Check thread count and handle usage**
   ```powershell
   Get-Process -Name "highCpuProcess" | Select-Object -ExpandProperty Threads | Measure-Object | Select-Object Count
   ```

### Memory Leaks

1. **Monitor memory growth over time**
   ```powershell
   # Run periodically to see increasing memory usage
   Get-Process -Name "suspectedProcess" | 
     Select-Object Name, @{Name="Memory(MB)"; Expression={$_.WorkingSet/1MB}}
   ```

2. **Check handle count growth (indication of resource leaks)**
   ```powershell
   Get-Process -Name "suspectedProcess" | Select-Object Handles
   ```

3. **Use performance counters for deeper analysis**
   ```powershell
   Get-Counter '\Process(suspectedProcess)\Working Set - Private' -SampleInterval 10 -MaxSamples 6
   ```

### Network Connectivity Issues

1. **Check if a host is reachable**
   ```powershell
   Test-NetConnection -ComputerName hostname -Port port
   ```

2. **Trace network path**
   ```powershell
   Test-NetConnection -ComputerName hostname -TraceRoute
   ```

3. **Check DNS resolution**
   ```powershell
   Resolve-DnsName -Name hostname
   ```

4. **Analyze connection latency**
   ```powershell
   1..5 | ForEach-Object { Test-Connection -ComputerName hostname -Count 1 } | 
     Select-Object Address, ResponseTime
   ```

## Quick Reference Cheat Sheet

### Essential Process Commands

| Task | Windows Command | PowerShell | Linux/macOS |
|------|----------------|------------|-------------|
| List processes | `tasklist` | `Get-Process` | `ps aux` |
| Find by name | `tasklist /FI "IMAGENAME eq name.exe"` | `Get-Process -Name name` | `ps aux \| grep name` |
| Kill process | `taskkill /PID pid /F` | `Stop-Process -Id pid -Force` | `kill -9 pid` |
| Process details | `wmic process where "name='name.exe'" get *` | `Get-Process -Name name \| Format-List *` | `ps -eo pid,ppid,cmd,%cpu,%mem,etime \| grep name` |

### Essential Network Commands

| Task | Windows Command | PowerShell | Linux/macOS |
|------|----------------|------------|-------------|
| All connections | `netstat -ano` | `Get-NetTCPConnection` | `ss -tuln` |
| Filter by port | `netstat -ano \| findstr ":port"` | `Get-NetTCPConnection -LocalPort port` | `ss -tuln \| grep :port` |
| Who's using port | `netstat -ano \| findstr ":port"` then<br>`tasklist /FI "PID eq pid"` | `Get-NetTCPConnection -LocalPort port \| Select OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).Name}}` | `lsof -i :port` |
| Trace route | `tracert hostname` | `Test-NetConnection -TraceRoute hostname` | `traceroute hostname` |
| DNS lookup | `nslookup hostname` | `Resolve-DnsName hostname` | `dig hostname` |

### Essential Resource Commands

| Task | Windows Command | PowerShell | Linux/macOS |
|------|----------------|------------|-------------|
| CPU usage | `wmic cpu get loadpercentage` | `Get-WmiObject win32_processor \| Measure-Object -property LoadPercentage -Average` | `top -n 1 \| grep "Cpu(s)"` |
| Memory usage | `wmic OS get FreePhysicalMemory,TotalVisibleMemorySize` | `Get-Counter '\Memory\Available MBytes'` | `free -m` |
| Disk usage | `wmic logicaldisk get deviceid,freespace,size` | `Get-PSDrive -PSProvider FileSystem` | `df -h` |
| Top CPU processes | `wmic process get name,percentprocessortime /format:list \| sort` | `Get-Process \| Sort-Object -Property CPU -Descending \| Select-Object -First 5` | `top -o %CPU -n 1 \| head -n 12` |

---

<div align="center">

**Created with ❤️ by [Your Name/Username]**  
*Last Updated: March 13, 2025*

</div>