# Windows TCP/UDP traffic monitor - script and PS2EXE compatible
# IP enrichment uses in-process asynchronous HttpClient (no curl or Start-Job).
# PktMon is launched directly as a child process, not via powershell.exe.
# A named mutex prevents overlapping monitors; stale PktMon sessions are stopped after verifying pktmon.exe.
# Script: powershell.exe -NoProfile -File .\traffic-monitor.ps1
# EXE: Invoke-ps2exe -inputFile .\traffic-monitor.ps1 -outputFile .\traffic-monitor.exe -requireAdmin -noConsole:$false
# The EXE requires Windows PowerShell and built-in pktmon.exe.
$ErrorActionPreference = 'Stop'

# PS2EXE sets $PSScriptRoot differently from a .ps1 script. Locate logs
# alongside the actual executable when packaged, or alongside the .ps1.
$processExe = (Get-Process -Id $PID).Path
$isPackaged = ([IO.Path]::GetFileName($processExe) -notin @('powershell.exe', 'pwsh.exe'))
if ($isPackaged) {
    $base = Split-Path -Parent $processExe
} elseif ($PSCommandPath) {
    $base = Split-Path -Parent $PSCommandPath
} else {
    $base = (Get-Location).Path
}

$who = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        if ($isPackaged) {
            # Relaunch the packaged monitor itself, not powershell.exe.
            Start-Process -FilePath $processExe -Verb RunAs -WorkingDirectory $base
        } else {
            if (-not $PSCommandPath) { throw 'Save the script as a .ps1 file first.' }
            $argsText = '-NoProfile -NoExit -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
            Start-Process -FilePath $processExe -Verb RunAs -WorkingDirectory $base -ArgumentList $argsText
        }
        return
    } catch {
        Write-Host "Administrator elevation failed: $_" -ForegroundColor Red
        Read-Host 'Press Enter to close'
        return
    }
}
$RefreshSeconds = 2
$RetentionSeconds = 300
$MaxRows = 40
$LookupIntervalSeconds = 2
$SuccessCacheHours = 24
$FailureCacheMinutes = 60
$MaxDailyLookups = 500
$MaxPendingLookups = 1000
$dir = Join-Path $base 'traffic-logs'
$flowCsv = Join-Path $dir 'flows.csv'
$lookupCsv = Join-Path $dir 'lookups.csv'
$cachePath = Join-Path $dir 'lookup-cache.json'
$capturePath = Join-Path $dir 'pktmon-output.txt'
$errorPath = Join-Path $dir 'errors.log'
$flows = @{}
$cache = @{}
$queued = @{}
$pending = New-Object 'System.Collections.Generic.Queue[string]'
$lookupIP = $null
$httpTask = $null
$dnsTask = $null
$lookupStarted = [datetime]::MinValue
$httpClient = $null
$dashboardTop = -1
$dashboardHeight = 0
$stopping = $false
$lastLookup = [datetime]::MinValue
$day = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
$dailyCount = 0
$packets = 0
$captureProcess = $null
$stdoutTask = $null
$stderrTask = $null
$captureWriter = $null
$captureOwned = $false
$startupFailed = $false
$stopRequested = $false
# A named mutex prevents two monitor instances from competing for the
# machine-wide PktMon session. Never automatically stop someone else's capture.
$instanceMutex = $null
$mutexOwned = $false
$pktmonStopSucceeded = $false
$pktmonPath = $null
$ctrlCHandlerInstalled = $false
# Native .NET console handler prevents Ctrl+C from aborting PowerShell before
# its finally block can stop the system-wide PktMon session.
$ctrlCHandlerSource = @'
using System;
public static class TrafficMonitorCtrlCHandler {
    public static volatile bool StopRequested = false;
    private static ConsoleCancelEventHandler registeredHandler;
    public static void Install() {
        StopRequested = false;
        if (registeredHandler != null) return;
        registeredHandler = new ConsoleCancelEventHandler(Handle);
        Console.CancelKeyPress += registeredHandler;
    }
    public static void Uninstall() {
        if (registeredHandler == null) return;
        Console.CancelKeyPress -= registeredHandler;
        registeredHandler = null;
    }
    private static void Handle(object sender, ConsoleCancelEventArgs args) {
        args.Cancel = true;
        StopRequested = true;
    }
}
'@

# Resolve the genuine Windows system PktMon executable, not a PATH shadow.
function Get-VerifiedPktMonPath {
    $expected = Join-Path $env:WINDIR 'System32\pktmon.exe'
    if (-not [IO.File]::Exists($expected)) {
        throw "Windows PktMon executable not found at $expected"
    }
    $item = Get-Item -LiteralPath $expected -ErrorAction Stop
    if ($item.Name -ine 'pktmon.exe' -or $item.Extension -ine '.exe') {
        throw "Unexpected PktMon executable: $expected"
    }
    # Signature check verifies the publisher, not merely the filename.
    $signature = Get-AuthenticodeSignature -LiteralPath $expected -ErrorAction Stop
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
        throw "PktMon signature is not a valid Microsoft signature: $($signature.Status)"
    }
    return $item.FullName
}

function Stop-VerifiedPktMon {
    param([string]$Executable, [int]$TimeoutMilliseconds = 5000)
    if (-not $Executable -or [IO.Path]::GetFileName($Executable) -ine 'pktmon.exe') {
        throw 'Refusing to run stop command: unverified executable path.'
    }
    $proc = $null
    try {
        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = $Executable
        $info.Arguments = 'stop'
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        # No redirected streams: avoids pipe deadlock during shutdown.
        $proc = [System.Diagnostics.Process]::Start($info)
        if (-not $proc.WaitForExit($TimeoutMilliseconds)) {
            try { $proc.Kill() } catch {}
            [void]$proc.WaitForExit(1000)
            throw "pktmon stop exceeded $TimeoutMilliseconds ms"
        }
        if ($proc.ExitCode -ne 0) {
            throw "pktmon stop returned exit code $($proc.ExitCode)"
        }
        return $true
    } finally {
        if ($proc) { $proc.Dispose() }
    }
}

function Csv($path, $row) { $row | Export-Csv -Path $path -NoTypeInformation -Append -Encoding UTF8 }
function FlowEvent($f, $eventName) {
    Csv $flowCsv ([pscustomobject]@{TimestampUTC=(Get-Date).ToUniversalTime().ToString('o');Event=$eventName;Protocol=$f.Protocol;SourceIP=$f.SourceIP;SourcePort=$f.SourcePort;DestinationIP=$f.DestinationIP;DestinationPort=$f.DestinationPort;Packets=$f.Packets;FirstSeenUTC=$f.FirstSeen.ToUniversalTime().ToString('o');LastSeenUTC=$f.LastSeen.ToUniversalTime().ToString('o')})
}
function SaveCache {
    @{Cache=$cache;Day=$day;Count=$dailyCount} | ConvertTo-Json -Depth 8 | Set-Content -Path "$cachePath.tmp" -Encoding UTF8
    Move-Item -Path "$cachePath.tmp" -Destination $cachePath -Force
}
function LoadCache {
    if (-not (Test-Path $cachePath)) { return }
    try {
        $d = Get-Content $cachePath -Raw | ConvertFrom-Json
        if ($d.Cache) { foreach ($p in $d.Cache.PSObject.Properties) { $script:cache[$p.Name] = $p.Value } }
        if ($d.Day -eq $day) { $script:dailyCount = [int]$d.Count }
    } catch { Add-Content $errorPath "Cache read error: $_" }
}
function PublicIP([string]$s) {
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($s, [ref]$ip)) { return $false }
    if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
    if ([Net.IPAddress]::IsLoopback($ip)) { return $false }
    $b = $ip.GetAddressBytes()
    if ($b.Length -eq 4) {
        if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224 -or
            ($b[0] -eq 169 -and $b[1] -eq 254) -or
            ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
            ($b[0] -eq 192 -and $b[1] -eq 168) -or
            ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
            ($b[0] -eq 192 -and $b[1] -eq 0) -or
            ($b[0] -eq 198 -and $b[1] -ge 18 -and $b[1] -le 19) -or
            ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) -or
            ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)) { return $false }
        return $true
    }
    if ($ip.IsIPv6Multicast -or $ip.IsIPv6LinkLocal -or $ip.Equals([Net.IPAddress]::IPv6Any) -or
        (($b[0] -band 254) -eq 252) -or
        ($b[0] -eq 32 -and $b[1] -eq 1 -and $b[2] -eq 13 -and $b[3] -eq 184)) { return $false }
    return $true
}
function QueueIP([string]$ip) {
    if (-not (PublicIP $ip) -or $queued.ContainsKey($ip)) { return }
    if ($cache.ContainsKey($ip)) {
        $c = $cache[$ip]
        $age = ((Get-Date).ToUniversalTime() - ([datetime]$c.Timestamp).ToUniversalTime()).TotalMinutes
        $ttl = if ($c.Success) { $SuccessCacheHours * 60 } else { $FailureCacheMinutes }
        if ($age -lt $ttl) { return }
    }
    if ($pending.Count -ge $MaxPendingLookups) { return }
    $queued[$ip] = $true
    $pending.Enqueue($ip)
}
# Flatten nested .NET exceptions so TLS, DNS and socket failures are visible.
function Get-HttpErrorDetail {
    param([System.Exception]$Exception)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    $current = $Exception
    $depth = 0
    while ($null -ne $current -and $depth -lt 12) {
        $parts.Add(('{0}: {1}' -f $current.GetType().FullName, $current.Message))
        if ($current -is [System.Net.WebException] -and $current.Status) {
            $parts.Add(('WebException status: {0}' -f $current.Status))
        }
        if ($current -is [System.Net.Sockets.SocketException]) {
            $parts.Add(('Socket error: {0} ({1})' -f $current.SocketErrorCode, $current.NativeErrorCode))
        }
        $current = $current.InnerException
        $depth++
    }
    return ($parts -join ' | ')
}

# In-process HttpClient: the EXE itself makes the outbound request.
# No powershell.exe child process is spawned for IP enrichment.
function Finish-Lookup {
    param([bool]$Success, [string]$ErrorText, [object]$Data)
    if (-not $script:lookupIP) { return }
    $hostName = '-'
    if ($script:dnsTask -and $script:dnsTask.IsCompleted -and -not $script:dnsTask.IsFaulted -and -not $script:dnsTask.IsCanceled) {
        try { $hostName = [string]$script:dnsTask.Result.HostName } catch {}
    }
    $provider = '-'; $asn = '-'; $country = '-'
    if ($Success -and $Data) {
        $provider = [string]$Data.connection.org
        if (-not $provider) { $provider = [string]$Data.connection.isp }
        if (-not $provider) { $provider = '-' }
        if ($null -ne $Data.connection.asn) { $asn = [string]$Data.connection.asn }
        if ($Data.country) { $country = [string]$Data.country }
    }
    $t = (Get-Date).ToUniversalTime().ToString('o')
    $script:cache[$script:lookupIP] = @{
        Timestamp=$t;Success=$Success;Hostname=$hostName;Provider=$provider;
        ASN=$asn;Country=$country;Error=$ErrorText
    }
    Csv $lookupCsv ([pscustomobject]@{
        TimestampUTC=$t;IP=$script:lookupIP;Hostname=$hostName;
        Provider=$provider;ASN=$asn;Country=$country;Success=$Success;Error=$ErrorText
    })
    [void]$queued.Remove($script:lookupIP)
    $script:lookupIP = $null
    $script:httpTask = $null
    $script:dnsTask = $null
    SaveCache
}
function UpdateLookups {
    $today = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
    if ($today -ne $script:day) { $script:day=$today; $script:dailyCount=0; SaveCache }
    if ($script:lookupIP) {
        if ($script:httpTask.IsCompleted) {
            try {
                # GetAsync task result is an HttpResponseMessage.
                $response = $script:httpTask.GetAwaiter().GetResult()
                try {
                    $status = [int]$response.StatusCode
                    if (-not $response.IsSuccessStatusCode) {
                        Finish-Lookup $false "HTTP $status" $null
                    } else {
                        $json = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                        $data = $json | ConvertFrom-Json -ErrorAction Stop
                        if ($data.success -eq $true) {
                            Finish-Lookup $true '-' $data
                        } else {
                            $reason = [string]$data.message
                            if (-not $reason) { $reason = 'API returned success=false' }
                            Finish-Lookup $false $reason $null
                        }
                    }
                } finally { $response.Dispose() }
            } catch {
                $detail = Get-HttpErrorDetail $_.Exception
                Finish-Lookup $false $detail $null
            }
        } elseif (((Get-Date) - $script:lookupStarted).TotalSeconds -gt 18) {
            # HttpClient.Timeout should fire first; this is a safety timeout.
            Finish-Lookup $false 'HTTP lookup timed out' $null
        }
    }
    if (-not $script:lookupIP -and $pending.Count -gt 0 -and
        $dailyCount -lt $MaxDailyLookups -and
        ((Get-Date) - $lastLookup).TotalSeconds -ge $LookupIntervalSeconds) {
        $script:lookupIP = $pending.Dequeue()
        $script:lastLookup = Get-Date
        $script:lookupStarted = Get-Date
        $script:dailyCount++
        SaveCache # persist request budget before request
        try {
            $script:dnsTask = [Net.Dns]::GetHostEntryAsync([Net.IPAddress]::Parse($script:lookupIP))
            $url = 'https://ipwho.is/' + [uri]::EscapeDataString($script:lookupIP)
            $script:httpTask = $httpClient.GetAsync($url)
        } catch {
            $detail = Get-HttpErrorDetail $_.Exception
            Finish-Lookup $false $detail $null
        }
    }
}
$packetPattern = [regex]'(?<src>[0-9a-fA-F:.]+)\.(?<sp>\d+)\s+>\s+(?<dst>[0-9a-fA-F:.]+)\.(?<dp>\d+):\s+(?<detail>.*)$'
function ProcessLine([string]$line) {
    $m = $packetPattern.Match($line)
    if (-not $m.Success) { return }
    $detail = $m.Groups['detail'].Value
    $proto = if ($detail -match '^UDP\b') { 'UDP' } elseif ($detail -match '^(Flags \[|TCP\b)') { 'TCP' } else { return }
    $src=$m.Groups['src'].Value; $dst=$m.Groups['dst'].Value
    $sp=$m.Groups['sp'].Value; $dp=$m.Groups['dp'].Value
    $endpoints = @("${src}:$sp", "${dst}:$dp") | Sort-Object -CaseSensitive
    $key = "$proto|$($endpoints[0])|$($endpoints[1])"
    $now = Get-Date
    if (-not $flows.ContainsKey($key)) {
        $flows[$key] = @{Protocol=$proto;SourceIP=$src;SourcePort=$sp;DestinationIP=$dst;DestinationPort=$dp;FirstSeen=$now;LastSeen=$now;Packets=0}
        QueueIP $src; QueueIP $dst
    }
    $flows[$key].Packets++
    $flows[$key].LastSeen=$now
    $script:packets++
    if ($flows[$key].Packets -eq 1) { FlowEvent $flows[$key] 'NEW' }
}
function ExpireFlows {
    $now=Get-Date
    foreach ($k in @($flows.Keys)) {
        if (($now - $flows[$k].LastSeen).TotalSeconds -ge $RetentionSeconds) {
            FlowEvent $flows[$k] 'EXPIRED'
            $flows.Remove($k)
        }
    }
}
function LookupDetails($ip) {
    if ($cache.ContainsKey($ip)) {
        $c = $cache[$ip]
        $status = if ($c.Success) { 'OK' } else { 'Failed' }
        return [pscustomobject]@{
            Provider = [string]$c.Provider
            Hostname = [string]$c.Hostname
            ASN = [string]$c.ASN
            Country = [string]$c.Country
            LookupStatus = $status
            HttpError = [string]$c.Error
        }
    }
    $status = if ($queued.ContainsKey($ip)) { 'Queued' } else { 'Not queried' }
    return [pscustomobject]@{
        Provider = '-'; Hostname = '-'; ASN = '-'; Country = '-'
        LookupStatus = $status; HttpError = '-'
    }
}
function ShortText($value, [int]$max) {
    $text = [string]$value
    if ($text.Length -gt $max) { return $text.Substring(0, $max - 3) + '...' }
    return $text
}
function Render {
    # Update a fixed console region without Clear-Host. Existing scrollback stays.
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('WINDOWS LIVE TCP / UDP FLOW MONITOR')
    $lines.Add("Refresh ${RefreshSeconds}s | Retention ${RetentionSeconds}s | Flows $($flows.Count) | Parsed packets $packets")
    $lines.Add("Queued IPs $($pending.Count) | HTTP lookups today $dailyCount / $MaxDailyLookups")
    $lines.Add("CSV logs: $dir")
    $lines.Add('Provider, hostname, ASN, country and HTTP error refer to destination IP.')
    $lines.Add('')
    $rows = @($flows.Values | Sort-Object LastSeen -Descending | Select-Object -First $MaxRows | ForEach-Object {
        $f = $_
        $info = LookupDetails $f.DestinationIP
        [pscustomobject]@{
            Proto=$f.Protocol
            Source=("{0}:{1}" -f $f.SourceIP,$f.SourcePort)
            Destination=("{0}:{1}" -f $f.DestinationIP,$f.DestinationPort)
            Provider=(ShortText $info.Provider 24)
            Hostname=(ShortText $info.Hostname 34)
            ASN=$info.ASN
            Country=(ShortText $info.Country 16)
            Lookup=$info.LookupStatus
            HttpError=(ShortText $info.HttpError 42)
            Packets=$f.Packets
            IdleSec=[int]((Get-Date)-$f.LastSeen).TotalSeconds
        }
    })
    if ($rows.Count) {
        $formatted = $rows | Format-Table -AutoSize | Out-String -Width 260
        foreach ($line in ($formatted.TrimEnd("`r","`n") -split "`r?`n")) { $lines.Add($line) }
    } else { $lines.Add('Waiting for packets. Check errors.log if this persists.') }
    $lines.Add('Ctrl+C stops capture; cleanup stops PktMon before waiting for exit.')
    try {
        $width = [Math]::Max(1, [Console]::BufferWidth - 1)
        $height = [Console]::BufferHeight
        # Initial allocation: append dashboard to current console position.
        if ($script:dashboardTop -lt 0) {
            $script:dashboardTop = [Console]::CursorTop
            # Reserve rows once so subsequent updates never erase old output.
            for ($j=0; $j -lt $lines.Count; $j++) { [Console]::WriteLine('') }
        }
        # If buffer scrolled or resized, append a fresh dashboard rather than
        # overwrite unrelated scrollback.
        if (($script:dashboardTop + [Math]::Max($lines.Count,$script:dashboardHeight)) -ge $height) {
            [Console]::SetCursorPosition(0, [Math]::Max(0, $height - 1))
            for ($j=0; $j -lt $lines.Count; $j++) { [Console]::WriteLine('') }
            $script:dashboardTop = [Math]::Max(0, [Console]::CursorTop - $lines.Count)
            $script:dashboardHeight = 0
        }
        $count = [Math]::Max($lines.Count, $script:dashboardHeight)
        for ($i=0; $i -lt $count; $i++) {
            if (($script:dashboardTop + $i) -ge [Console]::BufferHeight) { break }
            $line = if ($i -lt $lines.Count) { $lines[$i] } else { '' }
            if ($line.Length -gt $width) { $line = $line.Substring(0,$width) }
            [Console]::SetCursorPosition(0, $script:dashboardTop + $i)
            [Console]::Write($line.PadRight($width))
        }
        $script:dashboardHeight = $lines.Count
    } catch {
        # Fallback for redirected consoles / unsupported cursor positioning.
        $lines | ForEach-Object { Write-Host $_ }
        $script:dashboardTop = -1
    }
}

try {
    $instanceMutex = New-Object System.Threading.Mutex($false, 'Global\TrafficMonitor-PktMon')
    try { $mutexOwned = $instanceMutex.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] { $mutexOwned = $true }
    if (-not $mutexOwned) {
        throw 'Another TrafficMonitor instance is already running. Close it before starting a new capture.'
    }
    # Register before starting PktMon. Handler only signals; main loop performs
    # cleanup on the normal PowerShell thread, avoiding event-thread runspace issues.
    Add-Type -TypeDefinition $ctrlCHandlerSource -ErrorAction Stop
    [TrafficMonitorCtrlCHandler]::Install()
    $ctrlCHandlerInstalled = $true
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $pktmonPath = Get-VerifiedPktMonPath
    # The mutex is already held, so another copy of this monitor cannot
    # race us. PktMon sessions are system-wide; this may stop other captures.
    Write-Host 'Clearing any existing PktMon session before capture...' -ForegroundColor Yellow
    try { [void](Stop-VerifiedPktMon -Executable $pktmonPath) }
    catch { Write-Warning "Pre-start pktmon stop did not confirm success: $_" }
    Start-Sleep -Milliseconds 900
    LoadCache
    Add-Type -AssemblyName System.Net.Http
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.UseProxy = $false  # Direct HTTPS; change if your network requires a proxy.
    $httpClient = [Net.Http.HttpClient]::new($handler)
    $httpClient.Timeout = [TimeSpan]::FromSeconds(12)
    $httpClient.DefaultRequestHeaders.UserAgent.ParseAdd('TrafficMonitor/1.0 (Windows; network diagnostics)')
    $httpClient.DefaultRequestHeaders.Accept.ParseAdd('application/json')
    # Launch pktmon.exe directly: no Start-Job, no child powershell.exe.
    # HttpClient and DNS requests also run inside the current process.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $pktmonPath
    $psi.Arguments = 'start --capture --comp nics --type flow --pkt-size 96 --log-mode real-time'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $captureProcess = New-Object System.Diagnostics.Process
    $captureProcess.StartInfo = $psi
    if (-not $captureProcess.Start()) { throw 'Failed to launch pktmon.exe.' }
    # A successful Start() only means the process launched, not that capture started.
    # We mark ownership only once it remains alive after initial startup.
    Start-Sleep -Milliseconds 600
    if ($captureProcess.HasExited) {
        $out = $captureProcess.StandardOutput.ReadToEnd()
        $err = $captureProcess.StandardError.ReadToEnd()
        if ($out -match 'Packet Monitor is already started') {
            throw 'PktMon still reports an active session after the pre-start stop attempt. Check for another capture service.'
        }
        throw "PktMon failed during startup (exit $($captureProcess.ExitCode)). stdout: $out stderr: $err. Check for unsupported redirected real-time output."
    }
    $captureOwned = $true
    $captureWriter = New-Object IO.StreamWriter($capturePath, $false, [Text.Encoding]::UTF8)
    $captureWriter.AutoFlush = $true
    $stdoutTask = $captureProcess.StandardOutput.ReadLineAsync()
    $stderrTask = $captureProcess.StandardError.ReadToEndAsync()
    $lastDraw=[datetime]::MinValue
    while ($true) {
        if ([TrafficMonitorCtrlCHandler]::StopRequested) {
            $script:stopRequested = $true
            break
        }
        # Read continuously, independent of the 2-second dashboard refresh.
        $n=0
        while ($stdoutTask -and $stdoutTask.IsCompleted -and $n -lt 20000) {
            if ([TrafficMonitorCtrlCHandler]::StopRequested) { break }
            $line = $stdoutTask.GetAwaiter().GetResult()
            if ($null -eq $line) {
                $stdoutTask = $null
                break
            }
            $captureWriter.WriteLine($line)
            ProcessLine $line
            $n++
            $stdoutTask = $captureProcess.StandardOutput.ReadLineAsync()
        }
        if ($captureProcess.HasExited) {
            $errorText = if ($stderrTask -and $stderrTask.IsCompleted) {
                $stderrTask.GetAwaiter().GetResult()
            } else { 'No stderr available' }
            throw "PktMon exited (code $($captureProcess.ExitCode)): $errorText. Check $capturePath for captured stdout. Exit 5023 is not by itself proof of the cause."
        }
        UpdateLookups
        ExpireFlows
        if (((Get-Date)-$lastDraw).TotalSeconds -ge $RefreshSeconds) {
            Render
            $lastDraw=Get-Date
        }
        Start-Sleep -Milliseconds 100
    }
 } catch [System.Management.Automation.PipelineStoppedException] {
    # A pipeline interruption is a normal stop request, not a startup error.
    $script:stopRequested = $true
} catch {
    $script:startupFailed = $true
    $msg = "$(Get-Date -Format o) ERROR: $($_.Exception.Message)`n$($_.ScriptStackTrace)"
    Write-Host $msg -ForegroundColor Red
    try { if (Test-Path $dir) { Add-Content -Path $errorPath -Value $msg } } catch {}
} finally {
    # Shutdown order: stop ingestion, stop owned PktMon session, bound waits,
    # dispose resources, release mutex. Do not touch an unrelated session.
    $script:stopping = $true
    if ($ctrlCHandlerInstalled) {
        try {
            [TrafficMonitorCtrlCHandler]::Uninstall()
        } catch {}
    }
    if ($stopRequested) { Write-Host 'Ctrl+C received; stopping PktMon...' -ForegroundColor Yellow }
    # Stop the system-wide capture if this monitor started it.
    if ($captureOwned -and $pktmonPath) {
        try {
            $pktmonStopSucceeded = Stop-VerifiedPktMon -Executable $pktmonPath
        } catch { Write-Warning "PktMon stop request failed: $_" }
    }
    if ($captureProcess) {
        try {
            if (-not $captureProcess.HasExited -and -not $captureProcess.WaitForExit(2500)) {
                Write-Warning 'Capture process did not exit; terminating only this child process.'
                $captureProcess.Kill()
                [void]$captureProcess.WaitForExit(1000)
            }
        } catch { Write-Warning "Capture child cleanup failed: $_" }
        try { $captureProcess.Dispose() } catch {}
    }
    if ($captureWriter) { try { $captureWriter.Dispose() } catch {} }
    if ($httpClient) { try { $httpClient.Dispose() } catch {} }
    if ($instanceMutex) {
        if ($mutexOwned) { try { $instanceMutex.ReleaseMutex() } catch {} }
        try { $instanceMutex.Dispose() } catch {}
    }
    if ($captureOwned -and -not $pktmonStopSucceeded) {
        Write-Warning 'PktMon stop was not confirmed. Check pktmon status before restarting; do not assume capture is inactive.'
    }
    Write-Host 'Capture cleanup completed.' -ForegroundColor Yellow
    if ($startupFailed) {
        Write-Host "Startup/runtime error logged to $errorPath" -ForegroundColor Red
        if ($isPackaged) {
            try { [void](Read-Host 'Press Enter to close this window') } catch {}
        }
    }
}
