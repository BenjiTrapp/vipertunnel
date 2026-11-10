# Can this proxy carry the tunnel? Answer before deploying, not after.
#
# The Windows counterpart of proxy-preflight.py, for a host that has no
# Python -- which is the host this family brings its own interpreter to, so
# it is the host where a preflight most needs to work without one.
#
# The tunnel needs one thing from a proxy: CONNECT <host>:443, then bytes
# that are neither TLS nor HTTP. Three outcomes, and only the third is a
# deployable path:
#
#   REFUSED   a destination allowlist turned the CONNECT down. The tunnel
#             cannot exist on this host -- and neither can the family it
#             emulates. That is a result about the environment.
#   PERMITTED the CONNECT returned 200 and nothing proved the bytes survive.
#   CARRIED   a listener you control echoed a known string back intact.
#
# The middle case is the expensive one: the deployment looks fine and the
# handshake dies for a reason that reads as a server fault. So this does not
# stop at the 200.
#
# Usage, from the host that will carry the implant:
#
#   .\proxy-preflight.ps1 -Proxy 10.0.0.9:8080 -Echo 203.0.113.9:443
#   .\proxy-preflight.ps1 -Proxy 10.0.0.9:8080 -Target example.org:443
#
# Stand the echo listener up with the Python script on the server host:
#
#   ./proxy-preflight.py --echo-server 0.0.0.0:443
#
# Written for Windows PowerShell 5.1: raw sockets rather than
# Invoke-WebRequest, because no cmdlet will send a CONNECT and then hand you
# the stream.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Proxy,
    [string[]]$Echo = @(),
    [string[]]$Target = @(),
    [int]$TimeoutSeconds = 20
)

$ErrorActionPreference = 'Stop'

function Split-Endpoint {
    param([string]$Text, [int]$DefaultPort)
    if ($Text -match '^(.*):(\d+)$') {
        return @{ Host = $Matches[1]; Port = [int]$Matches[2] }
    }
    return @{ Host = $Text; Port = $DefaultPort }
}

$probe = "PREFLIGHT-" + ([guid]::NewGuid().ToString('N').Substring(0, 8))
$probeBytes = [Text.Encoding]::ASCII.GetBytes($probe)

function Test-Destination {
    param($ProxyEnd, $Dest, [bool]$ExpectEcho)

    $label = "$($Dest.Host):$($Dest.Port)"
    $client = $null
    try {
        $client = New-Object Net.Sockets.TcpClient
        $task = $client.ConnectAsync($ProxyEnd.Host, $ProxyEnd.Port)
        if (-not $task.Wait($TimeoutSeconds * 1000)) {
            throw "no answer from the proxy within ${TimeoutSeconds}s"
        }
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutSeconds * 1000
        $stream.WriteTimeout = $TimeoutSeconds * 1000

        $request = "CONNECT $label HTTP/1.1`r`nHost: $label`r`n" +
                   "Proxy-Connection: Keep-Alive`r`n`r`n"
        $raw = [Text.Encoding]::ASCII.GetBytes($request)
        $stream.Write($raw, 0, $raw.Length)
        $stream.Flush()

        # Read the status line and headers one byte at a time: the byte after
        # the blank line is the first byte of the tunnel and must not be
        # swallowed by a buffered reader.
        $header = New-Object Text.StringBuilder
        $one = New-Object byte[] 1
        while ($header.ToString() -notmatch "`r`n`r`n$") {
            if ($header.Length -gt 8192) { throw "proxy sent over 8 KiB of headers" }
            if ($stream.Read($one, 0, 1) -lt 1) {
                throw "proxy closed during CONNECT after $($header.Length) bytes"
            }
            [void]$header.Append([char]$one[0])
        }
        $status = ($header.ToString() -split "`r`n")[0].Trim()

        if ($status -notmatch ' 200') {
            Write-Host ("  {0,-28} REFUSED  -> {1}" -f $label, $status)
            return 'refused'
        }

        if (-not $ExpectEcho) {
            Write-Host ("  {0,-28} permitted ({1}) -- nothing proved bytes survive" -f $label, $status)
            return 'permitted'
        }

        $stream.Write($probeBytes, 0, $probeBytes.Length)
        $stream.Flush()
        $back = New-Object byte[] $probeBytes.Length
        $have = 0
        while ($have -lt $probeBytes.Length) {
            $read = $stream.Read($back, $have, $probeBytes.Length - $have)
            if ($read -lt 1) { break }
            $have += $read
        }
        $got = [Text.Encoding]::ASCII.GetString($back, 0, $have)
        if ($got -ceq $probe) {
            Write-Host ("  {0,-28} CARRIED  ({1}, {2} bytes echoed intact)" -f $label, $status, $have)
            return 'carried'
        }
        Write-Host ("  {0,-28} permitted but ALTERED: sent '{1}', got '{2}'" -f $label, $probe, $got)
        return 'altered'
    } catch {
        Write-Host ("  {0,-28} CONNECT failed: {1}" -f $label, $_.Exception.Message)
        return 'unreachable'
    } finally {
        if ($client) { $client.Close() }
    }
}

if ($Echo.Count -eq 0 -and $Target.Count -eq 0) {
    Write-Error "give at least one -Echo or -Target"
    exit 2
}

$proxyEnd = Split-Endpoint -Text $Proxy -DefaultPort 3128
Write-Host ("proxy {0}:{1}" -f $proxyEnd.Host, $proxyEnd.Port)

$verdicts = @{}
foreach ($dest in $Echo) {
    $verdicts[$dest] = Test-Destination $proxyEnd (Split-Endpoint $dest 443) $true
}
foreach ($dest in $Target) {
    $verdicts[$dest] = Test-Destination $proxyEnd (Split-Endpoint $dest 443) $false
}

Write-Host ""
$carried = @($verdicts.Keys | Where-Object { $verdicts[$_] -eq 'carried' })
$refused = @($verdicts.Keys | Where-Object { $verdicts[$_] -eq 'refused' })
$broken  = @($verdicts.Keys | Where-Object { $verdicts[$_] -in @('intercepted', 'altered') })

if ($carried.Count) {
    Write-Host ("DEPLOYABLE through this proxy to: {0}" -f ($carried -join ', '))
}
if ($refused.Count) {
    Write-Host ("REFUSED by an allowlist: {0}" -f ($refused -join ', '))
    Write-Host "  A destination-filtering proxy cannot carry this tunnel, and"
    Write-Host "  cannot carry the family it emulates either. That is a result"
    Write-Host "  about the environment, not a missing feature here."
}
if ($broken.Count) {
    Write-Host ("PERMITTED BUT NOT CARRIED: {0}" -f ($broken -join ', '))
    Write-Host "  The CONNECT succeeded and the stream did not survive. This is"
    Write-Host "  the case that looks like a server fault after deployment."
}
if (-not $carried.Count -and -not $refused.Count -and -not $broken.Count) {
    Write-Host "Nothing conclusive. Re-run with -Echo against a listener you"
    Write-Host "control: a 200 on its own proves only that CONNECT was allowed."
}

if ($carried.Count) { exit 0 } else { exit 1 }
