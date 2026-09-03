<#
.SYNOPSIS
    Live presentation demo for TITAN Endpoint: fires real, watchable activity across
    every endpoint (Process, Network, Files) and narrates each step on-screen so a
    presenter has natural talking points synced to what shows up in the app.

.DESCRIPTION
    Santosh, 2026-09-01: "create one automated test file that shows the demo in a
    presentation... it just runs something and then it shows in the application."
    Nothing here is simulated or faked -- every step is a real process launch, real
    file write, or real network connection. TITAN's endpoints are already watching
    the whole machine, so real activity is all it takes; this script just produces a
    presentable, repeatable sequence of it with narration paced for talking over.

    Story arc (2-3 minutes total):
      1. Warm-up: one benign process + a couple of real DNS/HTTPS lookups, so
         Overview/Process/Network show live rows before the "story" starts.
      2. File activity: create then modify a file in Documents\TitanDemo (FIM watch
         scope -- see FILEEE\_file_scope.h's GetProtectedPaths) so the Files page
         shows a real create -> hash change pair.
      3. The correlated moment: one named child process that both writes a file AND
         opens a network connection within the same short-lived PID -- gives the
         Correlator a real shared-PID link across Process+File+Network, which should
         surface as one incident on Correlation Graph / Incident Graph.
      4. The suspicious flourish: a raw TCP connection to port 443 carrying a plain
         HTTP request instead of a TLS ClientHello -- a real, benign protocol-mismatch
         probe (same technique used to verify TITAN's own port/protocol-mismatch
         detector this session). Watch the Network page's Protocol Details tree
         (Expected protocol / Protocol mismatch) for this one.

.PARAMETER PauseSeconds
    Seconds to pause after each narrated step so the presenter can point at the
    screen before the script moves on. Default 3.

.EXAMPLE
    .\Run-PresentationDemo.ps1
    Runs the full demo with default pacing. TITAN should already be running with
    Start All clicked -- this script only generates activity, it does not start
    TITAN itself.
#>
[CmdletBinding()]
param(
    [int]$PauseSeconds = 3
)

function Say {
    param([string]$Text, [string]$Color = "Cyan")
    Write-Host ""
    Write-Host $Text -ForegroundColor $Color
}

function Beat { Start-Sleep -Seconds $PauseSeconds }

Write-Host "=================================================================" -ForegroundColor DarkGray
Write-Host "  TITAN ENDPOINT -- LIVE DEMO" -ForegroundColor White
Write-Host "  Make sure TITAN is running with Start All clicked before you begin." -ForegroundColor DarkGray
Write-Host "=================================================================" -ForegroundColor DarkGray
Beat

# ---------------------------------------------------------------------------
# 1. Warm-up: a benign process, then a couple of real network lookups.
# ---------------------------------------------------------------------------
Say "STEP 1 -- Launching a process. Point at the Process page: it should appear within a second or two."
$warmupProc = Start-Process notepad.exe -PassThru
Beat

Say "Closing it again, so you can also show the matching 'stop' event." -Color Green
Stop-Process -Id $warmupProc.Id -ErrorAction SilentlyContinue
Beat

Say "STEP 2 -- A couple of real DNS lookups and HTTPS connections. Point at the Network page -- rows and the Protocol Hierarchy chart should move."
try { Resolve-DnsName -Name "github.com" -ErrorAction Stop | Out-Null } catch {}
try { Invoke-WebRequest -UseBasicParsing -Uri "https://example.com" -TimeoutSec 5 | Out-Null } catch {}
try { Invoke-WebRequest -UseBasicParsing -Uri "https://www.wikipedia.org" -TimeoutSec 5 | Out-Null } catch {}
Beat

# ---------------------------------------------------------------------------
# 2. File activity: create, then modify (hash changes) -- Files / FIM page.
# ---------------------------------------------------------------------------
$demoDir = Join-Path $env:USERPROFILE "Documents\TitanDemo"
if (-not (Test-Path $demoDir)) { New-Item -ItemType Directory -Path $demoDir -Force | Out-Null }
$demoFile = Join-Path $demoDir "titan_demo_notes.txt"

Say "STEP 3 -- Creating a file in Documents\TitanDemo. Point at the Files page: a 'create' event with a hash should land."
Set-Content -Path $demoFile -Value "TITAN demo file created at $(Get-Date)" -Encoding UTF8
Beat

Say "Modifying the same file. The hash TITAN recorded a moment ago should now change." -Color Green
Add-Content -Path $demoFile -Value "Modified at $(Get-Date) -- hash should now differ."
Beat

# ---------------------------------------------------------------------------
# 3. The correlated moment: one process, one PID, touches File + Network.
# ---------------------------------------------------------------------------
Say "STEP 4 -- One process is about to write a file AND open a network connection at the same time. Point at Correlation Graph / Incident Graph: this is what a real correlated incident looks like."
$correlatedScript = @"
Set-Content -Path '$demoFile' -Value 'Touched by the correlated demo process' -Encoding UTF8
try { Invoke-WebRequest -UseBasicParsing -Uri 'https://www.wikipedia.org' -TimeoutSec 5 | Out-Null } catch {}
Start-Sleep -Seconds 2
"@
Start-Process powershell.exe -ArgumentList @("-NoProfile", "-Command", $correlatedScript) -Wait
Beat

# ---------------------------------------------------------------------------
# 4. The suspicious flourish: real traffic that doesn't match its own port.
# ---------------------------------------------------------------------------
Say "STEP 5 -- Sending a plain HTTP request over port 443, the port reserved for encrypted HTTPS. This is a real, classic evasion technique. Point at the Network page's Protocol Details pane: 'Expected protocol: HTTPS_TLS' with 'Protocol mismatch: Yes' should appear on this connection." -Color Yellow
try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect("example.com", 443)
    $stream = $client.GetStream()
    $request = [System.Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: example.com`r`n`r`n")
    $stream.Write($request, 0, $request.Length)
    $stream.Flush()
    Start-Sleep -Milliseconds 500
    $client.Close()
} catch { }
Beat

# ---------------------------------------------------------------------------
# Wrap-up.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=================================================================" -ForegroundColor DarkGray
Write-Host "  DEMO COMPLETE -- where to look:" -ForegroundColor White
Write-Host "    Overview           - session totals just moved" -ForegroundColor DarkGray
Write-Host "    Process            - notepad.exe start + stop" -ForegroundColor DarkGray
Write-Host "    Network            - DNS/HTTPS rows, plus the port-443 mismatch" -ForegroundColor DarkGray
Write-Host "    Files              - titan_demo_notes.txt create + hash change" -ForegroundColor DarkGray
Write-Host "    Correlation Graph  - the connected Process/File/Network incident" -ForegroundColor DarkGray
Write-Host "    Incident Graph     - same incident, one full card" -ForegroundColor DarkGray
Write-Host "    Unified Logs       - every raw event from this run, searchable" -ForegroundColor DarkGray
Write-Host "    STIX Export        - optional: Convert to STIX to show the export format" -ForegroundColor DarkGray
Write-Host "=================================================================" -ForegroundColor DarkGray
