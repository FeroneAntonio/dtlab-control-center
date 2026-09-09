[CmdletBinding()]
param(
    [ValidateSet("staging", "production")]
    [string[]]$Target = @("staging", "production"),
    [ValidateRange(3, 10000)]
    [int]$SnapshotRetention = 240
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"
$liveSyncPath = Join-Path $projectRoot "tools\live_sync.py"
$configPath = Join-Path $projectRoot "config\dtlab.local.toml"
$runtimeRoot = Join-Path $projectRoot "runtime"
$logPath = Join-Path $runtimeRoot "near-real-time.log"
$previousLogPath = "$logPath.previous"
$openSshRoot = Join-Path $env:SystemRoot "System32\OpenSSH"
$sshPath = Join-Path $openSshRoot "ssh.exe"
$scpPath = Join-Path $openSshRoot "scp.exe"

if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    throw "Runtime Python DTLab non trovato."
}

foreach ($openSshExecutable in @($sshPath, $scpPath)) {
    if (-not (Test-Path -LiteralPath $openSshExecutable -PathType Leaf)) {
        throw "Runtime OpenSSH DTLab non trovato."
    }
}

$env:Path = "$openSshRoot;$env:Path"

if (-not (Test-Path -LiteralPath $runtimeRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $runtimeRoot | Out-Null
}

if ((Test-Path -LiteralPath $logPath -PathType Leaf) -and
    (Get-Item -LiteralPath $logPath).Length -gt 10MB) {
    Move-Item -LiteralPath $logPath -Destination $previousLogPath -Force
}

function Invoke-DTLabStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Add-Content -LiteralPath $logPath -Value "[$((Get-Date).ToString('o'))] $Name"
    $stepOutput = & $pythonPath $liveSyncPath @Arguments 2>&1
    $stepExitCode = $LASTEXITCODE
    if ($stepOutput) {
        $stepOutput | Add-Content -LiteralPath $logPath
        $stepOutput | Write-Output
    }
    if ($stepExitCode -ne 0) {
        Add-Content -LiteralPath $logPath -Value "[$((Get-Date).ToString('o'))] ${Name}_failed exit=$stepExitCode"
        exit $stepExitCode
    }
}

$commonArguments = @(
    "--config", $configPath,
    "--once",
    "--allow-classic-sensor-stats-server-error"
)

Invoke-DTLabStep -Name "collect" -Arguments @(
    $commonArguments + @("--snapshot-retention", $SnapshotRetention.ToString())
)

$publishArguments = @($commonArguments + "--publish-current")
foreach ($publishTarget in $Target) {
    $publishArguments += @("--target", $publishTarget)
}
Invoke-DTLabStep -Name "publish" -Arguments $publishArguments
