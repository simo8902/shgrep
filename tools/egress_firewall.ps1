<#
.SYNOPSIS
  Blocks outbound network access for shgrep, its language servers and other MCP servers (issue #51).

.DESCRIPTION
  Creates Windows Firewall outbound block rules, group "shgrep egress block", for every program that reads code on
  an agent's behalf. Windows Firewall does not filter loopback traffic, so stdio and loopback use keep working.
  Writes egress-block.json next to shgrep.exe; lsp.status reports each server's rule from it.
  Run in an elevated PowerShell. Running again replaces the group's rules; -Remove deletes them.

.PARAMETER ShgrepDir
  Folder holding shgrep.exe. Default: the folder above this script (a deployed tools\ folder).

.PARAMETER LspDir
  Folder holding the bundled servers. Default: $env:SHGREP_LSP_ROOT\lsp, else <ShgrepDir>\lsp.

.PARAMETER McpConfig
  .mcp.json files whose server executables are blocked too. Generic launchers (node, uvx, python, ...) are
  skipped with a warning unless -IncludeLaunchers is given, because blocking them affects every program they run.

.PARAMETER IncludeToolchains
  Also block dotnet.exe and cmake.exe. This stops your own package restores and downloads as well.

.EXAMPLE
  .\tools\egress_firewall.ps1 -ShgrepDir C:\Users\me\shgrep\build-llvm -McpConfig C:\Users\me\shgrep\.mcp.json
#>
[CmdletBinding()]
param(
    [string]$ShgrepDir = (Split-Path -Parent $PSScriptRoot),
    [string]$LspDir,
    [string[]]$McpConfig = @(),
    [string[]]$Program = @(),
    [switch]$IncludeLaunchers,
    [switch]$IncludeToolchains,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$group = 'shgrep egress block'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script in an elevated PowerShell (Run as administrator).'
}

Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$marker = Join-Path $ShgrepDir 'egress-block.json'
if ($Remove) {
    if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker }
    Write-Output "Removed all '$group' rules."
    return
}

$programs = [System.Collections.Generic.List[string]]::new()
$add = {
    param([string]$path)
    if (-not $path) { return }
    $full = [IO.Path]::GetFullPath($path)
    if ((Test-Path -LiteralPath $full -PathType Leaf) -and -not ($programs -contains $full)) { $programs.Add($full) }
}

& $add (Join-Path $ShgrepDir 'shgrep.exe')
if (-not $LspDir) {
    $LspDir = if ($env:SHGREP_LSP_ROOT) { Join-Path $env:SHGREP_LSP_ROOT 'lsp' } else { Join-Path $ShgrepDir 'lsp' }
}
if (Test-Path -LiteralPath $LspDir) {
    Get-ChildItem -LiteralPath $LspDir -Recurse -File -Filter *.exe | ForEach-Object { & $add $_.FullName }
} else {
    Write-Warning "No bundled language servers at $LspDir"
}

$launchers = 'node', 'npx', 'npm', 'uv', 'uvx', 'python', 'python3', 'py', 'pythonw', 'cmd', 'powershell', 'pwsh', 'dotnet', 'java', 'deno', 'bun'
foreach ($config in $McpConfig) {
    $json = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
    foreach ($server in $json.mcpServers.PSObject.Properties) {
        $command = [string]$server.Value.command
        if (-not $command) { continue }
        $name = [IO.Path]::GetFileNameWithoutExtension($command).ToLowerInvariant()
        $resolved = if ([IO.Path]::IsPathRooted($command)) { $command } else { (Get-Command $command -ErrorAction SilentlyContinue).Source }
        if (-not $resolved) { Write-Warning "MCP server '$($server.Name)': cannot find $command"; continue }
        if (($launchers -contains $name) -and -not $IncludeLaunchers) {
            Write-Warning "MCP server '$($server.Name)' runs through the generic launcher $resolved; not blocked. Use -IncludeLaunchers to block it for every program it runs."
            continue
        }
        & $add $resolved
    }
}

if ($IncludeToolchains) {
    $dotnet = if ($env:DOTNET_ROOT) { Join-Path $env:DOTNET_ROOT 'dotnet.exe' } else { (Get-Command dotnet -ErrorAction SilentlyContinue).Source }
    & $add $dotnet
    & $add (Get-Command cmake -ErrorAction SilentlyContinue).Source
}
foreach ($extra in $Program) { & $add $extra }

foreach ($path in $programs) {
    New-NetFirewallRule -DisplayName "shgrep egress block: $([IO.Path]::GetFileName($path))" -Group $group `
        -Direction Outbound -Action Block -Program $path -Profile Any -Enabled True | Out-Null
    Write-Output "Blocked outbound: $path"
}

[ordered]@{ created = (Get-Date).ToUniversalTime().ToString('o'); group = $group; programs = @($programs) } |
    ConvertTo-Json | Set-Content -LiteralPath $marker -Encoding utf8
Write-Output "$($programs.Count) programs blocked; record written to $marker"
