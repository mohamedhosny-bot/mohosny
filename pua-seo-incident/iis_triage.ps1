#Requires -Version 5.1
<#
.SYNOPSIS
    READ-ONLY triage of an IIS server for SEO-cloaking malware (BADIIS / GhostRedirector-Gamshen style).

.DESCRIPTION
    Pharos University in Alexandria (PUA) - incident triage for academic.pua.edu.eg,
    portal.pua.edu.eg and www.pua.edu.eg.

    This script NEVER modifies, deletes, stops, starts or uninstalls anything.
    It only reads configuration, files, logs and event logs, and writes its own
    output to C:\PUA-Triage\<hostname>-<timestamp>\ (plus a .zip of that folder).

    Run in an elevated (Administrator) Windows PowerShell 5.1 window:
        Set-ExecutionPolicy -Scope Process Bypass
        .\iis_triage.ps1

    Sections:
      1  IIS global (native) modules + ISAPI filters, signature/hash of every DLL
      2  Sites / applications / virtual directories and web.config modules/handlers
      3  Unsigned DLLs in inetsrv, app \bin folders and the .NET GAC
      4  Script/config/DLL files modified in the last 365 days (+ web-shell pattern scan)
      5  Local users, Administrators, Remote Desktop Users
      6  Non-Microsoft scheduled tasks, services outside C:\Windows
      7  Security/System events 4720, 4732, 4698, 7045 (last 180 days)
      8  Listening TCP ports and owning processes
      9  IIS W3C logs (last 90 days): /Account/Register and /SelfService/* by user-agent class
      10 Local SQL Server: xp_cmdshell state (read-only query of sys.configurations)

.PARAMETER OutputRoot
    Root folder for output. Default C:\PUA-Triage.

.PARAMETER LogDays
    How many days of IIS logs to parse. Default 90.

.NOTES
    Read-only by design. Output only.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = 'C:\PUA-Triage',
    [int]$LogDays = 90,
    [int]$RecentFileDays = 365,
    [int]$EventDays = 180
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------- globals
$script:StartTime = Get-Date
$script:HostName = $env:COMPUTERNAME
$script:OutDir = Join-Path -Path $OutputRoot -ChildPath ('{0}-{1}' -f $script:HostName, $script:StartTime.ToString('yyyyMMdd-HHmmss'))
$script:RedFlags = New-Object System.Collections.Generic.List[string]
$script:ReviewItems = New-Object System.Collections.Generic.List[string]
$script:TriageErrors = New-Object System.Collections.Generic.List[string]
$script:SectionStatus = New-Object System.Collections.Generic.List[string]
$script:SitePaths = New-Object System.Collections.Generic.List[object]   # objects: Site, App, VDir, PhysicalPath
$script:LogDirs = New-Object System.Collections.Generic.List[string]
$script:Windir = $env:windir
$script:Inetsrv = Join-Path -Path $env:windir -ChildPath 'System32\inetsrv'
$script:Inetsrv32 = Join-Path -Path $env:windir -ChildPath 'SysWOW64\inetsrv'
$script:AppCmd = Join-Path -Path $script:Inetsrv -ChildPath 'appcmd.exe'
$script:AppHostConfig = Join-Path -Path $script:Inetsrv -ChildPath 'config\applicationHost.config'
$script:AppHostXml = $null
$script:LogStats = 'not run'
$script:LogSummaryLines = @()
$script:SqlStatus = 'not checked'

$null = [System.IO.Directory]::CreateDirectory($script:OutDir)

# ---------------------------------------------------------------- helpers
function Write-TriageLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    $line = '[{0}] {1}' -f (Get-Date).ToString('HH:mm:ss'), $Message
    Write-Information -MessageData $line -InformationAction Continue
    Add-Content -LiteralPath (Join-Path -Path $script:OutDir -ChildPath 'triage.log') -Value $line -Encoding UTF8
}

function Add-RedFlag {
    param([string]$Category, [string]$Detail)
    $script:RedFlags.Add(('[{0}] {1}' -f $Category, $Detail))
}

function Add-ReviewItem {
    param([string]$Category, [string]$Detail)
    $script:ReviewItems.Add(('[{0}] {1}' -f $Category, $Detail))
}

function Add-TriageError {
    param([string]$Section, [string]$Detail)
    $script:TriageErrors.Add(('[{0}] {1}' -f $Section, $Detail))
    Write-TriageLog -Message ('ERROR in {0}: {1}' -f $Section, $Detail)
}

function Get-OutPath {
    param([Parameter(Mandatory = $true)][string]$Name)
    Join-Path -Path $script:OutDir -ChildPath $Name
}

function Export-TriageCsv {
    param([object[]]$InputData, [string]$Name)
    $path = Get-OutPath -Name $Name
    if ($null -eq $InputData -or @($InputData).Count -eq 0) {
        Set-Content -LiteralPath $path -Value '(no rows)' -Encoding UTF8
    }
    else {
        @($InputData) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    }
}

function Invoke-TriageSection {
    param([string]$Name, [scriptblock]$Body)
    Write-TriageLog -Message ('=== {0} ===' -f $Name)
    $t0 = Get-Date
    try {
        & $Body
        $script:SectionStatus.Add(('OK     {0} ({1:N0}s)' -f $Name, ((Get-Date) - $t0).TotalSeconds))
    }
    catch {
        Add-TriageError -Section $Name -Detail $_.Exception.Message
        $script:SectionStatus.Add(('FAILED {0} - {1}' -f $Name, $_.Exception.Message))
    }
}

function Expand-TriagePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
}

function Get-TriageFileInfo {
    <# Read-only: existence, Authenticode signature, SHA-256, size, timestamps. #>
    param([string]$Path)
    $info = [ordered]@{
        Path              = $Path
        Exists            = $false
        SignatureStatus   = ''
        SignatureType     = ''
        Signer            = ''
        IsMicrosoftSigned = $false
        SHA256            = ''
        Size              = ''
        CreationTime      = ''
        LastWriteTime     = ''
    }
    try {
        if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $info.Exists = $true
            $fi = Get-Item -LiteralPath $Path -Force
            $info.Size = $fi.Length
            $info.CreationTime = $fi.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
            $info.LastWriteTime = $fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            try { $info.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
            catch { $info.SHA256 = 'ERROR: ' + $_.Exception.Message }
            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
                $info.SignatureStatus = [string]$sig.Status
                $info.SignatureType = [string]$sig.SignatureType
                if ($null -ne $sig.SignerCertificate) { $info.Signer = $sig.SignerCertificate.Subject }
                $info.IsMicrosoftSigned = ($sig.Status -eq 'Valid' -and $info.Signer -match 'O=Microsoft Corporation')
            }
            catch { $info.SignatureStatus = 'ERROR: ' + $_.Exception.Message }
        }
    }
    catch { $info.SignatureStatus = 'ERROR: ' + $_.Exception.Message }
    New-Object -TypeName PSObject -Property $info
}

function Invoke-AppCmdList {
    <# Runs only "appcmd list ..." (read-only) and saves raw output. #>
    param([string[]]$Arguments, [string]$OutName)
    if (-not (Test-Path -LiteralPath $script:AppCmd)) {
        Add-TriageError -Section 'appcmd' -Detail ('appcmd.exe not found at ' + $script:AppCmd)
        return
    }
    if ($Arguments[0] -ne 'list') { throw 'Only appcmd list is allowed in this script.' }
    $out = & $script:AppCmd @Arguments 2>&1
    $out | Out-File -LiteralPath (Get-OutPath -Name $OutName) -Encoding UTF8
}

function Get-ExecutablePath {
    <# Extract the executable path from a service PathName / task action. #>
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|dll|sys|bat|cmd|ps1|vbs|js))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

function Test-UnderWindir {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.ToLowerInvariant()
    return ($p.StartsWith($script:Windir.ToLowerInvariant() + '\') -or $p.StartsWith('\systemroot\') -or $p.StartsWith('system32\'))
}

# ---------------------------------------------------------------- start
try { Start-Transcript -LiteralPath (Get-OutPath -Name 'transcript.txt') -ErrorAction Stop | Out-Null } catch { Write-TriageLog -Message ('Transcript not started: ' + $_.Exception.Message) }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Add-TriageError -Section 'startup' -Detail 'Not running as Administrator - many sections will be incomplete. Re-run in an elevated window.'
}
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Add-TriageError -Section 'startup' -Detail '32-bit PowerShell on 64-bit Windows: System32 paths are redirected. Re-run from 64-bit Windows PowerShell.'
}
Write-TriageLog -Message ('PUA IIS triage (READ-ONLY) on {0}; output: {1}' -f $script:HostName, $script:OutDir)

if (Test-Path -LiteralPath $script:AppHostConfig) {
    try { $script:AppHostXml = [xml](Get-Content -LiteralPath $script:AppHostConfig -Raw -ErrorAction Stop) }
    catch { Add-TriageError -Section 'startup' -Detail ('Cannot parse applicationHost.config: ' + $_.Exception.Message) }
}
else {
    Add-TriageError -Section 'startup' -Detail ('applicationHost.config not found - is IIS installed? ' + $script:AppHostConfig)
}

# ================================================================ 1. IIS modules
Invoke-TriageSection -Name '1. IIS global modules' -Body {
    Invoke-AppCmdList -Arguments @('list', 'modules') -OutName '01_appcmd_list_modules.txt'
    Invoke-AppCmdList -Arguments @('list', 'config', '-section:system.webServer/globalModules') -OutName '01_appcmd_globalModules.txt'
    Invoke-AppCmdList -Arguments @('list', 'config', '-section:system.webServer/isapiFilters') -OutName '01_appcmd_isapiFilters.txt'
    Export-TriageCsv -InputData @(Get-TriageFileInfo -Path $script:AppHostConfig) -Name '01_applicationHost_config_file.csv'
    if ($null -eq $script:AppHostXml) { throw 'applicationHost.config not available' }

    $rows = New-Object System.Collections.Generic.List[object]
    $entries = @()
    foreach ($n in @($script:AppHostXml.SelectNodes('/configuration/system.webServer/globalModules/add'))) {
        $entries += [pscustomobject]@{ Kind = 'globalModule'; Name = $n.GetAttribute('name'); Image = $n.GetAttribute('image'); PreCondition = $n.GetAttribute('preCondition') }
    }
    foreach ($n in @($script:AppHostXml.SelectNodes('//isapiFilters/filter'))) {
        $entries += [pscustomobject]@{ Kind = 'isapiFilter'; Name = $n.GetAttribute('name'); Image = $n.GetAttribute('path'); PreCondition = $n.GetAttribute('preCondition') }
    }
    foreach ($e in $entries) {
        $img = Expand-TriagePath -Path $e.Image
        $candidates = @($img)
        # 32-bit worker processes load the SysWOW64 copy of %windir%\system32 paths
        if ($img -match '(?i)\\system32\\') {
            $wow = $img -replace '(?i)\\system32\\', '\SysWOW64\'
            if (Test-Path -LiteralPath $wow) { $candidates += $wow }
        }
        foreach ($c in $candidates) {
            $fi = Get-TriageFileInfo -Path $c
            $row = [pscustomobject]@{
                Kind = $e.Kind; Name = $e.Name; ImageConfigured = $e.Image; PreCondition = $e.PreCondition
                Path = $fi.Path; Exists = $fi.Exists; SignatureStatus = $fi.SignatureStatus; SignatureType = $fi.SignatureType
                Signer = $fi.Signer; IsMicrosoftSigned = $fi.IsMicrosoftSigned; SHA256 = $fi.SHA256; Size = $fi.Size
                CreationTime = $fi.CreationTime; LastWriteTime = $fi.LastWriteTime
            }
            $rows.Add($row)
            if (-not $fi.IsMicrosoftSigned) {
                Add-RedFlag -Category 'IIS MODULE NOT MICROSOFT-SIGNED' -Detail ('{0} "{1}" -> {2} (exists={3}, sig={4}, signer={5}, sha256={6}, modified={7})' -f $e.Kind, $e.Name, $c, $fi.Exists, $fi.SignatureStatus, $fi.Signer, $fi.SHA256, $fi.LastWriteTime)
            }
        }
    }
    Export-TriageCsv -InputData $rows -Name '01_iis_global_modules.csv'
    Write-TriageLog -Message ('{0} global module/ISAPI images checked' -f $rows.Count)
}

# ================================================================ 2. Sites, apps, web.config
Invoke-TriageSection -Name '2. Sites, applications, web.config' -Body {
    Invoke-AppCmdList -Arguments @('list', 'site') -OutName '02_appcmd_list_site.txt'
    Invoke-AppCmdList -Arguments @('list', 'app') -OutName '02_appcmd_list_app.txt'
    Invoke-AppCmdList -Arguments @('list', 'vdir') -OutName '02_appcmd_list_vdir.txt'
    Invoke-AppCmdList -Arguments @('list', 'apppool', '/text:*') -OutName '02_appcmd_list_apppool.txt'
    if ($null -eq $script:AppHostXml) { throw 'applicationHost.config not available' }

    $defaultLogDir = '%SystemDrive%\inetpub\logs\LogFiles'
    $sd = $script:AppHostXml.SelectSingleNode('/configuration/system.applicationHost/sites/siteDefaults/logFile')
    if ($null -ne $sd -and $sd.GetAttribute('directory')) { $defaultLogDir = $sd.GetAttribute('directory') }

    foreach ($site in @($script:AppHostXml.SelectNodes('/configuration/system.applicationHost/sites/site'))) {
        $siteName = $site.GetAttribute('name'); $siteId = $site.GetAttribute('id')
        $logDir = $defaultLogDir
        $lf = $site.SelectSingleNode('logFile')
        if ($null -ne $lf -and $lf.GetAttribute('directory')) { $logDir = $lf.GetAttribute('directory') }
        $logDirFull = Join-Path -Path (Expand-TriagePath -Path $logDir) -ChildPath ('W3SVC' + $siteId)
        if (-not $script:LogDirs.Contains($logDirFull)) { $script:LogDirs.Add($logDirFull) }
        foreach ($app in @($site.SelectNodes('application'))) {
            foreach ($vd in @($app.SelectNodes('virtualDirectory'))) {
                $script:SitePaths.Add([pscustomobject]@{
                        Site = $siteName; SiteId = $siteId; App = $app.GetAttribute('path'); AppPool = $app.GetAttribute('applicationPool')
                        VDir = $vd.GetAttribute('path'); PhysicalPath = (Expand-TriagePath -Path $vd.GetAttribute('physicalPath'))
                        Bindings = (@($site.SelectNodes('bindings/binding') | ForEach-Object { $_.GetAttribute('protocol') + ' ' + $_.GetAttribute('bindingInformation') }) -join '; ')
                        LogDir = $logDirFull
                    })
            }
        }
    }
    Export-TriageCsv -InputData $script:SitePaths -Name '02_sites_apps_vdirs.csv'

    $wcRows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($sp in $script:SitePaths) {
        if (-not $sp.PhysicalPath -or -not (Test-Path -LiteralPath $sp.PhysicalPath)) {
            Add-TriageError -Section '2' -Detail ('Physical path missing: ' + $sp.PhysicalPath)
            continue
        }
        foreach ($wc in @(Get-ChildItem -LiteralPath $sp.PhysicalPath -Filter 'web.config' -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            if ($seen.ContainsKey($wc.FullName)) { continue }
            $seen[$wc.FullName] = $true
            try { $x = [xml](Get-Content -LiteralPath $wc.FullName -Raw -ErrorAction Stop) }
            catch { Add-TriageError -Section '2' -Detail ('Cannot parse ' + $wc.FullName + ': ' + $_.Exception.Message); continue }
            $xpaths = @('//system.webServer/modules/add', '//system.webServer/handlers/add', '//system.web/httpModules/add', '//system.web/httpHandlers/add')
            foreach ($xp in $xpaths) {
                foreach ($n in @($x.SelectNodes($xp))) {
                    $type = $n.GetAttribute('type')
                    $asm = ''; $binDll = ''; $binExists = ''
                    if ($type -match ',') {
                        $asm = ($type -split ',')[1].Trim()
                        $binDll = Join-Path -Path (Join-Path -Path $wc.DirectoryName -ChildPath 'bin') -ChildPath ($asm + '.dll')
                        $binExists = Test-Path -LiteralPath $binDll
                    }
                    $wcRows.Add([pscustomobject]@{
                            WebConfig = $wc.FullName; WebConfigModified = $wc.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); Section = $xp
                            Name = $n.GetAttribute('name'); Type = $type; Path = $n.GetAttribute('path'); Verb = $n.GetAttribute('verb')
                            Modules = $n.GetAttribute('modules'); ScriptProcessor = $n.GetAttribute('scriptProcessor')
                            Assembly = $asm; BinDll = $binDll; BinDllExists = $binExists
                        })
                    $sproc = Expand-TriagePath -Path $n.GetAttribute('scriptProcessor')
                    if ($sproc -and -not (Test-UnderWindir -Path $sproc)) {
                        Add-RedFlag -Category 'WEB.CONFIG HANDLER OUTSIDE WINDOWS' -Detail ('{0}: handler "{1}" scriptProcessor={2}' -f $wc.FullName, $n.GetAttribute('name'), $sproc)
                    }
                    if ($wc.LastWriteTime -gt (Get-Date).AddDays(-$RecentFileDays) -and $type -and $type -notmatch '^(System|Microsoft)\.') {
                        Add-ReviewItem -Category 'CUSTOM MODULE/HANDLER IN RECENTLY MODIFIED WEB.CONFIG' -Detail ('{0}: {1} type={2}' -f $wc.FullName, $n.GetAttribute('name'), $type)
                    }
                }
            }
        }
    }
    Export-TriageCsv -InputData $wcRows -Name '02_webconfig_modules_handlers.csv'
    Write-TriageLog -Message ('{0} vdirs, {1} web.config files, {2} module/handler entries' -f $script:SitePaths.Count, $seen.Count, $wcRows.Count)
}

# ================================================================ 3. Unsigned DLLs
Invoke-TriageSection -Name '3. Unsigned DLLs' -Body {
    $targets = New-Object System.Collections.Generic.List[object]
    $targets.Add([pscustomobject]@{ Area = 'inetsrv64'; Path = $script:Inetsrv })
    $targets.Add([pscustomobject]@{ Area = 'inetsrv32'; Path = $script:Inetsrv32 })
    $targets.Add([pscustomobject]@{ Area = 'GAC'; Path = (Join-Path -Path $env:windir -ChildPath 'Microsoft.NET\assembly') })
    foreach ($sp in $script:SitePaths) {
        if ($sp.PhysicalPath) {
            $bin = Join-Path -Path $sp.PhysicalPath -ChildPath 'bin'
            if (Test-Path -LiteralPath $bin) { $targets.Add([pscustomobject]@{ Area = 'appbin'; Path = $bin }) }
        }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $cut = (Get-Date).AddDays(-$RecentFileDays)
    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t.Path)) { continue }
        Write-TriageLog -Message ('Scanning DLLs in {0} ({1})' -f $t.Path, $t.Area)
        foreach ($f in @(Get-ChildItem -LiteralPath $t.Path -Filter '*.dll' -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            if ($seen.ContainsKey($f.FullName)) { continue }
            $seen[$f.FullName] = $true
            $sig = $null
            try { $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Stop } catch { Add-TriageError -Section '3' -Detail ($f.FullName + ': ' + $_.Exception.Message) }
            if ($null -ne $sig -and $sig.Status -eq 'Valid') { continue }   # only record non-valid signatures
            $fi = Get-TriageFileInfo -Path $f.FullName
            $rows.Add([pscustomobject]@{
                    Area = $t.Area; Path = $f.FullName; SignatureStatus = $fi.SignatureStatus; Signer = $fi.Signer; SHA256 = $fi.SHA256
                    Size = $fi.Size; CreationTime = $fi.CreationTime; LastWriteTime = $fi.LastWriteTime
                })
            if ($t.Area -like 'inetsrv*') {
                Add-RedFlag -Category 'UNSIGNED DLL IN INETSRV' -Detail ('{0} (sig={1}, sha256={2}, created={3}, modified={4})' -f $f.FullName, $fi.SignatureStatus, $fi.SHA256, $fi.CreationTime, $fi.LastWriteTime)
            }
            elseif ($t.Area -eq 'GAC' -and ($f.LastWriteTime -gt $cut -or $f.CreationTime -gt $cut)) {
                Add-RedFlag -Category 'RECENT UNSIGNED DLL IN .NET GAC' -Detail ('{0} (sha256={1}, created={2}, modified={3})' -f $f.FullName, $fi.SHA256, $fi.CreationTime, $fi.LastWriteTime)
            }
            elseif ($t.Area -eq 'appbin' -and ($f.LastWriteTime -gt $cut -or $f.CreationTime -gt $cut)) {
                Add-ReviewItem -Category 'RECENT UNSIGNED DLL IN APP BIN' -Detail ('{0} (modified={1}) - confirm it came from a known deployment' -f $f.FullName, $fi.LastWriteTime)
            }
        }
    }
    Export-TriageCsv -InputData ($rows | Sort-Object -Property LastWriteTime -Descending) -Name '03_unsigned_dlls.csv'
    Write-TriageLog -Message ('{0} DLLs checked, {1} without a valid signature' -f $seen.Count, $rows.Count)
}

# ================================================================ 4. Recently modified files
Invoke-TriageSection -Name '4. Recently modified web files' -Body {
    $ext = @{}
    foreach ($e in @('.aspx', '.ashx', '.asmx', '.asp', '.php', '.config', '.dll', '.js', '.cshtml', '.vbhtml', '.ascx', '.master', '.asax', '.svc')) { $ext[$e] = $true }
    $scriptExt = @{}
    foreach ($e in @('.aspx', '.ashx', '.asmx', '.asp', '.php', '.cshtml', '.vbhtml', '.ascx', '.master', '.asax', '.svc')) { $scriptExt[$e] = $true }
    $shellPattern = '(?i)(eval\s*\(\s*Request|Request\.Item\s*\[|cmd\.exe|ProcessStartInfo|Process\.Start|FromBase64String|xp_cmdshell|WScript\.Shell|System\.Reflection\.Assembly\]::Load|Assembly\.Load\s*\(|base64_decode|shell_exec|passthru|\bsystem\s*\()'
    $cut = (Get-Date).AddDays(-$RecentFileDays)
    $files = @{}
    foreach ($sp in $script:SitePaths) {
        if (-not $sp.PhysicalPath -or -not (Test-Path -LiteralPath $sp.PhysicalPath)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $sp.PhysicalPath -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            if ($ext.ContainsKey($f.Extension.ToLowerInvariant()) -and ($f.LastWriteTime -gt $cut -or $f.CreationTime -gt $cut)) {
                $files[$f.FullName] = $f
            }
        }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    $scriptCount = 0
    foreach ($f in ($files.Values | Sort-Object -Property LastWriteTime -Descending)) {
        $isScript = $scriptExt.ContainsKey($f.Extension.ToLowerInvariant())
        $hit = ''
        if ($isScript -and $f.Length -lt 5MB) {
            try {
                $m = Select-String -LiteralPath $f.FullName -Pattern $shellPattern -List -ErrorAction Stop
                if ($null -ne $m) { $hit = 'line ' + $m.LineNumber + ': ' + $m.Matches[0].Value }
            }
            catch { $hit = 'scan error: ' + $_.Exception.Message }
        }
        $hash = ''
        try { $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $hash = 'ERROR' }
        $rows.Add([pscustomobject]@{
                LastWriteTime = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); CreationTime = $f.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                Path = $f.FullName; Size = $f.Length; Extension = $f.Extension; SHA256 = $hash; SuspiciousPattern = $hit
            })
        if ($isScript) {
            $scriptCount++
            if ($scriptCount -le 100) {
                Add-RedFlag -Category 'RECENTLY MODIFIED SCRIPT FILE' -Detail ('{0} (modified {1}, created {2})' -f $f.FullName, $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $f.CreationTime.ToString('yyyy-MM-dd HH:mm'))
            }
            if ($f.Extension -ieq '.php') {
                Add-RedFlag -Category 'PHP FILE ON ASP.NET SITE' -Detail $f.FullName
            }
        }
        if ($hit -and $hit -notlike 'scan error*') {
            Add-RedFlag -Category 'POSSIBLE WEB SHELL PATTERN' -Detail ('{0} -> {1}' -f $f.FullName, $hit)
        }
    }
    if ($scriptCount -gt 100) {
        Add-RedFlag -Category 'RECENTLY MODIFIED SCRIPT FILE' -Detail ('... and {0} more - see 04_recent_files.csv' -f ($scriptCount - 100))
    }
    Export-TriageCsv -InputData $rows -Name '04_recent_files.csv'
    Write-TriageLog -Message ('{0} recently modified files ({1} script files)' -f $rows.Count, $scriptCount)
}

# ================================================================ 5. Users and groups
Invoke-TriageSection -Name '5. Local users and groups' -Body {
    try {
        $users = @(Get-LocalUser -ErrorAction Stop | Select-Object -Property Name, Enabled, SID, LastLogon, PasswordLastSet, PasswordExpires, Description, PrincipalSource)
        Export-TriageCsv -InputData $users -Name '05_local_users.csv'
        foreach ($u in $users) {
            if ($u.Enabled -and ($u.SID.Value -match '-501$' -or $u.SID.Value -match '-503$')) {
                Add-RedFlag -Category 'BUILT-IN ACCOUNT ENABLED' -Detail ('{0} ({1}) is enabled' -f $u.Name, $u.SID)
            }
            if ($u.PasswordLastSet -and $u.PasswordLastSet -gt (Get-Date).AddDays(-$EventDays)) {
                Add-ReviewItem -Category 'LOCAL USER PASSWORD SET RECENTLY' -Detail ('{0} password set {1}, enabled={2}, last logon {3}' -f $u.Name, $u.PasswordLastSet, $u.Enabled, $u.LastLogon)
            }
        }
    }
    catch { Add-TriageError -Section '5' -Detail ('Get-LocalUser failed (domain controller?): ' + $_.Exception.Message) }

    $groupRows = New-Object System.Collections.Generic.List[object]
    foreach ($g in @(@{ Name = 'Administrators'; Sid = 'S-1-5-32-544' }, @{ Name = 'Remote Desktop Users'; Sid = 'S-1-5-32-555' })) {
        try {
            $members = @(Get-LocalGroupMember -SID $g.Sid -ErrorAction Stop)
            foreach ($m in $members) {
                $groupRows.Add([pscustomobject]@{ Group = $g.Name; Member = $m.Name; Class = [string]$m.ObjectClass; Source = [string]$m.PrincipalSource; SID = [string]$m.SID })
                $isBuiltinAdmin = ([string]$m.SID -match '^S-1-5-21-.*-500$')
                $isDomainAdmins = ([string]$m.SID -match '-512$')
                if (-not $isBuiltinAdmin -and -not $isDomainAdmins) {
                    Add-RedFlag -Category ('MEMBER OF ' + $g.Name.ToUpperInvariant() + ' - CONFIRM EXPECTED') -Detail ('{0} ({1}, {2}, {3})' -f $m.Name, $m.ObjectClass, $m.PrincipalSource, $m.SID)
                }
            }
        }
        catch {
            # Get-LocalGroupMember fails on orphaned SIDs; fall back to net.exe (read-only)
            Add-TriageError -Section '5' -Detail ('Get-LocalGroupMember ' + $g.Name + ' failed: ' + $_.Exception.Message + ' - raw net localgroup output saved instead')
            & net.exe localgroup $g.Name 2>&1 | Out-File -LiteralPath (Get-OutPath -Name ('05_net_localgroup_' + ($g.Name -replace ' ', '_') + '.txt')) -Encoding UTF8
            Add-ReviewItem -Category 'GROUP MEMBERS (RAW)' -Detail ('Check 05_net_localgroup_' + ($g.Name -replace ' ', '_') + '.txt manually')
        }
    }
    Export-TriageCsv -InputData $groupRows -Name '05_group_members.csv'
}

# ================================================================ 6. Tasks and services
Invoke-TriageSection -Name '6. Scheduled tasks and services' -Body {
    $taskRows = New-Object System.Collections.Generic.List[object]
    foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
        $actions = @($t.Actions | ForEach-Object {
                if ($_.PSObject.Properties['Execute'] -and $_.Execute) { ($_.Execute + ' ' + $_.Arguments).Trim() }
                elseif ($_.PSObject.Properties['ClassId']) { 'COM:' + $_.ClassId }
            }) -join ' | '
        $isMs = $t.TaskPath -like '\Microsoft\*'
        $created = ''
        if ($t.PSObject.Properties['Date'] -and $t.Date) { $created = $t.Date }
        $runAs = ''
        if ($null -ne $t.Principal) { $runAs = $t.Principal.UserId }
        $row = [pscustomobject]@{ TaskPath = $t.TaskPath; TaskName = $t.TaskName; State = [string]$t.State; Author = $t.Author; Created = $created; RunAs = $runAs; Actions = $actions }
        if (-not $isMs) {
            $taskRows.Add($row)
            Add-RedFlag -Category 'NON-MICROSOFT SCHEDULED TASK' -Detail ('{0}{1} (author={2}, created={3}, runAs={4}) -> {5}' -f $t.TaskPath, $t.TaskName, $t.Author, $created, $runAs, $actions)
        }
        elseif ($actions -match '(?i)\\(Users|ProgramData|Temp|Public|AppData)\\|powershell.*-enc|mshta|regsvr32|rundll32.*http') {
            $taskRows.Add($row)
            Add-RedFlag -Category 'SUSPICIOUS TASK UNDER \Microsoft\' -Detail ('{0}{1} -> {2}' -f $t.TaskPath, $t.TaskName, $actions)
        }
    }
    Export-TriageCsv -InputData $taskRows -Name '06_scheduled_tasks_nonmicrosoft.csv'

    $svcRows = New-Object System.Collections.Generic.List[object]
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        $exe = Get-ExecutablePath -CommandLine $s.PathName
        if (Test-UnderWindir -Path $exe) { continue }
        $fi = Get-TriageFileInfo -Path $exe
        $svcRows.Add([pscustomobject]@{
                Name = $s.Name; DisplayName = $s.DisplayName; State = $s.State; StartMode = $s.StartMode; Account = $s.StartName
                PathName = $s.PathName; Executable = $exe; SignatureStatus = $fi.SignatureStatus; Signer = $fi.Signer; SHA256 = $fi.SHA256
                Created = $fi.CreationTime; Modified = $fi.LastWriteTime
            })
        if ($fi.Exists -and $fi.SignatureStatus -ne 'Valid') {
            Add-RedFlag -Category 'UNSIGNED SERVICE BINARY OUTSIDE WINDOWS' -Detail ('{0} -> {1} (account={2}, start={3}, sha256={4})' -f $s.Name, $exe, $s.StartName, $s.StartMode, $fi.SHA256)
        }
        if ($exe -match '(?i)\\(Users|ProgramData|Temp|Public|AppData)\\') {
            Add-RedFlag -Category 'SERVICE IN USER/TEMP FOLDER' -Detail ('{0} -> {1}' -f $s.Name, $exe)
        }
        if ($s.Name -match '(?i)anydesk|teamviewer|screenconnect|rustdesk|ngrok|frp|chisel|atera|splashtop|meshagent|simplehelp|tightvnc|ultravnc|radmin') {
            Add-ReviewItem -Category 'REMOTE-ACCESS TOOL SERVICE' -Detail ('{0} -> {1} - confirm IT installed it' -f $s.Name, $exe)
        }
    }
    Export-TriageCsv -InputData $svcRows -Name '06_services_outside_windows.csv'
    Write-TriageLog -Message ('{0} non-Microsoft/suspicious tasks, {1} services outside Windows' -f $taskRows.Count, $svcRows.Count)
}

# ================================================================ 7. Event logs
Invoke-TriageSection -Name '7. Security/System events' -Body {
    $start = (Get-Date).AddDays(-$EventDays)
    $rows = New-Object System.Collections.Generic.List[object]
    $queries = @(
        @{ LogName = 'Security'; Id = @(4720, 4732, 4698) },
        @{ LogName = 'System'; Id = @(7045) }
    )
    foreach ($q in $queries) {
        try {
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $q.LogName; Id = $q.Id; StartTime = $start } -ErrorAction Stop)
            foreach ($e in $ev) {
                $msg = ''
                if ($e.Message) { $msg = ($e.Message -replace '\s+', ' ') }
                if ($msg.Length -gt 1500) { $msg = $msg.Substring(0, 1500) }
                $rows.Add([pscustomobject]@{ TimeCreated = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Log = $q.LogName; Id = $e.Id; Message = $msg })
            }
        }
        catch {
            if ($_.Exception.Message -match 'No events were found') { Write-TriageLog -Message ('No matching events in ' + $q.LogName) }
            else { Add-TriageError -Section '7' -Detail ($q.LogName + ': ' + $_.Exception.Message) }
        }
    }
    Export-TriageCsv -InputData $rows -Name '07_events.csv'
    foreach ($id in @(4720, 4732, 4698, 7045)) {
        $n = @($rows | Where-Object { $_.Id -eq $id }).Count
        if ($n -gt 0) {
            $label = @{ 4720 = 'user account created'; 4732 = 'member added to security-enabled local group'; 4698 = 'scheduled task created'; 7045 = 'new service installed' }[$id]
            Add-ReviewItem -Category ('EVENT ' + $id) -Detail ('{0} x {1} in last {2} days - see 07_events.csv' -f $n, $label, $EventDays)
        }
    }
    $oldest = $null
    try { $oldest = (Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated } catch { Add-TriageError -Section '7' -Detail ('Cannot read oldest Security event: ' + $_.Exception.Message) }
    if ($null -ne $oldest -and $oldest -gt $start) {
        Add-ReviewItem -Category 'SECURITY LOG RETENTION' -Detail ('Oldest Security event is {0} - the log does not cover the full {1} days (it may have rolled over or been cleared; check event 1102)' -f $oldest, $EventDays)
    }
}

# ================================================================ 8. Listening ports
Invoke-TriageSection -Name '8. Listening ports' -Body {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
        $pname = ''; $ppath = ''
        try {
            $p = Get-Process -Id $c.OwningProcess -ErrorAction Stop
            $pname = $p.ProcessName
            try { $ppath = $p.Path } catch { $ppath = '' }
        }
        catch { $pname = '(unknown)' }
        $rows.Add([pscustomobject]@{ LocalAddress = $c.LocalAddress; LocalPort = $c.LocalPort; PID = $c.OwningProcess; Process = $pname; Path = $ppath })
        if ($pname -match '(?i)anydesk|teamviewer|screenconnect|rustdesk|ngrok|frpc|frps|chisel|meshagent|simplehelp|vnc|radmin|plink|socat|nc$|ncat') {
            Add-RedFlag -Category 'REMOTE-ACCESS / TUNNEL TOOL LISTENING' -Detail ('{0} (PID {1}) on {2}:{3} -> {4}' -f $pname, $c.OwningProcess, $c.LocalAddress, $c.LocalPort, $ppath)
        }
        if ($ppath -and $ppath -match '(?i)\\(Users|ProgramData|Temp|Public|AppData)\\') {
            Add-RedFlag -Category 'LISTENER RUNNING FROM USER/TEMP FOLDER' -Detail ('{0} on port {1} -> {2}' -f $pname, $c.LocalPort, $ppath)
        }
    }
    Export-TriageCsv -InputData ($rows | Sort-Object -Property LocalPort) -Name '08_listening_ports.csv'
    if (@($rows | Where-Object { $_.LocalPort -eq 3389 -and $_.LocalAddress -in @('0.0.0.0', '::') }).Count -gt 0) {
        Add-ReviewItem -Category 'RDP LISTENING ON ALL INTERFACES' -Detail 'Port 3389 is listening on all interfaces - confirm it is NOT reachable from the internet (firewall/VPN only)'
    }
}

# ================================================================ 9. IIS logs
Invoke-TriageSection -Name '9. IIS log analysis' -Body {
    if ($script:LogDirs.Count -eq 0) {
        $def = Join-Path -Path $env:SystemDrive -ChildPath 'inetpub\logs\LogFiles'
        if (Test-Path -LiteralPath $def) { foreach ($d in @(Get-ChildItem -LiteralPath $def -Directory)) { $script:LogDirs.Add($d.FullName) } }
    }
    $cut = (Get-Date).AddDays(-$LogDays)
    $agg = @{}           # key: stem|class -> stats
    $redir = New-Object System.Collections.Generic.List[object]
    $redirTotal = 0
    $redirTargets = @{}
    $filesParsed = 0; $linesMatched = 0
    $bytesFieldSeen = $false; $locationFieldSeen = $false
    $dirsFound = New-Object System.Collections.Generic.List[string]

    foreach ($dir in $script:LogDirs) {
        if (-not (Test-Path -LiteralPath $dir)) { Write-TriageLog -Message ('Log dir not found: ' + $dir); continue }
        $dirsFound.Add($dir)
        foreach ($file in @(Get-ChildItem -LiteralPath $dir -Filter '*.log' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $cut } | Sort-Object -Property LastWriteTime)) {
            $filesParsed++
            $idx = @{}
            $fs = $null; $sr = $null
            try {
                # open with FileShare.ReadWrite so the live log (still held by IIS) can be read without locking it
                $fs = New-Object System.IO.FileStream($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $sr = New-Object System.IO.StreamReader($fs)
                while ($null -ne ($line = $sr.ReadLine())) {
                    if ($line.StartsWith('#')) {
                        if ($line.StartsWith('#Fields:')) {
                            $idx = @{}
                            $names = $line.Substring(8).Trim() -split ' '
                            for ($i = 0; $i -lt $names.Count; $i++) { $idx[$names[$i]] = $i }
                            if ($idx.ContainsKey('sc-bytes')) { $bytesFieldSeen = $true }
                            foreach ($k in $idx.Keys) { if ($k -match '(?i)location') { $locationFieldSeen = $true } }
                        }
                        continue
                    }
                    $isTarget = ($line.IndexOf('/Account/Register', [StringComparison]::OrdinalIgnoreCase) -ge 0) -or ($line.IndexOf('/SelfService/', [StringComparison]::OrdinalIgnoreCase) -ge 0)
                    $hasGoogle = $line.IndexOf('google.', [StringComparison]::OrdinalIgnoreCase) -ge 0
                    if (-not $isTarget -and -not $hasGoogle) { continue }
                    if (-not $idx.ContainsKey('cs-uri-stem') -or -not $idx.ContainsKey('sc-status')) { continue }
                    $p = $line.Split(' ')
                    if ($p.Count -ne $idx.Count) { continue }
                    $stem = $p[$idx['cs-uri-stem']]
                    $status = $p[$idx['sc-status']]
                    $ua = ''; if ($idx.ContainsKey('cs(User-Agent)')) { $ua = $p[$idx['cs(User-Agent)']] }
                    $ref = ''; if ($idx.ContainsKey('cs(Referer)')) { $ref = $p[$idx['cs(Referer)']] }
                    $cip = ''; if ($idx.ContainsKey('c-ip')) { $cip = $p[$idx['c-ip']] }
                    if ($ua -match '(?i)Google-InspectionTool') { $cls = 'Google-InspectionTool' }
                    elseif ($ua -match '(?i)Googlebot|AdsBot-Google|Mediapartners-Google|Google-Read-Aloud|GoogleOther') { $cls = 'Googlebot' }
                    elseif ($ua -match '(?i)bot|crawl|spider|slurp|bingpreview|facebookexternalhit|curl|wget|python|java/|go-http|httpclient|scan|semrush|ahrefs|yandex|baidu|petal') { $cls = 'OtherBot' }
                    elseif ($ua -match '(?i)^Mozilla') { $cls = 'Browser' }
                    else { $cls = 'Other/Empty' }

                    $stemL = $stem.ToLowerInvariant()
                    $inScope = $stemL.StartsWith('/account/register') -or $stemL.StartsWith('/selfservice/')
                    if ($inScope) {
                        $linesMatched++
                        $key = $stemL + '|' + $cls
                        if (-not $agg.ContainsKey($key)) {
                            $agg[$key] = @{ Stem = $stemL; Class = $cls; Count = 0; Status = @{}; BytesSum = [double]0; BytesN = 0; From66249 = 0 }
                        }
                        $a = $agg[$key]
                        $a.Count++
                        if ($a.Status.ContainsKey($status)) { $a.Status[$status]++ } else { $a.Status[$status] = 1 }
                        if ($idx.ContainsKey('sc-bytes')) {
                            $b = 0.0
                            if ([double]::TryParse($p[$idx['sc-bytes']], [ref]$b)) { $a.BytesSum += $b; $a.BytesN++ }
                        }
                        if ($cip.StartsWith('66.249.')) { $a.From66249++ }
                    }
                    if ($status.StartsWith('3') -and $ref -match '(?i)google\.') {
                        $redirTotal++
                        $loc = ''
                        foreach ($k in $idx.Keys) { if ($k -match '(?i)location') { $loc = $p[$idx[$k]] } }
                        $tk = $stemL + ' -> ' + $(if ($loc) { $loc } else { '(target not logged)' })
                        if ($redirTargets.ContainsKey($tk)) { $redirTargets[$tk]++ } else { $redirTargets[$tk] = 1 }
                        if ($redir.Count -lt 5000) {
                            $date = ''; if ($idx.ContainsKey('date') -and $idx.ContainsKey('time')) { $date = $p[$idx['date']] + ' ' + $p[$idx['time']] }
                            $redir.Add([pscustomobject]@{ DateTime = $date; Stem = $stem; Status = $status; Referer = $ref; UAClass = $cls; ClientIP = $cip; Location = $loc; LogFile = $file.FullName })
                        }
                    }
                }
            }
            catch { Add-TriageError -Section '9' -Detail ($file.FullName + ': ' + $_.Exception.Message) }
            finally {
                if ($null -ne $sr) { $sr.Dispose() }
                if ($null -ne $fs) { $fs.Dispose() }
            }
        }
    }

    $rows = foreach ($a in $agg.Values) {
        $avg = ''
        if ($a.BytesN -gt 0) { $avg = [math]::Round($a.BytesSum / $a.BytesN, 0) }
        [pscustomobject]@{
            Stem = $a.Stem; UAClass = $a.Class; Count = $a.Count
            StatusCodes = (($a.Status.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { $_.Name + '=' + $_.Value }) -join ' ')
            AvgScBytes = $(if ($bytesFieldSeen) { $avg } else { 'sc-bytes not logged' })
            GooglebotFrom66_249 = $a.From66249
        }
    }
    Export-TriageCsv -InputData ($rows | Sort-Object -Property Stem, UAClass) -Name '09_iis_log_target_paths.csv'
    Export-TriageCsv -InputData $redir -Name '09_iis_log_3xx_google_referer.csv'
    $rt = foreach ($kv in ($redirTargets.GetEnumerator() | Sort-Object -Property Value -Descending)) { [pscustomobject]@{ StemToTarget = $kv.Key; Count = $kv.Value } }
    Export-TriageCsv -InputData $rt -Name '09_iis_log_3xx_google_referer_targets.csv'

    # Class totals per path group, and Googlebot vs Browser byte comparison (core cloaking evidence)
    $groupLines = New-Object System.Collections.Generic.List[string]
    foreach ($grp in @('/account/register', '/selfservice/')) {
        foreach ($cls in @('Googlebot', 'Google-InspectionTool', 'OtherBot', 'Browser', 'Other/Empty')) {
            $sel = @($agg.Values | Where-Object { $_.Stem.StartsWith($grp) -and $_.Class -eq $cls })
            if ($sel.Count -eq 0) { continue }
            $cnt = ($sel | Measure-Object -Property Count -Sum).Sum
            $bs = ($sel | ForEach-Object { $_.BytesSum } | Measure-Object -Sum).Sum
            $bn = ($sel | ForEach-Object { $_.BytesN } | Measure-Object -Sum).Sum
            $st = @{}
            foreach ($s in $sel) { foreach ($kv in $s.Status.GetEnumerator()) { if ($st.ContainsKey($kv.Key)) { $st[$kv.Key] += $kv.Value } else { $st[$kv.Key] = $kv.Value } } }
            $avgTxt = 'sc-bytes not logged'
            if ($bytesFieldSeen -and $bn -gt 0) { $avgTxt = [string][math]::Round($bs / $bn, 0) }
            $groupLines.Add(('{0,-20} {1,-22} requests={2,-8} avg sc-bytes={3,-12} status: {4}' -f ($grp + '*'), $cls, $cnt, $avgTxt, (($st.GetEnumerator() | Sort-Object -Property Name | ForEach-Object { $_.Name + '=' + $_.Value }) -join ' ')))
        }
    }
    $groupLines | Out-File -LiteralPath (Get-OutPath -Name '09_iis_log_summary.txt') -Encoding UTF8
    $script:LogSummaryLines = $groupLines

    if ($bytesFieldSeen) {
        $stems = @($agg.Values | ForEach-Object { $_.Stem } | Sort-Object -Unique)
        foreach ($s in $stems) {
            $g = $agg[$s + '|Googlebot']; $b = $agg[$s + '|Browser']
            if ($null -ne $g -and $null -ne $b -and $g.BytesN -ge 10 -and $b.BytesN -ge 10) {
                $ga = $g.BytesSum / $g.BytesN; $ba = $b.BytesSum / $b.BytesN
                if ($ba -gt 0 -and [math]::Abs($ga - $ba) / $ba -gt 0.30) {
                    Add-RedFlag -Category 'GOOGLEBOT GETS DIFFERENT-SIZE RESPONSES (CLOAKING EVIDENCE)' -Detail ('{0}: Googlebot avg {1:N0} bytes (n={2}) vs browsers avg {3:N0} bytes (n={4})' -f $s, $ga, $g.BytesN, $ba, $b.BytesN)
                }
            }
        }
    }
    else {
        Add-ReviewItem -Category 'IIS LOGGING' -Detail 'sc-bytes is NOT logged - enable "Bytes Sent (sc-bytes)" in IIS Logging fields so Googlebot vs browser response sizes can be compared'
    }
    if (-not $locationFieldSeen) {
        Add-ReviewItem -Category 'IIS LOGGING' -Detail 'Redirect target (Location) is not logged - 3xx targets cannot be reported; only the requested path is shown'
    }
    if ($redirTotal -gt 0) {
        Add-ReviewItem -Category '3XX WITH GOOGLE REFERER' -Detail ('{0} redirects of visitors arriving from google.* - see 09_iis_log_3xx_google_referer_targets.csv (normal login redirects are expected; redirects to other domains are not)' -f $redirTotal)
    }
    $script:LogStats = 'log dirs found: {0}; files parsed (last {1} days): {2}; target-path requests: {3}; 3xx with google referer: {4}; sc-bytes logged: {5}' -f $dirsFound.Count, $LogDays, $filesParsed, $linesMatched, $redirTotal, $bytesFieldSeen
    Write-TriageLog -Message $script:LogStats
}

# ================================================================ 10. SQL Server
Invoke-TriageSection -Name '10. Local SQL Server (read-only)' -Body {
    $instKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    if (-not (Test-Path -LiteralPath $instKey)) {
        Write-TriageLog -Message 'No local SQL Server instance found - skipped'
        $script:SqlStatus = 'No local SQL Server instance found'
        return
    }
    $instances = @((Get-Item -LiteralPath $instKey).Property)
    $rows = New-Object System.Collections.Generic.List[object]
    $status = New-Object System.Collections.Generic.List[string]
    # sys.configurations is the catalog view that sp_configure reads; SELECT-only, nothing is changed.
    $queries = [ordered]@{
        'configurations' = "SELECT name, CAST(value AS int) AS value, CAST(value_in_use AS int) AS value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','show advanced options','Ole Automation Procedures','clr enabled','Ad Hoc Distributed Queries')"
        'sysadmins'      = "SELECT p.name, p.type_desc, p.create_date, p.modify_date, p.is_disabled FROM sys.server_principals p JOIN sys.server_role_members m ON m.member_principal_id = p.principal_id JOIN sys.server_principals r ON r.principal_id = m.role_principal_id WHERE r.name = 'sysadmin'"
        'recent_logins'  = "SELECT name, type_desc, create_date, modify_date, is_disabled FROM sys.server_principals WHERE type IN ('S','U','G') AND create_date > DATEADD(day, -365, GETDATE())"
        'recent_jobs'    = "SELECT j.name, j.enabled, j.date_created, j.date_modified, s.command FROM msdb.dbo.sysjobs j LEFT JOIN msdb.dbo.sysjobsteps s ON s.job_id = j.job_id WHERE j.date_modified > DATEADD(day, -365, GETDATE())"
    }
    foreach ($inst in $instances) {
        $server = 'localhost'
        if ($inst -ne 'MSSQLSERVER') { $server = 'localhost\' + $inst }
        $conn = $null
        try {
            $conn = New-Object System.Data.SqlClient.SqlConnection(('Server={0};Database=master;Integrated Security=SSPI;Connect Timeout=5;Application Name=PUA-Triage-ReadOnly;ApplicationIntent=ReadOnly' -f $server))
            $conn.Open()
            foreach ($qn in $queries.Keys) {
                try {
                    $cmd = $conn.CreateCommand()
                    $cmd.CommandText = $queries[$qn]
                    $cmd.CommandTimeout = 15
                    $rd = $cmd.ExecuteReader()
                    while ($rd.Read()) {
                        $vals = @()
                        for ($i = 0; $i -lt $rd.FieldCount; $i++) { $vals += ($rd.GetName($i) + '=' + [string]$rd.GetValue($i)) }
                        $line = $vals -join '; '
                        $rows.Add([pscustomobject]@{ Instance = $server; Query = $qn; Row = $line })
                        if ($qn -eq 'configurations' -and $rd['name'] -eq 'xp_cmdshell') {
                            if ([int]$rd['value_in_use'] -eq 1) { Add-RedFlag -Category 'SQL XP_CMDSHELL ENABLED' -Detail ($server + ': xp_cmdshell value_in_use=1') }
                            $status.Add(('{0}: xp_cmdshell value={1} value_in_use={2}' -f $server, $rd['value'], $rd['value_in_use']))
                        }
                        if ($qn -eq 'recent_logins') { Add-ReviewItem -Category 'SQL LOGIN CREATED IN LAST 365 DAYS' -Detail ($server + ': ' + $line) }
                        if ($qn -eq 'recent_jobs') { Add-ReviewItem -Category 'SQL AGENT JOB CHANGED IN LAST 365 DAYS' -Detail ($server + ': ' + $line) }
                    }
                    $rd.Close()
                }
                catch { Add-TriageError -Section '10' -Detail ('{0} query {1}: {2}' -f $server, $qn, $_.Exception.Message) }
            }
        }
        catch {
            $status.Add(('{0}: no access ({1}) - skipped' -f $server, $_.Exception.Message))
            Write-TriageLog -Message ('SQL {0}: cannot connect - skipped' -f $server)
        }
        finally { if ($null -ne $conn) { $conn.Dispose() } }
    }
    Export-TriageCsv -InputData $rows -Name '10_sql_checks.csv'
    $script:SqlStatus = ($status -join '; ')
}

# ================================================================ summary
$summaryPath = Get-OutPath -Name 'summary.txt'
$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine('PUA IIS TRIAGE SUMMARY (READ-ONLY)')
$null = $sb.AppendLine('==================================')
$null = $sb.AppendLine(('Host: {0}   Started: {1}   Finished: {2}' -f $script:HostName, $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'), (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')))
$null = $sb.AppendLine(('User: {0}   Administrator: {1}   PowerShell: {2}' -f [Security.Principal.WindowsIdentity]::GetCurrent().Name, $isAdmin, $PSVersionTable.PSVersion))
try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop; $null = $sb.AppendLine(('OS: {0} {1} (last boot {2})' -f $os.Caption, $os.Version, $os.LastBootUpTime)) } catch { $null = $sb.AppendLine('OS: unknown') }
$null = $sb.AppendLine('')
$null = $sb.AppendLine(('=== RED FLAGS ({0}) ===' -f $script:RedFlags.Count))
if ($script:RedFlags.Count -eq 0) { $null = $sb.AppendLine('None detected by automated checks (this does NOT prove the server is clean).') }
foreach ($r in ($script:RedFlags | Sort-Object)) { $null = $sb.AppendLine(' ! ' + $r) }
$null = $sb.AppendLine('')
$null = $sb.AppendLine(('=== ITEMS TO REVIEW ({0}) ===' -f $script:ReviewItems.Count))
foreach ($r in ($script:ReviewItems | Sort-Object)) { $null = $sb.AppendLine(' - ' + $r) }
$null = $sb.AppendLine('')
$null = $sb.AppendLine('=== IIS LOGS: /Account/Register and /SelfService/* BY USER-AGENT CLASS ===')
$null = $sb.AppendLine($script:LogStats)
foreach ($l in $script:LogSummaryLines) { $null = $sb.AppendLine('  ' + $l) }
$null = $sb.AppendLine('  (A large Googlebot-vs-Browser difference in avg sc-bytes on the same path is strong evidence of cloaking.)')
$null = $sb.AppendLine('')
$null = $sb.AppendLine('=== SQL SERVER ===')
$null = $sb.AppendLine($script:SqlStatus)
$null = $sb.AppendLine('')
$null = $sb.AppendLine('=== SECTION STATUS ===')
foreach ($s in $script:SectionStatus) { $null = $sb.AppendLine(' ' + $s) }
$null = $sb.AppendLine('')
$null = $sb.AppendLine(('=== ERRORS ({0}) ===' -f $script:TriageErrors.Count))
foreach ($e in $script:TriageErrors) { $null = $sb.AppendLine(' ' + $e) }
$null = $sb.AppendLine('')
$null = $sb.AppendLine('=== FILES ===')
foreach ($f in @(Get-ChildItem -LiteralPath $script:OutDir -File | Sort-Object -Property Name)) { $null = $sb.AppendLine(' ' + $f.Name) }
$null = $sb.AppendLine(' summary.txt')
Set-Content -LiteralPath $summaryPath -Value $sb.ToString() -Encoding UTF8

try { Stop-Transcript | Out-Null } catch { Write-TriageLog -Message 'Transcript was not running' }

$zip = $script:OutDir + '.zip'
try {
    Compress-Archive -LiteralPath $script:OutDir -DestinationPath $zip -ErrorAction Stop
    Write-TriageLog -Message ('Zipped output: ' + $zip)
}
catch { Write-TriageLog -Message ('Could not create zip (send the folder instead): ' + $_.Exception.Message) }

Write-Output ''
Write-Output ('Done. RED FLAGS: {0}   Review items: {1}   Errors: {2}' -f $script:RedFlags.Count, $script:ReviewItems.Count, $script:TriageErrors.Count)
Write-Output ('Summary: ' + $summaryPath)
Write-Output ('Send this file to the incident team: ' + $zip)
