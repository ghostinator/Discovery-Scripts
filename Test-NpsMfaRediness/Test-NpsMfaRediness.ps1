<#
.SYNOPSIS
    Read-only readiness assessment for Windows NPS (RADIUS) and the Microsoft
    Entra / Azure MFA NPS Extension.

.DESCRIPTION
    Determines whether an NPS server is genuinely enforcing MFA, rather than
    merely having the extension installed. "Installed" and "functioning" are
    different states with different failure modes, so the script evaluates five
    independent gates:

        1. Installed        - package and binaries present on disk
        2. Registered       - extension hooked into NPS via AuthSrv
        3. Tenant-bound     - TENANT_ID populated (config setup completed)
        4. Certificate      - client certificate present, valid, not expired
        5. In use           - recent authentication activity in the event logs

    A server can pass 1-4 and still fail 5, which means MFA is configured but no
    traffic is actually authenticating through it. That distinction matters when
    scoping migrations, so it is reported explicitly.

    The script also collects supporting context commonly needed when replacing a
    firewall, VPN concentrator, or wireless controller that authenticates
    against NPS: RADIUS clients, network policies, listener ports, firewall
    rules, outbound connectivity to the MFA service, TLS posture, DHCP scopes,
    and VPN-related AD group membership.

    READ-ONLY. The script installs nothing, starts or stops nothing, and changes
    no configuration. It writes a transcript and a JSON summary to the output
    folder and nothing else.

    SECURITY: RADIUS shared secrets are never read or exported. The script
    reports that a client exists, not its secret. Do not substitute
    'netsh nps export' unless you intend to handle secrets accordingly.

.PARAMETER OutputPath
    Folder for the transcript and JSON summary. Created if absent.
    Default: C:\Discovery\NpsMfaReadiness

.PARAMETER EventLookbackDays
    Days of NPS and MFA event history to summarize. Default: 30.

.PARAMETER ExpectedRadiusClient
    One or more IP addresses or names expected to already exist as RADIUS
    clients, typically the device being replaced. Each is reported as found or
    missing. Optional.

.PARAMETER ExpectedVpnUserCount
    The user count assumed by your scope or statement of work. Compared against
    actual VPN-related AD group membership and flagged on mismatch. Optional.

.PARAMETER VpnGroupFilter
    Wildcard patterns used to locate VPN-related AD groups.
    Default: '*VPN*', '*RemoteAccess*', '*RAS*'

.PARAMETER MfaEndpoint
    Endpoints tested for outbound HTTPS reachability. Defaults to the current
    Entra MFA service set. Override for sovereign or government clouds.

.PARAMETER SkipConnectivity
    Skip outbound HTTPS tests. Use on isolated or egress-restricted hosts.

.PARAMETER SkipAD
    Skip Active Directory group enumeration.

.PARAMETER SkipDhcp
    Skip DHCP scope enumeration.

.PARAMETER Organization
    Label printed in the report header. Cosmetic only.

.PARAMETER Quiet
    Suppress console output. The transcript and JSON are still written.

.PARAMETER PassThru
    Emit the findings object to the pipeline for further processing.

.INPUTS
    None.

.OUTPUTS
    PSCustomObject when -PassThru is specified. Otherwise console output plus
    a .txt transcript and .json summary in OutputPath.

.EXAMPLE
    .\Test-NpsMfaReadiness.ps1

    Runs all checks with defaults.

.EXAMPLE
    .\Test-NpsMfaReadiness.ps1 -ExpectedRadiusClient '10.0.0.1' -ExpectedVpnUserCount 15

    Verifies a specific RADIUS client exists and compares AD group membership
    against an assumed user count.

.EXAMPLE
    .\Test-NpsMfaReadiness.ps1 -SkipConnectivity -SkipAD -Quiet -PassThru |
        Select-Object -ExpandProperty Verdict

    Minimal offline run returning only the verdict string.

.EXAMPLE
    Invoke-Command -ComputerName NPS01 -FilePath .\Test-NpsMfaReadiness.ps1

    Remote execution. Note that output files are written on the remote host.

.NOTES
    Requires    : Windows Server 2012 R2 or later, PowerShell 5.1 or later
    Privileges  : Elevated session. AD and DHCP checks need the matching RSAT
                  modules; they are skipped gracefully when unavailable.
    License     : MIT
    Version     : 2.0.0

.LINK
    https://learn.microsoft.com/entra/identity/authentication/howto-mfa-nps-extension
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string] $OutputPath = 'C:\Discovery\NpsMfaReadiness',

    [ValidateRange(1, 365)]
    [int] $EventLookbackDays = 30,

    [string[]] $ExpectedRadiusClient,

    [ValidateRange(0, 100000)]
    [int] $ExpectedVpnUserCount,

    [string[]] $VpnGroupFilter = @('*VPN*', '*RemoteAccess*', '*RAS*'),

    [string[]] $MfaEndpoint = @(
        'login.microsoftonline.com',
        'adnotifications.windowsazure.com',
        'strongauthenticationservice.auth.microsoft.com',
        'credentials.azure.com'
    ),

    [switch] $SkipConnectivity,
    [switch] $SkipAD,
    [switch] $SkipDhcp,

    [string] $Organization = 'Organization',

    [switch] $Quiet,
    [switch] $PassThru
)

#region ------------------------------------------------------- Initialization

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$script:Findings = [ordered]@{}
$script:Flags    = New-Object System.Collections.Generic.List[object]

# Constants
$script:ExtensionDllName = 'AzureMfaAuthenticationExtension.dll'
$script:AuthSrvKey       = 'HKLM:\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters'
$script:AzureMfaKey      = 'HKLM:\SOFTWARE\Microsoft\AzureMfa'
$script:NpsAuthEventIds  = @(6272, 6273, 6274, 6278)
$script:CertWarnDays     = 60

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$stamp          = Get-Date -Format 'yyyyMMdd-HHmmss'
$baseName       = "$env:COMPUTERNAME-NpsMfaReadiness-$stamp"
$transcriptFile = Join-Path $OutputPath "$baseName.txt"
$jsonFile       = Join-Path $OutputPath "$baseName.json"

try { Start-Transcript -Path $transcriptFile -Force | Out-Null } catch { }

#endregion

#region ----------------------------------------------------------- Helpers

function Write-Section {
    param([Parameter(Mandatory)][string] $Title)
    if ($Quiet) { return }
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function Write-Result {
    param(
        [Parameter(Mandatory)][string] $Label,
        [string] $Value = '',
        [ValidateSet('Pass', 'Fail', 'Warn', 'Info')]
        [string] $State = 'Info'
    )
    if ($Quiet) { return }
    $map = @{
        Pass = @{ Tag = '[ PASS ]'; Color = 'Green'  }
        Fail = @{ Tag = '[ FAIL ]'; Color = 'Red'    }
        Warn = @{ Tag = '[ WARN ]'; Color = 'Yellow' }
        Info = @{ Tag = '[ INFO ]'; Color = 'Gray'   }
    }
    Write-Host ("{0} {1,-46} {2}" -f $map[$State].Tag, $Label, $Value) -ForegroundColor $map[$State].Color
}

function Write-Table {
    param($InputObject, [string] $Caption)
    if ($Quiet -or -not $InputObject) { return }
    if ($Caption) {
        Write-Host ''
        Write-Host "  $Caption" -ForegroundColor DarkCyan
    }
    $InputObject | Format-Table -AutoSize | Out-String | Write-Host
}

function Add-Flag {
    param(
        [Parameter(Mandatory)][ValidateSet('Blocker', 'Risk', 'Note')]
        [string] $Severity,
        [Parameter(Mandatory)][string] $Message
    )
    $script:Flags.Add([pscustomobject]@{ Severity = $Severity; Message = $Message })
}

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CommandExists {
    param([Parameter(Mandatory)][string] $Name)
    [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

# Wraps a scriptblock so that expected failures never surface as noise in the
# transcript. Returns $null on failure rather than throwing.
function Invoke-Safely {
    param(
        [Parameter(Mandatory)][scriptblock] $ScriptBlock,
        [string] $ErrorLabel
    )
    $prior = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        & $ScriptBlock
    }
    catch {
        if ($ErrorLabel) { Write-Verbose "$ErrorLabel : $($_.Exception.Message)" }
        $null
    }
    finally {
        $ErrorActionPreference = $prior
    }
}

# Event logs that do not exist raise terminating errors that pollute the
# transcript. Check existence first.
function Test-EventLogExists {
    param([Parameter(Mandatory)][string] $LogName)
    [bool](Invoke-Safely { Get-WinEvent -ListLog $LogName } -ErrorLabel "ListLog $LogName")
}

# ConvertTo-Json serializes IPAddress, TimeSpan and DateTime into large nested
# objects. Flatten them so the JSON stays readable and diffable.
function ConvertTo-Flat {
    param($Value)
    if ($null -eq $Value) { return $null }
    switch ($Value.GetType().Name) {
        'IPAddress' { return $Value.IPAddressToString }
        'TimeSpan'  { return $Value.ToString() }
        'DateTime'  { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
        default     { return $Value }
    }
}

function ConvertTo-FlatRecord {
    param([Parameter(Mandatory)] $InputObject, [Parameter(Mandatory)][string[]] $Property)
    $out = [ordered]@{}
    foreach ($p in $Property) {
        $raw = if ($InputObject.PSObject.Properties.Name -contains $p) { $InputObject.$p } else { $null }
        $out[$p] = ConvertTo-Flat $raw
    }
    [pscustomobject]$out
}

#endregion

#region ------------------------------------------------------------ Header

Write-Section "NPS / ENTRA MFA EXTENSION READINESS CHECK - $Organization"
if (-not $Quiet) {
    Write-Host "  Run time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "  Host     : $env:COMPUTERNAME"
    Write-Host "  User     : $env:USERDOMAIN\$env:USERNAME"
    Write-Host "  Output   : $OutputPath"
    Write-Host "  Mode     : READ-ONLY (no changes will be made)"
}

$elevated = Test-IsElevated
if ($elevated) {
    Write-Result 'Elevated session' 'Yes' 'Pass'
} else {
    Write-Result 'Elevated session' 'NO - re-run as Administrator' 'Fail'
    Add-Flag -Severity 'Blocker' -Message 'Script was not run elevated. Registry, certificate and event log results will be incomplete or misleading.'
}

#endregion

#region ------------------------------------------- 1. Server identity / roles

Write-Section '1. SERVER IDENTITY AND ROLE INVENTORY'

$os = Invoke-Safely { Get-CimInstance Win32_OperatingSystem }
$cs = Invoke-Safely { Get-CimInstance Win32_ComputerSystem }

$ipv4 = @(
    Invoke-Safely { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' } |
    ForEach-Object { $_.IPAddress } |
    Where-Object { $_ -and $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }
)

$server = [ordered]@{
    ComputerName    = $env:COMPUTERNAME
    Domain          = if ($cs) { $cs.Domain } else { $null }
    OperatingSystem = if ($os) { $os.Caption } else { $null }
    Version         = if ($os) { $os.Version } else { $null }
    BuildNumber     = if ($os) { $os.BuildNumber } else { $null }
    LastBootUpTime  = if ($os) { ConvertTo-Flat $os.LastBootUpTime } else { $null }
    UptimeDays      = if ($os -and $os.LastBootUpTime) {
                          [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
                      } else { $null }
    IPv4Addresses   = $ipv4
    PSVersion       = $PSVersionTable.PSVersion.ToString()
    Elevated        = $elevated
}

Write-Result 'Operating system' "$($server.OperatingSystem) (build $($server.BuildNumber))"
Write-Result 'Domain'           "$($server.Domain)"
Write-Result 'IPv4'             ($ipv4 -join ', ')
Write-Result 'Uptime (days)'    "$($server.UptimeDays)"

$roles = @()
if (Test-CommandExists 'Get-WindowsFeature') {
    $roles = @(
        Invoke-Safely { Get-WindowsFeature } |
        Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } |
        Select-Object -ExpandProperty Name
    )
    Write-Result 'Installed roles' ($roles -join ', ')
}
$server.InstalledRoles = $roles

# NPAS role
$npsFeature   = Invoke-Safely { Get-WindowsFeature -Name 'NPAS' }
$npsInstalled = [bool]($npsFeature -and $npsFeature.Installed)
if ($npsInstalled) {
    Write-Result 'Network Policy Server (NPAS) role' 'Installed' 'Pass'
} else {
    Write-Result 'Network Policy Server (NPAS) role' 'NOT installed' 'Fail'
    Add-Flag -Severity 'Blocker' -Message 'The NPAS role is not installed. This host cannot serve RADIUS authentication without additional scope.'
}
$server.NpasRoleInstalled = $npsInstalled

# IAS service (displayed as "Network Policy Server")
$ias      = Get-Service -Name 'IAS' -ErrorAction SilentlyContinue
$iasStart = Invoke-Safely { (Get-CimInstance Win32_Service -Filter "Name='IAS'").StartMode }
if ($ias) {
    $state = "$($ias.Status) / StartType=$iasStart"
    if ($ias.Status -eq 'Running') {
        Write-Result 'NPS service (IAS)' $state 'Pass'
    } else {
        Write-Result 'NPS service (IAS)' $state 'Fail'
        Add-Flag -Severity 'Blocker' -Message "The NPS service (IAS) is not running. Current state: $($ias.Status)."
    }
} else {
    Write-Result 'NPS service (IAS)' 'Not present' 'Fail'
    Add-Flag -Severity 'Blocker' -Message 'The NPS service (IAS) was not found on this host.'
}
$server.IasServiceStatus    = if ($ias) { $ias.Status.ToString() } else { 'NotPresent' }
$server.IasServiceStartMode = $iasStart

$script:Findings.Server = $server

#endregion

#region --------------------------------------------- 2. Extension installation

Write-Section '2. ENTRA / AZURE MFA NPS EXTENSION - INSTALLATION'

$mfa = [ordered]@{}

$uninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$mfaProduct = @(
    Invoke-Safely { Get-ItemProperty -Path $uninstallPaths } |
    Where-Object {
        $_.PSObject.Properties.Name -contains 'DisplayName' -and
        ($_.DisplayName -like '*NPS Extension for Azure MFA*' -or
         $_.DisplayName -like '*NPS Extension for Microsoft Entra*' -or
         $_.DisplayName -like '*Azure Multi-Factor Authentication NPS*')
    }
) | Select-Object -First 1

if ($mfaProduct) {
    Write-Result 'Extension package installed' "$($mfaProduct.DisplayName) v$($mfaProduct.DisplayVersion)" 'Pass'
    $mfa.ProductName    = $mfaProduct.DisplayName
    $mfa.ProductVersion = $mfaProduct.DisplayVersion
    $mfa.InstallDate    = $mfaProduct.InstallDate
} else {
    Write-Result 'Extension package installed' 'NOT FOUND' 'Fail'
    $mfa.ProductName = $null
    Add-Flag -Severity 'Blocker' -Message 'No uninstall entry for the MFA NPS Extension was found. The extension is not installed. Any assumption that MFA is enforced here is invalid.'
}

$dllCandidates = @(
    "C:\Program Files\Microsoft\AzureMfa\RADIUS\$script:ExtensionDllName",
    "$env:SystemRoot\System32\$script:ExtensionDllName"
)
$foundDlls = @()
foreach ($path in $dllCandidates) {
    if (Test-Path -LiteralPath $path) {
        $file = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($file) {
            $foundDlls += [pscustomobject]@{
                Path          = $path
                FileVersion   = $file.VersionInfo.FileVersion
                LastWriteTime = ConvertTo-Flat $file.LastWriteTime
            }
        }
    }
}
if ($foundDlls.Count -gt 0) {
    foreach ($dll in $foundDlls) {
        Write-Result 'Extension DLL present' "$($dll.Path) (v$($dll.FileVersion))" 'Pass'
    }
} else {
    Write-Result 'Extension DLL present' 'NOT FOUND in expected paths' 'Fail'
    Add-Flag -Severity 'Blocker' -Message "$script:ExtensionDllName was not found in any expected install path."
}
$mfa.Binaries = $foundDlls

$setupScript = 'C:\Program Files\Microsoft\AzureMfa\Config\AzureMfaNpsExtnConfigSetup.ps1'
$mfa.ConfigSetupScriptPresent = Test-Path -LiteralPath $setupScript
Write-Result 'Config setup script present' "$($mfa.ConfigSetupScriptPresent)"

#endregion

#region ------------------------------------------- 3. Registration with NPS

Write-Section '3. EXTENSION REGISTRATION WITH NPS (AuthSrv)'

$authSrv  = Invoke-Safely { Get-ItemProperty -Path $script:AuthSrvKey }
$authDlls = @()
$extDlls  = @()
if ($authSrv) {
    if ($authSrv.PSObject.Properties.Name -contains 'AuthorizationDLLs') {
        $authDlls = @($authSrv.AuthorizationDLLs) | Where-Object { $_ }
    }
    if ($authSrv.PSObject.Properties.Name -contains 'ExtensionDLLs') {
        $extDlls = @($authSrv.ExtensionDLLs) | Where-Object { $_ }
    }
}

$pattern    = [regex]::Escape($script:ExtensionDllName)
$authHooked = (($authDlls -join ';') -match $pattern)
$extHooked  = (($extDlls  -join ';') -match $pattern)

if ($authHooked) {
    Write-Result 'AuthorizationDLLs hooked' "$script:ExtensionDllName registered" 'Pass'
} else {
    Write-Result 'AuthorizationDLLs hooked' 'Extension NOT registered' 'Fail'
    Add-Flag -Severity 'Blocker' -Message 'AuthSrv AuthorizationDLLs does not reference the MFA extension. NPS will authenticate without ever invoking MFA, even if the package is installed.'
}
if ($extHooked) {
    Write-Result 'ExtensionDLLs hooked' "$script:ExtensionDllName registered" 'Pass'
} else {
    Write-Result 'ExtensionDLLs hooked' 'Extension NOT registered' 'Warn'
}

$script:Findings.AuthSrv = [ordered]@{
    AuthorizationDLLs = $authDlls
    ExtensionDLLs     = $extDlls
    ExtensionHooked   = ($authHooked -or $extHooked)
}

#endregion

#region ------------------------------- 4. Tenant binding and client certificate

Write-Section '4. TENANT BINDING AND CLIENT CERTIFICATE'

$mfaReg   = Invoke-Safely { Get-ItemProperty -Path $script:AzureMfaKey }
$tenantId = $null

if ($mfaReg) {
    $props = @(
        'TENANT_ID', 'CLIENT_ID', 'STS_URL', 'AZURE_MFA_HOSTNAME', 'DISCOVERY_URL',
        'REQUIRE_USER_MATCH', 'LDAP_FORCE_GLOBAL_CATALOG',
        'OVERRIDE_NUMBER_MATCHING_WITH_OTP'
    )
    $regDump = [ordered]@{}
    foreach ($p in $props) {
        $regDump[$p] = if ($mfaReg.PSObject.Properties.Name -contains $p) { $mfaReg.$p } else { $null }
    }
    $mfa.Registry = $regDump
    $tenantId     = $regDump['TENANT_ID']

    if ($tenantId) {
        Write-Result 'Tenant ID configured' $tenantId 'Pass'
    } else {
        Write-Result 'Tenant ID configured' 'EMPTY' 'Fail'
        Add-Flag -Severity 'Blocker' -Message 'TENANT_ID is empty. The extension was never bound to a tenant, meaning AzureMfaNpsExtnConfigSetup.ps1 was not completed.'
    }

    # REQUIRE_USER_MATCH=FALSE lets unenrolled users bypass MFA entirely. This is
    # the single most common cause of an MFA control that silently does nothing.
    $rum = $regDump['REQUIRE_USER_MATCH']
    if ($rum -and "$rum" -match '^(FALSE|0)$') {
        Write-Result 'REQUIRE_USER_MATCH' "$rum - unenrolled users are allowed through" 'Warn'
        Add-Flag -Severity 'Risk' -Message 'REQUIRE_USER_MATCH is FALSE. Users not enrolled in MFA bypass the challenge entirely. Confirm this is intentional before treating MFA as an enforced control.'
    } elseif ($rum) {
        Write-Result 'REQUIRE_USER_MATCH' "$rum" 'Pass'
    }
} else {
    Write-Result 'AzureMfa registry key' 'NOT FOUND' 'Fail'
    Add-Flag -Severity 'Blocker' -Message "$script:AzureMfaKey does not exist. The MFA NPS Extension is not configured on this server."
}

# The extension's client certificate is self-signed with a two year lifetime.
# Expiry is the most common cause of a previously working extension breaking.
$mfaCerts = @()
if ($tenantId) {
    $mfaCerts = @(
        Invoke-Safely { Get-ChildItem -Path Cert:\LocalMachine\My } |
        Where-Object { $_.Subject -match [regex]::Escape($tenantId) }
    )
}
if ($mfaCerts.Count -eq 0) {
    $mfaCerts = @(
        Invoke-Safely { Get-ChildItem -Path Cert:\LocalMachine\My } |
        Where-Object { $_.Issuer -match 'CN=Microsoft Azure MFA' -or $_.FriendlyName -match 'MFA' }
    )
}

$certInfo = @()
foreach ($cert in $mfaCerts) {
    $daysLeft = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays, 0)
    $certInfo += [pscustomobject]@{
        Subject       = $cert.Subject
        Thumbprint    = $cert.Thumbprint
        NotBefore     = ConvertTo-Flat $cert.NotBefore
        NotAfter      = ConvertTo-Flat $cert.NotAfter
        DaysRemaining = $daysLeft
        HasPrivateKey = $cert.HasPrivateKey
    }

    if ($daysLeft -lt 0) {
        Write-Result 'MFA client certificate' "EXPIRED $([math]::Abs($daysLeft)) days ago" 'Fail'
        Add-Flag -Severity 'Blocker' -Message "The MFA client certificate expired on $($cert.NotAfter.ToString('yyyy-MM-dd')). MFA authentication is failing today. Renew by re-running AzureMfaNpsExtnConfigSetup.ps1."
    } elseif ($daysLeft -lt $script:CertWarnDays) {
        Write-Result 'MFA client certificate' "Expires in $daysLeft days" 'Warn'
        Add-Flag -Severity 'Risk' -Message "The MFA client certificate expires in $daysLeft days, on $($cert.NotAfter.ToString('yyyy-MM-dd')). Renew it before or during the change window."
    } else {
        Write-Result 'MFA client certificate' "Valid, $daysLeft days remaining" 'Pass'
    }

    if (-not $cert.HasPrivateKey) {
        Add-Flag -Severity 'Blocker' -Message "MFA client certificate $($cert.Thumbprint) has no associated private key."
    }
}
if ($certInfo.Count -eq 0) {
    Write-Result 'MFA client certificate' 'NOT FOUND in LocalMachine\My' 'Fail'
    Add-Flag -Severity 'Blocker' -Message 'No MFA client certificate was found in the local machine store. The extension cannot authenticate to the MFA service.'
}
$mfa.Certificates = $certInfo

$script:Findings.MfaExtension = $mfa

#endregion

#region --------------------------------- 5. RADIUS clients, policies and ports

Write-Section '5. RADIUS CLIENTS, POLICIES, AND PORTS'

$radius = [ordered]@{}
Import-Module NPS -ErrorAction SilentlyContinue | Out-Null

# Always wrap in @(). A single returned object otherwise breaks .Count logic
# and silently reports zero results.
$clients = @()
if (Test-CommandExists 'Get-NpsRadiusClient') {
    $clients = @(
        Invoke-Safely { Get-NpsRadiusClient } -ErrorLabel 'Get-NpsRadiusClient' |
        ForEach-Object {
            ConvertTo-FlatRecord -InputObject $_ -Property @('Name', 'Address', 'Enabled', 'VendorName', 'NapCompatible')
        }
    )
} else {
    Write-Result 'Get-NpsRadiusClient' 'Cmdlet unavailable on this host' 'Warn'
}

if ($clients.Count -gt 0) {
    Write-Result 'RADIUS clients configured' "$($clients.Count) found" 'Pass'
    Write-Table $clients
} else {
    Write-Result 'RADIUS clients configured' 'NONE found' 'Fail'
    Add-Flag -Severity 'Blocker' -Message 'No RADIUS clients are configured in NPS. Nothing is currently authenticating against this server.'
}
$radius.Clients = $clients

# Compare against expected clients, typically the device being replaced.
$expectedResults = @()
foreach ($expected in @($ExpectedRadiusClient)) {
    if (-not $expected) { continue }
    $match = $clients | Where-Object { $_.Address -eq $expected -or $_.Name -like "*$expected*" }
    $found = [bool]$match
    $expectedResults += [pscustomobject]@{
        Expected = $expected
        Found    = $found
        Name     = if ($match) { @($match)[0].Name } else { $null }
    }
    if ($found) {
        Write-Result "Expected RADIUS client '$expected'" "Found as '$(@($match)[0].Name)'" 'Pass'
        Add-Flag -Severity 'Note' -Message "Expected RADIUS client '$expected' exists as '$(@($match)[0].Name)'. Mirror its policy conditions when adding the replacement device, and remove it at decommission."
    } else {
        Write-Result "Expected RADIUS client '$expected'" 'NOT FOUND' 'Warn'
        Add-Flag -Severity 'Risk' -Message "Expected RADIUS client '$expected' was not found. Confirm how authentication is actually performed today before assuming RADIUS is in use."
    }
}
if ($expectedResults.Count -gt 0) { $radius.ExpectedClients = $expectedResults }

foreach ($cmd in @('Get-NpsNetworkPolicy', 'Get-NpsConnectionRequestPolicy')) {
    if (Test-CommandExists $cmd) {
        $policies = @(
            Invoke-Safely { & $cmd } -ErrorLabel $cmd |
            ForEach-Object {
                ConvertTo-FlatRecord -InputObject $_ -Property @('PolicyName', 'Enabled', 'ProcessingOrder', 'PolicySource')
            }
        )
        if ($policies.Count -gt 0) {
            Write-Table $policies "$cmd :"
            $radius[($cmd -replace '^Get-Nps', '')] = $policies
        } else {
            Write-Result $cmd 'No policies returned' 'Warn'
        }
    }
}

$udpPorts = @(
    Invoke-Safely { Get-NetUDPEndpoint } |
    Where-Object { $_.LocalPort -in 1812, 1813, 1645, 1646 } |
    Select-Object LocalAddress, LocalPort -Unique
)
if ($udpPorts.Count -gt 0) {
    Write-Result 'RADIUS UDP listeners' ((@($udpPorts.LocalPort) | Sort-Object -Unique) -join ', ') 'Pass'
} else {
    Write-Result 'RADIUS UDP listeners' 'None detected on 1812/1813/1645/1646' 'Warn'
    Add-Flag -Severity 'Risk' -Message 'No RADIUS UDP listeners were detected. The service may not be bound or may be listening on non-standard ports.'
}
$radius.UdpListeners = $udpPorts

$fwRules = @(
    Invoke-Safely { Get-NetFirewallRule } |
    Where-Object { $_.DisplayName -match 'Network Policy Server|RADIUS' } |
    Select-Object @{n = 'DisplayName'; e = { $_.DisplayName } },
                  @{n = 'Enabled';     e = { "$($_.Enabled)" } },
                  @{n = 'Direction';   e = { "$($_.Direction)" } },
                  @{n = 'Action';      e = { "$($_.Action)" } }
)
if ($fwRules.Count -gt 0) {
    Write-Table $fwRules 'Relevant Windows Firewall rules:'
}
$radius.FirewallRules = $fwRules

$script:Findings.Radius = $radius

#endregion

#region ----------------------------------------------- 6. Event log review

Write-Section "6. EVENT LOG REVIEW (last $EventLookbackDays days)"

$since  = (Get-Date).AddDays(-$EventLookbackDays)
$events = [ordered]@{}

$mfaLogNames = @(
    'AzureMfa/AuthN/AuthNOptCh',
    'AzureMfa/AuthZ/AuthZAdminCh',
    'AzureMfa/AuthZ/AuthZOptCh'
)
$mfaEventSummary = @()
foreach ($log in $mfaLogNames) {
    if (-not (Test-EventLogExists $log)) {
        Write-Result "Log $log" 'Not present' 'Info'
        continue
    }
    $entries = @(Invoke-Safely { Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $since } })
    if ($entries.Count -eq 0) {
        Write-Result "Log $log" 'Present, no events in window' 'Warn'
        continue
    }

    Write-Result "Log $log" "$($entries.Count) events" 'Pass'
    $mfaEventSummary += @(
        $entries | Group-Object Id, LevelDisplayName |
        Select-Object @{n = 'Log'; e = { $log } }, Name, Count
    )

    $errors = @($entries | Where-Object { $_.LevelDisplayName -in 'Error', 'Critical' } | Select-Object -First 5)
    if ($errors.Count -gt 0) {
        if (-not $Quiet) {
            Write-Host ''
            Write-Host "  Recent errors in ${log}:" -ForegroundColor Yellow
            foreach ($e in $errors) {
                Write-Host ("   {0}  Id={1}  {2}" -f $e.TimeCreated, $e.Id, (($e.Message -split "`n")[0])) -ForegroundColor Yellow
            }
        }
        Add-Flag -Severity 'Risk' -Message "Errors are present in $log within the last $EventLookbackDays days. Review them before relying on MFA at cutover."
    }
}
$events.MfaLogSummary = $mfaEventSummary

if ($mfaEventSummary.Count -eq 0) {
    Add-Flag -Severity 'Risk' -Message "No MFA extension events were found in the last $EventLookbackDays days. Either the extension is absent, or it is present but never invoked, meaning no traffic authenticates through it."
}

$npsEvents = @(
    Invoke-Safely {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = $script:NpsAuthEventIds
            StartTime = $since
        }
    }
)
if ($npsEvents.Count -gt 0) {
    $summary = @($npsEvents | Group-Object Id | Select-Object Name, Count)
    $latest  = ($npsEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1)
    Write-Result 'NPS auth events (Security log)' "$($npsEvents.Count) in $EventLookbackDays days" 'Pass'
    Write-Table $summary
    Write-Result 'Most recent NPS auth event' "$($latest.TimeCreated) (Id $($latest.Id))"
    $events.NpsSecuritySummary = $summary
    $events.MostRecentNpsAuth  = ConvertTo-Flat $latest.TimeCreated
} else {
    Write-Result 'NPS auth events (Security log)' "NONE in $EventLookbackDays days" 'Fail'
    $events.MostRecentNpsAuth = $null
    Add-Flag -Severity 'Blocker' -Message "No NPS authentication events (6272/6273) occurred in the last $EventLookbackDays days. NPS is not handling authentication today. Validate any assumption that RADIUS is in production use."
}

# Query providers individually. Passing a provider that does not exist causes
# the whole filter to fail with a misleading "parameter is incorrect" error.
$sysIssues = @()
foreach ($provider in @('Microsoft-Windows-NPS', 'IAS', 'NPS')) {
    $found = @(
        Invoke-Safely {
            Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = $provider
                StartTime    = $since
            }
        }
    ) | Where-Object { $_.LevelDisplayName -in 'Error', 'Warning' }
    if ($found) {
        $sysIssues += @($found | Select-Object -First 10 |
            ForEach-Object {
                [pscustomobject]@{
                    TimeCreated = ConvertTo-Flat $_.TimeCreated
                    Provider    = $provider
                    Id          = $_.Id
                    Level       = $_.LevelDisplayName
                }
            })
    }
}
if ($sysIssues.Count -gt 0) {
    Write-Table $sysIssues 'NPS/IAS warnings and errors (System log):'
    $events.SystemLogIssues = $sysIssues
}

$script:Findings.Events = $events

#endregion

#region -------------------------------------------- 7. Outbound connectivity

Write-Section '7. OUTBOUND CONNECTIVITY TO MFA SERVICE ENDPOINTS'

$connResults = @()
if ($SkipConnectivity) {
    Write-Result 'Connectivity tests' 'Skipped by parameter' 'Info'
} else {
    foreach ($endpoint in $MfaEndpoint) {
        $test = Invoke-Safely {
            Test-NetConnection -ComputerName $endpoint -Port 443 -WarningAction SilentlyContinue
        }
        $ok = [bool]($test -and $test.TcpTestSucceeded)
        $connResults += [pscustomobject]@{
            Endpoint         = $endpoint
            Port             = 443
            Resolved         = if ($test -and $test.RemoteAddress) { "$($test.RemoteAddress)" } else { $null }
            TcpTestSucceeded = $ok
        }
        if ($ok) {
            Write-Result "HTTPS $endpoint" 'Reachable' 'Pass'
        } else {
            Write-Result "HTTPS $endpoint" 'UNREACHABLE' 'Fail'
            Add-Flag -Severity 'Risk' -Message "Outbound HTTPS to $endpoint failed. The MFA extension requires this endpoint. Check egress filtering, and replicate any allowance on a replacement firewall."
        }
    }
}
$script:Findings.Connectivity = $connResults

# TLS 1.2 is required by the MFA service and is commonly unset on older builds.
$tlsKeys = @(
    'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
)
$strongCrypto = $null
foreach ($key in $tlsKeys) {
    $props = Invoke-Safely { Get-ItemProperty -Path $key }
    if ($props -and $props.PSObject.Properties.Name -contains 'SchUseStrongCrypto') {
        $strongCrypto = $props.SchUseStrongCrypto
        break
    }
}
if ($strongCrypto -eq 1) {
    Write-Result '.NET SchUseStrongCrypto (TLS 1.2)' 'Enabled' 'Pass'
} else {
    Write-Result '.NET SchUseStrongCrypto (TLS 1.2)' 'Not set or disabled' 'Warn'
    Add-Flag -Severity 'Risk' -Message 'SchUseStrongCrypto is not enabled. On older server builds this can prevent the extension from negotiating TLS 1.2 to the MFA service.'
}
$script:Findings.TlsStrongCrypto = $strongCrypto

#endregion

#region ------------------------------------------- 8. Supporting context data

Write-Section '8. SUPPORTING CONTEXT'

# DHCP scopes. Useful when the same host serves DHCP and a migration may move
# scope ownership to another device.
$scopes = @()
if ($SkipDhcp) {
    Write-Result 'DHCP enumeration' 'Skipped by parameter' 'Info'
} elseif (Test-CommandExists 'Get-DhcpServerv4Scope') {
    $scopes = @(
        Invoke-Safely { Get-DhcpServerv4Scope } -ErrorLabel 'Get-DhcpServerv4Scope' |
        ForEach-Object {
            ConvertTo-FlatRecord -InputObject $_ -Property @('ScopeId', 'SubnetMask', 'Name', 'State', 'StartRange', 'EndRange', 'LeaseDuration')
        }
    )
    if ($scopes.Count -gt 0) {
        Write-Result 'DHCP scopes on this server' "$($scopes.Count) found" 'Pass'
        Write-Table $scopes
    } else {
        Write-Result 'DHCP scopes on this server' 'None found' 'Info'
    }
} else {
    Write-Result 'DHCP server cmdlets' 'Not available on this host' 'Info'
}
$script:Findings.DhcpScopes = $scopes

# VPN-related AD groups. Membership totals are a sanity check against any user
# count assumed in a statement of work.
$vpnGroups = @()
if ($SkipAD) {
    Write-Result 'AD enumeration' 'Skipped by parameter' 'Info'
} elseif (Test-CommandExists 'Get-ADGroup') {
    $filter = ($VpnGroupFilter | ForEach-Object { "Name -like '$_'" }) -join ' -or '
    $vpnGroups = @(
        Invoke-Safely { Get-ADGroup -Filter $filter } -ErrorLabel 'Get-ADGroup' |
        ForEach-Object {
            $members = @(Invoke-Safely { Get-ADGroupMember -Identity $_ })
            [pscustomobject]@{
                GroupName   = $_.Name
                MemberCount = $members.Count
            }
        }
    )
    if ($vpnGroups.Count -gt 0) {
        Write-Result 'VPN-related AD groups' "$($vpnGroups.Count) found" 'Pass'
        Write-Table $vpnGroups

        $distinct = ($vpnGroups | Measure-Object -Property MemberCount -Maximum).Maximum
        if ($PSBoundParameters.ContainsKey('ExpectedVpnUserCount')) {
            if ($distinct -gt $ExpectedVpnUserCount) {
                Write-Result 'Expected VPN user count' "Scoped $ExpectedVpnUserCount, largest group has $distinct" 'Warn'
                Add-Flag -Severity 'Risk' -Message "The largest VPN group contains $distinct members against a scoped assumption of $ExpectedVpnUserCount. Group membership may be stale, or per-user effort is understated. Reconcile before finalizing estimates."
            } else {
                Write-Result 'Expected VPN user count' "Scoped $ExpectedVpnUserCount, largest group has $distinct" 'Pass'
            }
        } else {
            Add-Flag -Severity 'Note' -Message 'Compare VPN group membership against any user count assumed in scope, and adjust support effort accordingly.'
        }
    } else {
        Write-Result 'VPN-related AD groups' "None matched: $($VpnGroupFilter -join ', ')" 'Warn'
    }
} else {
    Write-Result 'AD cmdlets' 'Not available on this host' 'Info'
}
$script:Findings.VpnGroups = $vpnGroups

#endregion

#region -------------------------------------------------------- 9. Verdict

Write-Section '9. VERDICT'

$gates = [ordered]@{
    'Extension installed'  = [bool]$mfa.ProductName
    'Registered with NPS'  = [bool]$script:Findings.AuthSrv.ExtensionHooked
    'Bound to a tenant'    = [bool]$tenantId
    'Valid client cert'    = [bool](@($certInfo | Where-Object { $_.DaysRemaining -gt 0 }).Count -gt 0)
    'Recent auth activity' = [bool]$events.MostRecentNpsAuth
}

foreach ($gate in $gates.Keys) {
    Write-Result $gate "$($gates[$gate])" $(if ($gates[$gate]) { 'Pass' } else { 'Fail' })
}

$installed  = $gates['Extension installed']
$configured = $installed -and $gates['Registered with NPS'] -and $gates['Bound to a tenant'] -and $gates['Valid client cert']
$inUse      = $gates['Recent auth activity']

$verdict = if ($configured -and $inUse) {
    'FUNCTIONING - the extension is installed, registered, tenant-bound, holds a valid certificate, and is processing authentications.'
} elseif ($configured -and -not $inUse) {
    'INSTALLED BUT UNPROVEN - all components are present, but no recent authentications were observed. Validate with a live test before relying on it.'
} elseif ($installed) {
    'INCOMPLETE - the extension is installed, but registration, tenant binding, or certificate validity failed. MFA is not reliably enforced.'
} else {
    'NOT INSTALLED - the MFA NPS Extension is not present. Any scope or control assuming MFA enforcement here is invalid.'
}

$verdictState = if ($configured -and $inUse) { 'Pass' } elseif (-not $installed) { 'Fail' } else { 'Warn' }

if (-not $Quiet) {
    Write-Host ''
    Write-Host "  VERDICT: $verdict" -ForegroundColor $(
        switch ($verdictState) { 'Pass' { 'Green' } 'Fail' { 'Red' } default { 'Yellow' } }
    )
}

$script:Findings.Gates   = $gates
$script:Findings.Verdict = $verdict

$blockerCount = @($script:Flags | Where-Object { $_.Severity -eq 'Blocker' }).Count
$riskCount    = @($script:Flags | Where-Object { $_.Severity -eq 'Risk' }).Count

if ($script:Flags.Count -gt 0 -and -not $Quiet) {
    Write-Host ''
    Write-Host "  FLAGS RAISED ($blockerCount blocker, $riskCount risk):" -ForegroundColor Cyan
    foreach ($severity in @('Blocker', 'Risk', 'Note')) {
        foreach ($flag in @($script:Flags | Where-Object { $_.Severity -eq $severity })) {
            $color = switch ($severity) { 'Blocker' { 'Red' } 'Risk' { 'Yellow' } default { 'Gray' } }
            Write-Host ("   [{0,-7}] {1}" -f $severity, $flag.Message) -ForegroundColor $color
        }
    }
}
$script:Findings.Flags = @($script:Flags)

$script:Findings.Meta = [ordered]@{
    Organization      = $Organization
    GeneratedAt       = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    ScriptVersion     = '2.0.0'
    EventLookbackDays = $EventLookbackDays
    BlockerCount      = $blockerCount
    RiskCount         = $riskCount
}

#endregion

#region --------------------------------------------------------- 10. Output

$exitObject = [pscustomobject]$script:Findings

try {
    $exitObject | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonFile -Encoding UTF8
    if (-not $Quiet) {
        Write-Host ''
        Write-Host "  JSON summary : $jsonFile" -ForegroundColor Green
        Write-Host "  Transcript   : $transcriptFile" -ForegroundColor Green
        Write-Host ''
    }
}
catch {
    Write-Warning "Could not write JSON summary: $($_.Exception.Message)"
}

try { Stop-Transcript | Out-Null } catch { }

if ($PassThru) { $exitObject }

#endregion
