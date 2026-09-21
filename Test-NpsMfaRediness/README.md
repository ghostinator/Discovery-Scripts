# Test-NpsMfaReadiness

A read-only PowerShell assessment for Windows **NPS (RADIUS)** servers and the **Microsoft Entra / Azure MFA NPS Extension**.

It answers one question that most checks get wrong: **is MFA actually being enforced, or is the extension just installed?** Those are different states with different failure modes, and only one of them protects anything.

---

## Why this exists

"Is the MFA NPS Extension installed?" is the wrong question. An extension can be fully installed and still enforce nothing, because:

- the package is present but was never **hooked into NPS** via `AuthSrv`, so NPS authenticates without ever calling it
- the config setup script was never completed, leaving **`TENANT_ID` empty**
- the self-signed client certificate has a **two-year lifetime** and quietly expired
- `REQUIRE_USER_MATCH` is `FALSE`, so **unenrolled users bypass MFA entirely**
- everything is configured correctly but **no traffic authenticates through it**, so it has never been exercised

This script evaluates five independent gates and reports each one separately, then produces a single verdict.

| Gate | What it proves |
|---|---|
| 1. Installed | Package and binaries present on disk |
| 2. Registered | Extension hooked into NPS via `AuthSrv` |
| 3. Tenant-bound | `TENANT_ID` populated, config setup completed |
| 4. Certificate | Client certificate present, valid, not expired |
| 5. In use | Recent authentication activity in the event logs |

**Verdicts:** `FUNCTIONING` · `INSTALLED BUT UNPROVEN` · `INCOMPLETE` · `NOT INSTALLED`

The `INSTALLED BUT UNPROVEN` state is the one that matters most in practice. It means every component is present but nothing has authenticated recently, which usually means the control was built and then bypassed, decommissioned, or never cut over.

---

## Safety

**Read-only.** The script installs nothing, starts or stops nothing, and modifies no configuration. It writes a transcript and a JSON summary to the output folder and nothing else.

**Secrets are never read or exported.** RADIUS shared secrets are deliberately not collected. The script reports that a client *exists*, not its secret. Do not substitute `netsh nps export` unless you intend to handle secrets accordingly.

---

## Requirements

| Item | Requirement |
|---|---|
| OS | Windows Server 2012 R2 or later |
| PowerShell | 5.1 or later |
| Privileges | Elevated session (registry, certificate store, and event log access) |
| Optional | RSAT AD and DHCP modules. Those sections skip gracefully when unavailable. |

---

## Quick start

```powershell
# Default run, all checks
.\Test-NpsMfaReadiness.ps1

# Verify a specific RADIUS client exists and sanity-check an assumed user count
.\Test-NpsMfaReadiness.ps1 -ExpectedRadiusClient '10.0.0.1' -ExpectedVpnUserCount 15

# Offline or locked-down host
.\Test-NpsMfaReadiness.ps1 -SkipConnectivity -SkipAD -SkipDhcp

# Scripted use, verdict only
.\Test-NpsMfaReadiness.ps1 -Quiet -PassThru | Select-Object -ExpandProperty Verdict

# Remote execution (output files are written on the remote host)
Invoke-Command -ComputerName NPS01 -FilePath .\Test-NpsMfaReadiness.ps1
```

If execution policy blocks it:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Test-NpsMfaReadiness.ps1
```

---

## Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-OutputPath` | `C:\Discovery\NpsMfaReadiness` | Folder for transcript and JSON. Created if absent. |
| `-EventLookbackDays` | `30` | Days of NPS and MFA event history to summarize. |
| `-ExpectedRadiusClient` | none | IPs or names expected to exist as RADIUS clients, typically the device being replaced. Each reported found or missing. |
| `-ExpectedVpnUserCount` | none | User count assumed by your scope. Compared against AD group membership and flagged on mismatch. |
| `-VpnGroupFilter` | `*VPN*`, `*RemoteAccess*`, `*RAS*` | Wildcard patterns for locating VPN-related AD groups. |
| `-MfaEndpoint` | current Entra MFA set | Endpoints tested for outbound HTTPS. Override for sovereign or government clouds. |
| `-SkipConnectivity` | off | Skip outbound HTTPS tests. |
| `-SkipAD` | off | Skip AD group enumeration. |
| `-SkipDhcp` | off | Skip DHCP scope enumeration. |
| `-Organization` | `Organization` | Label in the report header. Cosmetic. |
| `-Quiet` | off | Suppress console output. Files still written. |
| `-PassThru` | off | Emit the findings object to the pipeline. |

---

## What it collects

**MFA extension** — package and version, binaries on disk, `AuthSrv` registration, `TENANT_ID` and related registry values, `REQUIRE_USER_MATCH`, client certificate validity with expiry warnings.

**RADIUS** — configured clients, network and connection request policies, UDP listeners on 1812/1813/1645/1646, and relevant Windows Firewall rules.

**Event logs** — MFA extension operational channels, NPS Security log events 6272/6273/6274/6278, and NPS/IAS errors in the System log.

**Connectivity** — outbound HTTPS to the MFA service endpoints, plus `SchUseStrongCrypto` (TLS 1.2) posture.

**Context** — server identity, installed roles, IAS service state, DHCP scopes, and VPN-related AD groups with member counts.

---

## Output

Two timestamped files in `-OutputPath`:

```
<COMPUTERNAME>-NpsMfaReadiness-<yyyyMMdd-HHmmss>.txt    # full console transcript
<COMPUTERNAME>-NpsMfaReadiness-<yyyyMMdd-HHmmss>.json   # structured summary
```

Console output is colour-coded `[ PASS ]` / `[ FAIL ]` / `[ WARN ]` / `[ INFO ]`, ending with the verdict and a flag list.

Flags are graded by severity:

- **Blocker** — invalidates an assumption or prevents MFA from working
- **Risk** — works today but is fragile, bypassable, or expiring
- **Note** — context worth reconciling before you commit to a plan

### JSON shape

```json
{
  "Server":       { "ComputerName": "...", "InstalledRoles": ["NPAS"], "IasServiceStatus": "Running" },
  "AuthSrv":      { "AuthorizationDLLs": [], "ExtensionHooked": false },
  "MfaExtension": { "ProductName": null, "Binaries": [], "Certificates": [] },
  "Radius":       { "Clients": [], "UdpListeners": [], "FirewallRules": [] },
  "Events":       { "MfaLogSummary": [], "MostRecentNpsAuth": null },
  "Connectivity": [ { "Endpoint": "login.microsoftonline.com", "TcpTestSucceeded": true } ],
  "DhcpScopes":   [],
  "VpnGroups":    [ { "GroupName": "VPN Users", "MemberCount": 3 } ],
  "Gates":        { "Extension installed": false, "Recent auth activity": false },
  "Verdict":      "NOT INSTALLED - ...",
  "Flags":        [ { "Severity": "Blocker", "Message": "..." } ],
  "Meta":         { "BlockerCount": 7, "RiskCount": 1 }
}
```

Nested `IPAddress`, `TimeSpan`, and `DateTime` values are flattened to strings so the JSON stays readable and diffable across runs.

---

## Typical uses

- **Pre-migration discovery** before replacing a firewall, VPN concentrator, or wireless controller that authenticates against NPS
- **Validating a scope assumption** that "MFA is already in place" before it becomes a line item
- **Security assessment evidence** for questionnaires asking whether MFA covers all remote access
- **Troubleshooting** an extension that worked until the client certificate hit its two-year expiry
- **Fleet audit** across multiple NPS servers via `Invoke-Command` and `-PassThru`

### Fleet example

```powershell
$servers = 'NPS01', 'NPS02', 'NPS03'

$results = foreach ($s in $servers) {
    Invoke-Command -ComputerName $s -FilePath .\Test-NpsMfaReadiness.ps1 `
        -ArgumentList @() -ErrorAction SilentlyContinue
}

$results | Select-Object PSComputerName, Verdict | Format-Table -AutoSize
```

---

## Implementation notes

A few deliberate choices, mostly learned the hard way:

- **Everything is wrapped in `@()`.** A cmdlet returning a single object otherwise breaks `.Count` logic and silently reports zero results. This is the classic reason a check reports "none found" while the data clearly exists.
- **Event logs are tested with `Get-WinEvent -ListLog` before querying.** Querying a non-existent log raises a terminating error that pollutes the transcript with noise.
- **System log providers are queried individually.** Passing an array containing one non-existent provider fails the entire filter with a misleading "the parameter is incorrect."
- **`Invoke-Safely` wraps expected failures** so missing cmdlets and absent registry keys produce clean `INFO` lines rather than red error text.
- **`Set-StrictMode -Version 2.0`** is on, so property existence is checked before access throughout.

---

## Limitations

- Gate 5 infers usage from event log history. A server with cleared or aggressively rotated Security logs may report `INSTALLED BUT UNPROVEN` despite working correctly. Widen `-EventLookbackDays` or validate with a live test.
- Connectivity tests confirm TCP 443 reachability only. They do not validate TLS inspection, proxy authentication, or certificate pinning behaviour.
- AD group membership is counted directly and does not expand nested groups.
- The script assesses the NPS server only. It does not inspect the RADIUS client device configuration.

---

## Contributing

Issues and pull requests welcome. Useful additions would include sovereign cloud endpoint sets, nested AD group expansion, and an HTML report renderer.

---

## License

MIT
