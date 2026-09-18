#requires -version 5.1
<#
SQL Inventory Collector + Spreadsheet + Zip + SendGrid
Designed for Datto RMM running as SYSTEM.

Recommended environment variables / Datto secure vars:
  SG_API_KEY = SendGrid API key
  SG_TO      = recipient email
  SG_FROM    = verified sender email/domain in SendGrid
#>

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------
$HostName     = $env:COMPUTERNAME
$BaseDir      = "C:\Temp\SQL_Audit_$HostName"
$ZipPath      = "C:\Temp\SQL_Audit_$HostName.zip"
$WorkbookPath = Join-Path $BaseDir ("SQL_Audit_{0}.xml" -f $HostName)

$SendGridApiKey = $env:SG_API_KEY
$ToEmail        = $env:SG_TO
$FromEmail      = $env:SG_FROM

if ([string]::IsNullOrWhiteSpace($ToEmail))   { $ToEmail   = "brandon.cook@gadellnet.com" }
if ([string]::IsNullOrWhiteSpace($FromEmail)) { $FromEmail = "noreply@your-verified-sendgrid-domain.com" }

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )

    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $line | Tee-Object -FilePath (Join-Path $BaseDir 'summary.txt') -Append
    if ($Level -eq 'ERROR') {
        $line | Out-File (Join-Path $BaseDir 'errors.txt') -Append -Encoding utf8
    }
}

function Escape-CsvValue {
    param([object]$Value)

    if ($null -eq $Value) { return '""' }
    $s = [string]$Value
    $s = $s -replace '"', '""'
    return '"' + $s + '"'
}

function Write-ObjectListToCsv {
    param(
        [Parameter(Mandatory)][System.Collections.IEnumerable]$InputObject,
        [Parameter(Mandatory)][string]$Path
    )

    $items = @($InputObject)
    if ($items.Count -eq 0) {
        "" | Out-File -FilePath $Path -Encoding utf8
        return
    }

    $props = @($items[0].PSObject.Properties.Name)
    $lines = New-Object System.Collections.Generic.List[string]

    $header = ($props | ForEach-Object { Escape-CsvValue $_ }) -join ','
    [void]$lines.Add($header)

    foreach ($item in $items) {
        $row = ($props | ForEach-Object { Escape-CsvValue ($item.$_) }) -join ','
        [void]$lines.Add($row)
    }

    $lines | Out-File -FilePath $Path -Encoding utf8
}

function Escape-XmlText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Security.SecurityElement]::Escape([string]$Value)
}

function Get-ExcelXmlType {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return 'String' }
    if ($Value -is [datetime]) { return 'DateTime' }
    if ($Value -is [byte] -or
        $Value -is [int16] -or
        $Value -is [int32] -or
        $Value -is [int64] -or
        $Value -is [decimal] -or
        $Value -is [double] -or
        $Value -is [single]) {
        return 'Number'
    }

    return 'String'
}

function Get-ExcelXmlValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return "" }
    if ($Value -is [datetime]) {
        return (Get-Date $Value -Format "s")
    }

    return (Escape-XmlText $Value)
}

function Sanitize-WorksheetName {
    param([Parameter(Mandatory)][string]$Name)

    $safe = $Name -replace '[:\\\/\?\*\[\]]', '_'
    if ($safe.Length -gt 31) {
        $safe = $safe.Substring(0,31)
    }
    if ([string]::IsNullOrWhiteSpace($safe)) {
        $safe = "Sheet"
    }
    return $safe
}

function ConvertTo-ExcelXmlWorksheet {
    param(
        [Parameter(Mandatory)][string]$WorksheetName,
        [Parameter(Mandatory)][array]$Rows
    )

    $sheetName = Sanitize-WorksheetName $WorksheetName
    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine("<Worksheet ss:Name=`"$sheetName`">")
    [void]$sb.AppendLine("<Table>")

    $rowArray = @($Rows)

    if ($rowArray.Count -eq 0) {
        [void]$sb.AppendLine('<Row><Cell ss:StyleID="Header"><Data ss:Type="String">No data</Data></Cell></Row>')
        [void]$sb.AppendLine("</Table>")
        [void]$sb.AppendLine("</Worksheet>")
        return $sb.ToString()
    }

    $props = @($rowArray[0].PSObject.Properties.Name)

    [void]$sb.AppendLine("<Row>")
    foreach ($p in $props) {
        [void]$sb.AppendLine("<Cell ss:StyleID=`"Header`"><Data ss:Type=`"String`">$([System.Security.SecurityElement]::Escape($p))</Data></Cell>")
    }
    [void]$sb.AppendLine("</Row>")

    foreach ($row in $rowArray) {
        [void]$sb.AppendLine("<Row>")
        foreach ($p in $props) {
            $value = $row.$p
            $type  = Get-ExcelXmlType $value
            $text  = Get-ExcelXmlValue $value
            [void]$sb.AppendLine("<Cell><Data ss:Type=`"$type`">$text</Data></Cell>")
        }
        [void]$sb.AppendLine("</Row>")
    }

    [void]$sb.AppendLine("</Table>")
    [void]$sb.AppendLine("</Worksheet>")

    return $sb.ToString()
}

function Write-ExcelXmlWorkbook {
    param(
        [Parameter(Mandatory)][hashtable]$Sheets,
        [Parameter(Mandatory)][string]$Path
    )

    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('<?xml version="1.0"?>')
    [void]$sb.AppendLine('<?mso-application progid="Excel.Sheet"?>')
    [void]$sb.AppendLine('<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"')
    [void]$sb.AppendLine(' xmlns:o="urn:schemas-microsoft-com:office:office"')
    [void]$sb.AppendLine(' xmlns:x="urn:schemas-microsoft-com:office:excel"')
    [void]$sb.AppendLine(' xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"')
    [void]$sb.AppendLine(' xmlns:html="http://www.w3.org/TR/REC-html40">')

    [void]$sb.AppendLine('<Styles>')
    [void]$sb.AppendLine('<Style ss:ID="Default" ss:Name="Normal">')
    [void]$sb.AppendLine('<Alignment ss:Vertical="Bottom"/>')
    [void]$sb.AppendLine('<Borders/>')
    [void]$sb.AppendLine('<Font ss:FontName="Calibri" ss:Size="11"/>')
    [void]$sb.AppendLine('<Interior/>')
    [void]$sb.AppendLine('<NumberFormat/>')
    [void]$sb.AppendLine('<Protection/>')
    [void]$sb.AppendLine('</Style>')
    [void]$sb.AppendLine('<Style ss:ID="Header">')
    [void]$sb.AppendLine('<Font ss:Bold="1"/>')
    [void]$sb.AppendLine('<Interior ss:Color="#D9EAF7" ss:Pattern="Solid"/>')
    [void]$sb.AppendLine('</Style>')
    [void]$sb.AppendLine('</Styles>')

    foreach ($key in $Sheets.Keys) {
    $rows = @($Sheets[$key])
    if ($rows.Count -eq 0 -or ($rows.Count -eq 1 -and $null -eq $rows[0])) {
        $rows = @([pscustomobject]@{ Status = 'No data collected' })
    }
    [void]$sb.AppendLine((ConvertTo-ExcelXmlWorksheet -WorksheetName $key -Rows $rows))
}

    [void]$sb.AppendLine('</Workbook>')
    $sb.ToString() | Out-File -FilePath $Path -Encoding utf8
}

function DataTable-ToPsObject {
    param([object]$DataTable)

    $rows = @()
    foreach ($row in $DataTable.Rows) {
        $obj = [ordered]@{}
        foreach ($col in $DataTable.Columns) {
            $obj[$col.ColumnName] = $row[$col.ColumnName]
        }
        $rows += [pscustomobject]$obj
    }
    return $rows
}

function Invoke-SqlQuery {
    param(
        [Parameter(Mandatory)][string]$ServerInstance,
        [Parameter(Mandatory)][string]$Database,
        [Parameter(Mandatory)][string]$Query,
        [int]$CommandTimeout = 60
    )

    $connString = "Server=$ServerInstance;Database=$Database;Integrated Security=True;Application Name=SQL_Audit_Collector;TrustServerCertificate=True;"
    $conn = New-Object System.Data.SqlClient.SqlConnection $connString
    $cmd = $null
    $adapter = $null
    $dt = New-Object System.Data.DataTable

    try {
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText    = $Query
        $cmd.CommandTimeout = $CommandTimeout
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
        [void]$adapter.Fill($dt)
        return ,$dt
    }
    finally {
        if ($adapter) { $adapter.Dispose() }
        if ($cmd)     { $cmd.Dispose() }
        if ($conn.State -ne 'Closed') { $conn.Close() }
        $conn.Dispose()
    }
}

function Get-SqlInstancesFromRegistry {
    $result = New-Object System.Collections.Generic.List[string]

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    )

    foreach ($path in $paths) {
        try {
            if (Test-Path $path) {
                $props = (Get-ItemProperty -Path $path).PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' }

                foreach ($p in $props) {
                    if (-not [string]::IsNullOrWhiteSpace($p.Name) -and -not $result.Contains($p.Name)) {
                        [void]$result.Add($p.Name)
                    }
                }
            }
        }
        catch {
            # ignore registry errors
        }
    }

    return @($result)
}

function Get-LocalSqlServices {
    Get-Service | Where-Object {
        $_.Name -like 'MSSQL*' -or $_.Name -like 'SQLAgent*' -or $_.Name -like 'SQLBrowser'
    } | Select-Object Name, DisplayName, Status, StartType
}

function Get-InstalledSqlPrograms {
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $programs = foreach ($path in $uninstallPaths) {
        try {
            Get-ItemProperty $path -ErrorAction SilentlyContinue
        } catch {}
    }

    $programs |
        Where-Object {
            $_.DisplayName -match 'SQL Server|Microsoft SQL|SSMS|SQL Server Management Studio|ODBC Driver'
        } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Sort-Object DisplayName -Unique
}

function Compress-Folder {
    param(
        [Parameter(Mandatory)][string]$SourceFolder,
        [Parameter(Mandatory)][string]$DestinationZip
    )

    if (Test-Path $DestinationZip) {
        Remove-Item $DestinationZip -Force
    }

    Compress-Archive -Path (Join-Path $SourceFolder '*') -DestinationPath $DestinationZip -CompressionLevel Optimal -Force
}

function Send-SendGridMail {
    param(
        [Parameter(Mandatory)][string]$ApiKey,
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string]$To,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$BodyText,
        [Parameter(Mandatory)][string]$AttachmentPath
    )

    if (-not (Test-Path $AttachmentPath)) {
        throw "Attachment not found: $AttachmentPath"
    }

    $bytes = [System.IO.File]::ReadAllBytes($AttachmentPath)
    $b64   = [System.Convert]::ToBase64String($bytes)
    $fileName = [System.IO.Path]::GetFileName($AttachmentPath)

    $payload = @{
        personalizations = @(
            @{
                to = @(@{ email = $To })
                subject = $Subject
            }
        )
        from = @{
            email = $From
        }
        content = @(
            @{
                type  = 'text/plain'
                value = $BodyText
            }
        )
        attachments = @(
            @{
                content     = $b64
                type        = 'application/zip'
                filename    = $fileName
                disposition = 'attachment'
            }
        )
    } | ConvertTo-Json -Depth 8

    $headers = @{
        Authorization = "Bearer $ApiKey"
        "Content-Type" = "application/json"
    }

    Invoke-RestMethod -Method Post -Uri 'https://api.sendgrid.com/v3/mail/send' -Headers $headers -Body $payload | Out-Null
}

# ---------------------------------------------------------------------
# Begin
# ---------------------------------------------------------------------
Ensure-Directory -Path $BaseDir
Write-Log "Starting SQL audit collection on $HostName"

$Sheets = @{}

# ---------------- Host inventory ----------------
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, OSArchitecture, CSName, LastBootUpTime
    $Sheets['Summary_OS'] = @($osInfo)
    Write-ObjectListToCsv -InputObject @($osInfo) -Path (Join-Path $BaseDir 'os.csv')
} catch {
    Write-Log "OS inventory failed: $($_.Exception.Message)" 'ERROR'
}

try {
    $sysInfo = Get-CimInstance Win32_ComputerSystem |
        Select-Object Manufacturer, Model, TotalPhysicalMemory, Domain, PartOfDomain
    $Sheets['Summary_System'] = @($sysInfo)
    Write-ObjectListToCsv -InputObject @($sysInfo) -Path (Join-Path $BaseDir 'system.csv')
} catch {
    Write-Log "System inventory failed: $($_.Exception.Message)" 'ERROR'
}

try {
    $cpuInfo = Get-CimInstance Win32_Processor |
        Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
    $Sheets['Summary_CPU'] = @($cpuInfo)
    Write-ObjectListToCsv -InputObject @($cpuInfo) -Path (Join-Path $BaseDir 'cpu.csv')
} catch {
    Write-Log "CPU inventory failed: $($_.Exception.Message)" 'ERROR'
}

try {
    $diskInfo = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
        Select-Object DeviceID, VolumeName, Size, FreeSpace
    $Sheets['Summary_Disks'] = @($diskInfo)
    Write-ObjectListToCsv -InputObject @($diskInfo) -Path (Join-Path $BaseDir 'disks.csv')
} catch {
    Write-Log "Disk inventory failed: $($_.Exception.Message)" 'ERROR'
}

try {
    $svcInfo = Get-LocalSqlServices
    $Sheets['SQL_Services'] = @($svcInfo)
    Write-ObjectListToCsv -InputObject @($svcInfo) -Path (Join-Path $BaseDir 'sql-services.csv')
} catch {
    Write-Log "SQL service inventory failed: $($_.Exception.Message)" 'ERROR'
}

try {
    $progInfo = Get-InstalledSqlPrograms
    $Sheets['Installed_SQL_Programs'] = @($progInfo)
    Write-ObjectListToCsv -InputObject @($progInfo) -Path (Join-Path $BaseDir 'installed-sql-programs.csv')
} catch {
    Write-Log "Installed SQL program inventory failed: $($_.Exception.Message)" 'ERROR'
}

# ---------------- SQL discovery ----------------
$instances = Get-SqlInstancesFromRegistry
if ($instances.Count -eq 0) {
    Write-Log "No SQL instances discovered from registry." 'WARN'
} else {
    Write-Log "Discovered SQL instances: $($instances -join ', ')"
}

$instanceSummary = foreach ($instance in $instances) {
    [pscustomobject]@{
        HostName       = $HostName
        Instance       = $instance
        ServerInstance = if ($instance -eq 'MSSQLSERVER') { $HostName } else { "$HostName\$instance" }
    }
}
$Sheets['Summary_Instances'] = @($instanceSummary)
Write-ObjectListToCsv -InputObject @($instanceSummary) -Path (Join-Path $BaseDir 'instance-summary.csv')

# ---------------- Queries ----------------
$qInstanceInfo = @"
SELECT
    @@SERVERNAME AS ServerName,
    @@VERSION AS SqlVersionString,
    SERVERPROPERTY('Edition') AS Edition,
    SERVERPROPERTY('ProductVersion') AS ProductVersion,
    SERVERPROPERTY('ProductLevel') AS ProductLevel,
    SERVERPROPERTY('EngineEdition') AS EngineEdition,
    SERVERPROPERTY('InstanceName') AS InstanceName,
    SERVERPROPERTY('IsClustered') AS IsClustered,
    SERVERPROPERTY('MachineName') AS MachineName,
    SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS ComputerNamePhysicalNetBIOS,
    SERVERPROPERTY('Collation') AS Collation;
"@

$qDatabases = @"
SELECT
    d.name,
    d.database_id,
    d.state_desc,
    d.recovery_model_desc,
    d.compatibility_level,
    d.user_access_desc,
    d.containment_desc,
    d.create_date,
    SUSER_SNAME(d.owner_sid) AS owner_name
FROM sys.databases d
ORDER BY d.name;
"@

$qDbSizes = @"
SELECT
    DB_NAME(mf.database_id) AS database_name,
    CAST(SUM(mf.size) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb,
    CAST(SUM(CASE WHEN mf.type_desc = 'ROWS' THEN mf.size ELSE 0 END) * 8.0 / 1024 AS DECIMAL(18,2)) AS data_mb,
    CAST(SUM(CASE WHEN mf.type_desc = 'LOG'  THEN mf.size ELSE 0 END) * 8.0 / 1024 AS DECIMAL(18,2)) AS log_mb
FROM sys.master_files mf
GROUP BY mf.database_id
ORDER BY DB_NAME(mf.database_id);
"@

$qJobs = @"
SELECT
    j.name,
    j.enabled,
    j.description,
    j.date_created,
    j.date_modified,
    SUSER_SNAME(j.owner_sid) AS owner_name
FROM msdb.dbo.sysjobs j
ORDER BY j.name;
"@

$qJobSchedules = @"
SELECT
    j.name AS job_name,
    s.name AS schedule_name,
    s.enabled,
    s.freq_type,
    s.freq_interval,
    s.freq_subday_type,
    s.freq_subday_interval,
    s.active_start_date,
    s.active_start_time
FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobschedules js ON j.job_id = js.job_id
JOIN msdb.dbo.sysschedules s ON js.schedule_id = s.schedule_id
ORDER BY j.name, s.name;
"@

$qLogins = @"
SELECT
    sp.name,
    sp.type_desc,
    sp.is_disabled,
    sp.create_date,
    sp.default_database_name
FROM sys.server_principals sp
WHERE sp.type IN ('S','U','G')
  AND sp.name NOT LIKE '##%'
ORDER BY sp.name;
"@

$qLinkedServers = @"
EXEC master.dbo.sp_linkedservers;
"@

$qServerConfigs = @"
SELECT
    name,
    value,
    value_in_use,
    description
FROM sys.configurations
ORDER BY name;
"@

# ---------------- Per instance ----------------
foreach ($instance in $instances) {
    $serverInstance = if ($instance -eq 'MSSQLSERVER') { $HostName } else { "$HostName\$instance" }
    $instanceKey = ($instance -replace '[^A-Za-z0-9_]', '_')

    Write-Log "Collecting from [$serverInstance]"

    try {
        $rows = DataTable-ToPsObject (Invoke-SqlQuery -ServerInstance $serverInstance -Database 'master' -Query $qInstanceInfo)
        $Sheets["${instanceKey}_Info"] = @($rows)
        Write-ObjectListToCsv -InputObject @($rows) -Path (Join-Path $BaseDir "${instanceKey}-instance-info.csv")
    } catch {
        Write-Log "Instance info failed for [$serverInstance]: $($_.Exception.Message)" 'ERROR'
        continue
    }

    try {
        $rows = DataTable-ToPsObject (Invoke-SqlQuery -ServerInstance $serverInstance -Database 'master' -Query $qDatabases)
        $Sheets["${instanceKey}_Databases"] = @($rows)
        Write-ObjectListToCsv -InputObject @($rows) -Path (Join-Path $BaseDir "${instanceKey}-databases.csv")
    } catch {
        Write-Log "Database inventory failed for [$serverInstance]: $($_.Exception.Message)" 'ERROR'
    }

    try {
        $rows = DataTable-ToPsObject (Invoke-SqlQuery -ServerInstance $serverInstance -Database 'master' -Query $qDbSizes)
        $Sheets["${instanceKey}_DBSizes"] = @($rows)
        Write-ObjectListToCsv -InputObject @($rows) -Path (Join-Path $BaseDir "${instanceKey}-db-sizes.csv")
    } catch {
        Write-Log "DB size inventory failed for [$serverInstance]: $($_.Exception.Message)" 'ERROR'
    }

    try {
        $rows = DataTable-ToPsObject (Invoke-SqlQuery -ServerInstance $serverInstance -Database 'msdb' -Query $qJobs)
        $Sheets["${instanceKey}_Jobs"] = @($rows)
        Write-ObjectListToCsv -InputObject @($rows) -Path (Join-Path $BaseDir "${instanceKey}-jobs.csv")
    } catch {
        Write-Log "Job inventory failed for [$serverInstance]: $($_.Exception.Message)" 'ERROR'
    }

    try {
        $rows = DataTable-ToPsObject (Invoke-SqlQuery -ServerInstance $serverInstance -Database 'msdb' -Query $qJobSchedules)
        $Sheets["${instanceKey}_JobSchedules"] = @($rows)
        Write-ObjectListToCsv -InputObject @($rows) -Path (Join-Path $BaseDir "${instanceKey}-job-schedules.csv")
    } catch {
        Write-Log "Job schedule inventory failed for [$serverInstance]: $($_.Exception.Message)" 'ERROR'
    }

    try {
        $rows = DataTable-ToPsObject (Invoke-SqlQuery -ServerInstance $serverInstance -Database 'master' -Query $qLogins)
        $Sheets["${instanceKey}_Logins"] = @($rows)
        Write-ObjectListToCsv -InputObject @($rows) -Path (Join-Path $BaseDir "${instanceKey}-logins.csv")
    } catch {
        Write-Log "Login inventory failed for [$serverInstance]: $($_.Exception.Message)" 'ERROR'
    }

    try {
        $rows = DataTable-ToPsObject (Invoke-SqlQuery -ServerInstance $serverInstance -Database 'master' -Query $qLinkedServers)
        $Sheets["${instanceKey}_LinkedServers"] = @($rows)
        Write-ObjectListToCsv -InputObject @($rows) -Path (Join-Path $BaseDir "${instanceKey}-linked-servers.csv")
    } catch {
        Write-Log "Linked server inventory failed for [$serverInstance]: $($_.Exception.Message)" 'ERROR'
    }

    try {
        $rows = DataTable-ToPsObject (Invoke-SqlQuery -ServerInstance $serverInstance -Database 'master' -Query $qServerConfigs)
        $Sheets["${instanceKey}_ServerConfigs"] = @($rows)
        Write-ObjectListToCsv -InputObject @($rows) -Path (Join-Path $BaseDir "${instanceKey}-server-configurations.csv")
    } catch {
        Write-Log "Server configuration inventory failed for [$serverInstance]: $($_.Exception.Message)" 'ERROR'
    }
}

# ---------------- Workbook ----------------
try {
    Write-ExcelXmlWorkbook -Sheets $Sheets -Path $WorkbookPath
    Write-Log "Workbook created: $WorkbookPath"
} catch {
    Write-Log "Workbook creation failed: $($_.Exception.Message)" 'ERROR'
}

# ---------------- Zip ----------------
try {
    Compress-Folder -SourceFolder $BaseDir -DestinationZip $ZipPath
    Write-Log "Zip created: $ZipPath"
} catch {
    Write-Log "Zip creation failed: $($_.Exception.Message)" 'ERROR'
    throw
}

# ---------------- Email ----------------
try {
    if ([string]::IsNullOrWhiteSpace($SendGridApiKey)) {
        Write-Log "SendGrid API key missing. Zip created but email skipped." 'WARN'
    }
    else {
        $subject = "SQL Audit - $HostName"
        $body = @"
Attached is the SQL audit collection for $HostName.

Included:
- CSV exports
- Excel-readable workbook
- Summary/error logs

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@

        Send-SendGridMail -ApiKey $SendGridApiKey -From $FromEmail -To $ToEmail -Subject $subject -BodyText $body -AttachmentPath $ZipPath
        Write-Log "Email sent to $ToEmail"
    }
} catch {
    Write-Log "Email send failed: $($_.Exception.Message)" 'ERROR'
    throw
}

Write-Log "SQL audit collection complete."
exit 0