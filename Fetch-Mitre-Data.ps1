# Example: powershell -ExecutionPolicy RemoteSigned -File "Fetch-Mitre-Data.ps1" -jsonfile "mitre.json" -outputcsv "mitre-data.csv"

# Ensure the param keyword at the top of the script, before any other code.
param(
    [Parameter(Mandatory)]
    [string]$jsonfile,      # Path to save the JSON file
    [Parameter(Mandatory)]
    [string]$outputcsv      # Path for the output CSV file
)

# Stop on any error so a failed download never produces a CSV from a stale JSON file
$ErrorActionPreference = 'Stop'

# The progress bar slows Invoke-WebRequest down considerably in Windows PowerShell 5.1
$ProgressPreference = 'SilentlyContinue'

# Older .NET versions do not enable TLS 1.2 by default, which GitHub requires
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Separator used when joining multiple values into a single CSV cell
$separator = '; '

# Define the URL to the ATT&CK Enterprise JSON file
$url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Download the JSON file
Invoke-WebRequest -Uri $url -OutFile $jsonfile -UseBasicParsing

# Read the JSON file
$json = Get-Content $jsonfile -Raw -Encoding UTF8 | ConvertFrom-Json

# Returns $true for objects that MITRE has revoked or deprecated
function Test-Retired($object) {
    return [bool]($object.revoked -or $object.x_mitre_deprecated)
}

# Returns the ATT&CK ID (e.g. T1003, DET0103) of an object
function Get-AttackId($object) {
    $reference = $object.external_references | Where-Object { $_.source_name -eq 'mitre-attack' } | Select-Object -First 1
    if ($reference) { return $reference.external_id }
    return $null
}

# Joins values into a single cell, dropping duplicates and empty values
function Join-Values($values) {
    $unique = @($values | Where-Object { $_ } | Select-Object -Unique)
    if ($unique.Count -gt 0) { return $unique -join $separator }
    return "NA"
}

# Index every object by its STIX ID so relationships can be resolved
$objectsById = @{}
foreach ($object in $json.objects) {
    $objectsById[$object.id] = $object
}

# Map each technique to the detection strategies that detect it.
# Since ATT&CK v18, detection guidance lives in x-mitre-detection-strategy objects
# (linked to techniques by "detects" relationships) instead of on the technique itself.
$strategiesByTechnique = @{}
foreach ($object in $json.objects) {
    if ($object.type -ne "relationship" -or $object.relationship_type -ne "detects" -or (Test-Retired $object)) {
        continue
    }
    $strategy = $objectsById[$object.source_ref]
    if (-not $strategy -or (Test-Retired $strategy)) {
        continue
    }
    if (-not $strategiesByTechnique.ContainsKey($object.target_ref)) {
        $strategiesByTechnique[$object.target_ref] = New-Object System.Collections.ArrayList
    }
    [void]$strategiesByTechnique[$object.target_ref].Add($strategy)
}

# Loop through each technique and sub-technique ("attack-pattern" objects), skipping retired ones
$outputData = foreach ($object in $json.objects) {
    if ($object.type -ne "attack-pattern" -or (Test-Retired $object)) {
        continue
    }

    $detections = @()
    $dataSources = @()
    $logSources = @()
    foreach ($strategy in $strategiesByTechnique[$object.id]) {
        $detections += "$(Get-AttackId $strategy): $($strategy.name)"

        # Each detection strategy is made up of analytics, which reference the
        # data components and log sources needed to implement the detection
        foreach ($analyticRef in $strategy.x_mitre_analytic_refs) {
            $analytic = $objectsById[$analyticRef]
            if (-not $analytic -or (Test-Retired $analytic)) {
                continue
            }
            $platforms = if ($analytic.x_mitre_platforms) { $analytic.x_mitre_platforms -join ', ' } else { "All" }
            $detections += "[$platforms] $($analytic.description)"

            foreach ($logSource in $analytic.x_mitre_log_source_references) {
                $logSources += $logSource.name
                $dataComponent = $objectsById[$logSource.x_mitre_data_component_ref]
                if ($dataComponent) {
                    $dataSources += $dataComponent.name
                }
            }
        }
    }

    # Create a custom object for the technique; [ordered] keeps the CSV columns in this order
    [pscustomobject][ordered]@{
        "Technique ID"     = Get-AttackId $object
        "Technique Name"   = $object.name
        "Is Sub-technique" = [bool]$object.x_mitre_is_subtechnique
        "Tactics"          = Join-Values ($object.kill_chain_phases | Where-Object { $_.kill_chain_name -eq 'mitre-attack' } | ForEach-Object { $_.phase_name })
        "Detection"        = if ($detections) { $detections -join "`n" } else { "NA" }
        "Data Sources"     = Join-Values ($dataSources | Sort-Object)
        "Log Sources"      = Join-Values ($logSources | Sort-Object)
        "OS Platforms"     = Join-Values $object.x_mitre_platforms
    }
}

# Export the output data to a CSV file, sorted by Technique ID
$outputData | Sort-Object "Technique ID" | Export-Csv $outputcsv -NoTypeInformation -Encoding UTF8
