# Example: powershell -Exec Bypass -File "Fetch-Mitre-Data.ps1" -jsonfile "mitre.json" -outputcsv "mitre-data.csv"

# Ensure the param keyword at the top of the script, before any other code.
param(
    [string]$jsonfile,      # Path to save the JSON file
    [string]$outputcsv  # Path for the output CSV file
)

# Define the URL to the ATT&CK Enterprise JSON file
$url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Download the JSON file
Invoke-WebRequest -Uri $url -OutFile $jsonfile

# Read the JSON file
$json = Get-Content $jsonfile | ConvertFrom-Json

# Create an empty array to hold the output data
$outputData = @()

# Loop through each object in the "objects" array
foreach ($object in $json.objects) {
    # If the object type is "attack-pattern" (which corresponds to a technique)
    if ($object.type -eq "attack-pattern") {
        # Create a custom object with the Technique ID and name
        $techniqueData = New-Object PSObject -Property @{
            "Technique ID" = $object.external_references[0].external_id
            "Technique Name" = $object.name
			"Detection" = $object.x_mitre_detection
			"Data Sources" = if ($object.x_mitre_data_sources) { $object.x_mitre_data_sources -join '| ' } else { "NA" }
			"OS Platforms" = if ($object.x_mitre_platforms) { $object.x_mitre_platforms -join '| '} else { "NA" }
        }

        # Add the custom object to the output data array
        $outputData += $techniqueData
    }
}

# Export the output data to a CSV file
$outputData | Export-Csv $outputcsv -NoTypeInformation