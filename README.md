# Fetch-Mitre-Data
To fetch MITRE Att&amp;ck Data by Technique, Sub-Technique mapped to ID, Data Sources and Detection in CSV format.

This data in CSV format would be handy while correlating threat data from other sources.

## How to Execute
`powershell -Exec Bypass -File "<.ps1 script>" -jsonfile "<json file path>" -outputcsv "<CSV file output path>"`

### Example: 
`powershell -Exec Bypass -File "Fetch-Mitre-Data.ps1" -jsonfile "mitre.json" -outputcsv "mitre-data.csv"`
  - where 
    - jsonfile is the JSON file downloaded from MITRE Att&ck github repo
    - outputcsv is the path to write the final CSV file
