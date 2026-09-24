# Fetch-Mitre-Data
To fetch MITRE Att&amp;ck Data by Technique, Sub-Technique mapped to ID, Tactics, Data Sources and Detection in CSV format.

This data in CSV format would be handy while correlating threat data from other sources.

## How to Execute
`powershell -ExecutionPolicy RemoteSigned -File "<.ps1 script>" -jsonfile "<json file path>" -outputcsv "<CSV file output path>"`

### Example: 
`powershell -ExecutionPolicy RemoteSigned -File "Fetch-Mitre-Data.ps1" -jsonfile "mitre.json" -outputcsv "mitre-data.csv"`
  - where 
    - jsonfile is the JSON file downloaded from MITRE Att&ck github repo
    - outputcsv is the path to write the final CSV file

Both parameters are required. The script works with Windows PowerShell 5.1 and PowerShell 7+.

## Output columns
Revoked and deprecated techniques are excluded. Multiple values in a cell are separated by `; `.

| Column | Description |
|---|---|
| Technique ID | ATT&CK ID, e.g. `T1003` or `T1003.001` |
| Technique Name | Technique or sub-technique name |
| Is Sub-technique | `True` for sub-techniques |
| Tactics | Tactics the technique belongs to, e.g. `credential-access` |
| Detection | Detection strategy (`DETxxxx: name`) followed by one line per analytic, prefixed with its platforms |
| Data Sources | Data components the analytics rely on, e.g. `Process Creation` |
| Log Sources | Log sources the analytics rely on, e.g. `WinEventLog:Security` |
| OS Platforms | Platforms the technique applies to |

Since ATT&CK v18, detection guidance is no longer stored on the technique itself; the script follows
the technique's detection strategies and their analytics to build the Detection, Data Sources and Log Sources columns.
