$since = (Get-Date).AddMinutes(-30)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$since} -ErrorAction SilentlyContinue |
ForEach-Object {
  $d = @{}
  ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  $parent = if ($d['ParentProcessName']) { Split-Path $d['ParentProcessName'] -Leaf } else { 'pid ' + $d['ProcessId'] }
  $proc   = if ($d['NewProcessName'])    { Split-Path $d['NewProcessName'] -Leaf }    else { '?' }
  [pscustomobject]@{
    Time   = $_.TimeCreated.ToString('HH:mm:ss')
    Parent = $parent
    Proc   = $proc
    Cmd    = $d['CommandLine']
  }
} | Where-Object {
  $_.Proc -match 'powershell|pwsh|cmd|python|node|bash|conhost|curl' -and
  $_.Cmd -notmatch 'view-cmds'
} | Format-Table -AutoSize -Wrap