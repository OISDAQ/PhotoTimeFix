param(
  [int]$Port = 4173,
  [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$script:Scans = @{}
$script:SourceExtensions = @('.arw', '.jpg', '.jpeg')
$script:TargetExtensions = @('.jpg', '.jpeg', '.avif')

function Write-Response {
  param($Context, [int]$StatusCode, [string]$ContentType, [byte[]]$Bytes)
  $Context.Response.StatusCode = $StatusCode
  $Context.Response.ContentType = $ContentType
  $Context.Response.ContentEncoding = [Text.Encoding]::UTF8
  $Context.Response.ContentLength64 = $Bytes.Length
  $Context.Response.OutputStream.Write($Bytes, 0, $Bytes.Length)
  $Context.Response.Close()
}

function Write-Json {
  param($Context, $Data, [int]$StatusCode = 200)
  $json = $Data | ConvertTo-Json -Depth 6 -Compress
  Write-Response $Context $StatusCode 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($json))
}

function Read-JsonBody {
  param($Request)
  $reader = New-Object IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
  $text = $reader.ReadToEnd()
  $reader.Close()
  if ([string]::IsNullOrWhiteSpace($text)) { return $null }
  return $text | ConvertFrom-Json
}

function Read-U16 {
  param([byte[]]$Bytes, [int]$Position, [bool]$LittleEndian)
  if ($Position -lt 0 -or $Position + 1 -ge $Bytes.Length) { return $null }
  if ($LittleEndian) { return [int]$Bytes[$Position] + ([int]$Bytes[$Position + 1] * 256) }
  return ([int]$Bytes[$Position] * 256) + [int]$Bytes[$Position + 1]
}

function Read-U32 {
  param([byte[]]$Bytes, [int]$Position, [bool]$LittleEndian)
  if ($Position -lt 0 -or $Position + 3 -ge $Bytes.Length) { return $null }
  if ($LittleEndian) {
    return [uint64]$Bytes[$Position] + ([uint64]$Bytes[$Position + 1] * 256) + ([uint64]$Bytes[$Position + 2] * 65536) + ([uint64]$Bytes[$Position + 3] * 16777216)
  }
  return ([uint64]$Bytes[$Position] * 16777216) + ([uint64]$Bytes[$Position + 1] * 65536) + ([uint64]$Bytes[$Position + 2] * 256) + [uint64]$Bytes[$Position + 3]
}

function Read-ExifAscii {
  param([byte[]]$Bytes, [int]$TiffBase, [int]$EntryPosition, [bool]$LittleEndian)
  $type = Read-U16 $Bytes ($EntryPosition + 2) $LittleEndian
  $count = Read-U32 $Bytes ($EntryPosition + 4) $LittleEndian
  if ($type -ne 2 -or $null -eq $count -or $count -lt 1 -or $count -gt 128) { return $null }
  if ($count -le 4) { $start = $EntryPosition + 8 } else { $start = $TiffBase + [int](Read-U32 $Bytes ($EntryPosition + 8) $LittleEndian) }
  if ($start -lt 0 -or $start + [int]$count -gt $Bytes.Length) { return $null }
  return ([Text.Encoding]::ASCII.GetString($Bytes, $start, [int]$count)).Trim([char]0)
}

function Get-IfdInfo {
  param([byte[]]$Bytes, [int]$TiffBase, [int]$IfdPosition, [bool]$LittleEndian)
  $result = [pscustomobject]@{ DateText = $null; ExifOffset = $null }
  $count = Read-U16 $Bytes $IfdPosition $LittleEndian
  if ($null -eq $count -or $count -gt 5000 -or $IfdPosition + 2 + ($count * 12) -gt $Bytes.Length) { return $result }
  for ($i = 0; $i -lt $count; $i++) {
    $entry = $IfdPosition + 2 + ($i * 12)
    $tag = Read-U16 $Bytes $entry $LittleEndian
    if ($tag -eq 0x9003 -or $tag -eq 0x9004 -or $tag -eq 0x0132) {
      $date = Read-ExifAscii $Bytes $TiffBase $entry $LittleEndian
      if ($date -and -not $result.DateText) { $result.DateText = $date }
    }
    elseif ($tag -eq 0x8769) {
      $offset = Read-U32 $Bytes ($entry + 8) $LittleEndian
      if ($null -ne $offset) { $result.ExifOffset = [int]$offset }
    }
  }
  return $result
}

function Convert-ExifDate {
  param([string]$Text)
  if ($Text -notmatch '^(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})') { return $null }
  try { return [datetime]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4], [int]$Matches[5], [int]$Matches[6]) } catch { return $null }
}

function Get-TiffDate {
  param([byte[]]$Bytes, [int]$TiffBase)
  if ($TiffBase -lt 0 -or $TiffBase + 8 -gt $Bytes.Length) { return $null }
  $little = $Bytes[$TiffBase] -eq 0x49 -and $Bytes[$TiffBase + 1] -eq 0x49
  $big = $Bytes[$TiffBase] -eq 0x4D -and $Bytes[$TiffBase + 1] -eq 0x4D
  if (-not ($little -or $big)) { return $null }
  if ((Read-U16 $Bytes ($TiffBase + 2) $little) -ne 42) { return $null }
  $ifdOffset = Read-U32 $Bytes ($TiffBase + 4) $little
  if ($null -eq $ifdOffset) { return $null }
  $ifd0 = Get-IfdInfo $Bytes $TiffBase ($TiffBase + [int]$ifdOffset) $little
  if ($ifd0.ExifOffset) {
    $exif = Get-IfdInfo $Bytes $TiffBase ($TiffBase + $ifd0.ExifOffset) $little
    $date = Convert-ExifDate $exif.DateText
    if ($date) { return $date }
  }
  return Convert-ExifDate $ifd0.DateText
}

function Get-CaptureDate {
  param([string]$Path)
  try {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $length = [Math]::Min($stream.Length, 16MB)
      $bytes = New-Object byte[] ([int]$length)
      [void]$stream.Read($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
  } catch { return $null }
  if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xD8) {
    $pos = 2
    while ($pos + 4 -le $bytes.Length) {
      if ($bytes[$pos] -ne 0xFF) { $pos++; continue }
      $marker = $bytes[$pos + 1]
      if ($marker -eq 0xD9 -or $marker -eq 0xDA) { break }
      $segmentLength = ([int]$bytes[$pos + 2] * 256) + [int]$bytes[$pos + 3]
      if ($segmentLength -lt 2 -or $pos + 2 + $segmentLength -gt $bytes.Length) { break }
      if ($marker -eq 0xE1 -and $segmentLength -ge 8 -and [Text.Encoding]::ASCII.GetString($bytes, $pos + 4, 6) -eq "Exif`0`0") {
        return Get-TiffDate $bytes ($pos + 10)
      }
      $pos += 2 + $segmentLength
    }
    return $null
  }
  return Get-TiffDate $bytes 0
}

function Get-RelativeName {
  param([string]$Root, [string]$Path)
  return $Path.Substring($Root.TrimEnd('\').Length).TrimStart('\')
}

function Convert-ShellDateProperty {
  param($Value)
  if ($null -eq $Value) { return $null }
  if ($Value -is [array]) {
    foreach ($entry in $Value) {
      $date = Convert-ShellDateProperty $entry
      if ($date) { return $date }
    }
    return $null
  }
  if ($Value.PSObject.Properties['Value']) { $Value = $Value.Value }
  if ($Value -is [datetime]) { return ([datetime]$Value).ToLocalTime() }
  $parsed = [datetime]::MinValue
  if ([datetime]::TryParse($Value.ToString(), [Globalization.CultureInfo]::CurrentCulture, [Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$parsed)) { return $parsed.ToLocalTime() }
  return $null
}

function Get-DateTakenProperty {
  param([string]$Path)
  $shell = $null
  try {
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.Namespace([IO.Path]::GetDirectoryName($Path))
    if ($null -eq $folder) { return $null }
    $item = $folder.ParseName([IO.Path]::GetFileName($Path))
    if ($null -eq $item) { return $null }
    $properties = @(
      [pscustomobject]@{ Key = 'System.Photo.DateTaken'; Label = '拍摄日期' },
      [pscustomobject]@{ Key = 'System.Media.DateEncoded'; Label = '媒体编码日期' },
      [pscustomobject]@{ Key = 'System.ItemDate'; Label = '项目日期' }
    )
    foreach ($property in $properties) {
      $value = $item.ExtendedProperty($property.Key) 2>$null
      $date = Convert-ShellDateProperty $value
      if ($date) { return [pscustomobject]@{ Date = $date; Label = $property.Label } }
    }
    return $null
  } catch { return $null }
  finally {
    if ($shell) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
  }
}

function Get-Scan {
  param([string]$TargetDirectory)
  if (-not (Test-Path -LiteralPath $TargetDirectory -PathType Container)) { throw '目标文件夹不存在。' }
  $targets = Get-ChildItem -LiteralPath $TargetDirectory -File -Recurse -Force | Where-Object { $script:TargetExtensions -contains $_.Extension.ToLowerInvariant() }
  $operations = New-Object System.Collections.ArrayList
  $missingDateTaken = 0
  foreach ($target in $targets) {
    $dateProperty = Get-DateTakenProperty $target.FullName
    if ($dateProperty) {
      [void]$operations.Add([pscustomobject]@{
        Source = '文件属性：' + $dateProperty.Label
        Target = Get-RelativeName $TargetDirectory $target.FullName
        TargetPath = $target.FullName
        Date = $dateProperty.Date
        DateText = $dateProperty.Date.ToString('yyyy-MM-dd HH:mm:ss')
        CurrentCreationText = $target.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
        CurrentText = $target.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
      })
    } else { $missingDateTaken++ }
  }
  return [pscustomobject]@{
    stats = [pscustomobject]@{ targetFiles = @($targets).Count; matchedFiles = $operations.Count; missingDateTaken = $missingDateTaken }
    operations = $operations
  }
}

function Choose-Folder {
  param([string]$Description)
  Add-Type -AssemblyName System.Windows.Forms
  $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
  $dialog.Description = $Description
  $dialog.ShowNewFolderButton = $false
  if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.SelectedPath }
  return $null
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = '照片拍摄日期同步工具'
$form.StartPosition = 'CenterScreen'
$form.ClientSize = New-Object System.Drawing.Size(960, 650)
$form.MinimumSize = New-Object System.Drawing.Size(760, 520)
$form.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 9)

$title = New-Object System.Windows.Forms.Label
$title.Text = '同步导出照片的修改时间'
$title.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 16, [System.Drawing.FontStyle]::Bold)
$title.Location = New-Object System.Drawing.Point(24, 20)
$title.AutoSize = $true
$form.Controls.Add($title)

$hint = New-Object System.Windows.Forms.Label
$hint.Text = '直接读取 Windows 文件属性中的拍摄日期，并同步写入创建时间和修改日期。'
$hint.Location = New-Object System.Drawing.Point(26, 55)
$hint.AutoSize = $true
$hint.ForeColor = [System.Drawing.Color]::DimGray
$form.Controls.Add($hint)

function Add-FolderRow {
  param([string]$LabelText, [int]$Top, [string]$DialogText)
  $label = New-Object System.Windows.Forms.Label
  $label.Text = $LabelText
  $label.Location = [System.Drawing.Point]::new(26, ($Top + 5))
  $label.Size = New-Object System.Drawing.Size(125, 24)
  $form.Controls.Add($label)
  $box = New-Object System.Windows.Forms.TextBox
  $box.Location = [System.Drawing.Point]::new(150, $Top)
  $box.Anchor = 'Top,Left,Right'
  $box.Size = New-Object System.Drawing.Size(675, 28)
  $form.Controls.Add($box)
  $button = New-Object System.Windows.Forms.Button
  $button.Text = '选择文件夹'
  $button.Location = [System.Drawing.Point]::new(835, ($Top - 1))
  $button.Anchor = 'Top,Right'
  $button.Size = New-Object System.Drawing.Size(100, 29)
  $button.Add_Click({ $picked = Choose-Folder $DialogText; if ($picked) { $box.Text = $picked } }.GetNewClosure())
  $form.Controls.Add($button)
  return $box
}

$targetBox = Add-FolderRow '照片文件夹（JPG/AVIF）' 95 '选择需要同步修改时间的照片文件夹（JPG / JPEG / AVIF）'

$scanButton = New-Object System.Windows.Forms.Button
$scanButton.Text = '扫描并预览'
$scanButton.Location = New-Object System.Drawing.Point(26, 134)
$scanButton.Size = New-Object System.Drawing.Size(120, 34)
$form.Controls.Add($scanButton)

$applyButton = New-Object System.Windows.Forms.Button
$applyButton.Text = '确认写入修改时间'
$applyButton.Location = New-Object System.Drawing.Point(156, 134)
$applyButton.Size = New-Object System.Drawing.Size(150, 34)
$applyButton.Enabled = $false
$form.Controls.Add($applyButton)

$status = New-Object System.Windows.Forms.Label
$status.Text = '请选择两个文件夹，然后扫描预览。'
$status.Location = New-Object System.Drawing.Point(325, 142)
$status.Anchor = 'Top,Left,Right'
$status.Size = New-Object System.Drawing.Size(610, 24)
$status.ForeColor = [System.Drawing.Color]::DimGray
$form.Controls.Add($status)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(26, 183)
$grid.Anchor = 'Top,Bottom,Left,Right'
$grid.Size = New-Object System.Drawing.Size(909, 435)
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false
$grid.RowHeadersVisible = $false
$grid.AutoSizeColumnsMode = 'Fill'
$grid.SelectionMode = 'FullRowSelect'
$grid.Columns.Add('Source', '拍摄日期来源') | Out-Null
$grid.Columns.Add('Target', '目标文件') | Out-Null
$grid.Columns.Add('CurrentCreation', '当前创建时间') | Out-Null
$grid.Columns.Add('Current', '当前修改时间') | Out-Null
$grid.Columns.Add('Capture', '将同步为拍摄时间') | Out-Null
$form.Controls.Add($grid)

$script:CurrentOperations = @()
$scanButton.Add_Click({
  if ([string]::IsNullOrWhiteSpace($targetBox.Text)) {
    $status.Text = '请选择照片文件夹。'; $status.ForeColor = [System.Drawing.Color]::Firebrick; return
  }
  $scanButton.Enabled = $false; $applyButton.Enabled = $false
  $status.Text = '正在读取文件属性中的拍摄日期…'; $status.ForeColor = [System.Drawing.Color]::DimGray
  [System.Windows.Forms.Application]::DoEvents()
  try {
    $scan = Get-Scan $targetBox.Text.Trim()
    $script:CurrentOperations = @($scan.operations)
    $grid.Rows.Clear()
    foreach ($operation in $script:CurrentOperations) { [void]$grid.Rows.Add($operation.Source, $operation.Target, $operation.CurrentCreationText, $operation.CurrentText, $operation.DateText) }
    $status.Text = "扫描文件 $($scan.stats.targetFiles) 个，可读取拍摄日期 $($scan.stats.matchedFiles) 个，未找到拍摄日期 $($scan.stats.missingDateTaken) 个。"
    $status.ForeColor = if ($script:CurrentOperations.Count) { [System.Drawing.Color]::DarkGreen } else { [System.Drawing.Color]::Firebrick }
    $applyButton.Enabled = $script:CurrentOperations.Count -gt 0
  } catch { $status.Text = $_.Exception.Message; $status.ForeColor = [System.Drawing.Color]::Firebrick }
  finally { $scanButton.Enabled = $true }
})

$applyButton.Add_Click({
  $answer = [System.Windows.Forms.MessageBox]::Show("将立即同步 $($script:CurrentOperations.Count) 个文件的创建时间和修改日期。确认继续？", '确认写入', [System.Windows.Forms.MessageBoxButtons]::OKCancel, [System.Windows.Forms.MessageBoxIcon]::Warning)
  if ($answer -ne [System.Windows.Forms.DialogResult]::OK) { return }
  $updated = 0; $failed = 0
  foreach ($operation in $script:CurrentOperations) {
    try {
      $item = Get-Item -LiteralPath $operation.TargetPath
      $item.CreationTime = $operation.Date
      $item.LastWriteTime = $operation.Date
      $updated++
    }
    catch { $failed++ }
  }
  $status.Text = if ($failed) { "已同步 $updated 个文件；$failed 个文件未能写入。" } else { "已成功同步 $updated 个文件的创建时间和修改日期。" }
  $status.ForeColor = if ($failed) { [System.Drawing.Color]::Firebrick } else { [System.Drawing.Color]::DarkGreen }
})

[void][System.Windows.Forms.Application]::Run($form)
