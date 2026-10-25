param([string]$Project = (Split-Path -Parent $PSScriptRoot))

# Derived from Pocket Windows' offline component repair; no installation or network operations.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$result = [ordered]@{ ok = $false; code = 'error'; message = 'Component preparation failed. No user data was changed.'; checked_files = 0; repaired_files = 0 }
$operationLock = $null
$linuxLock = $null
$archive = $null
$stage = $null
$maxFiles = 16384
$maxFileBytes = 512L * 1024 * 1024
$maxTotalBytes = 2L * 1024 * 1024 * 1024

function Assert-PlainPath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.LinkType -eq 'HardLink') {
                throw 'Reparse and hard-link paths are not supported.'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function Assert-RuntimeName([string]$Name) {
    if ($Name.Length -gt 1024 -or
        ($Name -cne 'PocketNet.exe' -and $Name -cnotmatch '^runtime/(python-3\.12\.14|qemu-11\.1\.0|host-files)/[^/]+(/[^/]+)*$') -or
        $Name.Contains('\') -or $Name.Contains(':') -or
        @($Name.Split('/') | Where-Object { $_ -in @('.', '..') -or $_.EndsWith('.') -or $_.EndsWith(' ') -or
            $_ -match '[<>"|?*\x00-\x1f]' -or $_ -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)' }).Count) {
        throw 'Invalid component path.'
    }
}

function Test-Component([string]$Path, $Record) {
    Assert-PlainPath $Path
    if (-not [IO.File]::Exists($Path)) { return $false }
    if ((Get-Item -LiteralPath $Path).Length -ne [long]$Record.bytes) { return $false }
    $stream = [IO.File]::OpenRead($Path)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-', '') -eq $Record.sha256
    } finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function Expand-Bounded($Entry, [string]$Destination, [long]$Length) {
    $source = $Entry.Open()
    $target = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $buffer = New-Object byte[] 65536
        $remaining = $Length
        while ($remaining -gt 0) {
            $read = $source.Read($buffer, 0, [int][Math]::Min($remaining, $buffer.Length))
            if ($read -le 0) { throw 'Truncated component.' }
            $target.Write($buffer, 0, $read)
            $remaining -= $read
        }
        if ($source.ReadByte() -ne -1) { throw 'Oversized component.' }
        $target.Flush()
    } finally {
        $target.Dispose()
        $source.Dispose()
    }
}

try {
    $Project = [IO.Path]::GetFullPath($Project)
    Assert-PlainPath $Project
    $manifestPath = Join-Path $Project 'runtime/components-manifest.json'
    Assert-PlainPath $manifestPath
    if (-not [IO.File]::Exists($manifestPath)) {
        $result.code = 'package_missing'
        $result.message = 'Restore the complete portable distribution including its component manifest.'
        throw 'Component manifest missing.'
    }
    $result.code = 'invalid_package'
    $result.message = 'The recovery package or manifest is invalid. Restore the complete portable distribution.'
    if ((Get-Item -LiteralPath $manifestPath).Length -gt 16 * 1024 * 1024) { throw 'Manifest too large.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (($manifest.schema -isnot [int] -and $manifest.schema -isnot [long]) -or $manifest.schema -ne 1 -or
        $manifest.files -isnot [Array] -or $manifest.files.Count -eq 0 -or $manifest.files.Count -gt $maxFiles -or
        @($manifest.PSObject.Properties.Name | Where-Object { $_ -notin @('schema', 'files') }).Count) { throw 'Invalid manifest schema.' }
    $records = @{}
    $total = 0L
    foreach ($record in $manifest.files) {
        if ($record.path -isnot [string] -or $record.sha256 -isnot [string] -or
            ($record.bytes -isnot [int] -and $record.bytes -isnot [long]) -or
            @($record.PSObject.Properties.Name | Where-Object { $_ -notin @('path', 'bytes', 'sha256') }).Count) { throw 'Invalid manifest fields.' }
        Assert-RuntimeName $record.path
        if ($records.ContainsKey($record.path) -or $record.sha256 -notmatch '^[0-9a-fA-F]{64}$' -or
            $record.bytes -lt 0 -or $record.bytes -gt $maxFileBytes) { throw 'Invalid manifest.' }
        $total += [long]$record.bytes
        if ($total -gt $maxTotalBytes) { throw 'Runtime size exceeds bound.' }
        $records[$record.path] = $record
    }
    foreach ($essential in @('PocketNet.exe', 'runtime/python-3.12.14/python.exe',
                            'runtime/qemu-11.1.0/qemu-system-x86_64.exe', 'runtime/qemu-11.1.0/qemu-img.exe',
                            'runtime/host-files/HostFiles.exe')) {
        if (-not $records.ContainsKey($essential)) { throw 'Required component missing from manifest.' }
    }
    $state = Join-Path $Project 'state'
    $operationPath = Join-Path $state 'operation.lock'
    $linuxPath = Join-Path $state 'linux.lock'
    Assert-PlainPath $operationPath
    Assert-PlainPath $linuxPath
    [IO.Directory]::CreateDirectory($state) | Out-Null
    try {
        # Match profile_store._exclusive_file and start.disk_lock, in the supervisor's lock order.
        $operationLock = [IO.File]::Open($operationPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $linuxLock = [IO.File]::Open($linuxPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        $linuxLock.Lock(0, 1)
    } catch {
        $result.code = 'runtime_busy'
        $result.message = 'Another operation or Linux session is active. Shut it down normally and retry.'
        throw 'Runtime locked.'
    }
    $needed = @()
    foreach ($name in ($records.Keys | Sort-Object)) {
        if (-not (Test-Component (Join-Path $Project $name) $records[$name])) { $needed += $name }
        $result.checked_files++
    }
    if ($needed.Count -eq 0) {
        $result.ok = $true
        $result.code = 'ready'
        $result.message = 'Portable runtime components are verified and ready.'
    } else {
        $result.code = 'runtime_busy'
        $result.message = 'A component process is active or its ownership could not be verified. No components were replaced.'
        $runtime = Join-Path $Project 'runtime'
        Assert-PlainPath $runtime
        $prefixes = @([IO.Path]::GetFullPath($runtime).TrimEnd('\') + '\')
        $networkPaths = @((Join-Path $Project 'PocketNet.exe'))
        $fso = $null
        try {
            $fso = New-Object -ComObject Scripting.FileSystemObject
            $shortRoot = $fso.GetFolder($Project).ShortPath
            if ($shortRoot) {
                $prefixes += (Join-Path $shortRoot 'runtime').TrimEnd('\') + '\'
                if ([IO.File]::Exists((Join-Path $Project 'PocketNet.exe'))) { $networkPaths += $fso.GetFile((Join-Path $Project 'PocketNet.exe')).ShortPath }
            }
        } finally { if ($fso) { [Runtime.InteropServices.Marshal]::FinalReleaseComObject($fso) | Out-Null } }
        $processes = @(Get-CimInstance Win32_Process -Filter "Name LIKE 'qemu%' OR Name = 'PocketNet.exe' OR Name = 'HostFiles.exe'")
        foreach ($process in $processes) {
            $image = $process.ExecutablePath
            if (-not $image -or @($prefixes | Where-Object { $image.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -or
                @($networkPaths | Where-Object { [string]::Equals($image, $_, [StringComparison]::OrdinalIgnoreCase) }).Count) { throw 'Owned component process is active.' }
        }
        $package = Join-Path $runtime 'components-recovery.zip'
        Assert-PlainPath $package
        if (-not [IO.File]::Exists($package)) {
            $result.code = 'package_missing'
            $result.message = 'Restore runtime/components-recovery.zip from the complete portable distribution.'
            throw 'Recovery package missing.'
        }
        $result.code = 'invalid_package'
        $result.message = 'The recovery package is invalid. Restore it from the complete portable distribution.'
        if ((Get-Item -LiteralPath $package).Length -gt $maxTotalBytes + 16 * 1024 * 1024) { throw 'Archive too large.' }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [IO.Compression.ZipFile]::OpenRead($package)
        if ($archive.Entries.Count -ne $records.Count) { throw 'Incomplete recovery package.' }
        $entries = @{}
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            Assert-RuntimeName $name
            $unixType = ($entry.ExternalAttributes -shr 16) -band 61440
            if ($entries.ContainsKey($name) -or -not $records.ContainsKey($name) -or
                $unixType -notin @(0, 32768) -or ($entry.ExternalAttributes -band 1104) -ne 0 -or
                $entry.Length -ne [long]$records[$name].bytes) { throw 'Invalid archive entry.' }
            $entries[$name] = $entry
        }
        $stage = Join-Path $runtime ('.repair-' + [Guid]::NewGuid().ToString('N'))
        Assert-PlainPath $stage
        [IO.Directory]::CreateDirectory($stage) | Out-Null
        # Verify the entire archive before replacing even one missing/corrupt component.
        foreach ($name in ($entries.Keys | Sort-Object)) {
            $destination = Join-Path $stage $name
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
            Expand-Bounded $entries[$name] $destination ([long]$records[$name].bytes)
            if (-not (Test-Component $destination $records[$name])) { throw 'Component verification failed.' }
        }
        $result.code = 'error'
        $result.message = 'Component repair could not finish. Close programs using this runtime and retry.'
        foreach ($name in $needed) {
            $destination = Join-Path $Project $name
            Assert-PlainPath $destination
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
            Assert-PlainPath $destination
            $source = Join-Path $stage $name
            if ([IO.File]::Exists($destination)) { [IO.File]::Replace($source, $destination, [NullString]::Value) }
            else { [IO.File]::Move($source, $destination) }
            if (-not (Test-Component $destination $records[$name])) { throw 'Repaired component verification failed.' }
            $result.repaired_files++
        }
        $result.ok = $true
        $result.code = 'repaired'
        $result.message = 'Portable components were restored beside the launcher and verified.'
    }
} catch {
    # Never return raw exceptions or private host paths to the launcher.
} finally {
    if ($archive) { $archive.Dispose() }
    if ($stage -and [IO.Directory]::Exists($stage)) {
        try {
            Assert-PlainPath $stage
            if ([IO.Path]::GetDirectoryName($stage) -ne (Join-Path $Project 'runtime') -or
                [IO.Path]::GetFileName($stage) -notmatch '^\.repair-[0-9a-f]{32}$') { throw 'Invalid staging directory.' }
            Remove-Item -LiteralPath $stage -Recurse -Force
        } catch { }
    }
    if ($linuxLock) { $linuxLock.Dispose() }
    if ($operationLock) { $operationLock.Dispose() }
}
$result | ConvertTo-Json -Compress
