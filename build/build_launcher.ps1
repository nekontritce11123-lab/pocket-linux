[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$linuxRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = Split-Path -Parent $linuxRoot
$buildRoot = Join-Path $projectRoot 'Разработка\Служебное\_temp\2026-10-25-pocket-linux\desktop-build\launcher'
$output = Join-Path $buildRoot 'out'
$intermediate = Join-Path $buildRoot 'obj'
$feed = Join-Path $buildRoot 'empty-feed'
$packages = Join-Path $env:USERPROFILE '.nuget\packages'
$msbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe'
if (-not (Test-Path -LiteralPath $msbuild -PathType Leaf)) { throw 'Existing MSBuild Build Tools were not found; nothing will be installed.' }
foreach ($package in @('wpf-ui\3.0.5\lib\net472\Wpf.Ui.dll', 'microsoft.netframework.referenceassemblies.net48\1.0.3\build\Microsoft.NETFramework.ReferenceAssemblies.net48.targets')) {
    if (-not (Test-Path -LiteralPath (Join-Path $packages $package) -PathType Leaf)) { throw ('Required local package is missing: ' + $package) }
}
foreach ($directory in @($output, $intermediate, $feed)) { $null = New-Item -ItemType Directory -Path $directory -Force }
$config = Join-Path $buildRoot 'NuGet.Config'
$escapedFeed = [Security.SecurityElement]::Escape($feed)
[IO.File]::WriteAllText($config, '<configuration><packageSources><clear/><add key="offline" value="' + $escapedFeed + '" /></packageSources><config><add key="httpCachePath" value="' + [Security.SecurityElement]::Escape((Join-Path $buildRoot 'http-cache')) + '" /></config></configuration>')
& (Join-Path $linuxRoot 'ui\New-AppIcon.ps1') -OutputPath (Join-Path $linuxRoot 'ui\AppIcon.ico')
$project = Join-Path $linuxRoot 'launcher-wpf\Launcher.Wpf.csproj'
$properties = @(
    '-p:Configuration=Release',
    ('-p:OutDir=' + $output + '/'),
    ('-p:OutputPath=' + $output + '/'),
    ('-p:BaseIntermediateOutputPath=' + $intermediate + '/'),
    ('-p:IntermediateOutputPath=' + $intermediate + '/Release/'),
    ('-p:MSBuildProjectExtensionsPath=' + $intermediate + '/'),
    ('-p:RestorePackagesPath=' + $packages),
    ('-p:NuGetPackageRoot=' + $packages + '\'),
    ('-p:RestoreConfigFile=' + $config),
    ('-p:RestoreSources=' + $feed),
    '-p:RestoreIgnoreFailedSources=false',
    '-p:NuGetAudit=false'
)
# The only feed is an empty local directory: restore can reuse installed packages but cannot access the network.
& $msbuild $project -t:Restore -nologo -v:minimal @properties
if ($LASTEXITCODE -ne 0) { throw 'Offline launcher restore failed; no packages will be downloaded.' }
& $msbuild $project -t:Build -nologo -v:minimal @properties
if ($LASTEXITCODE -ne 0) { throw 'Linux launcher compilation failed.' }
$exe = Join-Path $output 'Launcher.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'MSBuild did not produce Launcher.exe.' }
$artifact = Get-Item -LiteralPath $exe
[pscustomobject]@{ Executable = $exe; Bytes = $artifact.Length; SHA256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash; OfflineRestore = $true } | ConvertTo-Json
