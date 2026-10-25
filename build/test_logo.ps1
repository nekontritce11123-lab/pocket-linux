[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase
[xml]$app = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\launcher-wpf\App.xaml') -Raw
$ns = New-Object Xml.XmlNamespaceManager $app.NameTable
$ns.AddNamespace('p', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
$ns.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
$template = $app.SelectSingleNode('//p:ControlTemplate[@x:Key="LogoMark"]', $ns)
$dictionary = [Windows.Markup.XamlReader]::Parse('<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">' + $template.OuterXml + '</ResourceDictionary>')
$logo = New-Object Windows.Controls.ContentControl
$logo.Template = $dictionary['LogoMark']
$logo.Width = 72; $logo.Height = 72
$logo.Measure((New-Object Windows.Size 72,72))
$logo.Arrange((New-Object Windows.Rect 0,0,72,72))
$logo.UpdateLayout()
$bitmap = New-Object Windows.Media.Imaging.RenderTargetBitmap 72,72,96,96,([Windows.Media.PixelFormats]::Pbgra32)
$bitmap.Render($logo)
$pixels = New-Object byte[] (72*72*4)
$bitmap.CopyPixels($pixels,72*4,0)
$left=72; $right=-1; $top=72; $bottom=-1
for($y=0;$y -lt 72;$y++){for($x=0;$x -lt 72;$x++){if($pixels[($y*72+$x)*4+3] -gt 128){
    $left=[Math]::Min($left,$x);$right=[Math]::Max($right,$x);$top=[Math]::Min($top,$y);$bottom=[Math]::Max($bottom,$y)
}}}
if($right-$left -lt 63 -or $bottom-$top -lt 63){throw 'Logo is too small in its 72-pixel control.'}
if([Math]::Abs(($left+$right)/2-35.5) -gt 1 -or [Math]::Abs(($top+$bottom)/2-35.5) -gt 1){throw 'Logo is not centered.'}
$encoder = New-Object Windows.Media.Imaging.PngBitmapEncoder
$encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
$stream=[IO.File]::Create($Output)
try{$encoder.Save($stream)}finally{$stream.Dispose()}
[pscustomobject]@{Passed=$true;Bounds=@($left,$top,$right,$bottom);Output=$Output}|ConvertTo-Json
