[CmdletBinding()]
param([string]$OutputPath = (Join-Path $PSScriptRoot 'AppIcon.ico'))
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
# App icon: the launcher's Debian-inspired spiral on the same blue rounded tile; multi-size ICO.

function RoundRect([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $path.AddArc($x, $y, $d, $d, 180, 90); $path.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $path.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90); $path.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $path.CloseFigure(); $path
}

function Frame([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'
    $s = $size / 256.0
    $tile = RoundRect (8 * $s) (8 * $s) (240 * $s) (240 * $s) (56 * $s)
    $fill = New-Object System.Drawing.Drawing2D.LinearGradientBrush (New-Object System.Drawing.PointF 0, 0), (New-Object System.Drawing.PointF $size, $size), ([System.Drawing.Color]::FromArgb(74, 163, 255)), ([System.Drawing.Color]::FromArgb(36, 110, 224))
    $g.FillPath($fill, $tile)
    $spiral = New-Object System.Drawing.Drawing2D.GraphicsPath
    $spiral.AddBezier(123, 120, 100, 144, 61, 133, 50, 108)
    $spiral.AddBezier(50, 108, 36, 75, 58, 37, 92, 33)
    $spiral.AddBezier(92, 33, 123, 29, 145, 53, 141, 79)
    $spiral.AddBezier(141, 79, 138, 102, 115, 115, 94, 105)
    $spiral.AddBezier(94, 105, 77, 97, 76, 76, 87, 67)
    $spiral.AddBezier(87, 67, 97, 58, 110, 63, 113, 73)
    $spiral.AddBezier(113, 73, 116, 82, 109, 90, 101, 87)
    $bounds = $spiral.GetBounds()
    $markScale = 170.0 / [Math]::Max($bounds.Width, $bounds.Height)
    $offsetX = 128.0 - ($bounds.Left + $bounds.Width / 2.0) * $markScale
    $offsetY = 128.0 - ($bounds.Top + $bounds.Height / 2.0) * $markScale
    $matrix = New-Object System.Drawing.Drawing2D.Matrix ([float]($markScale * $s)), 0, 0, ([float]($markScale * $s)), ([float]($offsetX * $s)), ([float]($offsetY * $s))
    $spiral.Transform($matrix)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), ([float](10 * $markScale * $s))
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
    $g.DrawPath($pen, $spiral)
    $pen.Dispose(); $matrix.Dispose(); $spiral.Dispose(); $fill.Dispose(); $tile.Dispose()
    $g.Dispose(); $bmp
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
# PNG only for 256: System.Drawing (tray icon) cannot read small PNG frames, so they are 32-bit DIBs.
function Dib($bmp) {
    $n = $bmp.Width; $ms = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter $ms
    $mask = [int]([Math]::Ceiling($n / 32.0) * 4)
    $w.Write([uint32]40); $w.Write([int32]$n); $w.Write([int32]($n * 2)); $w.Write([uint16]1); $w.Write([uint16]32)
    $w.Write([uint32]0); $w.Write([uint32]($n * $n * 4 + $mask * $n)); $w.Write([int32]0); $w.Write([int32]0); $w.Write([uint32]0); $w.Write([uint32]0)
    for ($y = $n - 1; $y -ge 0; $y--) { for ($x = 0; $x -lt $n; $x++) { $c = $bmp.GetPixel($x, $y); $w.Write([byte]$c.B); $w.Write([byte]$c.G); $w.Write([byte]$c.R); $w.Write([byte]$c.A) } }
    $w.Write((New-Object byte[] ($mask * $n))); $w.Flush(); , $ms.ToArray()
}
$images = foreach ($size in $sizes) {
    $bmp = Frame $size
    if ($size -ge 256) { $ms = New-Object IO.MemoryStream; $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); $bytes = $ms.ToArray() } else { $bytes = Dib $bmp }
    $bmp.Dispose(); , $bytes
}
$out = New-Object IO.MemoryStream; $wr = New-Object IO.BinaryWriter $out
$wr.Write([uint16]0); $wr.Write([uint16]1); $wr.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($k = 0; $k -lt $sizes.Count; $k++) {
    $dim = if ($sizes[$k] -ge 256) { 0 } else { $sizes[$k] }
    $wr.Write([byte]$dim); $wr.Write([byte]$dim); $wr.Write([byte]0); $wr.Write([byte]0)
    $wr.Write([uint16]1); $wr.Write([uint16]32); $wr.Write([uint32]$images[$k].Length); $wr.Write([uint32]$offset)
    $offset += $images[$k].Length
}
foreach ($img in $images) { $wr.Write($img) }
$wr.Flush(); [IO.File]::WriteAllBytes($OutputPath, $out.ToArray())
Get-Item -LiteralPath $OutputPath | Select-Object FullName, Length
