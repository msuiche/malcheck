dir . | Foreach-Object{
    $file = $_
    $hash = Get-FileHash $file -Algorithm MD5
    $fileinfo = Get-Item $file

    New-Object -TypeName PSObject -Property @{
        VersionInfo = $fileinfo.VersionInfo
        LastWriteTime = $fileinfo.LastWriteTime
        Length = $fileinfo.Length
        Algorithm = $hash.Algorithm
        MD5 = $hash.Hash
        Name = $fileinfo.Name
    }
} | Format-List
