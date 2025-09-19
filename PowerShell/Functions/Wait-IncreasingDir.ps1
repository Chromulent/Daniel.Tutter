Function Wait-IncreasingDir {
    Param(
        [Parameter(Mandatory=$True,Position=0)][string]$Disk
    )
   
    $watchRoot = $Disk
    $watchRoot = $watchRoot -replace "\W"
    $altRoot   = $watchRoot + ":\*"
    $sizeCLI = "(Get-ChildItem " + $altRoot + " -File | Measure-Object -Sum Length).Sum"
    $dr = $watchRoot + ":"
    $dr1 = "'{0}'" -f $dr
    cmd /c MODE con:cols=71 lines=9
    do {
        # Get the current size of the directory that we
        $currSize = Invoke-Expression $sizeCLI
        Sleep 10
        $prevSize = Invoke-Expression $sizeCLI
        if($currSize -ne $prevSize){
        $diskRun = Get-WmiObject -Class win32_logicaldisk  -Filter "DeviceID=$dr1"
        $fDisk  = ($diskRun).Size
        $fspace = ($diskRun).FreeSpace
        $fUsed = $fDisk - $fspace
        $fUsed_GIB = [math]::Round($fUsed/1GB,2)
        $changSize = $prevSize - $currSize ; $changSize = [math]::ceiling($changSize / 1mb)
        Clear-Host 
            Write-Host("======================================================================")
            Write-Host("")
            Write-Host("Upgrade process is not yet complete. Size increased by $changSize MBs.")
            Write-Host("Total Disk Used: $fUsed_GIB GiB")
            Write-Host("Looping process...")
            Write-Host("")
            Write-Host("======================================================================")
            Sleep 7
            $Var = $False
            }

        if($currSize -eq $prevSize){ $Var = $True }

    } until ( $Var -eq $true)


}


# Wait-IncreasingDir -Disk ""

