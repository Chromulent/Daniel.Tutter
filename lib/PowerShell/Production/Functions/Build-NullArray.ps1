Function Build-NullArray {
    Clear-Host
    $FinalHeader = "Null Array Creation"
    $FinalOutHeader = "#" + "=" * $((59 - $FinalHeader.Length) / 2) + "[" + " $FinalHeader " + "]" + "=" * $((60 - $FinalHeader.Length) / 2) + "#"
    Write-Host -Object ("$("#"*65)`r`n$FinalOutHeader`r`n$("#"*65)`r`n")                
    $SelectionHeader   = "`tAdd all variables to this array to create a null array.`r`n`tDont worry about removing the $ within the variable.`r`n`tIf enter is pressed with no variable or 0 is pressed, this will halt this collection`r`n"
    Write-Host -Object("$SelectionHeader")
    $NullImport   = New-Object System.Collections.ArrayList
    Do{
        If($NullImport.Count -eq 0){ $OptionsPrompt = Read-Host -Prompt ("First Variable ") } Else { $OptionsPrompt = Read-Host -Prompt ("Next Variable(s)") }
        if((([string]::IsNullOrEmpty($OptionsPrompt))) -Or ($OptionsPrompt -eq 0)){ 
            # empty
            Write-Host -Object ("Either blank line or 0 has been pressed. Halting adding further additions...")
            $Squaddle = $True
        } else {
            # Not empty
            if(([string]::IsNullOrEmpty($OptionsPrompt)) -Or ($OptionsPrompt -eq 0)){ 
                # value is null
                $Squaddle = $True
                } else {
                # data is not null
                $Squaddle = $False
                # Check to see if the variables we are adding contains $ to ensure that we are adding the proper thing to the nullArray.
                If($OptionsPrompt.Contains('$')){ } Else { $OptionsPrompt = $OptionsPrompt.Insert(0, '$') }
                If($OptionsPrompt.Contains('$$')){ $OptionsPrompt = $OptionsPrompt.Replace('$$','$') } Else {  }
                $NullImport.Add($OptionsPrompt) > $null 
            }
        
        }
    
    } Until ($Squaddle -eq $True)
    
        $OutNull = '$nullArray = @(' 
        $NullImport | %{
            $V = $null ; $V1 = $null
            $V = $_
            If ($($NullImport.IndexOf("$V")) -lt $($NullImport.Count -1)){
                $V1 = "{0}{1}{2}" -f "'", $V, "', "
            } Else {
                $V1 = "{0}{1}{2}" -f "'", $V, "'"
            }
            $OutNull = $OutNull + $V1
           
        }    
    
        $OutNull = $OutNull + ')'
        $OutNull = $OutNull + "`r`n" + '$nullArray | %{ $NewVar = $($_ -replace ' + "'[$]','')" + ' ; Set-Variable -Name $NewVar -Value $Null }'
        $OutNull  

}

# Build-NullArray
