Function Build-QuestioningHeader {
    param (
    [Parameter(Mandatory=$True,Position=0)][string]$Header
    )
    
    $qHeaderList       = New-Object System.Collections.ArrayList
    $qHeaderCommand    = New-Object System.Collections.ArrayList
    $qCommand          = New-Object System.Collections.ArrayList
    $FaultManagement   = $null

    $QuestionForHeader = Read-Host -Prompt ("What is the question you will ask for our switch?")
    Write-Host -Object("If you have a number of titles you would like to enter ")
    Write-Host -Object("Note: If this is empty then we will continue until you are finished. ")
    $NumberofHeaders = Read-Host -Prompt ("Then please do so here ")
    $qCommand.Add('switch ($bludOrnge.ToUpper()) {') > $null

    $i = 0;
    Do {
        $Trial = $Null
        If($hObj_Short){ $hObj_Short = $Null }
        If($hObj_Long){ $hObj_Long = $Null }
        If($hObject){ $hObject = $Null }
        If($hObj_Comd){ $hObj_Comd = $Null }

        If($i -eq 0){
            Write-Host -Object("Example: `t'List of Commands:'")
            $hObj_Short = Read-Host -Prompt ("Top Header Explaining our header  ")
            $hObject    = "`r`n" + $hObj_Short
        }

        If($i -gt 0){
            $hObj_Short = Read-Host -Prompt ("What is the shorthand `t`t`t`t")
            $hObj_Long  = Read-Host -Prompt ("What is the Text in the Header `t`t`t")
            $hObj_Comd  = Read-Host -Prompt ("What is the command / Script / Scriptblock `t")
    
            $qObj = '"' + $hObj_Short + '"   { ' + $hObj_Comd + '; break}'
            $hObject    = '`r`n`t[' + $hObj_Short + '] - ' + $hObj_Long

            $qCommand.Add("$qObj") > $null

            if(([string]::IsNullOrEmpty($NumberofHeaders))){             
                # Switch for forcing a choice until shell is broken
                switch ($($Host.UI.PromptForChoice("This will repeat until you choose.", "Add Another Option?", @('&Yes', '&No'), 1))) {
                    "0" {$Trial = $True ; break}
                    "1" {$Trial = $False; break}
                default {Clear-Host; echo "Incorrect choice attempt again."; $Trial = $Null; break}
                }  
            }
           
        }

        $qHeaderList.Add($hObject) > $null
        $i++
    } Until (($Trial -eq $False) -or ($i -eq $NumberofHeaders))

    $qHeaderList.Add('`r`n`t[0] - Exit`r`n') > $null
    $HeaderList = $qHeaderList -Join ''
    $oHeader = 'Write-Host -Object ("' + $HeaderList + '")'
    $cSet = '$bludOrnge = Read-Host -Prompt ("' + $QuestionForHeader + '")'

    $qHeaderCommand.Add('Clear-Host') > $null
    $qHeaderCommand.Add($oHeader) > $null
    $qHeaderCommand.Add("") > $null
    $qHeaderCommand.Add('# == [ Switch Containing Functions and Scriptblocks') > $null
    $qHeaderCommand.Add("$cSet") > $null
    $qHeaderCommand.Add("") > $null
    $qCommand.Add('"0" {break}') > $null
    $qCommand.Add('default {"Something else happened"; break}
        }') > $null
    $qCommand | %{ $qHeaderCommand+=$_ }
    return $qHeaderCommand
}

<#
$ClipPart = Build-QuestioningHeader -Header "Test Header"

$ClipPart | Clip
#>
