Function Get-ResponseYesOrNo {
        Param(
            [Parameter(Mandatory=$True,Position=0)][string]$Title,
            [Parameter(Mandatory=$True,Position=1)][string]$Message
        )
    
        # $Title = "DNS Change"
        $Msg = "{0} ?" -f $Message
        $Yes = New-Object Management.Automation.Host.ChoiceDescription '&Yes'
        $No = New-Object Management.Automation.Host.ChoiceDescription '&No'
        $Options = [Management.Automation.Host.ChoiceDescription[]]($Yes, $No)
        $Default = 1 # No
        $Response = $Host.UI.PromptForChoice($Title, $Msg, $Options, $Default)
        If ($Response -eq 0) {
            # User typed Y
            return $True
        } Else {
            # User typed N
            return $False
        }
    }


