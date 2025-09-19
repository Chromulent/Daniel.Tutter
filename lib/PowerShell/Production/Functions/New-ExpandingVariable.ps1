Function New-ExpandingVariable {
    param (
        [Parameter(Mandatory=$true,Position=0)]$ArraySet,
        [Parameter(Mandatory=$True,Position=1)][ValidateSet("[","'","("," ",'"',"|")][char]$Affix,
        [Parameter(Mandatory=$False,Position=2)][ValidateSet(",",";","|")][char]$Separator
    )

    switch ($Affix) {
        "["     {$Prefix = "[" ; $Suffix = "]"; break}
        "'"     {$Prefix = "'" ; $Suffix = "'"; break}
        "|"     {$Prefix = "|" ; $Suffix = "|"; break}
        '"'     {$Prefix = '"' ; $Suffix = '"'; break}
        "("     {$Prefix = "(" ; $Suffix = ")"; break}
        " "     {$Prefix = " " ; $Suffix = ""; break}
        default {$Prefix = "$Null" ; $Suffix = "$Null"; break}
     }

    if(([string]::IsNullOrEmpty($Separator))){ 
        # Does not have data
        $FinAdd = ""
        $ArraySet | ForEach-Object{ $FinAdd = "$FinAdd" + $('{' + "$($ArraySet.IndexOf($_))" + '}') }
        $Defined = "$($Prefix)$($FinAdd)$($Suffix)" -f $ArraySet
                 
     } Else {
        # Has data   
        $FinAdd = ""
        $ArraySet | ForEach-Object{ $FinAdd = "$FinAdd" + $('{' + "$($ArraySet.IndexOf($_))" + '}') + "$($Separator)" }
        $Defined = "$($Prefix)$($FinAdd)$($Suffix)" -f $ArraySet
     }

    return $Defined
}

