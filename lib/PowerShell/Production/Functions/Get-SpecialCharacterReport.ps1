function Get-SpecialCharacterReport {
   [CmdletBinding(DefaultParameterSetName = 'Default')]
   param (
       [Parameter(Mandatory=$true,Position=0)][string]$InputString,
       [Parameter(ParameterSetName='Regex',Mandatory=$true)][string]$RegexPattern

   )

   switch ($PSCmdlet.ParameterSetName) {
       'Default' {
           $matches = [regex]::Matches($InputString, '[^\w\s]')
       }
       'Regex' {
           $matches = [regex]::Matches($InputString, $RegexPattern)
       }
   }

   if ($matches.Count -eq 0) {
       #Write-Output "No special characters in string $($InputString)"
       return
   }
   
   $report = $matches | Group-Object Value | Sort-Object Count -Descending

   $returnList   = New-Object System.Collections.ArrayList

   $FnObject = New-Object PSObject
   foreach ($entry in $report) {
       
       $SymbolIdentification = $null
       switch ($entry.Name) {
           "$"     {$SymbolIdentification = "Dollar Sign"          ; break}
           "&"     {$SymbolIdentification = "Ampersand"            ; break}
           "+"     {$SymbolIdentification = "Plus Sign"            ; break}
           ","     {$SymbolIdentification = "Comma"                ; break}
           ":"     {$SymbolIdentification = "Colon"                ; break}
           ";"     {$SymbolIdentification = "Semicolon"            ; break}
           "="     {$SymbolIdentification = "Equals Sign"          ; break}
           "?"     {$SymbolIdentification = "Question Mark"        ; break}
           "@"     {$SymbolIdentification = "At Sign"              ; break}
           "#"     {$SymbolIdentification = "Number Sign"          ; break}
           "|"     {$SymbolIdentification = "Vertical Bar"         ; break}
           " "     {$SymbolIdentification = "Whitespace"           ; break}
           "'"     {$SymbolIdentification = "Apostrophe"           ; break}
           "<"     {$SymbolIdentification = "Less-Than Sign"       ; break}
           ">"     {$SymbolIdentification = "Greater-Than Sign"    ; break}
           "."     {$SymbolIdentification = "Period"               ; break}
           "^"     {$SymbolIdentification = "Carrot"               ; break}
           "*"     {$SymbolIdentification = "Asterisk"             ; break}
           "("     {$SymbolIdentification = "Left Parenthesis"     ; break}
           ")"     {$SymbolIdentification = "Right Parenthesis"    ; break}
           "%"     {$SymbolIdentification = "Percent Sign"         ; break}
           "!"     {$SymbolIdentification = "Exclamation Mark"     ; break}
           "_"     {$SymbolIdentification = "Underscore"           ; break}
           "-"     {$SymbolIdentification = "Hyphen"               ; break}
           '"'     {$SymbolIdentification = "Quote"                ; break}
           default {$SymbolIdentification = $null ; break}
        }
       
       if(([string]::IsNullOrEmpty($SymbolIdentification))){ } Else {
           # Has data   
           $FnObject | Add-Member noteproperty "$($SymbolIdentification) Count"       -Value $($entry.Count)
           $returnList.Add($FnObject) > $null                 
        }    
   }

   return  $(($($returnList | Sort | Get-Unique) -Join ':').Replace('@','').Replace('{','').Replace('}',''))
}
