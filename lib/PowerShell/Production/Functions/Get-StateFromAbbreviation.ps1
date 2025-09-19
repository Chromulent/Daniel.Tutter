Function Get-StateFromAbbreviation{

    param ([Parameter(Mandatory=$True,Position=0)]$Abbreviation)
 
        if(!(([string]::IsNullOrEmpty($long)))){ $long = $Null }
 
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'AL'){ $long = "Alabama"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'AK'){ $long = "Alaska"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'AZ'){ $long = "Arizona"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'AR'){ $long = "Arkansas"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'CA'){ $long = "California"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'CO'){ $long = "Colorado"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'CT'){ $long = "Connecticut"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'DE'){ $long = "Deleware"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'FL'){ $long = "Florida"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'GA'){ $long = "Georgia"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'HI'){ $long = "Hawaii"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'ID'){ $long = "Idaho"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'IL'){ $long = "Illinois"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'IN'){ $long = "Indiana"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'IA'){ $long = "Iowa"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'KS'){ $long = "Kansas"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'KY'){ $long = "Kentucky"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'LA'){ $long = "Louisiana"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'ME'){ $long = "Maine"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'MD'){ $long = "Maryland"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'MA'){ $long = "Massachusetts"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'MI'){ $long = "Michigan"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'MN'){ $long = "Minnesota"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'MS'){ $long = "Mississippi"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'MO'){ $long = "Missouri"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'MT'){ $long = "Montana"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'NC'){ $long = "North Carolina"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'ND'){ $long = "North Dakota"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'NE'){ $long = "Nebraska"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'NV'){ $long = "Nevada"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'NH'){ $long = "New Hampshire"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'NJ'){ $long = "New Jersey"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'NM'){ $long = "New Mexico"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'NY'){ $long = "New York"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'OH'){ $long = "Ohio"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'OK'){ $long = "Oklahoma"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'OR'){ $long = "Oregon"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'PA'){ $long = "Pennsylvania"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'PR'){ $long = "Puerto Rico"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'RI'){ $long = "Rhode Island"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'SC'){ $long = "South Carolina"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'SD'){ $long = "South Dakota"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'TN'){ $long = "Tennessee"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'TX'){ $long = "Texas"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'TX'){ $long = "Texas"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'UT'){ $long = "Utah"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'VT'){ $long = "Vermont"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'VA'){ $long = "Virgina"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'DC'){ $long = "Washington DC"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'WA'){ $long = "Washington"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'WV'){ $long = "West Virginia"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'WI'){ $long = "Wisconsin"}}
        if((([string]::IsNullOrEmpty($long)))){ If($Abbreviation -eq  'WY'){ $long = "Wyoming"}}
         if(([string]::IsNullOrEmpty($long))){ 
            # Does not have data
                 $long = "Null"
         } 
 
         $CsObject = New-Object PSObject
         $CsObject | Add-Member noteproperty "State"       -Value $long
 
         return $CsObject
 }
 