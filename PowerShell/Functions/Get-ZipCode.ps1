Function Get-ZipCode{

    param ([Parameter(Mandatory=$True,Position=0)]$Zip)
 
        if(!(([string]::IsNullOrEmpty($code)))){ $code = $Null }
        if(!(([string]::IsNullOrEmpty($long)))){ $long = $Null }
 
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(35000..36999 ))) { $code = 'AL'; $long = "Alabama"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(99500..99999 ))) { $code = 'AK'; $long = "Alaska"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(85000..86999 ))) { $code = 'AZ'; $long = "Arizona"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(71600..72999 ))) { $code = 'AR'; $long = "Arkansas"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(90000..96699 ))) { $code = 'CA'; $long = "California"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(80000..81999 ))) { $code = 'CO'; $long = "Colorado"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(6000..6999 )))   { $code = 'CT'; $long = "Connecticut"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(19700..19999 ))) { $code = 'DE'; $long = "Deleware"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(32000..34999 ))) { $code = 'FL'; $long = "Florida"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(30000..31999 ))) { $code = 'GA'; $long = "Georgia"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(96700..96999 ))) { $code = 'HI'; $long = "Hawaii"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(83200..83999 ))) { $code = 'ID'; $long = "Idaho"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(60000..62999 ))) { $code = 'IL'; $long = "Illinois"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(46000..47999 ))) { $code = 'IN'; $long = "Indiana"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(50000..52999 ))) { $code = 'IA'; $long = "Iowa"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(66000..67999 ))) { $code = 'KS'; $long = "Kansas"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(40000..42999 ))) { $code = 'KY'; $long = "Kentucky"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(70000..71599 ))) { $code = 'LA'; $long = "Louisiana"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(3900..4999 )))   { $code = 'ME'; $long = "Maine"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(20600..21999 ))) { $code = 'MD'; $long = "Maryland"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(1000..2799 )))   { $code = 'MA'; $long = "Massachusetts"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(48000..49999 ))) { $code = 'MI'; $long = "Michigan"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(55000..56999 ))) { $code = 'MN'; $long = "Minnesota"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(38600..39999 ))) { $code = 'MS'; $long = "Mississippi"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(63000..65999 ))) { $code = 'MO'; $long = "Missouri"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(59000..59999 ))) { $code = 'MT'; $long = "Montana"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(27000..28999 ))) { $code = 'NC'; $long = "North Carolina"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(58000..58999 ))) { $code = 'ND'; $long = "North Dakota"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(68000..69999 ))) { $code = 'NE'; $long = "Nebraska"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(88900..89999 ))) { $code = 'NV'; $long = "Nevada"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(3000..3899 )))   { $code = 'NH'; $long = "New Hampshire"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(7000..8999 )))   { $code = 'NJ'; $long = "New Jersey"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(87000..88499 ))) { $code = 'NM'; $long = "New Mexico"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(10000..14999 ))) { $code = 'NY'; $long = "New York"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(43000..45999 ))) { $code = 'OH'; $long = "Ohio"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(73000..74999 ))) { $code = 'OK'; $long = "Oklahoma"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(97000..97999 ))) { $code = 'OR'; $long = "Oregon"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(15000..19699 ))) { $code = 'PA'; $long = "Pennsylvania"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(300..999 )))     { $code = 'PR'; $long = "Puerto Rico"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(2800..2999 )))   { $code = 'RI'; $long = "Rhode Island"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(29000..29999 ))) { $code = 'SC'; $long = "South Carolina"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(57000..57999 ))) { $code = 'SD'; $long = "South Dakota"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(37000..38599 ))) { $code = 'TN'; $long = "Tennessee"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(75000..79999 ))) { $code = 'TX'; $long = "Texas"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(88500..88599 ))) { $code = 'TX'; $long = "Texas"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(84000..84999 ))) { $code = 'UT'; $long = "Utah"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(5000..5999 )))   { $code = 'VT'; $long = "Vermont"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(22000..24699 ))) { $code = 'VA'; $long = "Virgina"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(20000..20599 ))) { $code = 'DC'; $long = "Washington DC"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(98000..99499 ))) { $code = 'WA'; $long = "Washington"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(24700..26999 ))) { $code = 'WV'; $long = "West Virginia"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(53000..54999 ))) { $code = 'WI'; $long = "Wisconsin"}}
        if(([string]::IsNullOrEmpty($code)) -and (([string]::IsNullOrEmpty($long)))){ if($zip -in $(@(82000..83199 ))) { $code = 'WY'; $long = "Wyoming"}}
         if(([string]::IsNullOrEmpty($code))){ 
            # Does not have data
                 $code = 'Null'
         } 
 
         if(([string]::IsNullOrEmpty($long))){ 
            # Does not have data
                 $long = "Null"
         } 
 
         $CsObject = New-Object PSObject
         $CsObject | Add-Member noteproperty "Abbreviation"       -Value $code
         $CsObject | Add-Member noteproperty "State"       -Value $long
 
         return $CsObject
 }
  