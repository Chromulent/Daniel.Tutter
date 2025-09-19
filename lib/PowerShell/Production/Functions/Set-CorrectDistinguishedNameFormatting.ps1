Function Set-CorrectDistinguishedNameFormatting {
    param    ($DN = $Args[0])
    $DN1 = @()
    $DN.split(',') | ForEach-Object{
        $e = $_
    
        If($($e.split('=')[1]) -ceq "all users"){
            $ea = "$($e.split('=')[1].ToUpper())"
        } else {
            $ea = "$($e.split('=')[1])"
        }
    
        $e1 = "{0}={1}" -f $($e.split('=')[0].ToUpper()),$($ea)
        $DN1+=$e1
    }
    $DN2 = $DN1 -join ','
    return $DN2
}
