# Convert SecureString to String
# https://gist.github.com/45413/a7dee1c67b914ba941f29502a824a002

function Convert-SecureString {
    [CmdletBinding()]
    param (
        # SecureString
        [Parameter(Mandatory=$true)]
        [SecureString]
        $SecureString
    )
    
    Return ( [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)) )
}