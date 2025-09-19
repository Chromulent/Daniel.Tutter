Function Write-PieceMeal_OfArray {
    param (
    [Parameter(Mandatory=$True,Position=0)][System.Collections.Generic.List[String]]$SubjectArray,
    [Parameter(Mandatory=$True,Position=1)][System.Int32]$Piece, 
    [Parameter(Mandatory=$True,Position=2)][System.Int32]$Whole,
    [Parameter(Mandatory=$False,Position=3)][System.Int32]$Part 
    )

    $ArrayContent = (Get-Variable | Where-Object{$_.Name -eq ("$((Get-Variable | Where-Object{$_.Name.Contains("SubjectArray") }).Name)") }).Value

    $subPiece = $([math]::Round(($piece/$Whole),1)) ; $subWhole = $null ; $LastSubWhole = $null

    If($Part){

        If($Part -eq $Piece){
            $ArrayContent[0..$([math]::Round(($ArrayContent.Count*$($subPiece * $($Part))),0))]
        } Else {
            $ArrayContent[$([math]::Round(($ArrayContent.Count*$($subPiece * $($Part-1))),0))..$([math]::Round(($ArrayContent.Count*$($subPiece * $($Part))),0))]
        }
    } Else {
        Write-Host -Object("You are looking at breaking up your Array into $([int]($Whole/$Piece )) pieces. `r`nEach segment being around $($([math]::Round(($SubjectArray.Count/$Whole),0))) items in length")

        Do{ 
            if(!(([string]::IsNullOrEmpty($LastSubWhole)))){ 
                # Has data  
                $LastSubWhole = $subWhole     
             } Else {
                $LastSubWhole = 0
             }
        
            If($subWhole){ $subWhole = $subWhole+$subPiece } Else { $subWhole = $subPiece }
        
            $ArrayContent[$([math]::Round(($ArrayContent.Count*$LastSubWhole),0))..$([math]::Round(($ArrayContent.Count*$subWhole),0))]
        
            Start-Sleep -Milliseconds 250
        
            Write-Host -NoNewLine "Press any key to continue... Piece mealing $($LastSubWhole) of $($subWhole)..."
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')    
        
        }Until([decimal]$subWhole -eq [decimal]$piece)    

    }
}