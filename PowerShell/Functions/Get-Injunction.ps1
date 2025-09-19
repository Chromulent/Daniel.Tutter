Function Get-Injunction {
    param (
        [Parameter(Mandatory=$True,Position=0)]$ValuesFound
        )    
    If((Get-Variable).Name | Where-Object{$_.Contains('Column_')} ){ (Get-Variable).Name | Where-Object{$_.Contains('Column_')} | ForEach-Object{ Remove-Variable -Name $_ }  } 
    If((Get-Variable).Name | Where-Object{$_.Contains('RowLine_')} ){ (Get-Variable).Name | Where-Object{$_.Contains('RowLine_')} | ForEach-Object{ Remove-Variable -Name $_ }  } 
    $Table   = New-Object System.Data.DataTable
    $Column1 = [System.Data.DataColumn]::new('Date', [string])
    $Column1.DefaultValue = '---'
    $Table.Columns.Add($Column1)
    $i = 0
    $FoundValues = $ValuesFound 

    $FoundValues | %{
    
        $in = $i+1
    
        $ThisRevision  = $_
        #$ThisRevision  = $FoundValues[0]
        
        $Row_pos = 0
        $t = 2;
        $ondx = $null
        $Row = $null
        New-Variable -Name "RowLine_$($Row_pos)" -Value @()
        $ObjectList | %{
            $ondx = $ObjectList.IndexOf("$_")
            If($FoundValues[$in].$($ObjectList[$ondx]) -eq $FoundValues[$i].$($ObjectList[$ondx])){  } Else { 
            
                If($($ObjectList[$ondx]) -eq 'HCM_StringDate'){ 
                } Else {
                    
                    if (-Not($Table.Columns.Contains("$($ObjectList[$ondx])"))) {
                        New-Variable -Name "Column_$($t)"
                        $(Get-Variable -Name "RowLine_$($Row_pos)").Value+="Column_$($t)"
                        $(Get-Variable -Name "Column_$($t)").Value+="$($ObjectList[$ondx])"
                        $Column1 = [System.Data.DataColumn]::new("$($ObjectList[$ondx])", [string])
                        $Column1.DefaultValue = '---'
                        $Table.Columns.Add($Column1)                    
        
                    } Else {
                        New-Variable -Name "Column_$($t)" 
                        $(Get-Variable -Name "RowLine_$($Row_pos)").Value+="Column_$($t)"
                        $(Get-Variable -Name "Column_$($t)").Value+="$($ObjectList[$ondx])"
                    }
                    $t++     
                }
                
                Write-Host -Object("$($ObjectList[$ondx]) was updated from `r`n`t$($FoundValues[$in].$($ObjectList[$ondx])) to $($FoundValues[$i].$($ObjectList[$ondx]))")    
                     
            }      
            
        }
    
        $Row = $Table.NewRow()
        $Row.Date = $ThisRevision.HCM_StringDate
        $(Get-Variable -Name "RowLine_$($Row_pos)").Value | ForEach-Object{
            if(-Not(([string]::IsNullOrEmpty($_)))){ 
                # Has data      
                $ColumnName = [string](Get-Variable -Name "$($_)").Value
                If($FoundValues[$in].$ColumnName -eq $FoundValues[$i].$ColumnName){  } Else { 
                    $Row.$ColumnName = $ThisRevision.$ColumnName  
                }          
             } 
        }
        $Table.Rows.Add($Row)     
    
        If((Get-Variable).Name | Where-Object{$_.Contains('Column_')} ){ (Get-Variable).Name | Where-Object{$_.Contains('Column_')} | ForEach-Object{ Remove-Variable -Name $_ }  } 
        If((Get-Variable).Name | Where-Object{$_.Contains('RowLine_')} ){ (Get-Variable).Name | Where-Object{$_.Contains('RowLine_')} | ForEach-Object{ Remove-Variable -Name $_ }  } 
    
        $Row_pos++
        $i++
    }
    
    $FormatEnumerationLimit = -1
    $previous_columnLength = [console]::BufferWidth
    [console]::BufferWidth = $Temp_columnLength
    $Temp_columnLength = 0 ; $TableFormat | %{ $Temp_columnLength = $Temp_columnLength + [int]$_.Split(';')[1].replace('}','').Trim().Split('=')[1] }
    
    [console]::BufferWidth = $($Temp_columnLength*2)
    return $Table 
        
}

