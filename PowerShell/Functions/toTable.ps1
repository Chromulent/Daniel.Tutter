Function toTable {
				param(
					[Parameter(ValueFromPipeline=$true)]
					$inputObject
				)

				begin {
					$collection 	= [System.Collections.Generic.List[object]]::new()
					$propertiesList	= [System.Collections.Generic.HashSet[string]]::new()
				}
				process {
					ForEach ( $property in ($inputObject | gm -MemberType properties).Name ) {
						[void]$propertiesList.Add($property)
					}
					[void]$collection.Add($inputObject)
				}
				end {
					$headersObject = [PSCustomObject]@{}
					Foreach ( $propertyName in $propertiesList ) {
						$headersObject | Add-Member -MemberType NoteProperty -Name $propertyName -Value $propertyName
					}
					[void]$collection.Insert(0,$headersObject)
					return $collection
				}
}
