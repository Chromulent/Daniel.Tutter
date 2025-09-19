function Expand-ZIPFile {
	param (
		[string]$file,
		[string]$destination
	)

	if (!$destination) {
		$destination = [string](Resolve-Path $file)
		$destination = $destination.Substring(0, $destination.LastIndexOf('.'))
		mkdir $destination | Out-Null
	}
	$shell = New-Object -ComObject Shell.Application
	#$shell.NameSpace($destination).CopyHere($shell.NameSpace($file).Items(), 16);
	$zip = $shell.NameSpace($file)
	foreach ($item in $zip.items()) {
		$shell.Namespace($destination).CopyHere($item)
	}
}
