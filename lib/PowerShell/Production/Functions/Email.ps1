Function Email {
	Param (
		$To,
		$CC,
		$Subject,
		$Body,
		$Attachments
	)

	$MSG = new-object Net.Mail.MailMessage
	$SMTP = new-object Net.Mail.SmtpClient($SMTPServer)

	$MSG.From = $From
	if($RunInTestMode -eq $true){
		$To = $AdminEmail
		$CC = $null
	}


	ForEach ($Email In $To){
		$MSG.To.Add($Email)
	}
	ForEach ($Email In $CC){
		$MSG.Cc.Add($Email)
	}
	
	$MSG.Subject = $Subject
	$MSG.Body = $Body
	$MSG.IsBodyHTML = $True
	$MSG.Priority = "normal"
	foreach($Attachment in $Attachments){
		$MSG.Attachments.Add($Attachment)
	}

	$SMTP.Send($MSG)
}
