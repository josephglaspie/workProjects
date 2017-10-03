
#Script created to run as task and find Domain Admin's whose account is about to expire or already expired. Run from DC trusted by multiple forests.
#ensure this script is only run from the Primary domain controller in QATHDRETAIL.NET
$localDc = $env:COMPUTERNAME + "." + $env:USERDNSDOMAIN
$PrimDC=(get-ADDomain $env:USERDNSDOMAIN).PDCEmulator
if($localDc -eq $PrimDC){

$Domains = 'qathdretail.net','amer.qacompany.com','qacompany.com'
#ensure the PDCE of each domain is being queried
$PDCEs = foreach($domain in $domains){(get-ADDomain $domain).PDCEmulator}
$myErrors=@()


foreach($PDCE in $PDCEs){
try{$DAs=Get-ADGroupMember 'domain admins' -Server $PDCE | 
        ForEach-Object { Get-ADUser  –Properties "UserPrincipalName",“DisplayName”, “msDS-UserPasswordExpiryTimeComputed”, "enabled","CN" -Identity $_ |
        Where-Object {($_.enabled -eq $true) -and ($_.UserPrincipalName -like "xsa-*") -and ($_.cn -notmatch "_svc")}} |
        Select-Object -Property "UserPrincipalName","CN","name",“Displayname”,"GivenName","Surname",@{Name=“ExpirationDate”;Expression={[datetime]::FromFileTime($_.“msDS-UserPasswordExpiryTimeComputed”)}}

#region Expiration Switch
    foreach($DA in $DAs){ 
        
        $needsEmail=$null
        $nullSubject="Your XSA Account PW in QA Domain is Null"
        $pastDueSubject="Your XSA Account PW in QA Domain is expired"
        $expiringSoonSubject="Your XSA Account PW in QA Domain is expiring soon"
        $nullMessage="$($DA.givenname),`n`nYour $($DA.UserPrincipalName) password expiration date is NULL. This is a securit violation, please resolve.`n`nThank you,`n`nActive Directory Team`n`nScript run from $env:COMPUTERNAME"
        $pastDueMessage="$($DA.givenname),`n`nYour $($DA.UserPrincipalName) account password expired on $($da.ExpirationDate) please reset your password or have the account removed.`n`nThank you,`n`nActive Directory Team`n`nScript run from $env:COMPUTERNAME"
        $expiringSoonMessage="$($DA.givenname),`n`nYour $($DA.UserPrincipalName) account password expires on $($DA.ExpirationDate) please reset your password.`n`nThank you,`n`nActive Directory Team`n`nScript run from $env:COMPUTERNAME"
        $emailAddress = $DA.givenname + '_' + $DA.surname + '@company.com'
        $emailAddress1 = $DA.givenname + '_' + $DA.surname + '1@company.com'
        
        switch ($DA)
            {
                #if account PW set to never expire, email them and let them know this is a security violation
                {($DA.ExpirationDate -eq $null)} {
                    Write-Host $nullMessage -ForegroundColor Yellow
                    $subject=$nullSubject
                    $message=$nullMessage
                    $needsEmail=$true
                    break}
                #if account is past due state so and give instrustions
                {($DA.ExpirationDate -le (GET-DATE).AddDays(0))} {
                    write-host $pastDueMessage -ForegroundColor Yellow
                    $subject=$pastDueSubject
                    $message=$pastDueMessage
                    $needsEmail=$true
                    break}
                #if account expiration date is less than or equal to 7 days do send an email warning with the date it will expire and instructions
                {($DA.ExpirationDate -le (GET-DATE).AddDays(7))} {
                    write-host $expiringSoonMessage -ForegroundColor yellow
                    $subject=$expiringSoonSubject
                    $message=$expiringSoonMessage
                    $needsEmail=$true
                    break}
                #if account expiration date is greater than or equal to 7 days do nothing
                {($DA.ExpirationDate -ge (GET-DATE).AddDays(7))} {
                    write-host "$($DA.name) your $($DA.UserPrincipalName) account is OK" -ForegroundColor Green
                    $needsEmail=$false
                    break} 
             }
       if($needsEmail){
        Send-MailMessage -To $emailAddress,$emailAddress1 -bcc 'user1@company.com' -subject $subject -Body $message -From QaPassExpChecker@company.com -SmtpServer smtpServer.company.com
        "Sending mail to  $emailAddress,$emailAddress1"
       }
       
    }

#endregion

}catch{ $myErrors += $Error[0].Exception.Message } 

}#End foreach Domains

if($myErrors.count -gt 0){
    $myErrors = $myErrors | Out-String
    Send-MailMessage -To user1@company.com -From GetDaPasswordExpirationScript@THD.com -SmtpServer smtpServer.company.com -Subject "Errors encountered" -Body $myErrors
}
}else{"This machine $env:COMPUTERNAME is not the PDCemulator"}