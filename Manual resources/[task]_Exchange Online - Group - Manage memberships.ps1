# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Exchange parameters
$exchangeOnlineConnectionUri = "https://outlook.office365.com/powershell-liveid/"
$username = $ExchangeOnlineAdminUsername
$password = $ExchangeOnlineAdminPassword

# Form input
$groupId = $form.gridGroups.id
$Owners = $form.owners.right
$usersToAdd = $form.members.leftToRight
$usersToRemove = $form.members.rightToLeft

# Connecto to Exchange
try{
    Write-Verbose "Connecting to Exchange Online.."
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeOnlineConnectionUri -Credential $credential -Authentication Basic -AllowRedirection -ErrorAction Stop 
   
    if($exchangeSession){
        $exchangeOnlineSession = Import-PSSession $exchangeSession -AllowClobber -DisableNameChecking
        Write-Information "Successfully connected to Office365"
    }else{
        throw "username or password is not correct"
    }
}catch{
    throw "Could not connect to Exchange Online, error: $($_.Exception.Message)"
}

try{
    try {
        Write-Verbose "Searching for Exchange Online group ID=$groupId"
        
        $exchangeOnlineGroup = Get-Group -Identity $groupId -ErrorAction Stop
        Write-Information "Succesfully found Exchange Online group [$groupId]"
    } catch {
        Write-Error "Could not find Exchange Online group [$groupId]. Error: $($_.Exception.Message)"
    }

    # Add members
    if($usersToAdd -ne $null){
        try {
            foreach($user in $usersToAdd){
                $addMember = Add-DistributionGroupMember -Identity $exchangeOnlineGroup.Identity -Member $user.Id -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop
            }

            Write-Information "Succesfully added Exchange Online users [$($usersToAdd | ConvertTo-Json)] to Exchange Online group [$($exchangeOnlineGroup.displayName)]"
        } catch {
            if($_ -like "*already a member of the group*"){
                Write-Information "The recipient $($user.Name) is already a member of the group $($exchangeOnlineGroup.Identity)";
            }elseif($_ -like "*object '$($exchangeOnlineGroup.id)' couldn't be found*"){
                Write-Warning "Group $($exchangeOnlineGroup.Identity) couldn't be found. Possibly no longer exists. Skipping action";
            }elseif($_ -like "*Couldn't find object ""$($user.Id)""*"){
                Write-Warning "User $($user.Name) couldn't be found. Possibly no longer exists. Skipping action";
            }else{
                Write-Error "Could not add Exchange Online users [$($usersToAdd | ConvertTo-Json)] to Exchange Online group [$($exchangeOnlineGroup.displayName). Error: $($_.Exception.Message)"
            }
        }
    }

    # Remove members
    if($usersToRemove -ne $null){
        try {
            foreach($user in $usersToRemove){
                $removeMember = Remove-DistributionGroupMember -Identity $exchangeOnlineGroup.Identity -Member $user.Id -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop
            }

            Write-Information "Succesfully removed Exchange Online users [$($usersToRemove | ConvertTo-Json)] from Exchange Online group [$($exchangeOnlineGroup.displayName)]"
        } catch {
            if($_ -like "*isn't a member of the group*"){
                Write-Information "The recipient  $($user.Name) isn't a member of the group $($exchangeOnlineGroup.Identity))";
            }elseif($_ -like "*object '$($exchangeOnlineGroup.id)' couldn't be found*"){
                Write-Warning "Group $($exchangeOnlineGroup.Identity) couldn't be found. Possibly no longer exists. Skipping action";
            }elseif($_ -like "*Couldn't find object ""$($user.Id)""*"){
                Write-Warning "User $($user.Name) couldn't be found. Possibly no longer exists. Skipping action";
            }else{
                Write-Error "Could not remove Exchange Online users [$($usersToRemove | ConvertTo-Json)] from Exchange Online group [$($exchangeOnlineGroup.displayName)]. Error: $($_.Exception.Message)"
            }
        }
    }

    # Update owners
    if($OwnersToUpdate -ne $null){
        try {
            $groupParams = @{
                Identity            =   $exchangeOnlineGroup.Identity
                ManagedBy           =  $Owners.userPrincipalName
            }

            Write-Information "Succesfully updated owners [$($Owners | ConvertTo-Json)] for Exchange Online group [$exchangeOnlineGroup.Identity]"
        } catch {
            Write-Error "Could not update owners [$($Owners | ConvertTo-Json)] for Exchange Online group [$exchangeOnlineGroup.Identity]. Error: $($_.Exception.Message)"
        }
    }    
} finally {
    Write-Verbose "Closing Exchange Online connection"
    $exchangeSession | Remove-PSSession -ErrorAction Stop       
    Write-Information "Successfully closed Exchange Online connection"
}
