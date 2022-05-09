# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Exchange parameters
$username = $ExchangeOnlineAdminUsername
$password = $ExchangeOnlineAdminPassword

# Form input
$groupId = $form.gridGroups.id
$Owners = $form.owners.right
$usersToAdd = $form.members.leftToRight
$usersToRemove = $form.members.rightToLeft

# Connect to Exchange Online
try{
    Write-Verbose "Connecting to Exchange Online"

    # Import module
    $moduleName = "ExchangeOnlineManagement"
    $commands = @("Get-Group","Add-DistributionGroupMember","Remove-DistributionGroupMember")

    # If module is imported say that and do nothing
    if (Get-Module | Where-Object { $_.Name -eq $ModuleName }) {
        Write-Verbose "Module $ModuleName is already imported."
    }
    else {
        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object { $_.Name -eq $ModuleName }) {
            $module = Import-Module $ModuleName -Cmdlet $commands
            Write-Verbose "Imported module $ModuleName"
        }
        else {
            # If the module is not imported, not available and not in the online gallery then abort
            throw "Module $ModuleName not imported, not available. Please install the module using: Install-Module -Name $ModuleName -Force"
        }
    }

        
    # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = [System.Management.Automation.PSCredential]::new($username, $securePassword)
    $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -PSSessionOption $remotePSSessionOption -ErrorAction Stop

}catch{
    $InvocationInfoPositionMessage = $_.InvocationInfo.PositionMessage
    Write-Error "$InvocationInfoPositionMessage"
    throw "Could not connect to Exchange Online, error: $_"
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
                Identity            =  $exchangeOnlineGroup.Identity
                ManagedBy           =  $Owners.userPrincipalName
            }

            Write-Information "Succesfully updated owners [$($Owners | ConvertTo-Json)] for Exchange Online group [$exchangeOnlineGroup.Identity]"
        } catch {
            Write-Error "Could not update owners [$($Owners | ConvertTo-Json)] for Exchange Online group [$exchangeOnlineGroup.Identity]. Error: $($_.Exception.Message)"
        }
    }    
} finally {
    Write-Verbose "Disconnecting from Exchange Online"
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    Write-Information "Successfully disconnected from Exchange Online"
}
