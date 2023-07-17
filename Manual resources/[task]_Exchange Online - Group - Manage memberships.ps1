# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Exchange Online in an unattended scripting scenario using a certificate.
# Follow the Microsoft Docs on how to set up the Azure App Registration: https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps
$AzureADExchangeOrganization = $AADExchangeOrganization
$AzureADExchangeAppID = $AADExchangeAppID
$AzureADExchangeCertificateThumbprint = $AADExchangeCertificateThumbprint # Certificate has to be locally installed

# PowerShell commands to import
$commands = @(
    "Get-User" # Always required
    , "Get-Group"
    , "Add-DistributionGroupMember"
    , "Remove-DistributionGroupMember"
    , "Set-DistributionGroup"
)

# Form input
$groupId = $form.gridGroups.id
$Owners = $form.owners.right
$usersToAdd = $form.members.leftToRight
$usersToRemove = $form.members.rightToLeft

#region functions
function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}
#endregion functions

# Import module
$moduleName = "ExchangeOnlineManagement"

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

# Connect to Exchange
try {
    Write-Verbose "Connecting to Exchange Online"

    # Connect to Exchange Online in an unattended scripting scenario using a certificate thumbprint (certificate has to be locally installed).
    $exchangeSessionParams = @{
        Organization          = $AzureADExchangeOrganization
        AppID                 = $AzureADExchangeAppID
        CertificateThumbPrint = $AzureADExchangeCertificateThumbprint
        CommandName           = $commands
        ShowBanner            = $false
        ShowProgress          = $false
        TrackPerformance      = $false
        ErrorAction           = 'Stop'
    }

    $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams
    
    Write-Information "Successfully connected to Exchange Online"
}
catch {
    $ex = $PSItem
    if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObject = Resolve-HTTPError -Error $ex

        $verboseErrorMessage = $errorObject.ErrorMessage

        $auditErrorMessage = $errorObject.ErrorMessage
    }

    # If error message empty, fall back on $ex.Exception.Message
    if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
        $verboseErrorMessage = $ex.Exception.Message
    }
    if ([String]::IsNullOrEmpty($auditErrorMessage)) {
        $auditErrorMessage = $ex.Exception.Message
    }

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
    $Log = @{
        Action            = "Undefined" # optional. ENUM (undefined = default) 
        System            = "Exchange Online" # optional (free format text) 
        Message           = "Failed to connect to Exchange Online" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = "Exchange Online" # optional (free format text) 
        
    }
    #send result back  
    Write-Information -Tags "Audit" -MessageData $log
    throw "Error connecting to Exchange Online. Error Message: $auditErrorMessage"
}

try {
    try {
        Write-Verbose "Querying Exchange Online group with ID '$groupId'"
        $exchangeOnlineGroup = Get-Group -Identity $groupId -ErrorAction Stop
        Write-Information "Succesfully queried Exchange Online group with ID '$groupId'"
    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObject = Resolve-HTTPError -Error $ex
    
            $verboseErrorMessage = $errorObject.ErrorMessage
    
            $auditErrorMessage = $errorObject.ErrorMessage
        }
    
        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
            $verboseErrorMessage = $ex.Exception.Message
        }
        if ([String]::IsNullOrEmpty($auditErrorMessage)) {
            $auditErrorMessage = $ex.Exception.Message
        }
    
        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
        $Log = @{
            Action            = "Undefined" # optional. ENUM (undefined = default) 
            System            = "Exchange Online" # optional (free format text) 
            Message           = "Could not query Exchange Online group with ID '$groupId'. Error: $auditErrorMessage" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = "Exchange Online" # optional (free format text) 
            
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
        throw "Could not query Exchange Online group with ID '$groupId'. Error: $auditErrorMessage"

        # Clean up error variables
        Remove-Variable 'verboseErrorMessage' -ErrorAction SilentlyContinue
        Remove-Variable 'auditErrorMessage' -ErrorAction SilentlyContinue
    }

    # Add members
    if ($usersToAdd -ne $null) {
        try {
            Write-Verbose "Adding Exchange Online users [$($usersToAdd.Name -join ',')] to Exchange Online group [$($exchangeOnlineGroup.displayName)]"
            
            foreach ($user in $usersToAdd) {
                $addMemberParams = @{
                    Identity                        = $exchangeOnlineGroup.Identity
                    Member                          = $user.Id
                    BypassSecurityGroupManagerCheck = $true
                    Confirm                         = $false
                    ErrorAction                     = 'Stop'
                }

                $addMember = Add-DistributionGroupMember @addMemberParams
            }

            Write-Information "Succesfully added Exchange Online users [$($usersToAdd.Name -join ',')] to Exchange Online group [$($exchangeOnlineGroup.displayName)]"
            $Log = @{
                Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                System            = "Exchange Online" # optional (free format text) 
                Message           = "Succesfully added Exchange Online users [$($usersToAdd.Name -join ',')] to Exchange Online group [$($exchangeOnlineGroup.displayName)]" # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
        catch {
            $ex = $PSItem
            if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                $errorObject = Resolve-HTTPError -Error $ex
        
                $verboseErrorMessage = $errorObject.ErrorMessage
        
                $auditErrorMessage = $errorObject.ErrorMessage
            }
        
            # If error message empty, fall back on $ex.Exception.Message
            if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                $verboseErrorMessage = $ex.Exception.Message
            }
            if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                $auditErrorMessage = $ex.Exception.Message
            }

            Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
            if ($auditErrorMessage -like "*already a member of the group*") {
                Write-Information "The recipient $($user.Name) is already a member of the group $($exchangeOnlineGroup.Identity)";
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange Online" # optional (free format text) 
                    Message           = "The recipient $($user.Name) is already a member of the group $($exchangeOnlineGroup.Identity)" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                    TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
            elseif ($auditErrorMessage -like "*object '$($exchangeOnlineGroup.id)' couldn't be found*") {
                Write-Warning "Group $($exchangeOnlineGroup.Identity) couldn't be found. Possibly no longer exists. Skipping action";
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange Online" # optional (free format text) 
                    Message           = "Group $($exchangeOnlineGroup.Identity) couldn't be found. Possibly no longer exists. Skipping action" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                    TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
            elseif ($auditErrorMessage -like "*Couldn't find object ""$($user.Id)""*") {
                Write-Warning "User $($user.Name) couldn't be found. Possibly no longer exists. Skipping action";
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange Online" # optional (free format text) 
                    Message           = "User $($user.Name) couldn't be found. Possibly no longer exists. Skipping action" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                    TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
            else {
                Write-Error "Could not add Exchange Online users [$($usersToAdd.Name -join ',')] to Exchange Online group [$($exchangeOnlineGroup.displayName). Error: $auditErrorMessage"
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange Online" # optional (free format text) 
                    Message           = "Could not add Exchange Online users [$($usersToAdd.Name -join ',')] to Exchange Online group [$($exchangeOnlineGroup.displayName). Error: $auditErrorMessage" # required (free format text) 
                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                    TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }

            # Clean up error variables
            Remove-Variable 'verboseErrorMessage' -ErrorAction SilentlyContinue
            Remove-Variable 'auditErrorMessage' -ErrorAction SilentlyContinue
        }
    }

    # Remove members
    if ($usersToRemove -ne $null) {
        try {
            Write-Verbose "Removing Exchange Online users [$($usersToRemove.Name -join ',')] from Exchange Online group [$($exchangeOnlineGroup.displayName)]"

            foreach ($user in $usersToRemove) {
                $removeMemberParams = @{
                    Identity                        = $exchangeOnlineGroup.Identity
                    Member                          = $user.Id
                    BypassSecurityGroupManagerCheck = $true
                    Confirm                         = $false
                    ErrorAction                     = 'Stop'
                }

                $removeMember = Remove-DistributionGroupMember @removeMemberParams
            }

            Write-Information "Succesfully removed Exchange Online users [$($usersToRemove.Name -join ',')] from Exchange Online group [$($exchangeOnlineGroup.displayName)]"
            $Log = @{
                Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                System            = "Exchange Online" # optional (free format text) 
                Message           = "Succesfully removed Exchange Online users [$($usersToRemove.Name -join ',')] from Exchange Online group [$($exchangeOnlineGroup.displayName)]" # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
        catch {
            $ex = $PSItem
            if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                $errorObject = Resolve-HTTPError -Error $ex

                $verboseErrorMessage = $errorObject.ErrorMessage

                $auditErrorMessage = $errorObject.ErrorMessage
            }
        
            # If error message empty, fall back on $ex.Exception.Message
            if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                $verboseErrorMessage = $ex.Exception.Message
            }
            if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                $auditErrorMessage = $ex.Exception.Message
            }
 
            Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
            if ($auditErrorMessage -like "*isn't a member of the group*") {
                Write-Information "The recipient  $($user.Name) isn't a member of the group $($exchangeOnlineGroup.Identity))";
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange Online" # optional (free format text) 
                    Message           = "The recipient  $($user.Name) isn't a member of the group $($exchangeOnlineGroup.Identity))" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                    TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
            elseif ($auditErrorMessage -like "*object '$($exchangeOnlineGroup.id)' couldn't be found*") {
                Write-Warning "Group $($exchangeOnlineGroup.Identity) couldn't be found. Possibly no longer exists. Skipping action";
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange Online" # optional (free format text) 
                    Message           = "Group $($exchangeOnlineGroup.Identity) couldn't be found. Possibly no longer exists. Skipping action" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                    TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
            elseif ($auditErrorMessage -like "*Couldn't find object ""$($user.Id)""*") {
                Write-Warning "User $($user.Name) couldn't be found. Possibly no longer exists. Skipping action";
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange Online" # optional (free format text) 
                    Message           = "User $($user.Name) couldn't be found. Possibly no longer exists. Skipping action" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                    TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
            else {
                Write-Error "Could not remove Exchange Online users [$($usersToRemove.Name -join ',')] from Exchange Online group [$($exchangeOnlineGroup.displayName)]. Error: $auditErrorMessage"
                $Log = @{
                    Action            = "RevokeMembership" # optional. ENUM (undefined = default) 
                    System            = "Exchange Online" # optional (free format text) 
                    Message           = "Could not remove Exchange Online users [$($usersToRemove.Name -join ',')] from Exchange Online group [$($exchangeOnlineGroup.displayName)]. Error: $auditErrorMessage" # required (free format text) 
                    IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                    TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }

            # Clean up error variables
            Remove-Variable 'verboseErrorMessage' -ErrorAction SilentlyContinue
            Remove-Variable 'auditErrorMessage' -ErrorAction SilentlyContinue
        }
    }

    # Update owners
    if ($Owners -ne $null) {
        try {
            Write-Verbose "Updating owners to [$($Owners.Name -join ',')] for Exchange Online group [$($exchangeOnlineGroup.displayName)]"

            $updateOwnersParams = @{
                Identity                        = $exchangeOnlineGroup.Identity
                ManagedBy                       = $Owners.userPrincipalName
                BypassSecurityGroupManagerCheck = $true
                Confirm                         = $false
                ErrorAction                     = 'Stop'
            }

            $updateOwners = Set-DistributionGroup @updateOwnersParams

            Write-Information "Succesfully updated owners to [$($Owners.Name -join ',')] for Exchange Online group [$($exchangeOnlineGroup.displayName)]"
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "Exchange Online" # optional (free format text) 
                Message           = "Succesfully updated owners to [$($Owners.Name -join ',')] for Exchange Online group [$($exchangeOnlineGroup.displayName)]" # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
        }
        catch {
            $ex = $PSItem
            if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                $errorObject = Resolve-HTTPError -Error $ex
        
                $verboseErrorMessage = $errorObject.ErrorMessage
        
                $auditErrorMessage = $errorObject.ErrorMessage
            }
        
            # If error message empty, fall back on $ex.Exception.Message
            if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                $verboseErrorMessage = $ex.Exception.Message
            }
            if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                $auditErrorMessage = $ex.Exception.Message
            }

            Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
            Write-Error "Could not update owners $($Owners.Name -join ',')] for Exchange Online group [$($exchangeOnlineGroup.displayName)]. Error: $auditErrorMessage"
            $Log = @{
                Action            = "UpdateResource" # optional. ENUM (undefined = default) 
                System            = "Exchange Online" # optional (free format text) 
                Message           = "Could not update owners $($Owners.Name -join ',')] for Exchange Online group [$($exchangeOnlineGroup.displayName)]. Error: $auditErrorMessage" # required (free format text) 
                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = "$($exchangeOnlineGroup.displayName)" # optional (free format text) 
                TargetIdentifier  = "$($exchangeOnlineGroup.Identity)" # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
            # Clean up error variables
            Remove-Variable 'verboseErrorMessage' -ErrorAction SilentlyContinue
            Remove-Variable 'auditErrorMessage' -ErrorAction SilentlyContinue
        }
    }    
}
finally {
    Write-Verbose "Closing Exchange Online connection"
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop      
    Write-Information "Successfully closed Exchange Online connection"
}
