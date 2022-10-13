# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Exchange Online in an unattended scripting scenario using a certificate.
# Follow the Microsoft Docs on how to set up the Azure App Registration: https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps
$AADOrganization = $AADExchangeOrganization
$AADAppID = $AADExchangeAppID
$AADCertificateThumbprint = $AADExchangeCertificateThumbprint # Certificate has to be locally installed

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
        Organization          = $AADOrganization
        AppID                 = $AADAppID
        CertificateThumbPrint = $AADCertificateThumbprint
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
            }
            elseif ($auditErrorMessage -like "*object '$($exchangeOnlineGroup.id)' couldn't be found*") {
                Write-Warning "Group $($exchangeOnlineGroup.Identity) couldn't be found. Possibly no longer exists. Skipping action";
            }
            elseif ($auditErrorMessage -like "*Couldn't find object ""$($user.Id)""*") {
                Write-Warning "User $($user.Name) couldn't be found. Possibly no longer exists. Skipping action";
            }
            else {
                Write-Error "Could not add Exchange Online users [$($usersToAdd.Name -join ',')] to Exchange Online group [$($exchangeOnlineGroup.displayName). Error: $auditErrorMessage"
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
            }
            elseif ($auditErrorMessage -like "*object '$($exchangeOnlineGroup.id)' couldn't be found*") {
                Write-Warning "Group $($exchangeOnlineGroup.Identity) couldn't be found. Possibly no longer exists. Skipping action";
            }
            elseif ($auditErrorMessage -like "*Couldn't find object ""$($user.Id)""*") {
                Write-Warning "User $($user.Name) couldn't be found. Possibly no longer exists. Skipping action";
            }
            else {
                Write-Error "Could not remove Exchange Online users [$($usersToRemove.Name -join ',')] from Exchange Online group [$($exchangeOnlineGroup.displayName)]. Error: $auditErrorMessage"
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
