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
    , "Get-DistributionGroupMember"
)

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
    throw "Error connecting to Exchange Online. Error Message: $auditErrorMessage"
}

try {
    $groupIdentity = $datasource.selectedGroup.id

    if ([String]::IsNullOrEmpty($groupIdentity) -eq $true) {
        Write-Error "No Group id provided"
    }
    else { 
        Write-Verbose "Querying Exchange Online group members"
        
        $exchangeOnlineUsers = Get-DistributionGroupMember -Identity $groupIdentity
        $users = $exchangeOnlineUsers
        $resultCount = $users.id.Count
        
        Write-Information "Successfully queried Exchange Online group members. Result count: $resultCount"
         
        if ($resultCount -gt 0) {
            foreach ($user in $users) {
                $displayValue = $user.displayName + " [" + $user.WindowsLiveID + "]"
                  
                $returnObject = @{
                    Name              = $displayValue;
                    UserPrincipalName = "$($user.UserPrincipalName)";
                    Id                = "$($user.id)";
                }
                Write-Output $returnObject
            }
        }
    }
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
    throw "Error searching for Exchange Online group members. Error Message: $auditErrorMessage"
}
finally {
    Write-Verbose "Disconnection from Exchange Online"
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop    
    Write-Information "Successfully disconnected from Exchange Online"
}
