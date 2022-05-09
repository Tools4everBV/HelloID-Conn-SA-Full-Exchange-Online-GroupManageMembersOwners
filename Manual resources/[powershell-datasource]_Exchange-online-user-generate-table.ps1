# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Exchange parameters
$username = $ExchangeOnlineAdminUsername
$password = $ExchangeOnlineAdminPassword

# Connect to Exchange Online
try{
    Write-Verbose "Connecting to Exchange Online"

    # Import module
    $moduleName = "ExchangeOnlineManagement"
    $commands = @("Get-User")

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


try {
    Write-Information "Searching for Exchange users.."
    
    $exchangeOnlineUsers = Get-User -ResultSize Unlimited
    $users = $exchangeOnlineUsers
    $resultCount = $users.id.Count
            
    Write-Information "Result count: $resultCount"
        
    if($resultCount -gt 0){
        foreach($user in $users){
            $displayValue = $user.displayName + " [" + $user.WindowsLiveID + "]"
                
            $returnObject = @{
                name=$displayValue;
                UserPrincipalName="$($user.UserPrincipalName)";
                id="$($user.id)";
            }
            Write-Output $returnObject
        }
    }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for Exchange Online users. Error: $($_.Exception.Message)" + $errorDetailsMessage)
} finally {
    Write-Verbose "Disconnecting from Exchange Online"
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    Write-Information "Successfully disconnected from Exchange Online"
}
