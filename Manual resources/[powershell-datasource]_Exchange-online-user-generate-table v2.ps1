# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Exchange parameters
$exchangeOnlineConnectionUri = "https://outlook.office365.com/powershell-liveid/"
$username = $ExchangeOnlineAdminUsername
$password = $ExchangeOnlineAdminPassword

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
    Write-Information -Message "Closing Exchange Online connection"
    $exchangeSession | Remove-PSSession -ErrorAction Stop       
    Write-Information -Message "Successfully closed Exchange Online connection"
}
