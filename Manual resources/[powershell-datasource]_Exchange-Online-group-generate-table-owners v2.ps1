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
    $Identity = $datasource.selectedGroup.id

    if([String]::IsNullOrEmpty($Identity) -eq $true){
        Write-Error "No Group id provided"
    }else{ 
        Write-Information "Searching for Exchange Online group owners.."
        
        $exchangeOnlineUsers = (Get-DistributionGroup -Identity $Identity).managedBy
        $users = foreach($exchangeOnlineUser in $exchangeOnlineUsers){
            Get-User $exchangeOnlineUser
        }
        $resultCount = $users.id.Count
        Write-Information  "Result count: $resultCount"
         
        if($resultCount -gt 0){
            foreach($user in $users){
                $displayValue = $user.displayName + " [" + $user.WindowsLiveID + "]"
                  
                $returnObject = @{
                    windowsLiveID="$($user.WindowsLiveID)";
                    name=$displayValue;
                    id="$($user.id)";
                }
                Write-Output $returnObject
            }
        }
    }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for Exchange Online group owners. Error: $($_.Exception.Message)" + $errorDetailsMessage)
} finally {
    Write-Verbose "Closing Exchange Online connection"
    $exchangeSession | Remove-PSSession -ErrorAction Stop       
    Write-Information "Successfully closed Exchange Online connection"
}
