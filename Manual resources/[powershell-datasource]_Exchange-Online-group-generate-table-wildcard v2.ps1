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
    $searchValue = $datasource.searchValue
    $searchQuery = "*$searchValue*"
     
    if([String]::IsNullOrEmpty($searchValue) -eq $true){
        # Do nothing
    }else{ 
        Write-Information "Searching for Exchange Online groups.."
        
        $exchangeOnlineGroups = Get-Group -Identity *

        Write-Information -Message "SearchQuery: $searchQuery"
        Write-Information -Message "Searching for: $searchQuery"
        
        # Filter for specicic group by Display name
        $exchangeOnlineGroups = foreach($exchangeOnlineGroup in $exchangeOnlineGroups){
            if($exchangeOnlineGroup.displayName -like $searchQuery){
                $exchangeOnlineGroup
            }
        }

        $groups = $exchangeOnlineGroups
        $resultCount = $groups.id.Count
     
        Write-Information -Message "Result count: $resultCount"
     
        if($resultCount -gt 0){
            foreach($group in $groups){
                $returnObject = @{
                    name="$($group.displayName)";
                    id="$($group.id)";
                    description="$($group.description)";
                    groupType ="$($group.GroupType)"
                }
                Write-Output $returnObject
            }
        }
    }
} catch {
    $errorDetailsMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).error.message
    Write-Error ("Error searching for Exchange Online groups. Error: $($_.Exception.Message)" + $errorDetailsMessage)
} finally {
    Write-Information "Closing Exchange Online connection"
    $exchangeSession | Remove-PSSession -ErrorAction Stop       
    Write-Information "Successfully closed Exchange Online connection"
}
