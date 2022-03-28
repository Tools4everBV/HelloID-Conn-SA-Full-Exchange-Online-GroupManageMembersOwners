# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("NTFS Management") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> ExchangeOnlineAdminPassword
$tmpName = @'
ExchangeOnlineAdminPassword
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "True"});

#Global variable #2 >> ExchangeOnlineAdminUsername
$tmpName = @'
ExchangeOnlineAdminUsername
'@ 
$tmpValue = @'
sa_exch@enyoi.nl
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][String][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "Exchange-online-user-generate-table v2" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"UserPrincipalName","type":0},{"key":"id","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Exchange-online-user-generate-table v2
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Exchange-online-user-generate-table v2" #>

<# Begin: DataSource "Exchange-online-user-generate-table v2" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"name","type":0},{"key":"UserPrincipalName","type":0},{"key":"id","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
Exchange-online-user-generate-table v2
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "Exchange-online-user-generate-table v2" #>

<# Begin: DataSource "Exchange-Online-group-generate-table-wildcard v2" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"groupType","type":0},{"key":"description","type":0},{"key":"name","type":0},{"key":"id","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"searchValue","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
Exchange-Online-group-generate-table-wildcard v2
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "Exchange-Online-group-generate-table-wildcard v2" #>

<# Begin: DataSource "Exchange-Online-group-generate-table-owners v2" #>
$tmpPsScript = @'
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
'@ 
$tmpModel = @'
[{"key":"windowsLiveID","type":0},{"key":"id","type":0},{"key":"name","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":1}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
Exchange-Online-group-generate-table-owners v2
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "Exchange-Online-group-generate-table-owners v2" #>

<# Begin: DataSource "Exchange-Online-group-generate-table-members v2" #>
$tmpPsScript = @'
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
        Write-Information "Searching for Exchange Online group members.."
        
        $exchangeOnlineUsers = Get-DistributionGroupMember -Identity $Identity
        $users = $exchangeOnlineUsers
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
    Write-Error ("Error searching for Exchange Online group members. Error: $($_.Exception.Message)" + $errorDetailsMessage)
} finally {
    Write-Verbose "Closing Exchange Online connection"
    $exchangeSession | Remove-PSSession -ErrorAction Stop       
    Write-Information "Successfully closed Exchange Online connection"
}
'@ 
$tmpModel = @'
[{"key":"windowsLiveID","type":0},{"key":"id","type":0},{"key":"name","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"selectedGroup","type":0,"options":1}]
'@ 
$dataSourceGuid_4 = [PSCustomObject]@{} 
$dataSourceGuid_4_Name = @'
Exchange-Online-group-generate-table-members v2
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_4_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_4) 
<# End: DataSource "Exchange-Online-group-generate-table-members v2" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Exchange Online - Group - Manage memberships" #>
$tmpSchema = @"
[{"label":"Select group","fields":[{"key":"searchfield","templateOptions":{"label":"Search","placeholder":""},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"gridGroups","templateOptions":{"label":"Select group","required":true,"grid":{"columns":[{"headerName":"Description","field":"description"},{"headerName":"Id","field":"id"},{"headerName":"Name","field":"name"},{"headerName":"Group Type","field":"groupType"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"searchValue","otherFieldValue":{"otherFieldKey":"searchfield"}}]}},"useFilter":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Members","fields":[{"key":"owners","templateOptions":{"label":"Manage group owners","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"name","optionDisplayProperty":"name","labelLeft":"Available","labelRight":"Owners"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[]}},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"gridGroups"}}]}}},"type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"members","templateOptions":{"label":"Manage group memberships","required":false,"filterable":true,"useDataSource":true,"dualList":{"options":[{"guid":"75ea2890-88f8-4851-b202-626123054e14","Name":"Apple"},{"guid":"0607270d-83e2-4574-9894-0b70011b663f","Name":"Pear"},{"guid":"1ef6fe01-3095-4614-a6db-7c8cd416ae3b","Name":"Orange"}],"optionKeyProperty":"name","optionDisplayProperty":"name","labelLeft":"Available","labelRight":"Member of"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[]}},"destinationDataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_4","input":{"propertyInputs":[{"propertyName":"selectedGroup","otherFieldValue":{"otherFieldKey":"gridGroups"}}]}},"useFilter":false},"type":"duallist","summaryVisibility":"Show","sourceDataSourceIdentifierSuffix":"source-datasource","destinationDataSourceIdentifierSuffix":"destination-datasource","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Exchange Online - Group - Manage memberships
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
foreach($group in $delegatedFormAccessGroupNames) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $delegatedFormAccessGroupGuid = $response.groupGuid
        $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
        
        Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
    } catch {
        Write-Error "HelloID (access)group '$group', message: $_"
    }
}
$delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Exchange Online - Group - Manage memberships
'@
$tmpTask = @'
{"name":"Exchange Online - Group - Manage memberships","script":"# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# Exchange parameters\r\n$exchangeOnlineConnectionUri = \"https://outlook.office365.com/powershell-liveid/\"\r\n$username = $ExchangeOnlineAdminUsername\r\n$password = $ExchangeOnlineAdminPassword\r\n\r\n# Form input\r\n$groupId = $form.gridGroups.id\r\n$Owners = $form.owners.right\r\n$usersToAdd = $form.members.leftToRight\r\n$usersToRemove = $form.members.rightToLeft\r\n\r\n# Connecto to Exchange\r\ntry{\r\n    Write-Verbose \"Connecting to Exchange Online..\"\r\n    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force\r\n    $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)\r\n    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeOnlineConnectionUri -Credential $credential -Authentication Basic -AllowRedirection -ErrorAction Stop \r\n   \r\n    if($exchangeSession){\r\n        $exchangeOnlineSession = Import-PSSession $exchangeSession -AllowClobber -DisableNameChecking\r\n        Write-Information \"Successfully connected to Office365\"\r\n    }else{\r\n        throw \"username or password is not correct\"\r\n    }\r\n}catch{\r\n    throw \"Could not connect to Exchange Online, error: $($_.Exception.Message)\"\r\n}\r\n\r\ntry{\r\n    try {\r\n        Write-Verbose \"Searching for Exchange Online group ID=$groupId\"\r\n        \r\n        $exchangeOnlineGroup = Get-Group -Identity $groupId -ErrorAction Stop\r\n        Write-Information \"Succesfully found Exchange Online group [$groupId]\"\r\n    } catch {\r\n        Write-Error \"Could not find Exchange Online group [$groupId]. Error: $($_.Exception.Message)\"\r\n    }\r\n\r\n    # Add members\r\n    if($usersToAdd -ne $null){\r\n        try {\r\n            foreach($user in $usersToAdd){\r\n                $addMember = Add-DistributionGroupMember -Identity $exchangeOnlineGroup.Identity -Member $user.Id -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop\r\n            }\r\n\r\n            Write-Information \"Succesfully added Exchange Online users [$($usersToAdd | ConvertTo-Json)] to Exchange Online group [$($exchangeOnlineGroup.displayName)]\"\r\n        } catch {\r\n            if($_ -like \"*already a member of the group*\"){\r\n                Write-Information \"The recipient $($user.Name) is already a member of the group $($exchangeOnlineGroup.Identity)\";\r\n            }elseif($_ -like \"*object '$($exchangeOnlineGroup.id)' couldn't be found*\"){\r\n                Write-Warning \"Group $($exchangeOnlineGroup.Identity) couldn't be found. Possibly no longer exists. Skipping action\";\r\n            }elseif($_ -like \"*Couldn't find object \"\"$($user.Id)\"\"*\"){\r\n                Write-Warning \"User $($user.Name) couldn't be found. Possibly no longer exists. Skipping action\";\r\n            }else{\r\n                Write-Error \"Could not add Exchange Online users [$($usersToAdd | ConvertTo-Json)] to Exchange Online group [$($exchangeOnlineGroup.displayName). Error: $($_.Exception.Message)\"\r\n            }\r\n        }\r\n    }\r\n\r\n    # Remove members\r\n    if($usersToRemove -ne $null){\r\n        try {\r\n            foreach($user in $usersToRemove){\r\n                $removeMember = Remove-DistributionGroupMember -Identity $exchangeOnlineGroup.Identity -Member $user.Id -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop\r\n            }\r\n\r\n            Write-Information \"Succesfully removed Exchange Online users [$($usersToRemove | ConvertTo-Json)] from Exchange Online group [$($exchangeOnlineGroup.displayName)]\"\r\n        } catch {\r\n            if($_ -like \"*isn't a member of the group*\"){\r\n                Write-Information \"The recipient  $($user.Name) isn't a member of the group $($exchangeOnlineGroup.Identity))\";\r\n            }elseif($_ -like \"*object '$($exchangeOnlineGroup.id)' couldn't be found*\"){\r\n                Write-Warning \"Group $($exchangeOnlineGroup.Identity) couldn't be found. Possibly no longer exists. Skipping action\";\r\n            }elseif($_ -like \"*Couldn't find object \"\"$($user.Id)\"\"*\"){\r\n                Write-Warning \"User $($user.Name) couldn't be found. Possibly no longer exists. Skipping action\";\r\n            }else{\r\n                Write-Error \"Could not remove Exchange Online users [$($usersToRemove | ConvertTo-Json)] from Exchange Online group [$($exchangeOnlineGroup.displayName)]. Error: $($_.Exception.Message)\"\r\n            }\r\n        }\r\n    }\r\n\r\n    # Update owners\r\n    if($OwnersToUpdate -ne $null){\r\n        try {\r\n            $groupParams = @{\r\n                Identity            =   $exchangeOnlineGroup.Identity\r\n                ManagedBy           =  $Owners.userPrincipalName\r\n            }\r\n\r\n            Write-Information \"Succesfully updated owners [$($Owners | ConvertTo-Json)] for Exchange Online group [$exchangeOnlineGroup.Identity]\"\r\n        } catch {\r\n            Write-Error \"Could not update owners [$($Owners | ConvertTo-Json)] for Exchange Online group [$exchangeOnlineGroup.Identity]. Error: $($_.Exception.Message)\"\r\n        }\r\n    }    \r\n} finally {\r\n    Write-Verbose \"Closing Exchange Online connection\"\r\n    $exchangeSession | Remove-PSSession -ErrorAction Stop       \r\n    Write-Information \"Successfully closed Exchange Online connection\"\r\n}","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-users" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

