<!-- Requirements -->
## Requirements
This HelloID Service Automation Delegated Form uses [Remote PowerShell to connect to Exchange Online](https://docs.microsoft.com/en-us/powershell/exchange/connect-to-exchange-servers-using-remote-powershell?view=exchange-ps)

<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides Exchange Online (Office365) distribution group functionality. The following steps will be performed:
 1. Search and select the Exchange Online group
 2. Select the owner(s)
 3. Select the member(s)
 4. After confirmation the updates are processed (add or remove AD group members and/or owners)

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.0   | Initial release | 2022/03/28  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [Requirements](#requirements)
- [Description](#description)
- [Table of Contents](#table-of-contents)
- [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  - [Getting started](#getting-started)
- [Post-setup configuration](#post-setup-configuration)
- [Manual resources](#manual-resources)
  - [Powershell data source 'Exchange-Online-group-generate-table-wildcard v2'](#powershell-data-source-Exchange-Online-group-generate-table-wildcard-v2)
  - [Powershell data source 'Exchange-online-user-generate-table v2'](#powershell-data-source-Exchange-online-user-generate-table-v2)
  - [Powershell data source 'Exchange-Online-group-generate-table-owners v2'](#powershell-data-source-Exchange-Online-group-generate-table-owners-v2)
  - [Powershell data source 'Exchange-Online-group-generate-table-members v2'](#powershell-data-source-Exchange-Online-group-generate-table-members-v2)
  - [Delegated form task 'Exchange Online - Group - Manage memberships'](#Delegated-form-task-Exchange-Online-Group-Manage-memberships)
- [Getting help](#getting-help)
- [HelloID Docs](#helloid-docs)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_


### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.

 
## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)

| Variable name                             | Description                                   | Example value     |
| ----------------------------------------- | --------------------------------------------- | ----------------- |
| ExchangeOnlineAdminUsername               | Exchange admin account                        | user@domain.com   |
| ExchangeOnlineAdminPassword               | Exchange admin password                       | ********          |


## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source 'Exchange-Online-group-generate-table-wildcard v2'
This Powershell data source gathers the available groups (that match the provided wildcard searchstring).

### Powershell data source 'Exchange-online-user-generate-table v2'
This Powershell data source queries and returns all available users.

### Powershell data source 'Exchange-Online-group-generate-table-owners v2'
This Powershell data source queries and returns the owners of the group.

### Powershell data source 'Exchange-Online-group-generate-table-members v2'
This Powershell data source queries and returns the members of the group.

### Delegated form task 'Exchange Online - Group - Manage memberships'
This delegated form task will update the group members and/or owners.

## Getting help
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012518799-How-to-add-a-target-system) pages_

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/804-helloid-sa-exchange-online-manage-group-members-and-or-owners)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/