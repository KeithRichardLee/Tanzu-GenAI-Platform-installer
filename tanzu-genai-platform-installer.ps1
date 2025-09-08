# PowerShell script which results in the deployment of VMware Tanzu Platform with GenAI capabilities
# 
# Script will... 
# - Validate all inputs
# - Deploy VMware Tanzu Operations Manager OVA
# - Configure authentication for VMware Tanzu Operations Manager
# - Configure and deploy BOSH Director
# - Configure and deploy VMware Tanzu Platform for Cloud Foundry
# - Configure and deploy VMware Tanzu Postgres
# - Configure and deploy VMware Tanzu GenAI
# - Configure and deploy VMware Tanzu Healthwatch & Healthwatch Exporter (optional)
# - Configure and deploy VMware Tanzu Hub (optional)
#
############################################################################################

### Required inputs

### Full Path to Tanzu Operations Manager OVA, TPCF tile, Postgres tile, GenAI tile, and OM CLI
$OpsManOVA    = "/Users/Tanzu/Downloads/ops-manager-vsphere-3.1.2.ova"         #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware%20Tanzu%20Operations%20Manager
$TPCFTile     = "/Users/Tanzu/Downloads/srt-10.2.2-build.2.pivotal"            #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=Tanzu%20Platform%20for%20Cloud%20Foundry
$PostgresTile = "/Users/Tanzu/Downloads/postgres-10.1.1-build.1.pivotal"       #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware+Tanzu+for+Postgres+on+Cloud+Foundry
$GenAITile    = "/Users/Tanzu/Downloads/genai-10.2.3.pivotal"                  #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=GenAI%20on%20Tanzu%20Platform%20for%20Cloud%20Foundry
$OMCLI        = "/usr/local/bin/om"                                            #Download from https://github.com/pivotal-cf/om

### Infra config
$VIServer = "FILL-ME-IN"
$VIUsername = "FILL-ME-IN"
$VIPassword = 'FILL-ME-IN'
$VMDatacenter = "FILL-ME-IN"
$VMCluster = "FILL-ME-IN"
$VMResourcePool = "FILL-ME-IN"  #where Tanzu Platform will be installed. Create manually before running the script.
$VMDatastore = "FILL-ME-IN"
$VirtualSwitchType = "VSS"      #VSS or VDS
$VMNetwork = "FILL-ME-IN"       #portgroup name
$VMNetworkCIDR = "FILL-ME-IN"   #eg "10.0.70.0/24"
$VMNetmask = "FILL-ME-IN"       #eg "255.255.255.0"
$VMGateway = "FILL-ME-IN"
$VMDNS = "FILL-ME-IN"
$VMNTP = "FILL-ME-IN"

### Tanzu Platform config
$OpsManagerAdminPassword = 'FILL-ME-IN'
$OpsManagerIPAddress = "FILL-ME-IN"
$OpsManagerFQDN = "FILL-ME-IN"
$BOSHNetworkReservedRange = "FILL-ME-IN"  #add IPs, either individual and/or ranges you _don't_ want BOSH to use in the subnet eg Ops Man, gateway, DNS, NTP, jumpbox eg 10.0.70.0-10.0.70.2,10.0.70.10
$TPCFGoRouter = "FILL-ME-IN"              #IP which the Tanzu Platform system and apps domain resolves to. Choose an IP towards the end of available IPs
$TPCFDomain = "FILL-ME-IN"                #Tanzu Platform system and apps subdomains will be added to this. Resolves to the TPCF GoRouter IP
$TPCFLicenseKey = ""                      #License key required for 10.2 and later

### Install Healthwatch (observability)?
$InstallHealthwatch = $false
$HealthwatchTile         = "/Users/Tanzu/Downloads/healthwatch-2.3.3-build.21.pivotal"                #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=Healthwatch
$HealthwatchExporterTile = "/Users/Tanzu/Downloads/healthwatch-pas-exporter-2.3.3-build.21.pivotal"   #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=Healthwatch

### Install Tanzu Hub (global control plane)?
$InstallHub = $false
$HubTile = "/Users/Tanzu/Downloads/tanzu-hub-10.2.1.pivotal"        #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=Tanzu%20Hub
$HubFQDN = "FILL-ME-IN"

### end of required inputs

############################################################################################

### Advanced parameters, do not change unless you know what you are doing!

# Ops Manager config
$OpsManagerDisplayName = "tanzu-ops-manager"
$OpsManagerNetmask = $VMNetmask
$OpsManagerGateway = $VMGateway
$OpsManagerAdminUsername = "admin"
$OpsManagerDecryptionPassword = $OpsManagerAdminPassword

# BOSH Director configuration 
$BOSHvCenterUsername = $VIUsername
$BOSHvCenterPassword = $VIPassword
$BOSHvCenterDatacenter = $VMDatacenter
$BOSHvCenterPersistentDatastores = $VMDatastore
$BOSHvCenterEpemeralDatastores = $VMDatastore
$BOSHvCenterVMFolder = "tpcf_vms"
$BOSHvCenterTemplateFolder = "tpcf_templates"
$BOSHvCenterDiskFolder = "tpcf_disk"

# AZ Definitions
$BOSHAZ = @{
    "az1" = @{
        iaas_name = "vCenter"
        cluster = $VMCluster
        resource_pool = $VMResourcePool
    }
}

# Network Definitions
$BOSHNetwork = @{
    "tp-network" = @{
        portgroupname = $VMNetwork 
        cidr = $VMNetworkCIDR
        reserved_range = $BOSHNetworkReservedRange 
        dns = $VMDNS
        gateway = $VMGateway
        az = "az1"
    }
}

$BOSHAZAssignment = "az1"
$BOSHNetworkAssignment = "tp-network"

##############################

# Tanzu Platform for Cloud Foundry (TPCF) configuration
$TPCFCredHubSecret = 'VMware1!VMware1!VMware1!' # must be 20 or more characters
$TPCFAZ = $BOSHAZAssignment
$TPCFNetwork = $BOSHNetworkAssignment
$TPCFComputeInstances = "1" # default is 1. Increase if planning to run many large apps

# User provided cert (full chain) and private key for the apps and system wildcard domains for TPCF. See https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-platform-for-cloud-foundry/10-0/tpcf/security_config.html for details on creating this cert and key
$userProvidedCert = $false
$CertPath = "/Users/Tanzu/certs/TP/fullchain.pem"
$KeyPath = "/Users/Tanzu/certs/TP/privkey.pem"

##############################

# Install Tanzu AI Solutions?
$InstallTanzuAI = $true 

# Tanzu AI Solutions config 
$OllamaEmbedModel = "nomic-embed-text"
$OllamaChatModel = "gemma2:2b"

# Deploy a model with chat and tools capabilities instead of just chat?  note; a vm will be created with 16 vCPU and 32 GB mem to run the model
$ToolsModel = $true
$OllamaChatToolsModel = "mistral-nemo:12b-instruct-2407-q4_K_M"

##############################

# Tanzu Hub
$UserProvidedHubCert = $false
$HubCertPath = "/Users/Tanzu/certs/Hub/fullchain.pem"
$HubKeyPath = "/Users/Tanzu/certs/Hub/privkey.pem"

##############################

# Product resource requirements
$ProductRequirements = @{
    "OpsMan" = @{
        IP = 2
        CPUGHz = 1
        MemoryGB = 16
        StorageGB = 40
    }
    "TPCF" = @{
        IP = 5
        CPUGHz = 2
        MemoryGB = 42
        StorageGB = 200
    }
    "TanzuAI" = @{
        IP = 6
        CPUGHz = 2
        MemoryGB = 26
        StorageGB = 140
    }
    "HealthWatch" = @{
        IP = 11
        CPUGHz = 1
        MemoryGB = 16
        StorageGB = 100
    }
    "Hub" = @{
        IP = 13
        CPUGHz = 10
        MemoryGB = 100
        StorageGB = 400
    }
}

##############################

# Required vSphere API privileges at vCenter level for Tanzu Operations Manager
$requiredVcenterPrivileges = @(
    "System.Anonymous",
    "System.Read",
    "System.View",
    "Global.ManageCustomFields",
    "Global.SetCustomField",
    "Extension.Register",
    "StorageProfile.Update",
    "StorageProfile.View"
)

# Required vSphere API privileges at Datacenter level for Tanzu Operations Manager
$requiredDatacenterPrivileges = @(
    "Datastore.FileManagement",
    "Network.Assign",
    "Datastore.AllocateSpace",
    "Datastore.Browse",
    "Datastore.DeleteFile",
    "Folder.Create",
    "Folder.Delete",
    "Folder.Move",
    "Folder.Rename",
    "Host.Inventory.EditCluster",
    "Host.Config.SystemManagement",
    "InventoryService.Tagging.CreateTag",
    "InventoryService.Tagging.EditTag",
    "InventoryService.Tagging.DeleteTag",
    "Resource.AssignVMToPool",
    "Resource.ColdMigrate",
    "Resource.HotMigrate",
    "StorageProfile.Update",
    "StorageProfile.View",
    "VirtualMachine.Config.AddExistingDisk",
    "VirtualMachine.Config.AddNewDisk",
    "VirtualMachine.Config.AddRemoveDevice",
    "VirtualMachine.Config.AdvancedConfig",
    "VirtualMachine.Config.CPUCount",
    "VirtualMachine.Config.Resource",
    "VirtualMachine.Config.ManagedBy",
    "VirtualMachine.Config.ChangeTracking",
    "VirtualMachine.Config.DiskLease",
    "VirtualMachine.Config.MksControl",
    "VirtualMachine.Config.DiskExtend",
    "VirtualMachine.Config.Memory",
    "VirtualMachine.Config.EditDevice",
    "VirtualMachine.Config.RawDevice",
    "VirtualMachine.Config.ReloadFromPath",
    "VirtualMachine.Config.RemoveDisk",
    "VirtualMachine.Config.Rename",
    "VirtualMachine.Config.ResetGuestInfo",
    "VirtualMachine.Config.Annotation",
    "VirtualMachine.Config.Settings",
    "VirtualMachine.Config.SwapPlacement",
    "VirtualMachine.Config.UpgradeVirtualHardware",
    "VirtualMachine.GuestOperations.Execute",
    "VirtualMachine.GuestOperations.Modify",
    "VirtualMachine.GuestOperations.Query",
    "VirtualMachine.Interact.AnswerQuestion",
    "VirtualMachine.Interact.SetCDMedia",
    "VirtualMachine.Interact.ConsoleInteract",
    "VirtualMachine.Interact.DefragmentAllDisks",
    "VirtualMachine.Interact.DeviceConnection",
    "VirtualMachine.Interact.GuestControl",
    "VirtualMachine.Interact.PowerOff",
    "VirtualMachine.Interact.PowerOn",
    "VirtualMachine.Interact.Reset",
    "VirtualMachine.Interact.Suspend",
    "VirtualMachine.Interact.ToolsInstall",
    "VirtualMachine.Inventory.CreateFromExisting",
    "VirtualMachine.Inventory.Create",
    "VirtualMachine.Inventory.Move",
    "VirtualMachine.Inventory.Register",
    "VirtualMachine.Inventory.Delete",
    "VirtualMachine.Inventory.Unregister",
    "VirtualMachine.Provisioning.DiskRandomAccess",
    "VirtualMachine.Provisioning.DiskRandomRead",
    "VirtualMachine.Provisioning.GetVmFiles",
    "VirtualMachine.Provisioning.PutVmFiles",
    "VirtualMachine.Provisioning.CloneTemplate",
    "VirtualMachine.Provisioning.Clone",
    "VirtualMachine.Provisioning.Customize",
    "VirtualMachine.Provisioning.DeployTemplate",
    "VirtualMachine.Provisioning.MarkAsTemplate",
    "VirtualMachine.Provisioning.MarkAsVM",
    "VirtualMachine.Provisioning.ModifyCustSpecs",
    "VirtualMachine.Provisioning.PromoteDisks",
    "VirtualMachine.Provisioning.ReadCustSpecs",
    "VirtualMachine.State.CreateSnapshot",
    "VirtualMachine.State.RemoveSnapshot",
    "VirtualMachine.State.RenameSnapshot",
    "VirtualMachine.State.RevertToSnapshot",
    "VApp.Import",
    "VApp.ApplicationConfig"
)

##############################

$verboseLogFile = "tanzu-genai-platform-installer.log"

# Installer Overrides
$confirmDeployment = 1
$preCheck = 1
$deployOpsManager = 1
$setupOpsManager = 1
$setupBOSHDirector = 1
$setupTPCF = 1
$setupPostgres = $InstallTanzuAI
$setupGenAI = $InstallTanzuAI
$setupHealthwatch = $InstallHealthwatch
$setupHub = $InstallHub
$ignoreWarnings = $false

############################################################################################
#### DO NOT EDIT BEYOND HERE ####

$StartTime = Get-Date

Function My-Logger {
    param(
    [Parameter(Mandatory=$true)]
    [String]$message,
    [ValidateSet("INFO", "WARNING", "ERROR")]
    [string]$level = "INFO",
    [System.ConsoleColor]$color = "Green",
    [switch]$LogOnly
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"
    $logMessage = "[$timeStamp] [$level] $message"
    
    # Write to console unless LogOnly switch is specified
    if (-not $LogOnly) {
        Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
        #Write-Host -NoNewline -ForegroundColor DarkGray " [$level]"
        Write-Host -ForegroundColor $color " $message"
    }
    
    # Always write to log file
    $logMessage | Out-File -Append -LiteralPath $verboseLogFile
}

function Check-productDeployed {
    param (
        [string]$productName
    )
    
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "products")
    $tableText = & $OMCLI $configArgs 2> $null
    
    # Split the table into lines
    $lines = $tableText -split "`n"
    
    # Find header row to determine column positions
    $headerRow = $lines | Where-Object { $_ -match "\|\s+NAME\s+\|" }
    
    if (-not $headerRow) {
        # Could not find header row in the table
        return $false
    }
    
    # Find the index of the NAME and DEPLOYED columns
    $headerParts = $headerRow -split "\|"
    $nameIndex = 0
    $deployedIndex = 0
    
    for ($i = 1; $i -lt $headerParts.Count; $i++) {
        if ($headerParts[$i] -match "^\s*NAME\s*$") {
            $nameIndex = $i
        }
        if ($headerParts[$i] -match "^\s*DEPLOYED\s*$") {
            $deployedIndex = $i
        }
    }
    
    # Find the item row
    $productRow = $lines | Where-Object { $_ -match "\|\s*$productName\s*\|" }
    
    if (-not $productRow) {
        # Could not find a row for '$productName' in the table
        return $false
    }
    
    # Extract the deployed value for the item
    $productRowParts = $productRow -split "\|"
    $productDeployedValue = $productRowParts[$deployedIndex].Trim()
    
    # Check if there's a value in the DEPLOYED column
    $hasDeployedEntry = -not [string]::IsNullOrWhiteSpace($productDeployedValue)
    
    return $hasDeployedEntry
}

function Test-UserPrivileges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^.+@.+$")]
        [string]$Username,
        
        [Parameter(Mandatory = $true)]
        [string]$EntityName,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Datacenter", "vCenter")]
        [string]$EntityType,
        
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredPrivileges
    )
    
    try {
        # Convert username@domain to domain\username format
        if ($Username -match "^(.+)@(.+)$") {
            $userPart = $matches[1]
            $domainPart = $matches[2]
            $UserPrincipal = "$domainPart\$userPart"
            My-Logger "Converted '$Username' to user principal format: '$UserPrincipal'" -LogOnly
        } else {
            throw "Invalid username format. Expected format: username@domain (e.g., tanzu@vsphere.local)"
        }
        
        My-Logger "Checking privileges for user: $UserPrincipal (original: $Username) on $EntityType entity: $EntityName" -LogOnly
        
        # Get the entity based on type
        switch ($EntityType) {
            "Datacenter" {
                $entity = Get-Datacenter -Name $EntityName -ErrorAction Stop
                if (-not $entity) {
                    throw "Datacenter '$EntityName' not found."
                }
            }
            "vCenter" {
                # For vCenter root entity, we need to get the root folder or use the service instance
                $entity = Get-Folder -Name "Datacenters" -ErrorAction SilentlyContinue
                if (-not $entity) {
                    # Alternative method to get vCenter root entity
                    $entity = Get-View -ViewType Folder -Filter @{"Name" = "Datacenters"} -ErrorAction SilentlyContinue
                    if (-not $entity) {
                        # Use service instance as fallback
                        $serviceInstance = Get-View ServiceInstance
                        $entity = Get-View $serviceInstance.Content.RootFolder
                    }
                }
                My-Logger "Using vCenter root entity for privilege check" -LogOnly
            }
        }
        
        # Get all permissions for the entity
        $permissions = Get-VIPermission -Entity $entity -ErrorAction Stop
        
        # Find permissions for the specified user
        $userPermissions = $permissions | Where-Object { $_.Principal -eq $UserPrincipal }
        
        if (-not $userPermissions) {
            My-Logger "No direct permissions found for user '$UserPrincipal' on $EntityType '$EntityName'" -LogOnly
            
            # Create result object for no permissions found
            return [PSCustomObject]@{
                Username = $Username
                UserPrincipal = $UserPrincipal
                EntityName = $EntityName
                EntityType = $EntityType
                HasAllRequiredPrivileges = $false
                MissingPrivileges = $RequiredPrivileges
                GrantedPrivileges = @()
                PermissionRoles = @()
            }
        }
        
        # Get all privileges granted through roles
        $grantedPrivileges = @()
        $roleNames = @()
        
        foreach ($permission in $userPermissions) {
            $role = Get-VIRole -Name $permission.Role -ErrorAction SilentlyContinue
            if ($role) {
                $roleNames += $role.Name
                $grantedPrivileges += $role.PrivilegeList
            }
        }
        
        # Remove duplicates
        $grantedPrivileges = $grantedPrivileges | Sort-Object | Get-Unique
        $roleNames = $roleNames | Sort-Object | Get-Unique
        
        # Check which required privileges are missing
        $missingPrivileges = @()
        $hasAllPrivileges = $true
        
        foreach ($requiredPriv in $RequiredPrivileges) {
            if ($requiredPriv -notin $grantedPrivileges) {
                $missingPrivileges += $requiredPriv
                $hasAllPrivileges = $false
            }
        }
        
        # Create and return result object
        $result = [PSCustomObject]@{
            Username = $Username
            UserPrincipal = $UserPrincipal
            EntityName = $EntityName
            EntityType = $EntityType
            HasAllRequiredPrivileges = $hasAllPrivileges
            MissingPrivileges = $missingPrivileges
            GrantedPrivileges = $grantedPrivileges
            PermissionRoles = $roleNames
        }
        
        # Output summary
        if ($hasAllPrivileges) {
            My-Logger "User '$Username' has all required privileges on $EntityType '$EntityName'" -LogOnly
        } else {
            My-Logger "User '$Username' is missing the following privileges on $EntityType '$EntityName':" -level Error -LogOnly
            $missingPrivileges | ForEach-Object { My-Logger "- $_" -level Error -LogOnly }
        }
        
        return $result
    }
    catch {
        My-Logger "Error checking privileges: $($_.Exception.Message)" -LogOnly
        throw
    }
}

function Ping-NetworkExcluding {
    param(
        [Parameter(Mandatory=$true)]
        [string]$NetworkCIDR,
        
        [Parameter(Mandatory=$true)]
        [string]$ExcludeList
    )
    
    # Function to convert IP address to integer
    function ConvertTo-IpInt {
        param([string]$IpAddress)
        $octets = $IpAddress.Split('.')
        return ([int64]$octets[0] -shl 24) + ([int64]$octets[1] -shl 16) + ([int64]$octets[2] -shl 8) + [int64]$octets[3]
    }
    
    # Function to convert integer back to IP address
    function ConvertFrom-IpInt {
        param([int64]$IpInt)
        $octet1 = [math]::Floor($IpInt / 16777216) % 256
        $octet2 = [math]::Floor($IpInt / 65536) % 256
        $octet3 = [math]::Floor($IpInt / 256) % 256
        $octet4 = $IpInt % 256
        return "$octet1.$octet2.$octet3.$octet4"
    }
    
    # Parse CIDR notation
    $cidrParts = $NetworkCIDR.Split('/')
    $networkAddress = $cidrParts[0]
    $subnetMask = [int]$cidrParts[1]
    
    # Calculate network range
    $networkInt = ConvertTo-IpInt -IpAddress $networkAddress
    $hostBits = 32 - $subnetMask
    $networkStart = $networkInt -band (-bnot ((1 -shl $hostBits) - 1))
    $networkEnd = $networkStart + ((1 -shl $hostBits) - 1)
    
    # Parse exclude list
    $excludeSet = @{}
    $excludeItems = $ExcludeList.Split(',')
    
    foreach ($item in $excludeItems) {
        $item = $item.Trim()
        if ($item -match '-') {
            # Handle range
            $rangeParts = $item.Split('-')
            $rangeStart = ConvertTo-IpInt -IpAddress $rangeParts[0].Trim()
            $rangeEnd = ConvertTo-IpInt -IpAddress $rangeParts[1].Trim()
            
            for ($i = $rangeStart; $i -le $rangeEnd; $i++) {
                $excludeSet[$i] = $true
            }
        } else {
            # Handle individual IP
            $ipInt = ConvertTo-IpInt -IpAddress $item
            $excludeSet[$ipInt] = $true
        }
    }
    
    # Ping each IP in the network range that's not excluded
    $results = @()
    
    My-Logger "Pinging network $NetworkCIDR excluding specified addresses $ExcludeList" -LogOnly
    
    for ($currentIp = $networkStart; $currentIp -le $networkEnd; $currentIp++) {
        # Skip network and broadcast addresses (first and last IP in the range)
        if ($currentIp -eq $networkStart -or $currentIp -eq $networkEnd) {
            continue
        }
        
        # Skip if IP is in exclude list
        if ($excludeSet.ContainsKey($currentIp)) {
            continue
        }
        
        $ipAddress = ConvertFrom-IpInt -IpInt $currentIp
        
        # Ping the IP address
        try {
            $pingResult = Test-Connection -ComputerName $ipAddress -Count 1 -Quiet -TimeoutSeconds 1
            
            $result = [PSCustomObject]@{
                IPAddress = $ipAddress
                Status = if ($pingResult) { "Reachable" } else { "Unreachable" }
            }
            
            $results += $result
            
            # Display real-time results
            if ($pingResult) {
                My-Logger "$ipAddress - Reachable" -LogOnly
            } else {
                My-Logger "$ipAddress - Unreachable" -LogOnly
            }
        }
        catch {
            $result = [PSCustomObject]@{
                IPAddress = $ipAddress
                Status = "Error: $($_.Exception.Message)"
            }
            $results += $result
            My-Logger "$ipAddress - Error" -LogOnly
        }
    }
    
    My-Logger "Ping operation completed. Total IPs tested: $($results.Count)" -LogOnly
    
    # Summary
    $reachable = ($results | Where-Object { $_.Status -eq "Reachable" }).Count
    $unreachable = ($results | Where-Object { $_.Status -eq "Unreachable" }).Count
    $errors = ($results | Where-Object { $_.Status -like "Error:*" }).Count
    My-Logger "Summary: Reachable:$reachable Unreachable:$unreachable Errors:$errors" -LogOnly
    
    return $results
}

function Test-IPAddressString {
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPString
    )
    
    # Check if string is null or empty
    if ([string]::IsNullOrWhiteSpace($IPString)) {
        My-Logger "IP string is null or empty" -LogOnly
        return $false
    }
    
    # Split by comma and trim whitespace from each entry
    $IPEntries = $IPString -split ',' | ForEach-Object { $_.Trim() }
    
    # Validate each entry
    foreach ($entry in $IPEntries) {
        if ([string]::IsNullOrEmpty($entry)) {
            My-Logger "Empty IP entry found (check for double commas or trailing comma)" -LogOnly
            return $false
        }
        
        if ($entry -match '-') {
            # This is an IP range
            $rangeParts = $entry -split '-'
            
            if ($rangeParts.Count -ne 2) {
                My-Logger "Invalid IP range format: $entry (should be IP1-IP2)" -LogOnly
                return $false
            }
            
            $startIP = $rangeParts[0].Trim()
            $endIP = $rangeParts[1].Trim()
            
            # Validate both IPs in the range using .NET IPAddress parsing
            try {
                $startIPObj = [System.Net.IPAddress]::Parse($startIP)
                if ($startIPObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    My-Logger "Invalid start IP in range (not IPv4): $startIP" -LogOnly
                    return $false
                }
            }
            catch {
                My-Logger "Invalid start IP in range: $startIP" -LogOnly
                return $false
            }
            
            try {
                $endIPObj = [System.Net.IPAddress]::Parse($endIP)
                if ($endIPObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    My-Logger "Invalid end IP in range (not IPv4): $endIP" -LogOnly
                    return $false
                }
            }
            catch {
                My-Logger "Invalid end IP in range: $endIP" -LogOnly
                return $false
            }
            
            # Validate that start IP is less than or equal to end IP
            try {
                $startBytes = $startIPObj.GetAddressBytes()
                $endBytes = $endIPObj.GetAddressBytes()
                
                # Reverse for little-endian systems
                if ([BitConverter]::IsLittleEndian) {
                    [Array]::Reverse($startBytes)
                    [Array]::Reverse($endBytes)
                }
                
                $startInt = [BitConverter]::ToUInt32($startBytes, 0)
                $endInt = [BitConverter]::ToUInt32($endBytes, 0)
                
                if ($startInt -gt $endInt) {
                    My-Logger "Invalid IP range order: $entry (start IP should be less than or equal to end IP)" -LogOnly
                    return $false
                }
            }
            catch {
                My-Logger "Error comparing IP range order: $entry" -LogOnly
                return $false
            }
        }
        else {
            # This is a single IP address
            try {
                $ipObj = [System.Net.IPAddress]::Parse($entry)
                # Check if it's IPv4
                if ($ipObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    My-Logger "Invalid IP address (not IPv4): $entry" -LogOnly
                    return $false
                }
            }
            catch {
                My-Logger "Invalid IP address: $entry" -LogOnly
                return $false
            }
        }
    }
    
    My-Logger "IP string validation successful: $IPString" -LogOnly
    return $true
}

function Test-IPAddressAvailability {
    param(
        [Parameter(Mandatory=$true)]
        [string]$NetworkCIDR,
        
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory=$true)]
        [string]$ExcludedIPs
    )
    
    # Helper function to convert IP to integer for comparison
    function ConvertTo-IPInteger {
        param([string]$IP)
        $octets = $IP.Split('.')
        return [int64]($octets[0]) * 16777216 + [int64]($octets[1]) * 65536 + [int64]($octets[2]) * 256 + [int64]($octets[3])
    }
    
    # Helper function to validate IP format
    function Test-IPFormat {
        param([string]$IP)
        return $IP -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    }
    
    # Parse CIDR notation
    if ($NetworkCIDR -notmatch '^(.+)/(\d+)$') {
        throw "Invalid CIDR format: $NetworkCIDR"
    }
    
    $networkIP = $matches[1]
    $subnetMask = [int]$matches[2]
    
    # Validate network IP format
    if (-not (Test-IPFormat $networkIP)) {
        throw "Invalid network IP format: $networkIP"
    }
    
    # Validate target IP format
    if (-not (Test-IPFormat $IPAddress)) {
        throw "Invalid IP address format: $IPAddress"
    }
    
    # Calculate network range
    $networkInt = ConvertTo-IPInteger $networkIP
    $targetInt = ConvertTo-IPInteger $IPAddress
    
    # Create subnet mask
    $maskBits = 0xFFFFFFFF -shl (32 - $subnetMask)
    $networkStart = $networkInt -band $maskBits
    $networkEnd = $networkStart -bor (-bnot $maskBits -band 0xFFFFFFFF)
    
    # Check if IP is within network range
    if ($targetInt -lt $networkStart -or $targetInt -gt $networkEnd) {
        My-Logger "IP $IPAddress is NOT within network $NetworkCIDR" -LogOnly
        return $false
    }
    
    My-Logger "IP $IPAddress is within network $NetworkCIDR" -LogOnly
    
    # Parse excluded IPs string
    $excludedParts = $ExcludedIPs.Split(',')
    
    foreach ($part in $excludedParts) {
        $part = $part.Trim()
        
        if ($part -match '^(.+)-(.+)$') {
            # Handle IP range
            $startIP = $matches[1].Trim()
            $endIP = $matches[2].Trim()
            
            if (-not (Test-IPFormat $startIP) -or -not (Test-IPFormat $endIP)) {
                My-Logger "Invalid IP range format: $part" -LogOnly
                continue
            }
            
            $startInt = ConvertTo-IPInteger $startIP
            $endInt = ConvertTo-IPInteger $endIP
            
            if ($targetInt -ge $startInt -and $targetInt -le $endInt) {
                My-Logger "IP $IPAddress is not available (found in the reserved range: $part)" -LogOnly
                return $false
            }
        }
        elseif (Test-IPFormat $part) {
            # Handle single IP
            if ($part -eq $IPAddress) {
                My-Logger "IP $IPAddress is not available (found in reserved list)" -LogOnly
                return $false
            }
        }
        else {
            My-Logger "Invalid IP or range format: $part" -LogOnly
        }
    }
    
    My-Logger "IP $IPAddress is AVAILABLE (not in reserved list)" -LogOnly
    return $true
}

function Test-NetworkCapacity {
    param(
        [Parameter(Mandatory=$true)]
        [string]$NetworkCIDR,
        
        [Parameter(Mandatory=$true)]
        [string]$ReservedIPs,
        
        [Parameter(Mandatory=$true)]
        [int]$MinimumRequired
    )
    
    # Function to convert IP to integer for calculations
    function ConvertTo-IPInteger {
        param([string]$IPAddress)
        $octets = $IPAddress.Split('.')
        return ([int]$octets[0] * 16777216) + ([int]$octets[1] * 65536) + ([int]$octets[2] * 256) + [int]$octets[3]
    }
    
    # Parse CIDR notation
    $cidrParts = $NetworkCIDR.Split('/')
    $subnetMask = [int]$cidrParts[1]
    
    # Calculate total IPs in the network
    $hostBits = 32 - $subnetMask
    $totalIPs = [math]::Pow(2, $hostBits)
    
    # Subtract network and broadcast addresses (typically not usable)
    $usableIPs = $totalIPs - 2
    
    # Parse reserved IPs and ranges
    $reservedCount = 0
    $reservedItems = $ReservedIPs -split ',' | ForEach-Object { $_.Trim() }
    
    foreach ($item in $reservedItems) {
        if ($item -match '^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$') {
            # Handle IP range
            $startIP = $matches[1]
            $endIP = $matches[2]
            
            $startInt = ConvertTo-IPInteger -IPAddress $startIP
            $endInt = ConvertTo-IPInteger -IPAddress $endIP
            
            $rangeCount = $endInt - $startInt + 1
            $reservedCount += $rangeCount
        }
        elseif ($item -match '^\d+\.\d+\.\d+\.\d+$') {
            # Handle single IP
            $reservedCount += 1
        }
        else {
            My-Logger "Invalid IP format: $item" -OnlyLog
        }
    }
    
    # Calculate available IPs
    $availableIPs = $usableIPs - $reservedCount
    
    # Return true if available IPs is greater than minimum required
    return $availableIPs -ge $MinimumRequired
}

function Test-NtpServer {
    param(
        [Parameter(Mandatory=$true)]
        [string]$NtpServer,
        
        [int]$TimeoutSeconds = 10
    )
    
    try {
        if ($IsWindows) {
            # Windows - use w32tm
            $result = & w32tm /stripchart /computer:$NtpServer /samples:1 /dataonly 2>&1
            
            if ($LASTEXITCODE -eq 0 -and $result -match "\d{2}:\d{2}:\d{2}") {
                return @{
                    Success = $true
                    Server = $NtpServer
                    Platform = "Windows"
                }
            } else {
                return @{
                    Success = $false
                    Server = $NtpServer
                    Platform = "Windows"
                    Error = $result -join "`n"
                }
            }
        }
        elseif ($IsMacOS -or $IsLinux) {
            # macOS/Linux - try ntpdate first, fallback to sntp
            $commands = @(
                @{ cmd = "ntpdate"; args = @("-q", $NtpServer) },
                @{ cmd = "sntp"; args = @("-t", $TimeoutSeconds, $NtpServer) }
            )
            
            foreach ($cmdInfo in $commands) {
                # Check if command exists
                $commandPath = Get-Command $cmdInfo.cmd -ErrorAction SilentlyContinue
                if (-not $commandPath) {
                    continue
                }
                
                try {
                    $result = & $cmdInfo.cmd @($cmdInfo.args) 2>&1
                    
                    if ($LASTEXITCODE -eq 0) {
                        return @{
                            Success = $true
                            Server = $NtpServer
                            Platform = if ($IsMacOS) { "macOS" } else { "Linux" }
                            Command = $cmdInfo.cmd
                        }
                    }
                } catch {
                    continue
                }
            }
            
            # If we get here, all commands failed
            return @{
                Success = $false
                Server = $NtpServer
                Platform = if ($IsMacOS) { "macOS" } else { "Linux" }
                Error = "Unable to query NTP server. Ensure ntpdate or sntp is installed."
            }
        }
        else {
            return @{
                Success = $false
                Server = $NtpServer
                Platform = "Unknown"
                Error = "Unsupported platform"
            }
        }
    }
    catch {
        return @{
            Success = $false
            Server = $NtpServer
            Error = $_.Exception.Message
        }
    }
}

function Test-DNSLookup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FQDN,
        
        [Parameter(Mandatory=$true)]
        [string]$DNSServer
    )
    
    try {
        # Execute nslookup command
        $nslookupResult = nslookup -timeout=1 $FQDN $DNSServer 2>&1

        # Convert result to string array for processing
        $resultLines = $nslookupResult | Out-String -Stream
        
        # Initialize variables
        $isValid = $false
        $ipAddresses = @()
        
        # Parse the nslookup output
        $foundName = $false
        foreach ($line in $resultLines) {
            # Check for successful resolution indicators
            if ($line -match "Name:\s+(.+)" -or $line -match "^$FQDN") {
                $isValid = $true
                $foundName = $true
            }
            
            # Extract IP addresses (IPv4 pattern) - only after finding the domain name
            if ($foundName -and $line -match "Address:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$") {
                $ipAddresses += $matches[1]
            }
            
            # Check for common error indicators
            if ($line -match "can't find|NXDOMAIN|No response|server failed|timed-out|no servers") {
                $isValid = $false
                break
            }
        }
        
        # Create return object
        $result = [PSCustomObject]@{
            FQDN = $FQDN
            DNSServer = $DNSServer
            IsValid = $isValid
            IPAddresses = $ipAddresses
            PrimaryIP = if ($ipAddresses.Count -gt 0) { $ipAddresses[0] } else { $null }
        }
        
        return $result
    }
    catch {
        # Handle any errors during execution
        $result = [PSCustomObject]@{
            FQDN = $FQDN
            DNSServer = $DNSServer
            IsValid = $false
            IPAddresses = @()
            PrimaryIP = $null
            Error = $_.Exception.Message
        }
        
        return $result
    }
}

function Test-Certificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CertPath,
        
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )
    
    # Check if file exists
    if (-not (Test-Path $CertPath)) {
        My-Logger "Certificate file not found: $CertPath" -LogOnly -level Error
        return $false
    }
    
    try {
        # Read the certificate file content
        $certContent = Get-Content $CertPath -Raw
        
        # Split certificates in the chain
        $certBlocks = @()
        $matches = [regex]::Matches($certContent, '-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        
        foreach ($match in $matches) {
            $certBlocks += $match.Value
        }
        
        if ($certBlocks.Count -eq 0) {
            My-Logger "No certificates found in the file" -LogOnly -level Error
            return $false
        }
        
        My-Logger "Found $($certBlocks.Count) certificate(s) in chain" -LogOnly
        
        # Parse each certificate
        $certificates = @()
        for ($i = 0; $i -lt $certBlocks.Count; $i++) {
            try {
                # Create temporary file for individual certificate
                $tempFile = [System.IO.Path]::GetTempFileName()
                $certBlocks[$i] | Out-File -FilePath $tempFile -Encoding ASCII
                
                # Load certificate
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tempFile)
                $certificates += $cert
                
                # Clean up temp file
                Remove-Item $tempFile -Force
            }
            catch {
                My-Logger "Failed to parse certificate $($i + 1): $_" -LogOnly -level Error
                return $false
            }
        }
        
        # Validation results
        $validationResults = @{
            KeyTypeRSA = $false
            CertOrder = $false
            CommonNameValid = $false
            SANValid = $false
            Details = @()
        }
        
        # 1. Validate key type is RSA (check first certificate - should be the leaf/wildcard cert)
        $leafCert = $certificates[0]
        if ($leafCert.PublicKey.Oid.FriendlyName -eq "RSA") {
            $validationResults.KeyTypeRSA = $true
            $validationResults.Details += "[PASS] Key type is RSA"
        } else {
            $validationResults.Details += "[FAIL] Key type is not RSA: $($leafCert.PublicKey.Oid.FriendlyName)"
        }
        
        # 2. Validate certificate order (wildcard, intermediate(s), CA)
        $orderValid = $true
        $orderDetails = @()
        
        for ($i = 0; $i -lt $certificates.Count; $i++) {
            $cert = $certificates[$i]
            $basicConstraints = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Basic Constraints" }
            
            if ($i -eq 0) {
                # First cert should be wildcard (leaf certificate)
                if ($cert.Subject -like "*CN=*$Domain*" -or $cert.Subject -like "*CN=*.*$Domain*") {
                    $orderDetails += "Certificate 1: Leaf/Wildcard certificate"
                } else {
                    $orderValid = $false
                    $orderDetails += "Certificate 1: Expected wildcard certificate, got: $($cert.Subject)"
                }
            } elseif ($i -eq $certificates.Count - 1) {
                # Last cert should be CA
                if ($basicConstraints -and $basicConstraints.CertificateAuthority) {
                    $orderDetails += "Certificate $($i + 1): Root CA certificate"
                } else {
                    $orderValid = $false
                    $orderDetails += "Certificate $($i + 1): Expected CA certificate, validation failed"
                }
            } else {
                # Middle certs should be intermediate CAs
                if ($basicConstraints -and $basicConstraints.CertificateAuthority) {
                    $orderDetails += "Certificate $($i + 1): Intermediate CA certificate"
                } else {
                    $orderValid = $false
                    $orderDetails += "Certificate $($i + 1): Expected intermediate CA certificate, validation failed"
                }
            }
        }
        
        $validationResults.CertOrder = $orderValid
        if ($orderValid) {
            $validationResults.Details += "[PASS] Certificate order is correct"
        } else {
            $validationResults.Details += "[FAIL] Certificate order is incorrect"
        }
        $validationResults.Details += $orderDetails
        
        # 3. Validate Common Name contains domain
        $commonName = ""
        if ($leafCert.Subject -match "CN=([^,]+)") {
            $commonName = $matches[1]
        }
        
        if ($commonName -like "*$Domain*") {
            $validationResults.CommonNameValid = $true
            $validationResults.Details += "[PASS] Common Name contains domain: $commonName"
        } else {
            $validationResults.Details += "[FAIL] Common Name does not contain domain '$Domain': $commonName"
        }
        
        # 4. Validate SAN entries
        $requiredSANs = @(
            "*.apps.$Domain",
            "*.sys.$Domain",
            "*.login.sys.$Domain",
            "*.uaa.sys.$Domain"
        )
        
        $sanExtension = $leafCert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
        $sanValid = $true
        $foundSANs = @()
        
        if ($sanExtension) {
            # Parse SAN extension
            $sanString = $sanExtension.Format($false)
            $sanEntries = $sanString -split ", " | ForEach-Object { $_.Replace("DNS Name=", "") }
            $foundSANs = $sanEntries
            
            foreach ($requiredSAN in $requiredSANs) {
                if ($sanEntries -contains $requiredSAN) {
                    $validationResults.Details += "[PASS] Found required SAN: $requiredSAN"
                } else {
                    $sanValid = $false
                    $validationResults.Details += "[FAIL] Missing required SAN: $requiredSAN"
                }
            }
        } else {
            $sanValid = $false
            $validationResults.Details += "[FAIL] No Subject Alternative Name extension found"
        }
        
        $validationResults.SANValid = $sanValid
        
        # Additional SAN information
        if ($foundSANs.Count -gt 0) {
            $validationResults.Details += "Found SAN entries: $($foundSANs -join ', ')"
        }
        
        # Overall validation result
        $overallValid = $validationResults.KeyTypeRSA -and 
                       $validationResults.CertOrder -and 
                       $validationResults.CommonNameValid -and 
                       $validationResults.SANValid
        
        # Output results
        My-Logger "=== Certificate Validation Results ===" -LogOnly
        foreach ($detail in $validationResults.Details) {
            if ($detail.StartsWith("[PASS]")) {
                My-Logger $detail -LogOnly
            } elseif ($detail.StartsWith("[FAIL]")) {
                My-Logger $detail -LogOnly
            } else {
                My-Logger $detail -LogOnly
            }
        }
        
        My-Logger "=== Summary ===" -LogOnly
        My-Logger "RSA Key Type: $(if ($validationResults.KeyTypeRSA) { 'PASS' } else { 'FAIL' })" -LogOnly
        My-Logger "Certificate Order: $(if ($validationResults.CertOrder) { 'PASS' } else { 'FAIL' })" -LogOnly
        My-Logger "Common Name: $(if ($validationResults.CommonNameValid) { 'PASS' } else { 'FAIL' })" -LogOnly
        My-Logger "SAN Validation: $(if ($validationResults.SANValid) { 'PASS' } else { 'FAIL' })" -LogOnly
        My-Logger "Overall Result: $(if ($overallValid) { 'PASS' } else { 'FAIL' })" -LogOnly
        
        return $overallValid
        
    }
    catch {
        My-Logger "Error validating certificate: $_" -LogOnly -level Error
        return $false
    }
}

function Calculate-TotalRequirements {
    param(
        [hashtable]$ProductRequirements
    )

    My-Logger "Calculating total install requirements to be used in validation tests" -LogOnly

    # Define which products to install
    $ProductsToInstall = @{
        "OpsMan" = $true
        "TPCF" = $true
        "TanzuAI" = $InstallTanzuAI
        "HealthWatch" = $InstallHealthwatch
        "Hub" = $InstallHub
    }

    # Initialize totals
    $TotalRequirements = @{
        IP = 0
        CPUGHz = 0
        MemoryGB = 0
        StorageGB = 0
    }

    # Calculate total requirements
    foreach ($product in $ProductsToInstall.Keys) {
        if ($ProductsToInstall[$product] -and $ProductRequirements.ContainsKey($product)) {
            $TotalRequirements.IP += $ProductRequirements[$product].IP
            $TotalRequirements.CPUGHz += $ProductRequirements[$product].CPUGHz
            $TotalRequirements.MemoryGB += $ProductRequirements[$product].MemoryGB
            $TotalRequirements.StorageGB += $ProductRequirements[$product].StorageGB
        }
    }

    My-Logger "Total Requirements Summary:" -LogOnly
    My-Logger "===========================" -LogOnly
    My-Logger "Total IP addresses needed: $($TotalRequirements.IP)" -LogOnly
    My-Logger "Total CPU needed: $($TotalRequirements.CPUGHz) GHz" -LogOnly
    My-Logger "Total Memory needed: $($TotalRequirements.MemoryGB) GB" -LogOnly
    My-Logger "Total Storage needed: $($TotalRequirements.StorageGB) GB" -LogOnly

    return $TotalRequirements
}

function Get-ClusterFreeResources {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ClusterName,
        
        [Parameter(Mandatory=$false)]
        [string]$vCenterServer,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential
    )
    
    try {
        # Get the cluster
        $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
        
        if (-not $cluster) {
            Write-Error "Cluster '$ClusterName' not found"
            return
        }
        
        # Get all hosts in the cluster
        $hosts = Get-VMHost -Location $cluster
        
        # Calculate total CPU resources
        $totalCpuMhz = ($hosts | Measure-Object -Property CpuTotalMhz -Sum).Sum
        
        # Calculate used CPU resources
        $usedCpuMhz = ($hosts | Measure-Object -Property CpuUsageMhz -Sum).Sum
        
        # Calculate free CPU
        $freeCpuMhz = $totalCpuMhz - $usedCpuMhz
        $freeCpuPercent = [math]::Round(($freeCpuMhz / $totalCpuMhz) * 100, 2)
        
        # Calculate total memory resources (in MB)
        $totalMemoryMB = ($hosts | Measure-Object -Property MemoryTotalMB -Sum).Sum
        
        # Calculate used memory resources (in MB)
        $usedMemoryMB = ($hosts | Measure-Object -Property MemoryUsageMB -Sum).Sum
        
        # Calculate free memory
        $freeMemoryMB = $totalMemoryMB - $usedMemoryMB
        $freeMemoryPercent = [math]::Round(($freeMemoryMB / $totalMemoryMB) * 100, 2)
        
        # Get additional cluster stats
        $totalCores = ($hosts | Measure-Object -Property NumCpu -Sum).Sum
        $totalHosts = $hosts.Count
        
        # Create results object
        $result = [PSCustomObject]@{
            ClusterName = $cluster.Name
            TotalHosts = $totalHosts
            TotalCores = $totalCores
            # CPU Statistics
            TotalCpuMhz = $totalCpuMhz
            UsedCpuMhz = $usedCpuMhz
            FreeCpuMhz = $freeCpuMhz
            FreeCpuPercent = $freeCpuPercent
            FreeCpuGhz = [math]::Round($freeCpuMhz / 1000, 2)
            # Memory Statistics
            TotalMemoryMB = $totalMemoryMB
            UsedMemoryMB = $usedMemoryMB
            FreeMemoryMB = $freeMemoryMB
            FreeMemoryPercent = $freeMemoryPercent
            FreeMemoryGB = [math]::Round($freeMemoryMB / 1024, 2)
            TotalMemoryGB = [math]::Round($totalMemoryMB / 1024, 2)
            UsedMemoryGB = [math]::Round($usedMemoryMB / 1024, 2)
        }
        
        return $result
        
    } catch {
        My-Logger "Error retrieving cluster information: $($_.Exception.Message)" -OnlyLog
    }
}

function Run-Test {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TestName,
        [Parameter(Mandatory=$true)]
        [scriptblock]$TestCode
    )
    
    My-Logger "Running test: $TestName" -LogOnly
    
    # Add test to order tracking array
    $script:TestOrder += $TestName
    
    try {
        $result = & $TestCode
        if ($result -eq $true) {
            $TestResults[$TestName] = @{
                Result = "PASS"
                Message = "Test passed successfully"
            }
            My-Logger "Test $TestName passed" -LogOnly
        } else {
            $TestResults[$TestName] = @{
                Result = "FAIL"
                Message = $result
            }
            My-Logger "Test $TestName failed: $result" -level Error -LogOnly
        }
    } catch {
        $TestResults[$TestName] = @{
            Result = "FAIL"
            Message = $_.Exception.Message
        }
        My-Logger "Test $TestName failed with exception: $($_.Exception.Message)" -level Error -LogOnly
        }
}

function Show-TestResults {
    My-Logger "======================================================"
    My-Logger "                INPUT VALIDATION RESULTS              "
    My-Logger "======================================================"
    
    $passCount = 0
    $failCount = 0
    
    foreach ($test in $TestResults.Keys) {
        $result = $TestResults[$test]
        $status = $result.Result
        $message = $result.Message
        
        if ($status -eq "PASS") {
            My-Logger "[PASS] $test"
            $passCount++
        } else {
            My-Logger "[FAIL] $message" -color Red
            $failCount++
        }
    }
    
    My-Logger "======================================================"
    My-Logger "Summary: $passCount tests passed, $failCount tests failed"
    My-Logger "======================================================"
    
    # Return overall status
    return ($failCount -eq 0)
}

function Generate-SSHKey {
    param (
        [string]$KeyType = "rsa",
        [int]$KeySize = 4096,
        [string]$OutputPath = "$HOME\.ssh",
        [string]$KeyFileName = "id_rsa_tanzu",
        [string]$Comment = "ssh key for Tanzu Operations Manager",
        [ref]$PublicKeyContent = $null,
        [switch]$Force = $false
    )

    # Create .ssh directory if it doesn't exist
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $KeyFilePath = Join-Path -Path $OutputPath -ChildPath $KeyFileName
    $PublicKeyPath = "$KeyFilePath.pub"

    # Check if key already exists
    if ((Test-Path $KeyFilePath) -or (Test-Path $PublicKeyPath)) {
        if (-not $Force) {
            # If public key exists, load it into the provided variable
            if (Test-Path $PublicKeyPath) {
                if ($null -ne $PublicKeyContent) {
                    $PublicKeyContent.Value = Get-Content -Path $PublicKeyPath -Raw
                }
            } else {
                My-Logger "[Error] SSH public key file not found, but private key exists." -level Error -color Red
            }
            return $false
        } else {
            # Overwrite existing SSH key
        }
    }

    # Check if ssh-keygen is available
    try {
        $null = Get-Command ssh-keygen -ErrorAction Stop
        
        # Generate the SSH key
        $process = Start-Process -FilePath "ssh-keygen" -ArgumentList "-q", "-t", $KeyType, "-b", $KeySize, "-f", "`"$KeyFilePath`"", "-C", "`"$Comment`"", "-N", "`"`"" -NoNewWindow -PassThru -Wait

        if ($process.ExitCode -eq 0) {
            # Save the public key content to the provided variable
            if ($PublicKeyContent -ne $null) {
                $PublicKeyContent.Value = Get-Content -Path "$KeyFilePath.pub" -Raw
            }
            return $true
        } else {
            My-Logger "[Error] Failed to generate SSH key. Exit code: $($process.ExitCode)"  -level Error -color Red
            return $false
        }
    }
    catch {
        # ssh-keygen isn't available
        My-Logger "[Error] ssh-keygen not found. You need to install OpenSSH." -level Error -color Red
        return $false
    }
}

if($confirmDeployment -eq 1) {
    Write-Host -ForegroundColor Magenta "`nPlease confirm the following configuration will be deployed:`n"

    Write-Host -ForegroundColor Yellow "---- Installer required files ---- "
    Write-Host -NoNewline -ForegroundColor Green "Tanzu Operations Manager OVA path: "
    Write-Host -ForegroundColor White $OpsManOVA
    Write-Host -NoNewline -ForegroundColor Green "Tanzu Platform for Cloud Foundry tile path: "
    Write-Host -ForegroundColor White $TPCFTile
    Write-Host -NoNewline -ForegroundColor Green "VMware Postgres tile path: "
    Write-Host -ForegroundColor White $PostgresTile
    Write-Host -NoNewline -ForegroundColor Green "Tanzu GenAI tile path: "
    Write-Host -ForegroundColor White $GenAITile
    if ($InstallHealthwatch) {
        Write-Host -NoNewline -ForegroundColor Green "Healthwatch tile path: "
        Write-Host -ForegroundColor White $HealthwatchTile
        Write-Host -NoNewline -ForegroundColor Green "Healthwatch Exporter tile path: "
        Write-Host -ForegroundColor White $HealthwatchExporterTile
    }
    if ($InstallHub) {
        Write-Host -NoNewline -ForegroundColor Green "Tanzu Hub tile path: "
        Write-Host -ForegroundColor White $HubTile
    }
    Write-Host -NoNewline -ForegroundColor Green "OM CLI path: "
    Write-Host -ForegroundColor White $OMCLI

    Write-Host -ForegroundColor Yellow "`n---- vCenter Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "vCenter Server: "
    Write-Host -ForegroundColor White $VIServer
    Write-Host -NoNewline -ForegroundColor Green "Datacenter: "
    Write-Host -ForegroundColor White $VMDatacenter
    Write-Host -NoNewline -ForegroundColor Green "Datastore: "
    Write-Host -ForegroundColor White $VMDatastore
    Write-Host -NoNewline -ForegroundColor Green "Disk type: "
    Write-Host -ForegroundColor White "Thin"
    Write-Host -NoNewline -ForegroundColor Green "VMs folder: "
    Write-Host -ForegroundColor White $BOSHvCenterVMFolder
    Write-Host -NoNewline -ForegroundColor Green "Templates folder: "
    Write-Host -ForegroundColor White $BOSHvCenterTemplateFolder
    Write-Host -NoNewline -ForegroundColor Green "Disks folder: "
    Write-Host -ForegroundColor White $BOSHvCenterDiskFolder

    Write-Host -ForegroundColor Yellow "`n---- Tanzu Operations Manager Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "IP Address: "
    Write-Host -ForegroundColor White $OpsManagerIPAddress
    Write-Host -NoNewline -ForegroundColor Green "FQDN: "
    Write-Host -ForegroundColor White $OpsManagerFQDN
    Write-Host -NoNewline -ForegroundColor Green "Username: "
    Write-Host -ForegroundColor White $OpsManagerAdminUsername
    Write-Host -NoNewline -ForegroundColor Green "Password: "
    Write-Host -ForegroundColor White $OpsManagerAdminPassword
    Write-Host -NoNewline -ForegroundColor Green "Decryption Password: "
    Write-Host -ForegroundColor White $OpsManagerDecryptionPassword

    Write-Host -ForegroundColor Yellow "`n---- BOSH Director Configuration ----"
    Write-Host -ForegroundColor Green "AZ Config"
    Write-Host -NoNewline -ForegroundColor Green "AZ Name: "
    Write-Host -ForegroundColor White $BOSHAZAssignment
    Write-Host -NoNewline -ForegroundColor Green "AZ Cluster: "
    Write-Host -ForegroundColor White $($BOSHAZ[$BOSHAZAssignment].cluster)
    Write-Host -NoNewline -ForegroundColor Green "AZ Resource Pool: "
    Write-Host -ForegroundColor White $($BOSHAZ[$BOSHAZAssignment].resource_pool)

    Write-Host -ForegroundColor Green "`nNetwork Config"
    Write-Host -NoNewline -ForegroundColor Green "Network Name: "
    Write-Host -ForegroundColor White $BOSHNetworkAssignment
    Write-Host -NoNewline -ForegroundColor Green "Network Portgroup: "
    Write-Host -ForegroundColor White $($BOSHNetwork[$BOSHNetworkAssignment].portgroupname) 
    Write-Host -NoNewline -ForegroundColor Green "Network CIDR: "
    Write-Host -ForegroundColor White $($BOSHNetwork[$BOSHNetworkAssignment].cidr)
    Write-Host -NoNewline -ForegroundColor Green "Network Gateway: "
    Write-Host -ForegroundColor White $($BOSHNetwork[$BOSHNetworkAssignment].gateway)
    Write-Host -NoNewline -ForegroundColor Green "Reserved IP Range: "
    Write-Host -ForegroundColor White $($BOSHNetwork[$BOSHNetworkAssignment].reserved_range)
    Write-Host -NoNewline -ForegroundColor Green "DNS: "
    Write-Host -ForegroundColor White $($BOSHNetwork[$BOSHNetworkAssignment].dns)
    Write-Host -NoNewline -ForegroundColor Green "NTP: "
    Write-Host -ForegroundColor White $VMNTP

    Write-Host -NoNewline -ForegroundColor Green "`nEnable human readable names: "
    Write-Host -ForegroundColor White "True"
    Write-Host -NoNewline -ForegroundColor Green "ICMP checks enabled: "
    Write-Host -ForegroundColor White "True"
    Write-Host -NoNewline -ForegroundColor Green "Include Tanzu Ops Manager Root CA in Trusted Certs: "
    Write-Host -ForegroundColor White "True"

    Write-Host -ForegroundColor Yellow "`n---- Tanzu Platform for Cloud Foundry Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "AZ: "
    Write-Host -ForegroundColor White $BOSHAZAssignment
    Write-Host -NoNewline -ForegroundColor Green "Network: "
    Write-Host -ForegroundColor White $BOSHNetworkAssignment
    Write-Host -NoNewline -ForegroundColor Green "System Domain: "
    Write-Host -ForegroundColor White "sys.$TPCFDomain"
    Write-Host -NoNewline -ForegroundColor Green "Apps Domain: "
    Write-Host -ForegroundColor White "apps.$TPCFDomain"
    Write-Host -NoNewline -ForegroundColor Green "GoRouter IP: "
    Write-Host -ForegroundColor White $TPCFGoRouter
    if ($userProvidedCert) {
        Write-Host -NoNewline -ForegroundColor Green "GoRouter wildcard cert path: "
        Write-Host -ForegroundColor White $CertPath
        Write-Host -NoNewline -ForegroundColor Green "GoRouter wildcard private key path: "
        Write-Host -ForegroundColor White $KeyPath
    } else {
        Write-Host -NoNewline -ForegroundColor Green "GoRouter wildcard cert SAN: "
        $domainlist = "*.apps.$TPCFDomain,*.login.sys.$TPCFDomain,*.uaa.sys.$TPCFDomain,*.sys.$TPCFDomain,*.$TPCFDomain"    
        Write-Host -ForegroundColor White $domainlist
    }

    if ($InstallTanzuAI) {
        Write-Host -ForegroundColor Yellow "`n---- Tanzu AI Solutions Configuration ----"
        Write-Host -NoNewline -ForegroundColor Green "AZ: "
        Write-Host -ForegroundColor White $BOSHAZAssignment
        Write-Host -NoNewline -ForegroundColor Green "Network: "
        Write-Host -ForegroundColor White $BOSHNetworkAssignment
        Write-Host -NoNewline -ForegroundColor Green "Ollama embedding model: "
        Write-Host -ForegroundColor White $OllamaEmbedModel
        if ($ToolsModel) {
            Write-Host -NoNewline -ForegroundColor Green "Ollama chat & tools model: "
            Write-Host -ForegroundColor White $OllamaChatToolsModel
        } else {
            Write-Host -NoNewline -ForegroundColor Green "Ollama chat model: "
            Write-Host -ForegroundColor White $OllamaChatModel
        }
    }

    if ($InstallHealthwatch) {
        Write-Host -ForegroundColor Yellow "`n---- Healthwatch Configuration ----"
        Write-Host -NoNewline -ForegroundColor Green "AZ: "
        Write-Host -ForegroundColor White $BOSHAZAssignment
        Write-Host -NoNewline -ForegroundColor Green "Network: "
        Write-Host -ForegroundColor White $BOSHNetworkAssignment
    }

    if ($InstallHub) {
        Write-Host -ForegroundColor Yellow "`n---- Tanzu Hub Configuration ----"
        Write-Host -NoNewline -ForegroundColor Green "AZ: "
        Write-Host -ForegroundColor White $BOSHAZAssignment
        Write-Host -NoNewline -ForegroundColor Green "Network: "
        Write-Host -ForegroundColor White $BOSHNetworkAssignment
        Write-Host -NoNewline -ForegroundColor Green "FQDN: "
        Write-Host -ForegroundColor White $HubFQDN
    }

    Write-Host -ForegroundColor Magenta "`nWould you like to proceed with this deployment?`n"
    $answer = Read-Host -Prompt "Do you accept (Y or N)"
    if($answer -ne "Y" -or $answer -ne "y") {
        exit
    }
}

if($preCheck -eq 1) {
    My-Logger "Validating inputs..."

    # Create an ordered hashtable to store test results in sequence
    $TestResults = [ordered]@{}
    # Create an array to track the order of tests
    $TestOrder = @()

    #Calculate total resource requirments to be used in several tests 
    $Requirements = Calculate-TotalRequirements -ProductRequirements $ProductRequirements

    # Verify if OM CLI exists
    My-Logger "Validating if OM CLI exists at $OMCLI" -LogOnly
    Run-Test -TestName "Files: OM CLI exists" -TestCode {
        if (Test-Path $OMCLI) { return $true } else { return "Files: Unable to find $OMCLI" }
    }

    # Verify if Tanzu Operations Manager OVA exists
    My-Logger "Validating if Tanzu Operations Manager OVA file exists at $OpsManOVA" -LogOnly
    Run-Test -TestName "Files: Tanzu Operations Manager OVA file exists" -TestCode {
        if (Test-Path $OpsManOVA) { return $true } else { return "Files: Unable to find $OpsManOVA" }
    }

    # Verify if Tanzu Platform for Cloud Foundry tile file exists
    My-Logger "Validating if Tanzu Platform for Cloud Foundry tile file exists at $TPCFTile" -LogOnly
    Run-Test -TestName "Files: Tanzu Platform for Cloud Foundry tile file exists" -TestCode {
        if (Test-Path $TPCFTile) { return $true } else { return "Files: Unable to find $TPCFTile" }
    }

    # Verify if VMware Postgres tile file exists
    if ($InstallTanzuAI) {
        My-Logger "Validating if VMware Postgres tile file exists at $PostgresTile" -LogOnly
        Run-Test -TestName "Files: VMware Postgres tile file exists" -TestCode {
            if (Test-Path $PostgresTile) { return $true } else { return "Files: Unable to find $PostgresTile" }
        }
    }

    # Verify if Tanzu GenAI tile file exists
    if ($InstallTanzuAI) {
        My-Logger "Validating if Tanzu GenAI tile file exists at $GenAITile" -LogOnly
        Run-Test -TestName "Files: Tanzu GenAI tile file exists" -TestCode {
            if (Test-Path $GenAITile) { return $true } else { return "Files: Unable to find $GenAITile" }
        }
    }

    # Verify if Healthwatch tile file exists
    if ($InstallHealthwatch) {
        My-Logger "Validating if Healthwatch tile file exists at $HealthwatchTile" -LogOnly
        Run-Test -TestName "Files: Healthwatch tile file exists" -TestCode {
            if (Test-Path $HealthwatchTile) { return $true } else { return "Files: Unable to find $HealthwatchTile" }
        }
    }

    # Verify if Healthwatch Exporter tile file exists
    if ($InstallHealthwatch -eq $true) {
        My-Logger "Validating if Healthwatch Exporter tile file exists at $HealthwatchExporterTile" -LogOnly
        Run-Test -TestName "Files: Healthwatch Exporter tile file exists" -TestCode {
            if (Test-Path $HealthwatchExporterTile) { return $true } else { return "Files: Unable to find $HealthwatchExporterTile" }
        }
    }

    # Verify if Tanzu Hub tile file exists
    if ($InstallHub -eq $true) {
        My-Logger "Validating if Tanzu Hub tile file exists at $HubTile" -LogOnly
        Run-Test -TestName "Files: Tanzu Hub tile file exists" -TestCode {
            if (Test-Path $HubTile) { return $true } else { return "Files: Unable to find $HubTile" }
        }
    }

    # Verify target network connectivity
    My-Logger "Validating Gateway $VMGateway connectivity" -LogOnly
    Run-Test -TestName "Network: Gateway connectivity" -TestCode {
        $Global:ProgressPreference = 'SilentlyContinue'
        try {
            $gateway = Test-Connection -ComputerName $VMGateway -Count 1 -Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($gateway) {
                return $true
            } else {
                return "Network: Cannot reach target network gateway $VMGateway"
            }
        } catch {
            return "Error testing connection to gateway $VMGateway. Error: $($_.Exception.Message)"
        }
    }

    # Verify connectivity to vCenter
    My-Logger "Validating vCenter connectivity https://$VIServer" -LogOnly
    Run-Test -TestName "Network: vCenter connectivity" -TestCode {
        try {
            $vcenterResult = Invoke-WebRequest -Uri https://$VIServer -SkipCertificateCheck -Method GET
            if ($vcenterResult.StatusCode -eq 200) {
                return $true
            } else {
                return "Network: Cannot reach vCenter $VIServer. Status code: $($vcenterResult.StatusCode)"
            }
        } catch {
            return "Cannot reach vCenter $VIServer. Error: $($_.Exception.Message)"
        }
    }

    # Verify DNS server connectivity
    My-Logger "Validating DNS server $VMDNS connectivity" -LogOnly
    Run-Test -TestName "Network: DNS server connectivity" -TestCode {
        try {
            $dnsResult = Test-Connection -ComputerName $VMDNS -Count 1 -Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($dnsResult) {
                return $true
            } else {
                return "Network: Cannot reach DNS server $VMDNS"
            }
        } catch {
            return "Error testing connection to DNS server $VMDNS. Error: $($_.Exception.Message)"
        }
    }

    # Verify NTP server connectivity
    My-Logger "Validating NTP server $VMNTP connectivity" -LogOnly
    Run-Test -TestName "Network: NTP server connectivity" -TestCode {
        try {
            $ntpResult = Test-Connection -ComputerName $VMNTP -Count 1 -Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($ntpResult) {
                return $true
            } else {
                return "Network: Cannot reach NTP server $VMNTP"
            }
        } catch {
            return "Error testing connection to NTP server $VMNTP. Error: $($_.Exception.Message)"
        }
    }

    # Verify NTP server responses
    My-Logger "Validating NTP server $VMNTP query response" -LogOnly
    Run-Test -TestName "Network: NTP server query response" -TestCode {
        try {
            $ntpqResult = Test-NtpServer -NtpServer $VMNTP
            if ($ntpqResult.Success -eq $true) {
                return $true
            } else {
                return "Network: NTP server $VMNTP did not provide a valid response when queried"
            }
        } catch {
            return "Error querying NTP server $VMNTP. Error: $($_.Exception.Message)"
        }
    }

    # verify reserved range format is valid
    My-Logger "Validating BOSH reserved range is in a valid format" -LogOnly
    Run-Test -TestName "Network: Reserved range syntax" -TestCode {
        try {
            $reservedrangeResult = Test-IPAddressString -IPString $BOSHNetworkReservedRange
            if ($reservedrangeResult -eq $true) {
                return $true
            } else {
                return "Network: The reserved range $BOSHNetworkReservedRange is not in a valid format"
            }
        } catch {
            return "Error verifying the reserved range format $BOSHNetworkReservedRange. Error: $($_.Exception.Message)"
        }
    }

    # verify have enough IPs available
    My-Logger "Validating if have at least $Requirements.IP IPs available" -LogOnly
    Run-Test -TestName "Network: Network capacity" -TestCode {
        try {
            $capacityResult = Test-NetworkCapacity -NetworkCIDR $VMNetworkCIDR -ReservedIPs $BOSHNetworkReservedRange -MinimumRequired $Requirements.IP
            if ($capacityResult -eq $true) {
                return $true
            } else {
                return "Network: There are not enough free IP addresses"
            }
        } catch {
            return "Error verifying if there are enough free IP addresses. Error: $($_.Exception.Message)"
        }
    }

    # verify usable IPs are available
    My-Logger "Validating usable IPs are available" -LogOnly
    Run-Test -TestName "Network: Usable IPs are available" -TestCode {
        try {
            $pingsResult = Ping-NetworkExcluding -NetworkCIDR $VMNetworkCIDR -ExcludeList $BOSHNetworkReservedRange
            $reachableCount = ($pingsResult | Where-Object { $_.Status -eq "Reachable" }).Count
            if ($reachableCount -eq 0) {
                return $true
            } else {
                return "Network: Not all usable IPs are available"
            }
        } catch {
            return "Error validating usable IPs are available. Error: $($_.Exception.Message)"
        }
    }

    # verify Ops Man IP is in the reserved range
    My-Logger "Validating the Tanzu Operations Manager IP $OpsManagerIPAddress is in the reserved range $BOSHNetworkReservedRange" -LogOnly
    Run-Test -TestName "Network: Tanzu Operations Manager IP is in the reserved range" -TestCode {
        try {
            $opsmanResult = Test-IPAddressAvailability -NetworkCIDR $VMNetworkCIDR -IPAddress $OpsManagerIPAddress -ExcludedIPs $BOSHNetworkReservedRange
            if ($opsmanResult -ne $true) {
                return $true
            } else {
                return "Network: Tanzu Operations Manager IP $OpsManagerIPAddress is not in the reserved range $BOSHNetworkReservedRange"
            }
        } catch {
            return "Error verifying if Tanzu Operations Manager IP $OpsManagerIPAddress is in the reserved range $BOSHNetworkReservedRange. Error: $($_.Exception.Message)"
        }
    }

    # verify the GoRouter IP is not in the reserved range
    My-Logger "Validating the GoRouter IP $TPCFGoRouter is not in the reserved range $BOSHNetworkReservedRange" -LogOnly
    Run-Test -TestName "Network: GoRouter is not in the reserved range" -TestCode {
        try {
            $gorouterResult = Test-IPAddressAvailability -NetworkCIDR $VMNetworkCIDR -IPAddress $TPCFGoRouter -ExcludedIPs $BOSHNetworkReservedRange
            if ($gorouterResult -eq $true) {
                return $true
            } else {
                return "Network: GoRouter IP $TPCFGoRouter is in the reserved range $BOSHNetworkReservedRange"
            }
        } catch {
            return "Error verifying if GoRouter IP $TPCFGoRouter is not in the reserved range $BOSHNetworkReservedRange. Error: $($_.Exception.Message)"
        }
    }

    # Verify Ops Man IP is available
    My-Logger "Validating if Tanzu Operations Manager IP $OpsManagerIPAddress is available" -LogOnly
    Run-Test -TestName "Network: Tanzu Operations Manager IP available" -TestCode {
        try {
            $ipResult = Test-Connection -ComputerName $OpsManagerIPAddress -Count 1 -Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($ipResult) {
                return "Network: Tanzu Operations Manager IP address $OpsManagerIPAddress is already in use"
            } else {
                return $true # IP is available if not reachable
            }
        } catch {
            return $true # IP is available if connection fails
        }
    }

    # Verify GoRouter IP is available
    My-Logger "Validating if GoRouter IP $TPCFGoRouter is available" -LogOnly
    Run-Test -TestName "Network: GoRouter IP available" -TestCode {
        try {
            $ipResult = Test-Connection -ComputerName $TPCFGoRouter -Count 1 -Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($ipResult) {
                return "Network: GoRouter IP address $TPCFGoRouter is already in use"
            } else {
                return $true # IP is available if not reachable
            }
        } catch {
            return $true # IP is available if connection fails
        }
    }

    # Verify Ops Man DNS
    My-Logger "Validating Tanzu Operations Manager DNS entry $OpsManagerFQDN" -LogOnly
    Run-Test -TestName "Network: Tanzu Operations Manager DNS entry" -TestCode {
        try {
            $dnsResult = Test-DNSLookup -FQDN $OpsManagerFQDN -DNSServer $VMDNS
            if ($dnsResult.IsValid -eq $true) {
                return $true
            } else {
                return "Network: DNS entry for $OpsManagerFQDN not found"
            }
        } catch {
            return "Error resolving DNS for $OpsManagerFQDN. Error: $($_.Exception.Message)"
        }
    } 

    # Verify wildcard apps domain DNS
    My-Logger "Validating wildcard apps domain DNS entry *.apps.$TPCFDomain" -LogOnly
    Run-Test -TestName "Network: Wildcard apps domain DNS entry" -TestCode {
        try {
            $dnsResult = Test-DNSLookup -FQDN "test.apps.$TPCFDomain" -DNSServer $VMDNS
            if ($dnsResult.IsValid -eq $true) {
                return $true
            } else {
                return "Network: No record found for apps wildcard domain *.apps.$TPCFDomain on DNS server $VMDNS"
            }
        } catch {
            return "Error resolving DNS for test.apps.$TPCFDomain. Error: $($_.Exception.Message)"
        }
    }

    # Verify wildcard system domain
    My-Logger "Validating wildcard system domain DNS entry *.sys.$TPCFDomain" -LogOnly
    Run-Test -TestName "Network: Wildcard system domain DNS entry" -TestCode {
        try {
            $dnsResult = Test-DNSLookup -FQDN "test.sys.$TPCFDomain" -DNSServer $VMDNS
            if ($dnsResult.IsValid -eq $true) {
                return $true
            } else {
                return "Network: No record found for system wildcard domain *.sys.$TPCFDomain on DNS server $VMDNS"
            }
        } catch {
            return "Error resolving DNS for test.sys.$TPCFDomain. Error: $($_.Exception.Message)"
        }
    }

    # Verify if wildcard apps domain resolves to GoRouter IP
    My-Logger "Validating if wildcard apps domain *.apps.$TPCFDomain resolves to GoRouter IP $TPCFGoRouter" -LogOnly
    Run-Test -TestName "Network: Wildcard apps domain resolves to GoRouter IP" -TestCode {
        try {
            $dnsResult = Test-DNSLookup -FQDN "test.apps.$TPCFDomain" -DNSServer $VMDNS
            if ($dnsResult.PrimaryIP -eq $TPCFGoRouter) {
                return $true
            } else {
                return "Network: Wildcard apps domain $TPCFDomain resolves to $($dnsResult.PrimaryIP) instead of GoRouter IP $TPCFGoRouter"
            }
        } catch {
            return "Error checking DNS resolution for test.apps.$TPCFDomain. Error: $($_.Exception.Message)"
        }
    }

    # Verify if wildcard system domain resolves to GoRouter IP
    My-Logger "Validating if wildcard system domain *.sys.$TPCFDomain resolves to GoRouter IP $TPCFGoRouter" -LogOnly
    Run-Test -TestName "Network: Wildcard system domain resolves to GoRouter IP" -TestCode {
        try {
            $dnsResult = Test-DNSLookup -FQDN "test.sys.$TPCFDomain" -DNSServer $VMDNS
            if ($dnsResult.PrimaryIP -eq $TPCFGoRouter) {
                return $true
            } else {
                return "Network: Wildcard system domain $TPCFDomain resolves to $($dnsResult.PrimaryIP) instead of GoRouter IP $TPCFGoRouter"
            }
        } catch {
            return "Error checking DNS resolution for test.sys.$TPCFDomain. Error: $($_.Exception.Message)"
        }
    }

    # Verify connectivity to ollama.com
    My-Logger "Validating ollama.com connectivity " -LogOnly
    Run-Test -TestName "Network: ollama.com connectivity" -TestCode {
        try {
            $ollamaResult = Invoke-WebRequest -Uri https://ollama.com -Method GET
            if ($ollamaResult.StatusCode -eq 200) {
                return $true
            } else {
                return "Network: Cannot reach ollama.com. Status code: $($vcenterResult.StatusCode)"
            }
        } catch {
            return "Cannot reach ollama.com. Error: $($_.Exception.Message)"
        }
    }

    if ($userProvidedCert){
        # Verify cert file exists
        My-Logger "Validating if cert file exists at $CertPath" -LogOnly
        Run-Test -TestName "Certs: cert file exists" -TestCode {
            if (Test-Path $CertPath) { return $true } else { return "Files: Unable to find $CertPath" }
        }
    
        # Verify private key file exists
        My-Logger "Validating if private key file exists at $KeyPath" -LogOnly
        Run-Test -TestName "Certs: private key file exists" -TestCode {
            if (Test-Path $KeyPath) { return $true } else { return "Files: Unable to find $KeyPath" }
        }
        
        # Verify cert is valid
        My-Logger "Validating if apps and system wildcard certificate is valid" -LogOnly
        Run-Test -TestName "Certs: cert is valid" -TestCode {
            try {
                $certResult = Test-Certificate -CertPath $CertPath -Domain $TPCFDomain
                if ($certResult) {
                    return $true
                } else {
                    return "Certs: apps and system wildcard certificate is not valid"
                }
            } catch {
                return "Cannot validate certificate. Error: $($_.Exception.Message)"
            }
        }
    }

    # Verify vCenter credentials
    My-Logger "Validating vCenter credentials; server:$VIServer User:$VIUsername Password:$VIPassword" -LogOnly
    Run-Test -TestName "vSphere: vCenter credentials" -TestCode {
        try {
            $Global:ProgressPreference = 'SilentlyContinue'
            $viConnection = Connect-VIServer $VIServer -User $VIUsername -Password $VIPassword -Force -WarningAction SilentlyContinue -ErrorAction Stop
            if ($viConnection) {
                $script:viConnectionObject = $viConnection # Store for later use
                return $true
            } else {
                return "vSphere: Cannot log into $VIServer"
            }
        } catch {
            return "Cannot log into $VIServer. Error: $($_.Exception.Message)"
        }
    }

    # Verify required vSphere API permissions
    My-Logger "Validating if user $VIUsername has required vSphere API permissions " -LogOnly
    # reformat from user@domain to domain\user principal format
    $parts = $VIUsername.Split('@')
    $username = $parts[0]
    $domain = $parts[1]
    $userPrincipal = "$domain\$username"
    # check if user is found as a Principal. Need to add logic to handle if the users group is added as the principal, not the user directly. SSO module requires admin rights which the installer may not have.
    $checkUser = Get-VIPermission | Where-Object { $_.Principal -eq $userPrincipal }
    if ($checkUser) {
        My-Logger "User $userPrincipal is a principal" -LogOnly
        Run-Test -TestName "vSphere: API permissions" -TestCode {
            try {
                $vcResult = Test-UserPrivileges -Username $VIUsername -EntityName $VIServer -EntityType "vCenter" -RequiredPrivileges $requiredVcenterPrivileges
                $dcResult = Test-UserPrivileges -Username $VIUsername -EntityName $VMDatacenter -EntityType "Datacenter" -RequiredPrivileges $requiredDatacenterPrivileges
                if ($vcResult.HasAllRequiredPrivileges -and $dcResult.HasAllRequiredPrivileges){
                    return $true
                } else {
                    return "vSphere: User $VIUsername does not have all the required vSphere API permissions"
                }
            } catch {
                return "Error verifying required permissions for user $VIUsername. Error: $($_.Exception.Message)"
            }
        }
    }

    # Verify datacenter object
    My-Logger "Validating if DataCenter $VMDatacenter exists" -LogOnly
    Run-Test -TestName "vSphere: Datacenter validation" -TestCode {
        try {
            if ($script:viConnectionObject) {
                $datacenterResult = Get-Datacenter -Name $VMDatacenter -ErrorAction Stop
                if ($datacenterResult) {
                    return $true
                } else {
                    return "vSphere: Datacenter $VMDatacenter not found"
                }
            } else {
                return "vCenter connection not established"
            }
        } catch {
            return "Error finding datacenter $VMDatacenter. Error: $($_.Exception.Message)"
        }
    }

    # Verify cluster object
    My-Logger "Validating if Cluster $VMCluster exists" -LogOnly
    Run-Test -TestName "vSphere: Cluster validation" -TestCode {
        try {
            if ($script:viConnectionObject) {
                $clusterResult = Get-Cluster -Name $VMCluster -ErrorAction Stop
                if ($clusterResult) {
                    return $true
                } else {
                    return "vSphere: Cluster $VMCluster not found"
                }
            } else {
                return "vCenter connection not established"
            }
        } catch {
            return "Error finding cluster $VMCluster. Error: $($_.Exception.Message)"
        }
    }

    # Verify resource pool object
    My-Logger "Validating if Resource Pool $VMResourcePool exists" -LogOnly
    Run-Test -TestName "vSphere: Resource Pool validation" -TestCode {
        try {
            if ($script:viConnectionObject) {
                $rpResult = Get-ResourcePool -Name $VMResourcePool -ErrorAction Stop
                if ($rpResult) {
                    return $true
                } else {
                    return "vSphere: Resource Pool $VMResourcePool not found"
                }
            } else {
                return "vCenter connection not established"
            }
        } catch {
            return "Error finding resource pool $VMResourcePool. Error: $($_.Exception.Message)"
        }
    }

    # Verify datastore object
    My-Logger "Validating if Datastore $VMDatastore exists" -LogOnly
    Run-Test -TestName "vSphere: Datastore validation" -TestCode {
        try {
            if ($script:viConnectionObject) {
                $datastoreResult = Get-DataStore -Name $VMDatastore -ErrorAction Stop
                if ($datastoreResult) {
                    return $true
                } else {
                    return "vSphere: Datastore $VMDatastore not found"
                }
            } else {
                return "vSphere: vCenter connection not established"
            }
        } catch {
            return "Error finding datastore $VMDatastore. Error: $($_.Exception.Message)"
        }
    }

    # Verify portgroup object
    My-Logger "Validating if Portgroup $VMNetwork exists" -LogOnly
    Run-Test -TestName "vSphere: Network Portgroup validation" -TestCode {
        try {
            if ($script:viConnectionObject) {
                if ($VirtualSwitchType -eq "VSS") {
                    $networkResult = Get-VirtualPortGroup -Server $script:viConnectionObject -Name $VMNetwork -ErrorAction Stop | Select-Object -First 1
                    if ($networkResult) {
                        return $true
                    } else {
                        return "vSphere: Cannot find portgroup $VMNetwork"
                    }
                } else {
                    $networkResult = Get-VDPortgroup -Server $script:viConnectionObject -Name $VMNetwork -ErrorAction Stop | Select-Object -First 1
                    if ($networkResult) {
                        return $true
                    } else {
                        return "vSphere: Cannot find portgroup $VMNetwork"
                    }
                }
            } else {
                return "vSphere: vCenter connection not established"
            }
        } catch {
            return "Error finding portgroup $VMNetwork. Error: $($_.Exception.Message)"
        }
    }

    # Verify if have enough CPU resources available
    My-Logger "Validating if Cluster $VMCluster has enough CPU resources available" -LogOnly
    Run-Test -TestName "vSphere: CPU resources available" -TestCode {
        try {
            if ($script:viConnectionObject) {
                $clusterStats = Get-ClusterFreeResources -ClusterName $VMCluster
                if ($clusterStats.FreeCpuGhz -ge $Requirements.CPUGHz) {
                    return $true
                } else {
                    return "vSphere: Not enough CPU resources available"
                }
            } else {
                return "vCenter connection not established"
            }
        } catch {
            return "Error calculating free CPU resources. Error: $($_.Exception.Message)"
        }
    }

    # Verify if have enough memory resources available
    My-Logger "Validating if Cluster $VMCluster has enough memory resources available" -LogOnly
    Run-Test -TestName "vSphere: Memory resources available" -TestCode {
        try {
            if ($script:viConnectionObject) {
                $clusterStats = Get-ClusterFreeResources -ClusterName $VMCluster
                if ($clusterStats.FreeMemoryGB -ge $Requirements.MemoryGB) {
                    return $true
                } else {
                    return "vSphere: Not enough memory resources available"
                }
            } else {
                return "vCenter connection not established"
            }
        } catch {
            return "Error calculating available memory resources. Error: $($_.Exception.Message)"
        }
    }

    # Verify if have enough free datastore storage available
    My-Logger "Validating if datastore $VMDatastore has enough storage available" -LogOnly
    Run-Test -TestName "vSphere: Datastore storage available" -TestCode {
        try {
            if ($script:viConnectionObject) {
                $FreeSpaceGB = (Get-Datastore -Name $VMDatastore -ErrorAction Stop).FreeSpaceGB
                if ($FreeSpaceGB -ge $Requirements.StorageGB) {
                    return $true
                } else {
                    return "vSphere: Not enough datastore storage available"
                }
            } else {
                return "vCenter connection not established"
            }
        } catch {
            return "Error calculating available datastore storage. Error: $($_.Exception.Message)"
        }
    }

    # End of vCenter tests. Disconnect from vCenter if connected
    My-Logger "End of vCenter related tests. Disconnect from vCenter if connected" -LogOnly
    if ($script:viConnectionObject) {
        Disconnect-VIServer -Server $script:viConnectionObject -Confirm:$false -ErrorAction SilentlyContinue
    }

    # Check if Ops Man is already installed
    My-Logger "Validating if Tanzu Operations Manager is not already installed" -LogOnly
    $global:opsmanResult = $null
    Run-Test -TestName "Platform: Tanzu Operations Manager is not installed" -TestCode {
        try {
            $global:opsmanResult = Invoke-WebRequest -Uri https://$OpsManagerFQDN -SkipCertificateCheck -Method GET -TimeoutSec 3 -ErrorAction stop
            return "Platform: Tanzu Operations Manager is already installed"
        } catch {
            return $true
        }
    }

    if ($opsmanResult) {
        # Check if BOSH director is already installed
        My-Logger "Validating if BOSH Director is not already installed" -LogOnly
        Run-Test -TestName "Platform: BOSH Director is not installed" -TestCode {
            try {
                $productToCheck = "p-bosh"
                $deployedResult = Check-productDeployed -productName $productToCheck
                if (!$deployedResult){
                    return $true
                } else {
                    return "Platform: BOSH Director is already installed"
                }
            } catch {
                return "Unable to confirm if BOSH Director is already installed. Error: $($_.Exception.Message)"
            }
        }

        # Check if Tanzu Platform Cloud Foundary is already installed
        My-Logger "Validating if Tanzu Platform Cloud Foundary is not already installed" -LogOnly
        Run-Test -TestName "Platform: Tanzu Platform Cloud Foundary is not installed" -TestCode {
            try {
                $productToCheck = "cf"
                $deployedResult = Check-productDeployed -productName $productToCheck
                if (!$deployedResult){
                    return $true
                } else {
                    return "Platform: Tanzu Platform Cloud Foundary is already installed"
                }
            } catch {
                return "Unable to confirm if Tanzu Platform Cloud Foundary is already installed. Error: $($_.Exception.Message)"
            }
        }

        # Check if VMware Postgres is already installed
        if ($InstallTanzuAI) {
            My-Logger "Validating if VMware Postgres is not already installed" -LogOnly
            Run-Test -TestName "Platform: VMware Postgres is not installed" -TestCode {
                try {
                    $productToCheck = "postgres"
                    $deployedResult = Check-productDeployed -productName $productToCheck
                    if (!$deployedResult){
                        return $true
                    } else {
                        return "Platform: VMware Postgres is already installed"
                    }
                } catch {
                    return "Unable to confirm if VMware Postgres is already installed. Error: $($_.Exception.Message)"
                }
            }
        }

        # Check if Tanzu GenAI is already installed
        if ($InstallTanzuAI) {
            My-Logger "Validating if Tanzu GenAI is not already installed" -LogOnly
            Run-Test -TestName "Platform: Tanzu GenAI is not installed" -TestCode {
                try {
                    $productToCheck = "genai"
                    $deployedResult = Check-productDeployed -productName $productToCheck
                    if (!$deployedResult){
                        return $true
                    } else {
                        return "Platform: Tanzu GenAI is already installed"
                    }
                } catch {
                    return "Unable to confirm if Tanzu GenAI is already installed. Error: $($_.Exception.Message)"
                }
            }
        }

        # Check if Healthwatch is already installed
        if ($InstallHealthwatch) {
            My-Logger "Validating if Healthwatch is not already installed" -LogOnly
            Run-Test -TestName "Platform: Healthwatch is not installed" -TestCode {
                try {
                    $productToCheck = "p-healthwatch2"
                    $deployedResult = Check-productDeployed -productName $productToCheck
                    if (!$deployedResult){
                        return $true
                    } else {
                        return "Platform: Healthwatch is already installed"
                    }
                } catch {
                    return "Unable to confirm if Healthwatch is already installed. Error: $($_.Exception.Message)"
                }
            }
        }

        # Check if Healthwatch Exporter is already installed
        if ($InstallHealthwatch) {
            My-Logger "Validating if Healthwatch Exporter is not already installed" -LogOnly
            Run-Test -TestName "Platform: Healthwatch Exporter is not installed" -TestCode {
                try {
                    $productToCheck = "p-healthwatch2-pas-exporter"
                    $deployedResult = Check-productDeployed -productName $productToCheck
                    if (!$deployedResult){
                        return $true
                    } else {
                        return "Platform: Healthwatch Exporter is already installed"
                    }
                } catch {
                    return "Unable to confirm if Healthwatch Exporter is already installed. Error: $($_.Exception.Message)"
                }
            }
        }

        # Check if Tanzu Hub is already installed
        if ($InstallHub) {
            My-Logger "Validating if Tanzu Hub is not already installed" -LogOnly
            Run-Test -TestName "Platform: Tanzu Hub is not installed" -TestCode {
                try {
                    $productToCheck = "hub"
                    $deployedResult = Check-productDeployed -productName $productToCheck
                    if (!$deployedResult){
                        return $true
                    } else {
                        return "Platform: Tanzu Hub is already installed"
                    }
                } catch {
                    return "Unable to confirm if Tanzu Hub is already installed. Error: $($_.Exception.Message)"
                }
            }
        }
    }

    # Verify if VMware PowerCLI module is installed
    My-Logger "Validating if VMware PowerCLI module is installed" -LogOnly
    Run-Test -TestName "VMware PowerCLI module installed" -TestCode {
        if (Get-Module -ListAvailable -Name VMware.PowerCLI) {
            return $true
        } else {
            return "VMware PowerCLI module not found"
        }
    }

    # Check if ssh-keygen is installed
    My-Logger "Validating if ssh-keygen is installed" -LogOnly
    Run-Test -TestName "ssh-keygen is installed" -TestCode {
        if (Get-Command ssh-keygen -ErrorAction Stop) {return $true} else {return "ssh-keygen not installed"}
    }

    # Check if TP License Key is valid if TPCF 10.2 or later is being installed
    $TPCFFilename = Split-Path $TPCFTile -Leaf
    if ($TPCFFilename -like "*10.2*") {
        My-Logger "Validating if TP Licence Key is of valid format" -LogOnly
        Run-Test -TestName "License Key is of valid format" -TestCode {
            # Check if license key is specified (not null/empty)
            if ([string]::IsNullOrWhiteSpace($TPCFLicenseKey)) {
                My-Logger "License Key field is empty" -LogOnly -Level Error
                return "License Key field is empty"
            }
            
            # Validate license key format (xxxxx-xxxxx-xxxxx-xxxxx-xxxxx)
            $licensePattern = "^[A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{5}$"
            
            if ($TPCFLicenseKey -match $licensePattern) {
                My-Logger "License key format is valid" -LogOnly
                return $true
            } else {
                My-Logger "License Key format is invalid. Expected format: xxxxx-xxxxx-xxxxx-xxxxx-xxxxx" -LogOnly -Level Error
                return "License Key format is invalid"
            }
        }
    }

    My-Logger "Input validation complete" 
    $overallSuccess = Show-TestResults
    if (!$overallSuccess){
        My-Logger "[Error] Input validation tests failed. Please review and resolve any failures before trying again. " -level Error -color Red
        exit
    } else {
        My-Logger "Input validation tests passed. Proceeding with install..."
    }
}

if($deployOpsManager -eq 1) {
    
    My-Logger "Installing Tanzu Operations Manager..."

    # Check if already installed
    try {
        $opsmanResult = Invoke-WebRequest -Uri https://$OpsManagerFQDN -SkipCertificateCheck -Method GET -TimeoutSec 3 -ErrorAction stop
        My-Logger "[Error] Tanzu Operations Manager is already installed" -level Error -color Red
        exit
    } catch {
        #catch any exception rather than printing it to console
    } 
    
    # Connect to vCenter Server
    $viConnection = Connect-VIServer $VIServer -User $VIUsername -Password $VIPassword -Force -WarningAction SilentlyContinue -ErrorAction Stop

    $datastore = Get-Datastore -Server $viConnection -Name $VMDatastore | Select-Object -First 1
    $cluster = Get-Cluster -Server $viConnection -Name $VMCluster
    $vmhost = $cluster | Get-VMHost | Select-Object -First 1
    $resourcepool = Get-ResourcePool -Server $viConnection -Name $VMResourcePool

    # Generate ssh key
    $OpsManagerPublicSshKey = $null
    $result = Generate-SSHKey -PublicKeyContent ([ref]$OpsManagerPublicSshKey)

    # Deploy Ops Manager
    $opsMgrOvfCOnfig = Get-OvfConfiguration $OpsManOVA
    $opsMgrOvfCOnfig.Common.ip0.Value = $OpsManagerIPAddress
    $opsMgrOvfCOnfig.Common.netmask0.Value = $OpsManagerNetmask
    $opsMgrOvfCOnfig.Common.gateway.Value = $OpsManagerGateway
    $opsMgrOvfCOnfig.Common.DNS.Value = $VMDNS
    $opsMgrOvfCOnfig.Common.ntp_servers.Value = $VMNTP
    $opsMgrOvfCOnfig.Common.public_ssh_key.Value = $OpsManagerPublicSshKey
    $opsMgrOvfCOnfig.Common.custom_hostname.Value = $OpsManagerFQDN
    $opsMgrOvfCOnfig.NetworkMapping.Network_1.Value = $VMNetwork
    
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
    $opsmgr_vm = Import-VApp -Source $OpsManOVA -OvfConfiguration $opsMgrOvfCOnfig -Name $OpsManagerDisplayName -Location $resourcepool -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin

    My-Logger "Tanzu Operations Manager installed"
    My-Logger "Powering on Tanzu Operations Manager..."
    $opsmgr_vm | Start-Vm -RunAsync | Out-Null

    #Disconnect from vCenter
    Disconnect-VIServer -Confirm:$false -ErrorAction SilentlyContinue
}

if($setupOpsManager -eq 1) {
    My-Logger "Waiting for Tanzu Operations Manager to come online..."
    while (1) {
        try {
            $results = Invoke-WebRequest -Uri https://$OpsManagerFQDN -SkipCertificateCheck -Method GET
            if ($results.StatusCode -eq 200) {
                break
            }
        } catch {
            My-Logger "Tanzu Operations Manager is not ready yet, sleeping 30 seconds..."
            Start-Sleep 30
        }
    }

    My-Logger "Setting up Tanzu Operations Manager authentication..."

    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "configure-authentication", "--username", "$OpsManagerAdminUsername", "--password", "$OpsManagerAdminPassword", "--decryption-passphrase", "$OpsManagerDecryptionPassword")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }
    My-Logger "Tanzu Operations Manager authentication configured"
}

if($setupBOSHDirector -eq 1) {
    
    My-Logger "Installing BOSH Director (can take up to 15 minutes)..."
    
    # Verify if BOSH Director is already installed
    $productToCheck = "p-bosh"
    $deployedResult = Check-productDeployed -productName $productToCheck
    if ($deployedResult){
        My-Logger "[Error] BOSH Director is already installed" -level Error -color Red
        exit
    }
    
    # Create BOSH Director config yaml 
    $boshPayloadStart = @"
---
az-configuration:

"@
    # Process AZ
    $singleAZString = ""
    $BOSHAZ.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $singleAZString += "- name: "+$_.Name+"`n"
        $singleAZString += "  iaas_configuration_name: "+$_.Value['iaas_name']+"`n"
        $singleAZString += "  clusters:`n"
        $singleAZString += "  - cluster: "+$_.Value['cluster']+"`n"
        $singleAZString += "    resource_pool: "+$_.Value['resource_pool']+"`n"
    }

    # Process Networks
    $boshPayloadNetwork = @"
networks-configuration:
  icmp_checks_enabled: true
  networks:

"@
    $singleNetworkString = ""
    $BOSHNetwork.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $singleNetworkString += "  - name: "+$_.Name+"`n"
        $singleNetworkString += "    subnets:`n"
        $singleNetworkString += "    - iaas_identifier: "+$_.Value['portgroupname']+"`n"
        $singleNetworkString += "      cidr: "+$_.Value['cidr']+"`n"
        $singleNetworkString += "      gateway: "+$_.Value['gateway']+"`n"
        $singleNetworkString += "      dns: "+$_.Value['dns']+"`n"
        $singleNetworkString += "      cidr: "+$_.Value['cidr']+"`n"
        $singleNetworkString += "      reserved_ip_ranges: "+$_.Value['reserved_range']+"`n"
        $singleNetworkString += "      availability_zone_names:`n"
        $singleNetworkString += "      - "+$_.Value['az']+"`n"
    }

    # Concat Network config
    $boshPayloadNetwork += $singleNetworkString

    # Process remainder configs
    $boshPayloadEnd = @"
network-assignment:
  network:
    name: $BOSHNetworkAssignment
  singleton_availability_zone:
    name: $BOSHAZAssignment
iaas-configurations:
- name: vCenter
  vcenter_host: $VIServer
  vcenter_username: $BOSHvCenterUsername
  vcenter_password: $BOSHvCenterPassword
  datacenter: $BOSHvCenterDatacenter
  disk_type: thin
  ephemeral_datastores_string: $BOSHvCenterEpemeralDatastores
  persistent_datastores_string: $BOSHvCenterPersistentDatastores
  nsx_networking_enabled: false
  avi_load_balancer_enabled: false
  bosh_vm_folder: $BOSHvCenterVMFolder
  bosh_template_folder: $BOSHvCenterTemplateFolder
  bosh_disk_path: $BOSHvCenterDiskFolder
  enable_human_readable_name: true
properties-configuration:
  director_configuration:
    ntp_servers_string: $VMNTP
    post_deploy_enabled: true
  security_configuration:
    generate_vm_passwords: true
    opsmanager_root_ca_trusted_certs: true
resource-configuration:
  director:
    persistent_disk:
      name: "102400"
      size_mb: "102400"
"@

    # Concat configuration to form final YAML
    $boshPayload = $boshPayloadStart + $singleAZString + $boshPayloadNetwork + $boshPayloadEnd
    $boshYaml = "bosh-director-config.yaml"
    $boshPayload > $boshYaml

    # Apply config
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "configure-director", "--config", "$boshYaml")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Apply BOSH Director configuration failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Install BOSH Director
    $installArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "apply-changes")
    if ($ignoreWarnings) {$installArgs += "--ignore-warnings"}
    My-Logger "${OMCLI} $installArgs" -LogOnly
    & $OMCLI $installArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Installing BOSH Director failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }
    
    My-Logger "BOSH Director successfully installed"
}

if($setupTPCF -eq 1) {
    
    # Verify if TPCF is already installed
    $productToCheck = "cf"
    $deployedResult = Check-productDeployed -productName $productToCheck
    if ($deployedResult){
        My-Logger "[Error] Tanzu Platform for Cloud Foundry is already installed" -level Error -color Red
        exit
    }
    
    # Get product name and version
    $TPCFProductName = & "$OMCLI" product-metadata --product-path $TPCFTile --product-name
    $TPCFVersion = & "$OMCLI" product-metadata --product-path $TPCFTile --product-version

    # Upload tile
    My-Logger "Uploading Tanzu Platform for Cloud Foundry tile to Tanzu Operations Manager (can take up to 15 minutes)..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "-r", "3600", "upload-product", "--product", "$TPCFTile")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Stage tile
    My-Logger "Adding Tanzu Platform for Cloud Foundry tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "stage-product", "--product-name", "$TPCFProductName", "--product-version", "$TPCFVersion")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Check if to use user provided certs or auto generate them
    if ($userProvidedCert){
        # read in user provided cert chain and key
        $TPCFcert = (Get-Content -Path $CertPath) -join "\n"
        $TPCFkey = (Get-Content -Path $KeyPath) -join "\n"
    } else {
        # Generate wildcard cert and key
        $domainlist = "*.apps.$TPCFDomain,*.login.sys.$TPCFDomain,*.uaa.sys.$TPCFDomain,*.sys.$TPCFDomain,*.$TPCFDomain"
        $TPCFcert_and_key = & "$OMCLI" -k -t $OpsManagerFQDN -u $OpsManagerAdminUsername -p $OpsManagerAdminPassword generate-certificate -d $domainlist

        $pattern = "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\\n"
        $TPCFcert = [regex]::Match($TPCFcert_and_key, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

        $pattern = "-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----\\n"
        $TPCFkey = [regex]::Match($TPCFcert_and_key, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    }

    # Build the license key section conditionally
    $licenseKeySection = ""
    if ($TPCFLicenseKey) {
        $licenseKeySection = @"

  .properties.license_key:
    value: $TPCFLicenseKey
"@
    }
    
    # Create TPCF config yaml
    $TPCFPayload = @"
---
product-name: cf
network-properties:
  singleton_availability_zone:
    name: $TPCFAZ
  other_availability_zones:
  - name: $TPCFAZ
  network:
    name: $TPCFNetwork
product-properties:
  .cloud_controller.system_domain:
    value: sys.$TPCFDomain
  .cloud_controller.apps_domain:
    value: apps.$TPCFDomain
  .router.static_ips:
    value: $TPCFGoRouter
  .properties.networking_poe_ssl_certs:
    value:
    - name: gorouter-cert
      certificate:
        cert_pem: "$TPCFcert"
        private_key_pem: "$TPCFkey"
  .properties.routing_tls_termination:
    value: router
  .properties.security_acknowledgement:
    value: X
  .uaa.service_provider_key_credentials:
    value:
      cert_pem: "$TPCFcert"
      private_key_pem: "$TPCFkey"
  .properties.credhub_internal_provider_keys:
    value:
    - name: Internal-encryption-provider-key
      key:
        secret: $TPCFCredHubSecret
      primary: true$licenseKeySection
resource-config:
  backup_restore:
    instances: 0
  mysql_monitor:
    instances: 0
  compute:
    instances: $TPCFComputeInstances
"@

    $TPCFyaml = "tpcf-config.yaml"
    $TPCFPayload > $TPCFyaml

    My-Logger "Applying Tanzu Platform for Cloud Foundry configuration..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "configure-product", "--config", "$TPCFyaml")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # To improve install time, don't install TPCF just yet if postgres and GenAI tiles are to be installed also
    if($InstallTanzuAI -eq 0) {
        My-Logger "Installing Tanzu Platform for Cloud Foundry (can take up to 60 minutes)..."
        $installArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "apply-changes")
        if ($ignoreWarnings) {$installArgs += "--ignore-warnings"}
        My-Logger "${OMCLI} $installArgs" -LogOnly
        & $OMCLI $installArgs 2>&1 >> $verboseLogFile
        if ($LASTEXITCODE -ne 0) {
            My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
            exit
        }
    }

}

if($setupPostgres -eq 1) {

    # Verify if Postgres is already installed
    $productToCheck = "postgres"
    $deployedResult = Check-productDeployed -productName $productToCheck
    if ($deployedResult){
        My-Logger "[Error] VMware Postgres tile is already installed" -level Error -color Red
        exit
    }

    # Get product name and version
    $PostgresProductName = & "$OMCLI" product-metadata --product-path $PostgresTile --product-name
    $PostgresVersion = & "$OMCLI" product-metadata --product-path $PostgresTile --product-version

    # Upload tile
    My-Logger "Uploading VMware Postgres tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "-r", "3600", "upload-product", "--product", "$PostgresTile")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Stage tile
    My-Logger "Adding VMware Postgres tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "stage-product", "--product-name", "$PostgresProductName", "--product-version", "$PostgresVersion")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Create Postgres config yaml
    $PostgresPayload = @"
---
product-name: postgres
product-properties:
  .properties.plan_collection:
    value:
    - az_multi_select:
      - $BOSHAZAssignment
      cf_service_access: enable
      name: on-demand-postgres-db
network-properties:
  network:
    name: $BOSHNetworkAssignment
  other_availability_zones:
  - name: $BOSHAZAssignment
  service_network:
    name: $BOSHNetworkAssignment
  singleton_availability_zone:
    name: $BOSHAZAssignment
"@

    $Postgresyaml = "postgres-config.yaml"
    $PostgresPayload > $Postgresyaml

    My-Logger "Applying VMware Postgres configuration..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "configure-product", "--config", "$Postgresyaml")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    My-Logger "Installing Tanzu Platform for Cloud Foundry and VMware Postgres (can take up to 75 minutes)..."
    $installArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "apply-changes")
    if ($ignoreWarnings) {$installArgs += "--ignore-warnings"}
    My-Logger "${OMCLI} $installArgs" -LogOnly
    & $OMCLI $installArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }
    
    My-Logger "Tanzu Platform for Cloud Foundry and VMware Postgres successfully installed"
}

if($setupGenAI -eq 1) {

    # Verify if GenAI is already installed
    $productToCheck = "genai"
    $deployedResult = Check-productDeployed -productName $productToCheck
    if ($deployedResult){
        My-Logger "[Error] Tanzu GenAI tile is already installed" -level Error -color Red
        exit
    }

    # Get product name and version
    $GenAIProductName = & "$OMCLI" product-metadata --product-path $GenAITile --product-name
    $GenAIVersion = & "$OMCLI" product-metadata --product-path $genAITile --product-version

    # Upload tile
    My-Logger "Uploading Tanzu GenAI tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "-r", "3600", "upload-product", "--product", "$GenAITile")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Stage tile
    My-Logger "Adding Tanzu GenAI tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "stage-product", "--product-name", "$GenAIProductName", "--product-version", "$GenAIVersion")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Create GenAI config yaml
    if($ToolsModel -eq 0) {
        $GenAIPayload = @"
---
product-name: genai
product-properties:
  .controller.plans:
    value:
    - binding_credential_format: legacy
      cf_access_enabled: true
      description: A high-performing open embedding model
      model_handles: $OllamaEmbedModel
      name: embedding-model
      requests_per_minute: null
      run_release_tests: true
      tkgi_access_enabled: false
      tokens_per_minute: null
    - binding_credential_format: legacy
      cf_access_enabled: true
      description: A model with chat capabilities
      model_handles: $OllamaChatModel
      name: chat-model
      requests_per_minute: null
      run_release_tests: true
      tkgi_access_enabled: false
      tokens_per_minute: null
  .errands.ollama_models:
    value:
    - azs:
      - $BOSHAZAssignment
      handle: $OllamaEmbedModel
      model_capabilities:
      - embedding
      model_name: $OllamaEmbedModel
      vm_type: cpu
    - azs:
      - $BOSHAZAssignment
      handle: $OllamaChatModel
      model_capabilities:
      - chat
      model_name: $OllamaChatModel
      vm_type: cpu
  .properties.database_source:
    selected_option: service_broker
    value: service_broker
  .properties.database_source.service_broker.name:
    value: postgres
  .properties.database_source.service_broker.plan_name:
    value: on-demand-postgres-db
network-properties:
  network:
    name: $BOSHNetworkAssignment
  other_availability_zones:
  - name: $BOSHAZAssignment
  service_network:
    name: $BOSHNetworkAssignment
  singleton_availability_zone:
    name: $BOSHAZAssignment
"@
    } else {
        $GenAIPayload = @"
---
product-name: genai
product-properties:
  .controller.plans:
    value:
    - binding_credential_format: legacy
      cf_access_enabled: true
      description: A high-performing open embedding model
      model_handles: $OllamaEmbedModel
      name: embedding-model
      requests_per_minute: null
      run_release_tests: true
      tkgi_access_enabled: false
      tokens_per_minute: null
    - binding_credential_format: legacy
      cf_access_enabled: true
      description: A model with chat and tool capabilities
      model_handles: $OllamaChatToolsModel
      name: chat-and-tools-model
      requests_per_minute: null
      run_release_tests: true
      tkgi_access_enabled: false
      tokens_per_minute: null
  .errands.ollama_models:
    value:
    - azs:
      - $BOSHAZAssignment
      handle: $OllamaEmbedModel
      instances: 1
      model_capabilities:
      - embedding
      model_name: $OllamaEmbedModel
      ollama_context_length: 2048
      ollama_flash_attention: false
      ollama_keep_alive: 60m
      ollama_kv_cache_type: f16
      ollama_load_timeout: 5m
      ollama_num_parallel: 0
      vm_type: cpu
      wire_format: openai
    - azs:
      - $BOSHAZAssignment
      handle: $OllamaChatToolsModel
      instances: 1
      model_aliases: null
      model_capabilities:
      - chat
      - tools
      model_name: $OllamaChatToolsModel
      ollama_context_length: 131072
      ollama_flash_attention: true
      ollama_keep_alive: "-1"
      ollama_kv_cache_type: q4_0
      ollama_load_timeout: 5m
      ollama_num_parallel: 1
      vm_type: cpu-2xlarge
      wire_format: openai
  .errands.vsphere_vm_types:
    value:
    - cpu: 8
      ephemeral_disk: 65536
      name: cpu
      processing_technology: cpu
      ram: 32768
      root_disk: 25
    - cpu: 16
      ephemeral_disk: 65536
      name: cpu-2xlarge
      processing_technology: cpu
      ram: 32768
      root_disk: 25
  .properties.database_source:
    selected_option: service_broker
    value: service_broker
  .properties.database_source.service_broker.name:
    value: postgres
  .properties.database_source.service_broker.plan_name:
    value: on-demand-postgres-db
network-properties:
  network:
    name: $BOSHNetworkAssignment
  other_availability_zones:
  - name: $BOSHAZAssignment
  service_network:
    name: $BOSHNetworkAssignment
  singleton_availability_zone:
    name: $BOSHAZAssignment
"@
    }

    $GenAIyaml = "genai-config.yaml"
    $GenAIPayload > $GenAIyaml

    My-Logger "Applying Tanzu GenAI configuration..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "configure-product", "--config", "$GenAIyaml")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    My-Logger "Installing Tanzu GenAI (can take up to 40 minutes)..."
    $installArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "apply-changes", "--product-name", "$GenAIProductName")
    if ($ignoreWarnings) {$installArgs += "--ignore-warnings"}
    My-Logger "${OMCLI} $installArgs" -LogOnly
    & $OMCLI $installArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    My-Logger "Tanzu GenAI successfully installed"
}

if($setupHealthwatch -eq 1) {
    # Verify if Healthwatch is already installed
    $productToCheck = "p-healthwatch2"
    $deployedResult = Check-productDeployed -productName $productToCheck
    if ($deployedResult){
        My-Logger "[Error] Healthwatch tile is already installed" -level Error -color Red
        exit
    }
    
    # Verify if Healthwatch Exporter is already installed
    $productToCheck = "p-healthwatch2-pas-exporter"
    $deployedResult = Check-productDeployed -productName $productToCheck
    if ($deployedResult){
        My-Logger "[Error] Healthwatch Exporter tile is already installed" -level Error -color Red
        exit
    }

    # Get product name and version
    $HealthwatchProductName = & "$OMCLI" product-metadata --product-path $HealthwatchTile --product-name
    $HealthwatchVersion = & "$OMCLI" product-metadata --product-path $HealthwatchTile --product-version
    $HealthwatchExporterProductName = & "$OMCLI" product-metadata --product-path $HealthwatchExporterTile --product-name
    $HealthwatchExporterVersion = & "$OMCLI" product-metadata --product-path $HealthwatchExporterTile --product-version

    # Upload Healthwatch tile
    My-Logger "Uploading Healthwatch tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "-r", "3600", "upload-product", "--product", "$HealthwatchTile")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Upload Healthwatch Exporter tile
    My-Logger "Uploading Healthwatch Exporter tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "-r", "3600", "upload-product", "--product", "$HealthwatchExporterTile")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Stage Healthwatch tile
    My-Logger "Adding Healthwatch tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "stage-product", "--product-name", "$HealthwatchProductName", "--product-version", "$HealthwatchVersion")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Stage Healthwatch Exporter tile
    My-Logger "Adding Healthwatch Exporter tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "stage-product", "--product-name", "$HealthwatchExporterProductName", "--product-version", "$HealthwatchExporterVersion")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # No config needed for Healthwatch
    
    # Create Healthwatch Exporter config yaml
    $HealthwatchExporterPayload = @"
---
product-name: p-healthwatch2-pas-exporter
product-properties:
  .bosh-health-exporter.health_check_az:
    value: $BOSHAZAssignment
network-properties:
  network:
    name: $BOSHNetworkAssignment
  other_availability_zones:
  - name: $BOSHAZAssignment
  service_network:
    name: $BOSHNetworkAssignment
  singleton_availability_zone:
    name: $BOSHAZAssignment
"@

    $HealthwatchExporteryaml = "HealthwatchExporter-config.yaml"
    $HealthwatchExporterPayload > $HealthwatchExporteryaml

    My-Logger "Applying Healthwatch configuration..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "configure-product", "--config", "$HealthwatchExporteryaml")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    My-Logger "Installing Healthwatch and Healthwatch Exporter (can take up to 35 minutes)..."
    $installArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "apply-changes", "--product-name", "$HealthwatchProductName", "--product-name", "$HealthwatchExporterProductName")
    if ($ignoreWarnings) {$installArgs += "--ignore-warnings"}
    My-Logger "${OMCLI} $installArgs" -LogOnly
    & $OMCLI $installArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    My-Logger "Healthwatch and Healthwatch Exporter successfully installed"
}

if($setupHub -eq 1) {

    # Verify if Hub is already installed
    $productToCheck = "hub"
    $deployedResult = Check-productDeployed -productName $productToCheck
    if ($deployedResult){
        My-Logger "[Error] Tanzu Hub tile is already installed" -level Error -color Red
        exit
    }

    # Get product name and version
    $HubProductName = & "$OMCLI" product-metadata --product-path $HubTile --product-name
    $HubVersion = & "$OMCLI" product-metadata --product-path $HubTile --product-version

    # Upload tile
    My-Logger "Uploading Tanzu Hub tile to Tanzu Operations Manager (can take up to 15 minutes)..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "-r", "3600", "upload-product", "--product", "$HubTile")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Stage tile
    My-Logger "Adding Tanzu Hub tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "stage-product", "--product-name", "$HubProductName", "--product-version", "$HubVersion")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Check if to use user provided cert or auto generate a self-signed cert
    if ($UserProvidedHubCert){
        # read in user provided cert chain and key
        $HubCert = (Get-Content -Path $HubCertPath) -join "\n"
        $HubKey = (Get-Content -Path $HubKeyPath) -join "\n"
    } else {
        # Generate a self-signed cert and key for Hub
        $HubCert_and_key = & "$OMCLI" -k -t $OpsManagerFQDN -u $OpsManagerAdminUsername -p $OpsManagerAdminPassword generate-certificate -d $HubFQDN
    
        $pattern = "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\\n"
        $HubCert = [regex]::Match($HubCert_and_key, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    
        $pattern = "-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----\\n"
        $HubKey = [regex]::Match($HubCert_and_key, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    }

    # Create Hub config yaml
    $HubPayload = @"
---
product-name: hub
product-properties:
  .properties.dns_zone:
    value: $HubFQDN
  .properties.ingress_tls:
    value:
      cert_pem: "$HubCert"
      private_key_pem: "$HubKey"
  .properties.idp:
    selected_option: idp_internal
    value: idp_internal
  .properties.tia:
    selected_option: none
    value: none
  .properties.trivy_allow_insecure_connections:
    value: true
network-properties:
  network:
    name: $BOSHNetworkAssignment
  other_availability_zones:
  - name: $BOSHAZAssignment
  singleton_availability_zone:
    name: $BOSHAZAssignment
"@

    $Hubyaml = "hub-config.yaml"
    $HubPayload > $Hubyaml

    My-Logger "Applying Tanzu Hub configuration..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "configure-product", "--config", "$Hubyaml")
    My-Logger "${OMCLI} $configArgs" -LogOnly
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    My-Logger "Installing Tanzu Hub (can take up to 75 minutes)..."
    $installArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "apply-changes", "--product-name", "$HubProductName")
    if ($ignoreWarnings) {$installArgs += "--ignore-warnings"}
    My-Logger "${OMCLI} $installArgs" -LogOnly
    & $OMCLI $installArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    My-Logger "Tanzu Hub successfully installed" 
}

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes,2)

My-Logger "======================================================"
My-Logger "                Installation Complete!                "
My-Logger "======================================================"
My-Logger "StartTime: $StartTime"
My-Logger "  EndTime: $EndTime"
My-Logger " Duration: $duration minutes"
My-Logger " "
My-Logger "Installation log: $verboseLogFile"
My-Logger " "

if ($setupTPCF){
    #retrieve uaa admin password
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "credentials", "-p", "cf", "-c", ".uaa.admin_credentials")
    $credsOutput = & $OMCLI $configArgs
    $uaaAdminPassword = $null
    foreach ($line in $credsOutput) {
        if ($line -match "^\|\s*admin\s*\|\s*(.+?)\s*\|$") {
            $uaaAdminPassword = $Matches[1].Trim()
            break
        }
    }

    My-Logger "======================================================"
    My-Logger "                Next steps...                         "
    My-Logger "======================================================"
    My-Logger "Follow the next steps at the link below where you can learn how to push your first app! Or, alternatively..."
    My-Logger " - https://github.com/KeithRichardLee/Tanzu-GenAI-Platform-installer"
    My-Logger " "
    My-Logger "Log into Tanzu Operations Manager"
    My-Logger "- Open a browser to https://$OpsManagerFQDN"
    My-Logger "- Username: $OpsManagerAdminUsername"
    My-Logger "- Password: $OpsManagerAdminPassword"
    My-Logger " "
    My-Logger "Log into Tanzu Apps Manager"
    My-Logger "- Open a browser to https://apps.sys.$TPCFDomain"
    My-Logger "- Username: $OpsManagerAdminUsername"
    My-Logger "- Password: $uaaAdminPassword"
    My-Logger " "
    My-Logger "Use Cloud Foundry CLI (cf cli) to push and manage apps, create and bind services, and more"
    My-Logger "- cf login -a https://api.sys.$TPCFDomain -u $OpsManagerAdminUsername -p $uaaAdminPassword --skip-ssl-validation"
    My-Logger " "
    My-Logger "  Note; you can download cf cli from https://apps.sys.$TPCFDomain/tools or https://github.com/cloudfoundry/cli/releases"

    If ($InstallHub){
        My-Logger " "
        My-Logger "Tanzu Hub"
        My-Logger "- See docs on how to configure ingress to Tanzu Hub https://$HubFQDN here https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-hub/10-2/tnz-hub/install-install.html#access-tanzu-hub"
    }
}
