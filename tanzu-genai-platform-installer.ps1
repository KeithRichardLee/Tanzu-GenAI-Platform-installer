# PowerShell script which results in the deployment of VMware Tanzu Platform with GenAI capabilities
# 
# Script will... 
# - Validate all inputs
# - Deploy VMware Tanzu Operations Manager OVA
# - Configure authentication for VMware Tanzu Operations Manager
# - Configure and deploy BOSH Director
# - Configure and deploy VMware Tanzu Platform for Cloud Foundry
# - Configure and deploy VMware Postgres
# - Configure and deploy VMware Tanzu GenAI
#
############################################################################################

### Required inputs

### Full Path to Tanzu Operations Manager OVA, TPCF tile, Postgres tile, GenAI tile, and OM CLI
$OpsManOVA    = "/Users/Tanzu/Downloads/ops-manager-vsphere-3.0.40+LTS-T.ova"  #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware%20Tanzu%20Operations%20Manager
$TPCFTile     = "/Users/Tanzu/Downloads/srt-10.0.5-build.2.pivotal"            #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=Tanzu%20Platform%20for%20Cloud%20Foundry
$PostgresTile = "/Users/Tanzu/Downloads/postgres-10.0.0-build.31.pivotal"      #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware+Tanzu+for+Postgres+on+Cloud+Foundry
$GenAITile    = "/Users/Tanzu/Downloads/genai-10.0.3.pivotal"                  #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=GenAI%20on%20Tanzu%20Platform%20for%20Cloud%20Foundry
$OMCLI        = "/usr/local/bin/om"                                            #Download from https://github.com/pivotal-cf/om

### Infra config
$VIServer = "FILL-ME-IN"
$VIUsername = "FILL-ME-IN"
$VIPassword = "FILL-ME-IN"
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
$OpsManagerAdminPassword = "FILL-ME-IN"
$OpsManagerIPAddress = "FILL-ME-IN"
$OpsManagerFQDN = "FILL-ME-IN"
$BOSHNetworkReservedRange = "FILL-ME-IN"  #add IPs, either individual and/or ranges you _don't_ want BOSH to use in the subnet eg Ops Man, gateway, DNS, NTP, jumpbox eg 10.0.70.0-10.0.70.2,10.0.70.10
$TPCFGoRouter = "FILL-ME-IN"              #IP which the Tanzu Platform system and apps domain resolves to
$TPCFDomain = "FILL-ME-IN"                #Tanzu Platform system and apps subdomains will be added to this. Resolves to the TPCF GoRouter IP

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

# Tanzu Platform for Cloud Foundry (TPCF) configuration
$TPCFCredHubSecret = "VMware1!VMware1!VMware1!" # must be 20 or more characters
$TPCFAZ = $BOSHAZAssignment
$TPCFNetwork = $BOSHNetworkAssignment
$TPCFComputeInstances = "1" # default is 1. Increase if planning to run many large apps

# Install Tanzu AI Solutions?
$InstallTanzuAI = $true 

# Tanzu AI Solutions config 
$OllamaEmbedModel = "nomic-embed-text"
$OllamaChatModel = "gemma2:2b"

# Deploy a model with chat and tools capabilities?  note; a vm will be created with 16 vCPU and 32 GB mem to run the model
$ToolsModel = $true
$OllamaChatToolsModel = "mistral-nemo:12b-instruct-2407-q4_K_M"


$debug = $false
$verboseLogFile = "tanzu-genai-platform-installer.log"

$confirmDeployment = 1
$preCheck = 1
$deployOpsManager = 1
$setupOpsManager = 1
$setupBOSHDirector = 1
$setupTPCF = 1
$setupPostgres = $InstallTanzuAI
$setupGenAI = $InstallTanzuAI

############################################################################################
#### DO NOT EDIT BEYOND HERE ####

$StartTime = Get-Date

Function My-Logger {
    param(
    [Parameter(Mandatory=$true)]
    [String]$message,
    [ValidateSet("INFO", "WARNING", "ERROR")]
    [string]$level = "INFO",
    [System.ConsoleColor]$color = "Green"
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"
    Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
    Write-Host -ForegroundColor $color " $message"
    $logMessage = "[$timeStamp] [$level] $message"
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

function Run-Test {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TestName,
        [Parameter(Mandatory=$true)]
        [scriptblock]$TestCode
    )
    
    if($debug) {My-Logger "Running test: $TestName" "INFO"}
    
    # Add test to order tracking array
    $script:TestOrder += $TestName
    
    try {
        $result = & $TestCode
        if ($result -eq $true) {
            $TestResults[$TestName] = @{
                Result = "PASS"
                Message = "Test passed successfully"
            }
            if($debug) {My-Logger "Test '$TestName' passed" "INFO"}
        } else {
            $TestResults[$TestName] = @{
                Result = "FAIL"
                Message = $result
            }
            if($debug) {My-Logger "Test '$TestName' failed: $result" "ERROR"}
        }
    } catch {
        $TestResults[$TestName] = @{
            Result = "FAIL"
            Message = $_.Exception.Message
        }
        if($debug) {My-Logger "Test '$TestName' failed with exception: $($_.Exception.Message)" "ERROR"}
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
    Write-Host -NoNewline -ForegroundColor Green "GoRouter wildcard cert SAN: "
    $domainlist = "*.apps.$TPCFDomain,*.login.sys.$TPCFDomain,*.uaa.sys.$TPCFDomain,*.sys.$TPCFDomain,*.$TPCFDomain"    
    Write-Host -ForegroundColor White $domainlist

    Write-Host -ForegroundColor Yellow "`n---- Tanzu AI Solutions Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "Ollama embedding model: "
    Write-Host -ForegroundColor White $OllamaEmbedModel
    if ($ToolsModel) {
        Write-Host -NoNewline -ForegroundColor Green "Ollama chat & tools model: "
        Write-Host -ForegroundColor White $OllamaChatToolsModel
    } else {
        Write-Host -NoNewline -ForegroundColor Green "Ollama chat model: "
        Write-Host -ForegroundColor White $OllamaChatModel
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
    
    # Test 1: Verify required files exist
    Run-Test -TestName "OM CLI exists" -TestCode {
        if (Test-Path $OMCLI) { return $true } else { return "Unable to find $OMCLI" }
    }
    
    # Test 2: Verify required files exist
    Run-Test -TestName "Tanzu Operations Manager OVA file exists" -TestCode {
        if (Test-Path $OpsManOVA) { return $true } else { return "Unable to find $OpsManOVA" }
    }
    
    # Test 3: Verify required files exist
    Run-Test -TestName "Tanzu Platform for Cloud Foundry tile file exists" -TestCode {
        if (Test-Path $TPCFTile) { return $true } else { return "Unable to find $TPCFTile" }
    }
    
    # Test 4: Verify required files exist
    Run-Test -TestName "Postgres tile file exists" -TestCode {
        if ($InstallTanzuAI -eq $true) {
            if (Test-Path $PostgresTile) { return $true } else { return "Unable to find $PostgresTile" }
        } else {
            return $true # Skip if not installing TanzuAI
        }
    }
    
    # Test 5: Verify required files exist
    Run-Test -TestName "GenAI tile file exists" -TestCode {
        if ($InstallTanzuAI -eq $true) {
            if (Test-Path $GenAITile) { return $true } else { return "Unable to find $GenAITile" }
        } else {
            return $true # Skip if not installing TanzuAI
        }
    }
    
    # Test 6: Verify if VMware PowerCLI module installed
    Run-Test -TestName "VMware PowerCLI module installed" -TestCode {
        if (Get-Module -ListAvailable -Name VMware.PowerCLI) {
            return $true
        } else {
            return "VMware PowerCLI module not found"
        }
    }
    
    # Test 7: Verify connectivity to vCenter
    Run-Test -TestName "vCenter connectivity" -TestCode {
        try {
            $vcenterResult = Invoke-WebRequest -Uri https://$VIServer -SkipCertificateCheck -Method GET
            if ($vcenterResult.StatusCode -eq 200) {
                return $true
            } else {
                return "Cannot reach vCenter $VIServer. Status code: $($vcenterResult.StatusCode)"
            }
        } catch {
            return "Cannot reach vCenter $VIServer. Error: $($_.Exception.Message)"
        }
    }
    
    # Test 8: Verify vCenter credentials
    Run-Test -TestName "vCenter credentials" -TestCode {
        try {
            $Global:ProgressPreference = 'SilentlyContinue'
            $viConnection = Connect-VIServer $VIServer -User $VIUsername -Password $VIPassword -Force -WarningAction SilentlyContinue -ErrorAction Stop
            if ($viConnection) {
                $script:viConnectionObject = $viConnection # Store for later use
                return $true
            } else {
                return "Cannot log into $VIServer"
            }
        } catch {
            return "Cannot log into $VIServer. Error: $($_.Exception.Message)"
        }
    }
    
    # Test 9: Verify datacenter
    Run-Test -TestName "Datacenter validation" -TestCode {
        try {
            if ($script:viConnectionObject) {
                $datacenterResult = Get-Datacenter -Name $VMDatacenter -ErrorAction Stop
                if ($datacenterResult) {
                    return $true
                } else {
                    return "Datacenter $VMDatacenter not found"
                }
            } else {
                return "vCenter connection not established"
            }
        } catch {
            return "Error finding datacenter $VMDatacenter. Error: $($_.Exception.Message)"
        }
    }
    
    # Test 10: Verify cluster
    Run-Test -TestName "Cluster validation" -TestCode {
        try {
            if ($script:viConnectionObject) {
                $clusterResult = Get-Cluster -Name $VMCluster -ErrorAction Stop
                if ($clusterResult) {
                    return $true
                } else {
                    return "Cluster $VMCluster not found"
                }
            } else {
                return "vCenter connection not established"
            }
        } catch {
            return "Error finding cluster $VMCluster. Error: $($_.Exception.Message)"
        }
    }
    
    # Test 11: Verify resource pool
    Run-Test -TestName "Resource Pool validation" -TestCode {
        try {
            if ($script:viConnectionObject) {
                $rpResult = Get-ResourcePool -Name $VMResourcePool -ErrorAction Stop
                if ($rpResult) {
                    return $true
                } else {
                    return "Resource Pool $VMResourcePool not found"
                }
            } else {
                return "vCenter connection not established"
            }
        } catch {
            return "Error finding resource pool $VMResourcePool. Error: $($_.Exception.Message)"
        }
    }
    
    # Test 12: Verify datastore
    Run-Test -TestName "Datastore validation" -TestCode {
        try {
            if ($script:viConnectionObject) {
                $datastoreResult = Get-DataStore -Name $VMDatastore -ErrorAction Stop
                if ($datastoreResult) {
                    return $true
                } else {
                    return "Datastore $VMDatastore not found"
                }
            } else {
                return "vCenter connection not established"
            }
        } catch {
            return "Error finding datastore $VMDatastore. Error: $($_.Exception.Message)"
        }
    }
    
    # Test 13: Verify portgroup
    Run-Test -TestName "Network Portgroup validation" -TestCode {
        try {
            if ($script:viConnectionObject) {
                if ($VirtualSwitchType -eq "VSS") {
                    $networkResult = Get-VirtualPortGroup -Server $script:viConnectionObject -Name $VMNetwork -ErrorAction Stop | Select-Object -First 1
                    if ($networkResult) {
                        return $true
                    } else {
                        return "Cannot find portgroup $VMNetwork"
                    }
                } else {
                    $networkResult = Get-VDPortgroup -Server $script:viConnectionObject -Name $VMNetwork -ErrorAction Stop | Select-Object -First 1
                    if ($networkResult) {
                        return $true
                    } else {
                        return "Cannot find portgroup $VMNetwork"
                    }
                }
            } else {
                return "vCenter connection not established"
            }
        } catch {
            return "Error finding portgroup $VMNetwork. Error: $($_.Exception.Message)"
        }
    }

    # End of vCenter tests. Disconnect from vCenter if connected
    if ($script:viConnectionObject) {
        Disconnect-VIServer -Server $script:viConnectionObject -Confirm:$false -ErrorAction SilentlyContinue
    }

    # Test 14: Verify target network connectivity
    Run-Test -TestName "Gateway connectivity" -TestCode {
        $Global:ProgressPreference = 'SilentlyContinue'
        try {
            $gateway = Test-Connection -ComputerName $VMGateway -Count 1 -Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($gateway) {
                return $true
            } else {
                return "Cannot reach target network gateway $VMGateway"
            }
        } catch {
            return "Error testing connection to gateway $VMGateway. Error: $($_.Exception.Message)"
        }
    }

    # Test 15: Verify DNS server connectivity
    Run-Test -TestName "DNS server connectivity" -TestCode {
        try {
            $dnsResult = Test-Connection -ComputerName $VMDNS -Count 1 -Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($dnsResult) {
                return $true
            } else {
                return "Cannot reach DNS server $VMDNS"
            }
        } catch {
            return "Error testing connection to DNS server $VMDNS. Error: $($_.Exception.Message)"
        }
    }

    # Test 16: Verify NTP server connectivity
    Run-Test -TestName "NTP server connectivity" -TestCode {
        try {
            $ntpResult = Test-Connection -ComputerName $VMNTP -Count 1 -Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($ntpResult) {
                return $true
            } else {
                return "Cannot reach NTP server $VMNTP"
            }
        } catch {
            return "Error testing connection to NTP server $VMNTP. Error: $($_.Exception.Message)"
        }
    }

    # Test 17: Verify Ops Man IP is available
    Run-Test -TestName "Tanzu Operations Manager IP available" -TestCode {
        try {
            $ipResult = Test-Connection -ComputerName $OpsManagerIPAddress -Count 1 -Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($ipResult) {
                return "Tanzu Operations Manager IP address $OpsManagerIPAddress is already in use"
            } else {
                return $true # IP is available if not reachable
            }
        } catch {
            return $true # IP is available if connection fails
        }
    }

    # Test 18: Verify GoRouter IP is available
    Run-Test -TestName "GoRouter IP available" -TestCode {
        try {
            $ipResult = Test-Connection -ComputerName $TPCFGoRouter -Count 1 -Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            if ($ipResult) {
                return "GoRouter IP address $TPCFGoRouter is already in use"
            } else {
                return $true # IP is available if not reachable
            }
        } catch {
            return $true # IP is available if connection fails
        }
    }

    # Test 19: Verify Ops Man DNS
    Run-Test -TestName "Tanzu Operations Manager DNS entry" -TestCode {
        $nsLookupArgs = @("$OpsManagerFQDN", "$VMDNS")
        try {
            $dnsResult = & nslookup $nsLookupArgs 2>&1
            if ($dnsResult) {
                return $true
            } else {
                return "DNS entry for $OpsManagerFQDN not found"
            }
        } catch {
            return "Error resolving DNS for $OpsManagerFQDN. Error: $($_.Exception.Message)"
        }
    } 


    # Test 20: Verify wildcard apps domain DNS
    Run-Test -TestName "Wildcard apps domain DNS entry" -TestCode {
        $nsLookupArgs = @("test.apps.$TPCFDomain", "$VMDNS")
        try {
            $dnsResult = & nslookup $nsLookupArgs 2>&1
            if ($dnsResult) {
                return $true
            } else {
                return "No record found for apps wildcard domain *.apps.$TPCFDomain on DNS server $VMDNS"
            }
        } catch {
            return "Error resolving DNS for test.apps.$TPCFDomain. Error: $($_.Exception.Message)"
        }
    }

    # Test 21: Verify wildcard system domain
    Run-Test -TestName "Wildcard system domain DNS entry" -TestCode {
        $nsLookupArgs = @("test.sys.$TPCFDomain", "$VMDNS")
        try {
            $dnsResult = & nslookup $nsLookupArgs 2>&1
            if ($dnsResult) {
                return $true
            } else {
                return "No record found for system wildcard domain *.sys.$TPCFDomain on DNS server $VMDNS"
            }
        } catch {
            return "Error resolving DNS for test.sys.$TPCFDomain. Error: $($_.Exception.Message)"
        }
    }

    # Test 22: Verify if wildcard domain resolves to GoRouter IP
    Run-Test -TestName "Wildcard apps and system domains resolve to GoRouter IP" -TestCode {
        $nsLookupArgs = @("test.sys.$TPCFDomain", "$VMDNS") 
        try {
            $dnsResult = & nslookup $nsLookupArgs 2>&1
            $ipaddress = ($dnsResult | Select-String -Pattern "Address:\s*(\d+\.\d+\.\d+\.\d+)" -AllMatches).Matches[1].Groups[1].Value
            if ($ipaddress -eq $TPCFGoRouter) {
                return $true
            } else {
                return "Wildcard domain $TPCFDomain resolves to $ipaddress instead of GoRouter IP $TPCFGoRouter"
            }
        } catch {
            return "Error checking DNS resolution for test.sys.$TPCFDomain. Error: $($_.Exception.Message)"
        }
    }

    # Test 23: Verify connectivity to ollama.com
    Run-Test -TestName "ollama.com connectivity" -TestCode {
        try {
            $ollamaResult = Invoke-WebRequest -Uri https://ollama.com -Method GET
            if ($ollamaResult.StatusCode -eq 200) {
                return $true
            } else {
                return "Cannot reach ollama.com. Status code: $($vcenterResult.StatusCode)"
            }
        } catch {
            return "Cannot reach ollama.com. Error: $($_.Exception.Message)"
        }
    }

    # Test 24: Check if Ops Man is already installed
    $global:opsmanResult = $null
    Run-Test -TestName "Tanzu Operations Manager is not installed" -TestCode {
        try {
            $global:opsmanResult = Invoke-WebRequest -Uri https://$OpsManagerFQDN -SkipCertificateCheck -Method GET -TimeoutSec 3 -ErrorAction stop
            return "Tanzu Operations Manager is already installed"
        } catch {
            return $true
        }
    }

    if ($opsmanResult) {
        # Test 25: Check if BOSH director is already installed
        Run-Test -TestName "BOSH Director is not installed" -TestCode {
            try {
                $productToCheck = "p-bosh"
                $deployedResult = Check-productDeployed -productName $productToCheck
                if (!$deployedResult){
                    return $true
                } else {
                    return "BOSH Director is already installed"
                }
            } catch {
                return "BOSH Director is already installed. Error: $($_.Exception.Message)"
            }
        }
        
        # Test 26: Check if Tanzu Platform Cloud Foundary is already installed
        Run-Test -TestName "Tanzu Platform Cloud Foundary is not installed" -TestCode {
            try {
                $productToCheck = "cf"
                $deployedResult = Check-productDeployed -productName $productToCheck
                if (!$deployedResult){
                    return $true
                } else {
                    return "Tanzu Platform Cloud Foundary is already installed"
                }
            } catch {
                return "Tanzu Platform Cloud Foundary is already installed. Error: $($_.Exception.Message)"
            }
        }
        
        # Test 27: Check if VMware Postgres is already installed
        Run-Test -TestName "VMware Postgres is not installed" -TestCode {
            try {
                $productToCheck = "postgres"
                $deployedResult = Check-productDeployed -productName $productToCheck
                if (!$deployedResult){
                    return $true
                } else {
                    return "VMware Postgres is already installed"
                }
            } catch {
                return "VMware Postgres is already installed. Error: $($_.Exception.Message)"
            }
        }
        
        # Test 28: Check if Tanzu GenAI is already installed
        Run-Test -TestName "Tanzu GenAI is not installed" -TestCode {
            try {
                $productToCheck = "genai"
                $deployedResult = Check-productDeployed -productName $productToCheck
                if (!$deployedResult){
                    return $true
                } else {
                    return "Tanzu GenAI is already installed"
                }
            } catch {
                return "Tanzu GenAI is already installed. Error: $($_.Exception.Message)"
            }
        }
    }

    # Test 29: Check if ssh-keygen is installed
    Run-Test -TestName "ssh-keygen is installed" -TestCode {
        if (Get-Command ssh-keygen -ErrorAction Stop) {return $true} else {return "ssh-keygen not installed"}
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
    
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
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
    if($debug) {My-Logger "${OMCLI} $configArgs"}
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
"@

    # Concat configuration to form final YAML
    $boshPayload = $boshPayloadStart + $singleAZString + $boshPayloadNetwork + $boshPayloadEnd
    $boshYaml = "bosh-director-config.yaml"
    $boshPayload > $boshYaml

    # Apply config
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "configure-director", "--config", "$boshYaml")
    if($debug) {My-Logger "${OMCLI} $configArgs"}
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Apply BOSH Director configuration failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Install BOSH Director
    $installArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "apply-changes")
    if($debug) {My-Logger "${OMCLI} $installArgs"}
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
    My-Logger "Uploading Tanzu Platform for Cloud Foundry tile to Tanzu Operations Manager (can take up to 15 mins)..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "upload-product", "--product", "$TPCFTile", "-r", "3600")
    if($debug) {My-Logger "${OMCLI} $configArgs"}
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Stage tile
    My-Logger "Adding Tanzu Platform for Cloud Foundry tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "stage-product", "--product-name", "$TPCFProductName", "--product-version", "$TPCFVersion")
    if($debug) { My-Logger "${OMCLI} $configArgs"}
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Generate wildcard cert and key
    $domainlist = "*.apps.$TPCFDomain,*.login.sys.$TPCFDomain,*.uaa.sys.$TPCFDomain,*.sys.$TPCFDomain,*.$TPCFDomain"
    $TPCFcert_and_key = & "$OMCLI" -k -t $OpsManagerFQDN -u $OpsManagerAdminUsername -p $OpsManagerAdminPassword generate-certificate -d $domainlist

    $pattern = "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\\n"
    $TPCFcert = [regex]::Match($TPCFcert_and_key, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    $pattern = "-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----\\n"
    $TPCFkey = [regex]::Match($TPCFcert_and_key, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

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
      primary: true
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
    if($debug) {My-Logger "${OMCLI} $configArgs"}
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # To improve install time, don't install TPCF just yet if postgres and GenAI tiles are to be installed also
    if($InstallTanzuAI -eq 0) {
        My-Logger "Installing Tanzu Platform for Cloud Foundry (can take up to 60 minutes)..."
        $installArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "apply-changes")
        if($debug) {My-Logger "${OMCLI} $installArgs"}
        & $OMCLI $installArgs 2>&1 >> $verboseLogFile
        if ($LASTEXITCODE -ne 0) {
            My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
            exit
        }
    }

}

if($setupPostgres -eq 1) {

    #My-Logger "Installing VMware Postgres..."

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
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "upload-product", "--product", "$PostgresTile", "-r", "3600")
    if($debug) {My-Logger "${OMCLI} $configArgs"}
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Stage tile
    My-Logger "Adding VMware Postgres tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "stage-product", "--product-name", "$PostgresProductName", "--product-version", "$PostgresVersion")
    if($debug) {My-Logger "${OMCLI} $configArgs"}
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
    if($debug) {My-Logger "${OMCLI} $configArgs"}
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    My-Logger "Installing Tanzu Platform for Cloud Foundry and VMware Postgres (can take up to 75 minutes)..."
    $installArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "apply-changes")
    if($debug) {My-Logger "${OMCLI} $installArgs"}
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
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "upload-product", "--product", "$GenAITile", "-r", "3600")
    if($debug) {My-Logger "${OMCLI} $configArgs"}
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    # Stage tile
    My-Logger "Adding Tanzu GenAI tile to Tanzu Operations Manager..."
    $configArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "stage-product", "--product-name", "$GenAIProductName", "--product-version", "$GenAIVersion")
    if($debug) {My-Logger "${OMCLI} $configArgs"}
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
  .errands.ollama_models:
    value:
    - azs:
      - $BOSHAZAssignment
      model_capabilities:
      - embedding
      model_name: $OllamaEmbedModel
      plan_name: nomic-embed-text
      plan_description: A high-performing open embedding model
      vm_type: cpu
    - azs:
      - $BOSHAZAssignment
      model_capabilities:
      - chat
      model_name: $OllamaChatModel
      vm_type: cpu
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
  .errands.ollama_models:
    value:
    - azs:
      - $BOSHAZAssignment
      model_name: $OllamaEmbedModel
      model_capabilities:
      - embedding
      plan_name: nomic-embed-text
      plan_description: A high-performing open embedding model
      vm_type: cpu
    - azs:
      - $BOSHAZAssignment
      model_name: $OllamaChatToolsModel
      model_capabilities:
      - chat
      - tools
      ollama_keep_alive: "-1"
      ollama_num_parallel: 1
      ollama_context_length: 131072
      ollama_kv_cache_type: q4_0
      ollama_flash_attention: true
      plan_name: mistral-nemo
      plan_description: mistral-nemo-12b-instruct-2407-q4_K_M with chat and tool capabilities
      disk_type: "153600"
      vm_type: cpu-2xlarge
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
    if($debug) {My-Logger "${OMCLI} $configArgs"}
    & $OMCLI $configArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    My-Logger "Installing Tanzu GenAI (can take up to 40 minutes)..."
    $installArgs = @("-k", "-t", "$OpsManagerFQDN", "-u", "$OpsManagerAdminUsername", "-p", "$OpsManagerAdminPassword", "apply-changes", "--product-name", "$GenAIProductName")
    if($debug) {My-Logger "${OMCLI} $installArgs"}
    & $OMCLI $installArgs 2>&1 >> $verboseLogFile
    if ($LASTEXITCODE -ne 0) {
        My-Logger "[Error] Previous step failed. Please see the following log for details: $verboseLogFile" -level Error -color Red
        exit
    }

    My-Logger "Tanzu GenAI successfully installed"
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
My-Logger "Follow the next steps at https://github.com/KeithRichardLee/Tanzu-GenAI-Platform-installer.git where you can learn how to push your first app! Or, alternatively..."
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
My-Logger "Note; you can download cf cli from https://apps.sys.$TPCFDomain/tools or https://github.com/cloudfoundry/cli/releases"