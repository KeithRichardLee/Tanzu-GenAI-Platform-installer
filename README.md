# Tanzu-GenAI-Platform-installer

TL;DR - A powershell script that automates the install of VMware Tanzu Platform, a private PaaS which includes GenAI capabilites, on VMware vSphere with minimal resource requirements.

The installer takes minimum set of parameters, validates them, and then performs the install of the platform which includes VMware Tanzu Operations Manager, BOSH Director, Cloud Foundry runtime, VMware Postgres, and GenAI service with models that have embedding, chat, and tools capabilities. Note, the script uses what is known as the Small Footprint Tanzu Platform for Cloud Foundry which is a repackaging of Tanzu Platform for Cloud Foundry into a smaller deployment with fewer VMs which is perfect for POC and sandbox work. Note, there are some limitations with small footprint which can be found [here](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-platform-for-cloud-foundry/10-0/tpcf/toc-tas-install-index.html#limits). For a much more comprehensive automated install of Tanzu Platform, which uses [Concourse](https://concourse-ci.org/), check out the [Platform Automation Toolkit for Tanzu](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/platform-automation-toolkit-for-tanzu/5-2/vmware-automation-toolkit/docs-index.html)

## Prerequisites
**VMware ESXi host/cluster (ESXi v7.x or v8.x) with the following spare capacity...**
  - Compute: ~40 vCPU, although only uses approx 5 GHz
  - Memory: ~100 GB
  - Storage: ~400 GB

**Networking**
  - IP addresses
    - A subnet with approximately 15 free IP addresses including two static IP addresses
      - 1x Tanzu Operations Manger
      - 1x GoRouter 
    
  - DNS
    - 3 records created
      - 1x VMware Tanzu Operations Manager eg opsman.tanzu.lab
      - 1x Tanzu Platform system wildcard eg *.sys.tp.tanzu.lab which will resolve to the GoRouter IP
      - 1x Tanzu Platfrom apps wildcard eg *.apps.tp.tanzu.lab which will resolve to the GoRouter IP
   
  - NTP service

  - Firewall
    - Ability to reach ollama.com so Tanzu Platform can download AI models (Note: Airgapped is supported but not covered in this guide & script at present. Please see [here](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform-services/genai-on-tanzu-platform-for-cloud-foundry/10-0/ai-cf/tutorials-offline-model-support.html) for offline model support)

**Workstation/jump-host**
- [Powershell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) or later installed
- [VMware PowerCLI](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/powercli/installing-vmware-vsphere-powercli/install-powercli.html) installed eg `Install-Module VMware.PowerCLI`
- [OM CLI](https://github.com/pivotal-cf/om) installed
- Following files downloaded...
  - [VMware Tanzu Operations Manager](https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware%20Tanzu%20Operations%20Manager)
  - [Small Footprint Tanzu Platform for Cloud Foundry](https://support.broadcom.com/group/ecx/productdownloads?subfamily=Tanzu%20Platform%20for%20Cloud%20Foundry)
  - [VMware Postgres](https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware+Tanzu+for+Postgres+on+Cloud+Foundry)
  - [GenAI for Tanzu Platform](https://support.broadcom.com/group/ecx/productdownloads?subfamily=GenAI%20on%20Tanzu%20Platform%20for%20Cloud%20Foundry)
- This repo cloned eg `git clone https://github.com/KeithRichardLee/Tanzu-GenAI-Platform-installer.git`


## Fill out required fields in the script
Update each instance of "FILL-ME-IN" in the script. See below for a worked example...

Update the path to the VMware Tanzu Operations Manager (OpsMan) OVA, Tanzu Platform for Cloud Foundry (TPCF) tile, VMware Postgres tile, VMware Tanzu GenAI tile, and OM CLI
```bash
### Full Path to Tanzu Operations Manager OVA, TPCF tile, Postgres tile, GenAI tile, and OM CLI
$OpsManOVA    = "/Users/Tanzu/Downloads/ops-manager-vsphere-3.0.40+LTS-T.ova"
$TPCFTile     = "/Users/Tanzu/Downloads/srt-10.0.5-build.2.pivotal"
$PostgresTile = "/Users/Tanzu/Downloads/postgres-10.0.0-build.31.pivotal"
$GenAITile    = "/Users/Tanzu/Downloads/genai-10.0.3.pivotal"
$OMCLI        = "/usr/local/bin/om"
```

Update infra details
```bash
### Infra config
$VIServer          = "vcenter.tanzu.lab"
$VIUsername        = "administrator@tanzu.lab"
$VIPassword        = "my-super-safe-password!"
$VMDatacenter      = "Tanzu-DC"
$VMCluster         = "Tanzu-Cluster"
$VMResourcePool    = "Tanzu-Platform-RP"
$VMDatastore       = "vsanDatastore"
$VirtualSwitchType = "VSS"       
$VMNetwork         = "tp-network-70" 
$VMNetworkCIDR     = "10.0.70.0/24"  
$VMNetmask         = "255.255.255.0"
$VMGateway         = "10.0.70.1"
$VMDNS             = "10.0.70.1"
$VMNTP             = "10.0.70.1"
```

Update Tanzu Platform config
```bash
### Tanzu Platform config
$OpsManagerAdminPassword  = "my-super-safe-password!"   
$OpsManagerIPAddress      = "10.0.70.10"       
$OpsManagerFQDN           = "opsman.tanzu.lab"            
$BOSHNetworkReservedRange = "10.0.70.0-10.0.70.2,10.0.70.10"  #add IPs, either individual and/or ranges you _don't_ want BOSH to use in the subnet eg Ops Man, gateway, DNS, NTP, jumpbox
$TPCFGoRouter             = "10.0.70.100"                     #IP which the Tanzu Platform system and apps domain resolves to
$TPCFDomain               = "tp.tanzu.lab"                    #Tanzu Platform system and apps subdomains will be added to this. Resolves to the GoRouter IP
```


## Run the script
- Open a powershell console eg `pwsh`
- Execute the script eg `tanzu-genai-platform-installer.ps1`
- Installation can take up to 2.5 hours. Install time depends on the performance of your underlying infrastructure. 

- Note; if this is your first time using Powershell with the VMware PowerCLI module, you may be promted participate in the VMware CEIP. You can accept/deny so not prompted again by running `Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $true or $false`

## Example of script output
```bash

Please confirm the following configuration will be deployed:

---- Installer required files ----
Tanzu Operations Manager OVA path: /Users/Tanzu/Downloads/ops-manager-vsphere-3.0.40+LTS-T.ova
Tanzu Platform for Cloud Foundry tile path: /Users/Tanzu/Downloads/srt-10.0.5-build.2.pivotal
VMware Postgres tile path: /Users/Tanzu/Downloads/postgres-10.0.0-build.31.pivotal
GenAI tile path: /Users/Tanzu/Downloads/genai-10.0.3.pivotal
OM CLI path: /usr/local/bin/om

---- vCenter Configuration ----
vCenter Server: vcenter.tanzu.lab
Datacenter: Tanzu-DC
Datastore: vsanDatastore
Disk type: Thin
VMs folder: tpcf_vms
Templates folder: tpcf_templates
Disks folder: tpcf_disk

---- Tanzu Operations Manager Configuration ----
IP Address: 10.0.70.10
FQDN: opsman.tanzu.lab
Username: admin
Password: my-super-safe-password!
Decryption Password: my-super-safe-password!

---- BOSH Director Configuration ----
AZ Config
AZ Name: az1
AZ Cluster: Tanzu-Cluster
AZ Resource Pool: Tanzu-Platform-RP

Network Config
Network Name: tp-network
Network Portgroup: tp-network-70
Network CIDR: 10.0.70.0/24
Network Gateway: 10.0.70.1
Reserved IP Range: 10.0.70.0-10.0.70.2,10.0.70.10
DNS: 10.0.70.1
NTP: 10.0.70.1

Enable human readable names: True
ICMP checks enabled: True
Include Tanzu Ops Manager Root CA in Trusted Certs: True

---- Tanzu Platform for Cloud Foundry Configuration ----
AZ: az1
Network: tp-network
System Domain: sys.tp.tanzu.lab
Apps Domain: apps.tp.tanzu.lab
GoRouter IP: 10.0.70.100
GoRouter wildcard cert SAN: *.apps.tp.tanzu.lab,*.login.sys.tp.tanzu.lab,*.uaa.sys.tp.tanzu.lab,*.sys.tp.tanzu.lab,*.tp.tanzu.lab

---- Tanzu AI Solutions Configuration ----
Ollama embedding model: nomic-embed-text
Ollama chat & tools model: mistral-nemo:12b-instruct-2407-q4_K_M

Would you like to proceed with this deployment?

Do you accept (Y or N): y
[05-12-2025_23:10:49] Validating inputs...
[05-12-2025_23:11:06] Input validation complete
[05-12-2025_23:11:06] ======================================================
[05-12-2025_23:11:06]                 INPUT VALIDATION RESULTS
[05-12-2025_23:11:06] ======================================================
[05-12-2025_23:11:06] [PASS] OM CLI exists
[05-12-2025_23:11:06] [PASS] Tanzu Operations Manager OVA file exists
[05-12-2025_23:11:06] [PASS] Tanzu Platform for Cloud Foundry tile file exists
[05-12-2025_23:11:06] [PASS] Postgres tile file exists
[05-12-2025_23:11:06] [PASS] GenAI tile file exists
[05-12-2025_23:11:06] [PASS] VMware PowerCLI module installed
[05-12-2025_23:11:06] [PASS] vCenter connectivity
[05-12-2025_23:11:06] [PASS] vCenter credentials
[05-12-2025_23:11:06] [PASS] Datacenter validation
[05-12-2025_23:11:06] [PASS] Cluster validation
[05-12-2025_23:11:06] [PASS] Resource Pool validation
[05-12-2025_23:11:06] [PASS] Datastore validation
[05-12-2025_23:11:06] [PASS] Network Portgroup validation
[05-12-2025_23:11:06] [PASS] Gateway connectivity
[05-12-2025_23:11:06] [PASS] DNS server connectivity
[05-12-2025_23:11:06] [PASS] NTP server connectivity
[05-12-2025_23:11:06] [PASS] Tanzu Operations Manager IP available
[05-12-2025_23:11:06] [PASS] GoRouter IP available
[05-12-2025_23:11:06] [PASS] Tanzu Operations Manager DNS entry
[05-12-2025_23:11:06] [PASS] Wildcard apps domain DNS entry
[05-12-2025_23:11:06] [PASS] Wildcard system domain DNS entry
[05-12-2025_23:11:06] [PASS] Wildcard apps and system domains resolve to GoRouter IP
[05-12-2025_23:11:06] [PASS] ollama.com connectivity
[05-12-2025_23:11:06] [PASS] Tanzu Operations Manager is not installed
[05-12-2025_23:11:06] [PASS] ssh-keygen is installed
[05-12-2025_23:11:06] ======================================================
[05-12-2025_23:11:06] Summary: 25 tests passed, 0 tests failed
[05-12-2025_23:11:06] ======================================================
[05-12-2025_23:11:06] Input validation tests passed. Proceeding with install...
[05-12-2025_23:11:06] Installing Tanzu Operations Manager...
[05-12-2025_23:14:56] Tanzu Operations Manager installed
[05-12-2025_23:14:56] Powering on Tanzu Operations Manager...
[05-12-2025_23:14:56] Waiting for Tanzu Operations Manager to come online...
[05-12-2025_23:15:17] Tanzu Operations Manager is not ready yet, sleeping 30 seconds...
[05-12-2025_23:16:08] Tanzu Operations Manager is not ready yet, sleeping 30 seconds...
[05-12-2025_23:16:59] Tanzu Operations Manager is not ready yet, sleeping 30 seconds...
[05-12-2025_23:17:50] Tanzu Operations Manager is not ready yet, sleeping 30 seconds...
[05-12-2025_23:18:20] Setting up Tanzu Operations Manager authentication...
[05-12-2025_23:19:13] Tanzu Operations Manager authentication configured
[05-12-2025_23:19:13] Installing BOSH Director (can take up to 15 minutes)...
[05-12-2025_23:32:03] BOSH Director successfully installed
[05-12-2025_23:32:04] Uploading Tanzu Platform for Cloud Foundry tile to Tanzu Operations Manager (can take up to 15 mins)...
[05-12-2025_23:44:28] Adding Tanzu Platform for Cloud Foundry tile to Tanzu Operations Manager...
[05-12-2025_23:44:34] Applying Tanzu Platform for Cloud Foundry configuration...
[05-12-2025_23:44:40] Uploading VMware Postgres tile to Tanzu Operations Manager...
[05-12-2025_23:45:43] Adding VMware Postgres tile to Tanzu Operations Manager...
[05-12-2025_23:45:46] Applying VMware Postgres configuration...
[05-12-2025_23:45:49] Installing Tanzu Platform for Cloud Foundry and VMware Postgres (can take up to 75 minutes)...
[05-13-2025_01:03:28] Tanzu Platform for Cloud Foundry and VMware Postgres successfully installed
[05-13-2025_01:03:30] Uploading Tanzu GenAI tile to Tanzu Operations Manager...
[05-13-2025_01:08:36] Adding Tanzu GenAI tile to Tanzu Operations Manager...
[05-13-2025_01:08:41] Applying Tanzu GenAI configuration...
[05-13-2025_01:08:45] Installing Tanzu GenAI (can take up to 40 minutes)...
[05-13-2025_01:55:26] Tanzu GenAI successfully installed
[05-13-2025_01:55:26] ======================================================
[05-13-2025_01:55:26]                 Installation Complete!
[05-13-2025_01:55:26] ======================================================
[05-13-2025_01:55:26] StartTime: 05/12/2025 23:10:44
[05-13-2025_01:55:26]   EndTime: 05/13/2025 01:55:26
[05-13-2025_01:55:26]  Duration: 164.71 minutes
[05-13-2025_01:55:26]
[05-13-2025_01:55:26] Installation log: tanzu-genai-platform-installer.log
[05-13-2025_01:55:26]
[05-13-2025_01:55:28] ======================================================
[05-13-2025_01:55:28]                 Next steps...
[05-13-2025_01:55:28] ======================================================
[05-13-2025_01:55:28] Follow the next steps guide at https://github.com/KeithRichardLee/Tanzu-GenAI-Platform-installer where you can learn how to push your first app! Or, alternatively...
[05-13-2025_01:55:28]
[05-13-2025_01:55:28] Log into Tanzu Operations Manager
[05-13-2025_01:55:28] - Open a browser to https://opsman.tanzu.lab
[05-13-2025_01:55:28] - Username: admin
[05-13-2025_01:55:28] - Password: my-super-safe-password!
[05-13-2025_01:55:28]
[05-13-2025_01:55:28] Log into Tanzu Apps Manager
[05-13-2025_01:55:28] - Open a browser to https://apps.sys.tp.tanzu.lab
[05-13-2025_01:55:28] - Username: admin
[05-13-2025_01:55:28] - Password: eFdVbZI7OxQ_VpBxEUBLy7cbKFY_f57q
[05-13-2025_01:55:28]
[05-13-2025_01:55:28] Use Cloud Foundry CLI (cf cli) to push and manage apps, create and bind services, and more
[05-13-2025_01:55:28] - cf login -a https://api.sys.tp.tanzu.lab -u admin -p eFdVbZI7OxQ_VpBxEUBLy7cbKFY_f57q --skip-ssl-validation
[05-13-2025_01:55:28] Note; you can download cf cli from https://apps.sys.tp.tanzu.lab/tools or https://github.com/cloudfoundry/cli/releases
```


## Next steps

### Deploy a sample app
- Retrieve UAA admin credentials
  - The script on completion will print out the admin credentials for Tanzu Apps Manager and CF CLI, alternatively, you can retrieve them via Tanzu Operations Manager > Small Footprint Tanzu Platform for Cloud Foundry > Credentials > UAA > Admin Credentials
- Create an Org and a Space using either Tanzu Apps Manager or cf CLI for where we can deploy a sample app
  - **Tanzu Apps Manager**
    - The script on completion will print out the Tanzu Apps Manager URL and credentials, alternatively, see the docs [here](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-platform-for-cloud-foundry/10-0/tpcf/console-login.html) on how to access and use Apps Manager 
  - **CF CLI**
    -  The script on completion will print out how to download cf cli and how to run `cf login`, alternatively, see the [install docs](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-platform-for-cloud-foundry/10-0/tpcf/install-go-cli.html) and [login docs](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-platform-for-cloud-foundry/10-0/tpcf/getting-started.html)
    - Create an Org eg
      - `cf create-org tanzu-demos-org`
    - Create a Space eg
      - `cf create-space demos-space -o tanzu-demos-org`
    - Target an Org and Space eg
      - `cf target -o tanzu-demos-org -s demos-space`
- Deploy a sample app
  - Download spring-music
    - `git clone https://github.com/cloudfoundry-samples/spring-music.git`
  - Build jar file
    - ```
      cd spring-music
      ./gradlew clean assemble
      ```
  - Run app
    - `cf push`
  - Verify app is running, retrieve route, and open app
    - `cf apps` 


## Troubleshooting
- An install log can be found where you run the script from with a file name of tanzu-genai-platform-installer.log. It contains verbose logging.
