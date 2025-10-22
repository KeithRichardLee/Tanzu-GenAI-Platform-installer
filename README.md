# Tanzu GenAI Platform installer

TL;DR - A powershell script that automates the install of VMware Tanzu Platform, a private PaaS which includes GenAI capabilities, on VMware vSphere with minimal resource requirements.

The installer takes minimum set of parameters, validates them, and then performs the install of the platform which includes VMware Tanzu Operations Manager, BOSH Director, Cloud Foundry runtime, VMware Postgres, and GenAI service with models that have embedding, chat, and tools capabilities. Optionally, Tanzu Healthwatch (observability) and Tanzu Hub (global control plane) can be installed.

The script, when ran after an install with "stop" or "start", can stop or start the whole platform.

Note:
- The script uses what is known as the Small Footprint Tanzu Platform for Cloud Foundry which is a repackaging of Tanzu Platform for Cloud Foundry into a smaller deployment with fewer VMs which is perfect for POC and sandbox work.
- There are some limitations with small footprint which can be found [here](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-platform-for-cloud-foundry/10-2/tpcf/toc-tas-install-index.html#limits). 

For a much more comprehensive automated install of Tanzu Platform, which uses [Concourse](https://concourse-ci.org/), check out the [Platform Automation Toolkit for Tanzu](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/platform-automation-toolkit-for-tanzu/5-3/vmware-automation-toolkit/docs-index.html)

## Prerequisites
**VMware vSphere**
  - ESXi host/cluster (ESXi v7.x / v8.x / v9.x) with the following spare capacity...
    - Compute: ~51 vCPU, although only uses approx 5 GHz
    - Memory: ~85 GB
    - Storage: ~380 GB
  - User / service account with at least the [following privileges](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-operations-manager/3-1/tanzu-ops-manager/vsphere-vsphere-service-account.html)

**Networking**
  - IP addresses
    - A subnet with at least 13 free IP addresses including two static IP addresses
      - 1x Tanzu Operations Manger
      - 1x GoRouter 
    
  - DNS
    - 3 records created
      - 1x VMware Tanzu Operations Manager eg opsman.tanzu.lab
      - 1x Tanzu Platform system wildcard eg *.sys.tp.tanzu.lab which will resolve to the GoRouter IP
      - 1x Tanzu Platfrom apps wildcard eg *.apps.tp.tanzu.lab which will resolve to the GoRouter IP
   
  - NTP service

  - Firewall
    - Ability to reach registry.ollama.ai so Tanzu Platform can download AI models (Note: The script also supports airgapped / internet restricted environments, see "Advanced Config" section below for further details)
   
  - Certificates (optional)
    - By default, the installer creates a self-signed cert for TLS termination at the GoRouter. A user can provide their own cert if wished. See [here](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-platform-for-cloud-foundry/10-2/tpcf/security_config.html) for cert requirements. 

**Entitlement**
- If don't already have entitlement to Tanzu Platform, you can request a 90 day trial [here](https://support.broadcom.com/group/ecx/trials-program)

**Workstation/jump-host**
- [Powershell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) or later installed
- [VMware PowerCLI](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/powercli/installing-vmware-vsphere-powercli/install-powercli.html) installed eg `Install-Module VMware.PowerCLI`
- [OM CLI](https://github.com/pivotal-cf/om) installed
- Following files downloaded...
  - [VMware Tanzu Operations Manager](https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware%20Tanzu%20Operations%20Manager)
  - [Small Footprint Tanzu Platform for Cloud Foundry](https://support.broadcom.com/group/ecx/productdownloads?subfamily=Tanzu%20Platform%20for%20Cloud%20Foundry)
  - [VMware Tanzu Postgres](https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware+Tanzu+for+Postgres+on+Cloud+Foundry)
  - [VMware Tanzu GenAI](https://support.broadcom.com/group/ecx/productdownloads?subfamily=GenAI%20on%20Tanzu%20Platform%20for%20Cloud%20Foundry)
  - [VMware Tanzu Healthwatch](https://support.broadcom.com/group/ecx/productdownloads?subfamily=Healthwatch) (optional)
  - [VMware Tanzu Healthwatch Exporter](https://support.broadcom.com/group/ecx/productdownloads?subfamily=Healthwatch) (optional)
  - [VMware Tanzu Hub](https://support.broadcom.com/group/ecx/productdownloads?subfamily=Tanzu%20Hub) (optional)
- This repo cloned eg `git clone https://github.com/KeithRichardLee/Tanzu-GenAI-Platform-installer.git`


## Fill out required fields in the script
Update each instance of "FILL-ME-IN" in the script. See below for a worked example...

Update the path to the VMware Tanzu Operations Manager (OpsMan) OVA, Tanzu Platform for Cloud Foundry (TPCF) tile, VMware Postgres tile, VMware Tanzu GenAI tile, and OM CLI
```bash
### Full Path to Tanzu Operations Manager OVA, TPCF tile, Postgres tile, GenAI tile, and OM CLI
$OpsManOVA    = "/Users/Tanzu/Downloads/ops-manager-vsphere-3.1.3.ova"
$TPCFTile     = "/Users/Tanzu/Downloads/srt-10.2.3-build.2.pivotal"
$PostgresTile = "/Users/Tanzu/Downloads/postgres-10.1.1-build.1.pivotal"
$GenAITile    = "/Users/Tanzu/Downloads/genai-10.2.5.pivotal"
$OMCLI        = "/usr/local/bin/om"
```

Update infra config fields
```bash
### Infra config
$VIServer          = "vcenter.tanzu.lab"
$VIUsername        = "administrator@tanzu.lab"
$VIPassword        = 'my-super-safe-password!'
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

Update Tanzu Platform config fields
```bash
### Tanzu Platform config
$OpsManagerAdminPassword  = 'my-super-safe-password!'
$OpsManagerIPAddress      = "10.0.70.10"       
$OpsManagerFQDN           = "opsman.tanzu.lab"            
$BOSHNetworkReservedRange = "10.0.70.0-10.0.70.2,10.0.70.10,10.0.70.30-10.0.70.254"  #add IPs, either individual and/or ranges you _don't_ want BOSH to use in the subnet eg Ops Man, gateway, DNS, NTP, jumpbox
$TPCFGoRouter             = "10.0.70.20"                                             #IP which the Tanzu Platform system and apps domain resolves to. Choose an IP towards the end of available IPs
$TPCFDomain               = "tp.tanzu.lab"                                           #Tanzu Platform system and apps subdomains will be added to this. Resolves to the GoRouter IP
$TPCFLicenseKey           = ""                                                       #License key required for 10.2 and later
```

Update Healthwatch fields 
- Note; installing Healthwatch (observability) is optional. Installing Healthwatch requires an additional 11 IP addresses, 1 GHz CPU, 16 GB mem, and 100 GB storage.
```bash
### Install Healthwatch (observability)?
$InstallHealthwatch      = $true
$HealthwatchTile         = "/Users/Tanzu/Downloads/healthwatch-2.3.3-build.21.pivotal"                #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=Healthwatch
$HealthwatchExporterTile = "/Users/Tanzu/Downloads/healthwatch-pas-exporter-2.3.3-build.21.pivotal"   #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=Healthwatch
```

Update Tanzu Hub fields 
- Note; installing Tanzu Hub (global control plane) is optional. Installing Tanzu Hub requires an additional 13 IP addresses, 10 GHz CPU, 100 GB mem, and 400 GB storage.
```bash
### Install Tanzu Hub (global control plane)?
$InstallHub = $true
$HubTile    = "/Users/Tanzu/Downloads/tanzu-hub-10.2.1.pivotal"        #Download from https://support.broadcom.com/group/ecx/productdownloads?subfamily=Tanzu%20Hub
$HubFQDN    = "hub.tanzu.lab"
```

## (Optional) Advanced Config
There are several advanced parameters which can be changed if wished, for example...

Number of compute instances
```bash
$TPCFComputeInstances = "1" # default is 1. Increase if planning to run many large apps
```

User provided cert for GoRouter. With $userProvidedCert set to false (default) the installer creates a self-signed cert
```bash
# User provided cert (full chain) and private key for the apps and system wildcard domains
# see https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-platform-for-cloud-foundry/10-0/tpcf/security_config.html for details on creating this cert and key
$userProvidedCert = $false
$CertPath         = "/Users/Tanzu/certs/fullchain.pem"
$KeyPath          = "/Users/Tanzu/certs/privkey.pem"
```

AI models
```bash
# Tanzu AI Solutions config
$OllamaEmbedModel = "nomic-embed-text"
$OllamaChatToolsModel = "mistral-nemo:12b-instruct-2407-q4_K_M"
```

Airgapped / internet restricted environment 
```bash
# Be default, this script pulls the above models from Ollama (registry.ollama.ai). For internet restricted environments, you can download the models 
# separately using the links below and specify their location in the variables in the section below. This script will then create a MinIO object store, 
# upload the models to it, so the installer can then pull the models from it rather than from the internet.
#
# Please note, the MinIO BOSH Release is not Broadcom software, it is licensed under the AGPL 3.0 https://www.gnu.org/licenses/agpl-3.0.en.html

# Install MinIO BOSH Release (an object store for AI models in internet restricted envs)
$InstallMinIO  = $true
$MinioFolder   = "/Users/Tanzu/Downloads/minio-boshrelease"                                                        #Download / git clone https://github.com/kinjelom/minio-boshrelease.git
$MinioURL      = "/Users/Tanzu/Downloads/minio-boshrelease/minio-boshrelease-3.0.0+minio.2025-04-03T14-56-28Z.tgz" #Download release from https://github.com/kinjelom/minio-boshrelease/releases/
$MinioSHA      = "7156eb2aa6bdf5aa8ddb173c413ea796ceafcd25"                                                        #Retrieve SHA1 from https://github.com/kinjelom/minio-boshrelease/releases/
$MinioVersion  = "3.0.0+minio.2025-04-03T14-56-28Z"
$MinioUsername = "root"
$MinioPassword = 'VMware1!'
$MinioBucket   = "models"
$EmbedModelPath         = "/Users/Tanzu/Downloads/nomic-embed-text-v1.5.f16.gguf"                                  #Download from https://huggingface.co/nomic-ai/nomic-embed-text-v1.5-GGUF/resolve/main/nomic-embed-text-v1.5.f16.gguf
$ChatToolsModelPath     = "/Users/Tanzu/Downloads/Mistral-Nemo-Instruct-2407-Q4_K_M.gguf"                          #Download from https://huggingface.co/bartowski/Mistral-Nemo-Instruct-2407-GGUF/resolve/main/Mistral-Nemo-Instruct-2407-Q4_K_M.gguf
$ChatToolsModelFilePath = "/Users/Tanzu/Downloads/mistral-nemo-instruct-2407-Q4_K_M_modelfile.txt"                 #Download from https://huggingface.co/keithrichardlee/mistral-nemo/resolve/main/mistral-nemo-12b-instruct-2407-q4_K_M_modelfile.txt
$BOSHCLI                = "/usr/local/bin/bosh"                                                                    #Download from https://github.com/cloudfoundry/bosh-cli/releases
$MCCLI                  = "/usr/local/bin/mc"                                                                      #Download from https://github.com/minio/mc 
```

## Run the script
- Open a powershell console eg `pwsh`
- Execute the script eg `tanzu-genai-platform-installer.ps1`
- Installation can take up to 3 hours. Install time depends on the performance of your underlying infrastructure. 

- Note; if this is your first time using Powershell with the VMware PowerCLI module, you may be prompted to participate in the VMware CEIP. You can accept/deny so not prompted again by running `Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $true or $false`

## Example of script output
![Config](images/tanzu-genai-platform-installer-config.png)
![Prechecks](images/tanzu-genai-platform-installer-prechecks.png)
![Install](images/tanzu-genai-platform-installer-install.png)

# Next steps: Deploy a sample app
Below we will deploy a Spring chatbot application which can consume AI services by the platform

## Prerequisites
- Retrieve UAA admin credentials
  - The script on completion will print out the admin credentials for Tanzu Apps Manager and CF CLI, alternatively, you can retrieve them via Tanzu Operations Manager > Small Footprint Tanzu Platform for Cloud Foundry > Credentials > UAA > Admin Credentials

- Download CF CLI and login to the platform
  -  The above script on completion will print out how to download cf cli and how to run `cf login`, alternatively, see the [install docs](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-platform-for-cloud-foundry/10-2/tpcf/install-go-cli.html) and [login docs](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-platform-for-cloud-foundry/10-2/tpcf/getting-started.html)

- Create an Org and a Space
    - Create an Org
    ```bash
    cf create-org tanzu-demos-org
    ```
    - Create a Space
    ```bash
    cf create-space tanzu-demos-space -o tanzu-demos-org
    ```
    - Target an Org and Space
    ```bash
    cf target -o tanzu-demos-org -s tanzu-demos-space
    ```

- Download JDKs & SDKs
  - Note; [sdkman](https://sdkman.io) is a great tool for installing and managing many versions of various JDKs and SDKs
  - Java 21 or later
    - Install Java 21 if not already installed
    ```bash
    sdk install java 21.0.7-oracle
    ```
    - If already installed, make Java 21 the current candiate version, or which ever candidate version you have installed
    ```bash
    sdk use java 21.0.7-oracle
    ```
  - Maven 3.8 or later
    - Install Maven if not already installed
    ```bash
    sdk install maven
    ```
    - If you have Maven already installed, make Maven 3.8 or later the current candiate version, or which ever candidate version you have installed
    ```bash
    sdk use maven 3.9.10
    ```
- Clone git repos
  ```bash
  git clone https://github.com/cpage-pivotal/cf-mcp-client
  git clone https://github.com/kirtiapte/bitcoin-mcp-server
  ```

## Deploy chat app

### Build the app
```bash
cd cf-mcp-client
mvn clean package
```

### Push the app to the platform
```bash
cf push
```

### Access the app
1. Retrieve the URL to the app
```bash
cf apps
```

2. Open the app in a browser and ask it a question!


### Bind to a LLM model
1. View services available
```bash
cf marketplace
```

2. View genai services available
```bash
cf marketplace -e genai
```

3. Create a service instance that provides chat LLM capabilities
```bash
cf create-service genai chat-and-tools-model chat-llm
```

4. Bind the service to the app
```bash
cf bind-service ai-tool-chat chat-llm
```

5. Restart the app to apply the binding
```bash
cf restart ai-tool-chat
```

Now the chatbot will use the LLM to respond to chat requests

Ask it for the current price of bitcoin!


### Bind to services so can do RAG
1. View genai services available
```bash
cf marketplace -e genai
```

2. Create a service instance that provides embedding LLM capabilities
```bash
cf create-service genai embedding-model embedding-llm
```

3. View postgres services available
```bash
cf marketplace -e postgres
```

4. Create a Postgres service instance to use as a vector database

```bash
cf create-service postgres on-demand-postgres-db vector-db
```

5. Bind the services to the app

```bash
cf bind-service ai-tool-chat embedding-llm 
cf bind-service ai-tool-chat vector-db
```
Note; if it fails to bind the vector-db, it may be that the Postgres DB is still being created from the previous command. You can confirm by running "cf services" and checking the "last operation" field. 

6. Restart the app to apply the binding

```bash
cf restart ai-tool-chat
```

7. Click on the document tool on the right-side of the screen, and upload a .PDF File

Now your chatbot will respond to queries about the uploaded document

### Deploy a MCP server
Model Context Protocol (MCP) servers are lightweight programs that expose specific capabilities to AI models through a standardized interface. These servers act as bridges between LLMs and external tools, data sources, or services, allowing your AI application to perform actions like searching databases, accessing files, or calling external APIs without complex custom integrations.

1. Build the app
```bash
cd ../bitcoin-mcp-server
mvn clean package
```

2. Push the app to the platform
```bash
cf push
```

3. Retrieve the URL to the bitcoin app
```bash
cf apps
```

4. Create a user-provided service that provides the URL for the bitcoin MCP server
```bash
cf cups bitcoin-mcp-server -p '{"mcpServiceURL":"http://bitcoin-mcp-server.apps.tp.tanzu.lab"}'
```

5. Bind the MCP service to your chatbot app
```bash
cf bind-service ai-tool-chat bitcoin-mcp-server
```

6. Restart your chatbot app
```bash
cf restart ai-tool-chat
```

Your chatbot will now register with the MCP server, and the LLM will be able to invoke the agent's capabilities when responding to chat requests

Ask it for the current price of bitcoin

Congratulations, you have come to the end of this quick start guide. We have barely scratched the surface of the GenAI capabilities of the platform, or the vast capabilities of the platform as a whole. To learn more, please see official documentation and resources below.

# Appendix

## Stop / Start Tanzu Platform
- After a successful install, you can stop / shutdown the whole Tanzu Platform should the scenario arise eg need to release resources or shutdown the host(s) eg in a home lab. You can then also start it back up.
- The script will...
  - Document the environment
  - Perform a health check
  - Disable resurrector (if enabled)
  - Shutdown the platform deployments
  - Shutdown BOSH Director and Ops Manager

 - And for start / power-up...
   - Start Ops Manager and BOSH Director
   - Unlock Ops Manager
   - Start the platform deployments
   - Perform a health check

- To stop / shutdown the platform
```bash
.\tanzu-ai-starter-kit-installer.ps1 stop
```

- To start / power-up the platform
```bash
.\tanzu-ai-starter-kit-installer.ps1 start
```

## Resources
- [VMware Tanzu AI Solutions website](https://www.vmware.com/solutions/app-platform/ai)
- [VMware Tanzu AI Solutions blogs, webinars, videos](https://github.com/KeithRichardLee/VMware-Tanzu-Guides/blob/main/Tanzu-AI-Solutions/Tanzu-AI-Solutions-resources.md)
- [VMware Tanzu Platform Marketplace Services](https://github.com/KeithRichardLee/VMware-Tanzu-Guides/blob/main/Tanzu-Platform/Tanzu-Platform-Marketplace-Services.md)
- [How to install MinIO object storage server to host Ollama and vLLM models offline](https://github.com/KeithRichardLee/VMware-Tanzu-Guides/blob/main/Tanzu-AI-Solutions/how-to-install-minio-to-host-ollama-and-vllm-models-offline.md)

## Documentation
- [VMware Tanzu Operations Manager](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-operations-manager/3-1/tanzu-ops-manager/index.html)
- [Small Footprint Tanzu Platform for Cloud Foundry](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-platform-for-cloud-foundry/10-2/tpcf/concepts-overview.html)
- [VMware Tanzu Postgres](https://techdocs.broadcom.com/us/en/vmware-tanzu/data-solutions/tanzu-for-postgres-on-cloud-foundry/10-1/postgres/index.html)
- [VMware Tanzu GenAI](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform-services/genai-on-tanzu-platform-for-cloud-foundry/10-2/ai-cf/index.html)
- [VMware Tanzu Healthwatch](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform-services/healthwatch-for-vmware-tanzu/2-3/healthwatch/index.html)
- [VMware Tanzu Hub](https://techdocs.broadcom.com/us/en/vmware-tanzu/platform/tanzu-hub/10-2/tnz-hub/index.html)

## Troubleshooting
- An install log can be found where you run the script from with a file name of tanzu-genai-platform-installer.log. It contains verbose logging.

- If you wish to just install upto a certain component, or skip a step, you can by changing the Installer Overrides flags in the Advanced Parameters section in the script
```bash
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
```

- If the install of a component fails due to a permissions/privileges warning (verify in the installer log), you can override the warning by setting the ignoreWarnings flag to $true in the Advanced Parameters section of the script
```bash
# Installer Overrides
$ignoreWarnings = $true
```

## Help!
If you find a bug or need help, please open an [issue](https://github.com/KeithRichardLee/Tanzu-GenAI-Platform-installer/issues)

PR's most welcome too!

## Pre-checks
Below are the pre-checks the script performs...

- Files
  - VMware Tanzu Operations Manager OVA exists
  - VMware Tanzu Platform for Cloud Foundry tile exists
  - VMware Tanzu Postgres tile exists
  - VMware Tanzu GenAI tile exists
  - VMware Tanzu Healthwatch tile exists
  - VMware Tanzu Healthwatch Exporter tile exists
  - VMware Tanzu Hub tile exists

- Network
  - Network gateway can be reached
  - vCenter can be reached
  - DNS server can be reached
  - NTP server can be reached
  - NTP server responds to a NTP query
  - Reserved range in valid format
  - Enough free IP addresses available
  - IP addresses are available
  - Tanzu Operations Manager IP is in reserved range
  - GoRouter is not in the reserved range
  - Tanzu Operations Manager IP is available
  - GoRouter IP is available
  - Tanzu Operations Manager DNS entry is valid
  - Apps domain wildcard DNS entry is valid
  - System domain wildcard DNS entry is valid
  - Apps domain resolves to GoRouter IP
  - System domain resolves to GoRouter IP
  - Connectivity to registry.ollama.ai
  - User provided cert and key exists
  - User provided cert is valid

- vSphere
  - vCenter credentials are valid
  - vCenter user / service account has required vSphere API permissions
  - Datacenter object is valid
  - Resource pool object is valid
  - Datastore object is valid
  - Portgroup object is valid
  - Enough CPU resources available
  - Enough memory resources available
  - Enough storage available

- Platform
  - VMware Tanzu Operations Manager is not already installed
  - BOSH Director is not already installed
  - VMware Tanzu Platform for Cloud Foundry is not already installed
  - VMware Tanzu Postgres is not already installed
  - VMware Tanzu GenAI is not already installed
  - VMware Tanzu Healthwatch is not already installed
  - VMware Tanzu Healthwatch Exporter is not already installed
  - VMware Tanzu Platform license key is in valid format

- Other
  - OM CLI is installed
  - PowerCLI module is installed
  - ssh-keygen is installed

## Validation
The script was validated against the following versions...
- **Tanzu Operations Manager:** ops-manager-vsphere-3.1.3.ova
- **Tanzu Platform for Cloud Foundry small footprint:** srt-10.2.3-build.2.pivotal
- **VMware Postgres:** postgres-10.1.1-build.1.pivotal
- **Tanzu GenAI:** genai-10.2.5.pivotal
- **Healthwatch:** healthwatch-2.3.3-build.21.pivotal
- **Healthwatch Exporter:** healthwatch-pas-exporter-2.3.3-build.21.pivotal
- **Tanzu Hub:** tanzu-hub-10.2.1.pivotal
- **OM CLI:** 7.16
- **Powershell:** 7.5.1
- **PowerCLI:** 13.3.0
- **CF CLI:** 10.2
- **cf-mcp-client:** 2.0
- **vSphere:** 8U3 & 9.0

## Credits
Shoutout to [William Lam](https://williamlam.com/) as used his Nested PKS script from 2018 as inspiration for this script.
