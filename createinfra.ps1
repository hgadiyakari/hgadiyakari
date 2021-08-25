<#
.SYNOPSIS
    Deploys necessery virtual components in an Azure subscription, necessery to host a virtual machine.

.DESCRIPTION
    The script can perform the below tasks
    1. Create a ResourceGroup in the subscription mentioned, if not already exists.
    2. Deploy a vNet in the location mentioned.
    3. Create four Subnets in that vNet.
    4. Create four NSGs with necessery rules and link to those four subnets created in the previous step.
    5. Create one storage account each for Disk and Boot Dignostics storage.
    6. If Opted, Deploy a domaincontroller as the first DC in a root domain on a newlly created AD forest.
    7. Adds necessery Tags to the Virtual Machine hosting the domain controller.
    8. If Opted, assigns a public IP to the DC.
    9. Provide options to install and configure CrowdStroke Sensor.
    10. Provide options to install and configure OMS Agent. 
    11. Changes the DNS entry of the vNet to point to the Privare static IP of the DC.
    12. Restarts the DC to make the DNS IP change effective.

.NOTES
    File Name  : CreateInfra.ps1
    Author     : santanu.sengupta@dxc.com
    Date       : 24th April 2018

.EXAMPLE
    .\CreateInfra.ps1 "<subscription>" "<Location>" "<resource goup>" "<First Two Octant of vNet Network Address>" "<DomainAdminName>" "<DomainAdminPassword>" "<DomainControllerName>" "<DomainName>" "<PublicIPRequired(Y/N)>" "<OMSWorkspaceName>" "<WprkspaceKey>" "<CrowdStrikeCID>"
    .\CreateInfra.ps1 "testsubscription1" "austin1" "RG-Santanu" "10.10" "rootadmin" "abcd(efg@123" "SantestDC01" "santest.com" "Y" "a6f25532-2cb3-4c44-b4a3-34130cec3018" "JlPjdSkqgd+OG4gUX+CGjlpkT21bm2I1IokmRquvBDhJd+KTZm4Q51tISxEMJyG5yfdYwmyZ3k9xzFzHessswg==" "D37C5F63236A4FE69DEABB9893DCF41D-D3"
    .\CreateInfra.ps1 "DXC Dev EA 1" "West India" "RG-Santanu-VM-DontTouch" "10.50" "rootadmin" "abcd(efg@123" "SantestDC01" "santest.com" "Y" "d53cfdee-3d9a-4ec7-ae45-ef0adc80ec6b" "zRNd7De3pGevksvQD9ygo0Y3r4bB0hPyZH2ZilVn6LuiQKcfjYHi1Yq7umL+yMFKIzVoZS7oSCx1jX30m9NQ5Q==" "D37C5F63236A4FE69DEABB9893DCF41D-D3"

.LINK

#>


# parameters
[CmdletBinding(SupportsShouldProcess=$true)]
Param
(
   [Parameter(Mandatory=$true)] [String]$SUBSCRIPTION,
   [Parameter(Mandatory=$true)] [String]$DeployLocation,
   [Parameter(Mandatory=$true)] [String]$RESGROUP,
   [Parameter(Mandatory=$true)] [String]$vNetIPNetworkAddress,  
   [Parameter(Mandatory=$false)] [String]$AdminUserName,
   [Parameter(Mandatory=$false)] [String]$AdminPassword,
   [Parameter(Mandatory=$false)] [String]$DCName,
   [Parameter(Mandatory=$false)] [String]$DomainName,
   [Parameter(Mandatory=$false)] [ValidateSet('Y','N')] [String]$PublicIPRequired,
   [Parameter(Mandatory=$false)] [String]$OMSWorkspaceName,
   [Parameter(Mandatory=$false)] [String]$OMSWorkspaceKey,
   [Parameter(Mandatory=$false)] [String]$CrowdStrikeCID
)

# Declaring Variables 
$ErrorActionPreference = "SilentlyContinue"

$AzureStack = "N"
$ToolsDir = "C:\AzureStack-Tools-master"
$rannum = Get-Random -Maximum 10000
$ARMLocation = ($DeployLocation.replace(' ', '')).ToLower()
$SASToken = '?sv=2017-07-29&ss=b&srt=co&sp=rl&se=2025-04-24T11:23:11Z&st=2018-04-24T09:23:11Z&spr=https&sig=dLX76JFYpM0hpNQ7Gx4HV83F2le2YrQykqe%2FPCBtimU%3D'

$vNetName = $ARMLocation + "_vNet"
$vNetSubPrefix = $vNetIPNetworkAddress + ".0.0/16"

$BootDiagStorage = $ARMLocation + "bootdiag" + $rannum
$DiskStorage = $ARMLocation + "disk" + $rannum

#Login to Azure
if ($AzureStack -eq "Y")
    {
    # Import modules
    Write-Host "Importing necessery modules......." -ForegroundColor Green
    Import-Module $ToolsDir\Connect\AzureStack.Connect.psm1
    Import-Module $ToolsDir\computeAdmin\AzureStack.ComputeAdmin.psm1
    $MyAppID = "1a1728fa-9784-4749-8bdf-c8bb9c3235ad"
    $MyKey = "LCeEBgUO74Fmt+Y3NxXXI76Rj2YxL44ndWrLQ9XFHmo="

    $TenantName = "dxccsptest1.onmicrosoft.com"
    $ArmEndpointUser = "https://management.austin1.austinlab1mas.com"
    $ArmNameUser = "AzureStackAppUser"
    
    # Add endpoint user
    Add-AzureRMEnvironment -Name $ArmNameUser -ArmEndpoint $ArmEndpointUser

    # Get Tenant ID
    $TenantID = Get-AzsDirectoryTenantId -AADTenantName $TenantName -EnvironmentName $ArmNameUser

    $MyPass = ConvertTo-SecureString $MyKey -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential ($MyAppID, $MyPass)

     try  
        { 
        Login-AzureRmAccount -ServicePrincipal -Tenant $TenantID -EnvironmentName $ArmNameUser -Credential $mycreds
        Select-AzureRmSubscription -SubscriptionName $SUBSCRIPTION 
        }
    catch 
        {    
        Write-Host "WARNING: Unable to connect to Azure Stack. Check your internet connection and verify authentication details." -ForegroundColor Yellow
        exit 
        }    
    }
Else
    {
    try  
        { 
        Login-AzureRmAccount -Subscription $SUBSCRIPTION -ErrorAction Stop 
        }
    catch 
        {    
        Write-Host "WARNING: Unable to connect to Azure Public. Check your internet connection and verify authentication details." -ForegroundColor Yellow
        exit 
        }
    }
Write-Host " Connected to Azure with provided authentication." -ForegroundColor Green 

#Creating / Selecting Resourcegroup
Write-Host "`n`n Creating / Selecting Resourcegroup:" $RESGROUP -ForegroundColor Green
New-AzureRmResourceGroup -Name $RESGROUP -Location $DeployLocation -Force > $null

#Deploying vNet and NSGs
Write-Host "`n`n Deploying vNet and NSGs.........." -ForegroundColor Green

$ObjvNet = New-AzureRmVirtualNetwork -ResourceGroupName $RESGROUP -Location $DeployLocation -Name $vNetName -AddressPrefix $vNetSubPrefix -WarningAction silentlyContinue

$NSGRule1 = New-AzureRmNetworkSecurityRuleConfig -Name Allow-Internet-InBound -Description "AllowInternetInBound" -Access Allow -Protocol * -Direction Inbound -Priority 200 `
     -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange * -WarningAction silentlyContinue
$NSGRule2 = New-AzureRmNetworkSecurityRuleConfig -Name Allow-SSH -Description "Allow SSH" -Access Allow -Protocol Tcp -Direction Inbound -Priority 220 `
     -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 22 -WarningAction silentlyContinue
$NSGRule3 = New-AzureRmNetworkSecurityRuleConfig -Name Allow-RDP -Description "Allow RDP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 300 `
     -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 3389 -WarningAction silentlyContinue

Write-Host "`n vNet Name: " $vNetName "    Subnet Prefix: " $vNetSubPrefix -ForegroundColor Green
Write-Host "`n       Subnet Name                        --------------------------->  Connected NSG Name" -ForegroundColor Green

For ($i=0; $i-le 3 ; $i++) 
    { 
    $SubnetName = $vNetName + "-Sub" + ($i + 1) + "_" + $vNetIPNetworkAddress + "." + $i + ".x_24"
    if ($i -eq 0) {$DCSubnet = $SubnetName}
    $SubPrefix = $vNetIPNetworkAddress + "." + $i + ".0/24"

    $ObjNSG = New-AzureRmNetworkSecurityGroup -ResourceGroupName $RESGROUP -Location $DeployLocation -Name $SubnetName -SecurityRules $NSGRule1, $NSGRule2, $NSGRule3 -WarningAction silentlyContinue
    Add-AzureRmVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix $SubPrefix -VirtualNetwork $ObjvNet -NetworkSecurityGroup $ObjNSG -WarningAction silentlyContinue > $Null
    $ObjvNet | Set-AzureRmVirtualNetwork -WarningAction silentlyContinue > $Null

    Write-Host "      " $SubnetName " ---------------------------> " $SubnetName  -ForegroundColor Green
    }      

#Deploying Storages
Write-Host "`n`n Creating Storage acounts..........." -ForegroundColor Green

if ($AzureStack -eq "Y")
    {
    $ObjBootDiagStorage = New-AzureRmStorageAccount -ResourceGroupName $RESGROUP -Name $BootDiagStorage -Location $DeployLocation -Type Standard_LRS
    $ObjDiskStorage = New-AzureRmStorageAccount -ResourceGroupName $RESGROUP -Name $DiskStorage -Location $DeployLocation -Type Standard_LRS
    }
else
    {
    $ObjBootDiagStorage = New-AzureRmStorageAccount -ResourceGroupName $RESGROUP -Name $BootDiagStorage -Location $DeployLocation -SkuName Standard_LRS -Kind StorageV2
    $ObjDiskStorage = New-AzureRmStorageAccount -ResourceGroupName $RESGROUP -Name $DiskStorage -Location $DeployLocation -SkuName Standard_LRS -Kind StorageV2
    }


Write-Host "`n Boot Dignostic storage acount: "  $BootDiagStorage -ForegroundColor Green
Write-Host " Disk storage acount: "  $DiskStorage -ForegroundColor Green

#Deploy Domain Controller if parameters not NULL.
if ($AdminUserName -And $AdminPassword -And $DCName -And $DomainName)
    { 
    $DepartmentName = "Infrastructure"
    $Project = "Infrastructure"
    $nicName = $DCName + "-vNic"
    $DCPrivateIP = $vNetSubPrefix.Substring(0,8) + "4"

    $AdminPasswordSec = convertto-securestring $AdminPassword -asplaintext -force
    $Cred = New-Object System.Management.Automation.PSCredential($AdminUserName, $AdminPasswordSec)

    $OSDiskUri = (Get-AzureRMStorageAccount -ResourceGroupName $RESGROUP -Name $ObjDiskStorage.StorageAccountName).PrimaryEndpoints.Blob.ToString() + "vhds/" + $DCName + "-osDisk.vhd"
    $DataDiskUri = (Get-AzureRMStorageAccount -ResourceGroupName $RESGROUP -Name $ObjDiskStorage.StorageAccountName).PrimaryEndpoints.Blob.ToString() + "vhds/" + $DCName + "-dataDisk01.vhd"

    $JsonUri = 'https://dxcazuretools.blob.core.windows.net/installers/JSON/CreateADForest.json'

    #Creating Network Interface
    Write-Host "`n Creating Network Interface: "  $nicName " ........." -ForegroundColor Green
    $ObjvNet = Get-AzureRmVirtualNetwork -Name $vNetName -ResourceGroupName $RESGROUP -WarningAction silentlyContinue
    $SubnetID = (Get-AzureRmVirtualNetworkSubnetConfig -Name $DCSubnet -VirtualNetwork $ObjvNet -WarningAction silentlyContinue).Id
    $netInterface = New-AzureRmNetworkInterface -Name $nicName -ResourceGroupName $RESGROUP -Location $DeployLocation -SubnetId $SubnetID -PrivateIpAddress $DCPrivateIP  -WarningAction silentlyContinue

    Write-Host " Creating Windows 2016-Datacenter virtual machine named:" $DCName ".This will take several minutes......." -ForegroundColor Green
    $VirtualMachine = New-AzureRmVMConfig -VMName $DCName -VMSize Standard_A2 -WarningAction silentlyContinue
    $VirtualMachine = Set-AzureRmVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $DCName -Credential $Cred -ProvisionVMAgent -WarningAction silentlyContinue
    $VirtualMachine = Add-AzureRmVMNetworkInterface -VM $VirtualMachine -Id $netInterface.Id -WarningAction silentlyContinue
    $VirtualMachine = Set-AzureRmVMOSDisk -VM $VirtualMachine -Name ($DCName + "-osDisk") -VhdUri $OSDiskUri -Caching ReadOnly -CreateOption FromImage -WarningAction silentlyContinue
    $VirtualMachine = Set-AzureRmVMSourceImage -VM $VirtualMachine -PublisherName MicrosoftWindowsServer -Offer WindowsServer -Skus 2016-Datacenter -Version latest -WarningAction silentlyContinue
    Set-AzureRmVMBootDiagnostics -VM $VirtualMachine -Enable -ResourceGroupName $RESGROUP -StorageAccountName $ObjBootDiagStorage.StorageAccountName -WarningAction silentlyContinue > $null

    New-AzureRmVM -ResourceGroupName $RESGROUP -Location $DeployLocation -VM $VirtualMachine -WarningAction silentlyContinue > $null

    Write-Host "`n Adding data disk of size 32GB to" $DCName "........."    -ForegroundColor Green

    $ObjVM = Get-AzureRmVM -ResourceGroupName $RESGROUP -WarningAction silentlyContinue
    Add-AzureRmVMDataDisk -VM $ObjVM -Name ($DCName + "-dataDisk01") -VhdUri $DataDiskUri -LUN 0 -Caching ReadOnly -DiskSizeinGB 32 -CreateOption Empty > $null
    Update-AzureRmVM -ResourceGroupName $RESGROUP -VM $ObjVM > $null

    #Assigning Public IP if Opted.
    if ($PublicIPRequired -eq "Y")
        {
        Write-Host " Assigning Public IP........."    -ForegroundColor Green
        $pIPName = $DCName + "-publicIP"
        
        $pip = New-AzureRmPublicIpAddress -Name $pIPName -ResourceGroupName $RESGROUP -Location $DeployLocation -AllocationMethod Dynamic -WarningAction silentlyContinue
        $nic = Get-AzureRmNetworkInterface -ResourceGroupName $RESGROUP -Name $nicName -WarningAction silentlyContinue
        $nic.IpConfigurations[0].PublicIpAddress = $pip 
        Set-AzureRmNetworkInterface -NetworkInterface $nic > $null
        
        Write-Host " Public IP assigned : " (Get-AzureRmPublicIpAddress -Name $pIPName -ResourceGroupName $RESGROUP).IpAddress     -ForegroundColor Green
        }

    Write-Host "`n Promoting to Domain Controller for a new Domain named " $DomainName " in a new Forest. This may take several minutes.........."     -ForegroundColor Green

    New-AzureRmResourceGroupDeployment -Name CreateADForest -ResourceGroupName $RESGROUP -TemplateUri $JsonUri `
        -vmName $DCName -vmLocation $DeployLocation -adminName $AdminUserName -adminPassword $AdminPasswordSec -domainName $DomainName > $null

    Write-Host " Domain Controller promition completed."     -ForegroundColor Green

    #Adding Virtual Machine Tags
    $addTags  =   @{Application="domaincontroller";
                    DepartmentName="$DepartmentName".ToLower(); 
                    Project="$Project".ToLower();
                    DXC_AutoDeploy="true"}
                    
    Set-AzureRmResource -ResourceGroupName $RESGROUP -Name $DCName -ResourceType "Microsoft.Compute/VirtualMachines" -Force -Tag $addTags > $null
    Write-Host "`n Vitual machine Tags added."    -ForegroundColor Green
    
    #Installing CrowdStrike Extension if opted
    $Error.Clear()
    if ($CrowdStrikeCID)
        {
        Write-Host "`n Installing CrowdStrike Extension........"     -ForegroundColor Green


        $FileURL = 'https://dxcazuretools.blob.core.windows.net/locked-installers/crowdstrikeinstaller.ps1' + $SASToken + '&sr=b'
        $CSArg =  '-CID ' + $CrowdStrikeCID
        Set-AzureRmVMCustomScriptExtension -ResourceGroupName $RESGROUP -VMName $DCName -Location $DeployLocation -FileUri $FileURL `
            -Run 'crowdstrikeinstaller.ps1' -Argument $CSArg -Name "CrowdStrikeSensor" > $null 

        Write-Host " Installation of CrowdStrike Extension completed."     -ForegroundColor Green
        }  
     
    #Installing OMS Extension if opted
    $Error.Clear()
    if ($OMSWorkspaceName -And $OMSWorkspaceKey)
        {
        Write-Host "`n Installing OMS Agent.........."     -ForegroundColor Green
        $PublicSettings = @{"workspaceId" = $OMSWorkspaceName }
        $ProtectedSettings = @{"workspaceKey" = $OMSWorkspaceKey }
        Set-AzureRmVMExtension -ExtensionName "OMSAgent" -ResourceGroupName $RESGROUP -VMName $DCName -Location $DeployLocation `
            -Publisher "Microsoft.EnterpriseCloud.Monitoring" -ExtensionType "MicrosoftMonitoringAgent" `
            -TypeHandlerVersion 1.0 -Settings $PublicSettings -ProtectedSettings $ProtectedSettings  > $null

        Write-Host " Installation of OMS Agent completed."     -ForegroundColor Green
        }

    #Update vNet DNS IP and rebooting the Domain Controller
    Write-Host "`n Changing vNets DNS Server to point to Domain Controller........."     -ForegroundColor Green
    Start-Sleep -s 60
    $ObjvNet.DhcpOptions.DnsServers = $null
    $ObjvNet.DhcpOptions.DnsServers = $DCPrivateIP
    Set-AzureRmVirtualNetwork -VirtualNetwork $ObjvNet > $null

    Write-Host " Restarting Domain Controller........."     -ForegroundColor Green
    Restart-AzureRmVM -ResourceGroupName $RESGROUP -Name $DCName > $null
    Start-Sleep -s 60
    Write-Host " Finished building infrastructure for hosting Virtual Machines."     -ForegroundColor Green
    }
Write-Host "`n`n`n *********************************END OF SCRIPT*********************************** `n`n`n" -ForegroundColor Green