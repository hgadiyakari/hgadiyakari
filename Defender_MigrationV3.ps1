<#=================================================================================================================
Required - Powershell Version 7.0, Azure CLI Version 2.1.0
===================================================================================================================
===================================================================================================================
AUTHOR:  Mounika Allampalli
DATE:    20/07/2021
Version: 0.1
Confluence Doc: 

 (c) Copyright DXC Technology, 2021. All rights reserved
==================================================================================================================
.SYNOPSIS
Migration of all the VMs to use Azure Defender as SecurityAgent in Subscription
.DESCRIPTION
This script will pick up all the Windows VMs in a subscription pointed to by the Subscription parameter.It will
then installs Anti Malware on 20008R2 and 2012 R2 vms and runs the GPO Update(For both domain joined and workgroup).
Finally,If the VM also has CrowdStrike installed,it will remove it only on successful installation of AntiMalware.
.PARAMETER subscriptionId
(Required for all operations) The subscription id to be updated 
.PARAMETER tenantId
(Required for all Operations) The tenant id of the scription to be updated
#>

#Requires -PSEdition Core
#Requires -Version 7.0
#Requires -Modules @{ ModuleName="Az.Resources"; ModuleVersion="3.5.0" }
#Requires -Modules @{ ModuleName="Az.Monitor"; ModuleVersion="2.0.1" }

#Collect required parameters
[CmdletBinding(SupportsShouldProcess=$true)]
Param
    (
    [Parameter(Mandatory=$true)] [String]$subscriptionId,
    [Parameter(Mandatory=$true)] [String]$tenantId,
    [Parameter(Mandatory=$false)] [String]$BulkMaintenanceToken,
    [Parameter(Mandatory = $false)][String]$keyvault = ""
    )

#=====================================================================================================================
# Variables Declaration
#=====================================================================================================================

$WarningPreference = "SilentlyContinue"
$SettingString = ‘{ "AntimalwareEnabled": true, "Exclusions": { "Extensions": ".log,.ldf", "Paths":"D:\\IISlogs,D:\\DatabaseLogs", "Processes":"mssence.svc" }}'

#==========================================================================================================================
#validating windowsCSUninstall.ps1 & linuxCSUninstall.sh files exists in the root file
#========================================================================================================================== 
foreach( $module in ('windowsCSUninstall.ps1')) {
    $cModulePath = "$PSScriptRoot\$module"
    if(-not (Test-Path -Path $cModulePath)) {
        Write-Log "Unable to find and load $cModulePath. Verify that this files exists and try again."
        Exit
    }
}   
#=====================================================================================================================
# IMPORTCUSTOM MODULES AND CHECK ENVIRONMENT FOR NECESSERY MODULES
#=====================================================================================================================
$dxcModuleList = "DXCEnvCheckV2.psm1"
foreach ($dxcModule in $dxcModuleList)
    {
    [String]$dxcModuleURL = "https://dxcazuretoolsdev.blob.core.windows.net/installers/DXCPowershellModules/" + $dxcModule
    [String]$dxcLocalModule = $PSScriptRoot + "\" + $dxcModule
    (New-Object System.Net.WebClient).DownloadFile($dxcModuleURL, $dxcLocalModule)
    Import-Module $dxcLocalModule -WA 0
    Remove-Item -Path $dxcLocalModule
    }
$dxcPSCore = Check-PSCore -Version 7.0.0
if ($dxcPSCore) { $dxcAZ = Check-AzModule -Version 2.5.0 }
if ($dxcAZ) { $dxcAZCli = Check-AzureCLI -Version 2.1.0 }
if ($dxcAZCli) { $dxcAZStorage = Check-PSModule -Name "Az.Storage" -Version 1.5.1 }
if ($dxcAZStorage) { $dxcAZMonitor = Check-PSModule -Name "Az.Monitor" -Version 1.5.0 }
if ($dxcAZMonitor) { $dxcAZFunctions = Check-PSModule -Name "Az.Functions" -Version 1.0.0 }
if($dxcAZApplicationInsights){$dxcAZResource = Check-PSModule -Name "Az.Resources" -Version 3.5.0 }
if (!$dxcAZResource)
    {
    Read-Host "`nPress 'ENTER'to exit the script........"
    exit
    }

#=====================================================================================================================
# LOGIN SECTION
#=====================================================================================================================
$error.Clear()
Utility-LoginAZTenant -TenantId $TenantId -SubscriptionId $SubscriptionId
Utility-LoginAureCliTenant -TenantId $TenantId -SubscriptionId $SubscriptionId


#======================================================================================================================
#Functions
#======================================================================================================================
#========================================================================================================================
#Function for creating and writing to log file
#========================================================================================================================
Function Write-Log($logText){
    $logFile = "$PSscriptroot\ReplacingCSwithCWP.log"
    If(!(Test-Path $logFile)){New-Item -Path $logFile -ItemType File -Force}
    Out-File-FilePath ($logFile) -InputObject ("[" + (Get-Date).ToString("MM-dd-yyyy HH:mm:ss") + "] " + $logText) -Append -Encoding ascii
    Write-Host $logText -ForegroundColor Yellow
}
#========================================================================================================================
#Function for keyvault
#========================================================================================================================
Function getKeyVault {
    $rg = Get-AzResourceGroup -Name "DXC-Maint-RG"
    If ($rg.ProvisioningState -eq "Succeeded") {
            $kv = Get-AzKeyVault -ResourceGroupName "DXC-Maint-RG"
            If ($kv) {
                    return $kv.VaultName
            }
    }
    return $null
}
# If keyvault parameter is not input, attempt to get it from the 'DXC-Maint-RG' resource group.
if ($keyvault -eq "" -or $null -eq $keyvault) {
        $keyvault = getKeyVault
        if ($null -eq $keyvault) {
            Write-Log -logText "Keyvault not input and unable to get it from 'DXC-Maint-RG'."
                exit   
        }
}

#Get maintainance token secrets
$CSuninstall = (Get-AzKeyVaultSecret -vaultName $keyvault -name "CSuninstall").SecretValueText

#Function for ServiceCheck
Function CheckService($vmname)
{   
        $serviceStatcmd =  "(Get-MpPreference | Select-Object DisableRealtimeMonitoring).disablerealtimemonitoring"
        $TempFile = New-TemporaryFile
        $serviceStatcmd | out-file -filepath $TempFile 
        $service=Invoke-AzVMRunCommand -VMName $vmname -ResourceGroupName $ResourceGroup -CommandId 'RunPowerShellScript' -ScriptPath $TempFile
        $serviceStat = $service.Value[0].Message
        Write-log -logText $serviceStat
}

#Function for GPO Checking
Function GPOUpdate($vmname)
{
$domaincmd= "(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain"
$TempFile = New-TemporaryFile
$domaincmd | out-file -filepath $TempFile 
$isdomainjoined = Invoke-AzVMRunCommand -VMName $vmname  -ResourceGroupName $ResourceGroup -CommandId 'RunPowerShellScript' -ScriptPath $TempFile
if ($isdomainjoined.Value[0].Message -match "False")
{
    if ($vmname:sku.ToLower().Contains("2016"))
    {
        $cmd16 ="[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12 ;(New-Object System.Net.WebClient).DownloadFile('https://metrictestam.blob.core.windows.net/tools/samplemde16.reg','C:\Windows\samplemde16.reg');
        reg import C:\Windows\samplemde16.reg"
        $TempFile = New-TemporaryFile
        $cmd16 | Out-File -FilePath $TempFile
        $regUpdate16 = Invoke-AzVMRunCommand -VMName $vmname  -ResourceGroupName $ResourceGroup -CommandId 'RunPowerShellScript' -ScriptPath $TempFile
        $regUpdate16
    }
    if ($vmname:sku.ToLower().Contains("2012"))
    {
        $cmd12 ="[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12 ;(New-Object System.Net.WebClient).DownloadFile('https://metrictestam.blob.core.windows.net/tools/samplemde16.reg','C:\Windows\sampleantimalware12r2.reg');
        reg import C:\Windows\sampleantimalware12r2.reg"
        $TempFile = New-TemporaryFile
        $cmd12 | Out-File -FilePath $TempFile
        $regUpdate12 = Invoke-AzVMRunCommand -VMName $vmname  -ResourceGroupName $ResourceGroup -CommandId 'RunPowerShellScript' -ScriptPath $TempFile
        $regUpdate12
    }
    if ($vmname:sku.ToLower().Contains("2019"))
    {
        $cmd19 ="[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12 ;(New-Object System.Net.WebClient).DownloadFile('https://metrictestam.blob.core.windows.net/tools/samplemde16.reg','C:\Windows\samplemde19.reg');
        reg import C:\Windows\samplemde19.reg"
        $TempFile = New-TemporaryFile
        $cmd19 | Out-File -FilePath $TempFile
        $regUpdate19 = Invoke-AzVMRunCommand -VMName $vmname  -ResourceGroupName $ResourceGroup -CommandId 'RunPowerShellScript' -ScriptPath $TempFile
        $regUpdate19
    }
    if ($vmname:sku.ToLower().Contains("2008-r2"))
    {
        $cmd08 ="[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12 ;(New-Object System.Net.WebClient).DownloadFile('https://metrictestam.blob.core.windows.net/tools/samplemde16.reg','C:\Windows\sampleantimalware8r2.reg');
        reg import C:\Windows\sampleantimalware8r2.reg"
        $TempFile = New-TemporaryFile
        $cmd08 | Out-File -FilePath $TempFile
        $regUpdate08 = Invoke-AzVMRunCommand -VMName $vmname  -ResourceGroupName $ResourceGroup -CommandId 'RunPowerShellScript' -ScriptPath $TempFile
        $regUpdate08
    }
}
else
{
$updatePolicycmd= "gpupdate /force"
$TempFile = New-TemporaryFile
$updatePolicycmd | out-file -filepath $TempFile 
$policy= Invoke-AzVMRunCommand -VMName $vmname  -ResourceGroupName $ResourceGroup -CommandId 'RunPowerShellScript' -ScriptPath $TempFile
   if ($policy.Value[0].Message -match "completed successfully")
     {
        Write-Log -logText "GPO Update succesful"
     }
   else 
     {
        Write-Log -logText "CANNOT UPDATE GPO.EXITING"
    EXIT
     }
}
}

#Function for Registry Check
Function CheckRegistry($vmname)
{
    $cmd="Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat protection\Status\' -Name 'OnboardingState'"
    $TempFile = New-TemporaryFile
    $cmd | out-file -filepath $TempFile 
    #$cmd
    $reg=Invoke-AzVMRunCommand -VMName $vmname  -ResourceGroupName $vmname.ResourceGroupName -CommandId 'RunPowerShellScript' -ScriptPath $TempFile -ErrorAction Stop
    #$reg
    if ($reg.Value[0].Message -match "OnboardingState : 1")
    {
        Write-Log -logText "Azure Defender is Onboarded in Regsitry"
        if  (($vmname.StorageProfile.ImageReference.Sku -match "2019-Datacenter") -or ($vmname.StorageProfile.ImageReference.Sku -match "2016-Datacenter"))
        {
            Write-Log -logText "Azure Defender is onbaorded in registry..Checking real timemonitoring for further information"
            $service = CheckService($vmName)
            #$service
            if ($service -match "False")
            {
                Write-Log -logText "Real time monitoring is enabled"
                GPOUpdate($vmname)
            }
            else
            {
                Write-Log -logText "Real time monitoring is not enabled...Enabling"
                $vmname
                $enableMonitoring = 'Set-MpPreference -DisableRealtimeMonitoring $false'
                $TempFile = New-TemporaryFile
                $enableMonitoring | out-file -filepath $TempFile 
                $RTMcmd=Invoke-AzVMRunCommand -VMName $vmname  -ResourceGroupName $vmname:ResourceGroupName -CommandId 'RunPowerShellScript' -ScriptPath $TempFile
                $monitoringValue= CheckService($vmname)
                   if ($monitoringValue -match "False")
                   {
                    Write-Log -logText "Real time monitoring enabled"
                    GPOUpdate($vmname)
                   }
                   else
                  {Write-Log -logText " Error enablong RealTime monitoring. EXITING SCRIPT"
                  exit}
             }

            }
            return $Service
        }
    }
    else 
    {
        Write-Log -logText "AZURE DEFENDER NOT ONBOARDED. WAIT FOR IT TO ONBOARD EXITING SCRIPT"
        Exit
    }
}
Function Csuninstall($vmname)
{
    $cmd16 ="[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12"
    $TempFile = New-TemporaryFile
    $cmd16 | Out-File -FilePath $TempFile
    $regUpdate16 = Invoke-AzVMRunCommand -VMName $vmname  -ResourceGroupName $ResourceGroup -CommandId 'RunPowerShellScript' -ScriptPath $TempFile
    $regUpdate16   
}
#Function to check Powershell version on 2008 r2

Function Psupgrade($vmname){
$psVersion = windowsPowershellVersion $vmname:ResourceGroupName $vmname 0
Write-Log -logText "VM: $vmname has powershellVersion $psVersion"
                        if ($psVersion -lt 4) {
                            Write-Log -logText "VM does not have high enough powershell version for CWP. Attempting to upgrade the powershell version."
                                $attemptLoop = 0
                                Do {
                                        $performance = Measure-Command { UpgradePStoV4 $vmname.ResourceGroupName $vmname 0 }
                                        $msg = $performance.TotalMinutes
                                        Write-Log -logText "UpgradePStoV4 execution time: $msg minutes"
                                        Start-Sleep -Seconds 60
                                        # Check if we actually upgraded the powershell version
                                        $psVersion = windowsPowershellVersion $vmname.ResourceGroupName $vmname 0
                                        if ($psVersion -lt 4) {
                                                $attemptLoop = $attemptLoop + 1
                                                if ($attemptLoop -lt 4) {
                                                        Write-Log -logText "Powershell not upgraded. Retry attempt $attemptLoop"
                                                        Restart-AzVM -ResourceGroupName $vmname.ResourceGroupName -Name $vmname 1>$null 2>$null 3>$null
                                                        Start-Sleep -Seconds 200
                                                }
                                                else {
                                                        break
                                                }
                                        }
                                        else {
                                                break
                                        }
                                } while ($attemptLoop -lt 100)

                                Write-Log -logText "VM: $vmname now has powershellVersion $psVersion"
                                if ($psVersion -lt 4) {
                                        # Something went wrong, we need to stop this deployment
                                        Write-Log -logText "Powershell does not appear to have been upgraded on $vmname.  Processing halted."
                                        Exit
                                }
                        } 
                    }

#========================================================================================================================
#Installation of Antimalware and remove crowdstrike
#========================================================================================================================
$Vmlist = Get-AzVM | Where-Object { ($_.StorageProfile.OSDisk.OSType -eq "Windows") -and ($_.Statuses.DisplayStatus -eq "VM running")}
Write-Log "Getting the list of Windows running VMs in a subscription"
try{
    $VM2k82k12 = $Vmlist | Where-Object {($_.StorageProfile.imagereference.sku  -match "2008-R2-SP1") -or ($_.StorageProfile.imagereference.sku  -match "2012-R2-Datacenter")}
    ForEach($vmname in $VM2k82k12){
        $Location =  $vmname.Location
        $ResourceGroup = $vmname.ResourceGroupName
        $extensioncheck = Get-AzVMExtension -ResourceGroupName $resourceGroup -VMName $vmname -Name AntiMalware
        Write-log "Checking if Antimalware extension already present"
        If($extensioncheck.ProvisioningState -ne "Succeeded"){
            $job = Set-AzVMExtension -VMName $vmname -ResourceGroupName $resourceGroup -Location $vmlocation -Publisher Microsoft.Azure.Security -ExtensionName IaaSAntimalware -ExtensionType IaaSAntimalware -Version 1.3 -SettingString $SettingString -AsJob
            Write-Log "Installed Antimalware Extension on $vmname "
            #check if Crowdstrike exists
            $ListofExtension = Get-AzVMExtension -ResourceGroupName $vm.resourcegroupname -VMName $vm.name | Select-Object Name
            $extension = Get-AzVMExtension -ResourceGroupName $vmname.resourcegroupname -VMName $vmname | Where-Object {$_.Name | Select-String -Pattern 'CrowdStrikeSensor|CrowdStrikeAgent'} | select name
            if ($ListofExtension.Name -contains "CrowdStrikeSensor" -or $ListofExtension.Name -contains "CrowdStrikeAgent"){
                #Uninstall Crowdstrike on the VM and output result
                Write-log "Uninstalling Crowdstrike on VM named $($vmname)"
                $guiresult = Remove-AzVMExtension -ResourceGroupName $vm.resourcegroupname -VMName $vm.name -ExtensionName $extension.name -Force
                $cmdresult = (invoke-azvmruncommand -ResourceGroupName $vm.resourcegroupname -Name $vm.name -CommandId 'RunPowerShellScript' -ScriptPath .\windowsCSUninstall.ps1 -Parameter @{MaintenanceToken = $CSuninstall})
                if($cmresult.Value[0].Message -eq "Unsupported crowdstrike Version")
                    {
                    Write-Log -logText "Unable to uninstall Crowdstrike on VM name $($vm.Name) because the Crowdstrike version is below 5.10.9106 "
                    }
            }
            Else
            {	
            Write-log "CrowdstrikeSensor extension not found on $($vm.name)"
            }  
        }
        else{
            Write-Log "$vmname already have AntiMalware extension installed "
    }
    }
    #Collect the list of Windows 2016 &Windows 2019 VMs
    $VM2K162K19 = $Vmlist | Where-Object {($_.StorageProfile.imagereference.sku  -eq "2016-Datacenter") -or ($_.StorageProfile.imagereference.sku  -eq "2012-R2-Datacenter")}
    ForEach($list in $VM2K162K19){
        #Checking if Antimalware extension is installed
        $extensioncheck = Get-AzVMExtension -ResourceGroupName $resourceGroup -VMName $vmname -Name AntiMalware
        Write-log "Checking if Antimalware extension is installed"
        $regpath = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat protection"
        If (($extensioncheck.ProvisioningState -ne "Succeeded") -and ($regpath -ne $null)){
            #check if Crowdstrike exists
            $ListofExtension = Get-AzVMExtension -ResourceGroupName $vm.resourcegroupname -VMName $vm.name | Select-Object Name
            $extension = Get-AzVMExtension -ResourceGroupName $vm.resourcegroupname -VMName $vm.name | Where-Object {$_.Name | Select-String -Pattern 'CrowdStrikeSensor|CrowdStrikeAgent'} | select name
            if ($ListofExtension.Name -contains "CrowdStrikeSensor" -or $ListofExtension.Name -contains "CrowdStrikeAgent"){
                #Uninstall Crowdstrike on the VM and output result
                Write-log "Uninstalling Crowdstrike on VM named $($vm.name)"
                $guiresult = Remove-AzVMExtension -ResourceGroupName $vm.resourcegroupname -VMName $vm.name -ExtensionName $extension.name -Force
                $cmdresult = (invoke-azvmruncommand -ResourceGroupName $vm.resourcegroupname -Name $vm.name -CommandId 'RunPowerShellScript' -ScriptPath .\windowsCSUninstall.ps1 -Parameter @{MaintenanceToken = $CSuninstall})
                if($cmresult.Value[0].Message -eq "Unsupported crowdstrike Version")
                    {
                    Write-Log -logText "Unable to uninstall Crowdstrike on VM name $($vm.Name) because the Crowdstrike version is below 5.10.9106 "
                    }
            }
            Else
            {	
            Write-log "CrowdstrikeSensor extension not found on $($vm.name)"
            }

        }
    }
}
catch 
        {
        Write-log "$($_.ErrorMessage)"
        }
finally {
        # Remove temporary file
        Remove-Item -Path $TempFile
    }

#=========================================================================================================================
#Main Code
#=========================================================================================================================
$Vmlist = Get-AzVM -Status -ResourceGroup "Mounika-RG" | Where-Object {($_.StorageProfile.OSDisk.OSType -eq "Windows") -and ($_.PowerState -eq "VM running")}
#Collect the list of Windows 2016 &Windows 2019 VMs
$VM2K162K19 = $Vmlist | Where-Object {($_.StorageProfile.imagereference.sku  -eq "2016-Datacenter") -or ($_.StorageProfile.imagereference.sku  -eq "2019-Datacenter")}
ForEach($vmname in $VM2K162K19){
    $Location =  $vmname.Location
    $ResourceGroup = $vmname.ResourceGroupName
    If (CheckRegistry -match "OnboardingState : 1"){
        Csuninstall
        #check if Crowdstrike exists
        $ListofExtension = Get-AzVMExtension -ResourceGroupName $vm.resourcegroupname -VMName $vm.name | Select-Object Name
        $extension = Get-AzVMExtension -ResourceGroupName $vm.resourcegroupname -VMName $vm.name | Where-Object {$_.Name | Select-String -Pattern 'CrowdStrikeSensor|CrowdStrikeAgent'} | select name
        if ($ListofExtension.Name -contains "CrowdStrikeSensor" -or $ListofExtension.Name -contains "CrowdStrikeAgent"){
            #Uninstall Crowdstrike on the VM and output result
            Write-log "Uninstalling Crowdstrike on VM named $($vm.name)"
            $guiresult = Remove-AzVMExtension -ResourceGroupName $vm.resourcegroupname -VMName $vm.name -ExtensionName $extension.name -Force
            $cmdresult = (invoke-azvmruncommand -ResourceGroupName $vm.resourcegroupname -Name $vm.name -CommandId 'RunPowerShellScript' -ScriptPath .\windowsCSUninstall.ps1 -Parameter @{MaintenanceToken = $CSuninstall})
            if($cmresult.Value[0].Message -eq "Unsupported crowdstrike Version"){
                Write-Log -logText "Unable to uninstall Crowdstrike on VM name $($vm.Name) because the Crowdstrike version is below 5.10.9106 "
            }
            Else
            {	
            Write-log "CrowdstrikeSensor extension not found on $($vm.name)"
            }
        }
        
    }
    
    

}