<#
====================================================================================================================================================
AUTHOR:  Santanu Sengupta 
DATE:    14/08/2018
Version: 1.0
Documentation: 
https://confluence.csc.com/display/CSA/CSA-4158+Update+script+that+automatically+updates+alert+rule+matrix+post+release
====================================================================================================================================================
====================================================================================================================================================
AUTHOR:  Chris Neale 
DATE:    07/02/2019
Version: 1.1
Documentation: Updated parent ID to point at more sensible place in Confluence hierarchy. 
https://confluence.csc.com/display/CSA/CSA-4158+Update+script+that+automatically+updates+alert+rule+matrix+post+release
====================================================================================================================================================
====================================================================================================================================================
AUTHOR:  Dudley Miller 
DATE:    05/24/2019
Version: 1.2
Documentation: Updated For New Alert Format
c/wiki/spaces/CSA/pages/587923776/CSA-4158+Update+script+that+automatically+updates+alert+rule+matrix+post+release
====================================================================================================================================================
====================================================================================================================================================
AUTHOR:  Kevin Bilderback
DATE:    19/07/2019
Version: 1.2
Documentation: Changed all references to dxc confluence to csc confluence equivalent.
====================================================================================================================================================
====================================================================================================================================================
====================================================================================================================================================
AUTHOR:  Harika Gadiyakari
DATE:    05/06/2020
Version: 1.3
Documentation: Modified the script to support MetricAlerts
====================================================================================================================================================



.NAME 
    alertReporting

.SYNOPSIS
    Uploads list of OMS alerts to Confluence as a new child page to the parent page nunmber 430964843.    Changed parent to: https://confluence.csc.com/display/CSA
	
.SYNTAX
    ./alertReporting.ps1 [[-dxcConfluenceUserID] <String[]>] [-dxcConfluenceAPIToken <String[]>] [-dxcAlertVersion <String[]>]

.DESCRIPTION
    .PARAMETER $dxcConfluenceUserID
        User name to login to DXC Confluence "confluence.csc.com" generally dxc email ID.
    .PARAMETER $dxcConfluenceAPIToken
        API token for the Confluence UserID used.  See below for notes on how to obtain
    .PARAMETER $dxcAlertVersion
        Version of the Alerts for which the report is getting generated.

.Note   
    To generate an API token follow these steps:
        1.  In a web browser, navigate to: https://id.atlassian.com/manage/api-tokens and click "Create API Token"
        2.  It will hide the token, but gives you the opportunity to copy it to your clipboard.    

.EXAMPLE
    .\alertReporting.ps1 '<Confluence UserID>' '<Confluence API Token>' '<2.3.1>'
====================================================================================================================================================
#>

[CmdletBinding(SupportsShouldProcess=$true)]
Param
    (
    [Parameter(Mandatory=$true)] [String]$dxcConfluenceUserID,
    [Parameter(Mandatory=$true)] [String]$dxcConfluenceAPIToken,
    [Parameter(Mandatory=$true)] [String]$dxcAlertVersion
    )

#Variables
$dxcSecurePassword = ConvertTo-SecureString $dxcConfluenceAPIToken -AsPlainText -Force
$dxcCred = New-Object System.Management.Automation.PSCredential ($dxcConfluenceUserID, $dxcSecurePassword)
$dxcChildPageName = 'Managed Services for Microsoft Azure V' + $dxcAlertVersion + '- Alert List'
$dxcScriptPath = $PSScriptRoot + '\Alerting'

#=====================================================================================================================
# FUNCTION TO CHECK AND INSTALL NECESSERY MODULES
#=====================================================================================================================
Function Check-Module 
    {
    Param($dxcModuleToCheck)
    If (get-module -ListAvailable -name $dxcModuleToCheck)
        {
        Write-Host "INFORMATION: $dxcModuleToCheck Powershell Module Found" -ForegroundColor Green
        } 
    else
        {
        $dxcInstallMod = Read-Host 'INFORMATION:' $dxcModuleToCheck 'Module Not Found. Do you want to try and install it now? (y/n):'
        If ($dxcInstallMod.ToLower() -eq 'y')
            {
            Write-Host "Yes, Installing Module $dxcModuleToCheck" 
            Install-Module $dxcModuleToCheck -Force -Confirm:$false
            Import-Module $dxcModuleToCheck
            }
        else   
            {
            Write-Host "No, Exiting script."
            Exit
            }
        }
    }

#=====================================================================================================================
# FUNCTION TO CONVERT OUTPUT TO CONFLUENCE TABULAR FORMAT
#===================================================================================================================== 
Function AtlassianTableContentFormat 
    {
   Param([String]$dxcNumber, [String]$dxcAlertFile, [String]$dxcAlertName,[String]$dxcAlertDescription, [String]$dxcAlertSeverity, [String]$dxcCategory, [String]$dxcEventType, [String]$dxcEventResource, [String]$dxcActionGroup, [String]$dxcQueryTimeSpan, [String]$dxcSchedule, [String]$dxcQuery)
    "|" + $dxcNumber + "|" + $dxcAlertFile + "|" + $dxcAlertName + "|" + $dxcAlertDescription + "|" + $dxcAlertSeverity + "|" + $dxcCategory + "|" + $dxcEventType + "|" + $dxcEventResource +  "|" + $dxcActionGroup + "|" + $dxcQueryTimeSpan + "|" + $dxcSchedule + "|" + $dxcQuery.Replace("|"," pipe ") + "|`n"
    } 

Function AtlassianTableTitleFormat 
    {
    Param([String]$dxcNumber, [String]$dxcAlertFile, [String]$dxcAlertName,[String]$dxcAlertDescription, [String]$dxcAlertSeverity, [String]$dxcCategory, [String]$dxcEventType, [String]$dxcEventResource, [String]$dxcActionGroup, [String]$dxcQueryTimeSpan, [String]$dxcSchedule, [String]$dxcQuery)
    "||" + $dxcNumber + "||" + $dxcAlertFile + "||" + $dxcAlertName + "||"  + $dxcAlertDescription + "||" + $dxcAlertSeverity + "||" + $dxcCategory +  "||" + $dxcEventType +  "||" + $dxcEventResource + "||" + $dxcActionGroup + "||" + $dxcQueryTimeSpan + "||" + $dxcSchedule + "||" + $dxcQuery + "||`n"
    }
Function AtlassianTableContentFormatformetrics 
    {
    Param([String]$dxcNumber, [String]$dxcAlertFile, [String]$dxcAlertName,[String]$dxcAlertDescription, [String]$dxcAlertSeverity, [String]$MetricName, [String]$Frequency, [String]$WindowSize, [String]$TimeAggregation, [String]$Operator, [String]$Threshold)
    "|" + $dxcNumber + "|" + $dxcAlertFile + "|" + $dxcAlertName + "|"  + $dxcAlertDescription + "|" + $dxcAlertSeverity + "|" + $MetricName +  "|" + $Frequency +  "|" + $WindowSize + "|" + $TimeAggregation + "|" + $Operator + "|" + $Threshold + "|`n"
    }
     
Function AtlassianTableTitleFormatformetrics 
    {
    Param([String]$dxcNumber, [String]$dxcAlertFile, [String]$dxcAlertName,[String]$dxcAlertDescription, [String]$dxcAlertSeverity, [String]$MetricName, [String]$Frequency, [String]$WindowSize, [String]$TimeAggregation, [String]$Operator, [String]$Threshold)
    "||" + $dxcNumber + "||" + $dxcAlertFile + "||" + $dxcAlertName + "||"  + $dxcAlertDescription + "||" + $dxcAlertSeverity + "||" + $MetricName +  "||" + $Frequency +  "||" + $WindowSize + "||" + $TimeAggregation + "||" + $Operator + "||" + $Threshold + "||`n"
    } 

#=====================================================================================================================
# MAIN BODY
#=====================================================================================================================

#Check Required Modules and Powershell version
If ((($PSVersionTable.psversion.major) + ($psversiontable.PSVersion.Minor)/10) -gt 5.0)
    {
    Write-Host "INFORMATION: Powershell 5.1 or higher Found" -ForegroundColor Green
    } 
else 
    {
    Write-Host "WARNING: Powershell 5.1 or higher is required, please exit and install the latest version" -ForegroundColor Yellow
	Exit
	}

Check-Module('ConfluencePS')

Write-Host "`nINFORMATION: Generating report..." -ForegroundColor Green
$dxcAlertARMFiles = Get-ChildItem -Path $dxcScriptPath -Include "alert*.json", "metricalert*.json" -Exclude "alerts-appinsights*", "alerts-vm*", "*selfheal*" -Recurse
[String]$dxcResultString += AtlassianTableTitleFormat -dxcNumber "Number" -dxcAlertFile "AlertFile" -dxcAlertName "AlertName" -dxcAlertDescription "Description" -dxcAlertSeverity "Severity" -dxcCategory "searchCategory (eventFormat)" -dxcEventType "eventType" -dxcEventResource "eventResource" -dxcQueryTimeSpan "QueryTimeSpan" -dxcSchedule "Schedule" -dxcQuery "Query"

$dxcCount = 0
foreach ($dxcAlertFile in $dxcAlertARMFiles)
    {
	$dxcOMSARMTemplate = Get-Content -Raw -Path $dxcAlertFile.FullName | ConvertFrom-Json
     
	foreach ($dxcAlert in $dxcOMSARMTemplate.variables.alertArray)
	    {
		$dxcCount += 1
        If (($dxcAlertFIle.Name).ToLower() -eq 'alerts-vm-availability-hbm.json')
	        {
            $dxcResultString += AtlassianTableContentFormat -dxcNumber $dxcCount.ToString() -dxcAlertFile $dxcAlertFile.Name -dxcAlertName $dxcAlert.alertName -dxcAlertDescription $dxcAlert.description -dxcAlertSeverity $dxcAlert.Severity -dxcCategory $dxcAlert.searchCategory -dxcEventType $dxcAlert.eventType -dxcEventResource $dxcAlert.eventResource -dxcQueryTimeSpan $dxcAlert.scheduleQueryTimeSpan -dxcSchedule $dxcAlert.scheduleIntervalInMinutes -dxcQuery "NA: Metric Alert"
            }
        else
            {
             $dxcResultString += AtlassianTableContentFormat -dxcNumber $dxcCount.ToString() -dxcAlertFile $dxcAlertFile.Name -dxcAlertName $dxcAlert.alertName -dxcAlertDescription $dxcAlert.description -dxcAlertSeverity $dxcAlert.Severity -dxcCategory $dxcAlert.searchCategory -dxcEventType $dxcAlert.eventType -dxcEventResource $dxcAlert.eventResource -dxcQueryTimeSpan $dxcAlert.scheduleQueryTimeSpan -dxcSchedule $dxcAlert.scheduleIntervalInMinutes -dxcQuery $dxcAlert.query
		    }
        }

    }
    [String]$dxcResultString += AtlassianTableTitleFormatformetrics -dxcNumber "Number" -dxcAlertFile "AlertFile" -dxcAlertName "AlertName" -dxcAlertDescription "Description" -dxcAlertSeverity "Severity" -MetricName "MetricName" -Frequency "Frequency" -WindowSize "WindowSize" -TimeAggregation "TimeAggregation" -Operator "Operator" -Threshold "Threshold" 
    foreach ($dxcAlertFile in $dxcAlertARMFiles){
    $dxcOMSARMTemplate = Get-Content -Raw -Path $dxcAlertFile.FullName | ConvertFrom-Json
     foreach ($dxcAlert in $dxcOMSARMTemplate.dxcAlertArray)
	    {
		$dxcCount += 1
        
             $dxcResultString += AtlassianTableContentFormatformetrics -dxcNumber $dxcCount.ToString() -dxcAlertFile $dxcAlertFile.Name -dxcAlertName $dxcAlert.alertName -dxcAlertDescription $dxcAlert.AlertDescription -dxcAlertSeverity $dxcAlert.Severity -MetricName $dxcAlert.MetricName -Frequency $dxcAlert.Frequency -WindowSize $dxcAlert.WindowSize -TimeAggregation $dxcAlert.TimeAggregation -Operator $dxcAlert.Operator -Threshold $dxcAlert.Threshold
		    
        }
        }
#Logging into Wiki
Write-Host "`nINFORMATION: Loggin into Confluence and connecting to target Space..." -ForegroundColor Green
$error.Clear()

#Set-ConfluenceInfo -BaseURi 'https://confluence.dxc.com/display/CSA' -Credential $dxcCred -EA 0 -WA 0

If ($error) 
    {
    Write-Host "WARNING: Failed to connect to Confluence page. Check for internet connectivity issue and authentication details, then try again." -ForegroundColor Yellow
    Get-Variable -Name dxc* | Remove-Variable -EA 0
    exit
    }

Write-Host "INFORMATION: connected to Confluence page with provided authentication. Creating report child page..." -ForegroundColor Green

#$dxcPageBody = $dxcResultString | ConvertTo-ConfluenceStorageFormat
$dxcResultString | Out-File $PSScriptRoot\$dxcChildPageName.txt

#*************************************************************************************************************************************************************
# Note:   To get -ParentID view URL of the parent page
#*************************************************************************************************************************************************************
#New-ConfluencePage -Title $dxcChildPageName -ParentID 162089018 -Body $dxcPageBody -EA 0 -WA 0

If ($error) 
    {
    Write-Host "WARNING: Failed to create child page. Check whether you are trying to upload an existing alert version, then try again." -ForegroundColor Yellow
    }
Else
    {
    Write-Host 'INFORMATION: Report child page "Managed Services for Microsoft Azure V' $dxcAlertVersion '- Alert List" uploaded to Confluence successfully.' -ForegroundColor Green
    }

Get-Variable -Name dxc* | Remove-Variable -EA 0