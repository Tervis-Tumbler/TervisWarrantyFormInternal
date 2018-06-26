
function Invoke-NewUDInputWarrantyParentInput {
    param (
        $Parameters
    )
    $WarrantyRequest = New-WarrantyRequest @Parameters
    $WarrantyParentTicket = $WarrantyRequest | New-WarrantyParentTicket
    $Session:WarrantyParentTicketID = $WarrantyParentTicket.ID
    $Session:WarrantyChildTicketID = New-Object System.Collections.ArrayList

    New-UDInputAction -RedirectUrl "/WarrantyChild"	
}

function Invoke-NewUDInputWarrantyChildInput {
    param (
        $Parameters
    )
    $WarrantyRequestLine = New-WarrantyRequestLine @Parameters

    $WarrantyChildTicket = $WarrantyRequestLine | 
    New-WarrantyChildTicket -WarrantyParentTicketID $Session:WarrantyParentTicketID

    if ($WarrantyChildTicket) {
        $Session:WarrantyChildTicketID.Add($WarrantyChildTicket.ID)

        Add-UDElement -ParentId "RedirectParent" -Content {
            New-UDHtml -Markup @"
            <meta http-equiv="refresh" content="0; URL='/WarrantyChild'" />
"@
        }
    #New-UDInputAction -ClearInput -Toast "Warranty Line Created" #Given we are redirecting the whole page below I don't know that we need this
    }    
}

function New-UDTableWarrantyParent {
    New-UDTable -Title "Warranty Parent" -Id "WarrantyParentTable" -Headers ID, FirstName, LastName, BusinessName, Address1, Address2, City, State, PostalCode, ResidentialOrBusinessAddress, PhoneNumber, Email, Action -Endpoint {
        $WarrantyRequest = Get-FreshDeskTicket -ID $Session:WarrantyParentTicketID |
        Where-Object {-Not $_.Deleted} |
        ConvertFrom-FreshDeskTicketToWarrantyRequest |
        Add-Member -MemberType NoteProperty -PassThru -Name ID -Value $Session:WarrantyParentTicketID |
        Add-Member -MemberType NoteProperty -PassThru -Name Remove -Value (
            New-UDElement -Tag "a" -Attributes @{
                className = "btn"
                onClick = {
                    Remove-FreshDeskTicket -ID $Session:WarrantyParentTicketID
                    $Session:WarrantyChildTicketID | ForEach-Object { Remove-FreshDeskTicket -ID $_ }
                    Remove-Item -Path Session:WarrantyParentTicketID
                    Remove-Item -Path Session:WarrantyChildTicketID
                    Add-UDElement -ParentId "RedirectParent" -Content {
                        New-UDHtml -Markup @"
                            <meta http-equiv="refresh" content="0; URL='/'" />
"@
                    }
                }
            } -Content {
                "Remove" 
            }
        )

        $WarrantyRequest | 
        Out-UDTableData -Property ID, FirstName, LastName, BusinessName, Address1, Address2, City, State, PostalCode, ResidentialOrBusinessAddress, PhoneNumber, Email, Remove
    }
}

function New-UDTableWarrantyChild {
    New-UDTable -Title "Warranty Child" -Id "WarrantyChildTable" -Headers ID, DesignName, Size, Quantity, ManufactureYear, ReturnReason, Action -Endpoint {
        $Session:WarrantyChildTicketID | 
        ForEach-Object {
            Get-FreshDeskTicket -ID $_ |
            Where-Object {-Not $_.Deleted} |
            ConvertFrom-FreshDeskTicketToWarrantyRequestLine |
            Add-Member -MemberType NoteProperty -Name ID -Value $_ -PassThru |                        
            Select-Object -Property *, @{
                Name = "Remove"
                Expression = {
                    New-UDElement -Tag "a" -Attributes @{
                        className = "btn"
                        onClick = {
                            Remove-FreshDeskTicket -ID $_.ID
                            $Session:WarrantyChildTicketID.Remove($_.ID)

                            Add-UDElement -ParentId "RedirectParent" -Content {
                                New-UDHtml -Markup @"
                                    <meta http-equiv="refresh" content="0; URL='/WarrantyChild'" />
"@  
                            }
                        }
                    } -Content {
                        "Remove"
                    }
                }
            }
        } |
        Out-UDTableData -Property ID, DesignName, Size, Quantity, ManufactureYear, ReturnReason, Remove
    } #-AutoRefresh -RefreshInterval 2  
}

function New-TervisWarrantyFormDashboard {
    $Port = 10001
	Get-UDDashboard | Where port -eq $Port | Stop-UDDashboard

	$NewWarrantyParentPage = New-UDPage -Name "NewWarrantyParentPage" -Icon home -Content {
        #New-UDRow {
            #New-UDColumn -Size 6 {
                New-UDInput -Title "New Warranty Parent" -Endpoint {
                    param (
                        $FirstName,
                        $LastName,
                        $BusinessName,
                        $Address1,
                        $Address2,
                        $City,
                        [ValidateSet(
                            "AL","AK","AZ","AR","CA","CO","CT","DC","DE","FL","GA","HI","ID","IL","IN","IA","KS","KY","LA","ME","MD","MA","MI","MN","MS","MO","MT","NE","NV","NH","NJ","NM","NY","NC","ND","OH","OK","OR","PA","RI","SC","SD","TN","TX","UT","VT","VA","WA","WV","WI","WY","GU","PR","VI","AE","AA","AP"
                        )]
                        $State,
                        [String]$PostalCode,
                        [ValidateSet("Residence","Business")]$ResidentialOrBusinessAddress,
                        $PhoneNumber,
                        $Email
                    )
                    Invoke-NewUDInputWarrantyParentInput -Parameters $PSBoundParameters
                }
            #}
        #}
	}


    
	$NewWarrantyChildPage = New-UDPage -Url "/WarrantyChild" -Icon link -Endpoint {
        New-UDElement -Tag div -Id RedirectParent
        New-UDRow {
            New-UDColumn -Size 12 {
                New-UDTableWarrantyParent              
            }
        
            New-UDLayout -Columns 2 -Content {
                New-UDInput -Title "New Warranty Child" -Id "NewWarrantyChildInput" -Endpoint {
                    param (
                        $DesignName,
                        [ValidateSet(
                            "10oz (5 1/2)",
                            "12oz (4 1/4)",
                            "wavy (5 1/2)",
                            "wine glass (8 1/2)",
                            "My First Tervis Sippy Cup (5 1/5)",
                            "16oz (6)",
                            "mug (5)",
                            "stemless wine glass (4 4/5)",
                            "24oz (7 7/8)",
                            "water bottle (10.4)",
                            "8oz (4)",
                            "goblet (7 7/8)",
                            "collectible (2 3/4)",
                            "tall (6 1/4)",
                            "stout (3 1/2)",
                            "20oz stainless Steel (6 3/4)",
                            "30oz stainless Steel (8)",
                            "12oz stainless (4.85)",
                            "stainless water bottle (10.75)"
                        )]
                        [String]$Size,
                
                        [ValidateSet("1","2","3","4","5","6","7","8","9","10")][String]$Quantity,
                        [ValidateSet(
                            "Before 2004","2004","2005","2006","2007","2008","2009","2010","2011","2012","2013","2014","2015","2016","2017","2018","NA","Non Tervis"
                        )][String]$ManufactureYear,
                
                        [ValidateSet(
                            "cracked",
                            "cracked not at weld",
                            "cracked stress cracks",
                            "decoration fail",
                            "film",
                            "heat distortion",
                            "stainless defect",
                            "seal failure",
                            "sunscreen"
                        )]
                        [String]$ReturnReason
                    )
                    Invoke-NewUDInputWarrantyChildInput -Parameters $PSBoundParameters
                }

                New-UDTableWarrantyChild
                
                New-UDElement -Tag "a" -Attributes @{
                    className = "btn"
                    onClick = {
                        Add-UDElement -ParentId "RedirectParent" -Content {
                            New-UDHtml -Markup @"
                                <meta http-equiv="refresh" content="0; URL='/'" />
"@
                        }
                    }
                } -Content {
                    "Done" 
                }
            }
        }
    }   
	
	$Dashboard = New-UDDashboard -Pages @($NewWarrantyParentPage, $NewWarrantyChildPage) -Title "Warranty Request Form" -EndpointInitializationScript {
        #Get-ChildItem -Path C:\ProgramData\PowerShellApplication\TervisFreshDeskPowerShell -File -Recurse -Filter *.psm1 -Depth 2 |
        #ForEach-Object {
        #    Import-Module -Name $_.FullName -Force
        #}
        
        Set-TervisFreshDeskEnvironment
	}

	Start-UDDashboard -Dashboard $Dashboard -Port $Port -AllowHttpForLogin
}

function Install-TervisFreshDeskWarrantyForm {
	param (
		$ComputerName
	)
	Install-PowerShellApplicationUniversalDashboard -ComputerName $ComputerName -ModuleName TervisFreshDeskPowerShell -TervisModuleDependencies PasswordstatePowerShell,
		TervisMicrosoft.PowerShell.Utility,
        FreshDeskPowerShell,
        WebServicesPowerShellProxyBuilder -PowerShellGalleryDependencies UniversalDashboard -CommandString "New-TervisWarrantyFormDashboard"

	$PowerShellApplicationInstallDirectory = Get-PowerShellApplicationInstallDirectory -ComputerName $ComputerName -ModuleName TervisFreshDeskPowerShell
	Invoke-Command -ComputerName $ComputerName -ScriptBlock {
		New-NetFirewallRule -Name TervisWarrantyFormDashboard -DisplayName TervisWarrantyFormDashboard -Profile Any -Direction Inbound -Action Allow -LocalPort 10001 -Protocol TCP
		#. $Using:PowerShellApplicationInstallDirectory\Import-ApplicationModules.ps1
		#Set-PSRepository -Trusted -Name PowerShellGallery
		#Install-Module -Name UniversalDashboard -Scopoe CurrentUser
		#$PSModulePathCurrentUser = Get-UserPSModulePath
		#Copy-Item -Path $PSModulePathCurrentUser -Destination $Using:PowerShellApplicationInstallDirectory\. -Recurse
		#Publish-UDDashboard -DashboardFile $Using:PowerShellApplicationInstallDirectory\Script.ps1
	}
}