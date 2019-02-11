function New-TervisUDDiagnosticDataCard {
    New-UDCard -Content {$Cache:FreshDeskCredentials.$User.UserName}
    New-UDCard -Content {$User}
    New-UDCard -Content {$SessionID}
}

function Invoke-NewUDInputWarrantyParentInput {
    param (
        $Parameters
    )
    $WarrantyRequest = New-WarrantyRequest @Parameters
    $WarrantyParentTicket = $WarrantyRequest | New-WarrantyParentTicket
    $Session:WarrantyParentTicketID = $WarrantyParentTicket.ID
    $Session:WarrantyChildTicketID = New-Object System.Collections.ArrayList

    New-UDInputAction -RedirectUrl "/Warranty-Child"
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
            <meta http-equiv="refresh" content="0; URL='/Warranty-Child'" />
"@
        }
    }
}

function New-UDTableWarrantyParent {
    New-UDTable -Title "Warranty Parent" -Id "WarrantyParentTable" -Headers ID, FirstName, LastName, BusinessName, Address1, Address2, City, State, PostalCode, ResidentialOrBusinessAddress, PhoneNumber, Email, Channel, Action -Endpoint {
        $WarrantyRequest = Get-FreshDeskTicket -ID $Session:WarrantyParentTicketID |
        Where-Object {-Not $_.Deleted} |
        ConvertFrom-FreshDeskTicketToWarrantyRequest |
        Add-Member -MemberType NoteProperty -PassThru -Name Remove -Value (
            New-UDElement -Tag "a" -Attributes @{
                className = "btn"
                onClick = {
                    Remove-FreshDeskTicket -ID $Session:WarrantyParentTicketID
                    $Session:WarrantyChildTicketID | ForEach-Object { Remove-FreshDeskTicket -ID $_}
                    Set-Item -Path Session:WarrantyParentTicketID -Value 0
                    Set-Item -Path Session:WarrantyChildTicketID -Value (New-Object System.Collections.ArrayList)
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
        Out-UDTableData -Property ID, FirstName, LastName, BusinessName, Address1, Address2, City, State, PostalCode, ResidentialOrBusinessAddress, PhoneNumber, Email, Channel, Remove
    }
}

function New-UDTableWarrantyChild {
    New-UDTable -Title "Warranty Child" -Id "WarrantyChildTable" -Headers ID, Subject, Size, Quantity, ManufactureYear, ReturnReason, Action -Endpoint {
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
                                    <meta http-equiv="refresh" content="0; URL='/Warranty-Child'" />
"@
                            }
                        }
                    } -Content {
                        "Remove"
                    }
                }
            }
        } |
        Out-UDTableData -Property ID, Subject, Size, Quantity, ManufactureYear, ReturnReason, Remove
    }
}

function New-TervisWarrantyFormDashboard {
    param (
        [ScriptBlock]$EndpointInitializationScript,
        $CertificateFile,
        $CertificateFilePassword
    )
    Set-TervisFreshDeskEnvironment
    Get-TervisFreshDeskTicketField | Out-Null
    Remove-TervisFreshDeskEnvironment

    #Set-FreshDeskDomain -Domain Tervis
    #Set-FreshDeskCredentialScriptBlock -ScriptBlock {$Cache:FreshDeskCredentials.$User}

    $Port = 10001
	Get-UDDashboard | Where-Object Port -eq $Port | Stop-UDDashboard

	$NewWarrantyParentPage = New-UDPage -Name "Warranty Parent" -Content {
        New-UDInput -Title "New Warranty Parent" -Content {
            New-UDInputField -Type select -Name Channel -Values (
                Get-WarrantyRequestPropertyValues -PropertyName Channel
            ) -DefaultValue "Production"
            New-UDInputField -Type textbox -Name FirstName
            New-UDInputField -Type textbox -Name LastName
            New-UDInputField -Type textbox -Name BusinessName
            New-UDInputField -Type textbox -Name Address1
            New-UDInputField -Type textbox -Name Address2
            New-UDInputField -Type textbox -Name City
            New-UDInputField -Type select -Name State -Values (
                Get-WarrantyRequestPropertyValues -PropertyName State
            ) -DefaultValue "FL"

            New-UDInputField -Type textbox -Name PostalCode
            New-UDInputField -Type select -Name ResidentialOrBusinessAddress -Values (
                Get-WarrantyRequestPropertyValues -PropertyName ResidentialOrBusinessAddress
            ) -DefaultValue "Residence"
            New-UDInputField -Type textbox -Name PhoneNumber
            New-UDInputField -Type textbox -Name Email
        } -Endpoint {
            param (
                $FirstName,
                $LastName,
                $BusinessName,
                $Address1,
                $Address2,
                $City,
                $State,
                $PostalCode,
                $ResidentialOrBusinessAddress,
                $PhoneNumber,
                $Email,
                $Channel
            )
            Invoke-NewUDInputWarrantyParentInput -Parameters $PSBoundParameters
        }
	}

	$NewWarrantyChildPage = New-UDPage -Name "Warranty Child" -Content {
        New-UDElement -Tag div -Id RedirectParent
        New-UDRow {
            New-UDColumn -Size 12 {
                New-UDTableWarrantyParent
            }

            New-UDLayout -Columns 2 -Content {
                New-UDInput -Title "New Warranty Child" -Id "NewWarrantyChildInput" -Content {
                    New-UDInputField -Name DesignName -Type textbox
                    New-UDInputField -Name Size -Type select -Values (
                        Get-WarrantyRequestPropertyValues -PropertyName Size
                    ) -DefaultValue "10oz (5 1/2)"
                    New-UDInputField -Name Quantity -Type select -Values (1..100)
                    New-UDInputField -Name ManufactureYear -Type select -Values (
                        Get-WarrantyRequestPropertyValues -PropertyName ManufactureYear
                    ) -DefaultValue "Before 2004"
                    New-UDInputField -Name ReturnReason -Type select -Values (
                        (Get-ReturnReasonIssueTypeMapping).Keys | ConvertTo-Json | ConvertFrom-Json
                    ) -DefaultValue "cracked"
                } -Endpoint {
                    param (
                        $DesignName,
                        $Size,
                        $Quantity,
                        $ManufactureYear,
                        $ReturnReason
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

    $GetTicketInformationPage = New-UDPage -Name "Get Ticket Information" -Content {
        New-UDLayout -Columns 1 -Content {
            New-UDInput -Title "Get Ticket Information" -Id "GetTicketInformation" -Endpoint {
                param (
                    $TicketID
                )
                New-UDInputAction -RedirectUrl "/TicketInformation/$TicketID"
            }
        }
    }
    
    $ShowTicketInformationPage = New-UDPage -Url "/TicketInformation/:ParentTicketID" -Endpoint {
        param (
            $ParentTicketID
        )
        New-UDRow {
            New-UDColumn -Size 12 {
                $WarrantyRequest = Get-FreshDeskTicket -ID $ParentTicketID |
                ConvertFrom-FreshDeskTicketToWarrantyRequest

                New-UDTable -ArgumentList $WarrantyRequest -Title "Warranty Parent" -Id "WarrantyParentTable" -Headers ID, FirstName, LastName, BusinessName, Address1, Address2, City, State, PostalCode, ResidentialOrBusinessAddress, PhoneNumber, Email, Channel -Endpoint {
                    $ArgumentList[0] |
                    Out-UDTableData -Property ID, FirstName, LastName, BusinessName, Address1, Address2, City, State, PostalCode, ResidentialOrBusinessAddress, PhoneNumber, Email, Channel
                }

                New-UDTable -ArgumentList $WarrantyRequest.WarrantyLines -Title "Warranty Child" -Id "WarrantyChildTable" -Headers ID, Subject, Size, Quantity, ManufactureYear, ReturnReason -Endpoint {
                    $ArgumentList[0] |
                    Out-UDTableData -Property ID, Subject, Size, Quantity, ManufactureYear, ReturnReason
                }
            }
        }
    }

    $ShipAndPrintWarrantyOrderPage = New-UDPage -Name "Ship and Print Warranty Order" -Content {
        New-UDElement -Tag div -Id RedirectParent
        New-UDLayout -Columns 1 -Content {
            New-UDInput -Title "Invoke Ship and Print Warranty Order" -Id "Invoke-ShipAndPrintWarrantyOrder" -Endpoint {
                param (
                    $WeightInLB,
                    $TicketID
                )
                if (-Not $Session:PrinterName) {
                    Add-UDElement -ParentId "RedirectParent" -Content {
                        New-UDHtml -Markup @"
                            <meta http-equiv="refresh" content="0; URL='/Set-Shipping-Label-Printer'" />
"@
                    }
                }
                Invoke-ShipAndPrintWarrantyOrder -FreshDeskWarrantyParentTicketID $TicketID -WeightInLB $WeightInLB -PrinterName $Session:PrinterName
            }
        }
    }
    

    $UnShipWarrantyOrderPage = New-UDPage -Name "UnShip Warranty Order" -Content {
        New-UDElement -Tag div -Id RedirectParent
        New-UDLayout -Columns 1 -Content {
            New-UDInput -Title "Invoke UnShip Warranty Order" -Id "Invoke-UnShipWarrantyOrder" -Endpoint {
                param (
                    $TicketID
                )
                Invoke-UnShipWarrantyOrder -FreshDeskWarrantyParentTicketID $TicketID
            }
        }
    }
    
    function Get-PrintersForDropdown {
        [String[]](
            Get-TervisPrinter |
            Where-Object Vendor -eq Zebra |
            Where-Object MediaType -eq Direct-Thermal |
            Select-Object -ExpandProperty Name
        )
    }

    $SetShippingPrinterPage = New-UDPage -Name "Set Shipping Label Printer" -Content {
        New-UDInput -Title "Set Shipping Label Printer" -Id "SetShippingLabelPrinter" -Content {
            New-UDInputField -Name PrinterName -Type select -Values (
                Get-PrintersForDropdown
            ) -DefaultValue "125Years"
        } -Endpoint {
            param (
                $PrinterName
            )
            $Session:PrinterName = $PrinterName
        }
    }

    $DiagnosticsPage = New-UDPage -Url "/Diagnostics" -Icon Home -Endpoint {
        New-UDChart -Title "FreshDesk api resonse times" -Type Line -Endpoint {
            Get-APICallLog |
            Add-Member -MemberType ScriptProperty -Name TotalMilliseconds -Force -PassThru -Value {
                $This |
                Select-Object -ExpandProperty TimeSpan |
                Select-Object -ExpandProperty TotalMilliseconds
            } |
            Out-UDChartData -DataProperty TotalMilliseconds -DatasetLabel "Total Milliseconds" -LabelProperty URL
        }
    }

    $LoginPage = New-UDLoginPage -AuthenticationMethod (
        New-UDAuthenticationMethod -Endpoint {
            param (
                [PSCredential]$Credential
            )
            if (-not $Cache:FreshDeskCredentials) {
                $Cache:FreshDeskCredentials = @{}
            }

            Try {
                Set-FreshDeskCredential -Credential $Credential
                $Agent = Get-FreshDeskAgent -Me
                if ($Cache:FreshDeskCredentials.ContainsKey($Agent.contact.email)) {
                    $Cache:FreshDeskCredentials.Remove($Agent.contact.email) | Out-Null
                }

                $Cache:FreshDeskCredentials.Add($Agent.contact.email, $Credential)
                New-UDAuthenticationResult -Success -UserName $Agent.contact.email
            } catch {
                New-UDAuthenticationResult -ErrorMessage "FreshDesk login failed"
            }
            Remove-FreshDeskCredential
        }
    )
    
    $EndpointInitializationScript |
    Out-File -FilePath .\InitilizationModule.psm1

    $InitilizationModuleFullName = Get-Item -Path .\InitilizationModule.psm1 |
    Select-Object -ExpandProperty FullName
    
    $EndpointInitialization = New-UDEndpointInitialization -Module @( $InitilizationModuleFullName )

	$Dashboard = New-UDDashboard -LoginPage $LoginPage -Pages @(
        $NewWarrantyParentPage,
        $NewWarrantyChildPage,
        $DiagnosticsPage,
        $ShipAndPrintWarrantyOrderPage,
        $UnShipWarrantyOrderPage,
        $SetShippingPrinterPage,
        $GetTicketInformationPage,
        $ShowTicketInformationPage
    ) -Title "Warranty Request Form" -EndpointInitialization $EndpointInitialization

	Start-UDDashboard -Dashboard $Dashboard -Port $Port -CertificateFile $CertificateFile -CertificateFilePassword $CertificateFilePassword -Wait
}

function Invoke-TervisWarrantyFormDashboard {
    $CertificateFilePassword = Get-TervisPasswordstatePassword -GUID "49d35824-dcce-4fc1-98ff-ebb7ecc971de" -AsCredential |
    Select-Object -ExpandProperty Password
    
    $ScriptContent = Get-Content -Path $MyInvocation.ScriptName -Raw
    $EndpointInitializationScript = [Scriptblock]::Create($ScriptContent.Replace("Invoke-TervisWarrantyFormDashboard",""))
    $File = Get-item -Path .\certificate.pfx
    New-TervisWarrantyFormDashboard -EndpointInitializationScript $EndpointInitializationScript -CertificateFile $File -CertificateFilePassword $CertificateFilePassword
}

function Install-TervisFreshDeskWarrantyForm {
	param (
		$ComputerName
    )
    $EnvironmentName = "Infrastructure"
    $ModuleName = "TervisWarrantyFormInternal"
    
    $PasswordstateAPIKey = Get-TervisPasswordstatePassword -Guid "3dfe3799-74f6-4dca-81b1-d37f355c790e" |
    Select-Object -ExpandProperty Password

    $Result = Install-PowerShellApplicationFiles -ScriptFileName Dashboard.ps1 -ComputerName $ComputerName -ModuleName $ModuleName -TervisModuleDependencies PasswordstatePowerShell,
        TervisPasswordstatePowershell,
        TervisMicrosoft.PowerShell.Security,
        TervisWarrantyRequest,
        TervisMicrosoft.PowerShell.Utility,
        TervisFreshDeskPowerShell,
        FreshDeskPowerShell,
        WebServicesPowerShellProxyBuilder,
        TervisPrintManagement,
        TervisProgisticsPowerShell,
        ProgisticsPowerShell,
        ShipWarranty,
        TervisApplication,
        TervisEnvironment,
        ZebraPowerShell,
        TCPClientPowerShell,
        TervisWCS,
        TervisWCSSybase,
        InvokeSQL,
        $ModuleName -CommandString @"
Set-PasswordstateAPIKey -APIKey $PasswordstateAPIKey
Set-PasswordstateAPIType -APIType Standard
Set-TervisPasswordstateAPIKeyPasswordListID -PasswordListID 312
Set-FreshDeskDomain -Domain Tervis
Set-FreshDeskCredentialScriptBlock -ScriptBlock {`$Cache:FreshDeskCredentials.`$User}
Set-TervisProgisticsEnvironment -Name Production
Invoke-TervisWarrantyFormDashboard
"@ -EnvironmentName $EnvironmentName -PowerShellGalleryDependencies @{Name="UniversalDashboard";RequiredVersion="2.2.1"} #2.3.0 breaks dynamic pages

    $Remote = $Result.PowerShellApplicationInstallDirectoryRemote
    $Local = $Result.PowerShellApplicationInstallDirectory

    if (-not (Test-Path -Path "$Remote\certificate.pfx")) {
        Get-TervisPasswordSateTervisDotComWildCardCertificate -Type pfx -OutPath $Remote
    }

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        nssm install TervisWarrantyFormInternal powershell.exe -file "$Using:Local\dashboard.ps1"
        nssm set TervisWarrantyFormInternal AppDirectory $Using:Local
    }
}