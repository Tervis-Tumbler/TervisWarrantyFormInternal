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
    $WarrantyParentTicket = $WarrantyRequest | New-WarrantyParentTicket -Credential $Cache:FreshDeskCredentials.$User
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
    New-WarrantyChildTicket -WarrantyParentTicketID $Session:WarrantyParentTicketID -Credential $Cache:FreshDeskCredentials.$User

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
    New-UDTable -Title "Warranty Parent" -Id "WarrantyParentTable" -Headers ID, FirstName, LastName, BusinessName, Address1, Address2, City, State, PostalCode, ResidentialOrBusinessAddress, PhoneNumber, Email, Action -Endpoint {
        $WarrantyRequest = Get-FreshDeskTicket -ID $Session:WarrantyParentTicketID -Credential $Cache:FreshDeskCredentials.$User |
        Where-Object {-Not $_.Deleted} |
        ConvertFrom-FreshDeskTicketToWarrantyRequest |
        Add-Member -MemberType NoteProperty -PassThru -Name Remove -Value (
            New-UDElement -Tag "a" -Attributes @{
                className = "btn"
                onClick = {
                    Remove-FreshDeskTicket -ID $Session:WarrantyParentTicketID -Credential $Cache:FreshDeskCredentials.$User
                    $Session:WarrantyChildTicketID | ForEach-Object { Remove-FreshDeskTicket -ID $_ -Credential $Cache:FreshDeskCredentials.$User}
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
        Out-UDTableData -Property ID, FirstName, LastName, BusinessName, Address1, Address2, City, State, PostalCode, ResidentialOrBusinessAddress, PhoneNumber, Email, Remove
    }
}

function New-UDTableWarrantyChild {
    New-UDTable -Title "Warranty Child" -Id "WarrantyChildTable" -Headers ID, Subject, Size, Quantity, ManufactureYear, ReturnReason, Action -Endpoint {
        $Session:WarrantyChildTicketID |
        ForEach-Object {
            Get-FreshDeskTicket -ID $_ -Credential $Cache:FreshDeskCredentials.$User |
            Where-Object {-Not $_.Deleted} |
            ConvertFrom-FreshDeskTicketToWarrantyRequestLine |
            Add-Member -MemberType NoteProperty -Name ID -Value $_ -PassThru |
            Select-Object -Property *, @{
                Name = "Remove"
                Expression = {
                    New-UDElement -Tag "a" -Attributes @{
                        className = "btn"
                        onClick = {
                            Remove-FreshDeskTicket -ID $_.ID -Credential $Cache:FreshDeskCredentials.$User
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

    $Port = 10001
	Get-UDDashboard | Where port -eq $Port | Stop-UDDashboard

	$NewWarrantyParentPage = New-UDPage -Name "Warranty Parent" -Content {
        New-UDInput -Title "New Warranty Parent" -Content {
            New-UDInputField -Type textbox -Name FirstName
            New-UDInputField -Type textbox -Name LastName
            New-UDInputField -Type textbox -Name BusinessName
            New-UDInputField -Type textbox -Name Address1
            New-UDInputField -Type textbox -Name Address2
            New-UDInputField -Type textbox -Name City
            New-UDInputField -Type select -Name State -Values (
                Get-WarrantyRequestPropertyValues -PropertyName State -Credential $Cache:FreshDeskCredentials.$User
            ) -DefaultValue "FL"

            New-UDInputField -Type textbox -Name PostalCode
            New-UDInputField -Type select -Name ResidentialOrBusinessAddress -Values (
                Get-WarrantyRequestPropertyValues -PropertyName ResidentialOrBusinessAddress -Credential $Cache:FreshDeskCredentials.$User
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
                $Email
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
                        Get-WarrantyRequestPropertyValues -PropertyName Size -Credential $Cache:FreshDeskCredentials.$User
                    ) -DefaultValue "10oz (5 1/2)"
                    New-UDInputField -Name Quantity -Type select -Values (1..100)
                    New-UDInputField -Name ManufactureYear -Type select -Values (
                        Get-WarrantyRequestPropertyValues -PropertyName ManufactureYear -Credential $Cache:FreshDeskCredentials.$User
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
                $Agent = Get-FreshDeskAgent -Me -Credential $Credential
                
                if ($Cache:FreshDeskCredentials.ContainsKey($Agent.contact.email)) {
                    $Cache:FreshDeskCredentials.Remove($Agent.contact.email) | Out-Null
                }

                $Cache:FreshDeskCredentials.Add($Agent.contact.email, $Credential)
                New-UDAuthenticationResult -Success -UserName $Agent.contact.email
            } catch {
                New-UDAuthenticationResult -ErrorMessage "FreshDesk login failed"
            }
        }
    )

	$Dashboard = New-UDDashboard -LoginPage $LoginPage -Pages @($NewWarrantyParentPage, $NewWarrantyChildPage, $DiagnosticsPage) -Title "Warranty Request Form" -EndpointInitializationScript $EndpointInitializationScript
	Start-UDDashboard -Dashboard $Dashboard -Port $Port -AllowHttpForLogin -CertificateFile $CertificateFile -CertificateFilePassword $CertificateFilePassword
}

function Invoke-TervisWarrantyFormDashboard {
    if (-not (Test-Path -Path certificate.pfx)) {
        Get-PasswordstateDocument -DocumentID 11 -OutFile certificate.pfx -DocumentLocation password
    }
    $CertificateFilePassword = Get-PasswordstatePassword -ID 4335 -AsCredential | Select-Object -ExpandProperty Password

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

    Install-PowerShellApplicationFiles -ScriptFileName Dashboard.ps1 -ComputerName $ComputerName -ModuleName $ModuleName -TervisModuleDependencies PasswordstatePowerShell,
        TervisWarrantyRequest,
        TervisMicrosoft.PowerShell.Utility,
        TervisFreshDeskPowerShell,
        FreshDeskPowerShell,
        WebServicesPowerShellProxyBuilder -PowerShellGalleryDependencies UniversalDashboard -CommandString @"
Set-FreshDeskDomain -Domain Tervis
Invoke-TervisWarrantyFormDashboard
"@ -EnvironmentName $EnvironmentName
}