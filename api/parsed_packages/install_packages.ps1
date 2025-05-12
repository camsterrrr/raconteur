<#
.Notes
Author: Cameron Oakley (CJOakley@ucsc.edu)
Date: May 2025

.Synopsis
This Powershell script is used for our lab's research. In our dynamic testing environment, we install
    the necessary packages needed to run (potentially) malicious commands.

.Example
Sample Utilization: 
.\install_packages.ps1
#>

# Function to install the necessary packages for our dynamic testing environment.
function install_packages_via_winget {
    # Active Directory Domain Services
        # no valid search result...

    # Active Directory Module for Windows PowerShell
        # no valid search result...

    # Google Chrome
    Write-Host "Installing Google Chrome..."
    winget install --id Google.Chrome

    # Microsoft .NET
        # no valid search result...

    # Microsoft .NET Core
    Write-Host "Installing Microsoft .NET Core..."
    winget install --id Microsoft.DotNet.AspNetCore.3_0 # is this the correct package?

    # Microsoft .NET Framework
    Write-Host "Installing Microsoft .NET Framework..."
    winget install --id Microsoft.DotNet.SDK.Preview # is this the correct package?

    # Microsoft App-V
        # no valid search result...

    # Microsoft Azure
        # not sure which result we want.
        # Name                                 Id                              Version         Source
        # --------------------------------------------------------------------------------------------
        # Microsoft Azure Export for Terraform Microsoft.Azure.AztfExport      0.17.1          winget
        # Microsoft Azure Kubelogin            Microsoft.Azure.Kubelogin       0.2.8           winget
        # Microsoft Azure Quick Review         Microsoft.Azure.QuickReview     2.4.5           winget
        # Microsoft Azure Storage Emulator     Microsoft.Azure.StorageEmulator 5.10.19227.2113 winget
        # Microsoft Azure Storage Explorer     Microsoft.Azure.StorageExplorer 1.38.0          winget
        # Microsoft Azure CLI                  Microsoft.AzureCLI              2.72.0          winget
        # Microsoft Azure Service Fabric       Microsoft.ServiceFabricRuntime  10.1.2175.9590  winget
        # Microsoft Azure Service Fabric SDK   Microsoft.ServiceFabricSDK      7.1.2175.9590   winget

    # Microsoft Build Tools
    Write-Host "Installing Microsoft Build Tools..."
    winget install --id Microsoft.BuildTools2015 --source winget

    # Microsoft Edge
    Write-Host "Installing Microsoft Edge..."
    winget install --id Microsoft.Edge --source winget

    # Microsoft Office 2016
    # No official package found. Will Microsoft.Office suffice? Or is the command reliant on old libraries?

    # Microsoft Office
    Write-Host "Installing Microsoft Office..."
    winget install --id Microsoft.Office --source winget

    # Microsoft OneDrive
    Write-Host "Installing Microsoft OneDrive..."
    winget install --id Microsoft.OneDrvie --source winget

    # Microsoft Publisher
    Write-Host "Installing Microsoft Publisher..."
    winget install --id Microsoft.Office --source winget # included in the o365 package.

    # Microsoft Silverlight
        # not sure if this result is legit publisher.
        # winget search -q "silverlight"
        # Name                            Id                                  Version Match            Source
        # ---------------------------------------------------------------------------------------------------
        # Streaming Video Downloader Lite BinaryMark.StreamingVideoDownloader 7       Tag: silverlight winget

    # Microsoft SQL Server
    Write-Host "Installing Microsoft SQL Server..."
    winget install --id Microsoft.SQLServer.2022.Developer # there are a bunch of different options

    # Microsoft Teams
    Write-Host "Installing Microsoft Teams..."
    winget install --id Microsoft.Teams

    # Microsoft Test Authoring and Execution Framework

    # Microsoft Visual Studio
    Write-Host "Installing Microsoft Visual Studio..."
    winget install --id Microsoft.VisualStudioCode

    # Microsoft WCF Data Services
        # no valid search result... 

    # Microsoft Web Deploy
    Write-Host "Installing Microsoft Web Deploy..."
    winget install --id Microsoft.WebDeploy

    # Mozilla Firefox
    Write-Host "Installing Mozilla Firefox..."
    winget install --id Mozilla.Firefox

    # NetSecurity
        # no valid winget search result...

    # NetTCPIP
        # no valid winget search result...
        # Microsoft.Ntttcp?

    # NodeJS Visual Studio Tools
        # no valid winget search result...

    # OpenSSH
    Write-Host "Installing OpenSSH..."
    winget install --id Microsoft.OpenSSH.Preview

    # Opera
    Write-Host "Installing Opera..."
    winget install --id Opera.Opera

    # rclone
    Write-Host "Installing rclone..."
    winget install --id Rclone.Rclone

    # Remote Server Administration Tools
        # no valid winget search result...

    # SysInternals Suite
    Write-Host "Installing SysInternals Suite..."
    winget install --id Microsoft.Sysinternals

    # Windows Defender
        # no valid winget search result...

    # Windows Package Manager
        # no valid winget search result...
        # Microsoft.WingetCreate?

    # Windows SDK
    Write-Host "Installing Windows SDK..."
    winget install --id Microsoft.WindowsSDK.10.0.18362

    # Windows Subsystem for Linux
    Write-Host "Installing Windows Subsystem for Linux..."
    winget install --id Microsoft.WSL
}

install_packages_via_winget