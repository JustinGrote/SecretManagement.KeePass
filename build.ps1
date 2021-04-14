#requires -version 5
using namespace System.IO

<#
.SYNOPSIS
Bootstraps Invoke-Build and starts it with supplied parameters.
.NOTES
If you already have Invoke-Build installed, just use Invoke-Build instead of this script. This is for CI/CD environments like Appveyor, Jenkins, or Azure DevOps pipelines.
.EXAMPLE
.\build.ps1
Starts Invoke-Build with the default parameters
#>

$ErrorActionPreference = 'Stop'

#Add TLS 1.2 to potential security protocols on Windows Powershell. This is now required for powershell gallery
if ($PSEdition -eq 'Desktop') {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 'Tls12'
}

function BootstrapModule {
    param (
        $ModuleSpecification,
        $Path = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Press')
    )
    $vEnvDir = New-Item -ItemType Directory -Force -Path $Path

    $env:PSModulePath = $vEnvDir,$env:PSModulePath -join [io.path]::PathSeparator

    #This is done for performance. If the module is found loaded it won't try to search filesystem
    $existingModule = (Get-Module -FullyQualifiedName $moduleSpecification -ErrorAction SilentlyContinue)
    if (-not $existingModule) {
        $existingModule = (Get-Module -ListAvailable -FullyQualifiedName $moduleSpecification -ErrorAction SilentlyContinue)
    }

    if ($existingModule) {
        Write-Verbose "Module $($moduleSpecification.ModuleName) was detected. Skipping bootstrap."
        return
    }

    $moduleParams = @{
        Name = $moduleSpecification.ModuleName
        MinimumVersion = $moduleSpecification.ModuleVersion
        MaximumVersion = $moduleSpecification.MaximumVersion
        Force = $true
        ErrorAction = 'Stop'
    }
    Write-Verbose "$($ModuleSpecification.ModuleName) not found locally. Bootstrapping..."
    Save-Module @moduleParams -Path $vEnvDir
    Import-Module @moduleParams
}

BootstrapModule @{
    ModuleName = 'InvokeBuild'
    ModuleVersion = '5.5.7'
    MaximumVersion = '5.99.99'
}

#Passthrough Invoke-Build
Push-Location $PSScriptRoot
try {
    Invoke-Expression "Invoke-Build $($args -join ' ')"
} catch {
    throw $PSItem
} finally {
    Pop-Location
}