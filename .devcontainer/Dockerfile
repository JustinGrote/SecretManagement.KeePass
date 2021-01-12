FROM mcr.microsoft.com/powershell:ubuntu-18.04
RUN pwsh -noprofile -noninteractive -c 'Install-Module PowershellGet -Scope AllUsers -AllowPrerelease -Force'
RUN pwsh -noprofile -noninteractive -c 'Register-PSResourceRepository -PSGallery -Trusted;Install-PSResource Pester -Scope AllUsers -Verbose;Install-PSResource -Scope AllUsers Microsoft.Powershell.SecretManagement'
