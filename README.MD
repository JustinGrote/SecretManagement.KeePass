# KeePass Secret Management Extension
[![Actions][]][ActionsLink]

This is a simple proof-of-concept using a modified version of PoshKeePass to allow for cross platform usage.

![KeePass SecretManagement Demo](./images/KeePassSecretManagementDemo.gif)


# Quick Start

1. Create a keepass database with a master password
1. `Install-Module SecretManagement.KeePass`
1. Run the following command:
    ``` powershell
    Register-SecretVault -Name 'testVault' -ModuleName 'SecretManagement.Keepass' -VaultParameters @{
        Path = "path/to/my/vault.kdbx"
    }
    ```
1. List and create secrets as normal

[Actions]: https://github.com/JustinGrote/SecretManagement.KeePass/workflows/Test/badge.svg?branch=main
[ActionsLink]: https://github.com/JustinGrote/SecretManagement.KeePass/workflows