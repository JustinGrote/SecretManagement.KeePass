# KeePass Secret Management Extension

## Actions

[![Actions][]][ActionsLink]

## Summary

This is a simple proof-of-concept using a modified version of PoshKeePass to allow for cross platform usage.

![KeePass SecretManagement Demo](./images/KeePassSecretManagementDemo.gif)

## Quick Start

1. Create a keepass database with a master password, Keyfile or both.
1. `Install-Module SecretManagement.KeePass`
1. Run the following command:

    ```powershell
    Register-SecretVault -Name 'testVault' -ModuleName 'SecretManagement.Keepass' -VaultParameters @{
        Path = "path/to/my/vault.kdbx"
        UseMasterPassword = $true
        KeyPath= "path/to/my/keyfile.key"
    }
    ```

1. (optional) Use Test-SecretVault to validate your connection to the vault

    ```powershell
    Test-SecretVault -VaultName 'testVault'
    ```

2. Get the secret data using Get-Secret

    ```powershell
    Get-Secret -Name 'My secret entry 1' -VaultName 'testVault'
    ```

# Vault Parameters
- `Path`: Path to your keepass database
- `KeyPath`: Path to your keepass keyfile, if required for your vault
- `UseWindowsAccount`: Set to true if your vault is locked with your windows Account
- `ShowFullPath`: Set to `$true` to display the full path of secret keys. Useful if you have keys with duplicate names in multiple
- `ShowRecyleBin`: Set to `$true` to have deleted recycle bin entries included in the results.

[Actions]: https://github.com/JustinGrote/SecretManagement.KeePass/workflows/Test/badge.svg?branch=main
[ActionsLink]: https://github.com/JustinGrote/SecretManagement.KeePass/workflows