# TiO2 Decrypt

This tool allows decrypting backup files that were created by 
[Titanium Backup](https://play.google.com/store/apps/details?id=com.keramidas.TitaniumBackup) on Android.
It is heavily inspired by [TitaniumBackupDecrypt](https://github.com/bhafer/TitaniumBackupDecrypt), but I decided
to rewrite it in Rust to start learning the language as well as not have to install a PHP interpreter.

You invoke the program with `tio2_decryptor -i EncryptedBackup.tar.gz -o DecryptedBackup.tar.gz`.
Afterwards, it will ask the passphrase (that you specified in TitaniumBackup) on the CLI and then decrypt the provided
input file.