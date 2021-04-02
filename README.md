# Encrypt and decrypt files using a self-signed, password protected certificate

## How to use

### Generating a certificate

Execute the powershell script `Create-SelfSignedCertificate.ps1` and specify a name for the certificate.

Use the parameter `-Force` to override existing certificates.

You will be asked to enter a password for the certificate but you can also specify it using the `-Password` parameter in
combination with `ConvertTo-SecureString`.

```powershell
.\Create-SelfSignedCertificate.ps1 -CommonName "CertificateName"
```

This Script will result in a `CertificateName.pfx`-file being created. Use this Certificate to encrypt / decrypt files.

### Encrypting and decrypting files

1. Copy the executables of the selected version to C:\Windows\ or execute them by using their absolute path
2. Open the directory to encrypt in a powershell / commandprompt window.
3. Execute the following command:

```powershell
# Encrypt files
# If the certificate is placed in the current folder it will not get encrypted by the program.
# This command will encrypt the files in the current directory and subdirectories
encrypt --cert "Path to certificate" --cert-passwd "Password of the certificate" --path "." # use . for the current directory

# Decrypt files
# This command will decrypt all encrypted files in the current directory and subdirectories
decrypt --cert "Path to certificate" --cert-passwd "Password of the certificate" --path "." # use . for the current directory
```

## Encryption methods

For each file a unique 32 Byte key is generated.

The unique key is used to encrypt the file using AES-CBC and saved with the `.crypt` extension.

The key used to encrypt the file is then encrypted using the public key of the certificate using RSA encryption with
OAEP (Optimal Asymmetric Encryption Padding) in combination with the SHA512 algorithm.

The encrypted key is stored in a file with the extension `.crypt.key` and stored next to the encrypted file.

## Changelog

### v1.0:

- Encrypt and decrypt files
- Generate a certificate using powershell

### v1.1:

- Added commandline parameters
    - [`--cert` {Path to certificate}] optional (Specify in the program)
    - [`--cert-passwd` {Password of the certificate}] optional (Specify in the program)
    - [`--path` {File or Directory to encrypt}} optional (Specify in the program)
