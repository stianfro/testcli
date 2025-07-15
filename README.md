# testcli

A CLI tool built with Cobra for certificate management tasks.

## Commands

### extract-pfx

Extract private key and certificate chain from a PFX (PKCS#12) file.

```bash
testcli extract-pfx [PFX_FILE] [DOMAIN]
```

**Options:**
- `--password string`: PFX password (if not provided, will prompt)

**Examples:**
```bash
# Prompt for password
testcli extract-pfx certificate.pfx example.com

# Provide password as flag
testcli extract-pfx certificate.pfx example.com --password mypassword
```

**Output:**
- `{DOMAIN}.key`: Private key in PEM format (600 permissions)
- `{DOMAIN}_full_chain.crt`: Certificate chain in PEM format (644 permissions)

This command replicates the functionality of the original bash script for extracting certificates and keys from PFX files.

## Building

```bash
go build -o testcli
```

## Usage

```bash
./testcli --help
```