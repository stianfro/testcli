/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// extractPfxCmd represents the extract-pfx command
var extractPfxCmd = &cobra.Command{
	Use:   "extract-pfx [pfx-file] [domain]",
	Short: "Extract private key and certificate chain from PFX file",
	Long: `Extract private key and certificate chain from a PFX file using OpenSSL.
This command will:
1. Extract the private key to {domain}.key
2. Extract the full certificate chain to {domain}_full_chain.crt

Usage examples:
  testcli extract-pfx /path/to/cert.pfx example.com
  testcli extract-pfx ./mycert.pfx mydomain.org`,
	Args: cobra.ExactArgs(2),
	RunE: extractPfxRun,
}

func extractPfxRun(cmd *cobra.Command, args []string) error {
	pfxFilePath := args[0]
	domain := args[1]

	// Validate PFX file exists
	if _, err := os.Stat(pfxFilePath); os.IsNotExist(err) {
		return fmt.Errorf("file => %s does not exist!", pfxFilePath)
	}

	// Get password securely
	fmt.Print("PFX_Password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}
	fmt.Println() // Add newline after password input

	// Create temporary password file with restricted permissions
	tempFile, err := os.CreateTemp("", "pfx_password_*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name()) // Clean up temp file

	// Set restrictive permissions (0600 = rw-------)
	if err := os.Chmod(tempFile.Name(), 0o600); err != nil {
		return fmt.Errorf("failed to set temp file permissions: %v", err)
	}

	// Write password to temp file
	if _, err := tempFile.Write(password); err != nil {
		tempFile.Close()
		return fmt.Errorf("failed to write password to temp file: %v", err)
	}
	tempFile.Close()

	// Extract private key
	keyFile := fmt.Sprintf("%s.key", domain)
	if err := extractPrivateKey(pfxFilePath, tempFile.Name(), keyFile); err != nil {
		return fmt.Errorf("failed to extract private key: %v", err)
	}

	// Extract certificate chain
	certFile := fmt.Sprintf("%s_full_chain.crt", domain)
	if err := extractCertificateChain(pfxFilePath, tempFile.Name(), certFile); err != nil {
		return fmt.Errorf("failed to extract certificate chain: %v", err)
	}

	fmt.Printf("Successfully extracted:\n")
	fmt.Printf("  Private key: %s\n", keyFile)
	fmt.Printf("  Certificate chain: %s\n", certFile)

	return nil
}

func extractPrivateKey(pfxPath, passwordFile, outputFile string) error {
	// openssl pkcs12 -in ${PFX_FILEPATH} -nocerts -nodes -password file:temp.file | sed -ne '/-BEGIN PRIVATE KEY-/,/-END PRIVATE KEY-/p' > "${DOMAIN}.key"

	// First command: openssl pkcs12
	opensslCmd := exec.Command("openssl", "pkcs12", "-in", pfxPath, "-nocerts", "-nodes", "-password", "file:"+passwordFile)

	// Second command: sed to extract private key
	sedCmd := exec.Command("sed", "-ne", "/-BEGIN PRIVATE KEY-/,/-END PRIVATE KEY-/p")

	// Set up pipe between commands
	sedCmd.Stdin, _ = opensslCmd.StdoutPipe()

	// Create output file
	outputFileHandle, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %v", outputFile, err)
	}
	defer outputFileHandle.Close()

	sedCmd.Stdout = outputFileHandle

	// Start both commands
	if err := sedCmd.Start(); err != nil {
		return fmt.Errorf("failed to start sed command: %v", err)
	}

	if err := opensslCmd.Run(); err != nil {
		return fmt.Errorf("openssl command failed: %v", err)
	}

	if err := sedCmd.Wait(); err != nil {
		return fmt.Errorf("sed command failed: %v", err)
	}

	return nil
}

func extractCertificateChain(pfxPath, passwordFile, outputFile string) error {
	// openssl pkcs12 -in ${PFX_FILEPATH} -chain -nokeys -password file:temp.file | sed '/Attributes/d;/^$/d;/localKeyID/d;/friendlyName/d' > "${DOMAIN}_full_chain.crt"

	// First command: openssl pkcs12
	opensslCmd := exec.Command("openssl", "pkcs12", "-in", pfxPath, "-chain", "-nokeys", "-password", "file:"+passwordFile)

	// Second command: sed to clean up the output
	sedCmd := exec.Command("sed", "/Attributes/d;/^$/d;/localKeyID/d;/friendlyName/d")

	// Set up pipe between commands
	sedCmd.Stdin, _ = opensslCmd.StdoutPipe()

	// Create output file
	outputFileHandle, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %v", outputFile, err)
	}
	defer outputFileHandle.Close()

	sedCmd.Stdout = outputFileHandle

	// Start both commands
	if err := sedCmd.Start(); err != nil {
		return fmt.Errorf("failed to start sed command: %v", err)
	}

	if err := opensslCmd.Run(); err != nil {
		return fmt.Errorf("openssl command failed: %v", err)
	}

	if err := sedCmd.Wait(); err != nil {
		return fmt.Errorf("sed command failed: %v", err)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(extractPfxCmd)
}
