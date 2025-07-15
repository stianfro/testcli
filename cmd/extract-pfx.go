/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"encoding/pem"
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/term"
)

// extractPfxCmd represents the extract-pfx command
var extractPfxCmd = &cobra.Command{
	Use:   "extract-pfx [PFX_FILE] [DOMAIN]",
	Short: "Extract private key and certificate chain from PFX file",
	Long: `Extract private key and certificate chain from a PFX (PKCS#12) file.

This command takes a PFX file and domain name as arguments, prompts for the PFX password,
and extracts the private key and certificate chain to separate files:
- {DOMAIN}.key: Private key in PEM format
- {DOMAIN}_full_chain.crt: Certificate chain in PEM format

Example:
  testcli extract-pfx certificate.pfx example.com
  testcli extract-pfx certificate.pfx example.com --password mypassword`,
	Args: cobra.ExactArgs(2),
	RunE: extractPfxRun,
}

var pfxPassword string

func init() {
	rootCmd.AddCommand(extractPfxCmd)
	extractPfxCmd.Flags().StringVar(&pfxPassword, "password", "", "PFX password (if not provided, will prompt)")
}

func extractPfxRun(cmd *cobra.Command, args []string) error {
	pfxFilePath := args[0]
	domain := args[1]

	// Validate PFX file exists
	if _, err := os.Stat(pfxFilePath); os.IsNotExist(err) {
		return fmt.Errorf("file => %s does not exist!", pfxFilePath)
	}

	// Get password from flag or prompt
	var password string
	if pfxPassword != "" {
		password = pfxPassword
	} else {
		// Read password from stdin (hidden)
		fmt.Print("PFX_Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %v", err)
		}
		fmt.Println() // Add newline after password input
		password = string(passwordBytes)
	}

	// Read PFX file
	pfxData, err := os.ReadFile(pfxFilePath)
	if err != nil {
		return fmt.Errorf("failed to read PFX file: %v", err)
	}

	// Parse PFX file using ToPEM
	pemBlocks, err := pkcs12.ToPEM(pfxData, password)
	if err != nil {
		return fmt.Errorf("failed to decode PFX file: %v", err)
	}

	var privateKeyPEM []byte
	var certificatePEM []byte

	for _, block := range pemBlocks {
		if block.Type == "PRIVATE KEY" {
			privateKeyPEM = pem.EncodeToMemory(block)
		} else if block.Type == "CERTIFICATE" {
			certificatePEM = append(certificatePEM, pem.EncodeToMemory(block)...)
		}
	}

	// Write private key to file
	keyFile := fmt.Sprintf("%s.key", domain)
	if err := os.WriteFile(keyFile, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	// Write certificate chain to file
	chainFile := fmt.Sprintf("%s_full_chain.crt", domain)
	if err := os.WriteFile(chainFile, certificatePEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	fmt.Printf("Successfully extracted:\n")
	fmt.Printf("  Private key: %s\n", keyFile)
	fmt.Printf("  Certificate chain: %s\n", chainFile)

	return nil
}

