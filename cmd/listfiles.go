package cmd

import (
	"os"
	"strings"

	"github.com/99designs/keyring"
	"github.com/majd/ipatool/pkg/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func listFilesCmd() *cobra.Command {
	var keychainPassphrase string
	var acquireLicense bool
	var bundleID string
	var outputPath string

	cmd := &cobra.Command{
		Use:   "listfiles",
		Short: "List files in iOS app packages from the App Store",
		RunE: func(cmd *cobra.Command, args []string) error {

			appstore, err := newAppStore(cmd, keychainPassphrase)
			if err != nil {
				return errors.Wrap(err, "failed to create appstore client")
			}

			out, err := appstore.ListFiles(bundleID, acquireLicense)

			if err != nil {
				return err
			}

			logger := cmd.Context().Value("logger").(log.Logger)

			if outputPath == "" {
				logger.Log().Strs("output", out).Bool("success", true).Send()
			} else {
				pathsString := strings.Join(out, "\n")
				err := os.WriteFile(outputPath, []byte(pathsString), 0644)
				if err != nil {
					return err
				}
				logger.Log().Bool("success", true).Send()
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&bundleID, "bundle-identifier", "b", "", "The bundle identifier of the target iOS app (required)")
	cmd.Flags().BoolVar(&acquireLicense, "purchase", false, "Obtain a license for the app if needed")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "The destination path to write the files to")

	if keyringBackendType() == keyring.FileBackend {
		cmd.Flags().StringVar(&keychainPassphrase, "keychain-passphrase", "", "passphrase for unlocking keychain")
	}

	_ = cmd.MarkFlagRequired("bundle-identifier")

	return cmd
}
