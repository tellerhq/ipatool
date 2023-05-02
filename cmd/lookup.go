package cmd

import (
	"github.com/99designs/keyring"
	"github.com/majd/ipatool/pkg/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func lookupCmd() *cobra.Command {
	var keychainPassphrase string

	cmd := &cobra.Command{
		Use:   "lookup <bundle_id",
		Short: "Lookup by bundle id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := newAppStore(cmd, keychainPassphrase)
			if err != nil {
				return errors.Wrap(err, "failed to create appstore client")
			}

			out, err := store.Lookup(args[0])
			if err != nil {
				return err
			}

			logger := cmd.Context().Value("logger").(log.Logger)
			logger.Log().Object("app", out.App).Send()

			return nil
		},
	}

	if keyringBackendType() == keyring.FileBackend {
		cmd.PersistentFlags().StringVar(&keychainPassphrase, "keychain-passphrase", "", "passphrase for unlocking keychain")
	}

	return cmd
}
