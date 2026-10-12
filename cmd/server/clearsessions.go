package main

import (
	"fmt"
	"io"

	"github.com/JustIkra/umir-gateway/internal/adapters/accountfile"
	"github.com/JustIkra/umir-gateway/internal/config"
	"github.com/JustIkra/umir-gateway/internal/operator"
)

// clearSessions implements the clear-sessions command: it empties the session list of the account file
// and keeps the account. Run it with the gateway stopped after restoring an older backup, so sessions
// that were logged out since the backup cannot come back.
func clearSessions(cfg config.Operator, stdout io.Writer) error {
	state, store, err := accountfile.Open(cfg.StorePath, accountfile.Bootstrap{}, accountfile.Options{
		NewProfileID: newToken, Validate: operator.ValidateState,
	})
	if err != nil {
		return err
	}
	if err := store.Replace(operator.State{Account: state.Account}); err != nil {
		return fmt.Errorf("clear sessions: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "cleared sessions: %d\n", len(state.Sessions))
	return err
}
