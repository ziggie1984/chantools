package main

import (
	"errors"
	"fmt"

	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/spf13/cobra"
)

type deleteTombstoneCommand struct {
	ChannelDB string

	cmd *cobra.Command
}

func newDeleteTombstoneCommand() *cobra.Command {
	cc := &deleteTombstoneCommand{}
	cc.cmd = &cobra.Command{
		Use:   "deletetombstone",
		Short: "Delete the tombstone bucket from the channel database",
		Long: `This command deletes the tombstone bucket from the channel database.
This can be useful if you need to recover from a corrupted state where the
tombstone bucket is preventing normal operation.`,
		RunE: cc.Execute,
	}

	cc.cmd.Flags().StringVar(
		&cc.ChannelDB, "channeldb", "", "path to the channel.db file",
	)

	return cc.cmd
}

func (c *deleteTombstoneCommand) Execute(_ *cobra.Command, _ []string) error {
	// Check that we have a channel DB.
	if c.ChannelDB == "" {
		return errors.New("channel DB is required")
	}
	db, _, err := lnd.OpenDB(c.ChannelDB, false)
	if err != nil {
		return fmt.Errorf("error opening channel DB: %w", err)
	}
	defer func() { _ = db.Close() }()

	log.Infof("Deleting tombstone bucket")

	rwTx, err := db.BeginReadWriteTx()
	if err != nil {
		return err
	}

	success := false
	defer func() {
		if !success {
			_ = rwTx.Rollback()
		}
	}()

	// Delete the tombstone bucket
	if err := rwTx.DeleteTopLevelBucket(channeldb.TombstoneKey); err != nil {
		return fmt.Errorf("error deleting tombstone bucket: %w", err)
	}

	success = true
	return rwTx.Commit()
}
