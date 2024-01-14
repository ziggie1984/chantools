package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/chantools/dump"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/spf13/cobra"
)

type decryptChanUpdateCommand struct {
	APIURL       string
	commitmentTx *wire.MsgTx
	TxID         string
	RawTx        string

	ChannelBackup string
	ChannelPoint  string

	rootKey *rootKey
	cmd     *cobra.Command
}

const (
	StateHintSize = 6
)

func newDecryptChanUpdateCommand() *cobra.Command {
	cc := &decryptChanUpdateCommand{}
	cc.cmd = &cobra.Command{
		Use: "decryptchanupdate",
		Short: "extracts the exact chanupdate number of a force close " +
			"transaction",
		Long: `TBD`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().StringVar(
		&cc.APIURL, "apiurl", defaultAPIURL, "API URL to use (must "+
			"be esplora compatible)",
	)
	cc.cmd.Flags().StringVar(
		&cc.TxID, "txid", "", "force close txid",
	)
	cc.cmd.Flags().StringVar(
		&cc.RawTx, "txhex", "", "force close rawtx",
	)
	cc.cmd.Flags().StringVar(
		&cc.ChannelBackup, "frombackup", "", "channel backup file to "+
			"read the channel information from",
	)
	cc.cmd.Flags().StringVar(
		&cc.ChannelPoint, "channelpoint", "", "channel point to use "+
			"for locating the channel in the channel backup file "+
			"specified in the --frombackup flag, "+
			"format: txid:index",
	)

	cc.rootKey = newRootKey(cc.cmd, "deriving keys")

	return cc.cmd
}

func createStateHintObfuscator(state *dump.BackupSingle) [StateHintSize]byte {
	localPaymentBasePoint, err := pubKeyFromHex(state.LocalChanCfg.PaymentBasePoint.PubKey)
	if err != nil {
		fmt.Errorf("error converting pubkey: %v", err)
	}

	remotePaymentBasePoint, err := pubKeyFromHex(state.RemoteChanCfg.PaymentBasePoint.PubKey)
	if err != nil {
		fmt.Errorf("error converting pubkey: %v", err)
	}

	if state.IsInitiator {
		return deriveStateHintObfuscator(
			localPaymentBasePoint,
			remotePaymentBasePoint,
		)
	}

	return deriveStateHintObfuscator(
		remotePaymentBasePoint,
		localPaymentBasePoint,
	)
}

func deriveStateHintObfuscator(key1, key2 *btcec.PublicKey) [StateHintSize]byte {
	h := sha256.New()
	h.Write(key1.SerializeCompressed())
	h.Write(key2.SerializeCompressed())

	sha := h.Sum(nil)

	var obfuscator [StateHintSize]byte
	copy(obfuscator[:], sha[26:])

	return obfuscator
}

func (c *decryptChanUpdateCommand) Execute(_ *cobra.Command, _ []string) error {
	extendedKey, err := c.rootKey.read()
	if err != nil {
		return fmt.Errorf("error reading root key: %w", err)
	}

	// Parse the commitment transaction via the API
	if c.RawTx != "" && c.TxID != "" {
		return fmt.Errorf("either provide the txid or the rawtx")
	}

	var locktime, sequence uint32
	if c.TxID != "" {
		api := newExplorerAPI(c.APIURL)
		tx, err := api.Transaction(c.TxID)
		if err != nil {
			return fmt.Errorf("error fetching tx: %w", err)
		}

		locktime = tx.Locktime
		sequence = tx.Vin[0].Sequence
	}

	if c.RawTx != "" {
		tx, err := hex.DecodeString(c.RawTx)
		if err != nil {
			return err
		}

		// Deserialize the transaction to get the transaction hash.
		msgTx := &wire.MsgTx{}
		txReader := bytes.NewReader(tx)
		if err := msgTx.Deserialize(txReader); err != nil {
			return err
		}
		locktime = msgTx.LockTime
		sequence = msgTx.TxIn[0].Sequence
	}

	// We have the Encrypted Locktime and Sequence, now we need to
	// decrypt these.
	// We create

	if c.ChannelPoint == "" || c.ChannelBackup == "" {
		return fmt.Errorf("channel point is required with " +
			"--frombackup")
	}

	backupChan, err := lnd.ExtractChannel(
		extendedKey, chainParams, c.ChannelBackup,
		c.ChannelPoint,
	)
	if err != nil {
		return fmt.Errorf("error extracting channel: %w", err)
	}

	path, err := lnd.ParsePath(backupChan.LocalChanCfg.PaymentBasePoint.Path)
	if err != nil {
		return err
	}
	localPrivPaymentKey, err := lnd.DeriveChildren(extendedKey, path)
	if err != nil {
		return err
	}
	localPaymentKey, err := localPrivPaymentKey.ECPubKey()
	backupChan.LocalChanCfg.PaymentBasePoint.PubKey = hex.EncodeToString(localPaymentKey.SerializeCompressed())

	fmt.Println("Local:", backupChan.LocalChanCfg.PaymentBasePoint)
	fmt.Println("Remote:", backupChan.RemoteChanCfg.PaymentBasePoint)

	txShell := &wire.MsgTx{
		LockTime: locktime,
		TxIn: []*wire.TxIn{{
			Sequence: sequence,
		}},
	}

	obfuscator := createStateHintObfuscator(backupChan)

	stateHint := lnwallet.GetStateNumHint(txShell, obfuscator)

	fmt.Println("StateHint:", stateHint)

	return nil
}
