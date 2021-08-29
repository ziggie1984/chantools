package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/guggero/chantools/btc"
	"github.com/guggero/chantools/lnd"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/spf13/cobra"
)

const (
	sweepRemoteClosedDefaultRecoveryWindow = 200
	sweepDustLimit                         = 600
)

type sweepRemoteClosedCommand struct {
	RecoveryWindow uint32
	APIURL         string
	Publish        bool
	SweepAddr      string
	FeeRate        uint16

	rootKey *rootKey
	cmd     *cobra.Command
}

func newSweepRemoteClosedCommand() *cobra.Command {
	cc := &sweepRemoteClosedCommand{}
	cc.cmd = &cobra.Command{
		Use: "sweepremoteclosed",
		Short: "Go through all the addresses that could have funds of " +
			"channels that were force-closed by the remote party. " +
			"A public block explorer is queried for each address " +
			"and if any balance is found, all funds are swept to " +
			"a given address",
		Long: `This command helps users sweep funds that are in 
outputs of channels that were force-closed by the remote party. This command
only needs to be used if no channel.backup file is available. By manually
contacting the remote peers and asking them to force-close the channels, the
funds can be swept after the force-close transaction was confirmed.

Supported remote force-closed channel types are:
 - STATIC_REMOTE_KEY (a.k.a. tweakless channels)
 - ANCHOR (a.k.a. anchor output channels)
`,
		Example: `chantools sweepremoteclosed \
	--recoverywindow 300 \
	--feerate 20 \
	--sweepaddr bc1q..... \
  	--publish`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().Uint32Var(
		&cc.RecoveryWindow, "recoverywindow",
		sweepRemoteClosedDefaultRecoveryWindow, "number of keys to "+
			"scan per derivation path",
	)
	cc.cmd.Flags().StringVar(
		&cc.APIURL, "apiurl", defaultAPIURL, "API URL to use (must "+
			"be esplora compatible)",
	)
	cc.cmd.Flags().BoolVar(
		&cc.Publish, "publish", false, "publish sweep TX to the chain "+
			"API instead of just printing the TX",
	)
	cc.cmd.Flags().StringVar(
		&cc.SweepAddr, "sweepaddr", "", "address to sweep the funds to",
	)
	cc.cmd.Flags().Uint16Var(
		&cc.FeeRate, "feerate", defaultFeeSatPerVByte, "fee rate to "+
			"use for the sweep transaction in sat/vByte",
	)

	cc.rootKey = newRootKey(cc.cmd, "sweeping the wallet")

	return cc.cmd
}

func (c *sweepRemoteClosedCommand) Execute(_ *cobra.Command, _ []string) error {
	extendedKey, err := c.rootKey.read()
	if err != nil {
		return fmt.Errorf("error reading root key: %v", err)
	}

	// Make sure sweep addr is set.
	if c.SweepAddr == "" {
		return fmt.Errorf("sweep addr is required")
	}

	// Set default values.
	if c.RecoveryWindow == 0 {
		c.RecoveryWindow = sweepRemoteClosedDefaultRecoveryWindow
	}
	if c.FeeRate == 0 {
		c.FeeRate = defaultFeeSatPerVByte
	}

	return sweepRemoteClosed(
		extendedKey, c.APIURL, c.SweepAddr, c.RecoveryWindow, c.FeeRate,
		c.Publish,
	)
}

type targetAddr struct {
	addr    btcutil.Address
	pubKey  *btcec.PublicKey
	path    string
	keyDesc *keychain.KeyDescriptor
	vouts   []*btc.Vout
	script  []byte
}

func sweepRemoteClosed(extendedKey *hdkeychain.ExtendedKey, apiURL,
	sweepAddr string, recoveryWindow uint32, feeRate uint16,
	publish bool) error {

	var (
		targets []*targetAddr
		api     = &btc.ExplorerAPI{BaseURL: apiURL}
	)
	for index := uint32(0); index < recoveryWindow; index++ {
		path := fmt.Sprintf("m/1017'/%d'/%d'/0/%d",
			chainParams.HDCoinType, keychain.KeyFamilyPaymentBase,
			index)
		parsedPath, err := lnd.ParsePath(path)
		if err != nil {
			return fmt.Errorf("error parsing path: %v", err)
		}

		hdKey, err := lnd.DeriveChildren(
			extendedKey, parsedPath,
		)
		if err != nil {
			return fmt.Errorf("eror deriving children: %v",
				err)
		}

		privKey, err := hdKey.ECPrivKey()
		if err != nil {
			return fmt.Errorf("could not derive private "+
				"key: %v", err)
		}

		foundTargets, err := queryAddressBalances(
			privKey.PubKey(), path, &keychain.KeyDescriptor{
				PubKey: privKey.PubKey(),
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamilyPaymentBase,
					Index:  index,
				},
			}, api,
		)
		if err != nil {
			return fmt.Errorf("could not query API for "+
				"addresses with funds: %v", err)
		}
		targets = append(targets, foundTargets...)
	}

	// Create estimator and transaction template.
	var (
		estimator        input.TxWeightEstimator
		signDescs        []*input.SignDescriptor
		sweepTx          = wire.NewMsgTx(2)
		totalOutputValue = uint64(0)
	)

	// Add all found target outputs.
	for _, target := range targets {
		for _, vout := range target.vouts {
			totalOutputValue += vout.Value

			txHash, err := chainhash.NewHashFromStr(
				vout.Outspend.Txid,
			)
			if err != nil {
				return fmt.Errorf("error parsing tx hash: %v",
					err)
			}
			pkScript, err := lnd.GetWitnessAddrScript(
				target.addr, chainParams,
			)
			if err != nil {
				return fmt.Errorf("error getting pk script: %v",
					err)
			}

			sequence := wire.MaxTxInSequenceNum
			switch target.addr.(type) {
			case *btcutil.AddressWitnessPubKeyHash:
				estimator.AddP2WKHInput()

			case *btcutil.AddressWitnessScriptHash:
				estimator.AddWitnessInput(
					input.ToRemoteConfirmedWitnessSize,
				)
				sequence = 1
			}

			sweepTx.TxIn = append(sweepTx.TxIn, &wire.TxIn{
				PreviousOutPoint: wire.OutPoint{
					Hash:  *txHash,
					Index: uint32(vout.Outspend.Vin),
				},
				Sequence: sequence,
			})

			signDescs = append(signDescs, &input.SignDescriptor{
				KeyDesc:       *target.keyDesc,
				WitnessScript: target.script,
				Output: &wire.TxOut{
					PkScript: pkScript,
					Value:    int64(vout.Value),
				},
				HashType: txscript.SigHashAll,
			})
		}
	}

	if len(targets) == 0 || totalOutputValue < sweepDustLimit {
		return fmt.Errorf("found %d sweep targets with total value "+
			"of %d satoshis which is below the dust limit of %d",
			len(targets), totalOutputValue, sweepDustLimit)
	}

	// Add our sweep destination output.
	sweepScript, err := lnd.GetP2WPKHScript(sweepAddr, chainParams)
	if err != nil {
		return err
	}
	estimator.AddP2WKHOutput()

	// Calculate the fee based on the given fee rate and our weight
	// estimation.
	feeRateKWeight := chainfee.SatPerKVByte(1000 * feeRate).FeePerKWeight()
	totalFee := feeRateKWeight.FeeForWeight(int64(estimator.Weight()))

	log.Infof("Fee %d sats of %d total amount (estimated weight %d)",
		totalFee, totalOutputValue, estimator.Weight())

	sweepTx.TxOut = []*wire.TxOut{{
		Value:    int64(totalOutputValue) - int64(totalFee),
		PkScript: sweepScript,
	}}

	// Sign the transaction now.
	var (
		signer = &lnd.Signer{
			ExtendedKey: extendedKey,
			ChainParams: chainParams,
		}
		sigHashes = txscript.NewTxSigHashes(sweepTx)
	)
	for idx, desc := range signDescs {
		desc.SigHashes = sigHashes
		desc.InputIndex = idx

		if len(desc.WitnessScript) > 0 {
			witness, err := input.CommitSpendToRemoteConfirmed(
				signer, desc, sweepTx,
			)
			if err != nil {
				return err
			}
			sweepTx.TxIn[idx].Witness = witness
		} else {
			// The txscript library expects the witness script of a
			// P2WKH descriptor to be set to the pkScript of the
			// output...
			desc.WitnessScript = desc.Output.PkScript
			witness, err := input.CommitSpendNoDelay(
				signer, desc, sweepTx, true,
			)
			if err != nil {
				return err
			}
			sweepTx.TxIn[idx].Witness = witness
		}
	}

	var buf bytes.Buffer
	err = sweepTx.Serialize(&buf)
	if err != nil {
		return err
	}

	// Publish TX.
	if publish {
		response, err := api.PublishTx(
			hex.EncodeToString(buf.Bytes()),
		)
		if err != nil {
			return err
		}
		log.Infof("Published TX %s, response: %s",
			sweepTx.TxHash().String(), response)
	}

	log.Infof("Transaction: %x", buf.Bytes())
	return nil
}

func queryAddressBalances(pubKey *btcec.PublicKey, path string,
	keyDesc *keychain.KeyDescriptor, api *btc.ExplorerAPI) ([]*targetAddr,
	error) {

	var targets []*targetAddr
	queryAddr := func(address btcutil.Address, script []byte) error {
		unspent, err := api.Unspent(address.EncodeAddress())
		if err != nil {
			return fmt.Errorf("could not query unspent: %v", err)
		}

		if len(unspent) > 0 {
			log.Infof("Found %d unspent outputs for address %v",
				len(unspent), address.EncodeAddress())
			targets = append(targets, &targetAddr{
				addr:    address,
				pubKey:  pubKey,
				path:    path,
				keyDesc: keyDesc,
				vouts:   unspent,
				script:  script,
			})
		}

		return nil
	}

	p2wkh, err := lnd.P2WKHAddr(pubKey, chainParams)
	if err != nil {
		return nil, err
	}
	if err := queryAddr(p2wkh, nil); err != nil {
		return nil, err
	}

	p2anchor, script, err := lnd.P2AnchorStaticRemote(pubKey, chainParams)
	if err != nil {
		return nil, err
	}
	if err := queryAddr(p2anchor, script); err != nil {
		return nil, err
	}

	return targets, nil
}