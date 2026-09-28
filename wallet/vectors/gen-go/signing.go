// Signing vectors (#29 phase 2): the builder's spends, signed through the
// signing oracle. The oracle is go-sdk's ProtoWallet over a root key; every
// call the builder makes crosses as a BRC-100 wire frame (getPublicKey for
// input and change keys, createSignature over the BIP143/ForkID sighash as
// hashToDirectlySign — go-sdk's own pattern, transaction/template/pushdrop).
// Fees are go-sdk's: SatoshisPerKilobyte over the size with a P2PKH
// unlocking script estimated at 106 bytes (p2pkh.EstimateLength), one change
// output (Fee, ChangeDistributionEqual; dropped when the change is zero).
// Each signed input is verified by go-sdk's script interpreter.
package main

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	feemodel "github.com/bsv-blockchain/go-sdk/transaction/fee_model"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	p2pkhtpl "github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
)

type SignKey struct {
	KeyID        string `json:"keyID"`
	Counterparty string `json:"counterparty"` // "self" or a public key (hex)
}

type SignInput struct {
	SignKey
	SourceTx        string `json:"sourceTx"`
	SourceTxid      string `json:"sourceTxid"`
	Vout            uint32 `json:"vout"`
	Satoshis        uint64 `json:"satoshis"`
	LockingScript   string `json:"lockingScript"`
	PubKeyFrame     string `json:"getPublicKeyFrame"`
	PubKeyResult    string `json:"getPublicKeyResult"`
	PublicKey       string `json:"publicKey"`
	Preimage        string `json:"preimage"`
	Sighash         string `json:"sighash"` // hashToDirectlySign: go-sdk CalcInputSignatureHash
	SignFrame       string `json:"createSignatureFrame"`
	SignResult      string `json:"createSignatureResult"`
	UnlockingScript string `json:"unlockingScript"`
}

type SignOutput struct {
	Satoshis      uint64 `json:"satoshis"`
	LockingScript string `json:"lockingScript"`
}

type SignChange struct {
	SignKey
	PubKeyFrame   string  `json:"getPublicKeyFrame"`
	PubKeyResult  string  `json:"getPublicKeyResult"`
	PublicKey     string  `json:"publicKey"`
	LockingScript string  `json:"lockingScript"`
	Satoshis      *uint64 `json:"satoshis"` // null: dropped (no change left)
}

type SignCase struct {
	Name      string       `json:"name"`
	SatsPerKb uint64       `json:"satsPerKb"`
	Inputs    []SignInput  `json:"inputs"`
	Outputs   []SignOutput `json:"outputs"`
	Change    SignChange   `json:"change"`
	Fee       uint64       `json:"fee"`
	Tx        string       `json:"tx"`
	Txid      string       `json:"txid"`
}

func counterpartyOf(s string) wallet.Counterparty {
	if s == "self" {
		return wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}
	}
	return wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: must(ec.PublicKeyFromString(s))}
}

func pubKeyFrame(k SignKey) []byte {
	t := true
	params := must(serializer.SerializeGetPublicKeyArgs(&wallet.GetPublicKeyArgs{
		EncryptionArgs: wallet.EncryptionArgs{ProtocolID: brc29, KeyID: k.KeyID, Counterparty: counterpartyOf(k.Counterparty)},
		ForSelf:        &t,
	}))
	return serializer.WriteRequestFrame(serializer.RequestFrame{Call: 8, Originator: "", Params: params})
}

// A source transaction paying `sats` to `lock`, spending a made-up outpoint (seeded).
func sourceTx(seed string, sats uint64, lock *script.Script) *transaction.Transaction {
	tx := transaction.NewTransaction()
	unlock := must(script.NewFromHex("51"))
	prev := keyFrom(seed).PubKey().Hash()
	var h [32]byte
	copy(h[:], prev)
	tx.AddInput(&transaction.TransactionInput{SourceTXID: must(chainhash.NewHash(h[:])), SourceTxOutIndex: 0, UnlockingScript: unlock, SequenceNumber: 0xffffffff})
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: must(script.NewFromHex("6a"))}) // an OP_RETURN before ours: vout 1
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: sats, LockingScript: lock})
	return tx
}

func genSigning() (any, error) {
	ctx := context.Background()
	root := keyFrom("skein-wallet-root")
	proto := must(wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypePrivateKey, PrivateKey: root}))
	sender := keyFrom("brc29-sender-for-signing").PubKey().ToDERHex()
	payTo := func(k SignKey) (*ec.PublicKey, *script.Script) {
		t := true
		r := must(proto.GetPublicKey(ctx, wallet.GetPublicKeyArgs{EncryptionArgs: wallet.EncryptionArgs{ProtocolID: brc29, KeyID: k.KeyID, Counterparty: counterpartyOf(k.Counterparty)}, ForSelf: &t}, ""))
		return r.PublicKey, must(script.NewFromHex(p2pkh(r.PublicKey)))
	}
	type utxo struct {
		key  SignKey
		seed string
		sats uint64
	}
	u1 := utxo{SignKey{"cHJlZml4MQ== c3VmZml4MQ==", sender}, "src-1", 30000}
	u2 := utxo{SignKey{"Y2hhbmdlMA== Y2hhbmdlMQ==", "self"}, "src-2", 12345}
	u3 := utxo{SignKey{"cHJlZml4Mw== c3VmZml4Mw==", sender}, "src-3", 700}
	other := func(seed string) string { return p2pkh(keyFrom(seed).PubKey()) }
	cases := []struct {
		name   string
		rate   uint64
		ins    []utxo
		outs   []SignOutput
		change SignKey
	}{
		{"one-payment-in", 100, []utxo{u1}, []SignOutput{{10000, other("payee-a")}}, SignKey{"Y2g= MA==", "self"}},
		{"payment-and-change-in-two-out", 1, []utxo{u1, u2}, []SignOutput{{25000, other("payee-b")}, {1, other("payee-c")}}, SignKey{"Y2g= MQ==", "self"}},
		{"change-dropped", 100, []utxo{u3}, []SignOutput{{677, other("payee-d")}}, SignKey{"Y2g= Mg==", "self"}},
		{"high-rate", 12345, []utxo{u2, u3}, []SignOutput{{5000, other("payee-e")}}, SignKey{"Y2g= Mw==", "self"}},
	}
	var out []SignCase
	for _, c := range cases {
		tx := transaction.NewTransaction()
		sc := SignCase{Name: c.name, SatsPerKb: c.rate}
		for _, u := range c.ins {
			_, lock := payTo(u.key)
			src := sourceTx(u.seed, u.sats, lock)
			priv := must(wallet.NewKeyDeriver(root).DerivePrivateKey(brc29, u.key.KeyID, counterpartyOf(u.key.Counterparty)))
			tx.AddInputFromTx(src, 1, must(p2pkhtpl.Unlock(priv, nil)))
			sc.Inputs = append(sc.Inputs, SignInput{SignKey: u.key, SourceTx: src.Hex(), SourceTxid: src.TxID().String(), Vout: 1, Satoshis: u.sats, LockingScript: lock.String()})
		}
		for _, o := range c.outs {
			tx.AddOutput(&transaction.TransactionOutput{Satoshis: o.Satoshis, LockingScript: must(script.NewFromHex(o.LockingScript))})
			sc.Outputs = append(sc.Outputs, o)
		}
		changePub, changeLock := payTo(c.change)
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: changeLock, Change: true})
		model := &feemodel.SatoshisPerKilobyte{Satoshis: c.rate}
		sc.Fee = must(model.ComputeFee(tx))
		if err := tx.Fee(model, transaction.ChangeDistributionEqual); err != nil {
			return nil, fmt.Errorf("%s: %w", c.name, err)
		}
		sc.Change = SignChange{SignKey: c.change, PubKeyFrame: hex.EncodeToString(pubKeyFrame(c.change)), PublicKey: changePub.ToDERHex(), LockingScript: changeLock.String()}
		sc.Change.PubKeyResult = hex.EncodeToString(serializer.WriteResultFrame(must(serializer.SerializeGetPublicKeyResult(&wallet.GetPublicKeyResult{PublicKey: changePub})), nil))
		if last := tx.Outputs[len(tx.Outputs)-1]; last.Change {
			s := last.Satoshis
			sc.Change.Satoshis = &s
		}
		// Sign every input through the oracle, as the wallet program does.
		for i := range tx.Inputs {
			in := &sc.Inputs[i]
			pub, _ := payTo(in.SignKey)
			in.PubKeyFrame = hex.EncodeToString(pubKeyFrame(in.SignKey))
			in.PubKeyResult = hex.EncodeToString(serializer.WriteResultFrame(must(serializer.SerializeGetPublicKeyResult(&wallet.GetPublicKeyResult{PublicKey: pub})), nil))
			in.PublicKey = pub.ToDERHex()
			flag := sighash.AllForkID
			in.Preimage = hex.EncodeToString(must(tx.CalcInputPreimage(uint32(i), flag)))
			hash := must(tx.CalcInputSignatureHash(uint32(i), flag))
			in.Sighash = hex.EncodeToString(hash)
			args := wallet.CreateSignatureArgs{EncryptionArgs: wallet.EncryptionArgs{ProtocolID: brc29, KeyID: in.KeyID, Counterparty: counterpartyOf(in.Counterparty)}, HashToDirectlySign: hash}
			params := must(serializer.SerializeCreateSignatureArgs(&args))
			in.SignFrame = hex.EncodeToString(serializer.WriteRequestFrame(serializer.RequestFrame{Call: 15, Originator: "", Params: params}))
			sig := must(proto.CreateSignature(ctx, args, ""))
			in.SignResult = hex.EncodeToString(serializer.WriteResultFrame(must(serializer.SerializeCreateSignatureResult(sig)), nil))
			unlock := &script.Script{}
			_ = unlock.AppendPushData(append(sig.Signature.Serialize(), byte(flag)))
			_ = unlock.AppendPushData(pub.Compressed())
			tx.Inputs[i].UnlockingScript = unlock
			in.UnlockingScript = unlock.String()
		}
		for i, input := range tx.Inputs {
			if err := interpreter.NewEngine().Execute(interpreter.WithTx(tx, i, input.SourceTxOutput()), interpreter.WithForkID(), interpreter.WithAfterGenesis()); err != nil {
				return nil, fmt.Errorf("%s input %d: %w", c.name, i, err)
			}
		}
		sc.Tx = tx.Hex()
		sc.Txid = tx.TxID().String()
		out = append(out, sc)
	}
	return map[string]any{
		"about":       "The builder's spends signed through a ProtoWallet oracle (go-sdk), every call as a BRC-100 wire frame: getPublicKey (call 8; protocol [2, \"3241645161d8\"], keyID, counterparty the sender or self, forSelf) for each input's and the change key, createSignature (call 15) with hashToDirectlySign = CalcInputSignatureHash(i, ALL|FORKID). Inputs spend vout 1 of their source; outputs in order, then the change (P2PKH to the change key) unless the change is zero. Fee: SatoshisPerKilobyte over the size with 106-byte P2PKH unlocking estimates, change included. Every input verified by go-sdk's interpreter.",
		"rootKey":     hex.EncodeToString(root.Serialize()),
		"identityKey": root.PubKey().ToDERHex(),
		"cases":       out,
	}, nil
}
