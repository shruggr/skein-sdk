// gen-go: the test-vector corpus for wallet-zig, computed by the reference
// implementations (go-sdk, go-chaintracks) — issue #14's rule: every ported
// builder function gets vectors from go-sdk or the TS toolbox before it is used.
//
//	go run . extract   go-sdk test fixtures + universal-test-vectors → ../inputs/fixtures.json
//	go run . fetch     mainnet headers for the fixtures' BUMP heights + a run → ../inputs/mainnet-headers.json (WhatsOnChain)
//	go run . gen       ../inputs/*.json → ../{tx,beef,merkle_path,headers,brc29,wire}.json
//
// `extract` and `fetch` snapshot their inputs into ../inputs (checked in), so
// `gen` is offline and reproducible. Every expected value in the output is
// what the reference library returns; nothing here re-implements a rule,
// except where noted (the proof-of-work comparison, cross-checked against the
// TS toolbox by ../gen-ts/check-headers.ts).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/block"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	feemodel "github.com/bsv-blockchain/go-sdk/transaction/fee_model"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
)

const (
	goSDK = "/home/shruggr/Work/bsv/go-sdk"
	utv   = "/home/shruggr/go/pkg/mod/github.com/bsv-blockchain/universal-test-vectors@v0.6.1"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gen-go extract|fetch|gen")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "extract":
		err = extract()
	case "fetch":
		err = fetch()
	case "gen":
		err = gen()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-go:", err)
		os.Exit(1)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ---------------------------------------------------------------- extract

// Fixture is a named hex blob and where it came from.
type Fixture struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Hex    string `json:"hex"`
}

type Fixtures struct {
	Beefs []Fixture `json:"beefs"`
	Txs   []Fixture `json:"txs"`
	Bumps []Fixture `json:"bumps"`
}

var goConst = regexp.MustCompile(`(?m)^\s*(?:var |const )?(\w+)\s*(?::=|=)\s*"([0-9a-fA-F+/=A-Za-z]+)"`)

// constsIn returns the string constants/vars named in `names` from a Go test file.
func constsIn(file string, names ...string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(goSDK, file))
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := map[string]string{}
	for _, m := range goConst.FindAllStringSubmatch(string(b), -1) {
		if want[m[1]] {
			if _, dup := out[m[1]]; !dup {
				out[m[1]] = m[2]
			}
		}
	}
	for _, n := range names {
		if _, ok := out[n]; !ok {
			return nil, fmt.Errorf("%s: %s not found", file, n)
		}
	}
	return out, nil
}

func extract() error {
	var f Fixtures
	beef, err := constsIn("transaction/beef_test.go", "BRC62Hex", "BEEF", "BEEFSet")
	if err != nil {
		return err
	}
	f.Beefs = append(f.Beefs,
		Fixture{"brc62", "go-sdk transaction/beef_test.go BRC62Hex", beef["BRC62Hex"]},
		Fixture{"beef-v1-base64", "go-sdk transaction/beef_test.go BEEF (base64)", hex.EncodeToString(must(base64.StdEncoding.DecodeString(beef["BEEF"])))},
		Fixture{"beef-set-v2", "go-sdk transaction/beef_test.go BEEFSet", beef["BEEFSet"]},
	)
	mp, err := constsIn("transaction/merklepath_test.go", "BRC74Hex", "wocBumpHex", "wocBeefHex", "tsSDKBumpHex")
	if err != nil {
		return err
	}
	f.Beefs = append(f.Beefs, Fixture{"woc-coinbase-only", "go-sdk transaction/merklepath_test.go wocBeefHex", mp["wocBeefHex"]})
	f.Bumps = append(f.Bumps,
		Fixture{"brc74", "go-sdk transaction/merklepath_test.go BRC74Hex", mp["BRC74Hex"]},
		Fixture{"woc-single-leaf", "go-sdk transaction/merklepath_test.go wocBumpHex", mp["wocBumpHex"]},
		Fixture{"ts-sdk-single-leaf", "go-sdk transaction/merklepath_test.go tsSDKBumpHex", mp["tsSDKBumpHex"]},
	)
	txt, err := constsIn("transaction/transaction_test.go", "sourceRawtx", "sourceMerklePathHex", "sourceRawTx")
	if err != nil {
		return err
	}
	f.Txs = append(f.Txs,
		Fixture{"tx-test-source-1", "go-sdk transaction/transaction_test.go sourceRawtx", txt["sourceRawtx"]},
		Fixture{"tx-test-source-2", "go-sdk transaction/transaction_test.go sourceRawTx", txt["sourceRawTx"]},
	)
	f.Bumps = append(f.Bumps, Fixture{"tx-test-source-1-path", "go-sdk transaction/transaction_test.go sourceMerklePathHex", txt["sourceMerklePathHex"]})

	for _, n := range []string{"1-in-1-out", "1-in-2-out", "2-in-1-out", "3-single-source-inputs"} {
		var v map[string]any
		if err := readJSON(filepath.Join(utv, "generated/bsv-tx", n+".json"), &v); err != nil {
			return err
		}
		src := "universal-test-vectors v0.6.1 generated/bsv-tx/" + n + ".json"
		f.Txs = append(f.Txs, Fixture{"utv-" + n, src + " raw_hex", v["raw_hex"].(string)})
		f.Beefs = append(f.Beefs,
			Fixture{"utv-" + n + "-v1", src + " beef_hex", v["beef_hex"].(string)},
			Fixture{"utv-" + n + "-v2", src + " beef_v2_hex", v["beef_v2_hex"].(string)},
			Fixture{"utv-" + n + "-atomic", src + " atomic_beef_hex", v["atomic_beef_hex"].(string)},
		)
	}
	return writeJSON("../inputs/fixtures.json", f)
}

// ---------------------------------------------------------------- fetch

type WocBlock struct {
	Hash         string `json:"hash"`
	Height       uint32 `json:"height"`
	Version      int32  `json:"version"`
	MerkleRoot   string `json:"merkleroot"`
	Time         uint32 `json:"time"`
	Bits         string `json:"bits"`
	Nonce        uint32 `json:"nonce"`
	PreviousHash string `json:"previousblockhash"`
}

// MainnetHeader is one fetched header: its 80 bytes, rebuilt from WhatsOnChain's fields and checked against its hash.
type MainnetHeader struct {
	Height uint32 `json:"height"`
	Hash   string `json:"hash"`
	Hex    string `json:"hex"`
}

// The run of consecutive headers used for chain validation vectors.
const runStart, runLen = 814430, 12

// The first mainnet headers from genesis: the wallet's chain is anchored at
// the network's genesis header (#29), so its chain tests start there.
const genesisRunLen = 11

func fetch() error {
	var f Fixtures
	if err := readJSON("../inputs/fixtures.json", &f); err != nil {
		return err
	}
	heights := map[uint32]bool{}
	for h := uint32(runStart); h < runStart+runLen; h++ {
		heights[h] = true
	}
	for h := uint32(0); h < genesisRunLen; h++ {
		heights[h] = true
	}
	for _, b := range f.Beefs {
		if strings.HasPrefix(b.Name, "utv-") || strings.HasPrefix(b.Name, "woc-") {
			continue // synthetic heights / testnet
		}
		bf, _, _, err := transaction.ParseBeef(must(hex.DecodeString(b.Hex)))
		if err != nil {
			return fmt.Errorf("%s: %w", b.Name, err)
		}
		for _, p := range bf.BUMPs {
			heights[p.BlockHeight] = true
		}
	}
	for _, b := range f.Bumps {
		if b.Name == "brc74" || b.Name == "tx-test-source-1-path" {
			heights[must(transaction.NewMerklePathFromHex(b.Hex)).BlockHeight] = true
		}
	}
	var hs []uint32
	for h := range heights {
		hs = append(hs, h)
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i] < hs[j] })
	var out []MainnetHeader
	for _, h := range hs {
		var w WocBlock
		for attempt := 0; ; attempt++ {
			resp, err := http.Get(fmt.Sprintf("https://api.whatsonchain.com/v1/bsv/main/block/height/%d", h))
			if err == nil && resp.StatusCode == 200 {
				err = json.NewDecoder(resp.Body).Decode(&w)
				resp.Body.Close()
				if err == nil {
					break
				}
			} else if resp != nil {
				resp.Body.Close()
			}
			if attempt > 5 {
				return fmt.Errorf("height %d: %v", h, err)
			}
			time.Sleep(2 * time.Second)
		}
		bits, err := hex.DecodeString(w.Bits)
		if err != nil || len(bits) != 4 {
			return fmt.Errorf("height %d: bits %q", h, w.Bits)
		}
		if h == 0 {
			w.PreviousHash = strings.Repeat("0", 64) // WhatsOnChain leaves it out for genesis
		}
		hdr := block.Header{
			Version:    w.Version,
			PrevHash:   *must(chainhash.NewHashFromHex(w.PreviousHash)),
			MerkleRoot: *must(chainhash.NewHashFromHex(w.MerkleRoot)),
			Timestamp:  w.Time,
			Bits:       binary.BigEndian.Uint32(bits),
			Nonce:      w.Nonce,
		}
		if hdr.Hash().String() != w.Hash {
			return fmt.Errorf("height %d: rebuilt header hashes to %s, not %s", h, hdr.Hash(), w.Hash)
		}
		out = append(out, MainnetHeader{Height: h, Hash: w.Hash, Hex: hdr.Hex()})
		time.Sleep(400 * time.Millisecond)
	}
	return writeJSON("../inputs/mainnet-headers.json", out)
}

// ---------------------------------------------------------------- gen

func gen() error {
	var f Fixtures
	if err := readJSON("../inputs/fixtures.json", &f); err != nil {
		return err
	}
	var mh []MainnetHeader
	if err := readJSON("../inputs/mainnet-headers.json", &mh); err != nil {
		return err
	}
	steps := []struct {
		file string
		f    func() (any, error)
	}{
		{"../tx.json", func() (any, error) { return genTx(f) }},
		{"../beef.json", func() (any, error) { return genBeef(f) }},
		{"../merkle_path.json", func() (any, error) { return genMerklePath(f, mh) }},
		{"../headers.json", func() (any, error) { return genHeaders(mh) }},
		{"../brc29.json", func() (any, error) { return genBrc29() }},
		{"../wire.json", func() (any, error) { return genWire() }},
		{"../signing.json", genSigning},
	}
	for _, s := range steps {
		v, err := s.f()
		if err != nil {
			return fmt.Errorf("%s: %w", s.file, err)
		}
		if err := writeJSON(s.file, v); err != nil {
			return err
		}
	}
	return nil
}

// ---- transactions + fees

type TxInput struct {
	SourceTxid      string `json:"sourceTxid"`
	SourceVout      uint32 `json:"sourceVout"`
	Sequence        uint32 `json:"sequence"`
	UnlockingScript string `json:"unlockingScript"`
}
type TxOutput struct {
	Satoshis      uint64 `json:"satoshis"`
	LockingScript string `json:"lockingScript"`
}
type Fee struct {
	SatsPerKb uint64 `json:"satsPerKb"`
	Fee       uint64 `json:"fee"`
}
type TxCase struct {
	Name     string     `json:"name"`
	Source   string     `json:"source"`
	Hex      string     `json:"hex"`
	Txid     string     `json:"txid"`
	Version  uint32     `json:"version"`
	LockTime uint32     `json:"lockTime"`
	Size     int        `json:"size"`
	Inputs   []TxInput  `json:"inputs"`
	Outputs  []TxOutput `json:"outputs"`
	Fees     []Fee      `json:"fees"`
}

var feeRates = []uint64{0, 1, 10, 50, 100, 250, 500, 999, 1000, 1001, 12345}

func txCase(name, source string, tx *transaction.Transaction) (TxCase, error) {
	c := TxCase{Name: name, Source: source, Hex: tx.Hex(), Txid: tx.TxID().String(), Version: tx.Version, LockTime: tx.LockTime, Size: tx.Size()}
	for _, in := range tx.Inputs {
		us := ""
		if in.UnlockingScript != nil {
			us = hex.EncodeToString(*in.UnlockingScript)
		}
		c.Inputs = append(c.Inputs, TxInput{in.SourceTXID.String(), in.SourceTxOutIndex, in.SequenceNumber, us})
	}
	for _, o := range tx.Outputs {
		c.Outputs = append(c.Outputs, TxOutput{o.Satoshis, hex.EncodeToString(*o.LockingScript)})
	}
	for _, r := range feeRates {
		fee, err := (&feemodel.SatoshisPerKilobyte{Satoshis: r}).ComputeFee(tx)
		if err != nil {
			if len(tx.Inputs) > 0 && len(*tx.Inputs[0].UnlockingScript) == 0 {
				continue // no unlocking script: go-sdk refuses (ErrNoUnlockingScript)
			}
			return c, err
		}
		c.Fees = append(c.Fees, Fee{r, fee})
	}
	return c, nil
}

func genTx(f Fixtures) (any, error) {
	var cases []TxCase
	seen := map[string]bool{}
	add := func(name, source string, tx *transaction.Transaction) error {
		id := tx.TxID().String()
		if seen[id] {
			return nil
		}
		seen[id] = true
		c, err := txCase(name, source, tx)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		cases = append(cases, c)
		return nil
	}
	for _, t := range f.Txs {
		tx, err := transaction.NewTransactionFromHex(t.Hex)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.Name, err)
		}
		if err := add(t.Name, t.Source, tx); err != nil {
			return nil, err
		}
	}
	// Every transaction inside the BEEF fixtures, too.
	for _, b := range f.Beefs {
		bf, _, _, err := transaction.ParseBeef(must(hex.DecodeString(b.Hex)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", b.Name, err)
		}
		for _, id := range sortedTxids(bf) {
			if btx := bf.Transactions[id]; btx.Transaction != nil {
				if err := add(b.Name+"/"+id.String()[:8], b.Source, btx.Transaction); err != nil {
					return nil, err
				}
			}
		}
	}
	// A size grid for the fee model: one input, one output, script lengths chosen
	// to cross the varint and rounding boundaries.
	var grid []TxCase
	for _, n := range []int{0, 1, 75, 76, 252, 253, 254, 700, 911, 912, 913, 1000, 65535, 65536} {
		tx := transaction.NewTransaction()
		us := script.Script(make([]byte, 107))
		for i := range us {
			us[i] = byte(i)
		}
		prev := chainhash.DoubleHashH([]byte(fmt.Sprintf("grid-%d", n)))
		tx.AddInput(&transaction.TransactionInput{SourceTXID: &prev, SourceTxOutIndex: uint32(n % 7), UnlockingScript: &us, SequenceNumber: 0xffffffff})
		ls := script.Script(make([]byte, n))
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: uint64(n) * 1000, LockingScript: &ls})
		c, err := txCase(fmt.Sprintf("fee-grid-%d", n), "go-sdk-built: 1 input (107-byte unlocking script), 1 output with an n-byte locking script", tx)
		if err != nil {
			return nil, err
		}
		grid = append(grid, c)
	}
	return map[string]any{
		"about": "Transaction serialization, txid (display order: byte-reversed double-SHA256) and fee (go-sdk fee_model.SatoshisPerKilobyte.ComputeFee) for each case.",
		"cases": append(cases, grid...),
	}, nil
}

func sortedTxids(b *transaction.Beef) []chainhash.Hash {
	var ids []chainhash.Hash
	for id := range b.Transactions {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	return ids
}

// ---- BEEF

type BeefTxCase struct {
	Txid      string `json:"txid"`
	Format    string `json:"format"` // raw | rawWithBump | txidOnly
	BumpIndex *int   `json:"bumpIndex,omitempty"`
}
type BumpCase struct {
	BlockHeight uint32 `json:"blockHeight"`
	Hex         string `json:"hex"`
}
type BeefCase struct {
	Name          string       `json:"name"`
	Source        string       `json:"source"`
	Hex           string       `json:"hex"`
	Version       string       `json:"version"` // v1 | v2
	Atomic        bool         `json:"atomic"`
	SubjectTxid   string       `json:"subjectTxid,omitempty"` // atomic: the txid it names; else the last tx
	Bumps         []BumpCase   `json:"bumps"`
	Txs           []BeefTxCase `json:"txs"`           // sorted by txid
	Valid         bool         `json:"valid"`         // go-sdk Beef.IsValid(false)
	ValidTxidOnly bool         `json:"validTxidOnly"` // go-sdk Beef.IsValid(true)
	Reserialized  string       `json:"reserialized"`  // go-sdk Beef.Bytes() of the parsed BEEF (tx order is go-sdk's)
}

func genBeef(f Fixtures) (any, error) {
	var cases []BeefCase
	for _, b := range f.Beefs {
		raw := must(hex.DecodeString(b.Hex))
		bf, subjectTx, subject, err := transaction.ParseBeef(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", b.Name, err)
		}
		c := BeefCase{Name: b.Name, Source: b.Source, Hex: b.Hex, Valid: bf.IsValid(false), ValidTxidOnly: bf.IsValid(true)}
		c.Atomic = binary.LittleEndian.Uint32(raw[:4]) == transaction.ATOMIC_BEEF
		// The wire version (go-sdk's parsed Beef.Version is always V2).
		ver := binary.LittleEndian.Uint32(raw[:4])
		if c.Atomic {
			ver = binary.LittleEndian.Uint32(raw[36:40])
		}
		switch ver {
		case transaction.BEEF_V1:
			c.Version = "v1"
		case transaction.BEEF_V2:
			c.Version = "v2"
		default:
			return nil, fmt.Errorf("%s: version %x", b.Name, ver)
		}
		if subject != nil {
			c.SubjectTxid = subject.String()
		} else if subjectTx != nil {
			c.SubjectTxid = subjectTx.TxID().String()
		}
		for _, p := range bf.BUMPs {
			c.Bumps = append(c.Bumps, BumpCase{p.BlockHeight, p.Hex()})
		}
		for _, id := range sortedTxids(bf) {
			t := bf.Transactions[id]
			tc := BeefTxCase{Txid: id.String()}
			switch t.DataFormat {
			case transaction.RawTx:
				tc.Format = "raw"
			case transaction.RawTxAndBumpIndex:
				tc.Format = "rawWithBump"
				bi := t.BumpIndex
				tc.BumpIndex = &bi
			case transaction.TxIDOnly:
				tc.Format = "txidOnly"
			}
			c.Txs = append(c.Txs, tc)
		}
		rb, err := bf.Bytes()
		if err != nil {
			return nil, fmt.Errorf("%s: bytes: %w", b.Name, err)
		}
		c.Reserialized = hex.EncodeToString(rb)
		cases = append(cases, c)
	}
	// Damaged BEEFs, made by go-sdk from the V2 fixtures: the proven parent
	// dropped (a missing input), or turned txid-only.
	var damaged []map[string]any
	for _, b := range f.Beefs {
		if !strings.HasPrefix(b.Name, "utv-") || !strings.HasSuffix(b.Name, "-v2") {
			continue
		}
		for _, mode := range []string{"parent-dropped", "parent-txid-only"} {
			bf, _, _, err := transaction.ParseBeef(must(hex.DecodeString(b.Hex)))
			if err != nil {
				return nil, err
			}
			var parent *chainhash.Hash
			for id, t := range bf.Transactions {
				if t.DataFormat == transaction.RawTxAndBumpIndex {
					id := id
					parent = &id
					break
				}
			}
			if mode == "parent-dropped" {
				delete(bf.Transactions, *parent)
			} else {
				bf.MakeTxidOnly(parent)
			}
			raw, err := bf.Bytes()
			if err != nil {
				return nil, err
			}
			damaged = append(damaged, map[string]any{
				"name": b.Name + "/" + mode, "hex": hex.EncodeToString(raw),
				"valid": bf.IsValid(false), "validTxidOnly": bf.IsValid(true),
			})
		}
	}
	// Malformed inputs go-sdk refuses.
	bad := []map[string]string{}
	for _, m := range []struct{ name, hex string }{
		{"empty", ""},
		{"bad-version", "0300beef00"},
		{"truncated-bumps", "0100beef01fe636d0c00"},
		{"v1-trailing-byte", strings.TrimSuffix(f.Beefs[0].Hex, "") + "00"},
	} {
		_, _, _, err := transaction.ParseBeef(must(hex.DecodeString(m.hex)))
		if err == nil {
			continue // go-sdk accepts it: not a refusal vector
		}
		bad = append(bad, map[string]string{"name": m.name, "hex": m.hex, "error": err.Error()})
	}
	return map[string]any{
		"about":     "BEEF (BRC-62/95/96) parse: version, atomic subject, BUMPs, txs by txid with format and bump index (go-sdk transaction.ParseBeef), validity (Beef.IsValid) and go-sdk's reserialization.",
		"cases":     cases,
		"malformed": bad,
		"damaged":   damaged,
	}, nil
}

// ---- merkle paths

type LeafRoot struct {
	Txid string `json:"txid"`
	Root string `json:"root"`
}
type MerklePathCase struct {
	Name         string     `json:"name"`
	Source       string     `json:"source"`
	Hex          string     `json:"hex"`
	BlockHeight  uint32     `json:"blockHeight"`
	Leaves       []LeafRoot `json:"leaves"` // every txid-flagged leaf and the root go-sdk computes for it
	Reserialized string     `json:"reserialized"`
}
type HeaderCheck struct {
	Name        string `json:"name"`
	BumpHex     string `json:"bumpHex"`
	Txid        string `json:"txid"`
	Height      uint32 `json:"height"`
	HeaderHex   string `json:"headerHex"`
	RootMatches bool   `json:"rootMatches"` // go-sdk MerklePath.Verify against a ChainTracker holding this header
}

func genMerklePath(f Fixtures, mh []MainnetHeader) (any, error) {
	byHeight := map[uint32]MainnetHeader{}
	for _, h := range mh {
		byHeight[h.Height] = h
	}
	var cases []MerklePathCase
	var checks []HeaderCheck
	addPath := func(name, source string, p *transaction.MerklePath) error {
		c := MerklePathCase{Name: name, Source: source, Hex: p.Hex(), BlockHeight: p.BlockHeight, Leaves: []LeafRoot{}}
		flagged := false
		for _, leaf := range p.Path[0] {
			flagged = flagged || (leaf.Txid != nil && *leaf.Txid)
		}
		// The txid-flagged leaves; a path that flags none (older encoders) gives
		// a root for every level-0 hash it can compute one for.
		for _, leaf := range p.Path[0] {
			if leaf.Hash == nil || (flagged && (leaf.Txid == nil || !*leaf.Txid)) {
				continue
			}
			root, err := p.ComputeRoot(leaf.Hash)
			if err != nil {
				if flagged {
					return fmt.Errorf("%s: %w", name, err)
				}
				continue
			}
			c.Leaves = append(c.Leaves, LeafRoot{leaf.Hash.String(), root.String()})
		}
		sort.Slice(c.Leaves, func(i, j int) bool { return c.Leaves[i].Txid < c.Leaves[j].Txid })
		c.Reserialized = p.Hex()
		cases = append(cases, c)
		if h, ok := byHeight[p.BlockHeight]; ok && len(c.Leaves) > 0 {
			hdr := must(block.NewHeaderFromHex(h.Hex))
			txid := must(chainhash.NewHashFromHex(c.Leaves[0].Txid))
			ok, err := p.Verify(context.Background(), txid, tracker{p.BlockHeight, hdr.MerkleRoot})
			if err != nil {
				return err
			}
			checks = append(checks, HeaderCheck{name, p.Hex(), c.Leaves[0].Txid, p.BlockHeight, h.Hex, ok})
			// The same path against the neighbouring block's header must not verify.
			if n, ok2 := byHeight[p.BlockHeight+1]; ok2 {
				nh := must(block.NewHeaderFromHex(n.Hex))
				bad, err := p.Verify(context.Background(), txid, tracker{p.BlockHeight, nh.MerkleRoot})
				if err != nil {
					return err
				}
				checks = append(checks, HeaderCheck{name + "/wrong-header", p.Hex(), c.Leaves[0].Txid, p.BlockHeight, n.Hex, bad})
			}
		}
		return nil
	}
	for _, b := range f.Bumps {
		p, err := transaction.NewMerklePathFromHex(b.Hex)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", b.Name, err)
		}
		if err := addPath(b.Name, b.Source, p); err != nil {
			return nil, err
		}
	}
	for _, b := range f.Beefs {
		if strings.HasPrefix(b.Name, "utv-") && !strings.HasSuffix(b.Name, "-v1") {
			continue // the same bump again
		}
		bf, _, _, err := transaction.ParseBeef(must(hex.DecodeString(b.Hex)))
		if err != nil {
			return nil, err
		}
		for i, p := range bf.BUMPs {
			if err := addPath(fmt.Sprintf("%s/bump%d", b.Name, i), b.Source, p); err != nil {
				return nil, err
			}
		}
	}
	return map[string]any{
		"about":        "BRC-74 merkle paths: the root go-sdk (MerklePath.ComputeRoot) computes for each txid leaf; and header checks: MerklePath.Verify against a chain tracker that knows exactly one mainnet header (fetched from WhatsOnChain, ../inputs/mainnet-headers.json).",
		"cases":        cases,
		"headerChecks": checks,
	}, nil
}

type tracker struct {
	height uint32
	root   chainhash.Hash
}

func (t tracker) IsValidRootForHeight(_ context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	return height == t.height && root.IsEqual(&t.root), nil
}
func (t tracker) CurrentHeight(_ context.Context) (uint32, error) { return t.height, nil }

// ---- headers

type HeaderCase struct {
	Height     uint32 `json:"height"`
	Hex        string `json:"hex"`
	Hash       string `json:"hash"`
	Version    int32  `json:"version"`
	PrevHash   string `json:"prevHash"`
	MerkleRoot string `json:"merkleRoot"`
	Time       uint32 `json:"time"`
	Bits       uint32 `json:"bits"`
	Nonce      uint32 `json:"nonce"`
	Target     string `json:"target"` // 64 hex, go-chaintracks CompactToBig(bits)
	Work       string `json:"work"`   // 64 hex, go-chaintracks CalculateWork(bits)
	PowOk      bool   `json:"powOk"`  // hash (as a big-endian number) <= target
}

func headerCase(height uint32, raw []byte) HeaderCase {
	h := must(block.NewHeaderFromBytes(raw))
	target := chainmanager_CompactToBig(h.Bits)
	hash := h.Hash()
	return HeaderCase{
		Height: height, Hex: hex.EncodeToString(raw), Hash: hash.String(), Version: h.Version,
		PrevHash: h.PrevHash.String(), MerkleRoot: h.MerkleRoot.String(), Time: h.Timestamp, Bits: h.Bits, Nonce: h.Nonce,
		Target: chainmanager_ChainWorkToHex(target), Work: chainmanager_ChainWorkToHex(chainmanager_CalculateWork(h.Bits)),
		PowOk: powOk(hash, target),
	}
}

// powOk: the header hash read as a big-endian 256-bit number (the display
// order) is at most the target. Written here, not taken from go-sdk (which has
// no PoW check); ../gen-ts/check-headers.ts checks every case against the TS
// toolbox's validateHeaderDifficulty.
func powOk(hash chainhash.Hash, target *big.Int) bool {
	n := new(big.Int).SetBytes(must(hex.DecodeString(hash.String())))
	return n.Cmp(target) <= 0
}

func genHeaders(mh []MainnetHeader) (any, error) {
	var all []HeaderCase
	for _, h := range mh {
		all = append(all, headerCase(h.Height, must(hex.DecodeString(h.Hex))))
	}
	// The consecutive run, and its cumulative work (go-chaintracks AddWork from zero).
	var run []HeaderCase
	work := big.NewInt(0)
	for _, c := range all {
		if c.Height >= runStart && c.Height < runStart+runLen {
			run = append(run, c)
			work = chainmanager_AddWork(work, c.Bits)
		}
	}
	for i := 1; i < len(run); i++ {
		if run[i].PrevHash != run[i-1].Hash || run[i].Height != run[i-1].Height+1 {
			return nil, fmt.Errorf("run is not a chain at %d", run[i].Height)
		}
	}
	// The run from genesis: the anchor (height 0) and its first successors.
	var genesisRun []HeaderCase
	gwork := big.NewInt(0)
	for _, c := range all {
		if c.Height < genesisRunLen {
			genesisRun = append(genesisRun, c)
			gwork = chainmanager_AddWork(gwork, c.Bits)
		}
	}
	if len(genesisRun) != genesisRunLen || genesisRun[0].PrevHash != strings.Repeat("0", 64) {
		return nil, fmt.Errorf("genesis run: %d headers", len(genesisRun))
	}
	for i := 1; i < len(genesisRun); i++ {
		if genesisRun[i].PrevHash != genesisRun[i-1].Hash || genesisRun[i].Height != genesisRun[i-1].Height+1 {
			return nil, fmt.Errorf("genesis run is not a chain at %d", genesisRun[i].Height)
		}
	}
	// Tampered headers: each must fail exactly the stated check.
	first := must(hex.DecodeString(run[1].Hex))
	nonce := append([]byte(nil), first...)
	binary.LittleEndian.PutUint32(nonce[76:], binary.LittleEndian.Uint32(nonce[76:])+1)
	prev := append([]byte(nil), first...)
	prev[4] ^= 0x01
	easy := append([]byte(nil), first...)
	binary.LittleEndian.PutUint32(easy[72:], 0x207fffff) // regtest bits: a hash almost surely meets it; PoW is checked against the header's own bits
	tampered := []map[string]any{
		{"name": "nonce+1", "case": headerCase(run[1].Height, nonce), "prevHashLinks": true},
		{"name": "prev-hash-bit-flipped", "case": headerCase(run[1].Height, prev), "prevHashLinks": false},
		{"name": "bits-regtest", "case": headerCase(run[1].Height, easy), "prevHashLinks": true},
	}
	// bits → target/work over edge values.
	var bits []map[string]any
	for _, b := range []uint32{0x1d00ffff, 0x1b0404cb, 0x18009645, 0x207fffff, 0x03123456, 0x02008000, 0x04123456, 0x1c0ffff0, 0x180d4a9e, 0x01003456, 0x04923456} {
		t := chainmanager_CompactToBig(b)
		v := map[string]any{"bits": b, "work": chainmanager_ChainWorkToHex(chainmanager_CalculateWork(b)), "valid": t.Sign() > 0}
		if t.Sign() > 0 {
			v["target"] = chainmanager_ChainWorkToHex(t)
		} else {
			// The references disagree here: go-chaintracks gives a zero or negative
			// target work 0; the TS toolbox ignores the sign bit and overflows 2^256
			// for a zero target. Neither is a usable header: wallet-zig refuses it.
			v["note"] = "invalid target (zero or negative): references disagree on work; refuse the header"
		}
		bits = append(bits, v)
	}
	return map[string]any{
		"about":          "Block headers (80 bytes): fields and hash (go-sdk block.Header), target and work from bits (go-chaintracks chainmanager_CompactToBig / CalculateWork), proof of work (hash <= target). `run` is consecutive mainnet headers: each prevHash is the previous hash; `runWork` is the run's summed work (AddWork). Heights 0..genesisRunLen-1 are mainnet's first headers from genesis, the chain anchor; `genesisRunWork` is their summed work, genesis included.",
		"headers":        all,
		"runStart":       runStart,
		"runLen":         runLen,
		"runWork":        chainmanager_ChainWorkToHex(work),
		"genesisRunLen":  genesisRunLen,
		"genesisRunWork": chainmanager_ChainWorkToHex(gwork),
		"tampered":       tampered,
		"bits":           bits,
		"tamperedAbout":  "Each tampered header is run[1] altered; prevHashLinks says whether it still links to run[0].",
	}, nil
}

// ---- BRC-29

var brc29 = wallet.Protocol{SecurityLevel: 2, Protocol: "3241645161d8"}

func keyFrom(seed string) *ec.PrivateKey {
	d := sha256.Sum256([]byte(seed))
	k, _ := ec.PrivateKeyFromBytes(d[:])
	return k
}

func p2pkh(pub *ec.PublicKey) string {
	return "76a914" + hex.EncodeToString(pub.Hash()) + "88ac"
}

func genBrc29() (any, error) {
	type Case struct {
		Name                 string `json:"name"`
		SenderPrivateKey     string `json:"senderPrivateKey"`
		SenderIdentityKey    string `json:"senderIdentityKey"`
		RecipientPrivateKey  string `json:"recipientPrivateKey"`
		RecipientIdentityKey string `json:"recipientIdentityKey"`
		DerivationPrefix     string `json:"derivationPrefix"`
		DerivationSuffix     string `json:"derivationSuffix"`
		KeyID                string `json:"keyID"`
		Invoice              string `json:"invoice"`
		PayerDerivedKey      string `json:"payerDerivedKey"` // sender: DerivePublicKey(counterparty = recipient, forSelf = false)
		PayeeDerivedKey      string `json:"payeeDerivedKey"` // recipient: DerivePublicKey(counterparty = sender, forSelf = true)
		PayeePrivateKey      string `json:"payeePrivateKey"` // recipient: DerivePrivateKey(counterparty = sender)
		LockingScript        string `json:"lockingScript"`   // P2PKH of the derived key
	}
	var cases []Case
	type Remit struct {
		Vout             uint32 `json:"vout"`
		DerivationPrefix string `json:"derivationPrefix"`
		DerivationSuffix string `json:"derivationSuffix"`
		SenderIdentity   string `json:"senderIdentityKey"`
		Matches          bool   `json:"matches"`
	}
	type Recognize struct {
		Name                 string  `json:"name"`
		RecipientPrivateKey  string  `json:"recipientPrivateKey"`
		RecipientIdentityKey string  `json:"recipientIdentityKey"`
		TxHex                string  `json:"txHex"`
		Txid                 string  `json:"txid"`
		Remittances          []Remit `json:"remittances"`
	}
	var recog []Recognize
	for i, n := range []struct{ prefix, suffix string }{
		{"cHJlZml4", "c3VmZml4"},
		{base64.StdEncoding.EncodeToString([]byte("skein-prefix-0001")), base64.StdEncoding.EncodeToString([]byte("skein-suffix-0001"))},
		{base64.StdEncoding.EncodeToString(keyFrom("p2").Serialize()[:16]), base64.StdEncoding.EncodeToString(keyFrom("s2").Serialize()[:10])},
		{"Zm9v", "YmFy"},
	} {
		sender := keyFrom(fmt.Sprintf("brc29-sender-%d", i))
		recipient := keyFrom(fmt.Sprintf("brc29-recipient-%d", i))
		keyID := n.prefix + " " + n.suffix
		payer := wallet.NewKeyDeriver(sender)
		payee := wallet.NewKeyDeriver(recipient)
		pp, err := payer.DerivePublicKey(brc29, keyID, wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: recipient.PubKey()}, false)
		if err != nil {
			return nil, err
		}
		pe, err := payee.DerivePublicKey(brc29, keyID, wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: sender.PubKey()}, true)
		if err != nil {
			return nil, err
		}
		pk, err := payee.DerivePrivateKey(brc29, keyID, wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: sender.PubKey()})
		if err != nil {
			return nil, err
		}
		if !pp.IsEqual(pe) || !pk.PubKey().IsEqual(pe) {
			return nil, fmt.Errorf("case %d: payer and payee derive different keys", i)
		}
		c := Case{
			Name: fmt.Sprintf("brc29-%d", i), SenderPrivateKey: hex.EncodeToString(sender.Serialize()), SenderIdentityKey: sender.PubKey().ToDERHex(),
			RecipientPrivateKey: hex.EncodeToString(recipient.Serialize()), RecipientIdentityKey: recipient.PubKey().ToDERHex(),
			DerivationPrefix: n.prefix, DerivationSuffix: n.suffix, KeyID: keyID, Invoice: "2-3241645161d8-" + keyID,
			PayerDerivedKey: pp.ToDERHex(), PayeeDerivedKey: pe.ToDERHex(), PayeePrivateKey: hex.EncodeToString(pk.Serialize()), LockingScript: p2pkh(pe),
		}
		cases = append(cases, c)

		// A payment: outputs [decoy, payment, other-recipient], and remittances to test.
		other := keyFrom(fmt.Sprintf("brc29-other-%d", i))
		otherKey, err := payer.DerivePublicKey(brc29, keyID, wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: other.PubKey()}, false)
		if err != nil {
			return nil, err
		}
		tx := transaction.NewTransaction()
		prev := chainhash.DoubleHashH([]byte(fmt.Sprintf("brc29-funding-%d", i)))
		us := script.Script(must(hex.DecodeString("00")))
		tx.AddInput(&transaction.TransactionInput{SourceTXID: &prev, SourceTxOutIndex: 0, UnlockingScript: &us, SequenceNumber: 0xffffffff})
		for _, s := range []string{p2pkh(keyFrom("decoy").PubKey()), c.LockingScript, p2pkh(otherKey)} {
			ls := script.Script(must(hex.DecodeString(s)))
			tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000 + uint64(i), LockingScript: &ls})
		}
		wrongSuffix := base64.StdEncoding.EncodeToString([]byte("not-it"))
		rems := []Remit{
			{1, n.prefix, n.suffix, c.SenderIdentityKey, true},
			{0, n.prefix, n.suffix, c.SenderIdentityKey, false},
			{2, n.prefix, n.suffix, c.SenderIdentityKey, false},
			{1, n.prefix, wrongSuffix, c.SenderIdentityKey, false},
			{1, n.prefix, n.suffix, other.PubKey().ToDERHex(), false},
		}
		// Double-check each expectation with go-sdk.
		for j, r := range rems {
			sp := must(ec.PublicKeyFromString(r.SenderIdentity))
			k, err := payee.DerivePublicKey(brc29, r.DerivationPrefix+" "+r.DerivationSuffix, wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: sp}, true)
			if err != nil {
				return nil, err
			}
			got := hex.EncodeToString(*tx.Outputs[r.Vout].LockingScript) == p2pkh(k)
			if got != r.Matches {
				return nil, fmt.Errorf("case %d remittance %d: go-sdk says %v", i, j, got)
			}
		}
		recog = append(recog, Recognize{c.Name, c.RecipientPrivateKey, c.RecipientIdentityKey, tx.Hex(), tx.TxID().String(), rems})
	}
	return map[string]any{
		"about":     "BRC-29 payments: protocol [2, \"3241645161d8\"], keyID \"<derivationPrefix> <derivationSuffix>\" (BRC-43 invoice 2-3241645161d8-<keyID>). Keys by go-sdk wallet.KeyDeriver (BRC-42): the payer's and payee's derivations agree. `recognize`: which declared remittances match the P2PKH output at their vout.",
		"protocol":  []any{2, "3241645161d8"},
		"cases":     cases,
		"recognize": recog,
	}, nil
}

// ---- BRC-100 wire: getPublicKey

func genWire() (any, error) {
	type Req struct {
		Name         string `json:"name"`
		ProtocolID   []any  `json:"protocolID"`
		KeyID        string `json:"keyID"`
		Counterparty string `json:"counterparty"`
		ForSelf      *bool  `json:"forSelf"`
		Frame        string `json:"frame"`
	}
	t, fls := true, false
	var reqs []Req
	for i, c := range []struct {
		name    string
		keyID   string
		cp      *ec.PublicKey
		forSelf *bool
	}{
		{"brc29-payee", "cHJlZml4 c3VmZml4", keyFrom("brc29-sender-0").PubKey(), &t},
		{"brc29-payer", "Zm9v YmFy", keyFrom("brc29-recipient-3").PubKey(), &fls},
		{"no-forself", "k", keyFrom("x").PubKey(), nil},
		{"long-keyid", strings.Repeat("a", 300), keyFrom("y").PubKey(), &t},
	} {
		_ = i
		args := wallet.GetPublicKeyArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: brc29, KeyID: c.keyID, Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: c.cp}},
			ForSelf:        c.forSelf,
		}
		params, err := serializer.SerializeGetPublicKeyArgs(&args)
		if err != nil {
			return nil, err
		}
		frame := serializer.WriteRequestFrame(serializer.RequestFrame{Call: 8, Originator: "", Params: params})
		reqs = append(reqs, Req{c.name, []any{2, "3241645161d8"}, c.keyID, c.cp.ToDERHex(), c.forSelf, hex.EncodeToString(frame)})
	}
	type Res struct {
		Frame     string `json:"frame"`
		PublicKey string `json:"publicKey,omitempty"`
		Error     bool   `json:"error"`
	}
	var res []Res
	for _, s := range []string{"a", "b"} {
		pub := keyFrom(s).PubKey()
		payload := must(serializer.SerializeGetPublicKeyResult(&wallet.GetPublicKeyResult{PublicKey: pub}))
		res = append(res, Res{hex.EncodeToString(serializer.WriteResultFrame(payload, nil)), pub.ToDERHex(), false})
	}
	res = append(res, Res{hex.EncodeToString(serializer.WriteResultFrame(nil, &wallet.Error{Code: 1, Message: "denied", Stack: ""})), "", true})
	return map[string]any{
		"about":    "BRC-100 wallet wire frames for getPublicKey (call 8), as go-sdk's WalletWireTransceiver writes them (serializer.SerializeGetPublicKeyArgs + WriteRequestFrame, empty originator), and result frames (WriteResultFrame).",
		"requests": reqs,
		"results":  res,
	}, nil
}
