package main

// Copied verbatim (renamed only) from github.com/bsv-blockchain/go-chaintracks
// v1.3.0, chainmanager/chainwork.go: the reference for target and work from a
// header's bits. The module itself is not imported because its dependency
// tree (teranode, libp2p, k8s) does not build here; these functions use only
// math/big. ../gen-ts/check-headers.ts checks the resulting vectors against
// the TS wallet-toolbox's convertBitsToTarget / convertBitsToWork too.

import "math/big"

var oneLsh256 = new(big.Int).Lsh(big.NewInt(1), 256)

func chainmanager_CompactToBig(compact uint32) *big.Int {
	mantissa := compact & 0x007fffff
	isNegative := compact&0x00800000 != 0
	exponent := uint(compact >> 24)

	var bn *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		bn = big.NewInt(int64(mantissa))
	} else {
		bn = big.NewInt(int64(mantissa))
		bn.Lsh(bn, 8*(exponent-3))
	}

	if isNegative {
		bn = bn.Neg(bn)
	}

	return bn
}

func chainmanager_CalculateWork(bits uint32) *big.Int {
	target := chainmanager_CompactToBig(bits)
	if target.Sign() <= 0 {
		return big.NewInt(0)
	}
	denominator := new(big.Int).Add(target, big.NewInt(1))
	work := new(big.Int).Div(oneLsh256, denominator)
	return work
}

func chainmanager_AddWork(cumulativeWork *big.Int, bits uint32) *big.Int {
	work := chainmanager_CalculateWork(bits)
	result := new(big.Int).Add(cumulativeWork, work)
	return result
}

func chainmanager_ChainWorkToHex(work *big.Int) string {
	hexStr := work.Text(16)
	for len(hexStr) < 64 {
		hexStr = "0" + hexStr
	}
	return hexStr
}
