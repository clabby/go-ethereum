package main

import (
	"errors"
	"reflect"

	"github.com/ethereum/go-ethereum/common"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

const PairElementLength = 192

func main() {
	input := common.Hex2Bytes("2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f61fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d92bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f902fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e000000000000000000000000000000000000000000000000000000000000000130644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd451971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc72a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea223a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc")
	r, err := runEcPairing(input)
	if err != nil {
		panic(err)
	}
	println(r)
}

// Geth-style
func runBn256Pairing(input []byte) (bool, error) {
	// Handle some corner cases cheaply
	if len(input)%192 > 0 {
		return false, errors.New("input length must be a multiple of 192")
	}
	// Convert the input into a set of coordinates
	var (
		cs []*bn256.G1
		ts []*bn256.G2
	)
	for i := 0; i < len(input); i += 192 {
		c, err := newCurvePoint(input[i : i+64])
		if err != nil {
			return false, err
		}
		t, err := newTwistPoint(input[i+64 : i+192])
		if err != nil {
			return false, err
		}
		cs = append(cs, c)
		ts = append(ts, t)
	}
	// Execute the pairing checks and return the results
	if bn256.PairingCheck(cs, ts) {
		return true, nil
	}
	return false, nil
}

// Revm-style
func runEcPairing(input []byte) (bool, error) {
	if len(input)%PairElementLength > 0 {
		return false, errors.New("Input length must be a multiple of 192")
	}

	// Short circuit the empty input case
	if len(input) == 0 {
		return true, nil
	}

	mul := bn256.GTOne()
	for i := 0; i < len(input); i += PairElementLength {
		c, err := newCurvePoint(input[i : i+64])
		if err != nil {
			return false, err
		}
		t, err := newTwistPoint(input[i+64 : i+192])
		if err != nil {
			return false, err
		}

		pair := bn256.Pair(c, t)
		mul = mul.Mul(mul, pair)
	}

	return reflect.DeepEqual(mul, bn256.GTOne()), nil
}

// newCurvePoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newCurvePoint(blob []byte) (*bn256.G1, error) {
	p := new(bn256.G1)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// newTwistPoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newTwistPoint(blob []byte) (*bn256.G2, error) {
	p := new(bn256.G2)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}
