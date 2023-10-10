package tls

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	// bh "go.mau.fi/libsignal/util/bytehelper"
)

// test key derivation

var VSFtoPublicInputData = []struct {
	ciphertext, H2, SHTS, nonce, additionalData, intermediateHashHSipad, intermediateHashHSopad, H7 string
}{
	{
		"2976a653ef8039d1ecae3113eb7b18cdcaaca29e9d027f8cf7fe774027b37f8eb9c1d7b3e9e7f18adfa9e39be0b63f635b0fab5ff9",
		"ff259d4661d5506e0ad7514c876456c742e4f264fa15263e70079adb390b7e78",
		"23352d6be62f8051e99c98259b5628cca583ec4f1edba6be4710770731eef84b",
		"0000000000000003",
		"1703030035",
		"dee038e2b37ddb6e84b2bc9d3a9054f2851b5d1b37f57b48366eaabcb895a240",
		"7c470a793fd5ef0124ad8b31ee2e1c27ba15684ed696728c4ea04bad7ebe38f9",
		"760437ada955959745b54b877ed0a6bcbf8404c1292e61be5e49c273da19bf38",
	},
}

func TestVSFtoPublicInput(t *testing.T) {
	for _, test := range VSFtoPublicInputData {

		// bytes
		ciphertext, _ := hex.DecodeString(test.ciphertext)
		H2, _ := hex.DecodeString(test.H2)
		SHTS, _ := hex.DecodeString(test.SHTS)
		nonce, _ := hex.DecodeString(test.nonce)
		additionalData, _ := hex.DecodeString(test.additionalData)
		intermediateHashHSipad, _ := hex.DecodeString(test.intermediateHashHSipad)
		intermediateHashHSopad, _ := hex.DecodeString(test.intermediateHashHSopad)
		H7, _ := hex.DecodeString(test.H7)

		// call function to verify
		ok, err := VSFtoPublicInput(ciphertext, H2, SHTS, nonce, additionalData, intermediateHashHSipad, intermediateHashHSopad, H7)
		if err != nil {
			t.Errorf("sf verification err: %x", err)
			return
		}

		// check output
		if !ok {
			t.Errorf("sf verification to public input failed.")
		}
	}
}

// test HS to SHTS computation functions
// took values from request/session.json
var hHSipadData = []struct {
	HS, H2, SHTS string
}{
	{
		"1129d03ad6d63d3c97a5fe035f6006646108bb3e0d4cb92bac4b433b329eaefd", // HS
		"c970a4fd03e62226a01a5248f0481a765f55400748b84ee4c2dab64a62ad87fa", // H2
		"1176b30d0b8119e3f5123075d38190b592d76c9a9af49dbd9e8c88e0b7ded213", // SHTS
	},
}

func TestSumMDShacal2(t *testing.T) {
	for _, test := range hHSipadData {

		// read in bytes
		HSBytes, _ := hex.DecodeString(test.HS)
		H2Bytes, _ := hex.DecodeString(test.H2)
		shtsBytes, _ := hex.DecodeString(test.SHTS)

		t.Log("shtsBytes:", shtsBytes)

		// label to generate mH2
		var label bytes.Buffer
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, uint16(32))
		label.Write(length)
		tmp := "tls13 " + serverHandshakeTrafficLabel // shtl="s hs traffic"
		label.Write([]byte{byte(len(tmp))})
		label.Write([]byte(tmp))
		label.Write([]byte{byte(len(H2Bytes))})
		label.Write(H2Bytes)
		label.Write([]byte{1})
		mH2 := label.Bytes()

		// xor HS with ipad
		HSipad := XorIPad(HSBytes)
		// fmt.Println("ipad:", HSipad)

		// default IV used when len(IV)==0
		IV := make([]byte, 0)

		// prover compute, should not require padding
		hHSipad, intermediateHashHSipad, l := SumMDShacal2(0, IV, HSipad)
		fmt.Println("hHSipad:", hHSipad)

		// mH2 := append(label.Bytes(), H2Bytes...)

		// verifier compute
		fmt.Println("writing to sha256:", mH2)
		SHTSin, _, _ := SumMDShacal2(l, intermediateHashHSipad, mH2)
		fmt.Println("SHTSin:", SHTSin)

		// these values must be computed in zk such that it can be used on the verifier side to compute SHTS, and with that check SF
		// xor HS with opad
		HSopad := XorOPad(HSBytes)
		fmt.Println("opad:", HSopad)
		_, intermediateHashHSopad, l := SumMDShacal2(0, IV, HSopad) // final hash is hHSopad

		shtsPrime, _, _ := SumMDShacal2(l, intermediateHashHSopad, SHTSin)
		t.Log("shtsPrime:", shtsPrime)

		// assert equal
		if !reflect.DeepEqual(shtsPrime, shtsBytes) {
			t.Errorf("shacal2 failed.")
			return
		}
	}
}

// test SF decryption

// test data
var testDataAES128GCM13 = []struct {
	trafficSecret, nonce, ciphertext, additionalData, plaintext string
}{
	{
		"349c87d5003e68d39e96426621fdd78e78b1ac6f35d1993e153be5365464cdc9", // SHTS when decrypting SF
		"0000000000000003",
		"a72050f7d03b8bdf234c88712998bf035db9b2a0ec30cb52008edebed46781ccdca0f65b157d20b0ff3404a7363fed666114646b94",
		"1703030035",
		"140000203f7d30ee2f6ba983828e133a45cff2aa2d0dc19b5f7b959db282c5fbc23966d916",
	},
}

// inside folder, execute with: `go test -run TestDecryptAESGCM13 -v .`
func TestDecryptAESGCM13(t *testing.T) {
	for _, test := range testDataAES128GCM13 {

		ts, _ := new(big.Int).SetString(test.trafficSecret, 16)
		nonce, _ := hex.DecodeString(test.nonce)
		c, _ := new(big.Int).SetString(test.ciphertext, 16)
		ad, _ := new(big.Int).SetString(test.additionalData, 16)
		trafficSecret := ts.Bytes()
		ciphertext := c.Bytes()
		additionalData := ad.Bytes()

		// decryption
		plaintext, err := DecryptAESGCM13(trafficSecret, nonce, ciphertext, additionalData)
		if err != nil {
			t.Errorf("aes decrypt error: %s", err)
		}

		// assert equal
		if !reflect.DeepEqual(plaintext, test.plaintext) {
			t.Errorf("aes decrypt failed.")
			return
		}
	}

	t.Log("aes decrypt test passed.")
}

// test SHA256

// test data
var testDataSHA256 = []struct {
	preimage, hash string
}{
	{
		"39316a73616b6c6a64313239333831303233316131",
		"8c3cbfa579522e522ddc1f593faacb6ce1b3d22a1fcca6abaaaae84e081a04cf",
	},
	{
		"ff",
		"a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89",
	},
	{
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"af9613760f72635fbdb44a5a0a63c39f12af30f950a6ee5c971be188e89c4051",
	},
}

// inside folder, execute with: `go test -run TestSum256 -v .`
func TestSum256(t *testing.T) {
	for _, test := range testDataSHA256 {

		preimage, _ := new(big.Int).SetString(test.preimage, 16)
		hash, _ := new(big.Int).SetString(test.hash, 16)
		preimageBytes := preimage.Bytes()

		// hashBytes := bh.SliceToArray(hash.Bytes()) // retuns [32]byte slice
		hashBytes := hash.Bytes()
		hashPrime := Sum256(preimageBytes)
		if !reflect.DeepEqual(hashBytes, hashPrime) {
			t.Errorf("sha256 failed.")
			return
		}
	}

	t.Log("sha256 test passed.")
}

func TestZKdHS(t *testing.T) {

	intermediateHashHSopadString := "4b666cdc720a74082b1594c95367f3c71f5124db03add4877e959c6c50c7e3b5"
	dHSinString := "3352927e78c6f8ff6e09a9cdbd13f22f94467f85316bb1d4be826c449d2c7f9f"
	dHSString := "d453d0c19ab5e562b3de0cf6a0769d75fecd3a5b2f578ac9d492b73a8cfa0c3a"

	intermediateHashHSopad, _ := hex.DecodeString(intermediateHashHSopadString)
	dHSin, _ := hex.DecodeString(dHSinString)
	dHSexpected, _ := hex.DecodeString(dHSString)

	// its a shacal2 l=64 example
	// calls block only once
	//
	dHS := ZKdHS(intermediateHashHSopad, dHSin)
	t.Log("dHS:", dHS, hex.EncodeToString(dHS))
	if !reflect.DeepEqual(dHS, dHSexpected) {
		t.Errorf("dHS compute failed.")
		return
	}
	// t.Log(hex.EncodeToString(dHS))
}
