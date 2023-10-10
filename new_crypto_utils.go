package tls

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"reflect"
)

////////////////
// KDC functions to compute intermediate hash values
// check KDC PDF Fig 6. to see all values
// functions starting with P are computed in postprocessing by the prover
// functions starting with V are computed in postprocessing by the verifier
////////////////

// kdc functions to compute required public input
func VIVin(intermediateHashXATSipad []byte) []byte {
	miv := GetSha256LabelTLS13("iv", nil, 12)
	IVin, _, _ := SumMDShacal2(64, intermediateHashXATSipad, miv)
	return IVin
}

func VTkXAPPin(intermediateHashXATSipad []byte) []byte {
	mk := GetSha256LabelTLS13("key", nil, 16)
	tkXAPPin, _, _ := SumMDShacal2(64, intermediateHashXATSipad, mk)
	return tkXAPPin
}

func VXATSin(intermediateHashMSipad, H3 []byte, label string) []byte {
	mH3 := GetSha256LabelTLS13(label, H3, 32)
	SATSin, _, _ := SumMDShacal2(64, intermediateHashMSipad, mH3)
	return SATSin
}

func VMSin(intermediateHashdHSipad []byte) []byte {
	zeros := make([]byte, 32)
	MSin, _, _ := SumMDShacal2(64, intermediateHashdHSipad, zeros) // 0 input
	return MSin
}

// function in zk kdc scope
// computes intermediate hash of HS xor opad input
// since opad is 64 bytes, returned length=64 is publicly known
func PIntermediateHashHSopad(HSBytes []byte) []byte {
	HSopad := XorOPad(HSBytes)
	IV := make([]byte, 0)
	_, intermediateHashHSopad, _ := SumMDShacal2(0, IV, HSopad)
	return intermediateHashHSopad
}

func PIntermediateHashHSipad(HSBytes []byte) []byte {
	HSipad := XorIPad(HSBytes)
	IV := make([]byte, 0)
	_, intermediateHashHSipad, _ := SumMDShacal2(0, IV, HSipad)
	return intermediateHashHSipad
}

func VDeriveSHTSin(intermediateHashHSipad, H2 []byte) []byte {
	mH2 := GetSha256LabelTLS13(serverHandshakeTrafficLabel, H2, 32)
	SHTSin, _, _ := SumMDShacal2(64, intermediateHashHSipad, mH2)
	return SHTSin
}

// returns SHTS.
// does not require l_x because its known that both intermediate hashes have been computed with a 64 byte input,
// thus no need to pass l_x cause its known to be 64.
func VDeriveSHTS(intermediateHashHSopad, SHTSin []byte) []byte {
	shtsPrime, _, _ := SumMDShacal2(64, intermediateHashHSopad, SHTSin)
	return shtsPrime
}

func VVerifySHTS(intermediateHashHSopad, shtsIn, SHTS []byte) bool {
	SHTSPrime := VDeriveSHTS(intermediateHashHSopad, shtsIn)
	return reflect.DeepEqual(SHTSPrime, SHTS)
}

func VVerifySHTSold(intermediateHashHSopad, intermediateHashHSipad, H2, SHTS []byte) bool {
	SHTSin := VDeriveSHTSin(intermediateHashHSipad, H2)
	SHTSPrime := VDeriveSHTS(intermediateHashHSopad, SHTSin)
	return reflect.DeepEqual(SHTSPrime, SHTS)
}

func GetSha256LabelTLS13(label string, transcript []byte, size int) []byte {
	var b bytes.Buffer
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(size))
	b.Write(length)
	tmp := "tls13 " + label
	b.Write([]byte{byte(len(tmp))})
	b.Write([]byte(tmp))
	b.Write([]byte{byte(len(transcript))})
	b.Write(transcript)
	b.Write([]byte{1})
	return b.Bytes()
}

func VDeriveSF(SHTS, H7, sfBytes []byte) bool {

	// catch cipher suite
	var cipherSuitesTLS13 = []*cipherSuiteTLS13{
		{TLS_AES_128_GCM_SHA256, 16, aeadAESGCMTLS13, crypto.SHA256},
	}
	c := cipherSuitesTLS13[0]

	// from finishedHash
	finishedKey := c.expandLabel(SHTS, "finished", nil, c.hash.Size())
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(H7)
	sfMac := verifyData.Sum(nil)

	// shrink plaintext to sf verify mac
	sfBytesReduced := sfBytes[4 : len(sfMac)+4]

	// compare
	return reflect.DeepEqual(sfMac, sfBytesReduced)
}

// function to verify that SF ciphertext maps to SHTS and intermediateHashHSopad (public input to zk circuit)
// prover sent all input arguments to the verifier who calls the function except the values:
// ciphertext, H2
func VSFtoPublicInput(ciphertext, H2, SHTS, nonce, additionalData, intermediateHashHSipad, intermediateHashHSopad, H7 []byte) (bool, error) {

	// decrypt SF ciphertext
	plaintextSF, err := DecryptAESGCM13(SHTS, nonce, ciphertext, additionalData)
	if err != nil {
		return false, err
	}

	// verify SHTS to public input of zk kdc circuit
	ok2 := VVerifySHTSold(intermediateHashHSopad, intermediateHashHSipad, H2, SHTS)

	// derive SF from SHTS and check against plaintextSF
	plaintextSFBytes, _ := hex.DecodeString(plaintextSF)
	ok1 := VDeriveSF(SHTS, H7, plaintextSFBytes)

	// make sure both verifications work
	ok := ok1 && ok2

	// return
	return ok, nil
}

////////////////
// Test Functions
////////////////

// AES GCM verification functions
func DecryptAESGCM13(trafficSecret, nonce, ciphertext, additionalData []byte) (string, error) {

	var cipherSuitesTLS13 = []*cipherSuiteTLS13{
		{TLS_AES_128_GCM_SHA256, 16, aeadAESGCMTLS13, crypto.SHA256},
	}
	c := cipherSuitesTLS13[0]

	// key, iv []byte
	key := c.expandLabel(trafficSecret, "key", nil, c.keyLen)
	iv := c.expandLabel(trafficSecret, "iv", nil, aeadNonceLength)

	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	nonceMask := iv

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)

	for i, b := range nonce {
		ret.nonceMask[4+i] ^= b
	}
	payload0 := make([]byte, 0)
	result, err := ret.aead.Open(payload0, ret.nonceMask[:], ciphertext, additionalData)
	if err != nil {
		return "", err
	}
	// for i, b := range nonce {
	// 	ret.nonceMask[4+i] ^= b
	// }

	return hex.EncodeToString(result), nil
}

// SHA256

const (
	Size      = 32
	BlockSize = 64
	chunk     = 64
	init0     = 0x6A09E667
	init1     = 0xBB67AE85
	init2     = 0x3C6EF372
	init3     = 0xA54FF53A
	init4     = 0x510E527F
	init5     = 0x9B05688C
	init6     = 0x1F83D9AB
	init7     = 0x5BE0CD19
)

var _K = []uint32{
	0x428a2f98,
	0x71374491,
	0xb5c0fbcf,
	0xe9b5dba5,
	0x3956c25b,
	0x59f111f1,
	0x923f82a4,
	0xab1c5ed5,
	0xd807aa98,
	0x12835b01,
	0x243185be,
	0x550c7dc3,
	0x72be5d74,
	0x80deb1fe,
	0x9bdc06a7,
	0xc19bf174,
	0xe49b69c1,
	0xefbe4786,
	0x0fc19dc6,
	0x240ca1cc,
	0x2de92c6f,
	0x4a7484aa,
	0x5cb0a9dc,
	0x76f988da,
	0x983e5152,
	0xa831c66d,
	0xb00327c8,
	0xbf597fc7,
	0xc6e00bf3,
	0xd5a79147,
	0x06ca6351,
	0x14292967,
	0x27b70a85,
	0x2e1b2138,
	0x4d2c6dfc,
	0x53380d13,
	0x650a7354,
	0x766a0abb,
	0x81c2c92e,
	0x92722c85,
	0xa2bfe8a1,
	0xa81a664b,
	0xc24b8b70,
	0xc76c51a3,
	0xd192e819,
	0xd6990624,
	0xf40e3585,
	0x106aa070,
	0x19a4c116,
	0x1e376c08,
	0x2748774c,
	0x34b0bcb5,
	0x391c0cb3,
	0x4ed8aa4a,
	0x5b9cca4f,
	0x682e6ff3,
	0x748f82ee,
	0x78a5636f,
	0x84c87814,
	0x8cc70208,
	0x90befffa,
	0xa4506ceb,
	0xbef9a3f7,
	0xc67178f2,
}

type digest struct {
	h   [8]uint32   // current hash value
	x   [chunk]byte // preimage
	nx  int
	len uint64
}

func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7

	d.nx = 0
	d.len = 0
}

func (d *digest) SetH(iv []byte, length uint64) {

	// use default H if iv is empty
	if len(iv) == 0 {
		d.h[0] = init0
		d.h[1] = init1
		d.h[2] = init2
		d.h[3] = init3
		d.h[4] = init4
		d.h[5] = init5
		d.h[6] = init6
		d.h[7] = init7

		d.nx = 0
		d.len = 0
	} else {
		d.h[0] = binary.BigEndian.Uint32(iv[0:4])
		d.h[1] = binary.BigEndian.Uint32(iv[4:8])
		d.h[2] = binary.BigEndian.Uint32(iv[8:12])
		d.h[3] = binary.BigEndian.Uint32(iv[12:16])
		d.h[4] = binary.BigEndian.Uint32(iv[16:20])
		d.h[5] = binary.BigEndian.Uint32(iv[20:24])
		d.h[6] = binary.BigEndian.Uint32(iv[24:28])
		d.h[7] = binary.BigEndian.Uint32(iv[28:32])

		d.nx = 0
		d.len = length
	}
}

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {

	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) checkSum() [Size]byte {
	len := d.len
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	var t uint64
	if len%64 < 56 {
		t = 56 - len%64
	} else {
		t = 64 + 56 - len%64
	}

	// Length in bits.
	len <<= 3
	padlen := tmp[:t+8]
	binary.BigEndian.PutUint64(padlen[t+0:], len)
	d.Write(padlen)

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte
	binary.BigEndian.PutUint32(digest[0:], d.h[0])
	binary.BigEndian.PutUint32(digest[4:], d.h[1])
	binary.BigEndian.PutUint32(digest[8:], d.h[2])
	binary.BigEndian.PutUint32(digest[12:], d.h[3])
	binary.BigEndian.PutUint32(digest[16:], d.h[4])
	binary.BigEndian.PutUint32(digest[20:], d.h[5])
	binary.BigEndian.PutUint32(digest[24:], d.h[6])
	binary.BigEndian.PutUint32(digest[28:], d.h[7])
	return digest
}

// Sum256 returns the SHA256 checksum of the data.
// old: func Sum256(data []byte) [Size]byte {
func Sum256(data []byte) []byte {
	var d digest
	d.Reset()
	d.Write(data)
	hash := d.checkSum()
	return hash[:]
}

// sum of merkle damgard shacal2 blockcipher
// if iv=make([]byte, 0), then the default init values if H are used
// if iv=make([]byte, x) with x›0, then H values are set to iv
func SumMDShacal2(length uint64, iv, data []byte) ([]byte, []byte, uint64) {
	var d digest
	d.SetH(iv, length)
	d.Write(data)

	// get intermediate values:
	var digest [Size]byte

	binary.BigEndian.PutUint32(digest[0:], d.h[0])
	binary.BigEndian.PutUint32(digest[4:], d.h[1])
	binary.BigEndian.PutUint32(digest[8:], d.h[2])
	binary.BigEndian.PutUint32(digest[12:], d.h[3])
	binary.BigEndian.PutUint32(digest[16:], d.h[4])
	binary.BigEndian.PutUint32(digest[20:], d.h[5])
	binary.BigEndian.PutUint32(digest[24:], d.h[6])
	binary.BigEndian.PutUint32(digest[28:], d.h[7])

	tmp := d.len
	hash := d.checkSum()
	return hash[:], digest[:], tmp
}

func (d *digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	// fmt.Println("L before sum:", d.len, d.nx)
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func XorOPad(data []byte) []byte {
	opad := make([]byte, 64)
	copy(opad, data)
	for i := range opad {
		opad[i] ^= 0x5c
	}
	return opad
}

func XorIPad(data []byte) []byte {
	ipad := make([]byte, 64)
	copy(ipad, data)
	for i := range ipad {
		ipad[i] ^= 0x36
	}
	return ipad
}

func NewSHA256() *digest {
	d := new(digest)
	d.Reset()
	return d
}

func block(dig *digest, p []byte) {

	var w [64]uint32
	h0, h1, h2, h3, h4, h5, h6, h7 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7]
	for len(p) >= chunk {
		// Can interlace the computation of w with the
		// rounds below if needed for speed.
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}
		for i := 16; i < 64; i++ {
			v1 := w[i-2]
			t1 := (bits.RotateLeft32(v1, -17)) ^ (bits.RotateLeft32(v1, -19)) ^ (v1 >> 10)
			v2 := w[i-15]
			t2 := (bits.RotateLeft32(v2, -7)) ^ (bits.RotateLeft32(v2, -18)) ^ (v2 >> 3)
			w[i] = t1 + w[i-7] + t2 + w[i-16]
		}

		a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7

		for i := 0; i < 64; i++ {
			t1 := h + ((bits.RotateLeft32(e, -6)) ^ (bits.RotateLeft32(e, -11)) ^ (bits.RotateLeft32(e, -25))) + ((e & f) ^ (^e & g)) + _K[i] + w[i]

			t2 := ((bits.RotateLeft32(a, -2)) ^ (bits.RotateLeft32(a, -13)) ^ (bits.RotateLeft32(a, -22))) + ((a & b) ^ (a & c) ^ (b & c))

			h = g
			g = f
			f = e
			e = d + t1
			d = c
			c = b
			b = a
			a = t1 + t2
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
		h5 += f
		h6 += g
		h7 += h

		p = p[chunk:]
	}

	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7] = h0, h1, h2, h3, h4, h5, h6, h7
}
