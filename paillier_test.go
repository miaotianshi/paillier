package paillier

import (
	"math/big"
	"testing"
)

func TestGeneratePaillierKeypair(t *testing.T) {
	publicKey, privateKey := GeneratePaillierKeypair(10)
	for i := 0; i < 100; i++ {
		x := big.NewInt(int64(124))
		r := big.NewInt(int64(34))
		y := publicKey.RawEncrypt(x, r)
		z := privateKey.RawDecrypt(y)
		if x.Cmp(z) != 0 {
			t.Errorf(`x=%v, z=%v, not equal.`, x, z)
		}
	}
}

func TestEncodedNumber_DecreaseExponentTo(t *testing.T) {
	pub, _ := generateStableKeys()
	x := float64(102.3)
	y := new(EncodedNumber).Encode(pub, x, PrecisionUnused, MaxExponentUnused)
	z := y.DecreaseExponentTo(y.Exponent - 1)
	dy := y.Decode()
	dz := z.Decode()
	if dy != dz || x != dy {
		t.Errorf(`x=%v, dy=%v, dz=%v, not equal.`, x, dy, dz)
	}
}

func generateNPQ() (n, p, q *big.Int) {
	n, _ = new(big.Int).SetString("14627327510445924371", 10)
	p, _ = new(big.Int).SetString("3778961023", 10)
	q, _ = new(big.Int).SetString("3870727277", 10)
	return n, p, q
}

func generateStableKeys() (*PaillierPublicKey, *PaillierPrivateKey) {
	_, p, q := generateNPQ()
	pub, pri := GeneratePaillierKeypairByPQ(p, q)
	return pub, pri
}

func TestPaillierPrivateKey_Decrypt(t *testing.T) {
	pub, pri := generateStableKeys()
	x := float64(102.3)
	y := pub.Encrypt(x, PrecisionUnused, nil)
	z := y.Add(float64(100.3))
	dz := pri.Decrypt(z)
	dy := pri.Decrypt(y)
	if dz != dy + 100.3 {
		t.Errorf(`(dy=%v + 100.3) and dz=%v not equal.`, dy, dz)
	}
}

func TestEncryptedNumber_DecreaseExponentTo(t *testing.T) {
	pub, pri := generateStableKeys()
	x := float64(102.3)
	y := new(EncodedNumber).Encode(pub, x, PrecisionUnused, MaxExponentUnused)
	z := pub.Encrypt(y, PrecisionUnused, nil)
	z2 := z.DecreaseExponentTo(z.Exponent - 1)

	dz := pri.Decrypt(z)
	dz2 := pri.Decrypt(z2)
	if dz != dz2 || dz != x {
		t.Errorf(`x=%v, dz=%v, dz2=%v, not equal.`, x, dz, dz2)
	}
}

func TestEncryptedNumber_Mul_WithoutDecreaseExponentTo(t *testing.T) {
	//pub, pri := generateStableKeys()
	pub, pri := GeneratePaillierKeypair(1024)
	x := float64(102.3)
	y := float64(102.3)
	z := pub.Encrypt(x, PrecisionUnused, nil)
	w := z.Mul(y)
	dw := pri.Decrypt(w)
	if dw != x * y {
		t.Errorf("%v * %v != %v", x, y, dw)
	}
}

func TestEncryptedNumber_rawMul(t *testing.T) {
	pub, _ := generateStableKeys()
	//n, p, q := generateNPQ()
	value, _ := new(big.Int).SetString("21549750908973310478636683764782244499", 10)
	x := float64(102.3)
	y := float64(102.3)
	r := big.NewInt(int64(5))
	xE := pub.Encrypt(x, PrecisionUnused, r)
	ye := new(EncodedNumber).Encode(pub, y, PrecisionUnused, MaxExponentUnused)
	w := xE.rawMul(ye.Encoding)
	if w.Cmp(value) != 0 {
		t.Errorf("%v != %v", w, value)
	}
}
