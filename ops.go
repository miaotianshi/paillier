package paillier

import (
	"fmt"
	"math"
	"math/big"
)

type EncryptedNumber struct {
	PublicKey *PaillierPublicKey
	ciphertext *big.Int
	Exponent float64
	isObfuscated bool
}

func (n *EncryptedNumber) String() string {
	return fmt.Sprintf("EncryptedNumber{ciphertext=%d, Exponent=%d}", n.ciphertext, int(n.Exponent))
	//return fmt.Sprintf("EncryptedNumber{PublicKey=%s, Exponent=%d}", n.PublicKey, int(n.Exponent))
}

func (n *EncryptedNumber) Init(PublicKey *PaillierPublicKey, Ciphertext *big.Int, Exponent float64) *EncryptedNumber {
	n.PublicKey = PublicKey
	n.ciphertext = Ciphertext
	n.Exponent = Exponent
	n.isObfuscated = false
	return n
}

func (n *EncryptedNumber) Obfuscate() {
	r := n.PublicKey.GetRandomItN()
	rPowN := new(big.Int).Exp(r, n.PublicKey.n, n.PublicKey.nsquare)
	n.ciphertext = new(big.Int).Mod(new(big.Int).Mul(n.ciphertext, rPowN), n.PublicKey.nsquare)
	n.isObfuscated = true
}

func (n *EncryptedNumber) Ciphertext(beSecure bool) *big.Int {
	if beSecure && !n.isObfuscated {
		n.Obfuscate()
	}
	return n.ciphertext
}

func (n *EncryptedNumber) DecreaseExponentTo(newExp float64) *EncryptedNumber {
	if newExp > n.Exponent {
		panic(fmt.Sprintf("New exponent %f should be more negative than old exponent %f", newExp, n.Exponent))
	}
	// must convert to int64, otherwise cause a terrible bug because switch into float64 branches
	multiplied := n.Mul(int64(math.Pow(Base, n.Exponent - newExp)))
	multiplied.Exponent = newExp
	return multiplied
}

func (n *EncryptedNumber) rawAdd(eA, eB *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(eA, eB), n.PublicKey.nsquare)
}

func (n *EncryptedNumber) rawMul(plaintext *big.Int) *big.Int  {
	if plaintext.Sign() < 0 || plaintext.Cmp(n.PublicKey.n) >= 0 {
		panic(fmt.Sprintf("Scalar out of bounds: %s", plaintext))
	}
	if new(big.Int).Sub(n.PublicKey.n, n.PublicKey.maxInt).Cmp(plaintext) <= 0 {
		negC := new(big.Int).ModInverse(n.Ciphertext(false), n.PublicKey.nsquare)
		negScalar := new(big.Int).Sub(n.PublicKey.n, plaintext)
		return new(big.Int).Exp(negC, negScalar, n.PublicKey.nsquare)
	} else {
		return new(big.Int).Exp(n.Ciphertext(false), plaintext, n.PublicKey.nsquare)
	}
}

func (n *EncryptedNumber) addEncrypted(other *EncryptedNumber) *EncryptedNumber {
	if !n.PublicKey.Equal(other.PublicKey) {
		panic("Attempted to add numbers encrypted against different public keys!")
	}

	a, b := n, other
	if a.Exponent > b.Exponent {
		a = a.DecreaseExponentTo(b.Exponent)
	} else if a.Exponent < b.Exponent {
		b = b.DecreaseExponentTo(a.Exponent)
	}
	sumCiphertext := a.rawAdd(a.Ciphertext(false), b.Ciphertext(false))
	//fmt.Println("a", a)
	//fmt.Println("b", b)
	return new(EncryptedNumber).Init(a.PublicKey, sumCiphertext, a.Exponent)
}

func (n *EncryptedNumber) addEncoded(encoded *EncodedNumber) *EncryptedNumber {
	if !n.PublicKey.Equal(encoded.PublicKey) {
		panic("Attempted to add numbers encrypted against different public keys!")
	}

	a, b := n, encoded
	if a.Exponent > b.Exponent {
		a = a.DecreaseExponentTo(b.Exponent)
	} else if a.Exponent < b.Exponent {
		b = b.DecreaseExponentTo(a.Exponent)
	}
	encryptedScalar := a.PublicKey.RawEncrypt(b.Encoding, one)
	sumCiphertext := a.rawAdd(a.Ciphertext(false), encryptedScalar)
	return new(EncryptedNumber).Init(a.PublicKey, sumCiphertext, a.Exponent)
}

func (n *EncryptedNumber) addScalar(scalar interface{}) *EncryptedNumber {
	encoded := new(EncodedNumber).Encode(n.PublicKey, scalar, PrecisionUnused, n.Exponent)
	return n.addEncoded(encoded)
}

func (n *EncryptedNumber) Mul(other interface{}) *EncryptedNumber {
	encoding := new(EncodedNumber)
	switch other := other.(type) {
	case *EncodedNumber:
		encoding = other
	case float64, int64:
		encoding = new(EncodedNumber).Encode(n.PublicKey, other, PrecisionUnused, MaxExponentUnused)
	default:
		panic("The argument of EncryptedNumber.Mul should be float64, int64 or *EncodedNumber")
	}
	product := n.rawMul(encoding.Encoding)
	// fmt.Println("product", product)
	exponent := n.Exponent + encoding.Exponent
	// fmt.Println("exponent", exponent)
	return new(EncryptedNumber).Init(n.PublicKey, product, exponent)
}

func (n *EncryptedNumber) Add(other interface{}) *EncryptedNumber {
	switch other := other.(type) {
	case *EncryptedNumber:
		return n.addEncrypted(other)
	case *EncodedNumber:
		return n.addEncoded(other)
	case float64, int64:
		return n.addScalar(other)
	default:
		panic("The argument of EncryptedNumber.Add should be *EncryptedNumber, *EncodedNumber, float64 or int64")
	}
}