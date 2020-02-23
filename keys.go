// Copyright 2020 miaotianshi. All rights reserved.

// There is a tiny bug in crypto.rand.Prime, which can only generate a handful of primes.
// E.g. for nbits = 6, it can only generate 53, 59, 61 without 37, 41, 43, 47.
// Maybe it is not a bug but a philosophy.

package paillier

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
)

var one = big.NewInt(1)
var three = big.NewInt(3)

type PaillierPublicKey struct {
	g, n, nsquare, maxInt *big.Int
}

func (p *PaillierPublicKey) String() string {
	return fmt.Sprintf("PublicKey{n=%s}", p.n)
}

func (p *PaillierPublicKey) Init(n *big.Int) {
	p.n = n
	p.g = new(big.Int).Add(n, one)
	p.nsquare = new(big.Int).Mul(n, n)
	p.maxInt = new(big.Int).Sub(new(big.Int).Div(n, three), one)
}

func (p *PaillierPublicKey) Equal(other *PaillierPublicKey) bool {
	return p.n == other.n
}

func (p *PaillierPublicKey) RawEncrypt(plaintext *big.Int, rValue *big.Int) *big.Int {
	var nudeCiphertext *big.Int
	if new(big.Int).Sub(p.n, p.maxInt).Cmp(plaintext) <= 0 && plaintext.Cmp(p.n) < 0 {
		negPlaintext := new(big.Int).Sub(p.n, plaintext)
		negCiphertext := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(p.n, negPlaintext), one), p.nsquare)
		nudeCiphertext = new(big.Int).ModInverse(negCiphertext, p.nsquare)
	} else {
		nudeCiphertext = new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(p.n, plaintext), one), p.nsquare)
	}
	var r *big.Int
	if rValue == nil {
		r = p.GetRandomItN()
	} else {
		r = rValue
	}
	obfuscator := new(big.Int).Exp(r, p.n, p.nsquare)
	return new(big.Int).Mod(new(big.Int).Mul(nudeCiphertext, obfuscator), p.nsquare)
}

func (p *PaillierPublicKey) GetRandomItN() *big.Int {
	randValue, err := rand.Int(rand.Reader, new(big.Int).Sub(p.n, one))
	if err != nil {
		log.Fatal(`rand.Int error`)
	}
	return new(big.Int).Add(randValue, one)
	//return big.NewInt(5)
}

func (p *PaillierPublicKey) EncryptEncoded(encoding *EncodedNumber, rValue *big.Int) *EncryptedNumber {
	var obfuscator *big.Int
	if rValue == nil {
		obfuscator = one
	} else {
		obfuscator = rValue
	}
	ciphertext := p.RawEncrypt(encoding.Encoding, obfuscator)
	//encryptedNumber := &EncryptedNumber{p, ciphertext, Encoding.Exponent, false}
	encryptedNumber := new(EncryptedNumber).Init(p, ciphertext, encoding.Exponent)
	if rValue == nil {
		encryptedNumber.Obfuscate()
	}
	return encryptedNumber
}

func (p *PaillierPublicKey) Encrypt(value interface{}, precision float64, rValue *big.Int) *EncryptedNumber {
	encoding := new(EncodedNumber)
	switch value := value.(type) {
	case *EncodedNumber:
		encoding = value
	case float64, int64:
		encoding = new(EncodedNumber).Encode(p, value, precision, MaxExponentUnused)
	default:
		panic("Value should be *EncodedNumber, int64 or float64")
	}
	return p.EncryptEncoded(encoding, rValue)
}

type PaillierPrivateKey struct {
	publicKey                                *PaillierPublicKey
	p, q, psquare, qsquare, pInverse, hp, hq *big.Int
}

func (pr *PaillierPrivateKey) String() string {
	return fmt.Sprintf("PrivateKey{p=%s, q=%s}", pr.p, pr.q)
}

func (pr *PaillierPrivateKey) Init(publicKey *PaillierPublicKey, p, q *big.Int) {
	pr.publicKey = publicKey
	if new(big.Int).Mul(p, q).Cmp(publicKey.n) != 0 {
		panic("q * p != n")
	}

	if p.Cmp(q) == 0 {
		panic("p shouldn't be equal to q")
	}

	if p.Cmp(q) > 0 {
		pr.p = q
		pr.q = p
	} else {
		pr.p = p
		pr.q = q
	}

	pr.psquare = new(big.Int).Mul(pr.p, pr.p)
	pr.qsquare = new(big.Int).Mul(pr.q, pr.q)
	pr.pInverse = new(big.Int).ModInverse(pr.p, pr.q)
	pr.hp = pr.HFunction(pr.p, pr.psquare)
	pr.hq = pr.HFunction(pr.q, pr.qsquare)
}

func (pr *PaillierPrivateKey) RawDecrypt(ciphertext *big.Int) *big.Int {
	decryptToP := new(big.Int).Mod(new(big.Int).Mul(
		pr.LFunction(new(big.Int).Exp(ciphertext, new(big.Int).Sub(pr.p, one), pr.psquare), pr.p), pr.hp), pr.p)
	decryptToQ := new(big.Int).Mod(new(big.Int).Mul(
		pr.LFunction(new(big.Int).Exp(ciphertext, new(big.Int).Sub(pr.q, one), pr.qsquare), pr.q), pr.hq), pr.q)
	return pr.Crt(decryptToP, decryptToQ)
}

func (pr *PaillierPrivateKey) DecryptEncoded(encryptedNumber *EncryptedNumber) *EncodedNumber {
	if !pr.publicKey.Equal(encryptedNumber.PublicKey) {
		panic("encryptedNumber was encrypted against a different key!")
	}
	encoded := pr.RawDecrypt(encryptedNumber.Ciphertext(false))
	return new(EncodedNumber).Init(pr.publicKey, encoded, encryptedNumber.Exponent)
}

func (pr *PaillierPrivateKey) Decrypt(encryptedNumber *EncryptedNumber) float64 {
	encoded := pr.DecryptEncoded(encryptedNumber)
	return encoded.Decode()
}

func (pr *PaillierPrivateKey) HFunction(x, xsquare *big.Int) *big.Int {
	return new(big.Int).ModInverse(pr.LFunction(
		new(big.Int).Exp(pr.publicKey.g, new(big.Int).Sub(x, one), xsquare), x), x)
}

func (pr *PaillierPrivateKey) LFunction(x, p *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, one), p)
}

func (pr *PaillierPrivateKey) Crt(mp, mq *big.Int) *big.Int {
	u := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(mq, mp), pr.pInverse), pr.q)
	return new(big.Int).Add(mp, new(big.Int).Mul(u, pr.p))
}

func GeneratePaillierKeypair(NLength int) (*PaillierPublicKey, *PaillierPrivateKey) {
	var nLen int
	var n, p, q *big.Int
	var err error
	for nLen != NLength {
		p, err = rand.Prime(rand.Reader, NLength/2)
		if err != nil {
			log.Print("rand error")
			continue
		}
		for q == nil || q.Cmp(p) == 0 {
			q, err = rand.Prime(rand.Reader, NLength/2)
			if err != nil {
				log.Print("rand error")
			}
		}
		n = new(big.Int).Mul(p, q)
		nLen = n.BitLen()
	}
	publicKey := new(PaillierPublicKey)
	privateKey := new(PaillierPrivateKey)
	publicKey.Init(n)
	privateKey.Init(publicKey, p, q)
	//log.Println(publicKey)
	//log.Println(privateKey)

	return publicKey, privateKey
}

func GeneratePaillierKeypairByPQ(p, q *big.Int) (*PaillierPublicKey, *PaillierPrivateKey) {
	publicKey := new(PaillierPublicKey)
	privateKey := new(PaillierPrivateKey)
	n := new(big.Int).Mul(p, q)
	publicKey.Init(n)
	privateKey.Init(publicKey, p, q)
	return publicKey, privateKey
}
