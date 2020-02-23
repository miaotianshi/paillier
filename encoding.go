package paillier

import (
	"fmt"
	"math"
	"math/big"
)

const (
	Base              = float64(16)
	FloatMantissaBits = 53
	MaxExponentUnused = float64(2000)
	PrecisionUnused   = float64(0)
)

var (
	Log2Base = math.Log2(Base)
)

type EncodedNumber struct {
	PublicKey *PaillierPublicKey
	Encoding  *big.Int
	Exponent  float64
}

func (n *EncodedNumber) String() string {
	return fmt.Sprintf("EncodedNumber{PublicKey=%s, Encoding=%s, Exponent=%d}", n.PublicKey, n.Encoding, int(n.Exponent))
}

func (n *EncodedNumber) Init(publicKey *PaillierPublicKey, encoding *big.Int, exponent float64) *EncodedNumber {
	n.PublicKey = publicKey
	n.Encoding = encoding
	n.Exponent = exponent
	return n
}

// encode sets n to the initialized value and returns n
// set precision <= 0 to make the precision unused
// set maxExponent >= 2000 to make the maxExponent unused. (MaxExponentUnused)
// For a float64 type, the MaxValue is 1.7977e+308, according to you Base, such as 16, your Exponent can be
// less than 308. Even when you choose Base = 2, because 2^4 is larger than 10, 308*4=1232 is large enough
// to support all the float64 situations. Therefore, maxExponent >= 2000 is good enough.
func (n *EncodedNumber) Encode(publicKey *PaillierPublicKey, scalar interface{}, precision float64, maxExponent float64) *EncodedNumber {
	var precExponent, _scalar float64
	if precision <= 0 {
		switch scalar := scalar.(type) {
		case int64:
			precExponent = 0.0
			_scalar = float64(scalar)
		case float64:
			_, binFltExponent := math.Frexp(scalar)
			binLsbExponent := binFltExponent - FloatMantissaBits
			precExponent = math.Floor(float64(binLsbExponent) / Log2Base)
			_scalar = scalar
		default:
			panic("scalar should be int64 or float64.")
		}
	} else {
		precExponent = math.Floor(math.Log(precision) / math.Log(Base))
	}

	exponent := math.Min(precExponent, maxExponent)
	intRep := big.NewInt(int64(math.Round(_scalar * math.Pow(Base, -exponent))))
	if intRep.Cmp(publicKey.maxInt) > 0 {
		panic("intRep should be less than publicKey.maxInt")
	}
	encoding := new(big.Int).Mod(intRep, publicKey.n)
	return new(EncodedNumber).Init(publicKey, encoding, exponent)
}

func (n *EncodedNumber) Decode() float64 {
	mantissa := new(big.Int)
	if n.Encoding.Cmp(n.PublicKey.n) >= 0 {
		panic("Attempted to decode corrupted number")
	} else if n.Encoding.Cmp(n.PublicKey.maxInt) <= 0 {
		mantissa = n.Encoding
	} else if n.Encoding.Cmp(new(big.Int).Sub(n.PublicKey.n, n.PublicKey.maxInt)) >= 0 {
		mantissa = new(big.Int).Sub(n.Encoding, n.PublicKey.n)
	} else {
		panic("Overflow detected in decrypted number")
	}

	//decoded := new(big.Int).Mul(mantissa, big.NewInt(int64(math.Pow(float64(Base), n.Exponent))))
	decoded, _ := new(big.Float).Mul(
		new(big.Float).SetInt(mantissa), new(big.Float).SetFloat64(math.Pow(Base, n.Exponent))).Float64()
	return decoded
}

func (n *EncodedNumber) DecreaseExponentTo(newExp float64) *EncodedNumber {
	if newExp > n.Exponent {
		panic(fmt.Sprintf("New exponent %f should be more negative than old exponent %f", newExp, n.Exponent))
	}

	factor := big.NewInt(int64(math.Pow(Base, n.Exponent-newExp)))
	newEnc := new(big.Int).Mod(new(big.Int).Mul(n.Encoding, factor), n.PublicKey.n)
	return new(EncodedNumber).Init(n.PublicKey, newEnc, newExp)
}


