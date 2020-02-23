## Paillier Cryptosystem

This is a Paillier cryptosystem package for Golang.

We modularize the package into `keys`, `ops` and `encoding`, which is a little different from the python package `pyphe`.

### Compare

I find some versions of paillier implementation in Go:

- https://github.com/Roasbeef/go-go-gadget-paillier
- https://github.com/didiercrunch/paillier

However, they seem not to support float arithmetic. The Paillier cryptosystem for practice and industory need the float supporting. As a result, I decide to migrate the Python version `pyphe` into Go. The `pyhe` may be the best implementation I have found, so I keep the similar structure and naming conventions. In this version, I didn't add key rings for simplicity, and only implement the core functions. The source code of `pyphe` is linked as:

https://github.com/data61/python-paillier

### Bugs

**1. EncryptedNumber.DecreaseExponentTo (fixed)** 

The `n.Mul` calls `EncodedNumber.Encode` and if we don't change the value to int64, the `Encode` function will encode the value as float64, which cause a serious bug.

```go
func (n *EncryptedNumber) DecreaseExponentTo(newExp float64) *EncryptedNumber {
    ...
    // must convert to int64, otherwise cause a terrible bug because switch into float64 branches
	multiplied := n.Mul(int64(math.Pow(Base, n.Exponent - newExp)))
}
```

**2. Prime Generations**

There is a tiny bug in crypto.rand.Prime, which can only generate a handful of primes. E.g. for nbits = 6, it can only generate 53, 59, 61 without 37, 41, 43, 47.  Maybe it is not a bug but a philosophy.

**3. Small key lengths**

When we set the length of key generations too small, the float64 multiplication may cause an error. This also happens in `pyphe` package. The usually approach to solve it is just set the key length large enough, such as 1024 or 2048. There are some other risks when you set the key length too small, which may cause uncertain results such as overflow sometimes but not always. A typical sample shows as follows:

```
NLen, x, y = 64, 102.3, 102.3

// x * y = 10465.289999999999
// D(E(x) * y) = 4.5918743674694584e-11 (changed by random, sometimes overflowing)
```

The better approach to fix the bug may be panicking when NLen is too small, and we may do that in the ongoing version.
