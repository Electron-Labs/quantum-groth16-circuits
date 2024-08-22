package imt

import (
	"errors"
	"fmt"
	"math/big"

	circuitData "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func GetZeroLeafHash() []uints.U8 {
	hashBytes := []frontend.Variable{60, 172, 49, 121, 8, 198, 153, 254, 135, 58, 127, 110, 228, 232, 205, 99, 251, 233, 145, 139, 35, 21, 201, 123, 233, 21, 133, 89, 1, 104, 227, 1}
	zeroHash := make([]uints.U8, len(hashBytes))
	for i := range hashBytes {
		zeroHash[i] = uints.U8{Val: hashBytes[i]}
	}
	return zeroHash
}

func GetEmptyTreeRoot(treeDepth *big.Int) []uints.U8 {
	root := make([]uints.U8, circuitData.N_BYTES_HASH)
	if treeDepth.Cmp(big.NewInt(10)) == 0 {
		rootBytes := []frontend.Variable{133, 27, 23, 145, 79, 228, 224, 227, 7, 173, 86, 21, 96, 202, 212, 76, 109, 0, 10, 109, 158, 64, 92, 46, 211, 186, 116, 105, 60, 22, 42, 118}
		for i := range rootBytes {
			root[i] = uints.U8{Val: rootBytes[i]}
		}
	} else if treeDepth.Cmp(big.NewInt(9)) == 0 {
		rootBytes := []frontend.Variable{157, 149, 45, 171, 75, 243, 215, 53, 86, 67, 124, 100, 47, 116, 51, 82, 48, 65, 157, 175, 29, 159, 136, 187, 96, 150, 225, 168, 160, 39, 191, 65}
		for i := range rootBytes {
			root[i] = uints.U8{Val: rootBytes[i]}
		}
	} else {
		panic(fmt.Sprintf("unsupported treeDepth:%d", treeDepth))
	}
	return root
}

func IsZeroValue(api frontend.API, value []uints.U8) frontend.Variable {
	isZero := frontend.Variable(0)
	for i := 0; i < len(value); i++ {
		isZero = api.Or(api.IsZero(value[i].Val), isZero)
	}
	return isZero
}

// IsAGtThanB returns:
//   - 1 if a>b,
//   - 0 if a<=b,
//   - a and b are the big-endian repr
func IsAGtThanB(api frontend.API, a []uints.U8, b []uints.U8) (frontend.Variable, error) {
	isAGtThanB := frontend.Variable(0)

	if len(a) == 0 {
		return isAGtThanB, errors.New("len a can't be 0")
	}
	if len(a) != len(b) {
		return isAGtThanB, errors.New("len a != len b")
	}
	one := frontend.Variable(1)
	var isALessThanB frontend.Variable
	for i := 0; i < len(a); i++ {
		c1 := api.Sub(one, isAGtThanB) // enable constraint, we haven't found the answer to isAGtThanB yet
		cmpRes := api.Cmp(a[i].Val, b[i].Val)
		isMinusOne := api.IsZero(api.Add(cmpRes, one))
		isNotMinusOne := api.Sub(one, isMinusOne)
		isALessThanB = api.Mul(isMinusOne, c1)
		c2 := api.Sub(one, isALessThanB) // enable constraint, we haven't found the answer to isALessThanB yet
		isAGtThanB = api.Add(isAGtThanB, api.Mul(api.Mul(cmpRes, isNotMinusOne), api.Mul(c1, c2)))
	}
	return isAGtThanB, nil
}

// IsAGtThanB returns:
//   - 1 if a==b,
//   - 0 otherwise
//   - a and b are the big-endian repr
func IsAEqToB(api frontend.API, a []uints.U8, b []uints.U8) (frontend.Variable, error) {
	isAEqToB := frontend.Variable(1)

	if len(a) == 0 {
		return isAEqToB, errors.New("len a can't be 0")
	}
	if len(a) != len(b) {
		return isAEqToB, errors.New("len a != len b")
	}
	for i := 0; i < len(a); i++ {
		cmpRes := api.Cmp(a[i].Val, b[i].Val)
		isEqual := api.IsZero(cmpRes)
		isAEqToB = api.And(isAEqToB, isEqual)
	}
	return isAEqToB, nil
}

func (leaf Leaf) Hash(api frontend.API) ([]uints.U8, error) {
	leafSerialized := leaf.Value
	leafSerialized = append(leafSerialized, leaf.NextValue...)
	leafSerialized = append(leafSerialized, leaf.NextIdx...)
	leafHash, err := circuitData.GetKeccak256Hash(api, leafSerialized)
	if err != nil {
		return leafHash, err
	}
	return leafHash, nil
}

func NumToFrontendBeBytes(num big.Int, nBytes int) []uints.U8 {
	numBytesBe := make([]byte, nBytes)
	numBytesBe = num.FillBytes(numBytesBe)
	numBytesBeFrontend := make([]uints.U8, nBytes)
	for i := 0; i < nBytes; i++ {
		numBytesBeFrontend[i].Val = numBytesBe[i]
	}
	return numBytesBeFrontend
}

func BeBytesToNum(api frontend.API, bytes []uints.U8) frontend.Variable {
	sum := frontend.Variable(0)
	factor := frontend.Variable(1)
	base := frontend.Variable(256)

	for i := range bytes {
		sum = api.Add(sum, api.Mul(factor, bytes[len(bytes)-1-i].Val))
		factor = api.Mul(factor, base)
	}

	return sum
}
