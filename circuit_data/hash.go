package circuitdata

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
)

func GetKeccak256Hash(api frontend.API, serializedElems []uints.U8) (KeccakHash, error) {
	var hashComputed []uints.U8
	hasher, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return hashComputed, err
	}
	hasher.Write(serializedElems)
	hashComputed = hasher.Sum()
	return hashComputed, nil
}
