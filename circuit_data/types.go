package circuitdata

import "github.com/consensys/gnark/std/math/uints"

const N_BYTES_HASH = 32

type KeccakHash []uints.U8

func (hash *KeccakHash) Make() {
	*hash = make([]uints.U8, N_BYTES_HASH)
}

func (keccakHashNative NativeKeccakHash) GetVariable() KeccakHash {
	var keccakHash KeccakHash
	for _, elm := range keccakHashNative {
		keccakHash = append(keccakHash, uints.U8{Val: elm})
	}
	return keccakHash
}
