package aggregator

import (
	"fmt"
	"math/big"

	circuitData "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	verifier_gnark "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type NativeGnarkVerifier struct {
	Proof     verifier_gnark.Proof
	VK        verifier_gnark.VK
	PubInputs fr_bn254.Vector
}

type NativeAggregator struct {
	ReductionCircuitDataVec []NativeGnarkVerifier
	ImtReductionCircuitData NativeGnarkVerifier
	ProtocolVKHashes        []circuitData.NativeKeccakHash
	ProtocolPisHashes       []circuitData.NativeKeccakHash
	OldRoot                 circuitData.NativeKeccakHash
	NewRoot                 circuitData.NativeKeccakHash
	PubInputs               []string
}

func (t NativeAggregator) Check() error {
	if len(t.ReductionCircuitDataVec) != len(t.ProtocolVKHashes) {
		return fmt.Errorf("unequal length of ReductionCircuitDataVec and ProtocolVKHashes")
	}
	if len(t.ReductionCircuitDataVec) != len(t.ProtocolPisHashes) {
		return fmt.Errorf("unequal length of ReductionCircuitDataVec and ProtocolPisHashes")
	}
	if len(t.PubInputs) != 2 {
		return fmt.Errorf("length of pubInputs must be 2")
	}
	return nil
}

func GetAggregatorPublicInputs(
	vkHashes []circuitData.NativeKeccakHash,
	verifiers []NativeGnarkVerifier,
	pisHashes []circuitData.NativeKeccakHash,
	oldRoot, newRoot circuitData.NativeKeccakHash,
	imtVerifier NativeGnarkVerifier,
) (pis [2]string, err error) {
	imtVk, err := imtVerifier.VK.Groth16VK()
	if err != nil {
		return pis, err
	}
	imtVkHash, err := verifier_gnark.GetReductionVKHash(&imtVk)
	if err != nil {
		return pis, err
	}
	reductionVkHashes := make([]circuitData.NativeKeccakHash, len(verifiers))
	for i, v := range verifiers {
		vk_, err := v.VK.Groth16VK()
		if err != nil {
			return pis, err
		}
		reductionVkHashes[i], err = verifier_gnark.GetReductionVKHash(&vk_)
		if err != nil {
			return pis, err
		}

	}

	if len(vkHashes) != len(pisHashes) {
		panic("len(vkHashes) != len(pisHashes)")
	}
	var sha3Input []byte
	for i := range vkHashes {
		combinedHash, err := verifier_gnark.KeccakHashFunc(append(vkHashes[i], reductionVkHashes[i]...))
		if err != nil {
			return pis, err
		}
		sha3Input = append(sha3Input, combinedHash...)
		sha3Input = append(sha3Input, pisHashes[i]...)
	}
	sha3Input = append(sha3Input, oldRoot...)
	sha3Input = append(sha3Input, newRoot...)
	sha3Input = append(sha3Input, imtVkHash...)
	pubInputsSerialized, err := verifier_gnark.KeccakHashFunc(sha3Input)
	if err != nil {
		panic("KeccakHashFn()")
	}

	pub1 := big.NewInt(0).SetBytes(pubInputsSerialized[:16])
	pub2 := big.NewInt(0).SetBytes(pubInputsSerialized[16:])

	return [2]string{pub1.String(), pub2.String()}, nil
}
