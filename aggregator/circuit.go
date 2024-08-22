package aggregator

import (
	"fmt"

	circuitData "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	imt "github.com/Electron-Labs/quantum-gnark-circuits/indexed_merkle_tree"
	verifier_gnark "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

type Aggregator struct {
	ReductionCircuits   []GnarkVerifier
	ImtReductionCircuit GnarkVerifier
	ProtocolVKHashes    []circuitData.KeccakHash
	ProtocolPisHashes   []circuitData.KeccakHash
	OldRoot             circuitData.KeccakHash
	NewRoot             circuitData.KeccakHash
	PubInputs           []frontend.Variable `gnark:",public"`
}

func (circuit Aggregator) Define(api frontend.API) error {
	if len(circuit.ReductionCircuits) != len(circuit.ProtocolVKHashes) {
		panic("length of ReductionCircuits and ProtocolVKHashes must be equal")
	}
	if len(circuit.ReductionCircuits) != len(circuit.ProtocolPisHashes) {
		panic("length of ReductionCircuits and ProtocolPisHashes must be equal")
	}
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("stdgroth16.NewVerifier::%w", err)
	}

	vkHashes := make([]circuitData.KeccakHash, len(circuit.ReductionCircuits))
	for i, reductionCircuit := range circuit.ReductionCircuits {
		// verify reductionCircuit
		err := verifier.AssertProof(reductionCircuit.VerifyingKey, reductionCircuit.Proof, reductionCircuit.InnerWitness)
		if err != nil {
			return fmt.Errorf("%dth verifier.AssertProof failed::%w", i, err)
		}

		// asserts ReductionCircuits[i].InnerWitness == keccak(protocolVKHash || protocolPisHash)
		reductionPubInputsComputed, err := computeReductionPubInputsSerializedCompressed(api, circuit.ProtocolVKHashes[i], circuit.ProtocolPisHashes[i])
		if err != nil {
			return fmt.Errorf("%dth computeReductionPubInputsSerializedCompressed failed::%w", i, err)
		}
		err = assertPubInputsSerializedAndCompressed(api, reductionPubInputsComputed, reductionCircuit.InnerWitness.Public)
		if err != nil {
			return fmt.Errorf("assertPubInputsSerializedAndCompressed(api, reductionPubInputsComputed::%w", err)
		}

		// compute combined vk hash
		vkHash, err := ComputeVkHash(api, circuit.ProtocolVKHashes[i], reductionCircuit.VerifyingKey)
		if err != nil {
			return fmt.Errorf("ComputeVkHash::%w", err)
		}
		vkHashes[i] = vkHash
	}

	// constrain pubInputs of ImtReductionCircuit
	imtPubInputsSerializedCompressed, err := imt.ComputePubInputs(api, vkHashes, circuit.ProtocolPisHashes, circuit.OldRoot, circuit.NewRoot)
	if err != nil {
		return fmt.Errorf("imt.ComputePubInputs failed::%w", err)
	}
	err = assertPubInputsSerializedAndCompressed(api, imtPubInputsSerializedCompressed, circuit.ImtReductionCircuit.InnerWitness.Public)
	if err != nil {
		return fmt.Errorf("assertPubInputsSerializedAndCompressed(api, imtPubInputsSerializedCompressed failed::%w", err)
	}

	// verify public inputs
	imtVkHash, err := verifier_gnark.VKHash(api, circuit.ImtReductionCircuit.VerifyingKey)
	if err != nil {
		return fmt.Errorf("verifier_gnark.VKHash(api, circuit.ImtReductionCircuit.VerifyingKey)::%w", err)
	}
	pubInputsSerializedComputed, err := ComputePubInputsSerialized(api, circuit.ProtocolVKHashes, vkHashes, circuit.ProtocolPisHashes, circuit.OldRoot, circuit.NewRoot, imtVkHash)
	if err != nil {
		return fmt.Errorf("ComputePubInputs failed::%w", err)
	}
	verifier_gnark.VerifyPublicInputs(api, pubInputsSerializedComputed, circuit.PubInputs)

	return nil
}

// returns byte array of length 32
// concatenated bn254 elms
func computeReductionPubInputsSerializedCompressed(api frontend.API, protocolVKHash circuitData.KeccakHash, protocolPisHash circuitData.KeccakHash) (circuitData.KeccakHash, error) {
	var serialized []uints.U8
	for i := 0; i < len(protocolVKHash); i++ {
		serialized = append(serialized, protocolVKHash[i])
	}
	for i := 0; i < len(protocolPisHash); i++ {
		serialized = append(serialized, protocolPisHash[i])
	}

	computed, err := circuitData.GetKeccak256Hash(api, serialized)
	if err != nil {
		return computed, fmt.Errorf("computeReductionPubInputsCompressed::circuitData.GetKeccak256Hash::%w", err)
	}
	return computed, nil
}

func assertPubInputsSerializedAndCompressed(api frontend.API, pubInputsSerializedCompressed circuitData.KeccakHash, pubInputs []emulated.Element[sw_bn254.ScalarField]) error {
	pubInputsSerialized, err := verifier_gnark.SerializePubInputs(api, pubInputs)
	if err != nil {
		return fmt.Errorf("verifier_gnark.SerializePubInputs::%w", err)
	}

	// pubInputsSerializedCompressed[:16] == pub1
	// pubInputsSerializedCompressed[16:] == pub2
	// reductionPisSerialized[:16] == 0
	// reductionPisSerialized[16:] == 0
	for i := 0; i < 16; i++ {
		api.AssertIsEqual(pubInputsSerialized[i].Val, frontend.Variable(0))
		api.AssertIsEqual(pubInputsSerialized[16+i].Val, pubInputsSerializedCompressed[i].Val)
		api.AssertIsEqual(pubInputsSerialized[32+i].Val, frontend.Variable(0))
		api.AssertIsEqual(pubInputsSerialized[48+i].Val, pubInputsSerializedCompressed[16+i].Val)
	}

	return nil
}

func ComputeVkHash(api frontend.API, protocolVKHash circuitData.KeccakHash, reductionVK stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]) (circuitData.KeccakHash, error) {
	vkHash := circuitData.KeccakHash{}

	var keccakInput []uints.U8
	keccakInput = append(keccakInput, protocolVKHash...)
	reductionVKHash, err := verifier_gnark.VKHash(api, reductionVK)
	if err != nil {
		return vkHash, fmt.Errorf("verifier_gnark.VKHash(api, reductionVK)::%w", err)
	}
	keccakInput = append(keccakInput, reductionVKHash...)
	vkHash, err = circuitData.GetKeccak256Hash(api, keccakInput)
	if err != nil {
		return vkHash, fmt.Errorf("circuitData.GetKeccak256Hash(api, keccakInput)::%w", err)
	}

	return vkHash, nil
}

// returns serialized pubInputs
// vkHash = keccak(protocolVKHash || reductionVKHash)
// keccakInput = ( (vkHashes[0] || protocolPisHashes[0]) || (vkHashes[1] || protocolPisHashes[1]) … n times … || oldRoot || newRoot || imtVkHash)
// pubInputs = keccak(keccakInput)
func ComputePubInputsSerialized(api frontend.API, protocolVKHashes []circuitData.KeccakHash, vkHashes []circuitData.KeccakHash, protocolPisHashes []circuitData.KeccakHash, oldRoot circuitData.KeccakHash, newRoot circuitData.KeccakHash, imtVkHash circuitData.KeccakHash) (circuitData.KeccakHash, error) {
	serializedInput := make([]uints.U8, len(protocolVKHashes)*64+32+32+32)
	for i, vkHash := range vkHashes {
		for j := 0; j < 32; j++ {
			serializedInput[i*64+j] = vkHash[j]
			serializedInput[i*64+j+32] = protocolPisHashes[i][j]
		}
	}
	for i := 0; i < 32; i++ {
		serializedInput[len(protocolVKHashes)*64+i] = oldRoot[i]
		serializedInput[len(protocolVKHashes)*64+32+i] = newRoot[i]
		serializedInput[len(protocolVKHashes)*64+32+32+i] = imtVkHash[i]
	}

	pubInputsSerialized, err := circuitData.GetKeccak256Hash(api, serializedInput)
	if err != nil {
		return pubInputsSerialized, fmt.Errorf("pubInputsSerialized::circuitData.GetKeccak256Hash::%w", err)
	}

	return pubInputsSerialized, nil
}
