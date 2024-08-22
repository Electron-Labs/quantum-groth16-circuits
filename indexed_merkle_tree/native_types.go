package imt

import (
	"fmt"

	circuitData "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
)

type NativeLeafIdx circuitData.NativeByteSlice

type NativeLeaf struct {
	Value     circuitData.NativeKeccakHash
	NextValue circuitData.NativeKeccakHash
	NextIdx   NativeLeafIdx
}

type NativeMerkleProof struct {
	Proof []circuitData.NativeKeccakHash
	Path  circuitData.NativeByteSlice
}

type NativeInsertLeafProof struct {
	OldRoot      circuitData.NativeKeccakHash
	LowLeaf      NativeLeaf
	LowLeafProof NativeMerkleProof
	NewLeaf      NativeLeaf
	NewLeafIdx   NativeLeafIdx
	NewLeafProof NativeMerkleProof
}

type NativeInsertLeafProofVerify struct {
	Proof   NativeInsertLeafProof
	NewRoot circuitData.NativeKeccakHash
}

type NativeInsertLeafIntermediateProof struct {
	LowLeaf      NativeLeaf
	LowLeafProof NativeMerkleProof
	NewLeaf      NativeLeaf
	NewLeafIdx   NativeLeafIdx
	NewLeafProof NativeMerkleProof
}

type NativeImt struct {
	VKHashes                     []circuitData.NativeKeccakHash
	ProtocolPisHashes            []circuitData.NativeKeccakHash
	InsertLeafProofs             []NativeInsertLeafIntermediateProof
	PrevBatchLastNewLowLeaf      NativeLeaf
	PrevBatchLastNewLowLeafProof NativeMerkleProof
	OldRoot                      circuitData.NativeKeccakHash
	PubInputs                    []string
}

type NativeInclusionProof struct {
	LeafHash    circuitData.NativeKeccakHash
	MerkleProof NativeMerkleProof
	Root        circuitData.NativeKeccakHash
}

type NativeNonInclusionProof struct {
	Root         circuitData.NativeKeccakHash
	LowLeaf      NativeLeaf
	LowLeafProof NativeMerkleProof
	NewLeafValue circuitData.NativeKeccakHash
}

func (t NativeImt) Check() error {
	if len(t.VKHashes) != len(t.ProtocolPisHashes) {
		return fmt.Errorf("unequal length of ReductionCircuitDataVec and ProtocolVKHashes")
	}
	if len(t.VKHashes) != len(t.InsertLeafProofs) {
		return fmt.Errorf("unequal length of ReductionCircuitDataVec and ProtocolVKHashes")
	}
	if len(t.PubInputs) != 2 {
		return fmt.Errorf("length of pubInputs must be 2")
	}
	return nil
}
