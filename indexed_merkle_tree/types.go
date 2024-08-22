package imt

import (
	circuitData "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const N_BYTES_LEAF_IDX = 8

type LeafIdx []uints.U8

type Leaf struct {
	Value     circuitData.KeccakHash
	NextValue circuitData.KeccakHash
	NextIdx   LeafIdx
}

type MerkleProof struct {
	Proof []circuitData.KeccakHash
	Path  []frontend.Variable
}

type InclusionProof struct {
	MerkleProof MerkleProof
	Root        circuitData.KeccakHash
}

type NonInclusionProof struct {
	Root         circuitData.KeccakHash
	LowLeaf      Leaf
	LowLeafProof MerkleProof
	NewLeafValue circuitData.KeccakHash
}

type InsertLeafProofs struct {
	OldRoot      circuitData.KeccakHash
	LowLeaf      Leaf
	LowLeafProof MerkleProof
	NewLeaf      Leaf
	NewLeafIdx   LeafIdx
	NewLeafProof MerkleProof
}

type InsertLeafProofVerify struct {
	Proof   InsertLeafProofs
	NewRoot circuitData.KeccakHash
}

type InsertLeafIntermediateProof struct {
	LowLeaf      Leaf
	LowLeafProof MerkleProof
	NewLeaf      Leaf
	NewLeafIdx   LeafIdx
	NewLeafProof MerkleProof
}

func (idx *LeafIdx) Make() {
	*idx = make([]uints.U8, N_BYTES_LEAF_IDX)
}

func (leaf *Leaf) Make() {
	leaf.Value.Make()
	leaf.NextValue.Make()
	leaf.NextIdx.Make()
}

func (proof *MerkleProof) Make(depth int) {
	proof.Proof = make([]circuitData.KeccakHash, depth)
	for i := range proof.Proof {
		proof.Proof[i].Make()
	}
	proof.Path = make([]frontend.Variable, depth)
}

func (circuit *InclusionProof) Make(depth int) {
	circuit.MerkleProof.Make(depth)
	circuit.Root.Make()
}

func (circuit *NonInclusionProof) Make(depth int) {
	circuit.Root.Make()
	circuit.LowLeaf.Make()
	circuit.LowLeafProof.Make(depth)
	circuit.NewLeafValue.Make()
}

func (circuit *InsertLeafProofs) Make(depth int) {
	circuit.OldRoot.Make()
	circuit.LowLeaf.Make()
	circuit.LowLeafProof.Make(depth)
	circuit.NewLeaf.Make()
	circuit.NewLeafIdx.Make()
	circuit.NewLeafProof.Make(depth)
}

func (circuit *InsertLeafProofVerify) Make(depth int) {
	circuit.Proof.Make(depth)
	circuit.NewRoot.Make()
}

func (circuit *InsertLeafIntermediateProof) Make(depth int) {
	circuit.LowLeaf.Make()
	circuit.LowLeafProof.Make(depth)
	circuit.NewLeaf.Make()
	circuit.NewLeafIdx.Make()
	circuit.NewLeafProof.Make(depth)
}

func (circuit *Imt) Make(nReduction int, nPubInputs int, nCommitments int, treeDepth int) {
	circuit.VKHashes = make([]circuitData.KeccakHash, nReduction)
	circuit.ProtocolPisHashes = make([]circuitData.KeccakHash, nReduction)
	circuit.InsertLeafProofs = make([]InsertLeafIntermediateProof, nReduction)
	for i := 0; i < nReduction; i++ {
		circuit.VKHashes[i].Make()
		circuit.ProtocolPisHashes[i].Make()
		circuit.InsertLeafProofs[i].Make(treeDepth)
	}
	circuit.PrevBatchLastNewLowLeaf.Make()
	circuit.PrevBatchLastNewLowLeafProof.Make(treeDepth)
	circuit.OldRoot.Make()
	circuit.PubInputs = make([]frontend.Variable, 2)
}

func (leafIdxNative NativeLeafIdx) GetVariable() (leafIdx LeafIdx) {
	for _, elm := range leafIdxNative {
		leafIdx = append(leafIdx, uints.U8{Val: elm})
	}
	return leafIdx
}

func (leaf *NativeLeaf) GetVariable() Leaf {
	var leafVariable Leaf
	leafVariable.Value = leaf.Value.GetVariable()
	leafVariable.NextValue = leaf.NextValue.GetVariable()
	for i := 0; i < len(leaf.NextIdx); i++ {
		leafVariable.NextIdx = append(leafVariable.NextIdx, uints.U8{Val: leaf.NextIdx[i]})
	}
	return leafVariable
}

func (inclusionProofNative *NativeMerkleProof) GetVariable() MerkleProof {
	var inclusionProof MerkleProof
	for _, elm := range inclusionProofNative.Proof {
		inclusionProof.Proof = append(inclusionProof.Proof, elm.GetVariable())
	}
	for _, elm := range inclusionProofNative.Path {
		inclusionProof.Path = append(inclusionProof.Path, elm)
	}
	return inclusionProof
}

func (merkleProofVerifyNative *NativeInclusionProof) GetVariable() InclusionProof {
	var merkleProofVerify InclusionProof
	merkleProofVerify.MerkleProof = merkleProofVerifyNative.MerkleProof.GetVariable()
	merkleProofVerify.Root = merkleProofVerifyNative.Root.GetVariable()
	return merkleProofVerify
}

func (u *NativeNonInclusionProof) GetVariable() NonInclusionProof {
	var t NonInclusionProof
	t.Root = u.Root.GetVariable()
	t.LowLeaf = u.LowLeaf.GetVariable()
	t.LowLeafProof = u.LowLeafProof.GetVariable()
	t.NewLeafValue = u.NewLeafValue.GetVariable()

	return t
}

func (u *NativeInsertLeafProof) GetVariable() InsertLeafProofs {
	var t InsertLeafProofs
	t.OldRoot = u.OldRoot.GetVariable()
	t.LowLeaf = u.LowLeaf.GetVariable()
	t.LowLeafProof = u.LowLeafProof.GetVariable()
	t.NewLeaf = u.NewLeaf.GetVariable()
	t.NewLeafIdx = u.NewLeafIdx.GetVariable()
	t.NewLeafProof = u.NewLeafProof.GetVariable()
	return t
}

func (u *NativeInsertLeafProofVerify) GetVariable() InsertLeafProofVerify {
	var t InsertLeafProofVerify
	t.Proof = u.Proof.GetVariable()
	t.NewRoot = u.NewRoot.GetVariable()
	return t
}

func (leaf NativeLeaf) Serialize() ([]byte, error) {
	serialized := leaf.Value
	serialized = append(serialized, leaf.NextValue...)

	serialized = append(serialized, leaf.NextIdx...)

	return serialized, nil
}

func (u *NativeInsertLeafIntermediateProof) GetVariable() (t InsertLeafIntermediateProof) {
	t.LowLeaf = u.LowLeaf.GetVariable()
	t.LowLeafProof = u.LowLeafProof.GetVariable()
	t.NewLeaf = u.NewLeaf.GetVariable()
	t.NewLeafIdx = u.NewLeafIdx.GetVariable()
	t.NewLeafProof = u.NewLeafProof.GetVariable()
	return t
}

func (u *NativeImt) GetVariable() (t Imt) {
	t.VKHashes = make([]circuitData.KeccakHash, len(u.VKHashes))
	t.ProtocolPisHashes = make([]circuitData.KeccakHash, len(u.ProtocolPisHashes))
	t.InsertLeafProofs = make([]InsertLeafIntermediateProof, len(u.InsertLeafProofs))
	for i := range u.InsertLeafProofs {
		t.VKHashes[i] = u.VKHashes[i].GetVariable()
		t.ProtocolPisHashes[i] = u.ProtocolPisHashes[i].GetVariable()
		t.InsertLeafProofs[i] = u.InsertLeafProofs[i].GetVariable()
	}
	t.PrevBatchLastNewLowLeaf = u.PrevBatchLastNewLowLeaf.GetVariable()
	t.PrevBatchLastNewLowLeafProof = u.PrevBatchLastNewLowLeafProof.GetVariable()

	t.OldRoot = u.OldRoot.GetVariable()
	t.PubInputs = []frontend.Variable{u.PubInputs[0], u.PubInputs[1]}

	return t
}
