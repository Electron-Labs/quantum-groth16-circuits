package imt

import (
	circuitData "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
)

func ComputeMerkleRoot(api frontend.API, leafHash []uints.U8, inclusionProof MerkleProof) (root []uints.U8, err error) {
	hash := leafHash
	one := frontend.Variable(1)
	for i := 0; i < len(inclusionProof.Path); i++ {
		concat := make([]uints.U8, 64)
		for j := 0; j < 32; j++ {
			concat[j].Val = api.Add(
				api.Mul(inclusionProof.Path[i], hash[j].Val),
				api.Mul(api.Sub(one, inclusionProof.Path[i]), inclusionProof.Proof[i][j].Val),
			)
			concat[32+j].Val = api.Add(
				api.Mul(inclusionProof.Path[i], inclusionProof.Proof[i][j].Val),
				api.Mul(api.Sub(one, inclusionProof.Path[i]), hash[j].Val),
			)
		}
		hasher, err := sha3.NewLegacyKeccak256(api)
		if err != nil {
			return root, err
		}
		hasher.Write(concat)
		hash = hasher.Sum()
	}
	root = hash
	return root, nil
}

func VerifyInclusionProof(api frontend.API, leafHash []uints.U8, inclusionProof MerkleProof, root circuitData.KeccakHash) error {
	computedRoot, err := ComputeMerkleRoot(api, leafHash, inclusionProof)
	if err != nil {
		return err
	}
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(root[i].Val, computedRoot[i].Val)
	}
	return nil
}

func VerifyNonInclusionProof(api frontend.API, root circuitData.KeccakHash, lowLeaf Leaf, lowLeafProof MerkleProof, newLeafValue circuitData.KeccakHash) error {
	one := frontend.Variable(1)

	lowLeafHash, err := lowLeaf.Hash(api)
	if err != nil {
		return err
	}

	// verify low leaf inclusion
	err = VerifyInclusionProof(api, lowLeafHash, lowLeafProof, root)
	if err != nil {
		return err
	}

	// new value must be greator than low value
	isNewGrThanLow, err := IsAGtThanB(api, newLeafValue, lowLeaf.Value)
	if err != nil {
		return err
	}
	api.AssertIsEqual(isNewGrThanLow, one)

	isLowNextValueNotZero := api.Sub(one, IsZeroValue(api, lowLeaf.NextValue))
	// if low next value != 0: low next value must > new value
	isLowNextGrThanNew, err := IsAGtThanB(api, lowLeaf.NextValue, newLeafValue)
	if err != nil {
		return err
	}
	api.AssertIsEqual(api.Mul(isLowNextGrThanNew, isLowNextValueNotZero), api.Mul(one, isLowNextValueNotZero))

	return nil
}

func InsertLeaf(api frontend.API, oldRoot circuitData.KeccakHash, lowLeaf Leaf, lowLeafProof MerkleProof, newLeaf Leaf, newLeafIdx LeafIdx, newLeafProof MerkleProof) (newRoot circuitData.KeccakHash, err error) {
	newLowLeaf := Leaf{
		Value:     lowLeaf.Value,
		NextValue: newLeaf.Value,
		NextIdx:   newLeafIdx,
	}

	// ** verify non-inclusion of new leaf **
	err = VerifyNonInclusionProof(api, oldRoot, lowLeaf, lowLeafProof, newLeaf.Value)
	if err != nil {
		return newRoot, err
	}

	// ** compute interim root **
	// interim tree -> after updating low leaf and before inserting new leaf
	newLowLeafHash, err := newLowLeaf.Hash(api)
	if err != nil {
		return newRoot, err
	}
	interimRoot, err := ComputeMerkleRoot(api, newLowLeafHash, lowLeafProof)
	if err != nil {
		return newRoot, err
	}

	// ** verify zero-hash-leaf inclusion against interim **
	// this way we can verify that provided `NewLeafProof` is indeed correct
	// zero hash is the state of the new-leaf in the interim tree
	err = VerifyInclusionProof(api, GetZeroLeafHash(), newLeafProof, interimRoot)
	if err != nil {
		return newRoot, err
	}

	// ** constrain NewLeaf.Value ==  LowLeaf.NextValue **
	for i := 0; i < circuitData.N_BYTES_HASH; i++ {
		api.AssertIsEqual(newLeaf.NextValue[i].Val, lowLeaf.NextValue[i].Val)
	}
	// ** constrain NewLeaf.NextIdx ==  LowLeaf.NextIdx **
	for i := 0; i < N_BYTES_LEAF_IDX; i++ {
		api.AssertIsEqual(newLeaf.NextIdx[i].Val, lowLeaf.NextIdx[i].Val)
	}

	// ** compute new leaf hash **
	newLeafHash, err := newLeaf.Hash(api)
	if err != nil {
		return newRoot, err
	}

	// ** compute new root **
	newRoot, err = ComputeMerkleRoot(api, newLeafHash, newLeafProof)
	if err != nil {
		return newRoot, err
	}

	return newRoot, nil
}

func VerifyInsertLeaf(api frontend.API, insertLeafProof InsertLeafProofs, newRoot circuitData.KeccakHash) error {
	newRootComputed, err := InsertLeaf(api, insertLeafProof.OldRoot, insertLeafProof.LowLeaf, insertLeafProof.LowLeafProof, insertLeafProof.NewLeaf, insertLeafProof.NewLeafIdx, insertLeafProof.NewLeafProof)
	if err != nil {
		return err
	}

	// ** constrain computed new root with public input **
	for i := 0; i < circuitData.N_BYTES_HASH; i++ {
		api.AssertIsEqual(newRootComputed[i].Val, newRoot[i].Val)
	}

	return nil
}
