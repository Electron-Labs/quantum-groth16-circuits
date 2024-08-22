package imt

import (
	"fmt"
	"math/big"

	circuitData "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"

	verifier_gnark "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type Imt struct {
	VKHashes                     []circuitData.KeccakHash
	ProtocolPisHashes            []circuitData.KeccakHash
	InsertLeafProofs             []InsertLeafIntermediateProof
	PrevBatchLastNewLowLeaf      Leaf
	PrevBatchLastNewLowLeafProof MerkleProof
	OldRoot                      circuitData.KeccakHash
	PubInputs                    []frontend.Variable `gnark:",public"`
}

func (circuit Imt) Define(api frontend.API) error {
	batchSize := len(circuit.InsertLeafProofs)
	if batchSize != len(circuit.ProtocolPisHashes) {
		panic("length of batchSize and ProtocolPisHashes must be equal")
	}
	if batchSize != len(circuit.VKHashes) {
		panic("length of batchSize and VKHashes must be equal")
	}
	treeDepthBig := big.NewInt(int64(len(circuit.InsertLeafProofs[0].LowLeafProof.Proof)))
	batchSizeBig := big.NewInt(int64(batchSize))

	// reset oldRoot when tree is full
	oldRoot, err := GetOldRoot(api, treeDepthBig, batchSizeBig, circuit.PrevBatchLastNewLowLeaf.NextIdx, circuit.OldRoot)
	if err != nil {
		return fmt.Errorf("GetOldRoot::%w", err)
	}

	// to constrain inter batch continuity
	prevLeafIdx, err := getPrevBatchLastLeafIdx(api, circuit.PrevBatchLastNewLowLeaf, oldRoot, treeDepthBig)
	if err != nil {
		return fmt.Errorf("constrainInterBatchContinuity::%w", err)
	}

	// ** verify prevBatchLastNewLowLeaf inclusion proof in old tree **
	err = verifyPrevBatchLastNewLowLeafInclusion(api, circuit.PrevBatchLastNewLowLeaf, circuit.PrevBatchLastNewLowLeafProof, circuit.OldRoot)
	if err != nil {
		return fmt.Errorf("verifyPrevBatchLastNewLowLeafInclusion.Hash(api)::%w", err)
	}

	lastRoot := oldRoot
	for i, p := range circuit.InsertLeafProofs {
		// constraint intra batch continuity
		constrainIndexContinuity(api, prevLeafIdx, circuit.InsertLeafProofs[i].NewLeafIdx)
		prevLeafIdx = circuit.InsertLeafProofs[i].NewLeafIdx

		// verify leaf insertion
		newRoot_, err := InsertLeaf(api, lastRoot, p.LowLeaf, p.LowLeafProof, p.NewLeaf, p.NewLeafIdx, p.NewLeafProof)
		lastRoot = newRoot_
		if err != nil {
			return err
		}

		// constrain leaf value
		VerifyLeafValue(api, circuit.VKHashes[i], circuit.ProtocolPisHashes[i], p.NewLeaf.Value)
	}

	// verify public inputs
	pubInputsSerializedComputed, err := ComputePubInputs(api, circuit.VKHashes, circuit.ProtocolPisHashes, circuit.OldRoot, lastRoot)
	if err != nil {
		return fmt.Errorf("ComputePubInputs failed::%w", err)
	}
	verifier_gnark.VerifyPublicInputs(api, pubInputsSerializedComputed, circuit.PubInputs)

	return nil
}

func getPrevBatchLastLeafIdx(api frontend.API, prevBatchLastNewLowLeaf Leaf, oldRoot circuitData.KeccakHash, treeDepth *big.Int) (LeafIdx, error) {
	zero := frontend.Variable(0)
	one := frontend.Variable(1)
	prevLeafIdx := LeafIdx{}

	isInitTree, err := IsAEqToB(api, oldRoot, GetEmptyTreeRoot(treeDepth))
	if err != nil {
		return prevLeafIdx, fmt.Errorf("IsAEqToB(api, oldRoot, GetEmptyTreeRoot())::%w", err)
	}
	isNotInitTree := api.Sub(one, isInitTree)
	prevBatchLastNewLowLeafNextIdx := prevBatchLastNewLowLeaf.NextIdx

	// **
	// if oldRoot == zero leaves root:
	// 	- prevLeafIdx = 0
	// else
	// 	- prevLeafIdx = prevBatchLastNewLowLeafNextIdx
	// **
	prevLeafIdx.Make()
	prevLeafIdx[N_BYTES_LEAF_IDX-2].Val = api.Add(api.Mul(zero, isInitTree), api.Mul(prevBatchLastNewLowLeafNextIdx[N_BYTES_LEAF_IDX-2].Val, isNotInitTree))
	prevLeafIdx[N_BYTES_LEAF_IDX-1].Val = api.Add(api.Mul(zero, isInitTree), api.Mul(prevBatchLastNewLowLeafNextIdx[N_BYTES_LEAF_IDX-1].Val, isNotInitTree))

	return prevLeafIdx, nil
}

func verifyPrevBatchLastNewLowLeafInclusion(api frontend.API, prevBatchLastNewLowLeaf Leaf, prevBatchLastNewLowLeafProof MerkleProof, oldRootOriginal circuitData.KeccakHash) error {
	// if last batch doesn't exist: set prevBatchLastNewLowLeaf in private inputs as the first, reserved leaf
	prevBatchLastNewLowLeafHash, err := prevBatchLastNewLowLeaf.Hash(api)
	if err != nil {
		return fmt.Errorf("prevBatchLastNewLowLeafHash.Hash(api)::%w", err)
	}
	err = VerifyInclusionProof(api, prevBatchLastNewLowLeafHash, prevBatchLastNewLowLeafProof, oldRootOriginal)
	if err != nil {
		return fmt.Errorf("VerifyInclusionProof(api, prevBatchLastNewLowLeafHash, prevBatchLastNewLowLeafProof, oldRoot)::%w", err)
	}
	return nil
}

func constrainIndexContinuity(api frontend.API, prevIdx LeafIdx, curIdx LeafIdx) {
	one := frontend.Variable(1)

	// curIdx == prevIdx + 1
	prevIdxNum := BeBytesToNum(api, prevIdx[N_BYTES_LEAF_IDX-2:]) // slice beacuse length 2 is sufficient for tree of depth 10
	curIdxNum := BeBytesToNum(api, curIdx[N_BYTES_LEAF_IDX-2:])
	prevIdxNumPlusOne := api.Add(prevIdxNum, one)
	api.AssertIsEqual(prevIdxNumPlusOne, curIdxNum)
}

// returns: empty tree root if the tree is full, else the original one
func GetOldRoot(api frontend.API, treeDepth *big.Int, batchSize *big.Int, prevBatchLastNewLowLeafNextIdx LeafIdx, oldRoot circuitData.KeccakHash) (circuitData.KeccakHash, error) {
	revisedOldRoot := circuitData.KeccakHash{}
	revisedOldRoot.Make()

	base := big.NewInt(2)
	nLeaves := big.Int{}
	nLeaves.Exp(base, treeDepth, nil)

	mod := big.NewInt(0)
	mod.Mod(&nLeaves, batchSize)
	if mod.Cmp(big.NewInt(0)) == 0 {
		mod = batchSize
	}
	prevBatchLastNewLowLeafNextIdxWhenFullTree := big.Int{}
	prevBatchLastNewLowLeafNextIdxWhenFullTree.Sub(&nLeaves, mod)

	// any other value is not possible due to continuity constraint
	prevBatchLastNewLowLeafNextIdxWhenFullTreeBeBytes := NumToFrontendBeBytes(prevBatchLastNewLowLeafNextIdxWhenFullTree, N_BYTES_LEAF_IDX)

	isTreeFull, err := IsAEqToB(api, prevBatchLastNewLowLeafNextIdxWhenFullTreeBeBytes, prevBatchLastNewLowLeafNextIdx)
	if err != nil {
		return revisedOldRoot, fmt.Errorf("isTreeFull::IsAGtThanB::%w", err)
	}

	emptyTreeRoot := GetEmptyTreeRoot(treeDepth)
	isTreeNotFull := api.Sub(frontend.Variable(1), isTreeFull)
	for i := range revisedOldRoot {
		revisedOldRoot[i].Val = api.Add(api.Mul(emptyTreeRoot[i].Val, isTreeFull), api.Mul(oldRoot[i].Val, isTreeNotFull))
	}

	return revisedOldRoot, nil
}

// leafValue = Keccak(vkHash || protocolPisHash)
func VerifyLeafValue(api frontend.API, vkHash circuitData.KeccakHash, protocolPisHash circuitData.KeccakHash, leafValue circuitData.KeccakHash) error {
	input := vkHash
	input = append(input, protocolPisHash...)
	computedLeafValue, err := circuitData.GetKeccak256Hash(api, input)
	if err != nil {
		return fmt.Errorf("circuitData.GetKeccak256Hash(api, input)::%w", err)
	}
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(computedLeafValue[i].Val, leafValue[i].Val)
	}

	return nil
}

// returns serialized pubInputs
// pubInputs = Keccak( ((vkHashes[0] || protocolPisHashes[0]) || (vkHashes[1] || protocolPisHashes[1]) … n times …) || oldRoot || newRoot)
func ComputePubInputs(api frontend.API, vkHashes []circuitData.KeccakHash, protocolPisHashes []circuitData.KeccakHash, oldRoot circuitData.KeccakHash, newRoot circuitData.KeccakHash) (circuitData.KeccakHash, error) {
	serializedInput := make([]uints.U8, len(vkHashes)*64+32+32)
	for i := range vkHashes {
		for j := 0; j < 32; j++ {
			serializedInput[i*64+j] = vkHashes[i][j]
			serializedInput[i*64+j+32] = protocolPisHashes[i][j]
		}
	}

	for i := 0; i < 32; i++ {
		serializedInput[len(vkHashes)*64+i] = oldRoot[i]
		serializedInput[len(vkHashes)*64+32+i] = newRoot[i]
	}
	pubInputsSerialized, err := circuitData.GetKeccak256Hash(api, serializedInput)
	if err != nil {
		return pubInputsSerialized, err
	}

	return pubInputsSerialized, nil
}
