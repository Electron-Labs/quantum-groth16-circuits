package imt

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"strconv"

	circuitData "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	mt "github.com/txaty/go-merkletree"
	"golang.org/x/crypto/sha3"
)

// first define a data structure with Serialize method to be used as data block
type testData struct {
	data []byte
}

type IMT struct {
	Leaves []NativeLeaf
	Tree   *mt.MerkleTree
}

func NewIMT(depth int) (*IMT, error) {
	numLeaves := 1 << depth
	leaves := getZeroLeaves(numLeaves)

	tree, err := treeFromLeaves(leaves)
	if err != nil {
		return nil, err
	}

	imt := IMT{
		Leaves: leaves,
		Tree:   tree,
	}

	return &imt, nil
}

func (imt *IMT) FirstZeroLeafIdx() int {
	for i := 1; i < len(imt.Leaves); i++ {
		if IsZero(imt.Leaves[i].Value) {
			return i
		}
	}
	return len(imt.Leaves)
}

func (imt *IMT) insertLeaf(leafVal circuitData.NativeKeccakHash, firstZeroIdx int) (*NativeInsertLeafIntermediateProof, error) {
	value := big.NewInt(0).SetBytes(leafVal)
	lowLeafValue := big.NewInt(0)
	lowLeafIdx := 0
	newLeafIdx := firstZeroIdx

	for i := 1; i < firstZeroIdx; i++ {
		leaf := imt.Leaves[i]
		leafValue := big.NewInt(0).SetBytes(leaf.Value)
		if leafValue.Cmp(lowLeafValue) == 1 && leafValue.Cmp(value) == -1 {
			lowLeafValue = leafValue
			lowLeafIdx = i
		}
	}

	lowLeaf := imt.Leaves[lowLeafIdx]
	lowLeafProof_, err := imt.Tree.Proof(lowLeaf)
	if err != nil {
		return nil, err
	}
	// in case of empty tree, all leaves are zero leaf, and the library provides the proof corresponding to the last leaf
	// which messes up the IMT verification algorithm. Hence update the proof corresponding to the first leaf.
	// only the path changes, the sibling remain the same
	if firstZeroIdx == 1 {
		lowLeafProof_.Path = uint32(len(imt.Tree.Leaves)) - 1
	}

	lowLeafProof := getNativeInclusionProof(lowLeafProof_)

	newLeaf := NativeLeaf{
		Value:     leafVal,
		NextValue: lowLeaf.NextValue,
		NextIdx:   lowLeaf.NextIdx,
	}

	updatedLowLeaf := NativeLeaf{
		Value:     lowLeaf.Value,
		NextValue: newLeaf.Value,
		NextIdx:   binary.BigEndian.AppendUint64(make([]byte, 0), uint64(newLeafIdx)),
	}

	imt.Leaves[lowLeafIdx] = updatedLowLeaf
	imt.Leaves[newLeafIdx] = newLeaf

	newTree, err := treeFromLeaves(imt.Leaves)
	if err != nil {
		return nil, err
	}
	imt.Tree = newTree

	newLeafProof_, err := imt.Tree.Proof(newLeaf)
	if err != nil {
		return nil, err
	}
	newLeafProof := getNativeInclusionProof(newLeafProof_)

	return &NativeInsertLeafIntermediateProof{
		LowLeaf:      lowLeaf,
		LowLeafProof: lowLeafProof,
		NewLeaf:      newLeaf,
		NewLeafIdx:   updatedLowLeaf.NextIdx,
		NewLeafProof: newLeafProof,
	}, nil
}

// TODO: insertion in case when numFilledLeaves + batchSize > totalLeaves
func (imt *IMT) InsertLeaves(batchSize int, leafVals []circuitData.NativeKeccakHash) (
	*NativeLeaf,
	*NativeMerkleProof,
	[]NativeInsertLeafIntermediateProof,
	error,
) {
	firstZeroIdx := imt.FirstZeroLeafIdx()
	var prevLowLeafPtr *NativeLeaf
	if firstZeroIdx == 1 {
		prevLowLeafPtr = &imt.Leaves[0]
	} else {
		nextIdx := binary.BigEndian.AppendUint64(make([]byte, 0), uint64(firstZeroIdx-1))
		for i := 0; i < firstZeroIdx; i++ {
			if slices.Equal(imt.Leaves[i].NextIdx, nextIdx) {
				prevLowLeafPtr = &imt.Leaves[i]
				break
			}
		}
	}
	if prevLowLeafPtr == nil {
		panic("missing prevLowLeaf")
	}
	prevLowLeaf := *prevLowLeafPtr
	prevLowLeafProof, err := imt.Tree.Proof(prevLowLeaf)
	if err != nil {
		return nil, nil, nil, err
	}
	// in case of empty tree, all leaves are zero leaf, and the library provides the proof corresponding to the last leaf
	// which messes up the IMT verification algorithm. Hence update the proof corresponding to the first leaf.
	// only the path changes, the sibling remain the same
	if firstZeroIdx == 1 {
		prevLowLeafProof.Path = uint32(len(imt.Tree.Leaves)) - 1
	}

	nativeProof := getNativeInclusionProof(prevLowLeafProof)

	// TODO: add batchSize check

	insertLeafProofs := make([]NativeInsertLeafIntermediateProof, len(leafVals))
	for i, v := range leafVals {
		proof, err := imt.insertLeaf(v, firstZeroIdx)
		if err != nil {
			return nil, nil, nil, err
		}
		insertLeafProofs[i] = *proof
		firstZeroIdx += 1
	}

	return &prevLowLeaf, &nativeProof, insertLeafProofs, nil
}

func IsZero(value circuitData.NativeKeccakHash) bool {
	for _, v := range value {
		if v != 0 {
			return false
		}
	}
	return true
}

func treeFromLeaves(leaves []NativeLeaf) (*mt.MerkleTree, error) {
	config := mt.Config{
		HashFunc: KeccakHashFunc,
		Mode:     mt.ModeTreeBuild,
	}
	blocks := make([]mt.DataBlock, len(leaves))
	for i := range blocks {
		blocks[i] = leaves[i]
	}
	return mt.New(&config, blocks)
}

func KeccakHashFunc(data []byte) ([]byte, error) {
	keccakFuncc := sha3.NewLegacyKeccak256()
	keccakFuncc.Write(data)
	return keccakFuncc.Sum(nil), nil
}

func (t *testData) Serialize() ([]byte, error) {
	return t.data, nil
}

func GetIMTPublicInputs(vkHashes, pisHashes []circuitData.NativeKeccakHash, oldRoot, newRoot circuitData.NativeKeccakHash) [2]string {
	if len(vkHashes) != len(pisHashes) {
		panic("len(vkHashes) != len(pisHashes)")
	}
	var sha3Input []byte
	for i := range vkHashes {
		sha3Input = append(sha3Input, vkHashes[i]...)
		sha3Input = append(sha3Input, pisHashes[i]...)
	}
	sha3Input = append(sha3Input, oldRoot...)
	sha3Input = append(sha3Input, newRoot...)
	pubInputsSerialized, err := KeccakHashFunc(sha3Input)
	if err != nil {
		panic("KeccakHashFn()")
	}

	pub1 := big.NewInt(0).SetBytes(pubInputsSerialized[:16])
	pub2 := big.NewInt(0).SetBytes(pubInputsSerialized[16:])

	return [2]string{pub1.String(), pub2.String()}
}

// generate dummy data blocks
func generateRandBlocks(size int) (blocks []mt.DataBlock) {
	for i := 0; i < size; i++ {
		block := &testData{
			data: make([]byte, 100),
		}
		_, err := rand.Read(block.data)
		handleError(err)
		blocks = append(blocks, block)
	}
	return
}

func getNativeInclusionProof(mtProof *mt.Proof) NativeMerkleProof {
	siblings := make([]circuitData.NativeKeccakHash, len(mtProof.Siblings))
	path := make([]uint8, len(mtProof.Siblings))
	pathBin := mtProof.Path
	for i := 0; i < len(mtProof.Siblings); i++ {
		siblings[i] = mtProof.Siblings[i]
		path[i] = uint8(pathBin & 1)
		pathBin >>= 1
	}
	return NativeMerkleProof{
		Proof: siblings,
		Path:  path,
	}
}

func GenerateMerkleProofNative(testDataDir string) {
	config := &mt.Config{
		HashFunc: KeccakHashFunc,
	}

	blocks := generateRandBlocks(1024)
	// the first argument is config, if it is nil, then default config is adopted
	tree, err := mt.New(config, blocks)
	handleError(err)

	// get proofs
	proofs := tree.Proofs
	idx := 3
	mtProof := proofs[idx]
	leaf := tree.Leaves[idx]
	inclusionProof := getNativeInclusionProof(mtProof)

	data := NativeInclusionProof{
		LeafHash:    leaf,
		MerkleProof: inclusionProof,
		Root:        tree.Root,
	}

	file, _ := json.MarshalIndent(data, "", " ")
	_ = os.WriteFile(testDataDir+"merkle_proof_verify.json", file, 0644)
}

func Reverse(array []byte) []byte {
	for i, j := 0, len(array)-1; i < j; i, j = i+1, j-1 {
		array[i], array[j] = array[j], array[i]
	}
	return array
}

func GetZeroLeaf() NativeLeaf {
	return NativeLeaf{
		Value:     getValueBytes("0"),
		NextValue: getValueBytes("0"),
		NextIdx:   getIdxBytes("0"),
	}
}

// returns big-endian
func getValueBytes(value string) []byte {
	valueBytes := make([]byte, circuitData.N_BYTES_HASH)
	bigValue := big.Int{}
	bigValue.SetString(value, 10)
	bigValue.FillBytes(valueBytes)
	return valueBytes
}

// returns big-endian
func getIdxBytes(value string) []byte {
	idxBytes := make([]byte, N_BYTES_LEAF_IDX)
	bigValue := big.Int{}
	bigValue.SetString(value, 10)
	bigValue.FillBytes(idxBytes)
	return idxBytes
}

func getZeroLeaves(nLeaves int) (leaves []NativeLeaf) {
	leaves = make([]NativeLeaf, nLeaves)
	for i := 0; i < nLeaves; i++ {
		leaves[i] = GetZeroLeaf()
	}

	return leaves
}

// total 3 leaves
func getLeavesSet1() (leaves []NativeLeaf) {
	nLeaves := 1024
	leaves = make([]NativeLeaf, nLeaves)
	for i := 0; i < nLeaves; i++ {
		leaves[i] = GetZeroLeaf()
	}

	leaves[1] = NativeLeaf{
		Value:     getValueBytes("5555"),
		NextValue: getValueBytes("7777"),
		NextIdx:   getIdxBytes("2"),
	}
	leaves[2] = NativeLeaf{
		Value:     getValueBytes("7777"),
		NextValue: getValueBytes("0"),
		NextIdx:   getIdxBytes("0"),
	}

	return leaves
}

func getLeavesSet2() (leaves []NativeLeaf) {
	nLeaves := 1024
	leaves = make([]NativeLeaf, nLeaves)
	for i := 0; i < nLeaves; i++ {
		leaves[i] = GetZeroLeaf()
	}
	return leaves
}

// Full Tree
func getLeavesSet3(batchSize int) (leaves []NativeLeaf) {
	if batchSize != 4 {
		panic("batchSize must be 4")
	}

	nLeaves := 1024
	leaves = make([]NativeLeaf, nLeaves)
	for i := 0; i < nLeaves; i++ {
		leaves[i] = GetZeroLeaf()
	}

	curLeafValue := 5555
	nextLeafValue := curLeafValue + 1
	mod := nLeaves % batchSize
	if mod == 0 {
		mod = batchSize
	}
	for i := 1; i <= nLeaves-mod; i++ {
		leaves[i] = NativeLeaf{
			Value:     getValueBytes(strconv.Itoa(curLeafValue)),
			NextValue: getValueBytes(strconv.Itoa(nextLeafValue)),
			NextIdx:   getIdxBytes(strconv.Itoa(i + 1)),
		}
		curLeafValue = nextLeafValue
		nextLeafValue += 1
	}
	return leaves
}

func GenerateNonInclusionNative(testDataDir string) {
	config := &mt.Config{
		HashFunc: KeccakHashFunc,
	}

	leaves := getLeavesSet1()
	blocks := make([]mt.DataBlock, len(leaves))
	for i := 0; i < len(leaves); i++ {
		blocks[i] = leaves[i]
	}
	tree, err := mt.New(config, blocks)
	handleError(err)

	lowLeafIdxU64 := uint64(0)
	lowLeafProof := getNativeInclusionProof(tree.Proofs[lowLeafIdxU64])

	newLeafNextValue := getValueBytes("6666")

	nativeNonInclusionData := NativeNonInclusionProof{
		Root:         tree.Root,
		LowLeaf:      leaves[lowLeafIdxU64],
		LowLeafProof: lowLeafProof,
		NewLeafValue: newLeafNextValue,
	}

	file, _ := json.MarshalIndent(nativeNonInclusionData, "", " ")
	_ = os.WriteFile(testDataDir+"non_inclusion_proof.json", file, 0644)
}

func GenerateIndexedMerkleTreeInsertSet1(testDataDir string) {
	config := &mt.Config{
		HashFunc: KeccakHashFunc,
	}

	leaves := getLeavesSet1()
	blocksOld := make([]mt.DataBlock, len(leaves))
	for i := 0; i < len(leaves); i++ {
		blocksOld[i] = leaves[i]
	}
	treeOld, err := mt.New(config, blocksOld)
	handleError(err)

	lowLeafIdxU64 := uint64(0)
	lowLeafProof := getNativeInclusionProof(treeOld.Proofs[lowLeafIdxU64])
	lowLeaf := leaves[lowLeafIdxU64]

	newLeaf := NativeLeaf{
		Value:     getValueBytes("6666"),
		NextValue: getValueBytes("7777"),
		NextIdx:   getIdxBytes("1"),
	}
	newLeafIdxU64 := uint64(2)
	newLeafIdx := getIdxBytes(strconv.FormatUint(newLeafIdxU64, 10))
	// update low leaf
	leaves[0].NextValue = newLeaf.Value
	leaves[0].NextIdx = newLeafIdx
	// insert new leaf
	leaves[newLeafIdxU64] = newLeaf
	// new blocks
	blocksNew := make([]mt.DataBlock, len(leaves))
	for i := 0; i < len(leaves); i++ {
		blocksNew[i] = leaves[i]
	}
	// new tree
	treeNew, err := mt.New(config, blocksNew)
	handleError(err)

	newLeafProof := getNativeInclusionProof(treeNew.Proofs[newLeafIdxU64])

	insertLeafProof := NativeInsertLeafProof{
		OldRoot:      treeOld.Root,
		LowLeaf:      lowLeaf,
		LowLeafProof: lowLeafProof,
		NewLeaf:      newLeaf,
		NewLeafIdx:   newLeafIdx,
		NewLeafProof: newLeafProof,
	}

	insertLeafProofverify := NativeInsertLeafProofVerify{
		Proof:   insertLeafProof,
		NewRoot: treeNew.Root,
	}

	file, _ := json.MarshalIndent(insertLeafProofverify, "", " ")
	_ = os.WriteFile(testDataDir+"insert_leaf_proof_verify_set1.json", file, 0644)
}

func GenerateIndexedMerkleTreeInsertSet2(testDataDir string) {
	config := &mt.Config{
		HashFunc: KeccakHashFunc,
	}

	leaves := getLeavesSet2()
	blocksOld := make([]mt.DataBlock, len(leaves))
	for i := 0; i < len(leaves); i++ {
		blocksOld[i] = leaves[i]
	}
	treeOld, err := mt.New(config, blocksOld)
	handleError(err)

	lowLeafIdxU64 := uint64(0)
	lowLeafProof := getNativeInclusionProof(treeOld.Proofs[lowLeafIdxU64])
	lowLeaf := leaves[lowLeafIdxU64]

	newLeaf := NativeLeaf{
		Value:     getValueBytes("1111"),
		NextValue: getValueBytes("0"),
		NextIdx:   getIdxBytes("0"),
	}
	newLeafIdxU64 := uint64(1)
	newLeafIdx := getIdxBytes(strconv.FormatUint(newLeafIdxU64, 10))
	// update low leaf
	leaves[0].NextValue = newLeaf.Value
	leaves[0].NextIdx = newLeafIdx
	// insert new leaf
	leaves[newLeafIdxU64] = newLeaf
	// new blocks
	blocksNew := make([]mt.DataBlock, len(leaves))
	for i := 0; i < len(leaves); i++ {
		blocksNew[i] = leaves[i]
	}
	// new tree
	treeNew, err := mt.New(config, blocksNew)
	handleError(err)

	newLeafProof := getNativeInclusionProof(treeNew.Proofs[newLeafIdxU64])

	insertLeafProof := NativeInsertLeafProof{
		OldRoot:      treeOld.Root,
		LowLeaf:      lowLeaf,
		LowLeafProof: lowLeafProof,
		NewLeaf:      newLeaf,
		NewLeafIdx:   newLeafIdx,
		NewLeafProof: newLeafProof,
	}

	insertLeafProofverify := NativeInsertLeafProofVerify{
		Proof:   insertLeafProof,
		NewRoot: treeNew.Root,
	}

	file, _ := json.MarshalIndent(insertLeafProofverify, "", " ")
	_ = os.WriteFile(testDataDir+"insert_leaf_proof_verify_set2.json", file, 0644)
}

func GenerateNewLeavesSet1(testDataDir string) {
	curLeaves := getLeavesSet1()

	file, _ := json.MarshalIndent(curLeaves, "", " ")
	_ = os.WriteFile(testDataDir+"new_leaves_set1.json", file, 0644)
}

func GenerateNewLeavesSet2(testDataDir string) {
	nLeaves := 1024
	curLeaves := getZeroLeaves(nLeaves)

	file, _ := json.MarshalIndent(curLeaves, "", " ")
	_ = os.WriteFile(testDataDir+"new_leaves_set2.json", file, 0644)
}

func GenerateNewLeavesSet3(testDataDir string, batchSize int) {
	curLeaves := getLeavesSet3(batchSize)

	file, _ := json.MarshalIndent(curLeaves, "", " ")
	_ = os.WriteFile(testDataDir+"new_leaves_set3.json", file, 0644)
}

func handleError(err error) {
	if err != nil {
		panic(err)
	}
}
