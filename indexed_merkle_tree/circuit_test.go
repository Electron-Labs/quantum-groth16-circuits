package imt

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	circuitData "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

type TestInclusionProof struct {
	InclusionProof InclusionProof
	LeafHash       []frontend.Variable
}

func (circuit *TestInclusionProof) Define(api frontend.API) error {
	leafHash := make([]uints.U8, len(circuit.LeafHash))
	for i := range leafHash {
		leafHash[i].Val = circuit.LeafHash[i]
	}
	return VerifyInclusionProof(api, leafHash, circuit.InclusionProof.MerkleProof, circuit.InclusionProof.Root)
}

func (circuit *NonInclusionProof) Define(api frontend.API) error {
	return VerifyNonInclusionProof(api, circuit.Root, circuit.LowLeaf, circuit.LowLeafProof, circuit.NewLeafValue)
}

func (circuit *InsertLeafProofVerify) Define(api frontend.API) error {
	return VerifyInsertLeaf(api, circuit.Proof, circuit.NewRoot)
}

type IsAGtThanBCircuit struct {
	A          []uints.U8
	B          []uints.U8
	IsAGtThanB frontend.Variable
}

func (circuit *IsAGtThanBCircuit) Define(api frontend.API) error {
	IsAGtThanB, err := IsAGtThanB(api, circuit.A, circuit.B)
	if err != nil {
		panic(err)
	}
	api.AssertIsEqual(IsAGtThanB, circuit.IsAGtThanB)
	return nil
}

type IsAEqToBCircuit struct {
	A        []uints.U8
	B        []uints.U8
	IsAEqToB frontend.Variable
}

func (circuit *IsAEqToBCircuit) Define(api frontend.API) error {
	IsAGtThanB, err := IsAEqToB(api, circuit.A, circuit.B)
	if err != nil {
		panic(err)
	}
	api.AssertIsEqual(IsAGtThanB, circuit.IsAEqToB)
	return nil
}

type GetOldRootCircuit struct {
	TreeDepth                      *big.Int
	BatchSize                      *big.Int
	PrevBatchLastNewLowLeafNextIdx LeafIdx
	OldRootOriginal                circuitData.KeccakHash
	OldRoot                        circuitData.KeccakHash
}

func (circuit *GetOldRootCircuit) Define(api frontend.API) error {
	oldRoot, err := GetOldRoot(api, circuit.TreeDepth, circuit.BatchSize, circuit.PrevBatchLastNewLowLeafNextIdx, circuit.OldRootOriginal)
	if err != nil {
		panic(err)
	}
	for i := 0; i < len(oldRoot); i++ {
		api.AssertIsEqual(oldRoot[i].Val, circuit.OldRoot[i].Val)
	}
	return nil
}

func TestVerifyInclusionProof(t *testing.T) {
	testDataDir := "../test_data/imt/"

	merkleProof := NativeInclusionProof{}
	file, _ := os.ReadFile(testDataDir + "merkle_proof_verify.json")
	_ = json.Unmarshal(file, &merkleProof)

	depth := 10
	var circuit TestInclusionProof
	circuit.InclusionProof.Make(depth)
	circuit.LeafHash = make([]frontend.Variable, circuitData.N_BYTES_HASH)
	circuit.InclusionProof = merkleProof.GetVariable()
	for i := range merkleProof.LeafHash {
		circuit.LeafHash[i] = merkleProof.LeafHash[i]
	}
	assignment := circuit

	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestIsAGtThanB(t *testing.T) {
	type testData struct {
		A          []byte
		B          []byte
		IsAGtThanB uint8
	}

	assert := test.NewAssert(t)

	tests := []testData{
		{
			A:          getValueBytes("6666"),
			B:          getValueBytes("5555"),
			IsAGtThanB: 1,
		},
		{
			A:          getValueBytes("1234"),
			B:          getValueBytes("1234"),
			IsAGtThanB: 0,
		},
		{
			A:          getValueBytes("4611686018427387904"),
			B:          getValueBytes("4611686018427387905"),
			IsAGtThanB: 0,
		},
	}

	for i, t_i := range tests {
		var circuit IsAGtThanBCircuit
		circuit.A = make([]uints.U8, len(tests[i].A))
		circuit.B = make([]uints.U8, len(tests[i].B))

		for i := 0; i < len(circuit.A); i++ {
			circuit.A[i] = uints.U8{Val: t_i.A[i]}
			circuit.B[i] = uints.U8{Val: t_i.B[i]}
			circuit.IsAGtThanB = frontend.Variable(t_i.IsAGtThanB)
		}
		assert.ProverSucceeded(&circuit, &circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	}
}

func TestIsAEqToB(t *testing.T) {
	type testData struct {
		A        []byte
		B        []byte
		IsAEqToB uint8
	}

	assert := test.NewAssert(t)

	tests := []testData{
		{
			A:        getIdxBytes("0"),
			B:        getIdxBytes("0"),
			IsAEqToB: 1,
		},
		{
			A:        getIdxBytes("1020"),
			B:        getIdxBytes("1020"),
			IsAEqToB: 1,
		},
		{
			A:        getIdxBytes("1020"),
			B:        getIdxBytes("1019"),
			IsAEqToB: 0,
		},
	}

	for i, t_i := range tests {
		var circuit IsAEqToBCircuit
		circuit.A = make([]uints.U8, len(tests[i].A))
		circuit.B = make([]uints.U8, len(tests[i].B))

		for i := 0; i < len(circuit.A); i++ {
			circuit.A[i] = uints.U8{Val: t_i.A[i]}
			circuit.B[i] = uints.U8{Val: t_i.B[i]}
			circuit.IsAEqToB = frontend.Variable(t_i.IsAEqToB)
		}
		assert.ProverSucceeded(&circuit, &circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	}
}

func TestNonInclusionVerifier(t *testing.T) {
	testDataDir := "../test_data/imt/"

	nonInclusionProof := NativeNonInclusionProof{}
	file, _ := os.ReadFile(testDataDir + "non_inclusion_proof.json")
	_ = json.Unmarshal(file, &nonInclusionProof)

	depth := 10
	var circuit NonInclusionProof
	circuit.Make(depth)
	nonInclusionProofVariable := nonInclusionProof.GetVariable()
	assignment := nonInclusionProofVariable

	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestIndexedMerkleTreeInsertVerifierSet1(t *testing.T) {
	testDataDir := "../test_data/imt/"

	insertNative := NativeInsertLeafProofVerify{}
	file, _ := os.ReadFile(testDataDir + "insert_leaf_proof_verify_set1.json")
	_ = json.Unmarshal(file, &insertNative)

	depth := 10
	var circuit InsertLeafProofVerify
	circuit.Make(depth)
	insertVariable := insertNative.GetVariable()
	assignment := insertVariable

	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

// starting with all-zero leaves
func TestIndexedMerkleTreeInsertVerifierSet2(t *testing.T) {
	testDataDir := "../test_data/imt/"

	insertNative := NativeInsertLeafProofVerify{}
	file, _ := os.ReadFile(testDataDir + "insert_leaf_proof_verify_set2.json")
	_ = json.Unmarshal(file, &insertNative)

	depth := 10
	var circuit InsertLeafProofVerify
	circuit.Make(depth)
	insertVariable := insertNative.GetVariable()
	assignment := insertVariable

	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestGetOldRoot(t *testing.T) {
	type testData struct {
		TreeDepth                      int64
		BatchSize                      int64
		PrevBatchLastNewLowLeafNextIdx []byte
		OldRootOriginal                circuitData.NativeKeccakHash
		OldRoot                        circuitData.NativeKeccakHash
	}
	assert := test.NewAssert(t)

	tests := []testData{
		{
			TreeDepth:                      10,
			BatchSize:                      20,
			PrevBatchLastNewLowLeafNextIdx: []byte{0, 0, 0, 0, 0, 0, 0, 9},
			OldRootOriginal: []byte{3, 135, 220, 198, 126, 61, 246, 170, 206, 208, 154, 64, 159, 188, 52, 28, 28, 155, 209, 236, 252, 51, 11, 32, 5, 13, 147, 219,
				102, 29, 58, 14},
			OldRoot: []byte{3, 135, 220, 198, 126, 61, 246, 170, 206, 208, 154, 64, 159, 188, 52, 28, 28, 155, 209, 236, 252, 51, 11, 32, 5, 13, 147, 219,
				102, 29, 58, 14},
		},
		{
			TreeDepth:                      10,
			BatchSize:                      20,
			PrevBatchLastNewLowLeafNextIdx: []byte{0, 0, 0, 0, 0, 0, 3, 252},
			OldRootOriginal: []byte{3, 135, 220, 198, 126, 61, 246, 170, 206, 208, 154, 64, 159, 188, 52, 28, 28, 155, 209, 236, 252, 51, 11, 32, 5, 13, 147, 219,
				102, 29, 58, 14},
			OldRoot: []byte{133, 27, 23, 145, 79, 228, 224, 227, 7, 173, 86, 21, 96, 202, 212, 76, 109, 0, 10, 109, 158, 64, 92, 46, 211, 186, 116, 105, 60, 22, 42, 118},
		},
	}

	for _, t_i := range tests {
		var circuit GetOldRootCircuit
		circuit.TreeDepth = big.NewInt(t_i.TreeDepth)
		circuit.BatchSize = big.NewInt(t_i.BatchSize)
		circuit.PrevBatchLastNewLowLeafNextIdx.Make()
		circuit.OldRootOriginal.Make()
		circuit.OldRoot.Make()

		circuit.TreeDepth = big.NewInt(t_i.TreeDepth)
		circuit.BatchSize = big.NewInt(t_i.BatchSize)
		for i := 0; i < len(circuit.PrevBatchLastNewLowLeafNextIdx); i++ {
			circuit.PrevBatchLastNewLowLeafNextIdx[i] = uints.U8{Val: t_i.PrevBatchLastNewLowLeafNextIdx[i]}
		}
		circuit.OldRootOriginal = t_i.OldRootOriginal.GetVariable()
		circuit.OldRoot = t_i.OldRoot.GetVariable()
		assert.ProverSucceeded(&circuit, &circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
	}
}

func TestSerialize(t *testing.T) {
	leaf := NativeLeaf{
		Value:     getValueBytes("10"),
		NextValue: getValueBytes("11"),
		NextIdx:   getIdxBytes("22"),
	}
	ser, err := leaf.Serialize()
	assert.Nil(t, err)

	serActual := make([]byte, 72)
	serActual[31] = 10
	serActual[63] = 11
	serActual[71] = 22

	assert.Equal(t, ser, serActual)
}
