package verifier

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16backend_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/uints"

	"golang.org/x/crypto/sha3"
)

func Neg(elm bn254.G2Affine) *bn254.G2Affine {
	negElm := bn254.G2Affine{}
	negElm.Neg(&elm)
	return &negElm
}

func KeccakHashFunc(data []byte) ([]byte, error) {
	keccakFuncc := sha3.NewLegacyKeccak256()
	keccakFuncc.Write(data)
	return keccakFuncc.Sum(nil), nil
}

func ReverseInPlaceUints(array *uints.U64) {
	for i, j := 0, len(*array)-1; i < j; i, j = i+1, j-1 {
		(*array)[i], (*array)[j] = (*array)[j], (*array)[i]
	}
}

func ReverseInPlace[T frontend.Variable](array *[]T) {
	for i, j := 0, len(*array)-1; i < j; i, j = i+1, j-1 {
		(*array)[i], (*array)[j] = (*array)[j], (*array)[i]
	}
}

func Reverse[T byte | frontend.Variable](array []T) []T {
	reversed := make([]T, len(array))
	for i, j := 0, len(array)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = array[j], array[i]
	}
	return reversed
}

func GetReductionVKHash(vk_ groth16.VerifyingKey) ([]byte, error) {
	vk := vk_.(*groth16backend_bn254.VerifyingKey)

	var sha3Input []byte
	e, _ := bn254.Pair([]bn254.G1Affine{vk.G1.Alpha}, []bn254.G2Affine{vk.G2.Beta})

	// E
	sha3Input = append(sha3Input, e.Marshal()...)

	for i := 0; i < len(vk.G1.K); i++ {
		sha3Input = append(sha3Input, vk.G1.K[i].Marshal()...)
	}

	// G2
	sha3Input = append(sha3Input, Neg(vk.G2.Gamma).Marshal()...)
	sha3Input = append(sha3Input, Neg(vk.G2.Delta).Marshal()...)

	// CommitmentKey
	sha3Input = append(sha3Input, vk.CommitmentKey.G.Marshal()...)
	sha3Input = append(sha3Input, vk.CommitmentKey.GRootSigmaNeg.Marshal()...)

	vkHash, err := KeccakHashFunc(sha3Input)
	if err != nil {
		return nil, err
	}
	return vkHash, nil
}

func GetProtocolVKHash(vk_ groth16.VerifyingKey, numCom int) ([]byte, error) {
	vk := vk_.(*groth16backend_bn254.VerifyingKey)

	var sha3Input []byte
	e, _ := bn254.Pair([]bn254.G1Affine{vk.G1.Alpha}, []bn254.G2Affine{vk.G2.Beta})

	// E
	sha3Input = append(sha3Input, e.Marshal()...)

	// G1
	lenK := len(vk.G1.K) - numCom

	for i := 0; i < lenK; i++ {
		sha3Input = append(sha3Input, vk.G1.K[i].Marshal()...)
	}
	for i := lenK - 1; i < MAX_PUB_INPUTS; i++ {
		sha3Input = append(sha3Input, make([]byte, 64)...)
	}
	for i := len(vk.G1.K) - numCom; i < len(vk.G1.K); i++ {
		sha3Input = append(sha3Input, vk.G1.K[i].Marshal()...)
	}

	// G2
	sha3Input = append(sha3Input, Neg(vk.G2.Gamma).Marshal()...)
	sha3Input = append(sha3Input, Neg(vk.G2.Delta).Marshal()...)

	// CommitmentKey
	sha3Input = append(sha3Input, vk.CommitmentKey.G.Marshal()...)
	sha3Input = append(sha3Input, vk.CommitmentKey.GRootSigmaNeg.Marshal()...)

	vkHash, err := KeccakHashFunc(sha3Input)
	if err != nil {
		return nil, err
	}
	return vkHash, nil
}

func GetPISHash(publicWitness_ fr_bn254.Vector) ([]byte, error) {
	pisBytes := []byte{}
	for i := 0; i < len(publicWitness_); i++ {
		pubBytesBe := publicWitness_[i].Bytes()
		pisBytes = append(pisBytes, pubBytesBe[:]...)
	}
	for i := len(publicWitness_); i < MAX_PUB_INPUTS; i++ {
		pisBytes = append(pisBytes, make([]byte, 32)...)
	}

	return KeccakHashFunc(pisBytes)
}

func GetPublicInputs(vk_ groth16.VerifyingKey, publicWitness_ fr_bn254.Vector, numCom int) [2]*big.Int {
	vkHash, err := GetProtocolVKHash(vk_, numCom)
	if err != nil {
		panic("GetProtocolVKHash")
	}

	// *** Pis Hash ***
	pisHash, err := GetPISHash(publicWitness_)
	if err != nil {
		panic("KeccakHashFunc(pisBytes)")
	}

	sha3Input := []byte{}
	sha3Input = append(sha3Input, vkHash...)
	sha3Input = append(sha3Input, pisHash...)

	pubInputsSerialized, err := KeccakHashFunc(sha3Input)
	if err != nil {
		panic("pubInputsSerialized, err := KeccakHashFunc(sha3Input)")
	}

	pub1 := new(big.Int)
	pub1.SetBytes(pubInputsSerialized[:16])

	pub2 := new(big.Int)
	pub2.SetBytes(pubInputsSerialized[16:])

	return [2]*big.Int{pub1, pub2}
}

func ReadCircuitData(proofPath string, vkPath string, publicWitnessPath string) (groth16backend_bn254.Proof, groth16backend_bn254.VerifyingKey, fr_bn254.Vector, error) {
	var file []byte
	proof := groth16backend_bn254.Proof{}
	vk := groth16backend_bn254.VerifyingKey{}
	publicWitness := fr_bn254.Vector{}

	// ** construct proof **
	inputProof := Proof{}
	file, err := os.ReadFile(proofPath)
	if err != nil {
		return proof, vk, publicWitness, err
	}
	err = json.Unmarshal(file, &inputProof)
	if err != nil {
		return proof, vk, publicWitness, err
	}
	proof, err = inputProof.Groth16Proof()
	if err != nil {
		return proof, vk, publicWitness, err
	}

	// ** construct vk **
	inputVK := VK{}
	file, err = os.ReadFile(vkPath)
	if err != nil {
		return proof, vk, publicWitness, err
	}
	err = json.Unmarshal(file, &inputVK)
	if err != nil {
		return proof, vk, publicWitness, err
	}
	vk, err = inputVK.Groth16VK()
	if err != nil {
		return proof, vk, publicWitness, err
	}

	// ** construct public witness **
	file, err = os.ReadFile(publicWitnessPath)
	if err != nil {
		return proof, vk, publicWitness, err
	}
	err = json.Unmarshal(file, &publicWitness)
	if err != nil {
		return proof, vk, publicWitness, err
	}

	return proof, vk, publicWitness, nil
}

func ReadCircuitData2(proofPath string, vkPath string, publicWitnessPath string) (groth16.Proof, groth16.VerifyingKey, fr_bn254.Vector, error) {
	var file []byte
	proof := groth16.NewProof(ecc.BN254)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	publicWitness := fr_bn254.Vector{}

	proofFile, _ := os.Open(proofPath)
	proof.ReadFrom(proofFile)

	vkFile, _ := os.Open(vkPath)
	vk.ReadFrom(vkFile)

	// ** construct public witness **
	file, err := os.ReadFile(publicWitnessPath)
	if err != nil {
		return proof, vk, publicWitness, err
	}
	err = json.Unmarshal(file, &publicWitness)
	if err != nil {
		return proof, vk, publicWitness, err
	}

	return proof, vk, publicWitness, nil
}

func AppendToNumInputs(assignment GnarkVerifier) GnarkVerifier {
	zero := sw_bn254.NewScalar(fr_bn254.NewElement(0))
	pointAtInf := sw_bn254.NewG1Affine(bn254.G1Affine{
		X: fp.NewElement(0),
		Y: fp.NewElement(0),
	})
	hasCommitment := len(assignment.Proof.Commitments) > 0
	initialLen := len(assignment.VerifyingKey.G1.K)
	for len(assignment.InnerWitness.Public) < MAX_PUB_INPUTS {
		assignment.InnerWitness.Public = append(assignment.InnerWitness.Public, zero)
		assignment.VerifyingKey.G1.K = append(assignment.VerifyingKey.G1.K, pointAtInf)
	}
	if hasCommitment {
		assignment.VerifyingKey.G1.K[len(assignment.VerifyingKey.G1.K)-1] = assignment.VerifyingKey.G1.K[initialLen-1]
		assignment.VerifyingKey.G1.K[initialLen-1] = pointAtInf
	}
	return assignment
}

// marshal to groth16backend_bn254.Proof
func (proof Proof) Groth16Proof() (groth16backend_bn254.Proof, error) {
	bytes, err := json.Marshal(proof)
	if err != nil {
		return groth16backend_bn254.Proof{}, err
	}
	groth16Proof := groth16backend_bn254.Proof{}
	err = json.Unmarshal(bytes, &groth16Proof)
	return groth16Proof, err
}

// marshal to Proof
func GnarkProofToBackendProof(proof groth16backend_bn254.Proof) Proof {
	gnarkProof := Proof{}

	gnarkProof.Ar.X = proof.Ar.X.String()
	gnarkProof.Ar.Y = proof.Ar.Y.String()

	gnarkProof.Krs.X = proof.Krs.X.String()
	gnarkProof.Krs.Y = proof.Krs.Y.String()

	gnarkProof.Bs.X.A0 = proof.Bs.X.A0.String()
	gnarkProof.Bs.X.A1 = proof.Bs.X.A1.String()
	gnarkProof.Bs.Y.A0 = proof.Bs.Y.A0.String()
	gnarkProof.Bs.Y.A1 = proof.Bs.Y.A1.String()

	gnarkProof.Commitments = make([]G1, len(proof.Commitments))
	for i := range proof.Commitments {
		gnarkProof.Commitments[i].X = proof.Commitments[i].X.String()
		gnarkProof.Commitments[i].Y = proof.Commitments[i].Y.String()
	}

	gnarkProof.CommitmentPok.X = proof.CommitmentPok.X.String()
	gnarkProof.CommitmentPok.Y = proof.CommitmentPok.Y.String()
	return gnarkProof
}

// marshal to groth16backend_bn254.VerifyingKey
func (vk VK) Groth16VK() (groth16backend_bn254.VerifyingKey, error) {
	bytes, err := json.Marshal(vk)
	if err != nil {
		return groth16backend_bn254.VerifyingKey{}, err
	}
	groth16VK := groth16backend_bn254.VerifyingKey{}
	err = json.Unmarshal(bytes, &groth16VK)
	if err != nil {
		return groth16backend_bn254.VerifyingKey{}, fmt.Errorf("json.Unmarshal(bytes, &groth16VK)::%w", err)
	}
	err = groth16VK.Precompute()
	if err != nil {
		return groth16backend_bn254.VerifyingKey{}, fmt.Errorf("groth16VK.Precompute()::%w", err)
	}
	return groth16VK, err
}

func SaveInnerCircuitData(testDataDir string, innerVK groth16.VerifyingKey, innerWitness witness.Witness, innerProof groth16.Proof) {
	// fileCCs, _ := json.MarshalIndent(innerccs, "", " ")
	// _ = os.WriteFile(testDataDir+"innerccs.json", fileCCs, 0644)

	fileVK, _ := json.MarshalIndent(innerVK, "", " ")
	_ = os.WriteFile(testDataDir+"innerVK.json", fileVK, 0644)

	innerPublicWitness, _ := innerWitness.Public()
	innerPublicWitnessVecFrVector := innerPublicWitness.Vector().(fr_bn254.Vector)
	innerPublicWitnessVecStr := make([]string, len(innerPublicWitnessVecFrVector))
	for i := 0; i < len(innerPublicWitnessVecStr); i++ {
		innerPublicWitnessVecStr[i] = innerPublicWitnessVecFrVector[i].String()
	}
	file, _ := json.MarshalIndent(innerPublicWitnessVecStr, "", " ")
	os.WriteFile(testDataDir+"innerPublicWitness.json", file, 0644)

	fileProof, _ := json.MarshalIndent(innerProof, "", " ")
	_ = os.WriteFile(testDataDir+"innerProof.json", fileProof, 0644)
}

func SaveInnerCircuitData2(testDataDir string, innerVK groth16.VerifyingKey, innerWitness witness.Witness, innerProof groth16.Proof) {
	fileVK, _ := os.Create(testDataDir + "innerVK.json")
	innerVK.WriteTo(fileVK)

	innerPublicWitness, _ := innerWitness.Public()
	innerPublicWitnessVecFrVector := innerPublicWitness.Vector().(fr_bn254.Vector)
	innerPublicWitnessVecStr := make([]string, len(innerPublicWitnessVecFrVector))
	for i := 0; i < len(innerPublicWitnessVecStr); i++ {
		innerPublicWitnessVecStr[i] = innerPublicWitnessVecFrVector[i].String()
	}
	file, _ := json.MarshalIndent(innerPublicWitnessVecStr, "", " ")
	os.WriteFile(testDataDir+"innerPublicWitness.json", file, 0644)

	fileProof, _ := os.Create(testDataDir + "innerProof.json")
	innerProof.WriteTo(fileProof)
}
