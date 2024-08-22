package verifier

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

func getValueOfPublicWitness[FR emulated.FieldParams](publicWitness fr_bn254.Vector) stdgroth16.Witness[FR] {
	var ret stdgroth16.Witness[FR]
	for i := range publicWitness {
		ret.Public = append(ret.Public, emulated.ValueOf[FR](publicWitness[i]))
	}
	return ret
}

func PlaceholderWitness[FR emulated.FieldParams](nPubInputs int) stdgroth16.Witness[FR] {
	return stdgroth16.Witness[FR]{
		Public: make([]emulated.Element[FR], nPubInputs-1),
	}
}

func PlaceholderVerifyingKey[G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](nPubInputs int, nCommitments int) stdgroth16.VerifyingKey[G1El, G2El, GtEl] {
	if nCommitments > 1 {
		panic("unsupported nCommitments")
	}

	publicAndCommitmentCommitted := make([][]int, nCommitments)
	for i := 0; i < len(publicAndCommitmentCommitted); i++ {
		publicAndCommitmentCommitted[i] = []int{}
	}

	return stdgroth16.VerifyingKey[G1El, G2El, GtEl]{
		G1: struct{ K []G1El }{
			K: make([]G1El, nPubInputs+nCommitments),
		},
		PublicAndCommitmentCommitted: publicAndCommitmentCommitted,
	}
}

func PlaceholderProof[G1El algebra.G1ElementT, G2El algebra.G2ElementT](nCommitments int) stdgroth16.Proof[G1El, G2El] {
	proof := stdgroth16.Proof[G1El, G2El]{}
	proof.Commitments = make([]pedersen.Commitment[G1El], nCommitments)
	return proof
}

func BuildGroth16Circuit(nCommitments int) (pass bool, msg string, pkBytes []uint8, vk groth16.VerifyingKey) {
	outerCircuit := &GnarkVerifier{
		InnerWitness: PlaceholderWitness[sw_bn254.ScalarField](MAX_PUB_INPUTS + 1),
		VerifyingKey: PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](MAX_PUB_INPUTS+1, nCommitments),
		Proof:        PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](nCommitments),
		PubInputs:    make([]frontend.Variable, 2),
	}

	// compile the outer circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	if err != nil {
		return false, "compile failed::" + err.Error(), pkBytes, vk
	}
	// create Groth16 setup. NB! UNSAFE
	pk, vk, err := groth16.Setup(ccs) // UNSAFE! Use MPC
	if err != nil {
		return false, "groth16.Setup failed::" + err.Error(), pkBytes, vk
	}
	var pkRaw bytes.Buffer
	_, err = pk.WriteRawTo(&pkRaw)
	if err != nil {
		return false, "write pk failed::" + err.Error(), pkBytes, vk
	}
	return true, "success", pkRaw.Bytes(), vk
}

// returned pubInputs are in big-endian
func (innerProof Proof) ProveGroth16Circuit(pk groth16.ProvingKey, vk groth16.VerifyingKey, innerVK VK, innerPublicWitness fr_bn254.Vector) (pass bool, msg string, proof groth16.Proof, pubInputs []string) {
	nPubInputs := len(innerPublicWitness)
	groth16VK, err := innerVK.Groth16VK()
	if err != nil {
		return false, "innerVK.Groth16VK failed::" + err.Error(), proof, pubInputs
	}
	innerGroth16Proof, err := innerProof.Groth16Proof()
	if err != nil {
		return false, "innerProof.Groth16Proof failed::" + err.Error(), proof, pubInputs
	}
	nCommitments := len(innerProof.Commitments)

	pubInputsBig := GetPublicInputs(&groth16VK, innerPublicWitness, nCommitments)
	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](&groth16VK)
	if err != nil {
		return false, "ValueOfVerifyingKey failed::" + err.Error(), proof, pubInputs
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](&innerGroth16Proof)
	if err != nil {
		return false, "ValueOfProof failed::" + err.Error(), proof, pubInputs
	}
	circuitWitness := getValueOfPublicWitness[sw_bn254.ScalarField](innerPublicWitness)
	outerAssignment := &GnarkVerifier{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVK,
		NumPubInputs: nPubInputs,
		PubInputs:    []frontend.Variable{pubInputsBig[0], pubInputsBig[1]},
	}
	*outerAssignment = AppendToNumInputs(*outerAssignment)

	outerCircuit := &GnarkVerifier{
		InnerWitness: PlaceholderWitness[sw_bn254.ScalarField](MAX_PUB_INPUTS + 1),
		VerifyingKey: PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](MAX_PUB_INPUTS+1, nCommitments),
		Proof:        PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](nCommitments),
		PubInputs:    make([]frontend.Variable, 2),
	}

	// compile the outer circuit
	fmt.Println("compiling...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	if err != nil {
		return false, "compile failed::" + err.Error(), proof, pubInputs
	}
	fmt.Println("compiling done")

	// create prover witness from the assignment
	fmt.Println("new witness...")
	secretWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		return false, "frontend.NewWitnessfailed::" + err.Error(), proof, pubInputs
	}
	fmt.Println("new witness done")
	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		return false, "secretWitness.Public failed::" + err.Error(), proof, pubInputs
	}

	// construct publicWitness as vec of string
	publicWitnessFrVector := publicWitness.Vector().(fr_bn254.Vector)
	pubInputs = make([]string, len(publicWitnessFrVector))
	for i := range publicWitnessFrVector {
		pubInputs[i] = publicWitnessFrVector[i].String()
	}

	// construct the groth16 proof of verifying Groth16 proof in-circuit
	proof, err = groth16.Prove(ccs, pk, secretWitness, stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		return false, "groth16.Prove failed::" + err.Error(), proof, pubInputs
	}

	// verify the Groth16 proof
	err = groth16.Verify(proof, vk, publicWitness, stdgroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		return false, "circuit verification failed::" + err.Error(), proof, pubInputs
	}
	return true, "success", proof, pubInputs
}

func BuildGroth16CircuitWithCs(nCommitments int) (pass bool, msg string, csBytes []uint8, pkBytes []uint8, vk groth16.VerifyingKey) {
	outerCircuit := &GnarkVerifier{
		InnerWitness: PlaceholderWitness[sw_bn254.ScalarField](MAX_PUB_INPUTS + 1),
		VerifyingKey: PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](MAX_PUB_INPUTS+1, nCommitments),
		Proof:        PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](nCommitments),
		PubInputs:    make([]frontend.Variable, 2),
	}

	// compile the outer circuit
	fmt.Println("compiling...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	if err != nil {
		return false, "compile failed::" + err.Error(), csBytes, pkBytes, vk
	}
	fmt.Println("compiling done")
	var cs bytes.Buffer
	_, err = ccs.WriteTo(&cs)
	if err != nil {
		return false, "write cs failed::" + err.Error(), csBytes, pkBytes, vk
	}
	csBytes = cs.Bytes()

	// create Groth16 setup. NB! UNSAFE
	pk, vk, err := groth16.Setup(ccs) // UNSAFE! Use MPC
	if err != nil {
		return false, "groth16.Setup failed::" + err.Error(), csBytes, pkBytes, vk
	}
	var pkRaw bytes.Buffer
	_, err = pk.WriteRawTo(&pkRaw)
	if err != nil {
		return false, "write pk failed::" + err.Error(), csBytes, pkBytes, vk
	}
	return true, "success", csBytes, pkRaw.Bytes(), vk
}

// returned pubInputs are in big-endian
func (innerProof Proof) ProveGroth16CircuitWithCs(cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, innerVK VK, innerPublicWitness fr_bn254.Vector) (pass bool, msg string, proof groth16.Proof, pubInputs []string) {
	nPubInputs := len(innerPublicWitness)
	groth16VK, err := innerVK.Groth16VK()
	if err != nil {
		return false, "innerVK.Groth16VK failed::" + err.Error(), proof, pubInputs
	}
	innerGroth16Proof, err := innerProof.Groth16Proof()
	if err != nil {
		return false, "innerProof.Groth16Proof failed::" + err.Error(), proof, pubInputs
	}
	nCommitments := len(innerProof.Commitments)

	pubInputsBig := GetPublicInputs(&groth16VK, innerPublicWitness, nCommitments)
	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](&groth16VK)
	if err != nil {
		return false, "ValueOfVerifyingKey failed::" + err.Error(), proof, pubInputs
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](&innerGroth16Proof)
	if err != nil {
		return false, "ValueOfProof failed::" + err.Error(), proof, pubInputs
	}
	circuitWitness := getValueOfPublicWitness[sw_bn254.ScalarField](innerPublicWitness)
	outerAssignment := &GnarkVerifier{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVK,
		NumPubInputs: nPubInputs,
		PubInputs:    []frontend.Variable{pubInputsBig[0], pubInputsBig[1]},
	}
	*outerAssignment = AppendToNumInputs(*outerAssignment)

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		return false, "frontend.NewWitnessfailed::" + err.Error(), proof, pubInputs
	}
	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		return false, "secretWitness.Public failed::" + err.Error(), proof, pubInputs
	}

	// construct publicWitness as vec of string
	publicWitnessFrVector := publicWitness.Vector().(fr_bn254.Vector)
	pubInputs = make([]string, len(publicWitnessFrVector))
	for i := range publicWitnessFrVector {
		pubInputs[i] = publicWitnessFrVector[i].String()
	}

	// construct the groth16 proof of verifying Groth16 proof in-circuit
	proof, err = groth16.Prove(cs, pk, secretWitness, stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		return false, "groth16.Prove failed::" + err.Error(), proof, pubInputs
	}

	// verify the Groth16 proof
	err = groth16.Verify(proof, vk, publicWitness, stdgroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	if err != nil {
		return false, "circuit verification failed::" + err.Error(), proof, pubInputs
	}
	return true, "success", proof, pubInputs
}
