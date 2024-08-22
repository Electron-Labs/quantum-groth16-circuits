package aggregator

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	verifier_gnark "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"

	groth16backend_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

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

func BuildAggCircuit(nReduction int) (pass bool, msg string, csBytes []uint8, pkBytes []uint8, vk groth16.VerifyingKey) {
	nReductionPubInputs := 2
	nReductionPubInputs += 1
	nReductionCommitments := 1

	var aggregatorCircuit Aggregator
	aggregatorCircuit.Make(nReduction, nReductionPubInputs, nReductionCommitments)

	// compile the aggregation circuit
	fmt.Println("compiling...")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &aggregatorCircuit)
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
	var pkBuffer bytes.Buffer
	_, err = pk.WriteTo(&pkBuffer)
	if err != nil {
		return false, "write pk failed::" + err.Error(), csBytes, pkBytes, vk
	}
	pkBytes = pkBuffer.Bytes()

	return true, "success", csBytes, pkBytes, vk
}

func ProveAggCircuit(cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, nativeAggregator NativeAggregator) (pass bool, msg string, proof groth16.Proof, pubInputs []string) {
	aggregatorVariable, err := nativeAggregator.GetVariable()
	if err != nil {
		return false, "nativeImtAggregator.GetVariable::" + err.Error(), proof, pubInputs
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(&aggregatorVariable, ecc.BN254.ScalarField())
	if err != nil {
		return false, "frontend.NewWitnessfailed::" + err.Error(), proof, pubInputs
	}

	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		return false, "secretWitness.Public failed::" + err.Error(), proof, pubInputs
	}

	// construct publicWitness as vec of string
	publicWitnessFrVector := publicWitness.Vector().(fr.Vector)
	pubInputs = make([]string, len(publicWitnessFrVector))
	for i := range publicWitnessFrVector {
		pubInputs[i] = publicWitnessFrVector[i].String()
	}

	// construct the groth16 proof of verifying Groth16 proof in-circuit
	proof, err = groth16.Prove(cs, pk, secretWitness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		return false, "groth16.Prove failed::" + err.Error(), proof, pubInputs
	}

	// verify the Groth16 proof
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
	if err != nil {
		return false, "circuit verification failed::" + err.Error(), proof, pubInputs
	}

	return true, "success", proof, pubInputs
}

func VerifyReductionCircuits(reductionCircuitDataVec []NativeGnarkVerifier) error {
	fmt.Println("verifying reduction circuits natively...")
	for _, reductionCircuit := range reductionCircuitDataVec {
		reductionProof_, err := reductionCircuit.Proof.Groth16Proof()
		if err != nil {
			return fmt.Errorf("reductionCircuit.Proof.Groth16Proof()::%w", err)
		}
		reductionVK_, err := reductionCircuit.VK.Groth16VK()
		if err != nil {
			return fmt.Errorf("reductionCircuit.VK.Groth16VK()::%w", err)
		}
		assignment_ := verifier_gnark.GnarkVerifier{
			PubInputs: []frontend.Variable{reductionCircuit.PubInputs[0].String(), reductionCircuit.PubInputs[1].String()},
		}
		reductionSecretWitness_, err := frontend.NewWitness(&assignment_, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if err != nil {
			return fmt.Errorf("frontend.NewWitness::%w", err)
		}
		reductionPublicWitness_, err := reductionSecretWitness_.Public()
		if err != nil {
			return fmt.Errorf("reductionCircuit.VK.Groth16VK()::%w", err)
		}
		err = groth16.Verify(&reductionProof_, &reductionVK_, reductionPublicWitness_, stdgroth16.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
		if err != nil {
			return fmt.Errorf("groth16.Verify::%w", err)
		}
	}
	fmt.Println("verifying reduction circuits natively done")

	return nil
}

type ProveResult struct {
	Pass      bool
	Msg       string
	Proof     verifier_gnark.Proof
	PubInputs []string
}

func Prove(nativeAggregator NativeAggregator, cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) ProveResult {
	fmt.Println("received aggregation Prove")
	proof := verifier_gnark.Proof{}
	var pubInputs []string

	err := nativeAggregator.Check()
	if err != nil {
		return ProveResult{
			Pass:      false,
			Msg:       "nativeAggregator.Check() failed::" + err.Error(),
			Proof:     proof,
			PubInputs: pubInputs,
		}
	}

	// verify reduction circuits natively
	err = VerifyReductionCircuits(nativeAggregator.ReductionCircuitDataVec)
	if err != nil {
		return ProveResult{
			Pass:      false,
			Msg:       "VerifyReductionCircuits(reductionCircuitDataVec) failed::" + err.Error(),
			Proof:     proof,
			PubInputs: pubInputs,
		}
	}

	pass, msg, proofAbstract, pubInputs := ProveAggCircuit(cs, pk, vk, nativeAggregator)
	if !pass {
		return ProveResult{
			Pass:      pass,
			Msg:       msg,
			Proof:     proof,
			PubInputs: pubInputs,
		}
	}

	proofPtr, ok := proofAbstract.(*groth16backend_bn254.Proof)
	if !ok {
		return ProveResult{
			Pass:      false,
			Msg:       "proofAbstract.(*groth16backend_bn254.Proof) failed",
			Proof:     proof,
			PubInputs: pubInputs,
		}
	}
	proof = verifier_gnark.GnarkProofToBackendProof(*proofPtr)

	fmt.Println("pass", pass)
	fmt.Println("msg", msg)
	fmt.Println("proving done!")

	return ProveResult{
		Pass:      pass,
		Msg:       msg,
		Proof:     proof,
		PubInputs: pubInputs,
	}
}
