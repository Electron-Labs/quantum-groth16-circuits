package imt

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
)

func BuildImtCircuit(nReduction int, treeDepth int) (pass bool, msg string, csBytes []uint8, pkBytes []uint8, vk groth16.VerifyingKey) {
	nReductionPubInputs := 2
	nReductionPubInputs += 1
	nReductionCommitments := 1

	var aggregatorCircuit Imt
	aggregatorCircuit.Make(nReduction, nReductionPubInputs, nReductionCommitments, treeDepth)

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

type ProveResult struct {
	Pass      bool
	Msg       string
	Proof     verifier_gnark.Proof
	PubInputs []string
}

func ProveImtCircuit(cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, nativeImt NativeImt) (pass bool, msg string, proof groth16.Proof, pubInputs []string) {
	imtVariable := nativeImt.GetVariable()

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(&imtVariable, ecc.BN254.ScalarField())
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

func Prove(nativeImt NativeImt, cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) ProveResult {
	proof := verifier_gnark.Proof{}
	var pubInputs []string

	err := nativeImt.Check()
	if err != nil {
		return ProveResult{
			Pass:      false,
			Msg:       "nativeImt.Check() failed::" + err.Error(),
			Proof:     proof,
			PubInputs: pubInputs,
		}
	}

	pass, msg, proofAbstract, pubInputs := ProveImtCircuit(cs, pk, vk, nativeImt)
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

	return ProveResult{
		Pass:      pass,
		Msg:       msg,
		Proof:     proof,
		PubInputs: pubInputs,
	}
}
