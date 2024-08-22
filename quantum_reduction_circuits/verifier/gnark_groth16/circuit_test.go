package verifier

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
)

func TestVerifier(t *testing.T) {
	testDataDir := "../../../test_data/reduction/gnark_groth16/"

	innerProof, innerVK, innerPublicWitness, err := ReadCircuitData(
		testDataDir+"innerProof.json",
		testDataDir+"innerVK.json",
		testDataDir+"innerPublicWitness.json",
	)
	// innerVK.Precompute()
	if err != nil {
		panic("ReadCircuitData" + err.Error())
	}

	nPubInputs := len(innerPublicWitness) + 1
	nCommitments := len(innerVK.G1.K) - nPubInputs

	pubInputs := GetPublicInputs(&innerVK, innerPublicWitness, nCommitments)
	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](&innerVK)
	if err != nil {
		panic("ValueOfVerifyingKey" + err.Error())
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](&innerProof)
	if err != nil {
		panic("ValueOfProof" + err.Error())
	}
	circuitWitness := getValueOfPublicWitness[sw_bn254.ScalarField](innerPublicWitness)

	outerAssignment := &GnarkVerifier{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVK,
		NumPubInputs: nPubInputs - 1,
		PubInputs:    []frontend.Variable{pubInputs[0], pubInputs[1]},
	}
	*outerAssignment = AppendToNumInputs(*outerAssignment)

	// the witness size depends on the number of public variables. We use the
	// compiled inner circuit to deduce the required size for the outer witness
	// using functions [stdgroth16.PlaceholderWitness] and
	// [stdgroth16.PlaceholderVerifyingKey]
	outerCircuit := &GnarkVerifier{
		InnerWitness: PlaceholderWitness[sw_bn254.ScalarField](MAX_PUB_INPUTS + 1),
		VerifyingKey: PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](MAX_PUB_INPUTS+1, nCommitments),
		Proof:        PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](nCommitments),
		PubInputs:    make([]frontend.Variable, 2),
	}
	assert := test.NewAssert(t)

	assert.ProverSucceeded(outerCircuit, outerAssignment, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}
