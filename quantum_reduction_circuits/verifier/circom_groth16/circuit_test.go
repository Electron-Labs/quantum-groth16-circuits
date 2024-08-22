package verifier

import (
	"testing"

	verifier_gnark "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
)

func getValueOfPublicWitness[FR emulated.FieldParams](publicWitness fr_bn254.Vector) stdgroth16.Witness[FR] {
	var ret stdgroth16.Witness[FR]
	for i := range publicWitness {
		ret.Public = append(ret.Public, emulated.ValueOf[FR](publicWitness[i]))
	}

	return ret
}

func TestVerifier(t *testing.T) {
	testDataDir := "../../../test_data/reduction/circom_groth16/"
	proofPath := testDataDir + "innerProof.json"
	VKPath := testDataDir + "innerVK.json"
	publicWitnessPath := testDataDir + "innerPublicWitness.json"
	innerProof, innerVK, innerPublicWitness, err := ReadCircuitData(proofPath, VKPath, publicWitnessPath)
	if err != nil {
		panic("ReadCircuitData" + err.Error())
	}

	nPubInputs := len(innerPublicWitness) + 1
	nCommitments := 0

	pubInputs := verifier_gnark.GetPublicInputs(&innerVK, innerPublicWitness, nCommitments)
	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](&innerVK)
	if err != nil {
		panic("ValueOfVerifyingKey" + err.Error())
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](&innerProof)
	if err != nil {
		panic("ValueOfProof" + err.Error())
	}
	circuitWitness := getValueOfPublicWitness[sw_bn254.ScalarField](innerPublicWitness)
	outerAssignment := &verifier_gnark.GnarkVerifier{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVK,
		NumPubInputs: nPubInputs - 1,
		PubInputs:    []frontend.Variable{pubInputs[0], pubInputs[1]},
	}
	*outerAssignment = verifier_gnark.AppendToNumInputs(*outerAssignment)

	// the witness size depends on the number of public variables. We use the
	// compiled inner circuit to deduce the required size for the outer witness
	// using functions [stdgroth16.PlaceholderWitness] and
	// [stdgroth16.PlaceholderVerifyingKey]
	outerCircuit := &verifier_gnark.GnarkVerifier{
		InnerWitness: verifier_gnark.PlaceholderWitness[sw_bn254.ScalarField](verifier_gnark.MAX_PUB_INPUTS + 1),
		VerifyingKey: verifier_gnark.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](verifier_gnark.MAX_PUB_INPUTS+1, nCommitments),
		Proof:        verifier_gnark.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](nCommitments),
		PubInputs:    make([]frontend.Variable, 2),
	}
	assert := test.NewAssert(t)

	assert.ProverSucceeded(outerCircuit, outerAssignment, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))

}
