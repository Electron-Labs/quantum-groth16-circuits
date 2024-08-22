package aggregator

import (
	"fmt"

	circuitData "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type GnarkVerifier struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	InnerWitness stdgroth16.Witness[sw_bn254.ScalarField]
}

func (circuit *GnarkVerifier) Make(nPubInputs int, nCommitments int) {
	circuit.InnerWitness = PlaceholderWitness[sw_bn254.ScalarField](nPubInputs)
	circuit.VerifyingKey = PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](nPubInputs, nCommitments)
	circuit.Proof = PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](nCommitments)
}

func (circuit *Aggregator) Make(nReduction int, nPubInputs int, nCommitments int) {
	circuit.ReductionCircuits = make([]GnarkVerifier, nReduction)
	circuit.ProtocolVKHashes = make([]circuitData.KeccakHash, nReduction)
	circuit.ProtocolPisHashes = make([]circuitData.KeccakHash, nReduction)
	for i := 0; i < nReduction; i++ {
		circuit.ReductionCircuits[i].Make(nPubInputs, nCommitments)
		circuit.ProtocolVKHashes[i].Make()
		circuit.ProtocolPisHashes[i].Make()
	}
	circuit.ImtReductionCircuit.Make(nPubInputs, nCommitments)
	circuit.OldRoot.Make()
	circuit.NewRoot.Make()

	circuit.PubInputs = make([]frontend.Variable, 2)
}

func getValueOfPublicWitness[FR emulated.FieldParams](publicWitness fr_bn254.Vector) stdgroth16.Witness[FR] {
	var ret stdgroth16.Witness[FR]
	for i := range publicWitness {
		ret.Public = append(ret.Public, emulated.ValueOf[FR](publicWitness[i]))
	}
	return ret
}

func (u *NativeGnarkVerifier) GetVariable() (GnarkVerifier, error) {
	var t GnarkVerifier

	circuitWitness := getValueOfPublicWitness[sw_bn254.ScalarField](u.PubInputs)

	reductionGroth16Proof, err := u.Proof.Groth16Proof()
	if err != nil {
		return t, err
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](&reductionGroth16Proof)
	if err != nil {
		return t, err
	}

	groth16VK, err := u.VK.Groth16VK()
	if err != nil {
		return t, err
	}
	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](&groth16VK)
	if err != nil {
		return t, err
	}

	t.Proof = circuitProof
	t.VerifyingKey = circuitVK
	t.InnerWitness = circuitWitness
	return t, nil
}

func (u *NativeAggregator) GetVariable() (t Aggregator, err error) {
	t.ReductionCircuits = make([]GnarkVerifier, len(u.ReductionCircuitDataVec))
	t.ProtocolVKHashes = make([]circuitData.KeccakHash, len(u.ProtocolVKHashes))
	t.ProtocolPisHashes = make([]circuitData.KeccakHash, len(u.ProtocolPisHashes))
	for i, reductionCicuitData := range u.ReductionCircuitDataVec {
		reductionCircuit, err := reductionCicuitData.GetVariable()
		if err != nil {
			return t, fmt.Errorf("reductionCicuitData.GetVariable()::%w", err)
		}
		t.ReductionCircuits[i] = reductionCircuit

		t.ProtocolVKHashes[i] = u.ProtocolVKHashes[i].GetVariable()
		t.ProtocolPisHashes[i] = u.ProtocolPisHashes[i].GetVariable()
	}
	imtReductionCircuitData, err := u.ImtReductionCircuitData.GetVariable()
	if err != nil {
		return t, fmt.Errorf("u.ImtReductionCircuitData.GetVariable()::%w", err)
	}
	t.ImtReductionCircuit = imtReductionCircuitData

	t.OldRoot = u.OldRoot.GetVariable()
	t.NewRoot = u.NewRoot.GetVariable()

	t.PubInputs = []frontend.Variable{u.PubInputs[0], u.PubInputs[1]}
	return t, nil
}
