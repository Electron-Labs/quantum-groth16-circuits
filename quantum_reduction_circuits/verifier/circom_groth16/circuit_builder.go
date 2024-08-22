package verifier

import (
	verifier_gnark "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

func BuildGroth16Circuit() (pass bool, msg string, pkBytes []uint8, vk groth16.VerifyingKey) {
	nCommitments := 0
	return verifier_gnark.BuildGroth16Circuit(nCommitments)
}

func (innerProof Proof) ProveGroth16Circuit(pk groth16.ProvingKey, vk groth16.VerifyingKey, innerVK VK, innerPublicWitness fr_bn254.Vector) (pass bool, msg string, proof groth16.Proof, pubInputs []string) {
	proofStruct := innerProof.GnarkStruct()
	vkStruct := innerVK.GnarkStruct()
	return proofStruct.ProveGroth16Circuit(pk, vk, vkStruct, innerPublicWitness)
}

func BuildGroth16CircuitWithCs() (pass bool, msg string, csBytes []uint8, pkBytes []uint8, vk groth16.VerifyingKey) {
	nCommitments := 0
	return verifier_gnark.BuildGroth16CircuitWithCs(nCommitments)
}

func (innerProof Proof) ProveGroth16CircuitWithCs(cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, innerVK VK, innerPublicWitness fr_bn254.Vector) (pass bool, msg string, proof groth16.Proof, pubInputs []string) {
	proofStruct := innerProof.GnarkStruct()
	vkStruct := innerVK.GnarkStruct()
	return proofStruct.ProveGroth16CircuitWithCs(cs, pk, vk, vkStruct, innerPublicWitness)
}
