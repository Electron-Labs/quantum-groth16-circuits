package verifier

import (
	"encoding/json"
	"os"

	verifier_gnark "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16backend_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

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

func (proof Proof) GnarkStruct() verifier_gnark.Proof {
	return verifier_gnark.Proof{
		Ar: verifier_gnark.G1{
			X: proof.A[0],
			Y: proof.A[1],
		},
		Krs: verifier_gnark.G1{
			X: proof.C[0],
			Y: proof.C[1],
		},
		Bs: verifier_gnark.G2{
			X: verifier_gnark.G1A{
				A0: proof.B[0][0],
				A1: proof.B[0][1],
			},
			Y: verifier_gnark.G1A{
				A0: proof.B[1][0],
				A1: proof.B[1][1],
			},
		},
		Commitments: []verifier_gnark.G1{},
		CommitmentPok: verifier_gnark.G1{
			X: "0",
			Y: "0",
		},
	}
}

// marshal to groth16backend_bn254.Proof
func (proof Proof) Groth16Proof() (groth16backend_bn254.Proof, error) {
	proofStruct := proof.GnarkStruct()
	bytes, err := json.MarshalIndent(proofStruct, "", " ")
	if err != nil {
		return groth16backend_bn254.Proof{}, err
	}
	groth16Proof := groth16backend_bn254.Proof{}
	err = json.Unmarshal(bytes, &groth16Proof)
	return groth16Proof, err
}

func (vk VK) GnarkStruct() verifier_gnark.VK {
	K := make([]verifier_gnark.G1, len(vk.IC))
	for i := 0; i < len(vk.IC); i++ {
		K[i] = verifier_gnark.G1{
			X: vk.IC[i][0],
			Y: vk.IC[i][1],
		}
	}
	return verifier_gnark.VK{
		G1: verifier_gnark.G1Elms{
			Alpha: verifier_gnark.G1{
				X: vk.Alpha[0],
				Y: vk.Alpha[1],
			},
			// putting dummy data in Beta
			Beta: verifier_gnark.G1{
				X: vk.Alpha[0],
				Y: vk.Alpha[1],
			},
			// // putting dummy data in Delta
			Delta: verifier_gnark.G1{
				X: vk.Alpha[0],
				Y: vk.Alpha[1],
			},
			K: K,
		},
		G2: verifier_gnark.G2Elms{
			Beta: verifier_gnark.G2{
				X: verifier_gnark.G1A{
					A0: vk.Beta[0][0],
					A1: vk.Beta[0][1],
				},
				Y: verifier_gnark.G1A{
					A0: vk.Beta[1][0],
					A1: vk.Beta[1][1],
				},
			},
			Gamma: verifier_gnark.G2{
				X: verifier_gnark.G1A{
					A0: vk.Gamma[0][0],
					A1: vk.Gamma[0][1],
				},
				Y: verifier_gnark.G1A{
					A0: vk.Gamma[1][0],
					A1: vk.Gamma[1][1],
				},
			},
			Delta: verifier_gnark.G2{
				X: verifier_gnark.G1A{
					A0: vk.Delta[0][0],
					A1: vk.Delta[0][1],
				},
				Y: verifier_gnark.G1A{
					A0: vk.Delta[1][0],
					A1: vk.Delta[1][1],
				},
			},
		},
		CommitmentKey: verifier_gnark.CommitmentKey{
			G: verifier_gnark.G2{
				X: verifier_gnark.G1A{
					A0: "0",
					A1: "0",
				},
				Y: verifier_gnark.G1A{
					A0: "0",
					A1: "0",
				},
			},
			GRootSigmaNeg: verifier_gnark.G2{
				X: verifier_gnark.G1A{
					A0: "0",
					A1: "0",
				},
				Y: verifier_gnark.G1A{
					A0: "0",
					A1: "0",
				},
			},
		},
		PublicAndCommitmentCommitted: [][]int{},
	}
}

// marshal to groth16backend_bn254.VerifyingKey
func (vk VK) Groth16VK() (groth16backend_bn254.VerifyingKey, error) {
	vkStruct := vk.GnarkStruct()
	bytes, err := json.MarshalIndent(vkStruct, "", " ")
	if err != nil {
		return groth16backend_bn254.VerifyingKey{}, err
	}
	groth16VK := groth16backend_bn254.VerifyingKey{}
	err = json.Unmarshal(bytes, &groth16VK)
	return groth16VK, err
}
