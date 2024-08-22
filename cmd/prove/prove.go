package prove

import (
	"encoding/json"
	"fmt"
	"os"

	circuit_data "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	"github.com/Electron-Labs/quantum-gnark-circuits/cmd"
	verifier_circom "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/circom_groth16"
	verifier_gnark "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/spf13/cobra"
)

var proofsFile string
var vksFile string
var pisFile string

// proveCmd represents the prove command
var proveCmd = &cobra.Command{
	Use:   "prove",
	Short: "Generate proofs for specific circuits",
}

func init() {
	cmd.RootCmd.AddCommand(proveCmd)

	proveCmd.PersistentFlags().StringVar(&proofsFile, "proofs", "", "path of file containing all the proofs")
	proveCmd.PersistentFlags().StringVar(&vksFile, "vks", "", "path of file containing all the VKs")
	proveCmd.PersistentFlags().StringVar(&pisFile, "pis", "", "path of file containing all the public inputs")
	proveCmd.MarkPersistentFlagRequired("proofs")
	proveCmd.MarkPersistentFlagRequired("vks")
	proveCmd.MarkPersistentFlagRequired("pis")
}

func readProofsVksPis() (
	[]verifier_circom.VK,
	[]verifier_circom.Proof,
	[]fr_bn254.Vector,
	error,
) {
	bytesVks, err := os.ReadFile(vksFile)
	if err != nil {
		return nil, nil, nil, err
	}
	var protocolVks []verifier_circom.VK
	err = json.Unmarshal(bytesVks, &protocolVks)
	if err != nil {
		return nil, nil, nil, err
	}

	bytesProofs, err := os.ReadFile(proofsFile)
	if err != nil {
		return nil, nil, nil, err
	}
	var proofs []verifier_circom.Proof
	err = json.Unmarshal(bytesProofs, &proofs)
	if err != nil {
		return nil, nil, nil, err
	}

	bytesPis, err := os.ReadFile(pisFile)
	if err != nil {
		return nil, nil, nil, err
	}
	var pis []fr_bn254.Vector
	err = json.Unmarshal(bytesPis, &pis)
	if err != nil {
		return nil, nil, nil, err
	}

	batchSize := len(protocolVks)
	if len(proofs) != batchSize || len(pis) != batchSize {
		return nil, nil, nil, fmt.Errorf("unequal number of vks(%d), proofs(%d), and public inputs(%d)", batchSize, len(proofs), len(pis))
	}

	return protocolVks, proofs, pis, nil
}

func hashVks(vks []verifier_circom.VK) ([]circuit_data.NativeKeccakHash, error) {
	hashes := make([]circuit_data.NativeKeccakHash, len(vks))
	for i, v := range vks {
		protocolVk_, err := v.Groth16VK()
		if err != nil {
			return nil, err
		}
		hashes[i], err = verifier_gnark.GetProtocolVKHash(&protocolVk_, 0)
		if err != nil {
			return nil, err
		}
	}
	return hashes, nil
}

func hashPis(pis []fr_bn254.Vector) ([]circuit_data.NativeKeccakHash, error) {
	hashes := make([]circuit_data.NativeKeccakHash, len(pis))
	var err error
	for i, v := range pis {
		hashes[i], err = verifier_gnark.GetPISHash(v)
		if err != nil {
			return nil, err
		}
	}
	return hashes, nil
}

func readPk(path string) (groth16.ProvingKey, error) {
	// reading pk
	bytesPk, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return circuit_data.GetNewPKFromBytes(bytesPk)
}

func readCs(path string) (constraint.ConstraintSystem, error) {
	// reading cs
	bytesCs, err := os.ReadFile(path)
	if err != nil {
		panic("Error opening file:")
	}
	return circuit_data.GetNewCSFromBytes(bytesCs)
}

func readVk(path string) (groth16_bn254.VerifyingKey, error) {
	// reading vk
	vk := groth16_bn254.VerifyingKey{}
	bytesVK, err := os.ReadFile(path)
	if err != nil {
		return vk, err
	}
	err = json.Unmarshal(bytesVK, &vk)
	if err != nil {
		return vk, err
	}
	err = vk.Precompute()
	if err != nil {
		return vk, err
	}
	return vk, err
}
