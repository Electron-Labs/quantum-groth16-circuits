package prove

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	circuit_data "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	"github.com/Electron-Labs/quantum-gnark-circuits/cmd"
	imt "github.com/Electron-Labs/quantum-gnark-circuits/indexed_merkle_tree"
	verifier_gnark "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/spf13/cobra"
)

// imtCmd represents the imt command
var imtCmd = &cobra.Command{
	Use:   "imt",
	Short: "Generate imt proof",
	Run: func(cmd *cobra.Command, args []string) {
		err := proveImt()
		if err != nil {
			panic(fmt.Errorf("error: %v", err))
		}
	},
}

func init() {
	proveCmd.AddCommand(imtCmd)
}

func proveImt() error {
	fmt.Println("setting up imt artifacts...")
	imtPk, err := readPk(cmd.OutputDir + "/imt/imt_pk.bin")
	if err != nil {
		return err
	}
	imtCs, err := readCs(cmd.OutputDir + "/imt/imt_cs.bin")
	if err != nil {
		return err
	}
	imtVk, err := readVk(cmd.OutputDir + "/imt/imt_vk.json")
	if err != nil {
		return err
	}
	fmt.Println("done")

	imtProve := time.Now()
	fmt.Println("creating proofs...")
	protocolVks, _, protocolPis, err := readProofsVksPis()
	if err != nil {
		return err
	}
	protocolVkHashes, err := hashVks(protocolVks)
	if err != nil {
		return err
	}
	pisHashes, err := hashPis(protocolPis)
	if err != nil {
		return err
	}

	reductionVk := groth16_bn254.VerifyingKey{}
	bytesVK, err := os.ReadFile(cmd.OutputDir + "/reduction/reduction_vk.json")
	if err != nil {
		return err
	}
	err = json.Unmarshal(bytesVK, &reductionVk)
	if err != nil {
		return err
	}

	reductionVkHash, err := verifier_gnark.GetReductionVKHash(&reductionVk)
	if err != nil {
		return err
	}
	imtAssignment, _, err := getNativeImt(protocolVkHashes, pisHashes, reductionVkHash)
	if err != nil {
		return err
	}

	pass, msg, proof, pis := imt.ProveImtCircuit(imtCs, imtPk, &imtVk, *imtAssignment)
	if !pass {
		return fmt.Errorf("failed to prove imt %s", msg)
	}
	proof_ := verifier_gnark.GnarkProofToBackendProof(*proof.(*groth16_bn254.Proof))

	fmt.Println("done")
	fmt.Printf("total proving time %.2f seconds\n", time.Since(imtProve).Seconds())

	fmt.Println("dumping proofs and pis")
	proofBytes, err := json.MarshalIndent(proof_, "", "    ")
	if err != nil {
		return err
	}
	fileProof, err := os.Create(cmd.OutputDir + "/imt/imt_proof.json")
	if err != nil {
		return err
	}
	defer fileProof.Close()
	_, err = fileProof.Write(proofBytes)
	if err != nil {
		return err
	}

	pisBytes, err := json.MarshalIndent(pis, "", "    ")
	if err != nil {
		return err
	}
	filePis, err := os.Create(cmd.OutputDir + "/imt/imt_pis.json")
	if err != nil {
		return err
	}
	defer filePis.Close()
	_, err = filePis.Write(pisBytes)
	if err != nil {
		return err
	}

	return nil
}

func getNativeImt(
	protocolVkHashes, pisHashes []circuit_data.NativeKeccakHash,
	reductionVkHash circuit_data.NativeKeccakHash,
) (*imt.NativeImt, circuit_data.NativeKeccakHash, error) {
	tree, err := imt.NewIMT(9)
	if err != nil {
		return nil, nil, err
	}
	oldRoot := tree.Tree.Root

	combinedVkHashes := make([]circuit_data.NativeKeccakHash, len(protocolVkHashes))
	leaves := make([]circuit_data.NativeKeccakHash, len(protocolVkHashes))
	for i := range protocolVkHashes {
		combinedVkHashes[i], err = verifier_gnark.KeccakHashFunc(append(protocolVkHashes[i], reductionVkHash...))
		if err != nil {
			return nil, nil, err
		}
		leaves[i], err = verifier_gnark.KeccakHashFunc(append(combinedVkHashes[i], pisHashes[i]...))
		if err != nil {
			return nil, nil, err
		}
	}
	prevLowLeaf, prevLowProof, intermediateProofs, err := tree.InsertLeaves(len(leaves), leaves)
	if err != nil {
		return nil, nil, err
	}

	publicInputs := imt.GetIMTPublicInputs(combinedVkHashes, pisHashes, oldRoot, tree.Tree.Root)

	nativeImt := imt.NativeImt{
		VKHashes:                     combinedVkHashes,
		ProtocolPisHashes:            pisHashes,
		InsertLeafProofs:             intermediateProofs,
		OldRoot:                      oldRoot,
		PubInputs:                    publicInputs[:],
		PrevBatchLastNewLowLeaf:      *prevLowLeaf,
		PrevBatchLastNewLowLeafProof: *prevLowProof,
	}
	return &nativeImt, tree.Tree.Root, nil
}
