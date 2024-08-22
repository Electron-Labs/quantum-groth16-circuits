package prove

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Electron-Labs/quantum-gnark-circuits/cmd"
	verifier_gnark "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/spf13/cobra"
)

// reductionCmd represents the reduction command
var reductionCmd = &cobra.Command{
	Use:   "reduction",
	Short: "Generate groth16 reduction proofs",
	Run: func(cmd *cobra.Command, args []string) {
		err := proveReduction()
		if err != nil {
			panic(fmt.Errorf("error: %v", err))
		}
	},
}

func init() {
	proveCmd.AddCommand(reductionCmd)
}

func proveReduction() error {
	fmt.Println("setting up reduction artifacts...")
	reductionPk, err := readPk(cmd.OutputDir + "/reduction/reduction_pk.bin")
	if err != nil {
		return err
	}
	reductionCs, err := readCs(cmd.OutputDir + "/reduction/reduction_cs.bin")
	if err != nil {
		return err
	}
	reductionVk, err := readVk(cmd.OutputDir + "/reduction/reduction_vk.json")
	if err != nil {
		return err
	}
	fmt.Println("done")

	reductionProve := time.Now()
	fmt.Println("creating proofs...")
	protocolVks, protocolProofs, protocolPis, err := readProofsVksPis()
	if err != nil {
		return err
	}

	proofs := make([]verifier_gnark.Proof, len(protocolVks))
	pis := make([][]string, len(protocolVks))

	var proveWg sync.WaitGroup
	for i := 0; i < len(protocolVks); i++ {
		proveWg.Add(1)

		go func(i int) {
			defer proveWg.Done()

			pass, msg, proof, pis_ := protocolProofs[i].ProveGroth16CircuitWithCs(
				reductionCs,
				reductionPk,
				&reductionVk,
				protocolVks[i],
				protocolPis[i],
			)
			if !pass {
				panic(fmt.Errorf("failed to prove protocol %d %s", i, msg))
			}
			proofs[i] = verifier_gnark.GnarkProofToBackendProof(*proof.(*groth16_bn254.Proof))
			pis[i] = pis_
		}(i)
	}
	proveWg.Wait()

	fmt.Println("done")
	fmt.Printf("total proving time %.2f seconds\n", time.Since(reductionProve).Seconds())

	fmt.Println("dumping proofs and pis")
	proofBytes, err := json.MarshalIndent(proofs, "", "    ")
	if err != nil {
		return err
	}
	fileProofs, err := os.Create(cmd.OutputDir + "/reduction/reduced_proofs.json")
	if err != nil {
		return err
	}
	defer fileProofs.Close()
	_, err = fileProofs.Write(proofBytes)
	if err != nil {
		return err
	}

	pisBytes, err := json.MarshalIndent(pis, "", "    ")
	if err != nil {
		return err
	}
	filePis, err := os.Create(cmd.OutputDir + "/reduction/reduced_pis.json")
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
