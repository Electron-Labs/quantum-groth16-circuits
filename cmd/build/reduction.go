package build

import (
	"fmt"
	"os"

	"github.com/Electron-Labs/quantum-gnark-circuits/cmd"
	verifier_circom "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/circom_groth16"
	"github.com/spf13/cobra"
)

// reductionCmd represents the reduction command
var reductionCmd = &cobra.Command{
	Use:   "reduction",
	Short: "Build cs, pk and vk for groth16 reduction circuit",
	Run: func(cmd *cobra.Command, args []string) {
		err := buildReduction()
		if err != nil {
			panic(fmt.Errorf("error: %v", err))
		}
	},
}

func init() {
	buildCmd.AddCommand(reductionCmd)
}

func buildReduction() error {
	outputDir := cmd.OutputDir + "/reduction/"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		return nil
	}

	pass, msg, csBytes, pkBytes, vkInterface := verifier_circom.BuildGroth16CircuitWithCs()
	if !pass || len(csBytes) == 0 || len(pkBytes) == 0 {
		return fmt.Errorf("build reduction circuit failed: %s", msg)
	}

	return writePkVkCs(
		csBytes, pkBytes,
		vkInterface,
		outputDir+"reduction_cs.bin",
		outputDir+"reduction_pk.bin",
		outputDir+"reduction_vk.json",
	)
}
