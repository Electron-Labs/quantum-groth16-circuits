package build

import (
	"fmt"
	"os"

	agg "github.com/Electron-Labs/quantum-gnark-circuits/aggregator"
	"github.com/Electron-Labs/quantum-gnark-circuits/cmd"
	"github.com/spf13/cobra"
)

// imtCmd represents the imt command
var aggCmd = &cobra.Command{
	Use:   "agg",
	Short: "Build cs, pk and vk for agg circuit",
	Run: func(cmd *cobra.Command, args []string) {
		err := buildAgg()
		if err != nil {
			panic(fmt.Errorf("error: %v", err))
		}
	},
}

func init() {
	buildCmd.AddCommand(aggCmd)

	aggCmd.Flags().IntVarP(&batchSize, "batchSize", "b", 8, "number of proofs in a batch")
}

func buildAgg() error {
	outputDir := cmd.OutputDir + "/agg/"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		return nil
	}
	pass, msg, csBytes, pkBytes, vkInterface := agg.BuildAggCircuit(batchSize)
	if !pass || len(csBytes) == 0 || len(pkBytes) == 0 {
		return fmt.Errorf("build agg circuit failed: %s", msg)
	}

	return writePkVkCs(
		csBytes, pkBytes,
		vkInterface,
		outputDir+"agg_cs.bin",
		outputDir+"agg_pk.bin",
		outputDir+"agg_vk.json",
	)
}
