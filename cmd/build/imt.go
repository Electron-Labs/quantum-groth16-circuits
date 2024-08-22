package build

import (
	"fmt"
	"os"

	"github.com/Electron-Labs/quantum-gnark-circuits/cmd"
	imt "github.com/Electron-Labs/quantum-gnark-circuits/indexed_merkle_tree"
	"github.com/spf13/cobra"
)

var batchSize int
var treeDepth int

// imtCmd represents the imt command
var imtCmd = &cobra.Command{
	Use:   "imt",
	Short: "Build cs, pk and vk for imt circuit",
	Run: func(cmd *cobra.Command, args []string) {
		err := buildImt()
		if err != nil {
			panic(fmt.Errorf("error: %v", err))
		}
	},
}

func init() {
	buildCmd.AddCommand(imtCmd)

	imtCmd.Flags().IntVarP(&batchSize, "batchSize", "b", 8, "number of leaves inserted in a batch")
	imtCmd.Flags().IntVarP(&treeDepth, "treeDepth", "t", 9, "depth of the merkle tree")
}

func buildImt() error {
	outputDir := cmd.OutputDir + "/imt/"
	err := os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		return nil
	}
	pass, msg, csBytes, pkBytes, vkInterface := imt.BuildImtCircuit(batchSize, treeDepth)
	if !pass || len(csBytes) == 0 || len(pkBytes) == 0 {
		return fmt.Errorf("build imt circuit failed: %s", msg)
	}

	return writePkVkCs(
		csBytes, pkBytes,
		vkInterface,
		outputDir+"imt_cs.bin",
		outputDir+"imt_pk.bin",
		outputDir+"imt_vk.json",
	)
}
