package build

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Electron-Labs/quantum-gnark-circuits/cmd"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/spf13/cobra"
)

// buildCmd represents the build command
var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build cs, pk, and vk files for specific circuits",
}

func init() {
	cmd.RootCmd.AddCommand(buildCmd)
}

func writePkVkCs(
	csBytes, pkBytes []byte,
	vkInterface groth16.VerifyingKey,
	csFile, pkFile, vkFile string,
) error {
	fileCs, err := os.Create(csFile)
	if err != nil {
		return err
	}
	defer fileCs.Close()
	_, err = fileCs.Write(csBytes)
	if err != nil {
		return err
	}

	filePk, err := os.Create(pkFile)
	if err != nil {
		return err
	}
	defer filePk.Close()
	_, err = filePk.Write(pkBytes)
	if err != nil {
		return err
	}

	vk, ok := vkInterface.(*groth16_bn254.VerifyingKey)
	if !ok {
		return fmt.Errorf("invalid vkey")
	}
	bytesVK, err := json.MarshalIndent(vk, "", " ")
	if err != nil {
		return fmt.Errorf("unable to convert struct to json.MarshalIndent format")
	}

	fileVk, err := os.Create(vkFile)
	if err != nil {
		return err
	}
	defer fileVk.Close()
	_, err = fileVk.Write(bytesVK)
	if err != nil {
		return err
	}

	return nil
}
