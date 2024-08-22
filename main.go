package main

import (
	"github.com/Electron-Labs/quantum-gnark-circuits/cmd"
	_ "github.com/Electron-Labs/quantum-gnark-circuits/cmd/build"
	_ "github.com/Electron-Labs/quantum-gnark-circuits/cmd/prove"
)

func main() {
	cmd.Execute()
}
