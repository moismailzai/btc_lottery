// gengtable generates the precomputed secp256k1 GTable for GPU acceleration.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"btc_lottery/gpu/gtable"
)

func main() {
	outDir := flag.String("out", ".", "Output directory for GTable files")
	flag.Parse()

	fmt.Println("Generating secp256k1 GTable...")
	fmt.Println("This will create ~67 MB of precomputed points.")
	fmt.Println()

	start := time.Now()

	gt, err := gtable.Generate(func(chunk int) {
		fmt.Printf("\rProcessing chunk %d/16...", chunk+1)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(" Done!")

	// Verify
	fmt.Print("Verifying GTable... ")
	if err := gt.Verify(); err != nil {
		fmt.Fprintf(os.Stderr, "FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")

	// Save
	xPath := *outDir + "/gtable_x.bin"
	yPath := *outDir + "/gtable_y.bin"

	fmt.Printf("Saving to %s and %s... ", xPath, yPath)
	if err := gt.Save(xPath, yPath); err != nil {
		fmt.Fprintf(os.Stderr, "FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")

	elapsed := time.Since(start)
	fmt.Printf("\nGeneration completed in %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("X table: %d bytes\n", len(gt.X))
	fmt.Printf("Y table: %d bytes\n", len(gt.Y))
}
