//go:build !cuda

package main

import (
	"context"
	"log"
	"sync"

	"btc_lottery/internal/lookup"
	"btc_lottery/internal/worker"
)

// runWorkers starts CPU workers (non-GPU build).
func runWorkers(ctx context.Context, hashSet *lookup.AddressHashSet, cfg workerConfig) (matchChan chan worker.Match, statsFn func() (int64, int64), waitFn func()) {
	if cfg.useGPU {
		log.Println("WARNING: GPU acceleration requested but not compiled with -tags cuda")
		log.Println("Falling back to CPU-only mode")
	}

	matchChan = make(chan worker.Match, 100)
	var wg sync.WaitGroup

	workerCfg := worker.Config{
		AddressIndexes: cfg.addressIndexes,
		EntropyBits:    cfg.entropyBits,
		GPUBatchSize:   cfg.gpuBatchSize,
		UseGPU:         false,
		Verbose:        cfg.verbose,
	}

	// Keep references to workers for stats
	workers := make([]*worker.CPUWorker, cfg.numWorkers)

	log.Printf("Starting %d CPU workers...", cfg.numWorkers)
	for i := 0; i < cfg.numWorkers; i++ {
		w := worker.NewCPUWorker(hashSet, workerCfg)
		workers[i] = w

		wg.Add(1)
		go func(w *worker.CPUWorker) {
			defer wg.Done()
			defer w.Close()

			workerMatches := w.Run(ctx)
			for match := range workerMatches {
				matchChan <- match
			}
		}(w)
	}

	// Stats function queries all workers in real-time
	statsFn = func() (int64, int64) {
		var totalAddr, totalMnem int64
		for _, w := range workers {
			stats := w.Stats()
			totalAddr += stats.AddressesChecked
			totalMnem += stats.MnemonicsGenerated
		}
		return totalAddr, totalMnem
	}

	waitFn = func() {
		wg.Wait()
		close(matchChan)
	}

	return
}
