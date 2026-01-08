//go:build cuda

package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"btc_lottery/internal/lookup"
	"btc_lottery/internal/worker"
)

// runWorkers starts workers (GPU-enabled build).
func runWorkers(ctx context.Context, hashSet *lookup.AddressHashSet, cfg workerConfig) (matchChan chan worker.Match, statsFn func() (int64, int64), waitFn func()) {
	matchChan = make(chan worker.Match, 100)
	var totalAddresses int64
	var totalMnemonics int64
	var wg sync.WaitGroup

	if cfg.useGPU {
		// Find PTX path
		ptxPath := cfg.ptxPath
		if ptxPath == "" {
			// Try common locations
			candidates := []string{
				"gpu/cuda/btc_lottery.ptx",
				"/home/mo/dev/src/btc_lottery/gpu/cuda/btc_lottery.ptx",
				filepath.Join(filepath.Dir(os.Args[0]), "btc_lottery.ptx"),
			}
			for _, p := range candidates {
				if _, err := os.Stat(p); err == nil {
					ptxPath = p
					break
				}
			}
			if ptxPath == "" {
				log.Fatal("Cannot find btc_lottery.ptx. Use -ptx flag to specify path.")
			}
		}

		gpuCfg := worker.GPUWorkerConfig{
			Config: worker.Config{
				AddressIndexes: cfg.addressIndexes,
				EntropyBits:    cfg.entropyBits,
				GPUBatchSize:   cfg.gpuBatchSize,
				UseGPU:         true,
				Verbose:        cfg.verbose,
			},
			PTXPath:     ptxPath,
			GTableXPath: cfg.gtableXPath,
			GTableYPath: cfg.gtableYPath,
		}

		log.Printf("Creating GPU worker...")
		gpuWorker, err := worker.NewGPUWorker(hashSet, gpuCfg)
		if err != nil {
			log.Printf("Failed to create GPU worker: %v", err)
			log.Printf("Falling back to CPU workers")
			return runCPUWorkers(ctx, hashSet, cfg, matchChan, &totalAddresses, &wg)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer gpuWorker.Close()

			workerMatches := gpuWorker.Run(ctx)
			for match := range workerMatches {
				matchChan <- match
			}

			stats := gpuWorker.Stats()
			atomic.AddInt64(&totalAddresses, stats.AddressesChecked)
			atomic.AddInt64(&totalMnemonics, stats.MnemonicsGenerated)
		}()

		// Start CPU workers in parallel
		// GPU batches keys while CPU workers also check independently
		cpuWorkers := cfg.numWorkers - 1
		if cpuWorkers > 0 {
			log.Printf("Starting %d additional CPU workers...", cpuWorkers)
			for i := 0; i < cpuWorkers; i++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()

					workerCfg := worker.Config{
						AddressIndexes: cfg.addressIndexes,
						EntropyBits:    cfg.entropyBits,
						GPUBatchSize:   cfg.gpuBatchSize,
						UseGPU:         false,
						Verbose:        cfg.verbose,
					}

					w := worker.NewCPUWorker(hashSet, workerCfg)
					defer w.Close()

					workerMatches := w.Run(ctx)
					for match := range workerMatches {
						matchChan <- match
					}

					stats := w.Stats()
					atomic.AddInt64(&totalAddresses, stats.AddressesChecked)
				}(i)
			}
		}

		// Create a stats function that also checks GPU worker
		statsFn = func() (int64, int64) {
			gpuStats := gpuWorker.Stats()
			cpuAddr := atomic.LoadInt64(&totalAddresses)
			return cpuAddr + gpuStats.AddressesChecked, gpuStats.MnemonicsGenerated
		}

		waitFn = func() {
			wg.Wait()
			close(matchChan)
		}

		return
	}

	// Non-GPU mode
	return runCPUWorkers(ctx, hashSet, cfg, matchChan, &totalAddresses, &wg)
}

func runCPUWorkers(ctx context.Context, hashSet *lookup.AddressHashSet, cfg workerConfig, matchChan chan worker.Match, totalAddresses *int64, wg *sync.WaitGroup) (chan worker.Match, func() (int64, int64), func()) {
	workerCfg := worker.Config{
		AddressIndexes: cfg.addressIndexes,
		EntropyBits:    cfg.entropyBits,
		GPUBatchSize:   cfg.gpuBatchSize,
		UseGPU:         false,
		Verbose:        cfg.verbose,
	}

	// Keep references to workers for real-time stats
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

	// Real-time stats from all workers
	statsFn := func() (int64, int64) {
		var totalAddr, totalMnem int64
		for _, w := range workers {
			stats := w.Stats()
			totalAddr += stats.AddressesChecked
			totalMnem += stats.MnemonicsGenerated
		}
		return totalAddr, totalMnem
	}

	waitFn := func() {
		wg.Wait()
		close(matchChan)
	}

	return matchChan, statsFn, waitFn
}
