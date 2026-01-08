NVCC = /opt/cuda/bin/nvcc
NVCC_FLAGS = -ptx -arch=sm_120 -O3

# RTX 5090 uses compute capability 12.0 (Blackwell architecture)

KERNELS = test_kernel.ptx btc_lottery.ptx

all: $(KERNELS)

%.ptx: %.cu
	$(NVCC) $(NVCC_FLAGS) $< -o $@

btc_lottery.ptx: btc_lottery.cu GPUMath.h GPUHash.h

clean:
	rm -f *.ptx

.PHONY: all clean
