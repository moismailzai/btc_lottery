// Package wrapper provides Go bindings for CUDA operations.
package wrapper

/*
#cgo LDFLAGS: -L/opt/cuda/lib64 -lcuda
#cgo CFLAGS: -I/opt/cuda/include

#include <cuda.h>
#include <stdlib.h>

// Initialize CUDA driver
CUresult initCUDA() {
    return cuInit(0);
}

// Get device count
CUresult getDeviceCount(int* count) {
    return cuDeviceGetCount(count);
}

// Get device handle
CUresult getDevice(CUdevice* device, int ordinal) {
    return cuDeviceGet(device, ordinal);
}

// Get device name
CUresult getDeviceName(char* name, int len, CUdevice device) {
    return cuDeviceGetName(name, len, device);
}

// Get device memory
CUresult getDeviceMemory(size_t* bytes, CUdevice device) {
    return cuDeviceTotalMem(bytes, device);
}

// Get primary context for device (simpler than cuCtxCreate)
CUresult retainPrimaryContext(CUcontext* ctx, CUdevice device) {
    return cuDevicePrimaryCtxRetain(ctx, device);
}

// Set current context
CUresult setCurrentContext(CUcontext ctx) {
    return cuCtxSetCurrent(ctx);
}

// Release primary context
CUresult releasePrimaryContext(CUdevice device) {
    return cuDevicePrimaryCtxRelease(device);
}

// Destroy context
CUresult destroyContext(CUcontext ctx) {
    return cuCtxDestroy(ctx);
}

// Allocate device memory
CUresult allocMem(CUdeviceptr* ptr, size_t bytes) {
    return cuMemAlloc(ptr, bytes);
}

// Free device memory
CUresult freeMem(CUdeviceptr ptr) {
    return cuMemFree(ptr);
}

// Copy host to device
CUresult copyHtoD(CUdeviceptr dst, void* src, size_t bytes) {
    return cuMemcpyHtoD(dst, src, bytes);
}

// Copy device to host
CUresult copyDtoH(void* dst, CUdeviceptr src, size_t bytes) {
    return cuMemcpyDtoH(dst, src, bytes);
}

// Load module from PTX
CUresult loadModule(CUmodule* module, const char* ptx) {
    return cuModuleLoadData(module, ptx);
}

// Get function from module
CUresult getFunction(CUfunction* func, CUmodule module, const char* name) {
    return cuModuleGetFunction(func, module, name);
}

// Launch kernel - params is passed as void* and cast internally
CUresult launchKernel(CUfunction func,
                      unsigned int gridX, unsigned int gridY, unsigned int gridZ,
                      unsigned int blockX, unsigned int blockY, unsigned int blockZ,
                      unsigned int sharedMem, CUstream stream,
                      void* params) {
    return cuLaunchKernel(func, gridX, gridY, gridZ, blockX, blockY, blockZ,
                          sharedMem, stream, (void**)params, NULL);
}

// Synchronize
CUresult synchronize() {
    return cuCtxSynchronize();
}

// Get error string
const char* getErrorString(CUresult err) {
    const char* str;
    cuGetErrorString(err, &str);
    return str;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Device represents a CUDA GPU device.
type Device struct {
	handle C.CUdevice
	ctx    C.CUcontext
	name   string
	memory uint64
}

// InitCUDA initializes the CUDA driver. Must be called before any other CUDA operations.
func InitCUDA() error {
	result := C.initCUDA()
	if result != C.CUDA_SUCCESS {
		return fmt.Errorf("cuInit failed: %s", C.GoString(C.getErrorString(result)))
	}
	return nil
}

// DeviceCount returns the number of CUDA-capable devices.
func DeviceCount() (int, error) {
	var count C.int
	result := C.getDeviceCount(&count)
	if result != C.CUDA_SUCCESS {
		return 0, fmt.Errorf("cuDeviceGetCount failed: %s", C.GoString(C.getErrorString(result)))
	}
	return int(count), nil
}

// NewDevice creates a new Device for the given ordinal (0-indexed).
func NewDevice(ordinal int) (*Device, error) {
	var device C.CUdevice
	result := C.getDevice(&device, C.int(ordinal))
	if result != C.CUDA_SUCCESS {
		return nil, fmt.Errorf("cuDeviceGet failed: %s", C.GoString(C.getErrorString(result)))
	}

	// Get device name
	name := make([]byte, 256)
	result = C.getDeviceName((*C.char)(unsafe.Pointer(&name[0])), 256, device)
	if result != C.CUDA_SUCCESS {
		return nil, fmt.Errorf("cuDeviceGetName failed: %s", C.GoString(C.getErrorString(result)))
	}

	// Get device memory
	var memory C.size_t
	result = C.getDeviceMemory(&memory, device)
	if result != C.CUDA_SUCCESS {
		return nil, fmt.Errorf("cuDeviceTotalMem failed: %s", C.GoString(C.getErrorString(result)))
	}

	// Get primary context (simpler than cuCtxCreate)
	var ctx C.CUcontext
	result = C.retainPrimaryContext(&ctx, device)
	if result != C.CUDA_SUCCESS {
		return nil, fmt.Errorf("cuDevicePrimaryCtxRetain failed: %s", C.GoString(C.getErrorString(result)))
	}

	// Set as current context
	result = C.setCurrentContext(ctx)
	if result != C.CUDA_SUCCESS {
		C.releasePrimaryContext(device)
		return nil, fmt.Errorf("cuCtxSetCurrent failed: %s", C.GoString(C.getErrorString(result)))
	}

	return &Device{
		handle: device,
		ctx:    ctx,
		name:   string(name[:clen(name)]),
		memory: uint64(memory),
	}, nil
}

// Name returns the device name.
func (d *Device) Name() string {
	return d.name
}

// Memory returns total device memory in bytes.
func (d *Device) Memory() uint64 {
	return d.memory
}

// Close releases the primary context.
func (d *Device) Close() error {
	result := C.releasePrimaryContext(d.handle)
	if result != C.CUDA_SUCCESS {
		return fmt.Errorf("cuDevicePrimaryCtxRelease failed: %s", C.GoString(C.getErrorString(result)))
	}
	return nil
}

// Synchronize blocks until all CUDA operations complete.
func (d *Device) Synchronize() error {
	result := C.synchronize()
	if result != C.CUDA_SUCCESS {
		return fmt.Errorf("cuCtxSynchronize failed: %s", C.GoString(C.getErrorString(result)))
	}
	return nil
}

// SetCurrent sets this device's context as the current context.
func (d *Device) SetCurrent() error {
	result := C.setCurrentContext(d.ctx)
	if result != C.CUDA_SUCCESS {
		return fmt.Errorf("cuCtxSetCurrent failed: %s", C.GoString(C.getErrorString(result)))
	}
	return nil
}

// clen returns the length of a null-terminated byte slice.
func clen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}

// DeviceMemory represents allocated GPU memory.
type DeviceMemory struct {
	ptr  C.CUdeviceptr
	size uint64
}

// Alloc allocates GPU memory.
func (d *Device) Alloc(size uint64) (*DeviceMemory, error) {
	var ptr C.CUdeviceptr
	result := C.allocMem(&ptr, C.size_t(size))
	if result != C.CUDA_SUCCESS {
		return nil, fmt.Errorf("cuMemAlloc failed: %s", C.GoString(C.getErrorString(result)))
	}
	return &DeviceMemory{ptr: ptr, size: size}, nil
}

// Free releases GPU memory.
func (m *DeviceMemory) Free() error {
	result := C.freeMem(m.ptr)
	if result != C.CUDA_SUCCESS {
		return fmt.Errorf("cuMemFree failed: %s", C.GoString(C.getErrorString(result)))
	}
	return nil
}

// CopyFromHost copies data from host to device.
func (m *DeviceMemory) CopyFromHost(data []byte) error {
	if uint64(len(data)) > m.size {
		return fmt.Errorf("data size %d exceeds allocation %d", len(data), m.size)
	}
	result := C.copyHtoD(m.ptr, unsafe.Pointer(&data[0]), C.size_t(len(data)))
	if result != C.CUDA_SUCCESS {
		return fmt.Errorf("cuMemcpyHtoD failed: %s", C.GoString(C.getErrorString(result)))
	}
	return nil
}

// CopyToHost copies data from device to host.
func (m *DeviceMemory) CopyToHost(data []byte) error {
	if uint64(len(data)) > m.size {
		return fmt.Errorf("data size %d exceeds allocation %d", len(data), m.size)
	}
	result := C.copyDtoH(unsafe.Pointer(&data[0]), m.ptr, C.size_t(len(data)))
	if result != C.CUDA_SUCCESS {
		return fmt.Errorf("cuMemcpyDtoH failed: %s", C.GoString(C.getErrorString(result)))
	}
	return nil
}

// Ptr returns the device pointer as uintptr for kernel arguments.
func (m *DeviceMemory) Ptr() uintptr {
	return uintptr(m.ptr)
}

// Module represents a loaded CUDA module (compiled PTX).
type Module struct {
	handle C.CUmodule
}

// LoadModule loads a PTX module.
func LoadModule(ptx string) (*Module, error) {
	cptx := C.CString(ptx)
	defer C.free(unsafe.Pointer(cptx))

	var module C.CUmodule
	result := C.loadModule(&module, cptx)
	if result != C.CUDA_SUCCESS {
		return nil, fmt.Errorf("cuModuleLoadData failed: %s", C.GoString(C.getErrorString(result)))
	}
	return &Module{handle: module}, nil
}

// GetFunction gets a kernel function from the module.
func (m *Module) GetFunction(name string) (*Function, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	var function C.CUfunction
	result := C.getFunction(&function, m.handle, cname)
	if result != C.CUDA_SUCCESS {
		return nil, fmt.Errorf("cuModuleGetFunction failed: %s", C.GoString(C.getErrorString(result)))
	}
	return &Function{handle: function}, nil
}

// Function represents a CUDA kernel function.
type Function struct {
	handle C.CUfunction
}

// Launch launches the kernel with the given grid and block dimensions.
// params should be pointers to the actual parameter values (not pointers to pointers).
func (f *Function) Launch(gridX, gridY, gridZ, blockX, blockY, blockZ uint32, sharedMem uint32, params []unsafe.Pointer) error {
	// Allocate C array for parameters
	if len(params) == 0 {
		result := C.launchKernel(
			f.handle,
			C.uint(gridX), C.uint(gridY), C.uint(gridZ),
			C.uint(blockX), C.uint(blockY), C.uint(blockZ),
			C.uint(sharedMem), nil,
			nil,
		)
		if result != C.CUDA_SUCCESS {
			return fmt.Errorf("cuLaunchKernel failed: %s", C.GoString(C.getErrorString(result)))
		}
		return nil
	}

	// Allocate C memory for the params array
	cParams := C.malloc(C.size_t(len(params)) * C.size_t(unsafe.Sizeof(uintptr(0))))
	defer C.free(cParams)

	// Copy params to C array
	cParamsSlice := (*[1 << 30]unsafe.Pointer)(cParams)[:len(params):len(params)]
	copy(cParamsSlice, params)

	result := C.launchKernel(
		f.handle,
		C.uint(gridX), C.uint(gridY), C.uint(gridZ),
		C.uint(blockX), C.uint(blockY), C.uint(blockZ),
		C.uint(sharedMem), nil,
		cParams,
	)
	if result != C.CUDA_SUCCESS {
		return fmt.Errorf("cuLaunchKernel failed: %s", C.GoString(C.getErrorString(result)))
	}
	return nil
}
