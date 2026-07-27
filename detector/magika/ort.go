package magika

import (
	"errors"
	"runtime"
	"sync"
	"unique"
	"unsafe"

	"github.com/ebitengine/purego"
)

//go:generate env -C _cmd/ortgen go run . -version 1.15.1 -o ../../ort_types.go

// The version requested here needs to match the value defined as
// ORT_API_VERSION in the C header used to generate "ort_types.go".
//
// This seems to always be the minor version. It should be fine to lag the
// version of the library used at runtime.
const apiVersion = 15

// GetRuntimeHandle attempts to load "libonnxruntime.so.1", reporting
// [errors.ErrUnsupported] if not found.
var getRuntimeHandle = sync.OnceValues(func() (uintptr, error) {
	handle, err := purego.Dlopen("libonnxruntime.so.1", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return 0, errors.Join(errors.ErrUnsupported, err)
	}

	return handle, nil
})

// GetAPIBase returns the [apiBase], loading the runtime if needed.
var getAPIBase = sync.OnceValues(func() (*apiBase, error) {
	handle, err := getRuntimeHandle()
	if err != nil {
		return nil, err
	}

	var fn func() *ortApiBase
	cfn, err := purego.Dlsym(handle, "OrtGetApiBase")
	if err != nil {
		return nil, errors.Join(errors.ErrUnsupported, err)
	}
	purego.RegisterFunc(&fn, cfn)

	return newAPIBase(fn()), nil
})

// GetAPI returns the [api], loading the runtime if needed.
var getAPI = sync.OnceValues(func() (*api, error) {
	base, err := getAPIBase()
	if err != nil {
		return nil, errors.Join(errors.ErrUnsupported, err)
	}

	return base.GetAPI()
})

type apiBase struct {
	getAPI           func(uint32) *ortApi
	getVersionString func() string
}

func newAPIBase(ort *ortApiBase) *apiBase {
	var r apiBase
	purego.RegisterFunc(&r.getAPI, ort.GetApi)
	purego.RegisterFunc(&r.getVersionString, ort.GetVersionString)
	return &r
}

func (a *apiBase) GetAPI() (*api, error) {
	ort := a.getAPI(apiVersion)
	if ort == nil {
		return nil, errors.New("unable to load ONNX Runtime")
	}
	return newAPI(ort), nil
}

func (a *apiBase) GetVersionString() string {
	// intern and return
	return unique.Make(a.getVersionString()).Value()
}

// See ort_types.go for the C function declarations to determine what the
// pointers are.
//
// The ONNX runtime returns most of its objects as typed but opaque pointers,
// which are written here as aliases to [unsafe.Pointer].
type api struct {
	getErrorMessage func(ortStatus) string
	getErrorCode    func(ortStatus) int

	createEnv              func(int, string, *ortEnv) ortStatus
	disableTelemetryEvents func(ortEnv) ortStatus

	createSessionOptions func(*ortSessionOptions) ortStatus
	enableCPUMemArena    func(ortSessionOptions) ortStatus

	createSessionFromArray func(ortEnv, unsafe.Pointer, int, ortSessionOptions, *ortSession) ortStatus

	createCPUMemoryInfo func(int, int, *ortMemoryInfo) ortStatus

	createTensorWithDataAsOrtValue func(ortMemoryInfo, unsafe.Pointer, int, *int64, int, int, *ortValue) ortStatus
	getTensorMutableData           func(ortValue, *unsafe.Pointer) ortStatus

	run func(ortSession, unsafe.Pointer, *string, *ortValue, int, *string, int, *ortValue) ortStatus

	releaseEnv            func(ortEnv)
	releaseMemoryInfo     func(ortMemoryInfo)
	releaseSession        func(ortSession)
	releaseSessionOptions func(ortSessionOptions)
	releaseStatus         func(ortStatus)
	releaseValue          func(ortValue)
}

func newAPI(ort *ortApi) *api {
	var r api

	purego.RegisterFunc(&r.getErrorMessage, ort.GetErrorMessage)
	purego.RegisterFunc(&r.getErrorCode, ort.GetErrorCode)

	purego.RegisterFunc(&r.createEnv, ort.CreateEnv)
	purego.RegisterFunc(&r.disableTelemetryEvents, ort.DisableTelemetryEvents)

	purego.RegisterFunc(&r.createSessionOptions, ort.CreateSessionOptions)
	purego.RegisterFunc(&r.enableCPUMemArena, ort.EnableCpuMemArena)

	purego.RegisterFunc(&r.createSessionFromArray, ort.CreateSessionFromArray)

	purego.RegisterFunc(&r.createCPUMemoryInfo, ort.CreateCpuMemoryInfo)

	purego.RegisterFunc(&r.createTensorWithDataAsOrtValue, ort.CreateTensorWithDataAsOrtValue)
	purego.RegisterFunc(&r.getTensorMutableData, ort.GetTensorMutableData)

	purego.RegisterFunc(&r.run, ort.Run)

	purego.RegisterFunc(&r.releaseEnv, ort.ReleaseEnv)
	purego.RegisterFunc(&r.releaseMemoryInfo, ort.ReleaseMemoryInfo)
	purego.RegisterFunc(&r.releaseSessionOptions, ort.ReleaseSessionOptions)
	purego.RegisterFunc(&r.releaseSession, ort.ReleaseSession)
	purego.RegisterFunc(&r.releaseStatus, ort.ReleaseStatus)
	purego.RegisterFunc(&r.releaseValue, ort.ReleaseValue)

	return &r
}

const onnxLogName = "magika\x00"

const (
	ortInvalidAllocator = iota - 1
	ortDeviceAllocator
	ortArenaAllocator
)

const (
	ortMemTypeCPUInput  = iota - 2            ///< Any CPU memory used by non-CPU execution provider
	ortMemTypeCPUOutput                       ///< CPU accessible memory outputted by non-CPU execution provider, i.e. CUDA_PINNED
	ortMemTypeDefault                         ///< The default allocator for execution provider
	ortMemTypeCPU       = ortMemTypeCPUOutput ///< Temporary CPU accessible memory allocated by non-CPU execution provider, i.e. CUDA_PINNED
)

func (a *api) checkStatus(s ortStatus) error {
	if s != nil {
		err := errors.New(a.getErrorMessage(s))
		a.releaseStatus(s)
		return err
	}
	return nil
}

func (a *api) CreateSession(model []byte) (*session, error) {
	const logLevelWarning = 2
	var env ortEnv
	if err := a.checkStatus(a.createEnv(logLevelWarning, onnxLogName, &env)); err != nil {
		return nil, err
	}
	if err := a.checkStatus(a.disableTelemetryEvents(env)); err != nil {
		return nil, err
	}

	var options ortSessionOptions
	if err := a.checkStatus(a.createSessionOptions(&options)); err != nil {
		return nil, err
	}
	if err := a.checkStatus(a.enableCPUMemArena(options)); err != nil {
		return nil, err
	}

	var mem ortMemoryInfo
	if err := a.checkStatus(a.createCPUMemoryInfo(ortArenaAllocator, ortMemTypeDefault, &mem)); err != nil {
		return nil, err
	}

	var session ortSession
	if err := a.checkStatus(a.createSessionFromArray(env, unsafe.Pointer(unsafe.SliceData(model)), len(model), options, &session)); err != nil {
		return nil, err
	}

	return newSession(env, options, mem, session), nil
}

type session struct {
	api     *api
	env     ortEnv
	options ortSessionOptions
	mem     ortMemoryInfo
	session ortSession
}

func newSession(env ortEnv, options ortSessionOptions, mem ortMemoryInfo, p ortSession) *session {
	api, _ := getAPI()
	r := &session{
		api:     api,
		env:     env,
		options: options,
		mem:     mem,
		session: p,
	}
	runtime.AddCleanup(r, api.releaseEnv, env)
	runtime.AddCleanup(r, api.releaseSessionOptions, options)
	runtime.AddCleanup(r, api.releaseMemoryInfo, mem)
	runtime.AddCleanup(r, api.releaseSession, p)
	return r
}

var (
	inputNames  = []string{"bytes\x00"}
	outputNames = []string{"target_label\x00"}
)

func (s *session) Run(features []int32, labelSpace int) ([]float32, error) {
	shape := []int64{1, int64(len(features))}

	var input, output ortValue
	status := s.api.createTensorWithDataAsOrtValue(s.mem,
		unsafe.Pointer(unsafe.SliceData(features)), len(features)*int(unsafe.Sizeof(int32(0))),
		unsafe.SliceData(shape), 2,
		tensorElementInt32, &input)
	if err := s.api.checkStatus(status); err != nil {
		return nil, err
	}
	defer s.api.releaseValue(input)

	status = s.api.run(s.session, nil,
		unsafe.SliceData(inputNames), &input, 1,
		unsafe.SliceData(outputNames), 1,
		&output,
	)
	if err := s.api.checkStatus(status); err != nil {
		return nil, err
	}
	defer s.api.releaseValue(output)

	// Returned data is owned by the Value, so copy it out.
	var out unsafe.Pointer
	status = s.api.getTensorMutableData(output, &out)
	if err := s.api.checkStatus(status); err != nil {
		return nil, err
	}
	ret := make([]float32, labelSpace)
	copy(ret, unsafe.Slice((*float32)(out), labelSpace))

	return ret, nil
}

type (
	ortEnv            unsafe.Pointer
	ortSessionOptions unsafe.Pointer
	ortMemoryInfo     unsafe.Pointer
	ortValue          unsafe.Pointer
	ortSession        unsafe.Pointer
	ortStatus         unsafe.Pointer
)

const (
	tensorElementUndefined = iota
	tensorElementFloat     // maps to c type float
	tensorElementUint8     // maps to c type uint8_t
	tensorElementInt8      // maps to c type int8_t
	tensorElementUint16    // maps to c type uint16_t
	tensorElementInt16     // maps to c type int16_t
	tensorElementInt32     // maps to c type int32_t
	tensorElementInt64     // maps to c type int64_t
	tensorElementString    // maps to c++ type std::string
	tensorElementBool
	tensorElementFloat16
	tensorElementDouble     // maps to c type double
	tensorElementUint32     // maps to c type uint32_t
	tensorElementUint64     // maps to c type uint64_t
	tensorElementComplex64  // complex with float32 real and imaginary components
	tensorElementComplex128 // complex with float64 real and imaginary components
	tensorElementBFloat16   // Non-IEEE floating-point format based on IEEE754 single-precision
	// float 8 types were introduced in onnx 1.14 see https://onnx.ai/onnx/technical/float8.html
	tensorElementFloat8E4M3FN   // Non-IEEE floating-point format based on IEEE754 single-precision
	tensorElementFloat8E4M3FNUZ // Non-IEEE floating-point format based on IEEE754 single-precision
	tensorElementFloat8E5M2     // Non-IEEE floating-point format based on IEEE754 single-precision
	tensorElementFloat8E5M2FNUZ // Non-IEEE floating-point format based on IEEE754 single-precision
)
