package frost_uniffi_sdk

// #include <frost_go_ffi.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"runtime"
	"sync/atomic"
	"unsafe"
)

type RustBuffer = C.RustBuffer

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() int
	Capacity() int
}

func RustBufferFromExternal(b RustBufferI) RustBuffer {
	return RustBuffer{
		capacity: C.int(b.Capacity()),
		len:      C.int(b.Len()),
		data:     (*C.uchar)(b.Data()),
	}
}

func (cb RustBuffer) Capacity() int {
	return int(cb.capacity)
}

func (cb RustBuffer) Len() int {
	return int(cb.len)
}

func (cb RustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.data)
}

func (cb RustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.data), C.int(cb.len))
	return bytes.NewReader(b)
}

func (cb RustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_frost_uniffi_sdk_rustbuffer_free(cb, status)
		return false
	})
}

func (cb RustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.data), C.int(cb.len))
}

func stringToRustBuffer(str string) RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) RustBuffer {
	if len(b) == 0 {
		return RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) RustBuffer {
		return C.ffi_frost_uniffi_sdk_rustbuffer_from_bytes(foreign, status)
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) RustBuffer
}

type FfiConverter[GoType any, FfiType any] interface {
	Lift(value FfiType) GoType
	Lower(value GoType) FfiType
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

type FfiRustBufConverter[GoType any, FfiType any] interface {
	FfiConverter[GoType, FfiType]
	BufReader[GoType]
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[U any](converter BufLifter[error], callback func(*C.RustCallStatus) U) (U, error) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)

	return returnValue, err
}

func checkCallStatus(converter BufLifter[error], status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		return converter.Lift(status.errorBuf)
	case 2:
		// when the rust code sees a panic, it tries to construct a rustbuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(status.errorBuf)))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a rustbuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(status.errorBuf)))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError(nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 24
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_frost_uniffi_sdk_uniffi_contract_version(uniffiStatus)
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("frost_uniffi_sdk: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_aggregate(uniffiStatus)
		})
		if checksum != 3424 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_aggregate: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_from_hex_string(uniffiStatus)
		})
		if checksum != 29801 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_from_hex_string: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_generate_nonces_and_commitments(uniffiStatus)
		})
		if checksum != 1477 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_generate_nonces_and_commitments: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_identifier_from_json_string(uniffiStatus)
		})
		if checksum != 56485 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_identifier_from_json_string: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_identifier_from_string(uniffiStatus)
		})
		if checksum != 3795 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_identifier_from_string: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_identifier_from_uint16(uniffiStatus)
		})
		if checksum != 11722 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_identifier_from_uint16: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_new_signing_package(uniffiStatus)
		})
		if checksum != 50111 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_new_signing_package: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_part_1(uniffiStatus)
		})
		if checksum != 7592 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_part_1: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_part_2(uniffiStatus)
		})
		if checksum != 30136 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_part_2: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_part_3(uniffiStatus)
		})
		if checksum != 31134 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_part_3: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_randomized_params_from_public_key_and_signing_package(uniffiStatus)
		})
		if checksum != 58556 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_randomized_params_from_public_key_and_signing_package: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_randomizer_from_params(uniffiStatus)
		})
		if checksum != 50217 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_randomizer_from_params: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_sign(uniffiStatus)
		})
		if checksum != 723 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_sign: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_trusted_dealer_keygen_from(uniffiStatus)
		})
		if checksum != 43563 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_trusted_dealer_keygen_from: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_trusted_dealer_keygen_with_identifiers(uniffiStatus)
		})
		if checksum != 49159 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_trusted_dealer_keygen_with_identifiers: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_validate_config(uniffiStatus)
		})
		if checksum != 26688 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_validate_config: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_verify_and_get_key_package_from(uniffiStatus)
		})
		if checksum != 16387 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_verify_and_get_key_package_from: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_verify_randomized_signature(uniffiStatus)
		})
		if checksum != 24114 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_verify_randomized_signature: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_frost_uniffi_sdk_checksum_func_verify_signature(uniffiStatus)
		})
		if checksum != 13620 {
			// If this happens try cleaning and rebuilding your project
			panic("frost_uniffi_sdk: uniffi_frost_uniffi_sdk_checksum_func_verify_signature: UniFFI API checksum mismatch")
		}
	}
}

type FfiConverterUint16 struct{}

var FfiConverterUint16INSTANCE = FfiConverterUint16{}

func (FfiConverterUint16) Lower(value uint16) C.uint16_t {
	return C.uint16_t(value)
}

func (FfiConverterUint16) Write(writer io.Writer, value uint16) {
	writeUint16(writer, value)
}

func (FfiConverterUint16) Lift(value C.uint16_t) uint16 {
	return uint16(value)
}

func (FfiConverterUint16) Read(reader io.Reader) uint16 {
	return readUint16(reader)
}

type FfiDestroyerUint16 struct{}

func (FfiDestroyerUint16) Destroy(_ uint16) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) RustBuffer {
	return stringToRustBuffer(value)
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct{}

func (FfiDestroyerString) Destroy(_ string) {}

type FfiConverterBytes struct{}

var FfiConverterBytesINSTANCE = FfiConverterBytes{}

func (c FfiConverterBytes) Lower(value []byte) RustBuffer {
	return LowerIntoRustBuffer[[]byte](c, value)
}

func (c FfiConverterBytes) Write(writer io.Writer, value []byte) {
	if len(value) > math.MaxInt32 {
		panic("[]byte is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := writer.Write(value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing []byte, expected %d, written %d", len(value), write_length))
	}
}

func (c FfiConverterBytes) Lift(rb RustBufferI) []byte {
	return LiftFromRustBuffer[[]byte](c, rb)
}

func (c FfiConverterBytes) Read(reader io.Reader) []byte {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading []byte, expected %d, read %d", length, read_length))
	}
	return buffer
}

type FfiDestroyerBytes struct{}

func (FfiDestroyerBytes) Destroy(_ []byte) {}

// Below is an implementation of synchronization requirements outlined in the link.
// https://github.com/mozilla/uniffi-rs/blob/0dc031132d9493ca812c3af6e7dd60ad2ea95bf0/uniffi_bindgen/src/bindings/kotlin/templates/ObjectRuntime.kt#L31

type FfiObject struct {
	pointer      unsafe.Pointer
	callCounter  atomic.Int64
	freeFunction func(unsafe.Pointer, *C.RustCallStatus)
	destroyed    atomic.Bool
}

func newFfiObject(pointer unsafe.Pointer, freeFunction func(unsafe.Pointer, *C.RustCallStatus)) FfiObject {
	return FfiObject{
		pointer:      pointer,
		freeFunction: freeFunction,
	}
}

func (ffiObject *FfiObject) incrementPointer(debugName string) unsafe.Pointer {
	for {
		counter := ffiObject.callCounter.Load()
		if counter <= -1 {
			panic(fmt.Errorf("%v object has already been destroyed", debugName))
		}
		if counter == math.MaxInt64 {
			panic(fmt.Errorf("%v object call counter would overflow", debugName))
		}
		if ffiObject.callCounter.CompareAndSwap(counter, counter+1) {
			break
		}
	}

	return ffiObject.pointer
}

func (ffiObject *FfiObject) decrementPointer() {
	if ffiObject.callCounter.Add(-1) == -1 {
		ffiObject.freeRustArcPtr()
	}
}

func (ffiObject *FfiObject) destroy() {
	if ffiObject.destroyed.CompareAndSwap(false, true) {
		if ffiObject.callCounter.Add(-1) == -1 {
			ffiObject.freeRustArcPtr()
		}
	}
}

func (ffiObject *FfiObject) freeRustArcPtr() {
	rustCall(func(status *C.RustCallStatus) int32 {
		ffiObject.freeFunction(ffiObject.pointer, status)
		return 0
	})
}

type DkgPart1Result struct {
	ffiObject FfiObject
}

func (object *DkgPart1Result) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterDKGPart1Result struct{}

var FfiConverterDKGPart1ResultINSTANCE = FfiConverterDKGPart1Result{}

func (c FfiConverterDKGPart1Result) Lift(pointer unsafe.Pointer) *DkgPart1Result {
	result := &DkgPart1Result{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_frost_uniffi_sdk_fn_free_dkgpart1result(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*DkgPart1Result).Destroy)
	return result
}

func (c FfiConverterDKGPart1Result) Read(reader io.Reader) *DkgPart1Result {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterDKGPart1Result) Lower(value *DkgPart1Result) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*DkgPart1Result")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterDKGPart1Result) Write(writer io.Writer, value *DkgPart1Result) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerDkgPart1Result struct{}

func (_ FfiDestroyerDkgPart1Result) Destroy(value *DkgPart1Result) {
	value.Destroy()
}

type DkgPart2Result struct {
	ffiObject FfiObject
}

func (object *DkgPart2Result) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterDKGPart2Result struct{}

var FfiConverterDKGPart2ResultINSTANCE = FfiConverterDKGPart2Result{}

func (c FfiConverterDKGPart2Result) Lift(pointer unsafe.Pointer) *DkgPart2Result {
	result := &DkgPart2Result{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_frost_uniffi_sdk_fn_free_dkgpart2result(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*DkgPart2Result).Destroy)
	return result
}

func (c FfiConverterDKGPart2Result) Read(reader io.Reader) *DkgPart2Result {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterDKGPart2Result) Lower(value *DkgPart2Result) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*DkgPart2Result")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterDKGPart2Result) Write(writer io.Writer, value *DkgPart2Result) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerDkgPart2Result struct{}

func (_ FfiDestroyerDkgPart2Result) Destroy(value *DkgPart2Result) {
	value.Destroy()
}

type DkgRound1SecretPackage struct {
	ffiObject FfiObject
}

func (object *DkgRound1SecretPackage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterDKGRound1SecretPackage struct{}

var FfiConverterDKGRound1SecretPackageINSTANCE = FfiConverterDKGRound1SecretPackage{}

func (c FfiConverterDKGRound1SecretPackage) Lift(pointer unsafe.Pointer) *DkgRound1SecretPackage {
	result := &DkgRound1SecretPackage{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_frost_uniffi_sdk_fn_free_dkground1secretpackage(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*DkgRound1SecretPackage).Destroy)
	return result
}

func (c FfiConverterDKGRound1SecretPackage) Read(reader io.Reader) *DkgRound1SecretPackage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterDKGRound1SecretPackage) Lower(value *DkgRound1SecretPackage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*DkgRound1SecretPackage")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterDKGRound1SecretPackage) Write(writer io.Writer, value *DkgRound1SecretPackage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerDkgRound1SecretPackage struct{}

func (_ FfiDestroyerDkgRound1SecretPackage) Destroy(value *DkgRound1SecretPackage) {
	value.Destroy()
}

type DkgRound2SecretPackage struct {
	ffiObject FfiObject
}

func (object *DkgRound2SecretPackage) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterDKGRound2SecretPackage struct{}

var FfiConverterDKGRound2SecretPackageINSTANCE = FfiConverterDKGRound2SecretPackage{}

func (c FfiConverterDKGRound2SecretPackage) Lift(pointer unsafe.Pointer) *DkgRound2SecretPackage {
	result := &DkgRound2SecretPackage{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_frost_uniffi_sdk_fn_free_dkground2secretpackage(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*DkgRound2SecretPackage).Destroy)
	return result
}

func (c FfiConverterDKGRound2SecretPackage) Read(reader io.Reader) *DkgRound2SecretPackage {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterDKGRound2SecretPackage) Lower(value *DkgRound2SecretPackage) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*DkgRound2SecretPackage")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterDKGRound2SecretPackage) Write(writer io.Writer, value *DkgRound2SecretPackage) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerDkgRound2SecretPackage struct{}

func (_ FfiDestroyerDkgRound2SecretPackage) Destroy(value *DkgRound2SecretPackage) {
	value.Destroy()
}

type FrostRandomizedParams struct {
	ffiObject FfiObject
}

func (object *FrostRandomizedParams) Destroy() {
	runtime.SetFinalizer(object, nil)
	object.ffiObject.destroy()
}

type FfiConverterFrostRandomizedParams struct{}

var FfiConverterFrostRandomizedParamsINSTANCE = FfiConverterFrostRandomizedParams{}

func (c FfiConverterFrostRandomizedParams) Lift(pointer unsafe.Pointer) *FrostRandomizedParams {
	result := &FrostRandomizedParams{
		newFfiObject(
			pointer,
			func(pointer unsafe.Pointer, status *C.RustCallStatus) {
				C.uniffi_frost_uniffi_sdk_fn_free_frostrandomizedparams(pointer, status)
			}),
	}
	runtime.SetFinalizer(result, (*FrostRandomizedParams).Destroy)
	return result
}

func (c FfiConverterFrostRandomizedParams) Read(reader io.Reader) *FrostRandomizedParams {
	return c.Lift(unsafe.Pointer(uintptr(readUint64(reader))))
}

func (c FfiConverterFrostRandomizedParams) Lower(value *FrostRandomizedParams) unsafe.Pointer {
	// TODO: this is bad - all synchronization from ObjectRuntime.go is discarded here,
	// because the pointer will be decremented immediately after this function returns,
	// and someone will be left holding onto a non-locked pointer.
	pointer := value.ffiObject.incrementPointer("*FrostRandomizedParams")
	defer value.ffiObject.decrementPointer()
	return pointer
}

func (c FfiConverterFrostRandomizedParams) Write(writer io.Writer, value *FrostRandomizedParams) {
	writeUint64(writer, uint64(uintptr(c.Lower(value))))
}

type FfiDestroyerFrostRandomizedParams struct{}

func (_ FfiDestroyerFrostRandomizedParams) Destroy(value *FrostRandomizedParams) {
	value.Destroy()
}

type Configuration struct {
	MinSigners uint16
	MaxSigners uint16
	Secret     []byte
}

func (r *Configuration) Destroy() {
	FfiDestroyerUint16{}.Destroy(r.MinSigners)
	FfiDestroyerUint16{}.Destroy(r.MaxSigners)
	FfiDestroyerBytes{}.Destroy(r.Secret)
}

type FfiConverterTypeConfiguration struct{}

var FfiConverterTypeConfigurationINSTANCE = FfiConverterTypeConfiguration{}

func (c FfiConverterTypeConfiguration) Lift(rb RustBufferI) Configuration {
	return LiftFromRustBuffer[Configuration](c, rb)
}

func (c FfiConverterTypeConfiguration) Read(reader io.Reader) Configuration {
	return Configuration{
		FfiConverterUint16INSTANCE.Read(reader),
		FfiConverterUint16INSTANCE.Read(reader),
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeConfiguration) Lower(value Configuration) RustBuffer {
	return LowerIntoRustBuffer[Configuration](c, value)
}

func (c FfiConverterTypeConfiguration) Write(writer io.Writer, value Configuration) {
	FfiConverterUint16INSTANCE.Write(writer, value.MinSigners)
	FfiConverterUint16INSTANCE.Write(writer, value.MaxSigners)
	FfiConverterBytesINSTANCE.Write(writer, value.Secret)
}

type FfiDestroyerTypeConfiguration struct{}

func (_ FfiDestroyerTypeConfiguration) Destroy(value Configuration) {
	value.Destroy()
}

type DkgPart3Result struct {
	PublicKeyPackage FrostPublicKeyPackage
	KeyPackage       FrostKeyPackage
}

func (r *DkgPart3Result) Destroy() {
	FfiDestroyerTypeFrostPublicKeyPackage{}.Destroy(r.PublicKeyPackage)
	FfiDestroyerTypeFrostKeyPackage{}.Destroy(r.KeyPackage)
}

type FfiConverterTypeDKGPart3Result struct{}

var FfiConverterTypeDKGPart3ResultINSTANCE = FfiConverterTypeDKGPart3Result{}

func (c FfiConverterTypeDKGPart3Result) Lift(rb RustBufferI) DkgPart3Result {
	return LiftFromRustBuffer[DkgPart3Result](c, rb)
}

func (c FfiConverterTypeDKGPart3Result) Read(reader io.Reader) DkgPart3Result {
	return DkgPart3Result{
		FfiConverterTypeFrostPublicKeyPackageINSTANCE.Read(reader),
		FfiConverterTypeFrostKeyPackageINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeDKGPart3Result) Lower(value DkgPart3Result) RustBuffer {
	return LowerIntoRustBuffer[DkgPart3Result](c, value)
}

func (c FfiConverterTypeDKGPart3Result) Write(writer io.Writer, value DkgPart3Result) {
	FfiConverterTypeFrostPublicKeyPackageINSTANCE.Write(writer, value.PublicKeyPackage)
	FfiConverterTypeFrostKeyPackageINSTANCE.Write(writer, value.KeyPackage)
}

type FfiDestroyerTypeDkgPart3Result struct{}

func (_ FfiDestroyerTypeDkgPart3Result) Destroy(value DkgPart3Result) {
	value.Destroy()
}

type DkgRound1Package struct {
	Identifier ParticipantIdentifier
	Data       []byte
}

func (r *DkgRound1Package) Destroy() {
	FfiDestroyerTypeParticipantIdentifier{}.Destroy(r.Identifier)
	FfiDestroyerBytes{}.Destroy(r.Data)
}

type FfiConverterTypeDKGRound1Package struct{}

var FfiConverterTypeDKGRound1PackageINSTANCE = FfiConverterTypeDKGRound1Package{}

func (c FfiConverterTypeDKGRound1Package) Lift(rb RustBufferI) DkgRound1Package {
	return LiftFromRustBuffer[DkgRound1Package](c, rb)
}

func (c FfiConverterTypeDKGRound1Package) Read(reader io.Reader) DkgRound1Package {
	return DkgRound1Package{
		FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader),
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeDKGRound1Package) Lower(value DkgRound1Package) RustBuffer {
	return LowerIntoRustBuffer[DkgRound1Package](c, value)
}

func (c FfiConverterTypeDKGRound1Package) Write(writer io.Writer, value DkgRound1Package) {
	FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, value.Identifier)
	FfiConverterBytesINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeDkgRound1Package struct{}

func (_ FfiDestroyerTypeDkgRound1Package) Destroy(value DkgRound1Package) {
	value.Destroy()
}

type DkgRound2Package struct {
	Identifier ParticipantIdentifier
	Data       []byte
}

func (r *DkgRound2Package) Destroy() {
	FfiDestroyerTypeParticipantIdentifier{}.Destroy(r.Identifier)
	FfiDestroyerBytes{}.Destroy(r.Data)
}

type FfiConverterTypeDKGRound2Package struct{}

var FfiConverterTypeDKGRound2PackageINSTANCE = FfiConverterTypeDKGRound2Package{}

func (c FfiConverterTypeDKGRound2Package) Lift(rb RustBufferI) DkgRound2Package {
	return LiftFromRustBuffer[DkgRound2Package](c, rb)
}

func (c FfiConverterTypeDKGRound2Package) Read(reader io.Reader) DkgRound2Package {
	return DkgRound2Package{
		FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader),
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeDKGRound2Package) Lower(value DkgRound2Package) RustBuffer {
	return LowerIntoRustBuffer[DkgRound2Package](c, value)
}

func (c FfiConverterTypeDKGRound2Package) Write(writer io.Writer, value DkgRound2Package) {
	FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, value.Identifier)
	FfiConverterBytesINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeDkgRound2Package struct{}

func (_ FfiDestroyerTypeDkgRound2Package) Destroy(value DkgRound2Package) {
	value.Destroy()
}

type FirstRoundCommitment struct {
	Nonces      FrostSigningNonces
	Commitments FrostSigningCommitments
}

func (r *FirstRoundCommitment) Destroy() {
	FfiDestroyerTypeFrostSigningNonces{}.Destroy(r.Nonces)
	FfiDestroyerTypeFrostSigningCommitments{}.Destroy(r.Commitments)
}

type FfiConverterTypeFirstRoundCommitment struct{}

var FfiConverterTypeFirstRoundCommitmentINSTANCE = FfiConverterTypeFirstRoundCommitment{}

func (c FfiConverterTypeFirstRoundCommitment) Lift(rb RustBufferI) FirstRoundCommitment {
	return LiftFromRustBuffer[FirstRoundCommitment](c, rb)
}

func (c FfiConverterTypeFirstRoundCommitment) Read(reader io.Reader) FirstRoundCommitment {
	return FirstRoundCommitment{
		FfiConverterTypeFrostSigningNoncesINSTANCE.Read(reader),
		FfiConverterTypeFrostSigningCommitmentsINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeFirstRoundCommitment) Lower(value FirstRoundCommitment) RustBuffer {
	return LowerIntoRustBuffer[FirstRoundCommitment](c, value)
}

func (c FfiConverterTypeFirstRoundCommitment) Write(writer io.Writer, value FirstRoundCommitment) {
	FfiConverterTypeFrostSigningNoncesINSTANCE.Write(writer, value.Nonces)
	FfiConverterTypeFrostSigningCommitmentsINSTANCE.Write(writer, value.Commitments)
}

type FfiDestroyerTypeFirstRoundCommitment struct{}

func (_ FfiDestroyerTypeFirstRoundCommitment) Destroy(value FirstRoundCommitment) {
	value.Destroy()
}

type FrostKeyPackage struct {
	Identifier ParticipantIdentifier
	Data       []byte
}

func (r *FrostKeyPackage) Destroy() {
	FfiDestroyerTypeParticipantIdentifier{}.Destroy(r.Identifier)
	FfiDestroyerBytes{}.Destroy(r.Data)
}

type FfiConverterTypeFrostKeyPackage struct{}

var FfiConverterTypeFrostKeyPackageINSTANCE = FfiConverterTypeFrostKeyPackage{}

func (c FfiConverterTypeFrostKeyPackage) Lift(rb RustBufferI) FrostKeyPackage {
	return LiftFromRustBuffer[FrostKeyPackage](c, rb)
}

func (c FfiConverterTypeFrostKeyPackage) Read(reader io.Reader) FrostKeyPackage {
	return FrostKeyPackage{
		FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader),
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeFrostKeyPackage) Lower(value FrostKeyPackage) RustBuffer {
	return LowerIntoRustBuffer[FrostKeyPackage](c, value)
}

func (c FfiConverterTypeFrostKeyPackage) Write(writer io.Writer, value FrostKeyPackage) {
	FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, value.Identifier)
	FfiConverterBytesINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeFrostKeyPackage struct{}

func (_ FfiDestroyerTypeFrostKeyPackage) Destroy(value FrostKeyPackage) {
	value.Destroy()
}

type FrostPublicKeyPackage struct {
	VerifyingShares map[ParticipantIdentifier]string
	VerifyingKey    string
}

func (r *FrostPublicKeyPackage) Destroy() {
	FfiDestroyerMapTypeParticipantIdentifierString{}.Destroy(r.VerifyingShares)
	FfiDestroyerString{}.Destroy(r.VerifyingKey)
}

type FfiConverterTypeFrostPublicKeyPackage struct{}

var FfiConverterTypeFrostPublicKeyPackageINSTANCE = FfiConverterTypeFrostPublicKeyPackage{}

func (c FfiConverterTypeFrostPublicKeyPackage) Lift(rb RustBufferI) FrostPublicKeyPackage {
	return LiftFromRustBuffer[FrostPublicKeyPackage](c, rb)
}

func (c FfiConverterTypeFrostPublicKeyPackage) Read(reader io.Reader) FrostPublicKeyPackage {
	return FrostPublicKeyPackage{
		FfiConverterMapTypeParticipantIdentifierStringINSTANCE.Read(reader),
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeFrostPublicKeyPackage) Lower(value FrostPublicKeyPackage) RustBuffer {
	return LowerIntoRustBuffer[FrostPublicKeyPackage](c, value)
}

func (c FfiConverterTypeFrostPublicKeyPackage) Write(writer io.Writer, value FrostPublicKeyPackage) {
	FfiConverterMapTypeParticipantIdentifierStringINSTANCE.Write(writer, value.VerifyingShares)
	FfiConverterStringINSTANCE.Write(writer, value.VerifyingKey)
}

type FfiDestroyerTypeFrostPublicKeyPackage struct{}

func (_ FfiDestroyerTypeFrostPublicKeyPackage) Destroy(value FrostPublicKeyPackage) {
	value.Destroy()
}

type FrostRandomizer struct {
	Data []byte
}

func (r *FrostRandomizer) Destroy() {
	FfiDestroyerBytes{}.Destroy(r.Data)
}

type FfiConverterTypeFrostRandomizer struct{}

var FfiConverterTypeFrostRandomizerINSTANCE = FfiConverterTypeFrostRandomizer{}

func (c FfiConverterTypeFrostRandomizer) Lift(rb RustBufferI) FrostRandomizer {
	return LiftFromRustBuffer[FrostRandomizer](c, rb)
}

func (c FfiConverterTypeFrostRandomizer) Read(reader io.Reader) FrostRandomizer {
	return FrostRandomizer{
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeFrostRandomizer) Lower(value FrostRandomizer) RustBuffer {
	return LowerIntoRustBuffer[FrostRandomizer](c, value)
}

func (c FfiConverterTypeFrostRandomizer) Write(writer io.Writer, value FrostRandomizer) {
	FfiConverterBytesINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeFrostRandomizer struct{}

func (_ FfiDestroyerTypeFrostRandomizer) Destroy(value FrostRandomizer) {
	value.Destroy()
}

type FrostSecretKeyShare struct {
	Identifier ParticipantIdentifier
	Data       []byte
}

func (r *FrostSecretKeyShare) Destroy() {
	FfiDestroyerTypeParticipantIdentifier{}.Destroy(r.Identifier)
	FfiDestroyerBytes{}.Destroy(r.Data)
}

type FfiConverterTypeFrostSecretKeyShare struct{}

var FfiConverterTypeFrostSecretKeyShareINSTANCE = FfiConverterTypeFrostSecretKeyShare{}

func (c FfiConverterTypeFrostSecretKeyShare) Lift(rb RustBufferI) FrostSecretKeyShare {
	return LiftFromRustBuffer[FrostSecretKeyShare](c, rb)
}

func (c FfiConverterTypeFrostSecretKeyShare) Read(reader io.Reader) FrostSecretKeyShare {
	return FrostSecretKeyShare{
		FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader),
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeFrostSecretKeyShare) Lower(value FrostSecretKeyShare) RustBuffer {
	return LowerIntoRustBuffer[FrostSecretKeyShare](c, value)
}

func (c FfiConverterTypeFrostSecretKeyShare) Write(writer io.Writer, value FrostSecretKeyShare) {
	FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, value.Identifier)
	FfiConverterBytesINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeFrostSecretKeyShare struct{}

func (_ FfiDestroyerTypeFrostSecretKeyShare) Destroy(value FrostSecretKeyShare) {
	value.Destroy()
}

type FrostSignature struct {
	Data []byte
}

func (r *FrostSignature) Destroy() {
	FfiDestroyerBytes{}.Destroy(r.Data)
}

type FfiConverterTypeFrostSignature struct{}

var FfiConverterTypeFrostSignatureINSTANCE = FfiConverterTypeFrostSignature{}

func (c FfiConverterTypeFrostSignature) Lift(rb RustBufferI) FrostSignature {
	return LiftFromRustBuffer[FrostSignature](c, rb)
}

func (c FfiConverterTypeFrostSignature) Read(reader io.Reader) FrostSignature {
	return FrostSignature{
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeFrostSignature) Lower(value FrostSignature) RustBuffer {
	return LowerIntoRustBuffer[FrostSignature](c, value)
}

func (c FfiConverterTypeFrostSignature) Write(writer io.Writer, value FrostSignature) {
	FfiConverterBytesINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeFrostSignature struct{}

func (_ FfiDestroyerTypeFrostSignature) Destroy(value FrostSignature) {
	value.Destroy()
}

type FrostSignatureShare struct {
	Identifier ParticipantIdentifier
	Data       []byte
}

func (r *FrostSignatureShare) Destroy() {
	FfiDestroyerTypeParticipantIdentifier{}.Destroy(r.Identifier)
	FfiDestroyerBytes{}.Destroy(r.Data)
}

type FfiConverterTypeFrostSignatureShare struct{}

var FfiConverterTypeFrostSignatureShareINSTANCE = FfiConverterTypeFrostSignatureShare{}

func (c FfiConverterTypeFrostSignatureShare) Lift(rb RustBufferI) FrostSignatureShare {
	return LiftFromRustBuffer[FrostSignatureShare](c, rb)
}

func (c FfiConverterTypeFrostSignatureShare) Read(reader io.Reader) FrostSignatureShare {
	return FrostSignatureShare{
		FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader),
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeFrostSignatureShare) Lower(value FrostSignatureShare) RustBuffer {
	return LowerIntoRustBuffer[FrostSignatureShare](c, value)
}

func (c FfiConverterTypeFrostSignatureShare) Write(writer io.Writer, value FrostSignatureShare) {
	FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, value.Identifier)
	FfiConverterBytesINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeFrostSignatureShare struct{}

func (_ FfiDestroyerTypeFrostSignatureShare) Destroy(value FrostSignatureShare) {
	value.Destroy()
}

type FrostSigningCommitments struct {
	Identifier ParticipantIdentifier
	Data       []byte
}

func (r *FrostSigningCommitments) Destroy() {
	FfiDestroyerTypeParticipantIdentifier{}.Destroy(r.Identifier)
	FfiDestroyerBytes{}.Destroy(r.Data)
}

type FfiConverterTypeFrostSigningCommitments struct{}

var FfiConverterTypeFrostSigningCommitmentsINSTANCE = FfiConverterTypeFrostSigningCommitments{}

func (c FfiConverterTypeFrostSigningCommitments) Lift(rb RustBufferI) FrostSigningCommitments {
	return LiftFromRustBuffer[FrostSigningCommitments](c, rb)
}

func (c FfiConverterTypeFrostSigningCommitments) Read(reader io.Reader) FrostSigningCommitments {
	return FrostSigningCommitments{
		FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader),
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeFrostSigningCommitments) Lower(value FrostSigningCommitments) RustBuffer {
	return LowerIntoRustBuffer[FrostSigningCommitments](c, value)
}

func (c FfiConverterTypeFrostSigningCommitments) Write(writer io.Writer, value FrostSigningCommitments) {
	FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, value.Identifier)
	FfiConverterBytesINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeFrostSigningCommitments struct{}

func (_ FfiDestroyerTypeFrostSigningCommitments) Destroy(value FrostSigningCommitments) {
	value.Destroy()
}

type FrostSigningNonces struct {
	Data []byte
}

func (r *FrostSigningNonces) Destroy() {
	FfiDestroyerBytes{}.Destroy(r.Data)
}

type FfiConverterTypeFrostSigningNonces struct{}

var FfiConverterTypeFrostSigningNoncesINSTANCE = FfiConverterTypeFrostSigningNonces{}

func (c FfiConverterTypeFrostSigningNonces) Lift(rb RustBufferI) FrostSigningNonces {
	return LiftFromRustBuffer[FrostSigningNonces](c, rb)
}

func (c FfiConverterTypeFrostSigningNonces) Read(reader io.Reader) FrostSigningNonces {
	return FrostSigningNonces{
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeFrostSigningNonces) Lower(value FrostSigningNonces) RustBuffer {
	return LowerIntoRustBuffer[FrostSigningNonces](c, value)
}

func (c FfiConverterTypeFrostSigningNonces) Write(writer io.Writer, value FrostSigningNonces) {
	FfiConverterBytesINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeFrostSigningNonces struct{}

func (_ FfiDestroyerTypeFrostSigningNonces) Destroy(value FrostSigningNonces) {
	value.Destroy()
}

type FrostSigningPackage struct {
	Data []byte
}

func (r *FrostSigningPackage) Destroy() {
	FfiDestroyerBytes{}.Destroy(r.Data)
}

type FfiConverterTypeFrostSigningPackage struct{}

var FfiConverterTypeFrostSigningPackageINSTANCE = FfiConverterTypeFrostSigningPackage{}

func (c FfiConverterTypeFrostSigningPackage) Lift(rb RustBufferI) FrostSigningPackage {
	return LiftFromRustBuffer[FrostSigningPackage](c, rb)
}

func (c FfiConverterTypeFrostSigningPackage) Read(reader io.Reader) FrostSigningPackage {
	return FrostSigningPackage{
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeFrostSigningPackage) Lower(value FrostSigningPackage) RustBuffer {
	return LowerIntoRustBuffer[FrostSigningPackage](c, value)
}

func (c FfiConverterTypeFrostSigningPackage) Write(writer io.Writer, value FrostSigningPackage) {
	FfiConverterBytesINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeFrostSigningPackage struct{}

func (_ FfiDestroyerTypeFrostSigningPackage) Destroy(value FrostSigningPackage) {
	value.Destroy()
}

type Message struct {
	Data []byte
}

func (r *Message) Destroy() {
	FfiDestroyerBytes{}.Destroy(r.Data)
}

type FfiConverterTypeMessage struct{}

var FfiConverterTypeMessageINSTANCE = FfiConverterTypeMessage{}

func (c FfiConverterTypeMessage) Lift(rb RustBufferI) Message {
	return LiftFromRustBuffer[Message](c, rb)
}

func (c FfiConverterTypeMessage) Read(reader io.Reader) Message {
	return Message{
		FfiConverterBytesINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeMessage) Lower(value Message) RustBuffer {
	return LowerIntoRustBuffer[Message](c, value)
}

func (c FfiConverterTypeMessage) Write(writer io.Writer, value Message) {
	FfiConverterBytesINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeMessage struct{}

func (_ FfiDestroyerTypeMessage) Destroy(value Message) {
	value.Destroy()
}

type ParticipantIdentifier struct {
	Data string
}

func (r *ParticipantIdentifier) Destroy() {
	FfiDestroyerString{}.Destroy(r.Data)
}

type FfiConverterTypeParticipantIdentifier struct{}

var FfiConverterTypeParticipantIdentifierINSTANCE = FfiConverterTypeParticipantIdentifier{}

func (c FfiConverterTypeParticipantIdentifier) Lift(rb RustBufferI) ParticipantIdentifier {
	return LiftFromRustBuffer[ParticipantIdentifier](c, rb)
}

func (c FfiConverterTypeParticipantIdentifier) Read(reader io.Reader) ParticipantIdentifier {
	return ParticipantIdentifier{
		FfiConverterStringINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeParticipantIdentifier) Lower(value ParticipantIdentifier) RustBuffer {
	return LowerIntoRustBuffer[ParticipantIdentifier](c, value)
}

func (c FfiConverterTypeParticipantIdentifier) Write(writer io.Writer, value ParticipantIdentifier) {
	FfiConverterStringINSTANCE.Write(writer, value.Data)
}

type FfiDestroyerTypeParticipantIdentifier struct{}

func (_ FfiDestroyerTypeParticipantIdentifier) Destroy(value ParticipantIdentifier) {
	value.Destroy()
}

type ParticipantList struct {
	Identifiers []ParticipantIdentifier
}

func (r *ParticipantList) Destroy() {
	FfiDestroyerSequenceTypeParticipantIdentifier{}.Destroy(r.Identifiers)
}

type FfiConverterTypeParticipantList struct{}

var FfiConverterTypeParticipantListINSTANCE = FfiConverterTypeParticipantList{}

func (c FfiConverterTypeParticipantList) Lift(rb RustBufferI) ParticipantList {
	return LiftFromRustBuffer[ParticipantList](c, rb)
}

func (c FfiConverterTypeParticipantList) Read(reader io.Reader) ParticipantList {
	return ParticipantList{
		FfiConverterSequenceTypeParticipantIdentifierINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeParticipantList) Lower(value ParticipantList) RustBuffer {
	return LowerIntoRustBuffer[ParticipantList](c, value)
}

func (c FfiConverterTypeParticipantList) Write(writer io.Writer, value ParticipantList) {
	FfiConverterSequenceTypeParticipantIdentifierINSTANCE.Write(writer, value.Identifiers)
}

type FfiDestroyerTypeParticipantList struct{}

func (_ FfiDestroyerTypeParticipantList) Destroy(value ParticipantList) {
	value.Destroy()
}

type TrustedKeyGeneration struct {
	SecretShares     map[ParticipantIdentifier]FrostSecretKeyShare
	PublicKeyPackage FrostPublicKeyPackage
}

func (r *TrustedKeyGeneration) Destroy() {
	FfiDestroyerMapTypeParticipantIdentifierTypeFrostSecretKeyShare{}.Destroy(r.SecretShares)
	FfiDestroyerTypeFrostPublicKeyPackage{}.Destroy(r.PublicKeyPackage)
}

type FfiConverterTypeTrustedKeyGeneration struct{}

var FfiConverterTypeTrustedKeyGenerationINSTANCE = FfiConverterTypeTrustedKeyGeneration{}

func (c FfiConverterTypeTrustedKeyGeneration) Lift(rb RustBufferI) TrustedKeyGeneration {
	return LiftFromRustBuffer[TrustedKeyGeneration](c, rb)
}

func (c FfiConverterTypeTrustedKeyGeneration) Read(reader io.Reader) TrustedKeyGeneration {
	return TrustedKeyGeneration{
		FfiConverterMapTypeParticipantIdentifierTypeFrostSecretKeyShareINSTANCE.Read(reader),
		FfiConverterTypeFrostPublicKeyPackageINSTANCE.Read(reader),
	}
}

func (c FfiConverterTypeTrustedKeyGeneration) Lower(value TrustedKeyGeneration) RustBuffer {
	return LowerIntoRustBuffer[TrustedKeyGeneration](c, value)
}

func (c FfiConverterTypeTrustedKeyGeneration) Write(writer io.Writer, value TrustedKeyGeneration) {
	FfiConverterMapTypeParticipantIdentifierTypeFrostSecretKeyShareINSTANCE.Write(writer, value.SecretShares)
	FfiConverterTypeFrostPublicKeyPackageINSTANCE.Write(writer, value.PublicKeyPackage)
}

type FfiDestroyerTypeTrustedKeyGeneration struct{}

func (_ FfiDestroyerTypeTrustedKeyGeneration) Destroy(value TrustedKeyGeneration) {
	value.Destroy()
}

type ConfigurationError struct {
	err error
}

func (err ConfigurationError) Error() string {
	return fmt.Sprintf("ConfigurationError: %s", err.err.Error())
}

func (err ConfigurationError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrConfigurationErrorInvalidMaxSigners = fmt.Errorf("ConfigurationErrorInvalidMaxSigners")
var ErrConfigurationErrorInvalidMinSigners = fmt.Errorf("ConfigurationErrorInvalidMinSigners")
var ErrConfigurationErrorInvalidIdentifier = fmt.Errorf("ConfigurationErrorInvalidIdentifier")
var ErrConfigurationErrorUnknownError = fmt.Errorf("ConfigurationErrorUnknownError")

// Variant structs
type ConfigurationErrorInvalidMaxSigners struct {
}

func NewConfigurationErrorInvalidMaxSigners() *ConfigurationError {
	return &ConfigurationError{
		err: &ConfigurationErrorInvalidMaxSigners{},
	}
}

func (err ConfigurationErrorInvalidMaxSigners) Error() string {
	return fmt.Sprint("InvalidMaxSigners")
}

func (self ConfigurationErrorInvalidMaxSigners) Is(target error) bool {
	return target == ErrConfigurationErrorInvalidMaxSigners
}

type ConfigurationErrorInvalidMinSigners struct {
}

func NewConfigurationErrorInvalidMinSigners() *ConfigurationError {
	return &ConfigurationError{
		err: &ConfigurationErrorInvalidMinSigners{},
	}
}

func (err ConfigurationErrorInvalidMinSigners) Error() string {
	return fmt.Sprint("InvalidMinSigners")
}

func (self ConfigurationErrorInvalidMinSigners) Is(target error) bool {
	return target == ErrConfigurationErrorInvalidMinSigners
}

type ConfigurationErrorInvalidIdentifier struct {
}

func NewConfigurationErrorInvalidIdentifier() *ConfigurationError {
	return &ConfigurationError{
		err: &ConfigurationErrorInvalidIdentifier{},
	}
}

func (err ConfigurationErrorInvalidIdentifier) Error() string {
	return fmt.Sprint("InvalidIdentifier")
}

func (self ConfigurationErrorInvalidIdentifier) Is(target error) bool {
	return target == ErrConfigurationErrorInvalidIdentifier
}

type ConfigurationErrorUnknownError struct {
}

func NewConfigurationErrorUnknownError() *ConfigurationError {
	return &ConfigurationError{
		err: &ConfigurationErrorUnknownError{},
	}
}

func (err ConfigurationErrorUnknownError) Error() string {
	return fmt.Sprint("UnknownError")
}

func (self ConfigurationErrorUnknownError) Is(target error) bool {
	return target == ErrConfigurationErrorUnknownError
}

type FfiConverterTypeConfigurationError struct{}

var FfiConverterTypeConfigurationErrorINSTANCE = FfiConverterTypeConfigurationError{}

func (c FfiConverterTypeConfigurationError) Lift(eb RustBufferI) error {
	return LiftFromRustBuffer[error](c, eb)
}

func (c FfiConverterTypeConfigurationError) Lower(value *ConfigurationError) RustBuffer {
	return LowerIntoRustBuffer[*ConfigurationError](c, value)
}

func (c FfiConverterTypeConfigurationError) Read(reader io.Reader) error {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &ConfigurationError{&ConfigurationErrorInvalidMaxSigners{}}
	case 2:
		return &ConfigurationError{&ConfigurationErrorInvalidMinSigners{}}
	case 3:
		return &ConfigurationError{&ConfigurationErrorInvalidIdentifier{}}
	case 4:
		return &ConfigurationError{&ConfigurationErrorUnknownError{}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterTypeConfigurationError.Read()", errorID))
	}
}

func (c FfiConverterTypeConfigurationError) Write(writer io.Writer, value *ConfigurationError) {
	switch variantValue := value.err.(type) {
	case *ConfigurationErrorInvalidMaxSigners:
		writeInt32(writer, 1)
	case *ConfigurationErrorInvalidMinSigners:
		writeInt32(writer, 2)
	case *ConfigurationErrorInvalidIdentifier:
		writeInt32(writer, 3)
	case *ConfigurationErrorUnknownError:
		writeInt32(writer, 4)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterTypeConfigurationError.Write", value))
	}
}

type CoordinationError struct {
	err error
}

func (err CoordinationError) Error() string {
	return fmt.Sprintf("CoordinationError: %s", err.err.Error())
}

func (err CoordinationError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrCoordinationErrorFailedToCreateSigningPackage = fmt.Errorf("CoordinationErrorFailedToCreateSigningPackage")
var ErrCoordinationErrorInvalidSigningCommitment = fmt.Errorf("CoordinationErrorInvalidSigningCommitment")
var ErrCoordinationErrorIdentifierDeserializationError = fmt.Errorf("CoordinationErrorIdentifierDeserializationError")
var ErrCoordinationErrorSigningPackageSerializationError = fmt.Errorf("CoordinationErrorSigningPackageSerializationError")
var ErrCoordinationErrorSignatureShareDeserializationError = fmt.Errorf("CoordinationErrorSignatureShareDeserializationError")
var ErrCoordinationErrorPublicKeyPackageDeserializationError = fmt.Errorf("CoordinationErrorPublicKeyPackageDeserializationError")
var ErrCoordinationErrorSignatureShareAggregationFailed = fmt.Errorf("CoordinationErrorSignatureShareAggregationFailed")
var ErrCoordinationErrorInvalidRandomizer = fmt.Errorf("CoordinationErrorInvalidRandomizer")

// Variant structs
type CoordinationErrorFailedToCreateSigningPackage struct {
}

func NewCoordinationErrorFailedToCreateSigningPackage() *CoordinationError {
	return &CoordinationError{
		err: &CoordinationErrorFailedToCreateSigningPackage{},
	}
}

func (err CoordinationErrorFailedToCreateSigningPackage) Error() string {
	return fmt.Sprint("FailedToCreateSigningPackage")
}

func (self CoordinationErrorFailedToCreateSigningPackage) Is(target error) bool {
	return target == ErrCoordinationErrorFailedToCreateSigningPackage
}

type CoordinationErrorInvalidSigningCommitment struct {
}

func NewCoordinationErrorInvalidSigningCommitment() *CoordinationError {
	return &CoordinationError{
		err: &CoordinationErrorInvalidSigningCommitment{},
	}
}

func (err CoordinationErrorInvalidSigningCommitment) Error() string {
	return fmt.Sprint("InvalidSigningCommitment")
}

func (self CoordinationErrorInvalidSigningCommitment) Is(target error) bool {
	return target == ErrCoordinationErrorInvalidSigningCommitment
}

type CoordinationErrorIdentifierDeserializationError struct {
}

func NewCoordinationErrorIdentifierDeserializationError() *CoordinationError {
	return &CoordinationError{
		err: &CoordinationErrorIdentifierDeserializationError{},
	}
}

func (err CoordinationErrorIdentifierDeserializationError) Error() string {
	return fmt.Sprint("IdentifierDeserializationError")
}

func (self CoordinationErrorIdentifierDeserializationError) Is(target error) bool {
	return target == ErrCoordinationErrorIdentifierDeserializationError
}

type CoordinationErrorSigningPackageSerializationError struct {
}

func NewCoordinationErrorSigningPackageSerializationError() *CoordinationError {
	return &CoordinationError{
		err: &CoordinationErrorSigningPackageSerializationError{},
	}
}

func (err CoordinationErrorSigningPackageSerializationError) Error() string {
	return fmt.Sprint("SigningPackageSerializationError")
}

func (self CoordinationErrorSigningPackageSerializationError) Is(target error) bool {
	return target == ErrCoordinationErrorSigningPackageSerializationError
}

type CoordinationErrorSignatureShareDeserializationError struct {
}

func NewCoordinationErrorSignatureShareDeserializationError() *CoordinationError {
	return &CoordinationError{
		err: &CoordinationErrorSignatureShareDeserializationError{},
	}
}

func (err CoordinationErrorSignatureShareDeserializationError) Error() string {
	return fmt.Sprint("SignatureShareDeserializationError")
}

func (self CoordinationErrorSignatureShareDeserializationError) Is(target error) bool {
	return target == ErrCoordinationErrorSignatureShareDeserializationError
}

type CoordinationErrorPublicKeyPackageDeserializationError struct {
}

func NewCoordinationErrorPublicKeyPackageDeserializationError() *CoordinationError {
	return &CoordinationError{
		err: &CoordinationErrorPublicKeyPackageDeserializationError{},
	}
}

func (err CoordinationErrorPublicKeyPackageDeserializationError) Error() string {
	return fmt.Sprint("PublicKeyPackageDeserializationError")
}

func (self CoordinationErrorPublicKeyPackageDeserializationError) Is(target error) bool {
	return target == ErrCoordinationErrorPublicKeyPackageDeserializationError
}

type CoordinationErrorSignatureShareAggregationFailed struct {
	Message string
}

func NewCoordinationErrorSignatureShareAggregationFailed(
	message string,
) *CoordinationError {
	return &CoordinationError{
		err: &CoordinationErrorSignatureShareAggregationFailed{
			Message: message,
		},
	}
}

func (err CoordinationErrorSignatureShareAggregationFailed) Error() string {
	return fmt.Sprint("SignatureShareAggregationFailed",
		": ",

		"Message=",
		err.Message,
	)
}

func (self CoordinationErrorSignatureShareAggregationFailed) Is(target error) bool {
	return target == ErrCoordinationErrorSignatureShareAggregationFailed
}

type CoordinationErrorInvalidRandomizer struct {
}

func NewCoordinationErrorInvalidRandomizer() *CoordinationError {
	return &CoordinationError{
		err: &CoordinationErrorInvalidRandomizer{},
	}
}

func (err CoordinationErrorInvalidRandomizer) Error() string {
	return fmt.Sprint("InvalidRandomizer")
}

func (self CoordinationErrorInvalidRandomizer) Is(target error) bool {
	return target == ErrCoordinationErrorInvalidRandomizer
}

type FfiConverterTypeCoordinationError struct{}

var FfiConverterTypeCoordinationErrorINSTANCE = FfiConverterTypeCoordinationError{}

func (c FfiConverterTypeCoordinationError) Lift(eb RustBufferI) error {
	return LiftFromRustBuffer[error](c, eb)
}

func (c FfiConverterTypeCoordinationError) Lower(value *CoordinationError) RustBuffer {
	return LowerIntoRustBuffer[*CoordinationError](c, value)
}

func (c FfiConverterTypeCoordinationError) Read(reader io.Reader) error {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &CoordinationError{&CoordinationErrorFailedToCreateSigningPackage{}}
	case 2:
		return &CoordinationError{&CoordinationErrorInvalidSigningCommitment{}}
	case 3:
		return &CoordinationError{&CoordinationErrorIdentifierDeserializationError{}}
	case 4:
		return &CoordinationError{&CoordinationErrorSigningPackageSerializationError{}}
	case 5:
		return &CoordinationError{&CoordinationErrorSignatureShareDeserializationError{}}
	case 6:
		return &CoordinationError{&CoordinationErrorPublicKeyPackageDeserializationError{}}
	case 7:
		return &CoordinationError{&CoordinationErrorSignatureShareAggregationFailed{
			Message: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 8:
		return &CoordinationError{&CoordinationErrorInvalidRandomizer{}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterTypeCoordinationError.Read()", errorID))
	}
}

func (c FfiConverterTypeCoordinationError) Write(writer io.Writer, value *CoordinationError) {
	switch variantValue := value.err.(type) {
	case *CoordinationErrorFailedToCreateSigningPackage:
		writeInt32(writer, 1)
	case *CoordinationErrorInvalidSigningCommitment:
		writeInt32(writer, 2)
	case *CoordinationErrorIdentifierDeserializationError:
		writeInt32(writer, 3)
	case *CoordinationErrorSigningPackageSerializationError:
		writeInt32(writer, 4)
	case *CoordinationErrorSignatureShareDeserializationError:
		writeInt32(writer, 5)
	case *CoordinationErrorPublicKeyPackageDeserializationError:
		writeInt32(writer, 6)
	case *CoordinationErrorSignatureShareAggregationFailed:
		writeInt32(writer, 7)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Message)
	case *CoordinationErrorInvalidRandomizer:
		writeInt32(writer, 8)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterTypeCoordinationError.Write", value))
	}
}

type FrostError struct {
	err error
}

func (err FrostError) Error() string {
	return fmt.Sprintf("FrostError: %s", err.err.Error())
}

func (err FrostError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrFrostErrorInvalidMinSigners = fmt.Errorf("FrostErrorInvalidMinSigners")
var ErrFrostErrorInvalidMaxSigners = fmt.Errorf("FrostErrorInvalidMaxSigners")
var ErrFrostErrorInvalidCoefficients = fmt.Errorf("FrostErrorInvalidCoefficients")
var ErrFrostErrorMalformedIdentifier = fmt.Errorf("FrostErrorMalformedIdentifier")
var ErrFrostErrorDuplicatedIdentifier = fmt.Errorf("FrostErrorDuplicatedIdentifier")
var ErrFrostErrorUnknownIdentifier = fmt.Errorf("FrostErrorUnknownIdentifier")
var ErrFrostErrorIncorrectNumberOfIdentifiers = fmt.Errorf("FrostErrorIncorrectNumberOfIdentifiers")
var ErrFrostErrorMalformedSigningKey = fmt.Errorf("FrostErrorMalformedSigningKey")
var ErrFrostErrorMalformedVerifyingKey = fmt.Errorf("FrostErrorMalformedVerifyingKey")
var ErrFrostErrorMalformedSignature = fmt.Errorf("FrostErrorMalformedSignature")
var ErrFrostErrorInvalidSignature = fmt.Errorf("FrostErrorInvalidSignature")
var ErrFrostErrorDuplicatedShares = fmt.Errorf("FrostErrorDuplicatedShares")
var ErrFrostErrorIncorrectNumberOfShares = fmt.Errorf("FrostErrorIncorrectNumberOfShares")
var ErrFrostErrorIdentityCommitment = fmt.Errorf("FrostErrorIdentityCommitment")
var ErrFrostErrorMissingCommitment = fmt.Errorf("FrostErrorMissingCommitment")
var ErrFrostErrorIncorrectCommitment = fmt.Errorf("FrostErrorIncorrectCommitment")
var ErrFrostErrorIncorrectNumberOfCommitments = fmt.Errorf("FrostErrorIncorrectNumberOfCommitments")
var ErrFrostErrorInvalidSignatureShare = fmt.Errorf("FrostErrorInvalidSignatureShare")
var ErrFrostErrorInvalidSecretShare = fmt.Errorf("FrostErrorInvalidSecretShare")
var ErrFrostErrorPackageNotFound = fmt.Errorf("FrostErrorPackageNotFound")
var ErrFrostErrorIncorrectNumberOfPackages = fmt.Errorf("FrostErrorIncorrectNumberOfPackages")
var ErrFrostErrorIncorrectPackage = fmt.Errorf("FrostErrorIncorrectPackage")
var ErrFrostErrorDkgNotSupported = fmt.Errorf("FrostErrorDkgNotSupported")
var ErrFrostErrorInvalidProofOfKnowledge = fmt.Errorf("FrostErrorInvalidProofOfKnowledge")
var ErrFrostErrorFieldError = fmt.Errorf("FrostErrorFieldError")
var ErrFrostErrorGroupError = fmt.Errorf("FrostErrorGroupError")
var ErrFrostErrorInvalidCoefficient = fmt.Errorf("FrostErrorInvalidCoefficient")
var ErrFrostErrorIdentifierDerivationNotSupported = fmt.Errorf("FrostErrorIdentifierDerivationNotSupported")
var ErrFrostErrorSerializationError = fmt.Errorf("FrostErrorSerializationError")
var ErrFrostErrorDeserializationError = fmt.Errorf("FrostErrorDeserializationError")
var ErrFrostErrorDkgPart2IncorrectNumberOfCommitments = fmt.Errorf("FrostErrorDkgPart2IncorrectNumberOfCommitments")
var ErrFrostErrorDkgPart2IncorrectNumberOfPackages = fmt.Errorf("FrostErrorDkgPart2IncorrectNumberOfPackages")
var ErrFrostErrorDkgPart3IncorrectRound1Packages = fmt.Errorf("FrostErrorDkgPart3IncorrectRound1Packages")
var ErrFrostErrorDkgPart3IncorrectNumberOfPackages = fmt.Errorf("FrostErrorDkgPart3IncorrectNumberOfPackages")
var ErrFrostErrorDkgPart3PackageSendersMismatch = fmt.Errorf("FrostErrorDkgPart3PackageSendersMismatch")
var ErrFrostErrorInvalidKeyPackage = fmt.Errorf("FrostErrorInvalidKeyPackage")
var ErrFrostErrorInvalidSecretKey = fmt.Errorf("FrostErrorInvalidSecretKey")
var ErrFrostErrorInvalidConfiguration = fmt.Errorf("FrostErrorInvalidConfiguration")
var ErrFrostErrorUnexpectedError = fmt.Errorf("FrostErrorUnexpectedError")

// Variant structs
type FrostErrorInvalidMinSigners struct {
}

func NewFrostErrorInvalidMinSigners() *FrostError {
	return &FrostError{
		err: &FrostErrorInvalidMinSigners{},
	}
}

func (err FrostErrorInvalidMinSigners) Error() string {
	return fmt.Sprint("InvalidMinSigners")
}

func (self FrostErrorInvalidMinSigners) Is(target error) bool {
	return target == ErrFrostErrorInvalidMinSigners
}

type FrostErrorInvalidMaxSigners struct {
}

func NewFrostErrorInvalidMaxSigners() *FrostError {
	return &FrostError{
		err: &FrostErrorInvalidMaxSigners{},
	}
}

func (err FrostErrorInvalidMaxSigners) Error() string {
	return fmt.Sprint("InvalidMaxSigners")
}

func (self FrostErrorInvalidMaxSigners) Is(target error) bool {
	return target == ErrFrostErrorInvalidMaxSigners
}

type FrostErrorInvalidCoefficients struct {
}

func NewFrostErrorInvalidCoefficients() *FrostError {
	return &FrostError{
		err: &FrostErrorInvalidCoefficients{},
	}
}

func (err FrostErrorInvalidCoefficients) Error() string {
	return fmt.Sprint("InvalidCoefficients")
}

func (self FrostErrorInvalidCoefficients) Is(target error) bool {
	return target == ErrFrostErrorInvalidCoefficients
}

type FrostErrorMalformedIdentifier struct {
}

func NewFrostErrorMalformedIdentifier() *FrostError {
	return &FrostError{
		err: &FrostErrorMalformedIdentifier{},
	}
}

func (err FrostErrorMalformedIdentifier) Error() string {
	return fmt.Sprint("MalformedIdentifier")
}

func (self FrostErrorMalformedIdentifier) Is(target error) bool {
	return target == ErrFrostErrorMalformedIdentifier
}

type FrostErrorDuplicatedIdentifier struct {
}

func NewFrostErrorDuplicatedIdentifier() *FrostError {
	return &FrostError{
		err: &FrostErrorDuplicatedIdentifier{},
	}
}

func (err FrostErrorDuplicatedIdentifier) Error() string {
	return fmt.Sprint("DuplicatedIdentifier")
}

func (self FrostErrorDuplicatedIdentifier) Is(target error) bool {
	return target == ErrFrostErrorDuplicatedIdentifier
}

type FrostErrorUnknownIdentifier struct {
}

func NewFrostErrorUnknownIdentifier() *FrostError {
	return &FrostError{
		err: &FrostErrorUnknownIdentifier{},
	}
}

func (err FrostErrorUnknownIdentifier) Error() string {
	return fmt.Sprint("UnknownIdentifier")
}

func (self FrostErrorUnknownIdentifier) Is(target error) bool {
	return target == ErrFrostErrorUnknownIdentifier
}

type FrostErrorIncorrectNumberOfIdentifiers struct {
}

func NewFrostErrorIncorrectNumberOfIdentifiers() *FrostError {
	return &FrostError{
		err: &FrostErrorIncorrectNumberOfIdentifiers{},
	}
}

func (err FrostErrorIncorrectNumberOfIdentifiers) Error() string {
	return fmt.Sprint("IncorrectNumberOfIdentifiers")
}

func (self FrostErrorIncorrectNumberOfIdentifiers) Is(target error) bool {
	return target == ErrFrostErrorIncorrectNumberOfIdentifiers
}

type FrostErrorMalformedSigningKey struct {
}

func NewFrostErrorMalformedSigningKey() *FrostError {
	return &FrostError{
		err: &FrostErrorMalformedSigningKey{},
	}
}

func (err FrostErrorMalformedSigningKey) Error() string {
	return fmt.Sprint("MalformedSigningKey")
}

func (self FrostErrorMalformedSigningKey) Is(target error) bool {
	return target == ErrFrostErrorMalformedSigningKey
}

type FrostErrorMalformedVerifyingKey struct {
}

func NewFrostErrorMalformedVerifyingKey() *FrostError {
	return &FrostError{
		err: &FrostErrorMalformedVerifyingKey{},
	}
}

func (err FrostErrorMalformedVerifyingKey) Error() string {
	return fmt.Sprint("MalformedVerifyingKey")
}

func (self FrostErrorMalformedVerifyingKey) Is(target error) bool {
	return target == ErrFrostErrorMalformedVerifyingKey
}

type FrostErrorMalformedSignature struct {
}

func NewFrostErrorMalformedSignature() *FrostError {
	return &FrostError{
		err: &FrostErrorMalformedSignature{},
	}
}

func (err FrostErrorMalformedSignature) Error() string {
	return fmt.Sprint("MalformedSignature")
}

func (self FrostErrorMalformedSignature) Is(target error) bool {
	return target == ErrFrostErrorMalformedSignature
}

type FrostErrorInvalidSignature struct {
}

func NewFrostErrorInvalidSignature() *FrostError {
	return &FrostError{
		err: &FrostErrorInvalidSignature{},
	}
}

func (err FrostErrorInvalidSignature) Error() string {
	return fmt.Sprint("InvalidSignature")
}

func (self FrostErrorInvalidSignature) Is(target error) bool {
	return target == ErrFrostErrorInvalidSignature
}

type FrostErrorDuplicatedShares struct {
}

func NewFrostErrorDuplicatedShares() *FrostError {
	return &FrostError{
		err: &FrostErrorDuplicatedShares{},
	}
}

func (err FrostErrorDuplicatedShares) Error() string {
	return fmt.Sprint("DuplicatedShares")
}

func (self FrostErrorDuplicatedShares) Is(target error) bool {
	return target == ErrFrostErrorDuplicatedShares
}

type FrostErrorIncorrectNumberOfShares struct {
}

func NewFrostErrorIncorrectNumberOfShares() *FrostError {
	return &FrostError{
		err: &FrostErrorIncorrectNumberOfShares{},
	}
}

func (err FrostErrorIncorrectNumberOfShares) Error() string {
	return fmt.Sprint("IncorrectNumberOfShares")
}

func (self FrostErrorIncorrectNumberOfShares) Is(target error) bool {
	return target == ErrFrostErrorIncorrectNumberOfShares
}

type FrostErrorIdentityCommitment struct {
}

func NewFrostErrorIdentityCommitment() *FrostError {
	return &FrostError{
		err: &FrostErrorIdentityCommitment{},
	}
}

func (err FrostErrorIdentityCommitment) Error() string {
	return fmt.Sprint("IdentityCommitment")
}

func (self FrostErrorIdentityCommitment) Is(target error) bool {
	return target == ErrFrostErrorIdentityCommitment
}

type FrostErrorMissingCommitment struct {
}

func NewFrostErrorMissingCommitment() *FrostError {
	return &FrostError{
		err: &FrostErrorMissingCommitment{},
	}
}

func (err FrostErrorMissingCommitment) Error() string {
	return fmt.Sprint("MissingCommitment")
}

func (self FrostErrorMissingCommitment) Is(target error) bool {
	return target == ErrFrostErrorMissingCommitment
}

type FrostErrorIncorrectCommitment struct {
}

func NewFrostErrorIncorrectCommitment() *FrostError {
	return &FrostError{
		err: &FrostErrorIncorrectCommitment{},
	}
}

func (err FrostErrorIncorrectCommitment) Error() string {
	return fmt.Sprint("IncorrectCommitment")
}

func (self FrostErrorIncorrectCommitment) Is(target error) bool {
	return target == ErrFrostErrorIncorrectCommitment
}

type FrostErrorIncorrectNumberOfCommitments struct {
}

func NewFrostErrorIncorrectNumberOfCommitments() *FrostError {
	return &FrostError{
		err: &FrostErrorIncorrectNumberOfCommitments{},
	}
}

func (err FrostErrorIncorrectNumberOfCommitments) Error() string {
	return fmt.Sprint("IncorrectNumberOfCommitments")
}

func (self FrostErrorIncorrectNumberOfCommitments) Is(target error) bool {
	return target == ErrFrostErrorIncorrectNumberOfCommitments
}

type FrostErrorInvalidSignatureShare struct {
	Culprit ParticipantIdentifier
}

func NewFrostErrorInvalidSignatureShare(
	culprit ParticipantIdentifier,
) *FrostError {
	return &FrostError{
		err: &FrostErrorInvalidSignatureShare{
			Culprit: culprit,
		},
	}
}

func (err FrostErrorInvalidSignatureShare) Error() string {
	return fmt.Sprint("InvalidSignatureShare",
		": ",

		"Culprit=",
		err.Culprit,
	)
}

func (self FrostErrorInvalidSignatureShare) Is(target error) bool {
	return target == ErrFrostErrorInvalidSignatureShare
}

type FrostErrorInvalidSecretShare struct {
}

func NewFrostErrorInvalidSecretShare() *FrostError {
	return &FrostError{
		err: &FrostErrorInvalidSecretShare{},
	}
}

func (err FrostErrorInvalidSecretShare) Error() string {
	return fmt.Sprint("InvalidSecretShare")
}

func (self FrostErrorInvalidSecretShare) Is(target error) bool {
	return target == ErrFrostErrorInvalidSecretShare
}

type FrostErrorPackageNotFound struct {
}

func NewFrostErrorPackageNotFound() *FrostError {
	return &FrostError{
		err: &FrostErrorPackageNotFound{},
	}
}

func (err FrostErrorPackageNotFound) Error() string {
	return fmt.Sprint("PackageNotFound")
}

func (self FrostErrorPackageNotFound) Is(target error) bool {
	return target == ErrFrostErrorPackageNotFound
}

type FrostErrorIncorrectNumberOfPackages struct {
}

func NewFrostErrorIncorrectNumberOfPackages() *FrostError {
	return &FrostError{
		err: &FrostErrorIncorrectNumberOfPackages{},
	}
}

func (err FrostErrorIncorrectNumberOfPackages) Error() string {
	return fmt.Sprint("IncorrectNumberOfPackages")
}

func (self FrostErrorIncorrectNumberOfPackages) Is(target error) bool {
	return target == ErrFrostErrorIncorrectNumberOfPackages
}

type FrostErrorIncorrectPackage struct {
}

func NewFrostErrorIncorrectPackage() *FrostError {
	return &FrostError{
		err: &FrostErrorIncorrectPackage{},
	}
}

func (err FrostErrorIncorrectPackage) Error() string {
	return fmt.Sprint("IncorrectPackage")
}

func (self FrostErrorIncorrectPackage) Is(target error) bool {
	return target == ErrFrostErrorIncorrectPackage
}

type FrostErrorDkgNotSupported struct {
}

func NewFrostErrorDkgNotSupported() *FrostError {
	return &FrostError{
		err: &FrostErrorDkgNotSupported{},
	}
}

func (err FrostErrorDkgNotSupported) Error() string {
	return fmt.Sprint("DkgNotSupported")
}

func (self FrostErrorDkgNotSupported) Is(target error) bool {
	return target == ErrFrostErrorDkgNotSupported
}

type FrostErrorInvalidProofOfKnowledge struct {
	Culprit ParticipantIdentifier
}

func NewFrostErrorInvalidProofOfKnowledge(
	culprit ParticipantIdentifier,
) *FrostError {
	return &FrostError{
		err: &FrostErrorInvalidProofOfKnowledge{
			Culprit: culprit,
		},
	}
}

func (err FrostErrorInvalidProofOfKnowledge) Error() string {
	return fmt.Sprint("InvalidProofOfKnowledge",
		": ",

		"Culprit=",
		err.Culprit,
	)
}

func (self FrostErrorInvalidProofOfKnowledge) Is(target error) bool {
	return target == ErrFrostErrorInvalidProofOfKnowledge
}

type FrostErrorFieldError struct {
	Message string
}

func NewFrostErrorFieldError(
	message string,
) *FrostError {
	return &FrostError{
		err: &FrostErrorFieldError{
			Message: message,
		},
	}
}

func (err FrostErrorFieldError) Error() string {
	return fmt.Sprint("FieldError",
		": ",

		"Message=",
		err.Message,
	)
}

func (self FrostErrorFieldError) Is(target error) bool {
	return target == ErrFrostErrorFieldError
}

type FrostErrorGroupError struct {
	Message string
}

func NewFrostErrorGroupError(
	message string,
) *FrostError {
	return &FrostError{
		err: &FrostErrorGroupError{
			Message: message,
		},
	}
}

func (err FrostErrorGroupError) Error() string {
	return fmt.Sprint("GroupError",
		": ",

		"Message=",
		err.Message,
	)
}

func (self FrostErrorGroupError) Is(target error) bool {
	return target == ErrFrostErrorGroupError
}

type FrostErrorInvalidCoefficient struct {
}

func NewFrostErrorInvalidCoefficient() *FrostError {
	return &FrostError{
		err: &FrostErrorInvalidCoefficient{},
	}
}

func (err FrostErrorInvalidCoefficient) Error() string {
	return fmt.Sprint("InvalidCoefficient")
}

func (self FrostErrorInvalidCoefficient) Is(target error) bool {
	return target == ErrFrostErrorInvalidCoefficient
}

type FrostErrorIdentifierDerivationNotSupported struct {
}

func NewFrostErrorIdentifierDerivationNotSupported() *FrostError {
	return &FrostError{
		err: &FrostErrorIdentifierDerivationNotSupported{},
	}
}

func (err FrostErrorIdentifierDerivationNotSupported) Error() string {
	return fmt.Sprint("IdentifierDerivationNotSupported")
}

func (self FrostErrorIdentifierDerivationNotSupported) Is(target error) bool {
	return target == ErrFrostErrorIdentifierDerivationNotSupported
}

type FrostErrorSerializationError struct {
}

func NewFrostErrorSerializationError() *FrostError {
	return &FrostError{
		err: &FrostErrorSerializationError{},
	}
}

func (err FrostErrorSerializationError) Error() string {
	return fmt.Sprint("SerializationError")
}

func (self FrostErrorSerializationError) Is(target error) bool {
	return target == ErrFrostErrorSerializationError
}

type FrostErrorDeserializationError struct {
}

func NewFrostErrorDeserializationError() *FrostError {
	return &FrostError{
		err: &FrostErrorDeserializationError{},
	}
}

func (err FrostErrorDeserializationError) Error() string {
	return fmt.Sprint("DeserializationError")
}

func (self FrostErrorDeserializationError) Is(target error) bool {
	return target == ErrFrostErrorDeserializationError
}

type FrostErrorDkgPart2IncorrectNumberOfCommitments struct {
}

func NewFrostErrorDkgPart2IncorrectNumberOfCommitments() *FrostError {
	return &FrostError{
		err: &FrostErrorDkgPart2IncorrectNumberOfCommitments{},
	}
}

func (err FrostErrorDkgPart2IncorrectNumberOfCommitments) Error() string {
	return fmt.Sprint("DkgPart2IncorrectNumberOfCommitments")
}

func (self FrostErrorDkgPart2IncorrectNumberOfCommitments) Is(target error) bool {
	return target == ErrFrostErrorDkgPart2IncorrectNumberOfCommitments
}

type FrostErrorDkgPart2IncorrectNumberOfPackages struct {
}

func NewFrostErrorDkgPart2IncorrectNumberOfPackages() *FrostError {
	return &FrostError{
		err: &FrostErrorDkgPart2IncorrectNumberOfPackages{},
	}
}

func (err FrostErrorDkgPart2IncorrectNumberOfPackages) Error() string {
	return fmt.Sprint("DkgPart2IncorrectNumberOfPackages")
}

func (self FrostErrorDkgPart2IncorrectNumberOfPackages) Is(target error) bool {
	return target == ErrFrostErrorDkgPart2IncorrectNumberOfPackages
}

type FrostErrorDkgPart3IncorrectRound1Packages struct {
}

func NewFrostErrorDkgPart3IncorrectRound1Packages() *FrostError {
	return &FrostError{
		err: &FrostErrorDkgPart3IncorrectRound1Packages{},
	}
}

func (err FrostErrorDkgPart3IncorrectRound1Packages) Error() string {
	return fmt.Sprint("DkgPart3IncorrectRound1Packages")
}

func (self FrostErrorDkgPart3IncorrectRound1Packages) Is(target error) bool {
	return target == ErrFrostErrorDkgPart3IncorrectRound1Packages
}

type FrostErrorDkgPart3IncorrectNumberOfPackages struct {
}

func NewFrostErrorDkgPart3IncorrectNumberOfPackages() *FrostError {
	return &FrostError{
		err: &FrostErrorDkgPart3IncorrectNumberOfPackages{},
	}
}

func (err FrostErrorDkgPart3IncorrectNumberOfPackages) Error() string {
	return fmt.Sprint("DkgPart3IncorrectNumberOfPackages")
}

func (self FrostErrorDkgPart3IncorrectNumberOfPackages) Is(target error) bool {
	return target == ErrFrostErrorDkgPart3IncorrectNumberOfPackages
}

type FrostErrorDkgPart3PackageSendersMismatch struct {
}

func NewFrostErrorDkgPart3PackageSendersMismatch() *FrostError {
	return &FrostError{
		err: &FrostErrorDkgPart3PackageSendersMismatch{},
	}
}

func (err FrostErrorDkgPart3PackageSendersMismatch) Error() string {
	return fmt.Sprint("DkgPart3PackageSendersMismatch")
}

func (self FrostErrorDkgPart3PackageSendersMismatch) Is(target error) bool {
	return target == ErrFrostErrorDkgPart3PackageSendersMismatch
}

type FrostErrorInvalidKeyPackage struct {
}

func NewFrostErrorInvalidKeyPackage() *FrostError {
	return &FrostError{
		err: &FrostErrorInvalidKeyPackage{},
	}
}

func (err FrostErrorInvalidKeyPackage) Error() string {
	return fmt.Sprint("InvalidKeyPackage")
}

func (self FrostErrorInvalidKeyPackage) Is(target error) bool {
	return target == ErrFrostErrorInvalidKeyPackage
}

type FrostErrorInvalidSecretKey struct {
}

func NewFrostErrorInvalidSecretKey() *FrostError {
	return &FrostError{
		err: &FrostErrorInvalidSecretKey{},
	}
}

func (err FrostErrorInvalidSecretKey) Error() string {
	return fmt.Sprint("InvalidSecretKey")
}

func (self FrostErrorInvalidSecretKey) Is(target error) bool {
	return target == ErrFrostErrorInvalidSecretKey
}

type FrostErrorInvalidConfiguration struct {
}

func NewFrostErrorInvalidConfiguration() *FrostError {
	return &FrostError{
		err: &FrostErrorInvalidConfiguration{},
	}
}

func (err FrostErrorInvalidConfiguration) Error() string {
	return fmt.Sprint("InvalidConfiguration")
}

func (self FrostErrorInvalidConfiguration) Is(target error) bool {
	return target == ErrFrostErrorInvalidConfiguration
}

type FrostErrorUnexpectedError struct {
}

func NewFrostErrorUnexpectedError() *FrostError {
	return &FrostError{
		err: &FrostErrorUnexpectedError{},
	}
}

func (err FrostErrorUnexpectedError) Error() string {
	return fmt.Sprint("UnexpectedError")
}

func (self FrostErrorUnexpectedError) Is(target error) bool {
	return target == ErrFrostErrorUnexpectedError
}

type FfiConverterTypeFrostError struct{}

var FfiConverterTypeFrostErrorINSTANCE = FfiConverterTypeFrostError{}

func (c FfiConverterTypeFrostError) Lift(eb RustBufferI) error {
	return LiftFromRustBuffer[error](c, eb)
}

func (c FfiConverterTypeFrostError) Lower(value *FrostError) RustBuffer {
	return LowerIntoRustBuffer[*FrostError](c, value)
}

func (c FfiConverterTypeFrostError) Read(reader io.Reader) error {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &FrostError{&FrostErrorInvalidMinSigners{}}
	case 2:
		return &FrostError{&FrostErrorInvalidMaxSigners{}}
	case 3:
		return &FrostError{&FrostErrorInvalidCoefficients{}}
	case 4:
		return &FrostError{&FrostErrorMalformedIdentifier{}}
	case 5:
		return &FrostError{&FrostErrorDuplicatedIdentifier{}}
	case 6:
		return &FrostError{&FrostErrorUnknownIdentifier{}}
	case 7:
		return &FrostError{&FrostErrorIncorrectNumberOfIdentifiers{}}
	case 8:
		return &FrostError{&FrostErrorMalformedSigningKey{}}
	case 9:
		return &FrostError{&FrostErrorMalformedVerifyingKey{}}
	case 10:
		return &FrostError{&FrostErrorMalformedSignature{}}
	case 11:
		return &FrostError{&FrostErrorInvalidSignature{}}
	case 12:
		return &FrostError{&FrostErrorDuplicatedShares{}}
	case 13:
		return &FrostError{&FrostErrorIncorrectNumberOfShares{}}
	case 14:
		return &FrostError{&FrostErrorIdentityCommitment{}}
	case 15:
		return &FrostError{&FrostErrorMissingCommitment{}}
	case 16:
		return &FrostError{&FrostErrorIncorrectCommitment{}}
	case 17:
		return &FrostError{&FrostErrorIncorrectNumberOfCommitments{}}
	case 18:
		return &FrostError{&FrostErrorInvalidSignatureShare{
			Culprit: FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader),
		}}
	case 19:
		return &FrostError{&FrostErrorInvalidSecretShare{}}
	case 20:
		return &FrostError{&FrostErrorPackageNotFound{}}
	case 21:
		return &FrostError{&FrostErrorIncorrectNumberOfPackages{}}
	case 22:
		return &FrostError{&FrostErrorIncorrectPackage{}}
	case 23:
		return &FrostError{&FrostErrorDkgNotSupported{}}
	case 24:
		return &FrostError{&FrostErrorInvalidProofOfKnowledge{
			Culprit: FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader),
		}}
	case 25:
		return &FrostError{&FrostErrorFieldError{
			Message: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 26:
		return &FrostError{&FrostErrorGroupError{
			Message: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 27:
		return &FrostError{&FrostErrorInvalidCoefficient{}}
	case 28:
		return &FrostError{&FrostErrorIdentifierDerivationNotSupported{}}
	case 29:
		return &FrostError{&FrostErrorSerializationError{}}
	case 30:
		return &FrostError{&FrostErrorDeserializationError{}}
	case 31:
		return &FrostError{&FrostErrorDkgPart2IncorrectNumberOfCommitments{}}
	case 32:
		return &FrostError{&FrostErrorDkgPart2IncorrectNumberOfPackages{}}
	case 33:
		return &FrostError{&FrostErrorDkgPart3IncorrectRound1Packages{}}
	case 34:
		return &FrostError{&FrostErrorDkgPart3IncorrectNumberOfPackages{}}
	case 35:
		return &FrostError{&FrostErrorDkgPart3PackageSendersMismatch{}}
	case 36:
		return &FrostError{&FrostErrorInvalidKeyPackage{}}
	case 37:
		return &FrostError{&FrostErrorInvalidSecretKey{}}
	case 38:
		return &FrostError{&FrostErrorInvalidConfiguration{}}
	case 39:
		return &FrostError{&FrostErrorUnexpectedError{}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterTypeFrostError.Read()", errorID))
	}
}

func (c FfiConverterTypeFrostError) Write(writer io.Writer, value *FrostError) {
	switch variantValue := value.err.(type) {
	case *FrostErrorInvalidMinSigners:
		writeInt32(writer, 1)
	case *FrostErrorInvalidMaxSigners:
		writeInt32(writer, 2)
	case *FrostErrorInvalidCoefficients:
		writeInt32(writer, 3)
	case *FrostErrorMalformedIdentifier:
		writeInt32(writer, 4)
	case *FrostErrorDuplicatedIdentifier:
		writeInt32(writer, 5)
	case *FrostErrorUnknownIdentifier:
		writeInt32(writer, 6)
	case *FrostErrorIncorrectNumberOfIdentifiers:
		writeInt32(writer, 7)
	case *FrostErrorMalformedSigningKey:
		writeInt32(writer, 8)
	case *FrostErrorMalformedVerifyingKey:
		writeInt32(writer, 9)
	case *FrostErrorMalformedSignature:
		writeInt32(writer, 10)
	case *FrostErrorInvalidSignature:
		writeInt32(writer, 11)
	case *FrostErrorDuplicatedShares:
		writeInt32(writer, 12)
	case *FrostErrorIncorrectNumberOfShares:
		writeInt32(writer, 13)
	case *FrostErrorIdentityCommitment:
		writeInt32(writer, 14)
	case *FrostErrorMissingCommitment:
		writeInt32(writer, 15)
	case *FrostErrorIncorrectCommitment:
		writeInt32(writer, 16)
	case *FrostErrorIncorrectNumberOfCommitments:
		writeInt32(writer, 17)
	case *FrostErrorInvalidSignatureShare:
		writeInt32(writer, 18)
		FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, variantValue.Culprit)
	case *FrostErrorInvalidSecretShare:
		writeInt32(writer, 19)
	case *FrostErrorPackageNotFound:
		writeInt32(writer, 20)
	case *FrostErrorIncorrectNumberOfPackages:
		writeInt32(writer, 21)
	case *FrostErrorIncorrectPackage:
		writeInt32(writer, 22)
	case *FrostErrorDkgNotSupported:
		writeInt32(writer, 23)
	case *FrostErrorInvalidProofOfKnowledge:
		writeInt32(writer, 24)
		FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, variantValue.Culprit)
	case *FrostErrorFieldError:
		writeInt32(writer, 25)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Message)
	case *FrostErrorGroupError:
		writeInt32(writer, 26)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Message)
	case *FrostErrorInvalidCoefficient:
		writeInt32(writer, 27)
	case *FrostErrorIdentifierDerivationNotSupported:
		writeInt32(writer, 28)
	case *FrostErrorSerializationError:
		writeInt32(writer, 29)
	case *FrostErrorDeserializationError:
		writeInt32(writer, 30)
	case *FrostErrorDkgPart2IncorrectNumberOfCommitments:
		writeInt32(writer, 31)
	case *FrostErrorDkgPart2IncorrectNumberOfPackages:
		writeInt32(writer, 32)
	case *FrostErrorDkgPart3IncorrectRound1Packages:
		writeInt32(writer, 33)
	case *FrostErrorDkgPart3IncorrectNumberOfPackages:
		writeInt32(writer, 34)
	case *FrostErrorDkgPart3PackageSendersMismatch:
		writeInt32(writer, 35)
	case *FrostErrorInvalidKeyPackage:
		writeInt32(writer, 36)
	case *FrostErrorInvalidSecretKey:
		writeInt32(writer, 37)
	case *FrostErrorInvalidConfiguration:
		writeInt32(writer, 38)
	case *FrostErrorUnexpectedError:
		writeInt32(writer, 39)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterTypeFrostError.Write", value))
	}
}

type FrostSignatureVerificationError struct {
	err error
}

func (err FrostSignatureVerificationError) Error() string {
	return fmt.Sprintf("FrostSignatureVerificationError: %s", err.err.Error())
}

func (err FrostSignatureVerificationError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrFrostSignatureVerificationErrorInvalidPublicKeyPackage = fmt.Errorf("FrostSignatureVerificationErrorInvalidPublicKeyPackage")
var ErrFrostSignatureVerificationErrorValidationFailed = fmt.Errorf("FrostSignatureVerificationErrorValidationFailed")

// Variant structs
type FrostSignatureVerificationErrorInvalidPublicKeyPackage struct {
}

func NewFrostSignatureVerificationErrorInvalidPublicKeyPackage() *FrostSignatureVerificationError {
	return &FrostSignatureVerificationError{
		err: &FrostSignatureVerificationErrorInvalidPublicKeyPackage{},
	}
}

func (err FrostSignatureVerificationErrorInvalidPublicKeyPackage) Error() string {
	return fmt.Sprint("InvalidPublicKeyPackage")
}

func (self FrostSignatureVerificationErrorInvalidPublicKeyPackage) Is(target error) bool {
	return target == ErrFrostSignatureVerificationErrorInvalidPublicKeyPackage
}

type FrostSignatureVerificationErrorValidationFailed struct {
	Reason string
}

func NewFrostSignatureVerificationErrorValidationFailed(
	reason string,
) *FrostSignatureVerificationError {
	return &FrostSignatureVerificationError{
		err: &FrostSignatureVerificationErrorValidationFailed{
			Reason: reason,
		},
	}
}

func (err FrostSignatureVerificationErrorValidationFailed) Error() string {
	return fmt.Sprint("ValidationFailed",
		": ",

		"Reason=",
		err.Reason,
	)
}

func (self FrostSignatureVerificationErrorValidationFailed) Is(target error) bool {
	return target == ErrFrostSignatureVerificationErrorValidationFailed
}

type FfiConverterTypeFrostSignatureVerificationError struct{}

var FfiConverterTypeFrostSignatureVerificationErrorINSTANCE = FfiConverterTypeFrostSignatureVerificationError{}

func (c FfiConverterTypeFrostSignatureVerificationError) Lift(eb RustBufferI) error {
	return LiftFromRustBuffer[error](c, eb)
}

func (c FfiConverterTypeFrostSignatureVerificationError) Lower(value *FrostSignatureVerificationError) RustBuffer {
	return LowerIntoRustBuffer[*FrostSignatureVerificationError](c, value)
}

func (c FfiConverterTypeFrostSignatureVerificationError) Read(reader io.Reader) error {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &FrostSignatureVerificationError{&FrostSignatureVerificationErrorInvalidPublicKeyPackage{}}
	case 2:
		return &FrostSignatureVerificationError{&FrostSignatureVerificationErrorValidationFailed{
			Reason: FfiConverterStringINSTANCE.Read(reader),
		}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterTypeFrostSignatureVerificationError.Read()", errorID))
	}
}

func (c FfiConverterTypeFrostSignatureVerificationError) Write(writer io.Writer, value *FrostSignatureVerificationError) {
	switch variantValue := value.err.(type) {
	case *FrostSignatureVerificationErrorInvalidPublicKeyPackage:
		writeInt32(writer, 1)
	case *FrostSignatureVerificationErrorValidationFailed:
		writeInt32(writer, 2)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Reason)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterTypeFrostSignatureVerificationError.Write", value))
	}
}

type Round1Error struct {
	err error
}

func (err Round1Error) Error() string {
	return fmt.Sprintf("Round1Error: %s", err.err.Error())
}

func (err Round1Error) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrRound1ErrorInvalidKeyPackage = fmt.Errorf("Round1ErrorInvalidKeyPackage")
var ErrRound1ErrorNonceSerializationError = fmt.Errorf("Round1ErrorNonceSerializationError")
var ErrRound1ErrorCommitmentSerializationError = fmt.Errorf("Round1ErrorCommitmentSerializationError")

// Variant structs
type Round1ErrorInvalidKeyPackage struct {
}

func NewRound1ErrorInvalidKeyPackage() *Round1Error {
	return &Round1Error{
		err: &Round1ErrorInvalidKeyPackage{},
	}
}

func (err Round1ErrorInvalidKeyPackage) Error() string {
	return fmt.Sprint("InvalidKeyPackage")
}

func (self Round1ErrorInvalidKeyPackage) Is(target error) bool {
	return target == ErrRound1ErrorInvalidKeyPackage
}

type Round1ErrorNonceSerializationError struct {
}

func NewRound1ErrorNonceSerializationError() *Round1Error {
	return &Round1Error{
		err: &Round1ErrorNonceSerializationError{},
	}
}

func (err Round1ErrorNonceSerializationError) Error() string {
	return fmt.Sprint("NonceSerializationError")
}

func (self Round1ErrorNonceSerializationError) Is(target error) bool {
	return target == ErrRound1ErrorNonceSerializationError
}

type Round1ErrorCommitmentSerializationError struct {
}

func NewRound1ErrorCommitmentSerializationError() *Round1Error {
	return &Round1Error{
		err: &Round1ErrorCommitmentSerializationError{},
	}
}

func (err Round1ErrorCommitmentSerializationError) Error() string {
	return fmt.Sprint("CommitmentSerializationError")
}

func (self Round1ErrorCommitmentSerializationError) Is(target error) bool {
	return target == ErrRound1ErrorCommitmentSerializationError
}

type FfiConverterTypeRound1Error struct{}

var FfiConverterTypeRound1ErrorINSTANCE = FfiConverterTypeRound1Error{}

func (c FfiConverterTypeRound1Error) Lift(eb RustBufferI) error {
	return LiftFromRustBuffer[error](c, eb)
}

func (c FfiConverterTypeRound1Error) Lower(value *Round1Error) RustBuffer {
	return LowerIntoRustBuffer[*Round1Error](c, value)
}

func (c FfiConverterTypeRound1Error) Read(reader io.Reader) error {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &Round1Error{&Round1ErrorInvalidKeyPackage{}}
	case 2:
		return &Round1Error{&Round1ErrorNonceSerializationError{}}
	case 3:
		return &Round1Error{&Round1ErrorCommitmentSerializationError{}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterTypeRound1Error.Read()", errorID))
	}
}

func (c FfiConverterTypeRound1Error) Write(writer io.Writer, value *Round1Error) {
	switch variantValue := value.err.(type) {
	case *Round1ErrorInvalidKeyPackage:
		writeInt32(writer, 1)
	case *Round1ErrorNonceSerializationError:
		writeInt32(writer, 2)
	case *Round1ErrorCommitmentSerializationError:
		writeInt32(writer, 3)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterTypeRound1Error.Write", value))
	}
}

type Round2Error struct {
	err error
}

func (err Round2Error) Error() string {
	return fmt.Sprintf("Round2Error: %s", err.err.Error())
}

func (err Round2Error) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrRound2ErrorInvalidKeyPackage = fmt.Errorf("Round2ErrorInvalidKeyPackage")
var ErrRound2ErrorNonceSerializationError = fmt.Errorf("Round2ErrorNonceSerializationError")
var ErrRound2ErrorCommitmentSerializationError = fmt.Errorf("Round2ErrorCommitmentSerializationError")
var ErrRound2ErrorSigningPackageDeserializationError = fmt.Errorf("Round2ErrorSigningPackageDeserializationError")
var ErrRound2ErrorSigningFailed = fmt.Errorf("Round2ErrorSigningFailed")
var ErrRound2ErrorInvalidRandomizer = fmt.Errorf("Round2ErrorInvalidRandomizer")

// Variant structs
type Round2ErrorInvalidKeyPackage struct {
}

func NewRound2ErrorInvalidKeyPackage() *Round2Error {
	return &Round2Error{
		err: &Round2ErrorInvalidKeyPackage{},
	}
}

func (err Round2ErrorInvalidKeyPackage) Error() string {
	return fmt.Sprint("InvalidKeyPackage")
}

func (self Round2ErrorInvalidKeyPackage) Is(target error) bool {
	return target == ErrRound2ErrorInvalidKeyPackage
}

type Round2ErrorNonceSerializationError struct {
}

func NewRound2ErrorNonceSerializationError() *Round2Error {
	return &Round2Error{
		err: &Round2ErrorNonceSerializationError{},
	}
}

func (err Round2ErrorNonceSerializationError) Error() string {
	return fmt.Sprint("NonceSerializationError")
}

func (self Round2ErrorNonceSerializationError) Is(target error) bool {
	return target == ErrRound2ErrorNonceSerializationError
}

type Round2ErrorCommitmentSerializationError struct {
}

func NewRound2ErrorCommitmentSerializationError() *Round2Error {
	return &Round2Error{
		err: &Round2ErrorCommitmentSerializationError{},
	}
}

func (err Round2ErrorCommitmentSerializationError) Error() string {
	return fmt.Sprint("CommitmentSerializationError")
}

func (self Round2ErrorCommitmentSerializationError) Is(target error) bool {
	return target == ErrRound2ErrorCommitmentSerializationError
}

type Round2ErrorSigningPackageDeserializationError struct {
}

func NewRound2ErrorSigningPackageDeserializationError() *Round2Error {
	return &Round2Error{
		err: &Round2ErrorSigningPackageDeserializationError{},
	}
}

func (err Round2ErrorSigningPackageDeserializationError) Error() string {
	return fmt.Sprint("SigningPackageDeserializationError")
}

func (self Round2ErrorSigningPackageDeserializationError) Is(target error) bool {
	return target == ErrRound2ErrorSigningPackageDeserializationError
}

type Round2ErrorSigningFailed struct {
	Message string
}

func NewRound2ErrorSigningFailed(
	message string,
) *Round2Error {
	return &Round2Error{
		err: &Round2ErrorSigningFailed{
			Message: message,
		},
	}
}

func (err Round2ErrorSigningFailed) Error() string {
	return fmt.Sprint("SigningFailed",
		": ",

		"Message=",
		err.Message,
	)
}

func (self Round2ErrorSigningFailed) Is(target error) bool {
	return target == ErrRound2ErrorSigningFailed
}

type Round2ErrorInvalidRandomizer struct {
}

func NewRound2ErrorInvalidRandomizer() *Round2Error {
	return &Round2Error{
		err: &Round2ErrorInvalidRandomizer{},
	}
}

func (err Round2ErrorInvalidRandomizer) Error() string {
	return fmt.Sprint("InvalidRandomizer")
}

func (self Round2ErrorInvalidRandomizer) Is(target error) bool {
	return target == ErrRound2ErrorInvalidRandomizer
}

type FfiConverterTypeRound2Error struct{}

var FfiConverterTypeRound2ErrorINSTANCE = FfiConverterTypeRound2Error{}

func (c FfiConverterTypeRound2Error) Lift(eb RustBufferI) error {
	return LiftFromRustBuffer[error](c, eb)
}

func (c FfiConverterTypeRound2Error) Lower(value *Round2Error) RustBuffer {
	return LowerIntoRustBuffer[*Round2Error](c, value)
}

func (c FfiConverterTypeRound2Error) Read(reader io.Reader) error {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &Round2Error{&Round2ErrorInvalidKeyPackage{}}
	case 2:
		return &Round2Error{&Round2ErrorNonceSerializationError{}}
	case 3:
		return &Round2Error{&Round2ErrorCommitmentSerializationError{}}
	case 4:
		return &Round2Error{&Round2ErrorSigningPackageDeserializationError{}}
	case 5:
		return &Round2Error{&Round2ErrorSigningFailed{
			Message: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 6:
		return &Round2Error{&Round2ErrorInvalidRandomizer{}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterTypeRound2Error.Read()", errorID))
	}
}

func (c FfiConverterTypeRound2Error) Write(writer io.Writer, value *Round2Error) {
	switch variantValue := value.err.(type) {
	case *Round2ErrorInvalidKeyPackage:
		writeInt32(writer, 1)
	case *Round2ErrorNonceSerializationError:
		writeInt32(writer, 2)
	case *Round2ErrorCommitmentSerializationError:
		writeInt32(writer, 3)
	case *Round2ErrorSigningPackageDeserializationError:
		writeInt32(writer, 4)
	case *Round2ErrorSigningFailed:
		writeInt32(writer, 5)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Message)
	case *Round2ErrorInvalidRandomizer:
		writeInt32(writer, 6)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterTypeRound2Error.Write", value))
	}
}

type FfiConverterOptionalTypeParticipantIdentifier struct{}

var FfiConverterOptionalTypeParticipantIdentifierINSTANCE = FfiConverterOptionalTypeParticipantIdentifier{}

func (c FfiConverterOptionalTypeParticipantIdentifier) Lift(rb RustBufferI) *ParticipantIdentifier {
	return LiftFromRustBuffer[*ParticipantIdentifier](c, rb)
}

func (_ FfiConverterOptionalTypeParticipantIdentifier) Read(reader io.Reader) *ParticipantIdentifier {
	if readInt8(reader) == 0 {
		return nil
	}
	temp := FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader)
	return &temp
}

func (c FfiConverterOptionalTypeParticipantIdentifier) Lower(value *ParticipantIdentifier) RustBuffer {
	return LowerIntoRustBuffer[*ParticipantIdentifier](c, value)
}

func (_ FfiConverterOptionalTypeParticipantIdentifier) Write(writer io.Writer, value *ParticipantIdentifier) {
	if value == nil {
		writeInt8(writer, 0)
	} else {
		writeInt8(writer, 1)
		FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, *value)
	}
}

type FfiDestroyerOptionalTypeParticipantIdentifier struct{}

func (_ FfiDestroyerOptionalTypeParticipantIdentifier) Destroy(value *ParticipantIdentifier) {
	if value != nil {
		FfiDestroyerTypeParticipantIdentifier{}.Destroy(*value)
	}
}

type FfiConverterSequenceTypeFrostSignatureShare struct{}

var FfiConverterSequenceTypeFrostSignatureShareINSTANCE = FfiConverterSequenceTypeFrostSignatureShare{}

func (c FfiConverterSequenceTypeFrostSignatureShare) Lift(rb RustBufferI) []FrostSignatureShare {
	return LiftFromRustBuffer[[]FrostSignatureShare](c, rb)
}

func (c FfiConverterSequenceTypeFrostSignatureShare) Read(reader io.Reader) []FrostSignatureShare {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FrostSignatureShare, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTypeFrostSignatureShareINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTypeFrostSignatureShare) Lower(value []FrostSignatureShare) RustBuffer {
	return LowerIntoRustBuffer[[]FrostSignatureShare](c, value)
}

func (c FfiConverterSequenceTypeFrostSignatureShare) Write(writer io.Writer, value []FrostSignatureShare) {
	if len(value) > math.MaxInt32 {
		panic("[]FrostSignatureShare is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTypeFrostSignatureShareINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTypeFrostSignatureShare struct{}

func (FfiDestroyerSequenceTypeFrostSignatureShare) Destroy(sequence []FrostSignatureShare) {
	for _, value := range sequence {
		FfiDestroyerTypeFrostSignatureShare{}.Destroy(value)
	}
}

type FfiConverterSequenceTypeFrostSigningCommitments struct{}

var FfiConverterSequenceTypeFrostSigningCommitmentsINSTANCE = FfiConverterSequenceTypeFrostSigningCommitments{}

func (c FfiConverterSequenceTypeFrostSigningCommitments) Lift(rb RustBufferI) []FrostSigningCommitments {
	return LiftFromRustBuffer[[]FrostSigningCommitments](c, rb)
}

func (c FfiConverterSequenceTypeFrostSigningCommitments) Read(reader io.Reader) []FrostSigningCommitments {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]FrostSigningCommitments, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTypeFrostSigningCommitmentsINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTypeFrostSigningCommitments) Lower(value []FrostSigningCommitments) RustBuffer {
	return LowerIntoRustBuffer[[]FrostSigningCommitments](c, value)
}

func (c FfiConverterSequenceTypeFrostSigningCommitments) Write(writer io.Writer, value []FrostSigningCommitments) {
	if len(value) > math.MaxInt32 {
		panic("[]FrostSigningCommitments is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTypeFrostSigningCommitmentsINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTypeFrostSigningCommitments struct{}

func (FfiDestroyerSequenceTypeFrostSigningCommitments) Destroy(sequence []FrostSigningCommitments) {
	for _, value := range sequence {
		FfiDestroyerTypeFrostSigningCommitments{}.Destroy(value)
	}
}

type FfiConverterSequenceTypeParticipantIdentifier struct{}

var FfiConverterSequenceTypeParticipantIdentifierINSTANCE = FfiConverterSequenceTypeParticipantIdentifier{}

func (c FfiConverterSequenceTypeParticipantIdentifier) Lift(rb RustBufferI) []ParticipantIdentifier {
	return LiftFromRustBuffer[[]ParticipantIdentifier](c, rb)
}

func (c FfiConverterSequenceTypeParticipantIdentifier) Read(reader io.Reader) []ParticipantIdentifier {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]ParticipantIdentifier, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceTypeParticipantIdentifier) Lower(value []ParticipantIdentifier) RustBuffer {
	return LowerIntoRustBuffer[[]ParticipantIdentifier](c, value)
}

func (c FfiConverterSequenceTypeParticipantIdentifier) Write(writer io.Writer, value []ParticipantIdentifier) {
	if len(value) > math.MaxInt32 {
		panic("[]ParticipantIdentifier is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceTypeParticipantIdentifier struct{}

func (FfiDestroyerSequenceTypeParticipantIdentifier) Destroy(sequence []ParticipantIdentifier) {
	for _, value := range sequence {
		FfiDestroyerTypeParticipantIdentifier{}.Destroy(value)
	}
}

type FfiConverterMapTypeParticipantIdentifierString struct{}

var FfiConverterMapTypeParticipantIdentifierStringINSTANCE = FfiConverterMapTypeParticipantIdentifierString{}

func (c FfiConverterMapTypeParticipantIdentifierString) Lift(rb RustBufferI) map[ParticipantIdentifier]string {
	return LiftFromRustBuffer[map[ParticipantIdentifier]string](c, rb)
}

func (_ FfiConverterMapTypeParticipantIdentifierString) Read(reader io.Reader) map[ParticipantIdentifier]string {
	result := make(map[ParticipantIdentifier]string)
	length := readInt32(reader)
	for i := int32(0); i < length; i++ {
		key := FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader)
		value := FfiConverterStringINSTANCE.Read(reader)
		result[key] = value
	}
	return result
}

func (c FfiConverterMapTypeParticipantIdentifierString) Lower(value map[ParticipantIdentifier]string) RustBuffer {
	return LowerIntoRustBuffer[map[ParticipantIdentifier]string](c, value)
}

func (_ FfiConverterMapTypeParticipantIdentifierString) Write(writer io.Writer, mapValue map[ParticipantIdentifier]string) {
	if len(mapValue) > math.MaxInt32 {
		panic("map[ParticipantIdentifier]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(mapValue)))
	for key, value := range mapValue {
		FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, key)
		FfiConverterStringINSTANCE.Write(writer, value)
	}
}

type FfiDestroyerMapTypeParticipantIdentifierString struct{}

func (_ FfiDestroyerMapTypeParticipantIdentifierString) Destroy(mapValue map[ParticipantIdentifier]string) {
	for key, value := range mapValue {
		FfiDestroyerTypeParticipantIdentifier{}.Destroy(key)
		FfiDestroyerString{}.Destroy(value)
	}
}

type FfiConverterMapTypeParticipantIdentifierTypeDKGRound1Package struct{}

var FfiConverterMapTypeParticipantIdentifierTypeDKGRound1PackageINSTANCE = FfiConverterMapTypeParticipantIdentifierTypeDKGRound1Package{}

func (c FfiConverterMapTypeParticipantIdentifierTypeDKGRound1Package) Lift(rb RustBufferI) map[ParticipantIdentifier]DkgRound1Package {
	return LiftFromRustBuffer[map[ParticipantIdentifier]DkgRound1Package](c, rb)
}

func (_ FfiConverterMapTypeParticipantIdentifierTypeDKGRound1Package) Read(reader io.Reader) map[ParticipantIdentifier]DkgRound1Package {
	result := make(map[ParticipantIdentifier]DkgRound1Package)
	length := readInt32(reader)
	for i := int32(0); i < length; i++ {
		key := FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader)
		value := FfiConverterTypeDKGRound1PackageINSTANCE.Read(reader)
		result[key] = value
	}
	return result
}

func (c FfiConverterMapTypeParticipantIdentifierTypeDKGRound1Package) Lower(value map[ParticipantIdentifier]DkgRound1Package) RustBuffer {
	return LowerIntoRustBuffer[map[ParticipantIdentifier]DkgRound1Package](c, value)
}

func (_ FfiConverterMapTypeParticipantIdentifierTypeDKGRound1Package) Write(writer io.Writer, mapValue map[ParticipantIdentifier]DkgRound1Package) {
	if len(mapValue) > math.MaxInt32 {
		panic("map[ParticipantIdentifier]DkgRound1Package is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(mapValue)))
	for key, value := range mapValue {
		FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, key)
		FfiConverterTypeDKGRound1PackageINSTANCE.Write(writer, value)
	}
}

type FfiDestroyerMapTypeParticipantIdentifierTypeDkgRound1Package struct{}

func (_ FfiDestroyerMapTypeParticipantIdentifierTypeDkgRound1Package) Destroy(mapValue map[ParticipantIdentifier]DkgRound1Package) {
	for key, value := range mapValue {
		FfiDestroyerTypeParticipantIdentifier{}.Destroy(key)
		FfiDestroyerTypeDkgRound1Package{}.Destroy(value)
	}
}

type FfiConverterMapTypeParticipantIdentifierTypeDKGRound2Package struct{}

var FfiConverterMapTypeParticipantIdentifierTypeDKGRound2PackageINSTANCE = FfiConverterMapTypeParticipantIdentifierTypeDKGRound2Package{}

func (c FfiConverterMapTypeParticipantIdentifierTypeDKGRound2Package) Lift(rb RustBufferI) map[ParticipantIdentifier]DkgRound2Package {
	return LiftFromRustBuffer[map[ParticipantIdentifier]DkgRound2Package](c, rb)
}

func (_ FfiConverterMapTypeParticipantIdentifierTypeDKGRound2Package) Read(reader io.Reader) map[ParticipantIdentifier]DkgRound2Package {
	result := make(map[ParticipantIdentifier]DkgRound2Package)
	length := readInt32(reader)
	for i := int32(0); i < length; i++ {
		key := FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader)
		value := FfiConverterTypeDKGRound2PackageINSTANCE.Read(reader)
		result[key] = value
	}
	return result
}

func (c FfiConverterMapTypeParticipantIdentifierTypeDKGRound2Package) Lower(value map[ParticipantIdentifier]DkgRound2Package) RustBuffer {
	return LowerIntoRustBuffer[map[ParticipantIdentifier]DkgRound2Package](c, value)
}

func (_ FfiConverterMapTypeParticipantIdentifierTypeDKGRound2Package) Write(writer io.Writer, mapValue map[ParticipantIdentifier]DkgRound2Package) {
	if len(mapValue) > math.MaxInt32 {
		panic("map[ParticipantIdentifier]DkgRound2Package is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(mapValue)))
	for key, value := range mapValue {
		FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, key)
		FfiConverterTypeDKGRound2PackageINSTANCE.Write(writer, value)
	}
}

type FfiDestroyerMapTypeParticipantIdentifierTypeDkgRound2Package struct{}

func (_ FfiDestroyerMapTypeParticipantIdentifierTypeDkgRound2Package) Destroy(mapValue map[ParticipantIdentifier]DkgRound2Package) {
	for key, value := range mapValue {
		FfiDestroyerTypeParticipantIdentifier{}.Destroy(key)
		FfiDestroyerTypeDkgRound2Package{}.Destroy(value)
	}
}

type FfiConverterMapTypeParticipantIdentifierTypeFrostSecretKeyShare struct{}

var FfiConverterMapTypeParticipantIdentifierTypeFrostSecretKeyShareINSTANCE = FfiConverterMapTypeParticipantIdentifierTypeFrostSecretKeyShare{}

func (c FfiConverterMapTypeParticipantIdentifierTypeFrostSecretKeyShare) Lift(rb RustBufferI) map[ParticipantIdentifier]FrostSecretKeyShare {
	return LiftFromRustBuffer[map[ParticipantIdentifier]FrostSecretKeyShare](c, rb)
}

func (_ FfiConverterMapTypeParticipantIdentifierTypeFrostSecretKeyShare) Read(reader io.Reader) map[ParticipantIdentifier]FrostSecretKeyShare {
	result := make(map[ParticipantIdentifier]FrostSecretKeyShare)
	length := readInt32(reader)
	for i := int32(0); i < length; i++ {
		key := FfiConverterTypeParticipantIdentifierINSTANCE.Read(reader)
		value := FfiConverterTypeFrostSecretKeyShareINSTANCE.Read(reader)
		result[key] = value
	}
	return result
}

func (c FfiConverterMapTypeParticipantIdentifierTypeFrostSecretKeyShare) Lower(value map[ParticipantIdentifier]FrostSecretKeyShare) RustBuffer {
	return LowerIntoRustBuffer[map[ParticipantIdentifier]FrostSecretKeyShare](c, value)
}

func (_ FfiConverterMapTypeParticipantIdentifierTypeFrostSecretKeyShare) Write(writer io.Writer, mapValue map[ParticipantIdentifier]FrostSecretKeyShare) {
	if len(mapValue) > math.MaxInt32 {
		panic("map[ParticipantIdentifier]FrostSecretKeyShare is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(mapValue)))
	for key, value := range mapValue {
		FfiConverterTypeParticipantIdentifierINSTANCE.Write(writer, key)
		FfiConverterTypeFrostSecretKeyShareINSTANCE.Write(writer, value)
	}
}

type FfiDestroyerMapTypeParticipantIdentifierTypeFrostSecretKeyShare struct{}

func (_ FfiDestroyerMapTypeParticipantIdentifierTypeFrostSecretKeyShare) Destroy(mapValue map[ParticipantIdentifier]FrostSecretKeyShare) {
	for key, value := range mapValue {
		FfiDestroyerTypeParticipantIdentifier{}.Destroy(key)
		FfiDestroyerTypeFrostSecretKeyShare{}.Destroy(value)
	}
}

func Aggregate(signingPackage FrostSigningPackage, signatureShares []FrostSignatureShare, pubkeyPackage FrostPublicKeyPackage, randomizer FrostRandomizer) (FrostSignature, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeCoordinationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_aggregate(FfiConverterTypeFrostSigningPackageINSTANCE.Lower(signingPackage), FfiConverterSequenceTypeFrostSignatureShareINSTANCE.Lower(signatureShares), FfiConverterTypeFrostPublicKeyPackageINSTANCE.Lower(pubkeyPackage), FfiConverterTypeFrostRandomizerINSTANCE.Lower(randomizer), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue FrostSignature
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeFrostSignatureINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func FromHexString(hexString string) (FrostRandomizer, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFrostError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_from_hex_string(FfiConverterStringINSTANCE.Lower(hexString), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue FrostRandomizer
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeFrostRandomizerINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func GenerateNoncesAndCommitments(keyPackage FrostKeyPackage) (FirstRoundCommitment, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeRound1Error{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_generate_nonces_and_commitments(FfiConverterTypeFrostKeyPackageINSTANCE.Lower(keyPackage), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue FirstRoundCommitment
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeFirstRoundCommitmentINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func IdentifierFromJsonString(string string) *ParticipantIdentifier {
	return FfiConverterOptionalTypeParticipantIdentifierINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_identifier_from_json_string(FfiConverterStringINSTANCE.Lower(string), _uniffiStatus)
	}))
}

func IdentifierFromString(string string) (ParticipantIdentifier, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFrostError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_identifier_from_string(FfiConverterStringINSTANCE.Lower(string), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ParticipantIdentifier
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeParticipantIdentifierINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func IdentifierFromUint16(unsignedUint uint16) (ParticipantIdentifier, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFrostError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_identifier_from_uint16(FfiConverterUint16INSTANCE.Lower(unsignedUint), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue ParticipantIdentifier
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeParticipantIdentifierINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func NewSigningPackage(message Message, commitments []FrostSigningCommitments) (FrostSigningPackage, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeCoordinationError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_new_signing_package(FfiConverterTypeMessageINSTANCE.Lower(message), FfiConverterSequenceTypeFrostSigningCommitmentsINSTANCE.Lower(commitments), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue FrostSigningPackage
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeFrostSigningPackageINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func Part1(participantIdentifier ParticipantIdentifier, maxSigners uint16, minSigners uint16) (*DkgPart1Result, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFrostError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_frost_uniffi_sdk_fn_func_part_1(FfiConverterTypeParticipantIdentifierINSTANCE.Lower(participantIdentifier), FfiConverterUint16INSTANCE.Lower(maxSigners), FfiConverterUint16INSTANCE.Lower(minSigners), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *DkgPart1Result
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterDKGPart1ResultINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func Part2(secretPackage *DkgRound1SecretPackage, round1Packages map[ParticipantIdentifier]DkgRound1Package) (*DkgPart2Result, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFrostError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_frost_uniffi_sdk_fn_func_part_2(FfiConverterDKGRound1SecretPackageINSTANCE.Lower(secretPackage), FfiConverterMapTypeParticipantIdentifierTypeDKGRound1PackageINSTANCE.Lower(round1Packages), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *DkgPart2Result
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterDKGPart2ResultINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func Part3(secretPackage *DkgRound2SecretPackage, round1Packages map[ParticipantIdentifier]DkgRound1Package, round2Packages map[ParticipantIdentifier]DkgRound2Package) (DkgPart3Result, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFrostError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_part_3(FfiConverterDKGRound2SecretPackageINSTANCE.Lower(secretPackage), FfiConverterMapTypeParticipantIdentifierTypeDKGRound1PackageINSTANCE.Lower(round1Packages), FfiConverterMapTypeParticipantIdentifierTypeDKGRound2PackageINSTANCE.Lower(round2Packages), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue DkgPart3Result
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeDKGPart3ResultINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func RandomizedParamsFromPublicKeyAndSigningPackage(publicKey FrostPublicKeyPackage, signingPackage FrostSigningPackage) (*FrostRandomizedParams, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFrostError{}, func(_uniffiStatus *C.RustCallStatus) unsafe.Pointer {
		return C.uniffi_frost_uniffi_sdk_fn_func_randomized_params_from_public_key_and_signing_package(FfiConverterTypeFrostPublicKeyPackageINSTANCE.Lower(publicKey), FfiConverterTypeFrostSigningPackageINSTANCE.Lower(signingPackage), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue *FrostRandomizedParams
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterFrostRandomizedParamsINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func RandomizerFromParams(randomizedParams *FrostRandomizedParams) (FrostRandomizer, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFrostError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_randomizer_from_params(FfiConverterFrostRandomizedParamsINSTANCE.Lower(randomizedParams), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue FrostRandomizer
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeFrostRandomizerINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func Sign(signingPackage FrostSigningPackage, nonces FrostSigningNonces, keyPackage FrostKeyPackage, randomizer FrostRandomizer) (FrostSignatureShare, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeRound2Error{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_sign(FfiConverterTypeFrostSigningPackageINSTANCE.Lower(signingPackage), FfiConverterTypeFrostSigningNoncesINSTANCE.Lower(nonces), FfiConverterTypeFrostKeyPackageINSTANCE.Lower(keyPackage), FfiConverterTypeFrostRandomizerINSTANCE.Lower(randomizer), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue FrostSignatureShare
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeFrostSignatureShareINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func TrustedDealerKeygenFrom(configuration Configuration) (TrustedKeyGeneration, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFrostError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_trusted_dealer_keygen_from(FfiConverterTypeConfigurationINSTANCE.Lower(configuration), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue TrustedKeyGeneration
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeTrustedKeyGenerationINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func TrustedDealerKeygenWithIdentifiers(configuration Configuration, participants ParticipantList) (TrustedKeyGeneration, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFrostError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_trusted_dealer_keygen_with_identifiers(FfiConverterTypeConfigurationINSTANCE.Lower(configuration), FfiConverterTypeParticipantListINSTANCE.Lower(participants), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue TrustedKeyGeneration
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeTrustedKeyGenerationINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func ValidateConfig(config Configuration) error {
	_, _uniffiErr := rustCallWithError(FfiConverterTypeConfigurationError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_frost_uniffi_sdk_fn_func_validate_config(FfiConverterTypeConfigurationINSTANCE.Lower(config), _uniffiStatus)
		return false
	})
	return _uniffiErr
}

func VerifyAndGetKeyPackageFrom(secretShare FrostSecretKeyShare) (FrostKeyPackage, error) {
	_uniffiRV, _uniffiErr := rustCallWithError(FfiConverterTypeFrostError{}, func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return C.uniffi_frost_uniffi_sdk_fn_func_verify_and_get_key_package_from(FfiConverterTypeFrostSecretKeyShareINSTANCE.Lower(secretShare), _uniffiStatus)
	})
	if _uniffiErr != nil {
		var _uniffiDefaultValue FrostKeyPackage
		return _uniffiDefaultValue, _uniffiErr
	} else {
		return FfiConverterTypeFrostKeyPackageINSTANCE.Lift(_uniffiRV), _uniffiErr
	}
}

func VerifyRandomizedSignature(randomizer FrostRandomizer, message Message, signature FrostSignature, pubkey FrostPublicKeyPackage) error {
	_, _uniffiErr := rustCallWithError(FfiConverterTypeFrostSignatureVerificationError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_frost_uniffi_sdk_fn_func_verify_randomized_signature(FfiConverterTypeFrostRandomizerINSTANCE.Lower(randomizer), FfiConverterTypeMessageINSTANCE.Lower(message), FfiConverterTypeFrostSignatureINSTANCE.Lower(signature), FfiConverterTypeFrostPublicKeyPackageINSTANCE.Lower(pubkey), _uniffiStatus)
		return false
	})
	return _uniffiErr
}

func VerifySignature(message Message, signature FrostSignature, pubkey FrostPublicKeyPackage) error {
	_, _uniffiErr := rustCallWithError(FfiConverterTypeFrostSignatureVerificationError{}, func(_uniffiStatus *C.RustCallStatus) bool {
		C.uniffi_frost_uniffi_sdk_fn_func_verify_signature(FfiConverterTypeMessageINSTANCE.Lower(message), FfiConverterTypeFrostSignatureINSTANCE.Lower(signature), FfiConverterTypeFrostPublicKeyPackageINSTANCE.Lower(pubkey), _uniffiStatus)
		return false
	})
	return _uniffiErr
}
