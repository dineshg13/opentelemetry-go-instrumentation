// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package client

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpf_no_tpHttpRequestT struct {
	StartTime   uint64
	EndTime     uint64
	Sc          bpf_no_tpSpanContext
	Psc         bpf_no_tpSpanContext
	Host        [128]int8
	Proto       [8]int8
	StatusCode  uint64
	Method      [16]int8
	Path        [128]int8
	Scheme      [8]int8
	Opaque      [8]int8
	RawPath     [8]int8
	Username    [8]int8
	RawQuery    [128]int8
	Fragment    [56]int8
	RawFragment [56]int8
	ForceQuery  uint8
	OmitHost    uint8
	_           [6]byte
}

type bpf_no_tpSliceArrayBuff struct{ Buff [1024]uint8 }

type bpf_no_tpSpanContext struct {
	TraceID    [16]uint8
	SpanID     [8]uint8
	TraceFlags uint8
	Padding    [7]uint8
}

// loadBpf_no_tp returns the embedded CollectionSpec for bpf_no_tp.
func loadBpf_no_tp() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Bpf_no_tpBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf_no_tp: %w", err)
	}

	return spec, err
}

// loadBpf_no_tpObjects loads bpf_no_tp and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpf_no_tpObjects
//	*bpf_no_tpPrograms
//	*bpf_no_tpMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpf_no_tpObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf_no_tp()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpf_no_tpSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_no_tpSpecs struct {
	bpf_no_tpProgramSpecs
	bpf_no_tpMapSpecs
}

// bpf_no_tpSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_no_tpProgramSpecs struct {
	UprobeTransportRoundTrip        *ebpf.ProgramSpec `ebpf:"uprobe_Transport_roundTrip"`
	UprobeTransportRoundTripReturns *ebpf.ProgramSpec `ebpf:"uprobe_Transport_roundTrip_Returns"`
	UprobeWriteSubset               *ebpf.ProgramSpec `ebpf:"uprobe_writeSubset"`
}

// bpf_no_tpMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_no_tpMapSpecs struct {
	AllocMap                   *ebpf.MapSpec `ebpf:"alloc_map"`
	Events                     *ebpf.MapSpec `ebpf:"events"`
	HttpClientUprobeStorageMap *ebpf.MapSpec `ebpf:"http_client_uprobe_storage_map"`
	HttpEvents                 *ebpf.MapSpec `ebpf:"http_events"`
	HttpHeaders                *ebpf.MapSpec `ebpf:"http_headers"`
	SliceArrayBuffMap          *ebpf.MapSpec `ebpf:"slice_array_buff_map"`
	TrackedSpans               *ebpf.MapSpec `ebpf:"tracked_spans"`
	TrackedSpansBySc           *ebpf.MapSpec `ebpf:"tracked_spans_by_sc"`
}

// bpf_no_tpObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpf_no_tpObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_no_tpObjects struct {
	bpf_no_tpPrograms
	bpf_no_tpMaps
}

func (o *bpf_no_tpObjects) Close() error {
	return _Bpf_no_tpClose(
		&o.bpf_no_tpPrograms,
		&o.bpf_no_tpMaps,
	)
}

// bpf_no_tpMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpf_no_tpObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_no_tpMaps struct {
	AllocMap                   *ebpf.Map `ebpf:"alloc_map"`
	Events                     *ebpf.Map `ebpf:"events"`
	HttpClientUprobeStorageMap *ebpf.Map `ebpf:"http_client_uprobe_storage_map"`
	HttpEvents                 *ebpf.Map `ebpf:"http_events"`
	HttpHeaders                *ebpf.Map `ebpf:"http_headers"`
	SliceArrayBuffMap          *ebpf.Map `ebpf:"slice_array_buff_map"`
	TrackedSpans               *ebpf.Map `ebpf:"tracked_spans"`
	TrackedSpansBySc           *ebpf.Map `ebpf:"tracked_spans_by_sc"`
}

func (m *bpf_no_tpMaps) Close() error {
	return _Bpf_no_tpClose(
		m.AllocMap,
		m.Events,
		m.HttpClientUprobeStorageMap,
		m.HttpEvents,
		m.HttpHeaders,
		m.SliceArrayBuffMap,
		m.TrackedSpans,
		m.TrackedSpansBySc,
	)
}

// bpf_no_tpPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpf_no_tpObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_no_tpPrograms struct {
	UprobeTransportRoundTrip        *ebpf.Program `ebpf:"uprobe_Transport_roundTrip"`
	UprobeTransportRoundTripReturns *ebpf.Program `ebpf:"uprobe_Transport_roundTrip_Returns"`
	UprobeWriteSubset               *ebpf.Program `ebpf:"uprobe_writeSubset"`
}

func (p *bpf_no_tpPrograms) Close() error {
	return _Bpf_no_tpClose(
		p.UprobeTransportRoundTrip,
		p.UprobeTransportRoundTripReturns,
		p.UprobeWriteSubset,
	)
}

func _Bpf_no_tpClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_no_tp_arm64_bpfel.o
var _Bpf_no_tpBytes []byte
