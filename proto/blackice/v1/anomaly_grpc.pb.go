// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.3
// source: blackice/proto/blackice/v1/anomaly.proto

package blackicev1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	AnomalyService_SubmitTelemetry_FullMethodName      = "/blackice.v1.AnomalyService/SubmitTelemetry"
	AnomalyService_QueryAnomalies_FullMethodName       = "/blackice.v1.AnomalyService/QueryAnomalies"
	AnomalyService_GetAnomalyDetails_FullMethodName    = "/blackice.v1.AnomalyService/GetAnomalyDetails"
	AnomalyService_UpdateDetectionModel_FullMethodName = "/blackice.v1.AnomalyService/UpdateDetectionModel"
	AnomalyService_ProvideFeedback_FullMethodName      = "/blackice.v1.AnomalyService/ProvideFeedback"
	AnomalyService_GetDetectorStatus_FullMethodName    = "/blackice.v1.AnomalyService/GetDetectorStatus"
)

// AnomalyServiceClient is the client API for AnomalyService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// AnomalyService provides real-time anomaly detection based on telemetry from
// various system components. It uses statistical modeling, Falco, Zeek, OSSEC inputs,
// and context-aware deep learning models.
type AnomalyServiceClient interface {
	// SubmitTelemetry is called by other BlackIce components to submit operational telemetry.
	SubmitTelemetry(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[TelemetryEvent, TelemetryResponse], error)
	// QueryAnomalies allows querying for detected anomalies based on various criteria.
	QueryAnomalies(ctx context.Context, in *QueryAnomaliesRequest, opts ...grpc.CallOption) (*QueryAnomaliesResponse, error)
	// GetAnomalyDetails retrieves detailed information about a specific anomaly.
	GetAnomalyDetails(ctx context.Context, in *GetAnomalyDetailsRequest, opts ...grpc.CallOption) (*GetAnomalyDetailsResponse, error)
	// UpdateDetectionModel (Admin) triggers an update or retraining of a specific detection model.
	UpdateDetectionModel(ctx context.Context, in *UpdateModelRequest, opts ...grpc.CallOption) (*UpdateModelResponse, error)
	// ProvideFeedback allows human analysts to provide feedback on an anomaly's classification,
	// feeding into Bayesian feedback loops.
	ProvideFeedback(ctx context.Context, in *FeedbackRequest, opts ...grpc.CallOption) (*FeedbackResponse, error)
	// GetDetectorStatus returns the current operational status of anomaly detectors.
	GetDetectorStatus(ctx context.Context, in *DetectorStatusRequest, opts ...grpc.CallOption) (*DetectorStatusResponse, error)
}

type anomalyServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAnomalyServiceClient(cc grpc.ClientConnInterface) AnomalyServiceClient {
	return &anomalyServiceClient{cc}
}

func (c *anomalyServiceClient) SubmitTelemetry(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[TelemetryEvent, TelemetryResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &AnomalyService_ServiceDesc.Streams[0], AnomalyService_SubmitTelemetry_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[TelemetryEvent, TelemetryResponse]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type AnomalyService_SubmitTelemetryClient = grpc.ClientStreamingClient[TelemetryEvent, TelemetryResponse]

func (c *anomalyServiceClient) QueryAnomalies(ctx context.Context, in *QueryAnomaliesRequest, opts ...grpc.CallOption) (*QueryAnomaliesResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(QueryAnomaliesResponse)
	err := c.cc.Invoke(ctx, AnomalyService_QueryAnomalies_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *anomalyServiceClient) GetAnomalyDetails(ctx context.Context, in *GetAnomalyDetailsRequest, opts ...grpc.CallOption) (*GetAnomalyDetailsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetAnomalyDetailsResponse)
	err := c.cc.Invoke(ctx, AnomalyService_GetAnomalyDetails_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *anomalyServiceClient) UpdateDetectionModel(ctx context.Context, in *UpdateModelRequest, opts ...grpc.CallOption) (*UpdateModelResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(UpdateModelResponse)
	err := c.cc.Invoke(ctx, AnomalyService_UpdateDetectionModel_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *anomalyServiceClient) ProvideFeedback(ctx context.Context, in *FeedbackRequest, opts ...grpc.CallOption) (*FeedbackResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(FeedbackResponse)
	err := c.cc.Invoke(ctx, AnomalyService_ProvideFeedback_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *anomalyServiceClient) GetDetectorStatus(ctx context.Context, in *DetectorStatusRequest, opts ...grpc.CallOption) (*DetectorStatusResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DetectorStatusResponse)
	err := c.cc.Invoke(ctx, AnomalyService_GetDetectorStatus_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AnomalyServiceServer is the server API for AnomalyService service.
// All implementations must embed UnimplementedAnomalyServiceServer
// for forward compatibility.
//
// AnomalyService provides real-time anomaly detection based on telemetry from
// various system components. It uses statistical modeling, Falco, Zeek, OSSEC inputs,
// and context-aware deep learning models.
type AnomalyServiceServer interface {
	// SubmitTelemetry is called by other BlackIce components to submit operational telemetry.
	SubmitTelemetry(grpc.ClientStreamingServer[TelemetryEvent, TelemetryResponse]) error
	// QueryAnomalies allows querying for detected anomalies based on various criteria.
	QueryAnomalies(context.Context, *QueryAnomaliesRequest) (*QueryAnomaliesResponse, error)
	// GetAnomalyDetails retrieves detailed information about a specific anomaly.
	GetAnomalyDetails(context.Context, *GetAnomalyDetailsRequest) (*GetAnomalyDetailsResponse, error)
	// UpdateDetectionModel (Admin) triggers an update or retraining of a specific detection model.
	UpdateDetectionModel(context.Context, *UpdateModelRequest) (*UpdateModelResponse, error)
	// ProvideFeedback allows human analysts to provide feedback on an anomaly's classification,
	// feeding into Bayesian feedback loops.
	ProvideFeedback(context.Context, *FeedbackRequest) (*FeedbackResponse, error)
	// GetDetectorStatus returns the current operational status of anomaly detectors.
	GetDetectorStatus(context.Context, *DetectorStatusRequest) (*DetectorStatusResponse, error)
	mustEmbedUnimplementedAnomalyServiceServer()
}

// UnimplementedAnomalyServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedAnomalyServiceServer struct{}

func (UnimplementedAnomalyServiceServer) SubmitTelemetry(grpc.ClientStreamingServer[TelemetryEvent, TelemetryResponse]) error {
	return status.Errorf(codes.Unimplemented, "method SubmitTelemetry not implemented")
}
func (UnimplementedAnomalyServiceServer) QueryAnomalies(context.Context, *QueryAnomaliesRequest) (*QueryAnomaliesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method QueryAnomalies not implemented")
}
func (UnimplementedAnomalyServiceServer) GetAnomalyDetails(context.Context, *GetAnomalyDetailsRequest) (*GetAnomalyDetailsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAnomalyDetails not implemented")
}
func (UnimplementedAnomalyServiceServer) UpdateDetectionModel(context.Context, *UpdateModelRequest) (*UpdateModelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateDetectionModel not implemented")
}
func (UnimplementedAnomalyServiceServer) ProvideFeedback(context.Context, *FeedbackRequest) (*FeedbackResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ProvideFeedback not implemented")
}
func (UnimplementedAnomalyServiceServer) GetDetectorStatus(context.Context, *DetectorStatusRequest) (*DetectorStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetDetectorStatus not implemented")
}
func (UnimplementedAnomalyServiceServer) mustEmbedUnimplementedAnomalyServiceServer() {}
func (UnimplementedAnomalyServiceServer) testEmbeddedByValue()                        {}

// UnsafeAnomalyServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AnomalyServiceServer will
// result in compilation errors.
type UnsafeAnomalyServiceServer interface {
	mustEmbedUnimplementedAnomalyServiceServer()
}

func RegisterAnomalyServiceServer(s grpc.ServiceRegistrar, srv AnomalyServiceServer) {
	// If the following call pancis, it indicates UnimplementedAnomalyServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&AnomalyService_ServiceDesc, srv)
}

func _AnomalyService_SubmitTelemetry_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(AnomalyServiceServer).SubmitTelemetry(&grpc.GenericServerStream[TelemetryEvent, TelemetryResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type AnomalyService_SubmitTelemetryServer = grpc.ClientStreamingServer[TelemetryEvent, TelemetryResponse]

func _AnomalyService_QueryAnomalies_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryAnomaliesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AnomalyServiceServer).QueryAnomalies(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AnomalyService_QueryAnomalies_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AnomalyServiceServer).QueryAnomalies(ctx, req.(*QueryAnomaliesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AnomalyService_GetAnomalyDetails_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAnomalyDetailsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AnomalyServiceServer).GetAnomalyDetails(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AnomalyService_GetAnomalyDetails_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AnomalyServiceServer).GetAnomalyDetails(ctx, req.(*GetAnomalyDetailsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AnomalyService_UpdateDetectionModel_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateModelRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AnomalyServiceServer).UpdateDetectionModel(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AnomalyService_UpdateDetectionModel_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AnomalyServiceServer).UpdateDetectionModel(ctx, req.(*UpdateModelRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AnomalyService_ProvideFeedback_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FeedbackRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AnomalyServiceServer).ProvideFeedback(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AnomalyService_ProvideFeedback_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AnomalyServiceServer).ProvideFeedback(ctx, req.(*FeedbackRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AnomalyService_GetDetectorStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DetectorStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AnomalyServiceServer).GetDetectorStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AnomalyService_GetDetectorStatus_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AnomalyServiceServer).GetDetectorStatus(ctx, req.(*DetectorStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AnomalyService_ServiceDesc is the grpc.ServiceDesc for AnomalyService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AnomalyService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blackice.v1.AnomalyService",
	HandlerType: (*AnomalyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "QueryAnomalies",
			Handler:    _AnomalyService_QueryAnomalies_Handler,
		},
		{
			MethodName: "GetAnomalyDetails",
			Handler:    _AnomalyService_GetAnomalyDetails_Handler,
		},
		{
			MethodName: "UpdateDetectionModel",
			Handler:    _AnomalyService_UpdateDetectionModel_Handler,
		},
		{
			MethodName: "ProvideFeedback",
			Handler:    _AnomalyService_ProvideFeedback_Handler,
		},
		{
			MethodName: "GetDetectorStatus",
			Handler:    _AnomalyService_GetDetectorStatus_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SubmitTelemetry",
			Handler:       _AnomalyService_SubmitTelemetry_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "blackice/proto/blackice/v1/anomaly.proto",
}
