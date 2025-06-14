// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.3
// source: blackice/proto/blackice/v1/satellite.proto

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
	SatelliteService_SendBackup_FullMethodName             = "/blackice.v1.SatelliteService/SendBackup"
	SatelliteService_RetrieveBackup_FullMethodName         = "/blackice.v1.SatelliteService/RetrieveBackup"
	SatelliteService_GetLinkStatus_FullMethodName          = "/blackice.v1.SatelliteService/GetLinkStatus"
	SatelliteService_ActivateEmergencyRelay_FullMethodName = "/blackice.v1.SatelliteService/ActivateEmergencyRelay"
	SatelliteService_SendControlSignal_FullMethodName      = "/blackice.v1.SatelliteService/SendControlSignal"
	SatelliteService_GetOrbitalNodeHealth_FullMethodName   = "/blackice.v1.SatelliteService/GetOrbitalNodeHealth"
)

// SatelliteServiceClient is the client API for SatelliteService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// SatelliteService manages communication and data transfer with Satellite/HAPS nodes
// for off-planet backups, emergency relay, and last-resort control plane access.
type SatelliteServiceClient interface {
	// SendBackup sends critical data (e.g., ledger snapshots, key material) to orbital storage.
	// Handles latency-aware traffic shaping and packet prioritization.
	SendBackup(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[BackupDataChunk, BackupAck], error)
	// RetrieveBackup retrieves data from orbital storage.
	RetrieveBackup(ctx context.Context, in *RetrieveBackupRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[BackupDataChunk], error)
	// GetLinkStatus retrieves the status of satellite communication links.
	GetLinkStatus(ctx context.Context, in *LinkStatusRequest, opts ...grpc.CallOption) (*LinkStatusResponse, error)
	// ActivateEmergencyRelay activates the satellite network as an emergency relay for critical communications.
	// This is a high-privilege operation, typically triggered during severe panic tiers.
	ActivateEmergencyRelay(ctx context.Context, in *ActivateRelayRequest, opts ...grpc.CallOption) (*RelayActivationResponse, error)
	// SendControlSignal sends a highly authenticated control signal via the satellite relay.
	SendControlSignal(ctx context.Context, in *ControlSignalRequest, opts ...grpc.CallOption) (*ControlSignalResponse, error)
	// GetOrbitalNodeHealth checks the health and status of specific orbital/HAPS nodes.
	GetOrbitalNodeHealth(ctx context.Context, in *OrbitalNodeHealthRequest, opts ...grpc.CallOption) (*OrbitalNodeHealthResponse, error)
}

type satelliteServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSatelliteServiceClient(cc grpc.ClientConnInterface) SatelliteServiceClient {
	return &satelliteServiceClient{cc}
}

func (c *satelliteServiceClient) SendBackup(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[BackupDataChunk, BackupAck], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &SatelliteService_ServiceDesc.Streams[0], SatelliteService_SendBackup_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[BackupDataChunk, BackupAck]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type SatelliteService_SendBackupClient = grpc.ClientStreamingClient[BackupDataChunk, BackupAck]

func (c *satelliteServiceClient) RetrieveBackup(ctx context.Context, in *RetrieveBackupRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[BackupDataChunk], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &SatelliteService_ServiceDesc.Streams[1], SatelliteService_RetrieveBackup_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[RetrieveBackupRequest, BackupDataChunk]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type SatelliteService_RetrieveBackupClient = grpc.ServerStreamingClient[BackupDataChunk]

func (c *satelliteServiceClient) GetLinkStatus(ctx context.Context, in *LinkStatusRequest, opts ...grpc.CallOption) (*LinkStatusResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(LinkStatusResponse)
	err := c.cc.Invoke(ctx, SatelliteService_GetLinkStatus_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *satelliteServiceClient) ActivateEmergencyRelay(ctx context.Context, in *ActivateRelayRequest, opts ...grpc.CallOption) (*RelayActivationResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(RelayActivationResponse)
	err := c.cc.Invoke(ctx, SatelliteService_ActivateEmergencyRelay_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *satelliteServiceClient) SendControlSignal(ctx context.Context, in *ControlSignalRequest, opts ...grpc.CallOption) (*ControlSignalResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ControlSignalResponse)
	err := c.cc.Invoke(ctx, SatelliteService_SendControlSignal_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *satelliteServiceClient) GetOrbitalNodeHealth(ctx context.Context, in *OrbitalNodeHealthRequest, opts ...grpc.CallOption) (*OrbitalNodeHealthResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(OrbitalNodeHealthResponse)
	err := c.cc.Invoke(ctx, SatelliteService_GetOrbitalNodeHealth_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SatelliteServiceServer is the server API for SatelliteService service.
// All implementations must embed UnimplementedSatelliteServiceServer
// for forward compatibility.
//
// SatelliteService manages communication and data transfer with Satellite/HAPS nodes
// for off-planet backups, emergency relay, and last-resort control plane access.
type SatelliteServiceServer interface {
	// SendBackup sends critical data (e.g., ledger snapshots, key material) to orbital storage.
	// Handles latency-aware traffic shaping and packet prioritization.
	SendBackup(grpc.ClientStreamingServer[BackupDataChunk, BackupAck]) error
	// RetrieveBackup retrieves data from orbital storage.
	RetrieveBackup(*RetrieveBackupRequest, grpc.ServerStreamingServer[BackupDataChunk]) error
	// GetLinkStatus retrieves the status of satellite communication links.
	GetLinkStatus(context.Context, *LinkStatusRequest) (*LinkStatusResponse, error)
	// ActivateEmergencyRelay activates the satellite network as an emergency relay for critical communications.
	// This is a high-privilege operation, typically triggered during severe panic tiers.
	ActivateEmergencyRelay(context.Context, *ActivateRelayRequest) (*RelayActivationResponse, error)
	// SendControlSignal sends a highly authenticated control signal via the satellite relay.
	SendControlSignal(context.Context, *ControlSignalRequest) (*ControlSignalResponse, error)
	// GetOrbitalNodeHealth checks the health and status of specific orbital/HAPS nodes.
	GetOrbitalNodeHealth(context.Context, *OrbitalNodeHealthRequest) (*OrbitalNodeHealthResponse, error)
	mustEmbedUnimplementedSatelliteServiceServer()
}

// UnimplementedSatelliteServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedSatelliteServiceServer struct{}

func (UnimplementedSatelliteServiceServer) SendBackup(grpc.ClientStreamingServer[BackupDataChunk, BackupAck]) error {
	return status.Errorf(codes.Unimplemented, "method SendBackup not implemented")
}
func (UnimplementedSatelliteServiceServer) RetrieveBackup(*RetrieveBackupRequest, grpc.ServerStreamingServer[BackupDataChunk]) error {
	return status.Errorf(codes.Unimplemented, "method RetrieveBackup not implemented")
}
func (UnimplementedSatelliteServiceServer) GetLinkStatus(context.Context, *LinkStatusRequest) (*LinkStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetLinkStatus not implemented")
}
func (UnimplementedSatelliteServiceServer) ActivateEmergencyRelay(context.Context, *ActivateRelayRequest) (*RelayActivationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ActivateEmergencyRelay not implemented")
}
func (UnimplementedSatelliteServiceServer) SendControlSignal(context.Context, *ControlSignalRequest) (*ControlSignalResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendControlSignal not implemented")
}
func (UnimplementedSatelliteServiceServer) GetOrbitalNodeHealth(context.Context, *OrbitalNodeHealthRequest) (*OrbitalNodeHealthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetOrbitalNodeHealth not implemented")
}
func (UnimplementedSatelliteServiceServer) mustEmbedUnimplementedSatelliteServiceServer() {}
func (UnimplementedSatelliteServiceServer) testEmbeddedByValue()                          {}

// UnsafeSatelliteServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SatelliteServiceServer will
// result in compilation errors.
type UnsafeSatelliteServiceServer interface {
	mustEmbedUnimplementedSatelliteServiceServer()
}

func RegisterSatelliteServiceServer(s grpc.ServiceRegistrar, srv SatelliteServiceServer) {
	// If the following call pancis, it indicates UnimplementedSatelliteServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&SatelliteService_ServiceDesc, srv)
}

func _SatelliteService_SendBackup_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(SatelliteServiceServer).SendBackup(&grpc.GenericServerStream[BackupDataChunk, BackupAck]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type SatelliteService_SendBackupServer = grpc.ClientStreamingServer[BackupDataChunk, BackupAck]

func _SatelliteService_RetrieveBackup_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(RetrieveBackupRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(SatelliteServiceServer).RetrieveBackup(m, &grpc.GenericServerStream[RetrieveBackupRequest, BackupDataChunk]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type SatelliteService_RetrieveBackupServer = grpc.ServerStreamingServer[BackupDataChunk]

func _SatelliteService_GetLinkStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LinkStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SatelliteServiceServer).GetLinkStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SatelliteService_GetLinkStatus_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SatelliteServiceServer).GetLinkStatus(ctx, req.(*LinkStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SatelliteService_ActivateEmergencyRelay_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivateRelayRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SatelliteServiceServer).ActivateEmergencyRelay(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SatelliteService_ActivateEmergencyRelay_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SatelliteServiceServer).ActivateEmergencyRelay(ctx, req.(*ActivateRelayRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SatelliteService_SendControlSignal_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ControlSignalRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SatelliteServiceServer).SendControlSignal(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SatelliteService_SendControlSignal_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SatelliteServiceServer).SendControlSignal(ctx, req.(*ControlSignalRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SatelliteService_GetOrbitalNodeHealth_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(OrbitalNodeHealthRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SatelliteServiceServer).GetOrbitalNodeHealth(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SatelliteService_GetOrbitalNodeHealth_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SatelliteServiceServer).GetOrbitalNodeHealth(ctx, req.(*OrbitalNodeHealthRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// SatelliteService_ServiceDesc is the grpc.ServiceDesc for SatelliteService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SatelliteService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blackice.v1.SatelliteService",
	HandlerType: (*SatelliteServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetLinkStatus",
			Handler:    _SatelliteService_GetLinkStatus_Handler,
		},
		{
			MethodName: "ActivateEmergencyRelay",
			Handler:    _SatelliteService_ActivateEmergencyRelay_Handler,
		},
		{
			MethodName: "SendControlSignal",
			Handler:    _SatelliteService_SendControlSignal_Handler,
		},
		{
			MethodName: "GetOrbitalNodeHealth",
			Handler:    _SatelliteService_GetOrbitalNodeHealth_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SendBackup",
			Handler:       _SatelliteService_SendBackup_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "RetrieveBackup",
			Handler:       _SatelliteService_RetrieveBackup_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "blackice/proto/blackice/v1/satellite.proto",
}
