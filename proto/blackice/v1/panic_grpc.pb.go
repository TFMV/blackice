// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.3
// source: blackice/proto/blackice/v1/panic.proto

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
	PanicService_TriggerPanic_FullMethodName       = "/blackice.v1.PanicService/TriggerPanic"
	PanicService_GetPanicStatus_FullMethodName     = "/blackice.v1.PanicService/GetPanicStatus"
	PanicService_AcknowledgeSignal_FullMethodName  = "/blackice.v1.PanicService/AcknowledgeSignal"
	PanicService_RequestEscalation_FullMethodName  = "/blackice.v1.PanicService/RequestEscalation"
	PanicService_DeactivatePanic_FullMethodName    = "/blackice.v1.PanicService/DeactivatePanic"
	PanicService_ManagePanicPolicy_FullMethodName  = "/blackice.v1.PanicService/ManagePanicPolicy"
	PanicService_CoordinateBurnback_FullMethodName = "/blackice.v1.PanicService/CoordinateBurnback"
)

// PanicServiceClient is the client API for PanicService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// PanicService coordinates the system-wide response to critical security events,
// managing tiered burnback, controlled isolation, and forensic state preservation.
type PanicServiceClient interface {
	// TriggerPanic initiates a panic event or escalates an existing one.
	// Requires strong attestation and potentially multi-party authorization for higher tiers.
	TriggerPanic(ctx context.Context, in *TriggerPanicRequest, opts ...grpc.CallOption) (*PanicResponse, error)
	// GetPanicStatus retrieves the current status of the panic system or a specific event.
	GetPanicStatus(ctx context.Context, in *GetPanicStatusRequest, opts ...grpc.CallOption) (*PanicStatusResponse, error)
	// AcknowledgeSignal is used by components to acknowledge receipt and execution of panic directives.
	AcknowledgeSignal(ctx context.Context, in *SignalAcknowledgement, opts ...grpc.CallOption) (*AcknowledgementResponse, error)
	// RequestEscalation requests an escalation to a higher panic tier from an authorized entity.
	RequestEscalation(ctx context.Context, in *EscalationRequest, opts ...grpc.CallOption) (*PanicResponse, error)
	// DeactivatePanic attempts to return the system to a normal operational state post-panic.
	// Requires thorough verification and authorization.
	DeactivatePanic(ctx context.Context, in *DeactivatePanicRequest, opts ...grpc.CallOption) (*PanicResponse, error)
	// ManagePanicPolicy (Admin) allows updating panic tiers and response playbooks.
	ManagePanicPolicy(ctx context.Context, in *ManagePanicPolicyRequest, opts ...grpc.CallOption) (*ManagePanicPolicyResponse, error)
	// CoordinateBurnback (Internal) handles cross-region coordination for burnback.
	// This is likely called by a leader-elected panic coordinator.
	CoordinateBurnback(ctx context.Context, in *BurnbackCoordinationRequest, opts ...grpc.CallOption) (*BurnbackCoordinationResponse, error)
}

type panicServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPanicServiceClient(cc grpc.ClientConnInterface) PanicServiceClient {
	return &panicServiceClient{cc}
}

func (c *panicServiceClient) TriggerPanic(ctx context.Context, in *TriggerPanicRequest, opts ...grpc.CallOption) (*PanicResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(PanicResponse)
	err := c.cc.Invoke(ctx, PanicService_TriggerPanic_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *panicServiceClient) GetPanicStatus(ctx context.Context, in *GetPanicStatusRequest, opts ...grpc.CallOption) (*PanicStatusResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(PanicStatusResponse)
	err := c.cc.Invoke(ctx, PanicService_GetPanicStatus_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *panicServiceClient) AcknowledgeSignal(ctx context.Context, in *SignalAcknowledgement, opts ...grpc.CallOption) (*AcknowledgementResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AcknowledgementResponse)
	err := c.cc.Invoke(ctx, PanicService_AcknowledgeSignal_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *panicServiceClient) RequestEscalation(ctx context.Context, in *EscalationRequest, opts ...grpc.CallOption) (*PanicResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(PanicResponse)
	err := c.cc.Invoke(ctx, PanicService_RequestEscalation_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *panicServiceClient) DeactivatePanic(ctx context.Context, in *DeactivatePanicRequest, opts ...grpc.CallOption) (*PanicResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(PanicResponse)
	err := c.cc.Invoke(ctx, PanicService_DeactivatePanic_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *panicServiceClient) ManagePanicPolicy(ctx context.Context, in *ManagePanicPolicyRequest, opts ...grpc.CallOption) (*ManagePanicPolicyResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ManagePanicPolicyResponse)
	err := c.cc.Invoke(ctx, PanicService_ManagePanicPolicy_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *panicServiceClient) CoordinateBurnback(ctx context.Context, in *BurnbackCoordinationRequest, opts ...grpc.CallOption) (*BurnbackCoordinationResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(BurnbackCoordinationResponse)
	err := c.cc.Invoke(ctx, PanicService_CoordinateBurnback_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PanicServiceServer is the server API for PanicService service.
// All implementations must embed UnimplementedPanicServiceServer
// for forward compatibility.
//
// PanicService coordinates the system-wide response to critical security events,
// managing tiered burnback, controlled isolation, and forensic state preservation.
type PanicServiceServer interface {
	// TriggerPanic initiates a panic event or escalates an existing one.
	// Requires strong attestation and potentially multi-party authorization for higher tiers.
	TriggerPanic(context.Context, *TriggerPanicRequest) (*PanicResponse, error)
	// GetPanicStatus retrieves the current status of the panic system or a specific event.
	GetPanicStatus(context.Context, *GetPanicStatusRequest) (*PanicStatusResponse, error)
	// AcknowledgeSignal is used by components to acknowledge receipt and execution of panic directives.
	AcknowledgeSignal(context.Context, *SignalAcknowledgement) (*AcknowledgementResponse, error)
	// RequestEscalation requests an escalation to a higher panic tier from an authorized entity.
	RequestEscalation(context.Context, *EscalationRequest) (*PanicResponse, error)
	// DeactivatePanic attempts to return the system to a normal operational state post-panic.
	// Requires thorough verification and authorization.
	DeactivatePanic(context.Context, *DeactivatePanicRequest) (*PanicResponse, error)
	// ManagePanicPolicy (Admin) allows updating panic tiers and response playbooks.
	ManagePanicPolicy(context.Context, *ManagePanicPolicyRequest) (*ManagePanicPolicyResponse, error)
	// CoordinateBurnback (Internal) handles cross-region coordination for burnback.
	// This is likely called by a leader-elected panic coordinator.
	CoordinateBurnback(context.Context, *BurnbackCoordinationRequest) (*BurnbackCoordinationResponse, error)
	mustEmbedUnimplementedPanicServiceServer()
}

// UnimplementedPanicServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedPanicServiceServer struct{}

func (UnimplementedPanicServiceServer) TriggerPanic(context.Context, *TriggerPanicRequest) (*PanicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TriggerPanic not implemented")
}
func (UnimplementedPanicServiceServer) GetPanicStatus(context.Context, *GetPanicStatusRequest) (*PanicStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPanicStatus not implemented")
}
func (UnimplementedPanicServiceServer) AcknowledgeSignal(context.Context, *SignalAcknowledgement) (*AcknowledgementResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AcknowledgeSignal not implemented")
}
func (UnimplementedPanicServiceServer) RequestEscalation(context.Context, *EscalationRequest) (*PanicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RequestEscalation not implemented")
}
func (UnimplementedPanicServiceServer) DeactivatePanic(context.Context, *DeactivatePanicRequest) (*PanicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeactivatePanic not implemented")
}
func (UnimplementedPanicServiceServer) ManagePanicPolicy(context.Context, *ManagePanicPolicyRequest) (*ManagePanicPolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ManagePanicPolicy not implemented")
}
func (UnimplementedPanicServiceServer) CoordinateBurnback(context.Context, *BurnbackCoordinationRequest) (*BurnbackCoordinationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CoordinateBurnback not implemented")
}
func (UnimplementedPanicServiceServer) mustEmbedUnimplementedPanicServiceServer() {}
func (UnimplementedPanicServiceServer) testEmbeddedByValue()                      {}

// UnsafePanicServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PanicServiceServer will
// result in compilation errors.
type UnsafePanicServiceServer interface {
	mustEmbedUnimplementedPanicServiceServer()
}

func RegisterPanicServiceServer(s grpc.ServiceRegistrar, srv PanicServiceServer) {
	// If the following call pancis, it indicates UnimplementedPanicServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&PanicService_ServiceDesc, srv)
}

func _PanicService_TriggerPanic_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TriggerPanicRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PanicServiceServer).TriggerPanic(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PanicService_TriggerPanic_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PanicServiceServer).TriggerPanic(ctx, req.(*TriggerPanicRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PanicService_GetPanicStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetPanicStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PanicServiceServer).GetPanicStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PanicService_GetPanicStatus_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PanicServiceServer).GetPanicStatus(ctx, req.(*GetPanicStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PanicService_AcknowledgeSignal_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignalAcknowledgement)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PanicServiceServer).AcknowledgeSignal(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PanicService_AcknowledgeSignal_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PanicServiceServer).AcknowledgeSignal(ctx, req.(*SignalAcknowledgement))
	}
	return interceptor(ctx, in, info, handler)
}

func _PanicService_RequestEscalation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EscalationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PanicServiceServer).RequestEscalation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PanicService_RequestEscalation_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PanicServiceServer).RequestEscalation(ctx, req.(*EscalationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PanicService_DeactivatePanic_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeactivatePanicRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PanicServiceServer).DeactivatePanic(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PanicService_DeactivatePanic_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PanicServiceServer).DeactivatePanic(ctx, req.(*DeactivatePanicRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PanicService_ManagePanicPolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ManagePanicPolicyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PanicServiceServer).ManagePanicPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PanicService_ManagePanicPolicy_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PanicServiceServer).ManagePanicPolicy(ctx, req.(*ManagePanicPolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PanicService_CoordinateBurnback_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BurnbackCoordinationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PanicServiceServer).CoordinateBurnback(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PanicService_CoordinateBurnback_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PanicServiceServer).CoordinateBurnback(ctx, req.(*BurnbackCoordinationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// PanicService_ServiceDesc is the grpc.ServiceDesc for PanicService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PanicService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blackice.v1.PanicService",
	HandlerType: (*PanicServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "TriggerPanic",
			Handler:    _PanicService_TriggerPanic_Handler,
		},
		{
			MethodName: "GetPanicStatus",
			Handler:    _PanicService_GetPanicStatus_Handler,
		},
		{
			MethodName: "AcknowledgeSignal",
			Handler:    _PanicService_AcknowledgeSignal_Handler,
		},
		{
			MethodName: "RequestEscalation",
			Handler:    _PanicService_RequestEscalation_Handler,
		},
		{
			MethodName: "DeactivatePanic",
			Handler:    _PanicService_DeactivatePanic_Handler,
		},
		{
			MethodName: "ManagePanicPolicy",
			Handler:    _PanicService_ManagePanicPolicy_Handler,
		},
		{
			MethodName: "CoordinateBurnback",
			Handler:    _PanicService_CoordinateBurnback_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blackice/proto/blackice/v1/panic.proto",
}
