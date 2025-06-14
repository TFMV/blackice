// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.3
// source: blackice/proto/blackice/v1/storage.proto

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
	StorageService_CreateTable_FullMethodName           = "/blackice.v1.StorageService/CreateTable"
	StorageService_GetTableSchema_FullMethodName        = "/blackice.v1.StorageService/GetTableSchema"
	StorageService_WriteData_FullMethodName             = "/blackice.v1.StorageService/WriteData"
	StorageService_ReadData_FullMethodName              = "/blackice.v1.StorageService/ReadData"
	StorageService_CreateSnapshot_FullMethodName        = "/blackice.v1.StorageService/CreateSnapshot"
	StorageService_GetSnapshot_FullMethodName           = "/blackice.v1.StorageService/GetSnapshot"
	StorageService_ListSnapshots_FullMethodName         = "/blackice.v1.StorageService/ListSnapshots"
	StorageService_RollbackTable_FullMethodName         = "/blackice.v1.StorageService/RollbackTable"
	StorageService_CreateBranch_FullMethodName          = "/blackice.v1.StorageService/CreateBranch"
	StorageService_MergeBranch_FullMethodName           = "/blackice.v1.StorageService/MergeBranch"
	StorageService_ListBranches_FullMethodName          = "/blackice.v1.StorageService/ListBranches"
	StorageService_GetStorageStats_FullMethodName       = "/blackice.v1.StorageService/GetStorageStats"
	StorageService_ManageRetentionPolicy_FullMethodName = "/blackice.v1.StorageService/ManageRetentionPolicy"
)

// StorageServiceClient is the client API for StorageService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// StorageService provides mutation-aware storage capabilities, integrating
// with Apache Iceberg and offering Git-like semantics for data versioning.
type StorageServiceClient interface {
	// CreateTable creates a new table with Iceberg schema and BlackIce versioning.
	CreateTable(ctx context.Context, in *CreateTableRequest, opts ...grpc.CallOption) (*StorageOperationResponse, error)
	// GetTableSchema retrieves the schema for a given table.
	GetTableSchema(ctx context.Context, in *GetTableRequest, opts ...grpc.CallOption) (*GetTableSchemaResponse, error)
	// WriteData writes a batch of data to a table. This creates a new snapshot/commit.
	// Data is expected in a format like Apache Parquet or ORC, referenceable by a URI.
	WriteData(ctx context.Context, in *WriteDataRequest, opts ...grpc.CallOption) (*WriteDataResponse, error)
	// ReadData reads data from a table, optionally at a specific snapshot or time.
	// Supports time-travel queries.
	ReadData(ctx context.Context, in *ReadDataRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[DataChunk], error)
	// CreateSnapshot explicitly creates a new snapshot for a table.
	CreateSnapshot(ctx context.Context, in *CreateSnapshotRequest, opts ...grpc.CallOption) (*SnapshotResponse, error)
	// GetSnapshot retrieves details of a specific snapshot.
	GetSnapshot(ctx context.Context, in *GetSnapshotRequest, opts ...grpc.CallOption) (*SnapshotResponse, error)
	// ListSnapshots lists snapshots for a table, with pagination and filtering.
	ListSnapshots(ctx context.Context, in *ListSnapshotsRequest, opts ...grpc.CallOption) (*ListSnapshotsResponse, error)
	// RollbackTable rolls a table back to a specific snapshot ID or timestamp.
	// This is a critical operation requiring strong attestation.
	RollbackTable(ctx context.Context, in *RollbackTableRequest, opts ...grpc.CallOption) (*StorageOperationResponse, error)
	// CreateBranch creates a new branch from an existing table state (snapshot).
	CreateBranch(ctx context.Context, in *CreateBranchRequest, opts ...grpc.CallOption) (*BranchResponse, error)
	// MergeBranch merges changes from one branch into another (or main).
	// Implements conflict resolution strategies.
	MergeBranch(ctx context.Context, in *MergeBranchRequest, opts ...grpc.CallOption) (*MergeResponse, error)
	// ListBranches lists all branches for a given table.
	ListBranches(ctx context.Context, in *ListBranchesRequest, opts ...grpc.CallOption) (*ListBranchesResponse, error)
	// GetStorageStats provides operational statistics for the storage service.
	GetStorageStats(ctx context.Context, in *StorageStatsRequest, opts ...grpc.CallOption) (*StorageStatsResponse, error)
	// ManageRetentionPolicy sets or updates retention policies for snapshots and data.
	ManageRetentionPolicy(ctx context.Context, in *ManageRetentionPolicyRequest, opts ...grpc.CallOption) (*StorageOperationResponse, error)
}

type storageServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewStorageServiceClient(cc grpc.ClientConnInterface) StorageServiceClient {
	return &storageServiceClient{cc}
}

func (c *storageServiceClient) CreateTable(ctx context.Context, in *CreateTableRequest, opts ...grpc.CallOption) (*StorageOperationResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(StorageOperationResponse)
	err := c.cc.Invoke(ctx, StorageService_CreateTable_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageServiceClient) GetTableSchema(ctx context.Context, in *GetTableRequest, opts ...grpc.CallOption) (*GetTableSchemaResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetTableSchemaResponse)
	err := c.cc.Invoke(ctx, StorageService_GetTableSchema_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageServiceClient) WriteData(ctx context.Context, in *WriteDataRequest, opts ...grpc.CallOption) (*WriteDataResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(WriteDataResponse)
	err := c.cc.Invoke(ctx, StorageService_WriteData_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageServiceClient) ReadData(ctx context.Context, in *ReadDataRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[DataChunk], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &StorageService_ServiceDesc.Streams[0], StorageService_ReadData_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[ReadDataRequest, DataChunk]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type StorageService_ReadDataClient = grpc.ServerStreamingClient[DataChunk]

func (c *storageServiceClient) CreateSnapshot(ctx context.Context, in *CreateSnapshotRequest, opts ...grpc.CallOption) (*SnapshotResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SnapshotResponse)
	err := c.cc.Invoke(ctx, StorageService_CreateSnapshot_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageServiceClient) GetSnapshot(ctx context.Context, in *GetSnapshotRequest, opts ...grpc.CallOption) (*SnapshotResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SnapshotResponse)
	err := c.cc.Invoke(ctx, StorageService_GetSnapshot_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageServiceClient) ListSnapshots(ctx context.Context, in *ListSnapshotsRequest, opts ...grpc.CallOption) (*ListSnapshotsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListSnapshotsResponse)
	err := c.cc.Invoke(ctx, StorageService_ListSnapshots_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageServiceClient) RollbackTable(ctx context.Context, in *RollbackTableRequest, opts ...grpc.CallOption) (*StorageOperationResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(StorageOperationResponse)
	err := c.cc.Invoke(ctx, StorageService_RollbackTable_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageServiceClient) CreateBranch(ctx context.Context, in *CreateBranchRequest, opts ...grpc.CallOption) (*BranchResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(BranchResponse)
	err := c.cc.Invoke(ctx, StorageService_CreateBranch_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageServiceClient) MergeBranch(ctx context.Context, in *MergeBranchRequest, opts ...grpc.CallOption) (*MergeResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(MergeResponse)
	err := c.cc.Invoke(ctx, StorageService_MergeBranch_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageServiceClient) ListBranches(ctx context.Context, in *ListBranchesRequest, opts ...grpc.CallOption) (*ListBranchesResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListBranchesResponse)
	err := c.cc.Invoke(ctx, StorageService_ListBranches_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageServiceClient) GetStorageStats(ctx context.Context, in *StorageStatsRequest, opts ...grpc.CallOption) (*StorageStatsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(StorageStatsResponse)
	err := c.cc.Invoke(ctx, StorageService_GetStorageStats_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageServiceClient) ManageRetentionPolicy(ctx context.Context, in *ManageRetentionPolicyRequest, opts ...grpc.CallOption) (*StorageOperationResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(StorageOperationResponse)
	err := c.cc.Invoke(ctx, StorageService_ManageRetentionPolicy_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// StorageServiceServer is the server API for StorageService service.
// All implementations must embed UnimplementedStorageServiceServer
// for forward compatibility.
//
// StorageService provides mutation-aware storage capabilities, integrating
// with Apache Iceberg and offering Git-like semantics for data versioning.
type StorageServiceServer interface {
	// CreateTable creates a new table with Iceberg schema and BlackIce versioning.
	CreateTable(context.Context, *CreateTableRequest) (*StorageOperationResponse, error)
	// GetTableSchema retrieves the schema for a given table.
	GetTableSchema(context.Context, *GetTableRequest) (*GetTableSchemaResponse, error)
	// WriteData writes a batch of data to a table. This creates a new snapshot/commit.
	// Data is expected in a format like Apache Parquet or ORC, referenceable by a URI.
	WriteData(context.Context, *WriteDataRequest) (*WriteDataResponse, error)
	// ReadData reads data from a table, optionally at a specific snapshot or time.
	// Supports time-travel queries.
	ReadData(*ReadDataRequest, grpc.ServerStreamingServer[DataChunk]) error
	// CreateSnapshot explicitly creates a new snapshot for a table.
	CreateSnapshot(context.Context, *CreateSnapshotRequest) (*SnapshotResponse, error)
	// GetSnapshot retrieves details of a specific snapshot.
	GetSnapshot(context.Context, *GetSnapshotRequest) (*SnapshotResponse, error)
	// ListSnapshots lists snapshots for a table, with pagination and filtering.
	ListSnapshots(context.Context, *ListSnapshotsRequest) (*ListSnapshotsResponse, error)
	// RollbackTable rolls a table back to a specific snapshot ID or timestamp.
	// This is a critical operation requiring strong attestation.
	RollbackTable(context.Context, *RollbackTableRequest) (*StorageOperationResponse, error)
	// CreateBranch creates a new branch from an existing table state (snapshot).
	CreateBranch(context.Context, *CreateBranchRequest) (*BranchResponse, error)
	// MergeBranch merges changes from one branch into another (or main).
	// Implements conflict resolution strategies.
	MergeBranch(context.Context, *MergeBranchRequest) (*MergeResponse, error)
	// ListBranches lists all branches for a given table.
	ListBranches(context.Context, *ListBranchesRequest) (*ListBranchesResponse, error)
	// GetStorageStats provides operational statistics for the storage service.
	GetStorageStats(context.Context, *StorageStatsRequest) (*StorageStatsResponse, error)
	// ManageRetentionPolicy sets or updates retention policies for snapshots and data.
	ManageRetentionPolicy(context.Context, *ManageRetentionPolicyRequest) (*StorageOperationResponse, error)
	mustEmbedUnimplementedStorageServiceServer()
}

// UnimplementedStorageServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedStorageServiceServer struct{}

func (UnimplementedStorageServiceServer) CreateTable(context.Context, *CreateTableRequest) (*StorageOperationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateTable not implemented")
}
func (UnimplementedStorageServiceServer) GetTableSchema(context.Context, *GetTableRequest) (*GetTableSchemaResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTableSchema not implemented")
}
func (UnimplementedStorageServiceServer) WriteData(context.Context, *WriteDataRequest) (*WriteDataResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method WriteData not implemented")
}
func (UnimplementedStorageServiceServer) ReadData(*ReadDataRequest, grpc.ServerStreamingServer[DataChunk]) error {
	return status.Errorf(codes.Unimplemented, "method ReadData not implemented")
}
func (UnimplementedStorageServiceServer) CreateSnapshot(context.Context, *CreateSnapshotRequest) (*SnapshotResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateSnapshot not implemented")
}
func (UnimplementedStorageServiceServer) GetSnapshot(context.Context, *GetSnapshotRequest) (*SnapshotResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSnapshot not implemented")
}
func (UnimplementedStorageServiceServer) ListSnapshots(context.Context, *ListSnapshotsRequest) (*ListSnapshotsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListSnapshots not implemented")
}
func (UnimplementedStorageServiceServer) RollbackTable(context.Context, *RollbackTableRequest) (*StorageOperationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RollbackTable not implemented")
}
func (UnimplementedStorageServiceServer) CreateBranch(context.Context, *CreateBranchRequest) (*BranchResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateBranch not implemented")
}
func (UnimplementedStorageServiceServer) MergeBranch(context.Context, *MergeBranchRequest) (*MergeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method MergeBranch not implemented")
}
func (UnimplementedStorageServiceServer) ListBranches(context.Context, *ListBranchesRequest) (*ListBranchesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListBranches not implemented")
}
func (UnimplementedStorageServiceServer) GetStorageStats(context.Context, *StorageStatsRequest) (*StorageStatsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStorageStats not implemented")
}
func (UnimplementedStorageServiceServer) ManageRetentionPolicy(context.Context, *ManageRetentionPolicyRequest) (*StorageOperationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ManageRetentionPolicy not implemented")
}
func (UnimplementedStorageServiceServer) mustEmbedUnimplementedStorageServiceServer() {}
func (UnimplementedStorageServiceServer) testEmbeddedByValue()                        {}

// UnsafeStorageServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to StorageServiceServer will
// result in compilation errors.
type UnsafeStorageServiceServer interface {
	mustEmbedUnimplementedStorageServiceServer()
}

func RegisterStorageServiceServer(s grpc.ServiceRegistrar, srv StorageServiceServer) {
	// If the following call pancis, it indicates UnimplementedStorageServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&StorageService_ServiceDesc, srv)
}

func _StorageService_CreateTable_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTableRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).CreateTable(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_CreateTable_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).CreateTable(ctx, req.(*CreateTableRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StorageService_GetTableSchema_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetTableRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).GetTableSchema(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_GetTableSchema_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).GetTableSchema(ctx, req.(*GetTableRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StorageService_WriteData_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(WriteDataRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).WriteData(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_WriteData_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).WriteData(ctx, req.(*WriteDataRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StorageService_ReadData_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ReadDataRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(StorageServiceServer).ReadData(m, &grpc.GenericServerStream[ReadDataRequest, DataChunk]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type StorageService_ReadDataServer = grpc.ServerStreamingServer[DataChunk]

func _StorageService_CreateSnapshot_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateSnapshotRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).CreateSnapshot(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_CreateSnapshot_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).CreateSnapshot(ctx, req.(*CreateSnapshotRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StorageService_GetSnapshot_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetSnapshotRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).GetSnapshot(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_GetSnapshot_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).GetSnapshot(ctx, req.(*GetSnapshotRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StorageService_ListSnapshots_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListSnapshotsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).ListSnapshots(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_ListSnapshots_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).ListSnapshots(ctx, req.(*ListSnapshotsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StorageService_RollbackTable_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RollbackTableRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).RollbackTable(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_RollbackTable_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).RollbackTable(ctx, req.(*RollbackTableRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StorageService_CreateBranch_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateBranchRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).CreateBranch(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_CreateBranch_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).CreateBranch(ctx, req.(*CreateBranchRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StorageService_MergeBranch_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MergeBranchRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).MergeBranch(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_MergeBranch_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).MergeBranch(ctx, req.(*MergeBranchRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StorageService_ListBranches_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListBranchesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).ListBranches(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_ListBranches_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).ListBranches(ctx, req.(*ListBranchesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StorageService_GetStorageStats_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StorageStatsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).GetStorageStats(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_GetStorageStats_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).GetStorageStats(ctx, req.(*StorageStatsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _StorageService_ManageRetentionPolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ManageRetentionPolicyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServiceServer).ManageRetentionPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: StorageService_ManageRetentionPolicy_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServiceServer).ManageRetentionPolicy(ctx, req.(*ManageRetentionPolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// StorageService_ServiceDesc is the grpc.ServiceDesc for StorageService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var StorageService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blackice.v1.StorageService",
	HandlerType: (*StorageServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateTable",
			Handler:    _StorageService_CreateTable_Handler,
		},
		{
			MethodName: "GetTableSchema",
			Handler:    _StorageService_GetTableSchema_Handler,
		},
		{
			MethodName: "WriteData",
			Handler:    _StorageService_WriteData_Handler,
		},
		{
			MethodName: "CreateSnapshot",
			Handler:    _StorageService_CreateSnapshot_Handler,
		},
		{
			MethodName: "GetSnapshot",
			Handler:    _StorageService_GetSnapshot_Handler,
		},
		{
			MethodName: "ListSnapshots",
			Handler:    _StorageService_ListSnapshots_Handler,
		},
		{
			MethodName: "RollbackTable",
			Handler:    _StorageService_RollbackTable_Handler,
		},
		{
			MethodName: "CreateBranch",
			Handler:    _StorageService_CreateBranch_Handler,
		},
		{
			MethodName: "MergeBranch",
			Handler:    _StorageService_MergeBranch_Handler,
		},
		{
			MethodName: "ListBranches",
			Handler:    _StorageService_ListBranches_Handler,
		},
		{
			MethodName: "GetStorageStats",
			Handler:    _StorageService_GetStorageStats_Handler,
		},
		{
			MethodName: "ManageRetentionPolicy",
			Handler:    _StorageService_ManageRetentionPolicy_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ReadData",
			Handler:       _StorageService_ReadData_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "blackice/proto/blackice/v1/storage.proto",
}
