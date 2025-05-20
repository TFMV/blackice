package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/flight"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	addr    = flag.String("addr", "localhost:8991", "Address of the Flight Data Server")
	action  = flag.String("action", "store", "Action to perform: store, retrieve, list, stats, ping, delete")
	batchID = flag.String("id", "", "Batch ID for retrieve or delete operations")
	numRows = flag.Int("rows", 1000, "Number of rows to generate for store operation")
	verbose = flag.Bool("v", false, "Enable verbose logging")
)

func main() {
	// Parse command line flags
	flag.Parse()

	// Configure logging
	if *verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to the Flight server
	client, err := connectToServer(ctx, *addr)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to Flight server")
	}
	// Note: The underlying gRPC connection will be managed by Go's garbage collector

	// Perform the requested action
	switch *action {
	case "store":
		batchID, err := storeBatch(ctx, client, *numRows)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to store batch")
		}
		fmt.Printf("Successfully stored batch with ID: %s\n", batchID)

	case "retrieve":
		if *batchID == "" {
			log.Fatal().Msg("Batch ID is required for retrieve operation")
		}
		batch, err := retrieveBatch(ctx, client, *batchID)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to retrieve batch")
		}
		printBatchInfo(batch)
		batch.Release()

	case "list":
		batches, err := listBatches(ctx, client)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to list batches")
		}
		fmt.Printf("Found %d batches:\n", len(batches))
		for i, info := range batches {
			fmt.Printf("%d. Batch ID: %s, Records: %d\n", i+1, string(info.FlightDescriptor.Cmd), info.TotalRecords)
		}

	case "stats":
		stats, err := getServerStats(ctx, client)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get server stats")
		}
		fmt.Println("Server statistics:")
		fmt.Println(stats)

	case "ping":
		response, err := pingServer(ctx, client)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to ping server")
		}
		fmt.Printf("Server response: %s\n", response)

	case "delete":
		if *batchID == "" {
			log.Fatal().Msg("Batch ID is required for delete operation")
		}
		err := deleteBatch(ctx, client, *batchID)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to delete batch")
		}
		fmt.Printf("Successfully deleted batch with ID: %s\n", *batchID)

	default:
		log.Fatal().Str("action", *action).Msg("Unknown action")
	}
}

// connectToServer establishes a connection to the Flight server
func connectToServer(ctx context.Context, addr string) (flight.Client, error) {
	log.Debug().Str("addr", addr).Msg("Connecting to Flight server")

	// Set up gRPC dial options
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(256*1024*1024), // 256MB
			grpc.MaxCallSendMsgSize(256*1024*1024), // 256MB
		),
	}

	// Create the Flight client with no middleware
	client, err := flight.NewClientWithMiddleware(addr, nil, nil, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	log.Debug().Msg("Successfully connected to Flight server")
	return client, nil
}

// storeBatch creates and stores a batch of data on the server
func storeBatch(ctx context.Context, client flight.Client, numRows int) (string, error) {
	log.Debug().Int("numRows", numRows).Msg("Creating batch to store")

	// Create a memory allocator
	allocator := memory.NewGoAllocator()

	// Create a sample record batch with int64 and float64 columns
	intBuilder := array.NewInt64Builder(allocator)
	defer intBuilder.Release()

	floatBuilder := array.NewFloat64Builder(allocator)
	defer floatBuilder.Release()

	stringBuilder := array.NewStringBuilder(allocator)
	defer stringBuilder.Release()

	// Add values to the columns
	for i := 0; i < numRows; i++ {
		intBuilder.Append(int64(i))
		floatBuilder.Append(float64(i) * 1.1)
		stringBuilder.Append(fmt.Sprintf("row-%d", i))
	}

	// Build the arrays
	intArray := intBuilder.NewArray()
	defer intArray.Release()

	floatArray := floatBuilder.NewArray()
	defer floatArray.Release()

	stringArray := stringBuilder.NewArray()
	defer stringArray.Release()

	// Create the schema
	schema := arrow.NewSchema(
		[]arrow.Field{
			{Name: "id", Type: arrow.PrimitiveTypes.Int64},
			{Name: "value", Type: arrow.PrimitiveTypes.Float64},
			{Name: "name", Type: arrow.BinaryTypes.String},
		},
		nil,
	)

	// Create the record batch
	batch := array.NewRecord(schema, []arrow.Array{intArray, floatArray, stringArray}, int64(numRows))
	defer batch.Release()

	// Create a Flight descriptor
	descriptor := &flight.FlightDescriptor{
		Type: flight.DescriptorPATH,
		Path: []string{"sample_data"},
	}

	// Send the batch to the server
	writer, err := client.DoPut(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to start DoPut: %w", err)
	}

	// Send the descriptor first
	err = writer.Send(&flight.FlightData{
		FlightDescriptor: descriptor,
	})
	if err != nil {
		return "", fmt.Errorf("failed to send descriptor: %w", err)
	}

	// Create a writer for the stream with the schema
	recWriter := flight.NewRecordWriter(writer, ipc.WithSchema(schema))

	// Send the data to the server
	err = recWriter.Write(batch)
	if err != nil {
		return "", fmt.Errorf("failed to write batch: %w", err)
	}

	// Close the writer
	err = recWriter.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close writer: %w", err)
	}

	// Get the result
	result, err := writer.Recv()
	if err != nil {
		return "", fmt.Errorf("failed to receive result: %w", err)
	}

	log.Debug().Str("batchID", string(result.AppMetadata)).Msg("Batch stored successfully")
	return string(result.AppMetadata), nil
}

// retrieveBatch retrieves a batch of data from the server
func retrieveBatch(ctx context.Context, client flight.Client, batchID string) (arrow.Record, error) {
	log.Debug().Str("batchID", batchID).Msg("Retrieving batch")

	// Create a ticket for the batch
	ticket := &flight.Ticket{
		Ticket: []byte(batchID),
	}

	// Get the data from the server
	stream, err := client.DoGet(ctx, ticket)
	if err != nil {
		return nil, fmt.Errorf("failed to start DoGet: %w", err)
	}

	// Create a reader for the stream
	reader, err := flight.NewRecordReader(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to create reader: %w", err)
	}

	// Read the batch
	var batch arrow.Record
	if reader.Next() {
		batch = reader.Record()
		batch.Retain() // Retain the batch so it's not released when the reader is released
	} else if err := reader.Err(); err != nil {
		return nil, fmt.Errorf("error reading batch: %w", err)
	} else {
		return nil, fmt.Errorf("no data received")
	}

	// Release the reader
	reader.Release()

	log.Debug().Str("batchID", batchID).Int64("rows", batch.NumRows()).Msg("Batch retrieved successfully")
	return batch, nil
}

// listBatches lists all batches stored on the server
func listBatches(ctx context.Context, client flight.Client) ([]*flight.FlightInfo, error) {
	log.Debug().Msg("Listing batches")

	// Create a criteria for listing
	criteria := &flight.Criteria{}

	// List the flights
	stream, err := client.ListFlights(ctx, criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to start ListFlights: %w", err)
	}

	// Collect the flight information
	var infos []*flight.FlightInfo
	for {
		info, err := stream.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("error receiving flight info: %w", err)
		}
		infos = append(infos, info)
	}

	log.Debug().Int("count", len(infos)).Msg("Batches listed successfully")
	return infos, nil
}

// getServerStats gets server statistics
func getServerStats(ctx context.Context, client flight.Client) (string, error) {
	log.Debug().Msg("Getting server statistics")

	// Create an action for getting statistics
	action := &flight.Action{
		Type: "stats",
		Body: []byte{},
	}

	// Execute the action
	stream, err := client.DoAction(ctx, action)
	if err != nil {
		return "", fmt.Errorf("failed to start DoAction: %w", err)
	}

	// Get the result
	result, err := stream.Recv()
	if err != nil {
		return "", fmt.Errorf("failed to receive result: %w", err)
	}

	log.Debug().Msg("Server statistics retrieved successfully")
	return string(result.Body), nil
}

// pingServer pings the server
func pingServer(ctx context.Context, client flight.Client) (string, error) {
	log.Debug().Msg("Pinging server")

	// Create an action for pinging
	action := &flight.Action{
		Type: "ping",
		Body: []byte{},
	}

	// Execute the action
	stream, err := client.DoAction(ctx, action)
	if err != nil {
		return "", fmt.Errorf("failed to start DoAction: %w", err)
	}

	// Get the result
	result, err := stream.Recv()
	if err != nil {
		return "", fmt.Errorf("failed to receive result: %w", err)
	}

	log.Debug().Msg("Server pinged successfully")
	return string(result.Body), nil
}

// deleteBatch deletes a batch from the server
func deleteBatch(ctx context.Context, client flight.Client, batchID string) error {
	log.Debug().Str("batchID", batchID).Msg("Deleting batch")

	// Create an action for deleting
	action := &flight.Action{
		Type: "delete_batch",
		Body: []byte(batchID),
	}

	// Execute the action
	stream, err := client.DoAction(ctx, action)
	if err != nil {
		return fmt.Errorf("failed to start DoAction: %w", err)
	}

	// Get the result
	result, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive result: %w", err)
	}

	log.Debug().Str("response", string(result.Body)).Msg("Batch deleted successfully")
	return nil
}

// printBatchInfo prints information about a batch
func printBatchInfo(batch arrow.Record) {
	fmt.Printf("Batch information:\n")
	fmt.Printf("  Number of rows: %d\n", batch.NumRows())
	fmt.Printf("  Number of columns: %d\n", batch.NumCols())

	// Print schema information
	fmt.Printf("  Schema:\n")
	for i, field := range batch.Schema().Fields() {
		fmt.Printf("    Column %d: %s (%s)\n", i, field.Name, field.Type)
	}

	// Print the first 10 rows
	maxRows := 10
	if int(batch.NumRows()) < maxRows {
		maxRows = int(batch.NumRows())
	}

	fmt.Printf("  First %d rows:\n", maxRows)
	for i := 0; i < maxRows; i++ {
		fmt.Printf("    Row %d: ", i)
		for j := 0; j < int(batch.NumCols()); j++ {
			fmt.Printf("%v ", batch.Column(j).GetOneForMarshal(i))
			if j < int(batch.NumCols())-1 {
				fmt.Printf("| ")
			}
		}
		fmt.Println()
	}
}
