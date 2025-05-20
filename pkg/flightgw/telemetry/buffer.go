// Package telemetry provides a secure framework for collecting and exposing metrics
package telemetry

// BufferFullBehavior defines the behavior when a buffer is full
type BufferFullBehavior int

const (
	// DropOldest drops the oldest items from the buffer when it's full
	DropOldest BufferFullBehavior = iota
	// DropNewest drops the newest item when the buffer is full
	DropNewest
	// BlockUntilSpace blocks until there's space in the buffer
	BlockUntilSpace
	// DropRandom drops a random item when the buffer is full
	DropRandom
	// ExpandBuffer automatically expands the buffer when it's full
	ExpandBuffer
)

// String returns the string representation of the BufferFullBehavior
func (b BufferFullBehavior) String() string {
	switch b {
	case DropOldest:
		return "drop_oldest"
	case DropNewest:
		return "drop_newest"
	case BlockUntilSpace:
		return "block_until_space"
	case DropRandom:
		return "drop_random"
	case ExpandBuffer:
		return "expand_buffer"
	default:
		return "unknown"
	}
}
