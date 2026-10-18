package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// WorkItem represents a computational task payload.
type WorkItem struct {
	ID        string    `json:"id"`
	Payload   []byte    `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
}

// ProcessingResult encapsulates task completion statistics.
type ProcessingResult struct {
	ID        string `json:"id"`
	Digest    string `json:"digest"`
	Duration  time.Duration
	StatusOk  bool
}

// TaskProcessor defines concurrent pipeline orchestration.
type TaskProcessor struct {
	workers int
	inputCh chan WorkItem
	resCh   chan ProcessingResult
	wg      sync.WaitGroup
}

// NewTaskProcessor initializes a concurrent pipeline.
func NewTaskProcessor(workers int, bufferSize int) *TaskProcessor {
	return &TaskProcessor{
		workers: workers,
		inputCh: make(chan WorkItem, bufferSize),
		resCh:   make(chan ProcessingResult, bufferSize),
	}
}

// Start launches worker goroutines.
func (tp *TaskProcessor) Start(ctx context.Context) {
	for i := 0; i < tp.workers; i++ {
		tp.wg.Add(1)
		go func(workerID int) {
			defer tp.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case item, ok := <-tp.inputCh:
					if !ok {
						return
					}
					start := time.Now()
					h := sha256.Sum256(item.Payload)
					digest := hex.EncodeToString(h[:])
					tp.resCh <- ProcessingResult{
						ID:       item.ID,
						Digest:   digest,
						Duration: time.Since(start),
						StatusOk: true,
					}
				}
			}
		}(i)
	}
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	proc := NewTaskProcessor(4, 16)
	proc.Start(ctx)

	sampleData := []byte("දත්ත පරීක්ෂණ නියැදිය - Golang unicode stream test")
	proc.inputCh <- WorkItem{
		ID:        "item-001",
		Payload:   sampleData,
		Timestamp: time.Now(),
	}
	close(proc.inputCh)

	select {
	case res := <-proc.resCh:
		fmt.Printf("Item %s processed: digest=%s\n", res.ID, res.Digest)
	case <-ctx.Done():
		fmt.Println("Processing timed out")
	}
}
