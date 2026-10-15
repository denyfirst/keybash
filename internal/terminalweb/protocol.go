package terminalweb

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type control struct {
	Type     string `json:"type"`
	Sequence uint32 `json:"sequence,omitempty"`
	Columns  uint32 `json:"columns,omitempty"`
	Rows     uint32 `json:"rows,omitempty"`
}

func parseControl(data []byte) (control, bool) {
	var command control
	if len(data) == 0 || len(data) > 1024 {
		return command, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF {
		return control{}, false
	}
	keys := json.NewDecoder(bytes.NewReader(data))
	opening, err := keys.Token()
	if err != nil || opening != json.Delim('{') {
		return control{}, false
	}
	seen := make(map[string]bool, 4)
	for keys.More() {
		key, err := keys.Token()
		name, isString := key.(string)
		if err != nil || !isString || seen[name] || keys.Decode(new(json.RawMessage)) != nil {
			return control{}, false
		}
		seen[name] = true
	}
	switch command.Type {
	case "ack":
		return command, command.Sequence != 0 && command.Columns == 0 && command.Rows == 0
	case "resize":
		return command, command.Sequence == 0 && command.Columns > 0 && command.Columns <= 500 && command.Rows > 0 && command.Rows <= 200
	}
	return control{}, false
}

type flow struct {
	mu       sync.Mutex
	sequence uint32
	acked    bool
	credit   chan struct{}
}

func (f *flow) acknowledge(sequence uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sequence != f.sequence || sequence == 0 || f.acked {
		return false
	}
	f.acked = true
	f.credit <- struct{}{}
	return true
}

func run(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, stream Stream, outputLimit int) {
	chunks := make(chan []byte, 2)
	var readers, workers sync.WaitGroup
	// Never block the socket reader on remote input writes: output credits
	// share that socket, so a backpressured duplex stream could deadlock its
	// own ACK behind queued keyboard input. Preserve ordered input in a bounded
	// 32-frame queue (at most 1 MiB); overflow closes rather than accumulating.
	type inputFrame struct {
		data          []byte
		columns, rows uint32
	}
	input := make(chan inputFrame, 32)
	workers.Go(func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case frame := <-input:
				if frame.data != nil {
					n, e := stream.Write(frame.data)
					if e != nil || n != len(frame.data) {
						return
					}
				} else if stream.Resize(frame.columns, frame.rows) != nil {
					return
				}
			}
		}
	})
	read := func(source io.Reader) {
		defer readers.Done()
		buffer := make([]byte, 8192)
		for {
			n, err := source.Read(buffer)
			if n > 0 {
				chunk := append([]byte(nil), buffer[:n]...)
				select {
				case chunks <- chunk:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					cancel()
				}
				return
			}
		}
	}
	readers.Add(2)
	workers.Go(func() { read(stream) })
	workers.Go(func() { read(stderrSource{stream}) })
	workers.Go(func() { readers.Wait(); close(chunks) })
	window := &flow{credit: make(chan struct{}, 1)}
	workers.Go(func() {
		defer cancel()
		var sequence uint32
		sentBytes := 0
		for {
			select {
			case <-ctx.Done():
				return
			case data, ok := <-chunks:
				if !ok || sequence == ^uint32(0) || len(data) > outputLimit-sentBytes {
					return
				}
				sentBytes += len(data)
				sequence++
				frame := make([]byte, 4+len(data))
				binary.BigEndian.PutUint32(frame, sequence)
				copy(frame[4:], data)
				window.mu.Lock()
				window.sequence, window.acked = sequence, false
				window.mu.Unlock()
				writeCtx, stop := context.WithTimeout(ctx, 10*time.Second)
				err := conn.Write(writeCtx, websocket.MessageBinary, frame)
				stop()
				if err != nil {
					return
				}
				timer := time.NewTimer(10 * time.Second)
				select {
				case <-window.credit:
					timer.Stop()
				case <-timer.C:
					return
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}
		}
	})
	defer func() { cancel(); _ = conn.CloseNow(); _ = stream.Close(); workers.Wait() }()
	start, frames, inputBytes := time.Now(), 0, 0
	for {
		kind, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if time.Since(start) >= time.Second {
			start, frames, inputBytes = time.Now(), 0, 0
		}
		frames++
		inputBytes += len(data)
		if frames > 128 || inputBytes > 256*1024 {
			return
		}
		if kind == websocket.MessageBinary {
			if len(data) == 0 {
				continue
			}
			select {
			case input <- inputFrame{data: data}:
			case <-ctx.Done():
				return
			default:
				return
			}
			continue
		}
		command, ok := parseControl(data)
		if !ok {
			return
		}
		if command.Type == "ack" {
			if !window.acknowledge(command.Sequence) {
				return
			}
		} else {
			select {
			case input <- inputFrame{columns: command.Columns, rows: command.Rows}:
			case <-ctx.Done():
				return
			default:
				return
			}
		}
	}
}

type stderrSource struct{ Stream }

func (s stderrSource) Read(data []byte) (int, error) { return s.ReadStderr(data) }
