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

// At most outputWindow frames await their in-order render credit. One frame
// per round trip made bulk output unusable over any real link; a window keeps
// browser memory bounded while letting long sessions keep pace.
const outputWindow = 32

// A browser that stops acknowledging (closed laptop, stalled tab) releases the
// stream after this long with a full window. Background tabs are throttled, so
// this is deliberately longer than a timer-clamped render callback.
const creditTimeout = 2 * time.Minute

type flow struct {
	mu          sync.Mutex
	sent, acked uint32
	credit      chan struct{}
}

// acknowledge accepts only the next unacknowledged frame that was actually
// sent. Duplicate, out-of-order or future credit refuses.
func (f *flow) acknowledge(sequence uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sequence == 0 || sequence != f.acked+1 || sequence > f.sent {
		return false
	}
	f.acked = sequence
	select {
	case f.credit <- struct{}{}:
	default:
	}
	return true
}

// reserve assigns the next sequence when the window has room.
func (f *flow) reserve() (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sent-f.acked >= outputWindow {
		return 0, false
	}
	f.sent++
	return f.sent, true
}

// outputLimit <= 0 means no lifetime ceiling; the window, the bounded queues
// and the session's idle/absolute lifetime bound an owned stream instead.
func run(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, stream Stream, outputLimit int, wait time.Duration) {
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
		sentBytes := 0
		for {
			select {
			case <-ctx.Done():
				return
			case data, ok := <-chunks:
				if !ok || outputLimit > 0 && len(data) > outputLimit-sentBytes {
					return
				}
				sentBytes += len(data)
				sequence, ok := window.reserve()
				for !ok {
					timer := time.NewTimer(wait)
					select {
					case <-window.credit:
						timer.Stop()
					case <-timer.C:
						return
					case <-ctx.Done():
						timer.Stop()
						return
					}
					sequence, ok = window.reserve()
				}
				if sequence == ^uint32(0) {
					return
				}
				frame := make([]byte, 4+len(data))
				binary.BigEndian.PutUint32(frame, sequence)
				copy(frame[4:], data)
				writeCtx, stop := context.WithTimeout(ctx, 10*time.Second)
				err := conn.Write(writeCtx, websocket.MessageBinary, frame)
				stop()
				if err != nil {
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
		var command control
		if kind != websocket.MessageBinary {
			var ok bool
			if command, ok = parseControl(data); !ok {
				return
			}
			// Valid credit is bounded by frames the server chose to send, so it
			// does not spend the input budget. Any invalid credit closes.
			if command.Type == "ack" {
				if !window.acknowledge(command.Sequence) {
					return
				}
				continue
			}
		}
		if time.Since(start) >= time.Second {
			start, frames, inputBytes = time.Now(), 0, 0
		}
		frames++
		inputBytes += len(data)
		if frames > 128 || inputBytes > 256*1024 {
			return
		}
		next := inputFrame{columns: command.Columns, rows: command.Rows}
		if kind == websocket.MessageBinary {
			if len(data) == 0 {
				continue
			}
			next = inputFrame{data: data}
		}
		select {
		case input <- next:
		case <-ctx.Done():
			return
		default:
			return
		}
	}
}

type stderrSource struct{ Stream }

func (s stderrSource) Read(data []byte) (int, error) { return s.ReadStderr(data) }
