package sshtransport

import (
	"encoding/binary"

	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

// Files frames (ADR 0011) between the gateway and a Files worker. The gateway
// asks for one operation at a time; the worker answers with entries, an
// accept, data and then done or failed. Every frame has its own limit,
// checked before it is read (frameLimit), and every field is checked again
// when it is decoded.
const (
	frameFileRequest byte = 10 // gateway → worker: one operation
	frameFileCancel  byte = 11 // gateway → worker: stop the operation with this ID
	frameFileData    byte = 12 // both ways: an upload's or a download's next bytes
	frameFileEntries byte = 13 // worker → gateway: a batch of a folder's names
	frameFileAccept  byte = 14 // worker → gateway: a download's size, or an upload's go-ahead
	frameFileDone    byte = 15 // worker → gateway: the operation finished
	frameFileFailed  byte = 16 // worker → gateway: the operation failed, as one code

	fileRequestFrameLimit = 2*terminalweb.MaxFilePath + 64
	fileDoneFrameLimit    = 14 + terminalweb.MaxFilePath
	// One entry: a length byte, the name, kind, target, size and time.
	fileEntryOverhead = 1 + 1 + 1 + 8 + 4
)

func filesFrameLimit(kind byte) int {
	switch kind {
	case frameFileRequest:
		return fileRequestFrameLimit
	case frameFileCancel:
		return 4
	case frameFileData, frameFileEntries:
		return terminalweb.FileChunk
	case frameFileAccept:
		return 12
	case frameFileDone:
		return fileDoneFrameLimit
	case frameFileFailed:
		return 5
	}
	return -1
}

type fileRequestWire struct {
	ID       uint32
	Op       string
	Path, To string
	Size     uint64
}

func encodeFileRequest(r terminalweb.FileRequest) ([]byte, bool) {
	if !terminalweb.ValidFileRequest(r) {
		return nil, false
	}
	data := ssh.Marshal(&fileRequestWire{ID: r.ID, Op: string(r.Op), Path: r.Path, To: r.To, Size: r.Size})
	return data, len(data) <= fileRequestFrameLimit
}

// decodeFileRequest is the worker's own check of what the gateway sent.
func decodeFileRequest(data []byte) (terminalweb.FileRequest, bool) {
	var wire fileRequestWire
	if len(data) > fileRequestFrameLimit || ssh.Unmarshal(data, &wire) != nil {
		return terminalweb.FileRequest{}, false
	}
	r := terminalweb.FileRequest{ID: wire.ID, Op: terminalweb.FileOp(wire.Op), Path: wire.Path, To: wire.To, Size: wire.Size}
	return r, terminalweb.ValidFileRequest(r)
}

func encodeID(id uint32) []byte { return binary.BigEndian.AppendUint32(nil, id) }

func decodeID(data []byte) (uint32, bool) {
	if len(data) != 4 {
		return 0, false
	}
	id := binary.BigEndian.Uint32(data)
	return id, id != 0
}

// entryBatch gathers one operation's entries into frames of at most
// FileChunk bytes, the operation's ID first.
type entryBatch struct{ data []byte }

func newEntryBatch(id uint32) entryBatch { return entryBatch{data: encodeID(id)} }
func (b *entryBatch) empty() bool        { return len(b.data) <= 4 }

// add appends one entry, or says the frame is full. A name is 1 to 255 bytes.
func (b *entryBatch) add(e terminalweb.FileEntry) bool {
	if len(e.Name) == 0 || len(e.Name) > terminalweb.MaxFileName {
		return true // a name that cannot be listed is left out, not sent
	}
	if len(b.data)+fileEntryOverhead+len(e.Name) > terminalweb.FileChunk {
		return false
	}
	b.data = append(b.data, byte(len(e.Name))) // #nosec G115 -- at most MaxFileName (255), checked above
	b.data = append(b.data, e.Name...)
	b.data = append(b.data, byte(e.Kind), byte(e.Target))
	b.data = binary.BigEndian.AppendUint64(b.data, e.Size)
	b.data = binary.BigEndian.AppendUint32(b.data, e.Time)
	return true
}

func decodeEntries(data []byte) (uint32, []terminalweb.FileEntry, bool) {
	if len(data) <= 4 || len(data) > terminalweb.FileChunk {
		return 0, nil, false
	}
	id, ok := decodeID(data[:4])
	if !ok {
		return 0, nil, false
	}
	data = data[4:]
	var out []terminalweb.FileEntry
	for len(data) > 0 {
		size := int(data[0])
		if size == 0 || len(data) < fileEntryOverhead+size {
			return 0, nil, false
		}
		name := append([]byte(nil), data[1:1+size]...)
		rest := data[1+size:]
		kind, target := terminalweb.FileKind(rest[0]), terminalweb.FileKind(rest[1])
		if kind > terminalweb.KindLink || target > terminalweb.KindLink || (kind != terminalweb.KindLink && target != terminalweb.KindOther) {
			return 0, nil, false
		}
		out = append(out, terminalweb.FileEntry{Name: name, Kind: kind, Target: target, Size: binary.BigEndian.Uint64(rest[2:]), Time: binary.BigEndian.Uint32(rest[10:])})
		data = rest[14:]
	}
	return id, out, true
}

func encodeAccept(id uint32, size uint64) []byte {
	return binary.BigEndian.AppendUint64(encodeID(id), size)
}

func decodeAccept(data []byte) (uint32, uint64, bool) {
	if len(data) != 12 {
		return 0, 0, false
	}
	id, ok := decodeID(data[:4])
	size := binary.BigEndian.Uint64(data[4:])
	return id, size, ok && size <= terminalweb.MaxFileSize
}

func encodeDone(id uint32, size uint64, path string) ([]byte, bool) {
	if len(path) > terminalweb.MaxFilePath || (path != "" && !terminalweb.ValidFilePath(path)) {
		return nil, false
	}
	data := binary.BigEndian.AppendUint64(encodeID(id), size)
	data = binary.BigEndian.AppendUint16(data, uint16(len(path))) // #nosec G115 -- at most MaxFilePath, checked above
	return append(data, path...), true
}

func decodeDone(data []byte) (uint32, uint64, string, bool) {
	if len(data) < 14 || len(data) > fileDoneFrameLimit {
		return 0, 0, "", false
	}
	id, ok := decodeID(data[:4])
	size := binary.BigEndian.Uint64(data[4:12])
	length := int(binary.BigEndian.Uint16(data[12:14]))
	if !ok || length != len(data)-14 || size > terminalweb.MaxFileSize {
		return 0, 0, "", false
	}
	path := string(data[14:])
	if path != "" && !terminalweb.ValidFilePath(path) {
		return 0, 0, "", false
	}
	return id, size, path, true
}

var failureCodes = []terminalweb.FileFailure{
	1: terminalweb.FailExists, 2: terminalweb.FailMissing, 3: terminalweb.FailDenied, 4: terminalweb.FailNotEmpty,
	5: terminalweb.FailTooLarge, 6: terminalweb.FailNotAllowed, 7: terminalweb.FailFailed, 8: terminalweb.FailCancelled,
}

func encodeFailed(id uint32, failure terminalweb.FileFailure) []byte {
	code := byte(7)
	for i, known := range failureCodes {
		if known != "" && known == failure {
			code = byte(i) // #nosec G115 -- the table has eight entries
		}
	}
	return append(encodeID(id), code)
}

func decodeFailed(data []byte) (uint32, terminalweb.FileFailure, bool) {
	if len(data) != 5 || data[4] == 0 || int(data[4]) >= len(failureCodes) {
		return 0, "", false
	}
	id, ok := decodeID(data[:4])
	return id, failureCodes[data[4]], ok
}
