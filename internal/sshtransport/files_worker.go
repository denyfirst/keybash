package sshtransport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/keybash/internal/sftpclient"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// errCancelled is a Files operation the gateway stopped.
var errCancelled = errors.New("file operation cancelled")

// At most this many links in one folder are followed to say whether they
// point at a folder or a file; the rest are shown as links.
const maxLinkStats = 256

type fileFrame struct {
	kind byte
	data []byte
}

// filesWorker serves one Files session: one operation at a time, over the
// sftp channel the worker authenticated exactly as a terminal does.
type filesWorker struct {
	client *sftpclient.Client
	output io.Writer
	frames <-chan fileFrame
	mode   terminalweb.FilesMode
	// A failed upload's bytes the gateway had already sent, dropped here.
	discard uint64
}

// serveFiles runs after the worker said ready. The gateway sends requests,
// cancels and upload bytes; anything out of place ends the session.
func serveFiles(ctx context.Context, cancel context.CancelFunc, terminal *Terminal, input io.ReadCloser, output io.WriteCloser, mode terminalweb.FilesMode) error {
	defer cancel()
	// The SFTP server's own messages are never shown; they are read so the
	// channel's window keeps moving.
	go func() { _, _ = io.Copy(io.Discard, terminal.channel.Stderr()) }()
	start, stop := context.WithTimeout(ctx, 10*time.Second)
	client, err := sftpclient.New(start, terminal.channel)
	stop()
	if err != nil {
		return ErrProcess
	}
	frames := make(chan fileFrame, 2)
	go func() {
		defer close(frames)
		defer cancel()
		for {
			kind, data, err := readWorkerFrame(input)
			if err != nil {
				return
			}
			select {
			case frames <- fileFrame{kind, data}:
			case <-ctx.Done():
				return
			}
		}
	}()
	w := &filesWorker{client: client, output: output, frames: frames, mode: mode}
	for {
		select {
		case <-ctx.Done():
			return nil
		case frame, open := <-frames:
			if !open {
				return nil
			}
			if err := w.frame(ctx, frame); err != nil {
				return err
			}
		}
	}
}

// frame handles one frame while no operation runs.
func (w *filesWorker) frame(ctx context.Context, frame fileFrame) error {
	switch frame.kind {
	case frameFileCancel:
		// A cancel can cross the operation's own end; it then has nothing to stop.
		if _, ok := decodeID(frame.data); !ok {
			return ErrProcess
		}
		return nil
	case frameFileData:
		if uint64(len(frame.data)) > w.discard {
			return ErrProcess
		}
		w.discard -= uint64(len(frame.data))
		return nil
	case frameFileRequest:
	default:
		return ErrProcess
	}
	request, ok := decodeFileRequest(frame.data)
	if !ok {
		return ErrProcess
	}
	w.discard = 0
	if request.Op.Writes() && w.mode != terminalweb.FilesBoth {
		return w.failed(request.ID, terminalweb.FailNotAllowed)
	}
	var err error
	switch request.Op {
	case terminalweb.OpList:
		err = w.list(request)
	case terminalweb.OpMkdir:
		err = w.mkdir(request)
	case terminalweb.OpRename:
		err = w.rename(request)
	case terminalweb.OpRemove:
		err = w.remove(request)
	case terminalweb.OpRmdir:
		err = w.rmdir(request)
	case terminalweb.OpGet:
		err = w.get(ctx, request)
	case terminalweb.OpPut, terminalweb.OpReplace:
		err = w.put(ctx, request)
	default:
		return ErrProcess
	}
	if err == nil {
		return nil
	}
	if fatal(err) {
		return ErrProcess
	}
	return w.failed(request.ID, failure(err))
}

// fatal is an error after which the SFTP stream or the pipe cannot be
// trusted, so the session ends.
func fatal(err error) bool {
	return errors.Is(err, sftpclient.ErrProtocol) || errors.Is(err, ErrProcess)
}

// failure turns an error into the one word the page gets.
func failure(err error) terminalweb.FileFailure {
	var status *sftpclient.StatusError
	switch {
	case errors.Is(err, errCancelled), errors.Is(err, context.Canceled):
		return terminalweb.FailCancelled
	case errors.Is(err, sftpclient.ErrTooLarge), errors.Is(err, sftpclient.ErrTooMany):
		return terminalweb.FailTooLarge
	case errors.As(err, &status) && status.Code == sftpclient.StatusNoSuchFile:
		return terminalweb.FailMissing
	case errors.As(err, &status) && status.Code == sftpclient.StatusPermissionDenied:
		return terminalweb.FailDenied
	}
	var known terminalweb.FileFailure
	if errors.As(err, &known) && terminalweb.ValidFailure(known) {
		return known
	}
	return terminalweb.FailFailed
}

func (w *filesWorker) send(kind byte, data []byte) error {
	if writeWorkerFrame(w.output, kind, data) != nil {
		return ErrProcess
	}
	return nil
}

func (w *filesWorker) failed(id uint32, why terminalweb.FileFailure) error {
	return w.send(frameFileFailed, encodeFailed(id, why))
}

func (w *filesWorker) done(id uint32, size uint64, where string) error {
	data, ok := encodeDone(id, size, where)
	if !ok {
		return w.failed(id, terminalweb.FailFailed)
	}
	return w.send(frameFileDone, data)
}

// exists asks whether something already has this name, without following a
// link. A missing name is the only answer that lets a new one be made.
func (w *filesWorker) exists(p string) (sftpclient.Attr, bool, error) {
	attr, err := w.client.Lstat(p)
	var status *sftpclient.StatusError
	if errors.As(err, &status) && status.Code == sftpclient.StatusNoSuchFile {
		return sftpclient.Attr{}, false, nil
	}
	if err != nil {
		return sftpclient.Attr{}, false, err
	}
	return attr, true, nil
}

func kindOf(kind sftpclient.Kind) terminalweb.FileKind {
	switch kind {
	case sftpclient.KindFile:
		return terminalweb.KindFile
	case sftpclient.KindDir:
		return terminalweb.KindDir
	case sftpclient.KindLink:
		return terminalweb.KindLink
	}
	return terminalweb.KindOther
}

func (w *filesWorker) list(r terminalweb.FileRequest) error {
	where := r.Path
	if where == "" {
		where = "."
	}
	folder, err := w.client.RealPath(where)
	if err != nil {
		return err
	}
	if !terminalweb.ValidFilePath(folder) {
		return terminalweb.FailFailed
	}
	var entries []terminalweb.FileEntry
	err = w.client.List(folder, terminalweb.MaxEntries, func(e sftpclient.Entry) error {
		entries = append(entries, terminalweb.FileEntry{Name: append([]byte(nil), e.Name...), Kind: kindOf(e.Attr.Kind), Size: e.Attr.Size, Time: e.Attr.ModTime})
		return nil
	})
	if err != nil {
		return err
	}
	links := 0
	for i := range entries {
		if entries[i].Kind != terminalweb.KindLink || links == maxLinkStats || !utf8.Valid(entries[i].Name) {
			continue
		}
		links++
		target := path.Join(folder, string(entries[i].Name))
		if !terminalweb.ValidFilePath(target) {
			continue
		}
		attr, err := w.client.Stat(target)
		if fatal(err) {
			return err
		}
		if err == nil && (attr.Kind == sftpclient.KindDir || attr.Kind == sftpclient.KindFile) {
			entries[i].Target = kindOf(attr.Kind)
		}
	}
	batch := newEntryBatch(r.ID)
	for _, entry := range entries {
		if batch.add(entry) {
			continue
		}
		if err := w.send(frameFileEntries, batch.data); err != nil {
			return err
		}
		batch = newEntryBatch(r.ID)
		batch.add(entry)
	}
	if !batch.empty() {
		if err := w.send(frameFileEntries, batch.data); err != nil {
			return err
		}
	}
	return w.done(r.ID, 0, folder)
}

func (w *filesWorker) mkdir(r terminalweb.FileRequest) error {
	if _, taken, err := w.exists(r.Path); err != nil || taken {
		return orExists(err)
	}
	if err := w.client.Mkdir(r.Path); err != nil {
		return err
	}
	return w.done(r.ID, 0, "")
}

func orExists(err error) error {
	if err != nil {
		return err
	}
	return terminalweb.FailExists
}

func (w *filesWorker) rename(r terminalweb.FileRequest) error {
	if _, taken, err := w.exists(r.To); err != nil || taken {
		return orExists(err)
	}
	if err := w.client.Rename(r.Path, r.To); err != nil {
		return err
	}
	return w.done(r.ID, 0, "")
}

// remove deletes a file or a link, never a folder.
func (w *filesWorker) remove(r terminalweb.FileRequest) error {
	attr, err := w.client.Lstat(r.Path)
	if err != nil {
		return err
	}
	if attr.Kind == sftpclient.KindDir {
		return terminalweb.FailFailed
	}
	if err := w.client.Remove(r.Path); err != nil {
		return err
	}
	return w.done(r.ID, 0, "")
}

var errNotEmpty = errors.New("folder not empty")

// rmdir deletes only an empty folder: Keybash never deletes a tree.
func (w *filesWorker) rmdir(r terminalweb.FileRequest) error {
	attr, err := w.client.Lstat(r.Path)
	if err != nil {
		return err
	}
	if attr.Kind != sftpclient.KindDir {
		return terminalweb.FailFailed
	}
	err = w.client.List(r.Path, terminalweb.MaxEntries, func(sftpclient.Entry) error { return errNotEmpty })
	if errors.Is(err, errNotEmpty) {
		return terminalweb.FailNotEmpty
	}
	if err != nil {
		return err
	}
	if err := w.client.Rmdir(r.Path); err != nil {
		return err
	}
	return w.done(r.ID, 0, "")
}

// operation is a context that a matching cancel from the gateway ends. Only
// a cancel may arrive while a download runs; anything else ends the session.
func (w *filesWorker) operation(ctx context.Context, id uint32) (context.Context, func() error) {
	op, cancel := context.WithCancelCause(ctx)
	quit := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		for {
			select {
			case <-quit:
				result <- nil
				return
			case frame, open := <-w.frames:
				if !open {
					cancel(ErrProcess)
					result <- ErrProcess
					return
				}
				got, ok := decodeID(frame.data)
				if frame.kind != frameFileCancel || !ok {
					cancel(ErrProcess)
					result <- ErrProcess
					return
				}
				if got == id {
					cancel(errCancelled)
				}
			}
		}
	}()
	return op, func() error {
		close(quit)
		err := <-result
		cancel(nil)
		return err
	}
}

func (w *filesWorker) get(ctx context.Context, r terminalweb.FileRequest) error {
	// Only a file is downloaded, a link's file included: opening anything else,
	// such as a FIFO, can hold the server's SFTP process.
	attr, err := w.client.Stat(r.Path)
	if err != nil {
		return err
	}
	if attr.Kind != sftpclient.KindFile {
		return terminalweb.FailFailed
	}
	op, finish := w.operation(ctx, r.ID)
	size, err := w.client.Download(op, r.Path, terminalweb.MaxFileSize,
		func(size int64) error { return w.send(frameFileAccept, encodeAccept(r.ID, uint64(size))) }, // #nosec G115 -- the client checked it against the limit
		func(chunk []byte) error { return w.send(frameFileData, chunk) })
	if watched := finish(); watched != nil {
		return watched
	}
	if err != nil {
		if errors.Is(context.Cause(op), errCancelled) {
			return errCancelled
		}
		return err
	}
	return w.done(r.ID, uint64(size), "") // #nosec G115 -- a size the client counted, at most the limit
}

// put uploads to a fresh hidden name in the same folder, then gives it its
// name, so a cancelled or failed upload never leaves half a file under the
// real name, and a replaced file stays whole until the new one is complete.
func (w *filesWorker) put(ctx context.Context, r terminalweb.FileRequest) error {
	attr, taken, err := w.exists(r.Path)
	if err != nil {
		return err
	}
	if taken && (r.Op == terminalweb.OpPut || attr.Kind != sftpclient.KindFile) {
		return terminalweb.FailExists
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return terminalweb.FailFailed
	}
	part := path.Join(path.Dir(r.Path), ".keybash-upload-"+hex.EncodeToString(random[:]))
	if !terminalweb.ValidFilePath(part) {
		return terminalweb.FailFailed
	}
	left := r.Size
	accepted := false
	next := func() ([]byte, error) {
		// The go-ahead goes only once the server opened the file, so a
		// refused upload never has bytes on their way.
		if !accepted {
			accepted = true
			if err := w.send(frameFileAccept, encodeAccept(r.ID, 0)); err != nil {
				return nil, err
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case frame, open := <-w.frames:
			if !open {
				return nil, ErrProcess
			}
			switch frame.kind {
			case frameFileData:
				if uint64(len(frame.data)) > left {
					return nil, ErrProcess
				}
				left -= uint64(len(frame.data))
				return frame.data, nil
			case frameFileCancel:
				if id, ok := decodeID(frame.data); ok && id == r.ID {
					return nil, errCancelled
				}
			}
			return nil, ErrProcess
		}
	}
	// An empty file sends no bytes, so it gets no go-ahead: only done.
	err = w.client.Upload(ctx, part, int64(r.Size), terminalweb.MaxFileSize, next) // #nosec G115 -- at most MaxFileSize, checked by ValidFileRequest
	if err != nil {
		if accepted && !errors.Is(err, errCancelled) && !fatal(err) {
			w.discard = left
		}
		if !fatal(err) {
			_ = w.client.Remove(part)
		}
		return err
	}
	if taken {
		if err := w.client.Remove(r.Path); err != nil {
			_ = w.client.Remove(part)
			return err
		}
	}
	if err := w.client.Rename(part, r.Path); err != nil {
		_ = w.client.Remove(part)
		if _, now, e := w.exists(r.Path); e == nil && now {
			return terminalweb.FailExists
		}
		return err
	}
	return w.done(r.ID, r.Size, "")
}
