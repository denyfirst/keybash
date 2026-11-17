//go:build !linux || !amd64

package rdplab

import (
	"context"
	"net"
)

func ServeRDPManager(context.Context, ManagerConfig) error { return errNative }
func connectRDPManager(context.Context, context.Context, string, func(context.Context) (net.Conn, error), *Identity, bool) (net.Conn, error) {
	return nil, errNative
}
func RunNativeWorker(string, uint32, uint32, bool) error { return errNative }
func RuntimeInventory(string) ([32]byte, error)          { return [32]byte{}, errNative }
