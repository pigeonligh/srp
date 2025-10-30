package nets

import (
	"io"

	"golang.org/x/sync/errgroup"
)

func IOCopy(dst io.Writer, src io.Reader) error {
	_, err := io.CopyBuffer(dst, src, make([]byte, 8192))
	return err
}

func HandleConnections(c1, c2 io.ReadWriteCloser) error {
	var pipes errgroup.Group
	pipes.Go(func() error {
		err := IOCopy(c1, c2)
		SafeCloseConn(c1)
		return err
	})
	pipes.Go(func() error {
		err := IOCopy(c2, c1)
		SafeCloseConn(c2)
		return err
	})

	return pipes.Wait()
}

func SafeCloseConn(c io.ReadWriteCloser) {
	if cw, ok := c.(interface {
		CloseWrite() error
	}); ok {
		_ = cw.CloseWrite()
	} else {
		_ = c.Close()
	}
}
