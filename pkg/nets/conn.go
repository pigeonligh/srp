package nets

import (
	"io"
	"sync"

	"golang.org/x/sync/errgroup"
)

var DefaultCopyBufferSize = 8192

func IOCopy(dst io.Writer, src io.Reader) error {
	_, err := io.CopyBuffer(dst, src, make([]byte, DefaultCopyBufferSize))
	return err
}

func HandleConnections(c1, c2 io.ReadWriteCloser) error {
	var o sync.Once
	cleanup := func() {
		o.Do(func() {
			_ = c1.Close()
			_ = c2.Close()
		})
	}
	defer cleanup()

	handleDirect := func(w io.Writer, r io.Reader) error {
		err := IOCopy(w, r)
		if err != nil && err != io.EOF {
			cleanup() // 如果一端出错，关闭连接
		} else {
			ConnCloseWrite(w) // 正常结束时，关闭写端
		}
		return err
	}

	var pipes errgroup.Group
	pipes.Go(func() error {
		return handleDirect(c1, c2)
	})
	pipes.Go(func() error {
		return handleDirect(c2, c1)
	})
	return pipes.Wait()
}

func ConnCloseWrite(c any) {
	if cw, ok := c.(interface {
		CloseWrite() error
	}); ok {
		_ = cw.CloseWrite()
	}
}
