package gotun2socks

import (
	"sync"
)

var (
	bufPool *sync.Pool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, MTU)
		},
	}
)

func newBuffer() []byte {
	return bufPool.Get().([]byte)
}

func releaseBuffer(buf []byte) {
	bufPool.Put(buf)
}
