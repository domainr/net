//go:build wasip1

package wasip1

import (
	"net"
	"os"
	"syscall"
)

// Listen announces on the local network address.
func Listen(network, address string) (net.Listener, error) {
	addrs, err := lookupAddr("listen", network, address)
	if err != nil {
		addr := &netAddr{network, address}
		return nil, listenErr(addr, err)
	}
	// TODO: implement dual-stack listening
	addr := addrs[0]
	lstn, err := listenAddr(addr)
	if err != nil {
		return nil, listenErr(addr, err)
	}
	return lstn, nil
}

func listenErr(addr net.Addr, err error) error {
	return newOpError("listen", addr, err)
}

func listenAddr(addr net.Addr) (net.Listener, error) {
	sotype, err := socketType(addr)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	fd, err := socket(family(addr), sotype, 0)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}

	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, os.NewSyscallError("setnonblock", err)
	}
	if err := setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, os.NewSyscallError("setsockopt", err)
	}

	bindAddr, err := socketAddress(addr)
	if err != nil {
		return nil, os.NewSyscallError("bind", err)
	}
	if err := bind(fd, bindAddr); err != nil {
		syscall.Close(fd)
		return nil, os.NewSyscallError("bind", err)
	}
	const backlog = 64 // TODO: configurable?
	if err := listen(fd, backlog); err != nil {
		syscall.Close(fd)
		return nil, os.NewSyscallError("listen", err)
	}

	sockaddr, err := getsockname(fd)
	if err != nil {
		syscall.Close(fd)
		return nil, os.NewSyscallError("getsockname", err)
	}

	f := os.NewFile(uintptr(fd), "")
	defer f.Close()

	l, err := net.FileListener(f)
	if err != nil {
		return nil, err
	}
	setNetAddr(l.Addr(), sockaddr)
	return &listener{l}, nil
}

type listener struct{ net.Listener }

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return makeConn(c)
}
