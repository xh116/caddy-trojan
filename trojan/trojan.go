package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"	

	"github.com/xh116/caddy-trojan/socks"
	"github.com/xh116/caddy-trojan/utils"
)

// HeaderLen is ...
const HeaderLen = 56

const (
	// CmdConnect is ...
	CmdConnect = 1
	// CmdAssociate is ...
	CmdAssociate = 3
)

// GenKey is ...
func GenKey(s string, key []byte) {
	hash := sha256.Sum224(utils.StringToByteSlice(s))
	hex.Encode(key, hash[:])
}

// Handle is ...
func Handle(r io.Reader, w io.Writer) (int64, int64, error) {
	b := [1 + socks.MaxAddrLen + 2]byte{}

	// read command
	if _, err := io.ReadFull(r, b[:1]); err != nil {
		return 0, 0, fmt.Errorf("read command error: %w", err)
	}
	if b[0] != CmdConnect && b[0] != CmdAssociate {
		return 0, 0, errors.New("command error")
	}

	// read address
	addr, err := socks.ReadAddrBuffer(r, b[3:])
	if err != nil {
		return 0, 0, fmt.Errorf("read addr error: %w", err)
	}

	// read 0x0d, 0x0a
	if _, err := io.ReadFull(r, b[1:3]); err != nil {
		return 0, 0, fmt.Errorf("read 0x0d 0x0a error: %w", err)
	}

	timeStr := time.Now().In(time.FixedZone("CST", 8*3600)).Format("Jan-2 15:04:05")

        switch b[0] {
	case CmdConnect:	
              dstAddr := addr.String()
	      srcAddr := w.(net.Conn).RemoteAddr().String()
	      nr, nw, err := HandleTCP(r, w, dstAddr)
		
		fmt.Printf("[%s] TCP connection from %s to %s, upload %d bytes, download %d bytes\n", timeStr, srcAddr, dstAddr, nr, nw)
		
		if err != nil {
			return nr, nw, fmt.Errorf("handle tcp error: %w", err)
		}
		return nr, nw, nil
		
	case CmdAssociate:
	      dstAddr := addr.String()
	      srcAddr := w.(net.Conn).RemoteAddr().String()
	      nr, nw, err := HandleUDP(r, w, time.Minute*10)
	      
		fmt.Printf("[%s] UDP connection from %s to %s, upload %d bytes, download %d bytes\n", timeStr, srcAddr, dstAddr, nr, nw)

		if err != nil {
			return nr, nw, fmt.Errorf("handle udp error: %w", err)
		}
		return nr, nw, nil
	default:
	}
	return 0, 0, errors.New("command error")
}
