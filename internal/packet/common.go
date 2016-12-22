package packet

var lotsOfZeros [1024]byte

//func Checksum(data []byte) uint16 {
//	var csum uint32
//	length := len(data) - 1
//	for i := 0; i < length; i += 2 {
//		csum += uint32(data[i]) << 8
//		csum += uint32(data[i+1])
//	}
//	if len(data)%2 == 1 {
//		csum += uint32(data[length]) << 8
//	}
//	for csum > 0xffff {
//		csum = (csum >> 16) + (csum & 0xffff)
//	}
//	return ^uint16(csum + (csum >> 16))
//}

func Checksum(fields ...[]byte) uint16 {
	var csum uint32
	for _, field := range fields {
		length := len(field) - 1
		for i := 0; i < length; i += 2 {
			csum += uint32(field[i]) << 8
			csum += uint32(field[i+1])
		}
		if len(field)%2 == 1 {
			// only last field may have odd number of bytes
			csum += uint32(field[length]) << 8
		}
	}

	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum + (csum >> 16))
}
