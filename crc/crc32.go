package crc


var Instance = NewCRC32Cls()


// TCRC32Cls .
type TCRC32Cls struct {
	crc32Table []int
}



// NewCRC32Cls .
func NewCRC32Cls() *TCRC32Cls {
	p := &TCRC32Cls{}
	//生成码表
	p.genCRC32Table()
	return p
}

// genCRC32Table 生成CRC32码表
func (m *TCRC32Cls) genCRC32Table() {
	m.crc32Table = make([]int, 256)

	for i := 0; i < 256; i++ {
		nCrc := i
		for j := 8; j > 0; j-- {
			if nCrc&1 == 1 {
				nCrc = (nCrc >> 1) ^ 0xEDB88320
			} else {
				nCrc >>= 1
			}
		}
		m.crc32Table[i] = nCrc
	}
}

func GetCRC32Str(strInputString string) int {
	return Instance.GetCRC32Str(strInputString)
}
// GetCRC32Str 获取字符串的CRC32校验值
func (m *TCRC32Cls) GetCRC32Str(strInputString string) int {
	
	m.genCRC32Table()
	buffer := []byte(strInputString)
	value := 0xFFFFFFFF

	nLen := len(buffer)
	for i := 0; i < nLen; i++ {
		value = (value >> 8) ^ m.crc32Table[(byte(value)&0xFF)^buffer[i]]
	}

	return value ^ 0xFFFFFFFF
}

func GetCRC32Byte(buffer []byte) int {
	return Instance.GetCRC32Byte(buffer)
}
// GetCRC32Byte .
func (m *TCRC32Cls) GetCRC32Byte(buffer []byte) int {
	//生成码表
	m.genCRC32Table()

	value := 0xFFFFFFFF

	nLen := len(buffer)
	for i := 0; i < nLen; i++ {
		value = (value >> 8) ^ m.crc32Table[(byte(value)&0xFF)^buffer[i]]
	}

	return value ^ 0xFFFFFFFF
}
