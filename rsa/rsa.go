package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/yangtizi/crypto/zlib"
)

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

// WxRSA RSA加密
func WxRSA(origData []byte, pubKey []byte) ([]byte, error) {
	block, _ := pem.Decode(pubKey) //将密钥解析成公钥实例
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData) //RSA算法加密
}

// WxCoRSA 压缩加密 (对于比较大的必须要这样, 不然会报错)
func WxCoRSA(origData []byte, pubKey []byte) ([]byte, error) {
	block, _ := pem.Decode(pubKey) //将密钥解析成公钥实例
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)

	buffer := bytes.NewBufferString("")

	partLen := pub.N.BitLen()/8 - 11
	chunks := split(zlib.Compress(origData), partLen)

	for _, chunk := range chunks {
		by, err := rsa.EncryptPKCS1v15(rand.Reader, pub, chunk)
		if err != nil {
			return nil, err
		}
		buffer.Write(by)
	}

	return buffer.Bytes(), nil //RSA算法加密
}

// 生成 rsakey

func GenerateRsaKey(keySize int, dirPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return err
	}
	// x509
	derText := x509.MarshalPKCS1PrivateKey(privateKey)
	// pem Block
	block := &pem.Block{
		Type:  "rsa private key",
		Bytes: derText,
	}
	// just joint, caller must let dirPath right
	file, err := os.Create(dirPath + "private.pem")
	if err != nil {
		return err
	}

	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	// get PublicKey from privateKey
	publicKey := privateKey.PublicKey
	derStream, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "rsa public key",
		Bytes: derStream,
	}
	file, err = os.Create(dirPath + "public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func Encrypt(plainText []byte, filePath string) ([]byte, error) {
	// get pem.Block
	block, err := GetKey(filePath)
	if err != nil {
		return nil, err
	}
	// X509
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, flag := publicInterface.(*rsa.PublicKey)
	if !flag {
		return nil, err
	}
	// encrypt
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func Decrypt(cipherText []byte, filePath string) (plainText []byte, err error) {
	// get pem.Block
	block, err := GetKey(filePath)
	if err != nil {
		return nil, err
	}
	// get privateKey
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	// get plainText use privateKey
	plainText, err3 := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err3 != nil {
		return nil, err
	}
	return plainText, nil
}

func GetKey(filePath string) (*pem.Block, error) {
	file, err := os.Open(filePath)

	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(buf)
	return block, nil
}
