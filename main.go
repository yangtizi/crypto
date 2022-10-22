package main

import (
	"fmt"

	"github.com/yangtizi/crypto/aes"
	"github.com/yangtizi/crypto/googleauth"
	"github.com/yangtizi/crypto/gzip"
	"github.com/yangtizi/crypto/rsa"
	"github.com/yangtizi/crypto/zlib"
)

func main() {
	aesDemo1()
	aesDemo2()
	zlibDemo()
	gzipDemo()
	googleauthDemo("yangtizi")
	rsaDemo1()
}

func aesDemo1() {
	fmt.Println("aseDemo1 -----------------")
	strWary := "warrially"          // 加密原文
	strAESKey := "1234567812345678" // AES KEY

	bufCrypto, _ := aes.CoAES([]byte(strWary), []byte(strAESKey), make([]byte, 16, 16), "PKCS5")
	fmt.Println("加密后是: ", bufCrypto)

	strWary2, _ := aes.UnAES(bufCrypto, []byte(strAESKey), make([]byte, 16, 16), "PKCS5")
	fmt.Println("解密", string(strWary2)) //
	fmt.Println("aseDemo1 -----------------")
}

func aesDemo2() {
	fmt.Println("aseDemo2 -----------------")
	strWary := "warrially"          // 加密原文
	strAESKey := "1234567812345678" // AES KEY

	bufCrypto, _ := aes.CoAES([]byte(strWary), []byte(strAESKey), []byte(strAESKey), "PKCS7")
	fmt.Println("加密后是: ", bufCrypto)

	strWary2, _ := aes.UnAES(bufCrypto, []byte(strAESKey), []byte(strAESKey), "PKCS7")
	fmt.Println("解密", string(strWary2)) //
	fmt.Println("aseDemo2 -----------------")
}

func zlibDemo() {
	fmt.Println("zlibDemo -----------------")
	strWary := "warrially"

	bufCrypto := zlib.Compress([]byte(strWary))
	fmt.Println("加密后是: ", bufCrypto)

	strWary2 := zlib.UnCompress(bufCrypto)
	fmt.Println("解密", string(strWary2)) //
	fmt.Println("zlibDemo -----------------")
}

func gzipDemo() {
	a := []byte("xiaonini")

	b := gzip.Compress(a)
	fmt.Println(b)

	c := gzip.UnCompress(b)
	fmt.Println(c)
	fmt.Println(string(c))
}

func googleauthDemo(user string) (secret, code string) {
	// 秘钥
	secret = googleauth.GetSecret()
	fmt.Println("Secret:", secret)

	// 动态码(每隔30s会动态生成一个6位数的数字)
	code, err := googleauth.GetCode(secret)
	fmt.Println("Code:", code, err)

	// 用户名
	qrCode := googleauth.GetQrcode(user, code)
	fmt.Println("Qrcode", qrCode)

	// 打印二维码地址
	qrCodeUrl := googleauth.GetQrcodeUrl(user, secret)
	fmt.Println("QrcodeUrl", qrCodeUrl)

	return
}

func rsaDemo1() {
	rsa.GenerateRsaKey(2048, "./")

	a, _ := rsa.Encrypt([]byte("I Love Lisa"), "./public.pem")

	b, _ := rsa.Decrypt(a, "./private.pem")

	fmt.Println(string(b))
}
