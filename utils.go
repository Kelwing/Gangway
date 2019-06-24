package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func (f *AuthFramework) GenerateKeyPair(privateKeyPath string, bitSize int) (privPath, pubPath string) {
	log.Println("Generating private key with bit size: ", bitSize)
	var err error
	f.KeyPair, err = rsa.GenerateKey(rand.Reader, bitSize)
	checkError(err)

	privPath = privateKeyPath
	pubPath = fmt.Sprintf("%s.pub", privateKeyPath)

	savePEMKey(privateKeyPath, f.KeyPair)
	savePublicPEMKey(pubPath, f.KeyPair.PublicKey)
	return
}

func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	privateKey, _ := pem.Decode(data)

	return x509.ParsePKCS1PrivateKey(privateKey.Bytes)
}

func LoadPublicKey(filename string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	publicKey, _ := pem.Decode(data)

	return x509.ParsePKCS1PublicKey(publicKey.Bytes)
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	log.Print("Saving private key: ", fileName)
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		log.Fatalln("Fatal error ", err.Error())
	}
}
