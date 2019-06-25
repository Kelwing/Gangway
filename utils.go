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

func (f *authFramework) generateKeyPair(privateKeyPath string, bitSize int) (privPath, pubPath string, err error) {
	log.Println("Generating private key with bit size: ", bitSize)
	f.KeyPair, err = rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return
	}

	privPath = privateKeyPath
	pubPath = fmt.Sprintf("%s.pub", privateKeyPath)

	err = savePEMKey(privateKeyPath, f.KeyPair)
	if err != nil {
		return
	}
	err = savePublicPEMKey(pubPath, f.KeyPair.PublicKey)
	return
}

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	privateKey, _ := pem.Decode(data)

	return x509.ParsePKCS1PrivateKey(privateKey.Bytes)
}

func loadPublicKey(filename string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	publicKey, _ := pem.Decode(data)

	return x509.ParsePKCS1PublicKey(publicKey.Bytes)
}

func savePEMKey(fileName string, key *rsa.PrivateKey) error {
	log.Print("Saving private key: ", fileName)
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	return err
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) error {
	asn1Bytes, err := asn1.Marshal(pubkey)
	if err != nil {
		return err
	}

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	return err
}
