package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/kyokomi/emoji"
	"gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"math/big"
	"os"
	"test/kubehelpers"
	"time"
)

func generateCsr(commonName, organization string, privateKey *rsa.PrivateKey) []byte {
	subj := pkix.Name{
		CommonName:   commonName,
		Organization: []string{organization},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)

	return csrBytes

}

func generatePrivateKey(bitSize int) (*rsa.PrivateKey, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	//if err := ioutil.WriteFile(filename+".key", privateKeyPem, 0700); err != nil {
	//	panic(err)
	//}

	return privateKey, privateKeyPem

}

func crsToCrt(caPath string, csrBytes []byte) []byte {

	caCrtFile := caPath + "/ca.crt"
	caKeyFile := caPath + "/ca.key"

	caPublicKeyFile, err := ioutil.ReadFile(caCrtFile)
	if err != nil {
		panic(err)
	}
	pemBlock, _ := pem.Decode(caPublicKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		panic(err)
	}

	//      private key
	caPrivateKeyFile, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		panic(err)
	}
	pemBlock, _ = pem.Decode(caPrivateKeyFile)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		panic(err)
	}
	clientCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		panic(err)
	}
	if err = clientCSR.CheckSignature(); err != nil {
		panic(err)
	}

	// create client certificate template
	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: big.NewInt(2),
		Issuer:       caCRT.Subject,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, caPrivateKey)
	if err != nil {
		panic(err)
	}

	clientCertBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: clientCRTRaw,
		},
	)

	return clientCertBytes

}

func printWithEmoji(str string) {
	msg := emoji.Sprint(str)
	fmt.Println(msg)

}

func main() {
	//certDir = /home/dfs/GolandProjects/rbac-spidy/certs
	kubePkiDir := kingpin.Flag("pki-dir", "Kubernetes PKI directory location (/etc/kubernetes/pki/").Short('p').String()
	configOutputDir := kingpin.Flag("out", "Kube config output directory location").Short('o').String()
	bitSize := kingpin.Flag("bit", "Private cert bit size bit size").Short('b').Int()
	organization := kingpin.Flag("org", "Certificate organization name").String()
	userName := kingpin.Flag("user", "Certificate user name").Short('u').String()
	clusterName := kingpin.Flag("cluster", "Cluster name").Short('c').String()
	serverString := kingpin.Flag("server", "Cluster endpoint address").Short('s').String()
	contextName := kingpin.Flag("context", "User context name").Short('x').String()

	kingpin.Parse()

	printWithEmoji(":smirk: Generating private key")

	privateKey, privateKeyBytes := generatePrivateKey(*bitSize)

	printWithEmoji(":tada: Private key generation successful")

	csrBytes := generateCsr(*userName, *organization, privateKey)

	clientCertBytes := crsToCrt(*kubePkiDir, csrBytes)

	caCert, err := ioutil.ReadFile(*kubePkiDir + "/ca.crt")
	if err != nil {
		panic(err)
	}

	caCertStr := base64.StdEncoding.EncodeToString(caCert)
	clientCertStr := base64.StdEncoding.EncodeToString(clientCertBytes)
	privateKeyStr := base64.StdEncoding.EncodeToString(privateKeyBytes)

	kubeConfig := kubehelpers.GenerateKubeConfig(*clusterName, *userName, caCertStr, *serverString, *contextName, clientCertStr, privateKeyStr)

	fmt.Println(*configOutputDir)
	f, _ := os.Create(*configOutputDir + "/config.yaml")
	f.WriteString(kubeConfig)
	//fmt.Println("-------------------------------")
	//fmt.Println(clientCertStr)
	//fmt.Println("-------------------------------")
	//fmt.Println(caCertStr)

}
