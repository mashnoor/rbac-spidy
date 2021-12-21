package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
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
		NotAfter:     time.Now().Add(5000 * time.Hour),
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

func main() {
	//certDir = /home/dfs/GolandProjects/rbac-spidy/certs
	kingpin.New("RBAC Spidy", "'RBAC Spidy' is helper that automatically generates kubeconfig, role and rolebinding for a user.")
	kubePkiDir := kingpin.Flag("pki-dir", "Kubernetes PKI directory location (/etc/kubernetes/pki/").Short('p').String()
	configOutputDir := kingpin.Flag("out", "Kube config output directory location").Short('o').String()
	bitSize := kingpin.Flag("bit", "Private cert bit size bit size").Short('b').Int()
	organization := kingpin.Flag("org", "Certificate organization name").String()
	userName := kingpin.Flag("user", "Certificate user name").Short('u').String()
	clusterName := kingpin.Flag("cluster", "Cluster name").Short('c').String()
	serverString := kingpin.Flag("server", "Cluster endpoint address").Short('s').String()
	contextName := kingpin.Flag("context", "User context name").Short('x').String()
	seedNamespace := kingpin.Flag("seed-namespace", "Initial namespace").Short('n').String()
	roleName := kingpin.Flag("role-name", "Role name").Short('r').String()
	roleBindingName := kingpin.Flag("role-binding-name", "Role binding name").String()

	kingpin.Parse()

	fmt.Println("- Generating private key...")
	privateKey, privateKeyBytes := generatePrivateKey(*bitSize)
	fmt.Println("- Private key generation successful!")

	fmt.Println("- Generating Certificate Signing Request...")
	csrBytes := generateCsr(*userName, *organization, privateKey)
	fmt.Println("- CSR generation successful")

	fmt.Println("- Generating certificate")
	clientCertBytes := crsToCrt(*kubePkiDir, csrBytes)
	fmt.Println("- Certificate generation successful")

	caCert, err := ioutil.ReadFile(*kubePkiDir + "/ca.crt")
	if err != nil {
		panic(err)
	}

	caCertStr := base64.StdEncoding.EncodeToString(caCert)
	clientCertStr := base64.StdEncoding.EncodeToString(clientCertBytes)
	privateKeyStr := base64.StdEncoding.EncodeToString(privateKeyBytes)

	kubeConfig := kubehelpers.GenerateKubeConfig(*clusterName, *userName, caCertStr, *serverString, *contextName, clientCertStr, privateKeyStr)

	role := kubehelpers.GenerateRole(*seedNamespace, *roleName)
	roleBinding := kubehelpers.GenerateRoleBinding(*seedNamespace, *roleBindingName, *userName, *roleName)

	fmt.Println("- Writing files...")
	writeConfigFiles(&kubeConfig, &role, &roleBinding, configOutputDir)
	fmt.Println("-Successfully generate all files. You can locate the files in: " + *configOutputDir)

}

func writeConfigFiles(kubeConfig, role, roleBinding, configOutputDir *string) {

	// kubeconfig
	f, _ := os.Create(*configOutputDir + "/config.yaml")
	_, err := f.WriteString(*kubeConfig)
	if err != nil {
		panic(err)
	}
	err = f.Close()
	if err != nil {
		return
	}

	//role
	f, _ = os.Create(*configOutputDir + "/role.yaml")
	_, err = f.WriteString(*role)
	if err != nil {
		panic(err)
	}
	err = f.Close()
	if err != nil {
		return
	}

	//Role binding
	f, _ = os.Create(*configOutputDir + "/rolebinding.yaml")
	_, err = f.WriteString(*roleBinding)
	if err != nil {
		panic(err)
	}
	err = f.Close()
	if err != nil {
		return
	}
}
