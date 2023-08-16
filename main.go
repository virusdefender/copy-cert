package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

type certPair struct {
	originCert *x509.Certificate
	newCert    *x509.Certificate
	newCertPem []byte
	priv       interface{}
	privPem    []byte
}

func getCertsFromNetwork(addr string) ([]*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: false,
	}
	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

func makeCerts(originCerts []*x509.Certificate) ([]*certPair, error) {
	certs := make([]*certPair, len(originCerts))
	// the origin order: website cert, intermediate ca, root ca
	for idx, cert := range originCerts {
		log.Printf("got cert: %s", cert.Subject.CommonName)
		certs[idx] = &certPair{originCert: cert}
	}
	slices.Reverse(certs)

	for idx, pair := range certs {
		var pub interface{}
		switch pair.originCert.PublicKey.(type) {
		case *rsa.PublicKey:
			p, err := rsa.GenerateKey(rand.Reader, pair.originCert.PublicKey.(*rsa.PublicKey).Size()*8)
			if err != nil {
				return nil, fmt.Errorf("generate rsa key: %w", err)
			}
			pub = &p.PublicKey
			pair.priv = p
			pair.privPem = pem.EncodeToMemory(&pem.Block{Bytes: x509.MarshalPKCS1PrivateKey(p), Type: "RSA PRIVATE KEY"})
		case *ecdsa.PublicKey:
			p, err := ecdsa.GenerateKey(pair.originCert.PublicKey.(*ecdsa.PublicKey).Curve, rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("generate ec key: %w", err)
			}
			pub = &p.PublicKey
			pair.priv = p
			data, err := x509.MarshalPKCS8PrivateKey(p)
			if err != nil {
				return nil, fmt.Errorf("MarshalPKCS8PrivateKey: %w", err)
			}
			pair.privPem = pem.EncodeToMemory(&pem.Block{Bytes: data, Type: "EC PRIVATE KEY"})
		default:
			return nil, fmt.Errorf("unknown key type: %T", pair.originCert.PublicKey)
		}

		// remove the old public key (from the origin website cert)
		pair.originCert.PublicKey = nil
		// wo do not generate the root ca, the intermediate ca will be self-signed,
		// so the origin signature algorithm may be wrong
		pair.originCert.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
		pair.newCert = pair.originCert
		var parent *certPair

		if idx > 0 {
			parent = certs[idx-1]
		} else {
			parent = pair
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, pair.originCert, parent.newCert, pub, parent.priv)
		if err != nil {
			return nil, fmt.Errorf("CreateCertificate: %w", err)
		}
		pair.newCertPem = pem.EncodeToMemory(&pem.Block{Bytes: derBytes, Type: "CERTIFICATE"})
		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, fmt.Errorf("ParseCertificate: %w", err)
		}
		pair.newCert = cert
	}
	return certs, nil
}

var fileNameRegex = regexp.MustCompile(`[^a-zA-Z0-9_\-.]`)

func main() {
	if len(os.Args) != 2 {
		name := filepath.Base(os.Args[0])
		log.Fatalf("usage: %s $addr, for example: %s github.com:443", name, name)
	}
	certs, err := getCertsFromNetwork(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	newCerts, err := makeCerts(certs)
	if err != nil {
		log.Fatal(err)
	}
	slices.Reverse(newCerts)

	dir := filepath.Join("certs", time.Now().Local().Format("2006_01_02_15_04_05"))
	err = os.MkdirAll(dir, 0o744)
	if err != nil {
		log.Fatal(err)
	}

	bundleCert, err := os.OpenFile(filepath.Join(dir, "bundle.crt"), os.O_WRONLY|os.O_CREATE, 0o744)
	if err != nil {
		log.Fatal(err)
	}
	defer bundleCert.Close()
	bundleKey, err := os.OpenFile(filepath.Join(dir, "bundle.key"), os.O_WRONLY|os.O_CREATE, 0o744)
	if err != nil {
		log.Fatal(err)
	}
	defer bundleKey.Close()

	for _, pair := range newCerts {
		log.Printf("going to write new cert and key: %s", pair.newCert.Subject.CommonName)
		// 担心星号在 Windows 上是不合法的文件名（当然我也没测试），但是被替换为下换线又很奇怪，所以替换成 __wildcard__
		pathBase := strings.ReplaceAll(pair.newCert.Subject.CommonName, "*", "__wildcard__")
		pathBase = fileNameRegex.ReplaceAllString(pathBase, "_")
		err = os.WriteFile(filepath.Join(dir, pathBase+".crt"), pair.newCertPem, 0o744)
		if err != nil {
			log.Fatal(err)
		}
		_, err = bundleCert.Write(pair.newCertPem)
		if err != nil {
			log.Fatal(err)
		}

		err = os.WriteFile(filepath.Join(dir, pathBase+".key"), pair.privPem, 0o744)
		if err != nil {
			log.Fatal(err)
		}
		_, err = bundleKey.Write(pair.privPem)
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("certs save to %s", dir)
}
