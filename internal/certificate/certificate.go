package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

type CA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// Setup loads an existing CA from disk or generates a new one.
func Setup(certPath, keyPath string) (*CA, error) {
	if err := os.MkdirAll("certs", 0755); err != nil {
		return nil, err
	}

	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	if certErr == nil && keyErr == nil {
		return load(certPath, keyPath)
	}

	return generate(certPath, keyPath)
}

// GenerateCert creates a short-lived TLS certificate for a given host, signed by the CA.
func (ca *CA) GenerateCert(host string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(30 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &priv.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

func generate(certPath, keyPath string) (*CA, error) {
	log.Println("Generating new CA certificate")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"HAR Scraper Proxy CA"},
			CommonName:   "HAR Scraper Proxy Root CA",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(30 * time.Minute),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return nil, err
	}

	if err := writePEM(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
		return nil, err
	}

	log.Println("CA certificate generated and saved to", certPath)
	log.Println("CA private key saved to", keyPath)
	log.Println("Install ca.crt in your browser/system to trust this proxy")

	return &CA{Cert: cert, Key: key}, nil
}

func load(certPath, keyPath string) (*CA, error) {
	log.Println("Loading existing CA certificate")

	cert, err := loadCert(certPath)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		log.Println("CA certificate expired, regenerating")
		return generate(certPath, keyPath)
	}

	key, err := loadKey(keyPath)
	if err != nil {
		return nil, err
	}

	log.Println("CA certificate loaded successfully")
	return &CA{Cert: cert, Key: key}, nil
}

func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, err
	}

	return x509.ParseCertificate(block.Bytes)
}

func loadKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func writePEM(path, blockType string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
}
