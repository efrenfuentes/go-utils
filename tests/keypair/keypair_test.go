package keypair_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	. "github.com/efrenfuentes/go-utils/keypair"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Keypair", func() {
	var (
		bits                  int
		privateKey, publicKey string
		block                 *pem.Block
		err                   error
	)

	BeforeEach(func() {
		bits = 2048

		privateKey, publicKey = GenerateKeys(bits)
	})

	Describe("GenerateKeys function", func() {
		It("private key", func() {
			var privKey *rsa.PrivateKey

			block, _ = pem.Decode([]byte(privateKey))

			privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			Expect(err).Should(BeNil())

			err = privKey.Validate()
			Expect(err).Should(BeNil())

			// public key
			pub := privKey.PublicKey
			pubDer, _ := x509.MarshalPKIXPublicKey(&pub)

			pubBlk := pem.Block{
				Type:    "PUBLIC KEY",
				Headers: nil,
				Bytes:   pubDer,
			}

			// Resultant public key in PEM format.
			pubPem := string(pem.EncodeToMemory(&pubBlk))
			Expect(pubPem).To(Equal(publicKey))
		})
	})
})
