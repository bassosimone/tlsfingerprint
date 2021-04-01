package main

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"

	tls "github.com/refraction-networking/utls"
)

func main() {
	tcpConn, err := net.Dial("tcp", os.Args[1])
	if err != nil {
		fmt.Printf("net.Dial() failed: %+v\n", err)
		return
	}
	tlsConfig := tls.Config{ServerName: os.Args[2]}
	tlsConn := tls.UClient(tcpConn, &tlsConfig, tls.HelloCustom)
	clientHelloSpec := tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.SessionTicketExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			}},
			&tls.StatusRequestExtension{},
			&tls.SCTExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&tls.FakeChannelIDExtension{},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.CurveID(tls.GREASE_PLACEHOLDER),
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}},
			&tls.UtlsGREASEExtension{},
		},
	}
	tlsConn.ApplyPreset(&clientHelloSpec)
	err = tlsConn.Handshake()
	if err != nil {
		fmt.Printf("tlsConn.Handshake() failed: %+v\n", err)
		printExtraErrorDetails(err)
		return
	}
}

func printExtraErrorDetails(err error) {
	var uaerr x509.UnknownAuthorityError
	if errors.As(err, &uaerr) {
		certdata := base64.StdEncoding.EncodeToString(uaerr.Cert.Raw)
		fmt.Printf("%+v\n", certdata)
	}
}
