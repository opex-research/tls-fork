package tls

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog/log"
)

type TrafficData struct {
	handshakeComplete bool
	vers              int
	filePath          string

	// data buffers
	rawInput bytes.Buffer
	hand     bytes.Buffer
	input    bytes.Buffer

	// cipher
	aead     cipher.AEAD // func(key, fixedNonce []byte) aead
	cipherID uint16
	seq      [8]byte
	cipher   any

	// certificates
	certPool         *x509.CertPool
	verifiedChains   [][]*x509.Certificate
	peerCertificates []*x509.Certificate

	// messages of interest
	clientHello         *clientHelloMsg
	serverHello         *serverHelloMsg
	encryptedExtensions *encryptedExtensionsMsg
	certReq             *certificateRequestMsgTLS13
	certMsg             *certificateMsgTLS13
	certVerify          *certificateVerifyMsg
	finished            *finishedMsg
}

func NewTrafficData(filePath string, version int, cipherID uint16, certPool *x509.CertPool) TrafficData {
	return TrafficData{
		filePath:          filePath,
		vers:              version,
		handshakeComplete: false,
		cipherID:          cipherID,
		certPool:          certPool,
	}
}

func (td *TrafficData) ReadTransmissionBitstream() error {

	// open captured raw transcript
	fd, err := os.OpenFile(td.filePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		log.Error().Err(err).Msg("os.OpenFile")
		return err
	}
	defer fd.Close()

	// file reader to get size
	fileReader := bufio.NewReader(fd)
	fileInfo, err := fd.Stat()
	if err != nil {
		log.Error().Err(err).Msg("fd.Stat()")
		return err
	}
	fileSize := int(fileInfo.Size())

	// read Bitstream
	if err := td.readCompleteBitstream(fileReader, fileSize); err != nil {
		if err == io.ErrUnexpectedEOF && td.rawInput.Len() == 0 {
			err = io.EOF
		}
		return err
	}
	return nil
}

func (td *TrafficData) readCompleteBitstream(r io.Reader, fileSize int) error {

	// read raw data into rawInput
	if td.rawInput.Len() == 0 {

		// prepare raw input for required size of file
		td.rawInput.Grow(fileSize)

		// atLeastReader taken from tls Conn.go file
		_, err := td.rawInput.ReadFrom(&atLeastReader{r, int64(fileSize)})
		if err != nil {
			log.Error().Err(err).Msg("td.rawInput.ReadFrom(&atLeastReader{r, int64(fileSize)})")
			return err
		}
		return nil
	}

	return nil
}

func (td *TrafficData) ParseClientHello() error {
	msg, err := td.parseHandshake()
	if err != nil {
		return errors.New("parse Hello error")
	}
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		return errors.New("cannot typecast clientHello")
	}
	td.clientHello = clientHello

	return nil
}

func (td *TrafficData) ParseServerHello() error {
	msg, err := td.parseHandshake()
	if err != nil {
		return errors.New("parse Hello error")
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		return errors.New("cannot typecast serverHello")
	}
	td.serverHello = serverHello

	return nil
}

func (td *TrafficData) parseHandshake() (interface{}, error) {
	for td.hand.Len() < 4 {
		if err := td.readRecord(); err != nil {
			return nil, err
		}
	}

	data := td.hand.Bytes()
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		return nil, errors.New("tls: handshake message of length exceeds maximum  bytes")
	}
	for td.hand.Len() < 4+n {
		if err := td.readRecord(); err != nil {
			return nil, err
		}
	}
	data = td.hand.Next(4 + n)
	var m handshakeMessage
	switch data[0] {
	case typeHelloRequest:
		m = new(helloRequestMsg)
	case typeClientHello:
		m = new(clientHelloMsg)
	case typeServerHello:
		m = new(serverHelloMsg)
	case typeNewSessionTicket:
		m = new(newSessionTicketMsgTLS13)
	case typeCertificate:
		m = new(certificateMsgTLS13)
	case typeCertificateRequest:
		m = new(certificateRequestMsgTLS13)
	case typeCertificateStatus:
		m = new(certificateStatusMsg)
	case typeServerKeyExchange:
		m = new(serverKeyExchangeMsg)
	case typeServerHelloDone:
		m = new(serverHelloDoneMsg)
	case typeClientKeyExchange:
		m = new(clientKeyExchangeMsg)
	case typeCertificateVerify:
		m = &certificateVerifyMsg{
			hasSignatureAlgorithm: td.vers >= VersionTLS12,
		}
	case typeFinished:
		m = new(finishedMsg)
	case typeEncryptedExtensions:
		m = new(encryptedExtensionsMsg)
	case typeEndOfEarlyData:
		m = new(endOfEarlyDataMsg)
	case typeKeyUpdate:
		m = new(keyUpdateMsg)
	default:
		return nil, errors.New("tls parser: unexpected handshake type")
	}

	// The handshake message unmarshalers
	// expect to be able to keep references to data,
	// so pass in a fresh copy that won't be overwritten.
	data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		return nil, errors.New("tls parser: unmarshal error")
	}
	return m, nil
}

func (td *TrafficData) readRecord() error {

	if td.rawInput.Len() <= 0 {
		log.Debug().Msg("done transcript parsing")
		return nil
	}
	handshakeComplete := td.handshakeComplete

	td.input.Reset()

	hdr := td.rawInput.Bytes()[:recordHeaderLen]
	typ := recordType(hdr[0])

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
	// start with a uint16 length where the MSB is set and the first record
	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
	// an SSLv2 client.
	if !handshakeComplete && typ == 0x80 {
		log.Error().Msg("tls parser: unsupported SSLv2 handshake received\n")
		return alertProtocolVersion
	}

	//vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	n := int(hdr[3])<<8 | int(hdr[4])

	if n > maxCiphertextTLS13 {
		log.Error().Msg("tls parser: oversized record received with length")
		return alertRecordOverflow
	}

	record := td.rawInput.Next(recordHeaderLen + n)
	data, typ, err := td.decrypt(record)
	if err != nil {
		return err
	}
	if len(data) > maxPlaintext {
		return alertRecordOverflow
	}

	switch typ {
	default:
		return alertUnexpectedMessage
	case recordTypeAlert:
		return alertUnexpectedMessage
	case recordTypeChangeCipherSpec:
		td.handshakeComplete = true
		return td.readRecord()
	case recordTypeApplicationData:

		if len(data) == 0 {
			return td.readRecord()
		}
		// Note that data is owned by p.rawInput, following the Next call above,
		// to avoid copying the plaintext. This is safe because p.rawInput is
		// not read from or written to until p.input is drained.
		td.input.Reset()

	case recordTypeHandshake:
		td.hand.Write(data)
	}
	return nil
}

func (td *TrafficData) decrypt(record []byte) ([]byte, recordType, error) {
	var plaintext []byte
	typ := recordType(record[0])
	payload := record[recordHeaderLen:]

	// In TLS 1.3, change_cipher_spec messages are to be ignored without being
	// decrypted. See RFC 8446, Appendix D.4.
	if td.vers == VersionTLS13 && typ == recordTypeChangeCipherSpec {
		return payload, typ, nil
	}

	explicitNonceLen := 0

	if td.cipher != nil && td.handshakeComplete {

		// not called when parsing hello messages
		// decryption parameters must be set before parsing tls1.3 messages not of type hello

		if len(payload) < explicitNonceLen {
			return nil, 0, alertBadRecordMAC
		}
		nonce := payload[:explicitNonceLen]
		if len(nonce) == 0 {
			nonce = td.seq[:]
		}
		payload = payload[explicitNonceLen:]

		// var additionalData []byte

		additionalData := record[:recordHeaderLen]

		var err error
		// c := td.cipher.(aead)
		aead := td.aead
		plaintext, err = aead.Open(payload[:0], nonce, payload, additionalData)
		if err != nil {
			return nil, 0, alertBadRecordMAC
		}

		if td.vers == VersionTLS13 {
			if typ != recordTypeApplicationData {
				return nil, 0, alertUnexpectedMessage
			}
			if len(plaintext) > maxPlaintext+1 {
				return nil, 0, alertRecordOverflow
			}
			// Remove padding and find the ContentType scanning from the end.
			for i := len(plaintext) - 1; i >= 0; i-- {
				if plaintext[i] != 0 {
					typ = recordType(plaintext[i])
					plaintext = plaintext[:i]
					break
				}
				if i == 0 {
					return nil, 0, alertUnexpectedMessage
				}
			}
		}
	} else {
		plaintext = payload
	}

	td.incSeq()
	return plaintext, typ, nil
}

func (td *TrafficData) incSeq() {
	for i := 7; i >= 0; i-- {
		td.seq[i]++
		if td.seq[i] != 0 {
			return
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("sequence number wraparound")
}

func (td *TrafficData) SetCipherParameters(secret []byte) error {
	cipher := cipherSuiteTLS13ByID(td.cipherID)
	key, iv := cipher.trafficKey(secret)
	td.aead = cipher.aead(key, iv)
	td.cipher = cipher
	for i := range td.seq {
		td.seq[i] = 0
	}
	return nil
}

func (td *TrafficData) ParseServerEncryptedExtension() error {
	msg, err := td.parseHandshake()
	if err != nil {
		return err
	}
	encryptedExtensions, ok := msg.(*encryptedExtensionsMsg)
	if !ok {
		return errors.New("cannot typecast encryptedExtensionsMsg")
	}
	td.encryptedExtensions = encryptedExtensions
	return nil
}

func (td *TrafficData) ParseServerCertificate(clientHello *clientHelloMsg) error {

	// calculate transcript for certificate verification
	transcript, err := td.getCertificateVerifyTranscript(clientHello)
	if err != nil {
		return err
	}

	// continue to parse content
	msg, err := td.parseHandshake()
	if err != nil {
		fmt.Println("no error here..")
		return err
	}
	certReq, ok := msg.(*certificateRequestMsgTLS13)
	if ok {
		td.certReq = certReq
		transcript, err = td.addCertReqTranscript(transcript)
		if err != nil {
			return err
		}
		msg, err = td.parseHandshake()
		if err != nil {
			return err
		}
	}

	// typecast message
	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		return errors.New("cannot typecast certificateMsgTLS13")
	}
	td.certMsg = certMsg

	// update transcript
	transcript, err = td.addCertMsgTranscript(transcript)
	if err != nil {
		return err
	}

	// check if certificate received
	if len(certMsg.certificate.Certificate) == 0 {
		return errors.New("received empty certificates message")
	}

	// verify server certificate
	// sets peerCertificates, which is required for signature verification
	if err := td.verifyServerCertificate(certMsg.certificate.Certificate); err != nil {
		return err
	}

	// capture certificate verify message
	msg, err = td.parseHandshake()
	if err != nil {
		return err
	}
	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		return errors.New("cannot typecast certificateVerifyMsg")
	}
	td.certVerify = certVerify

	// check certificate verification message
	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms()) {
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return err
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		return errors.New("tls: certificate used with invalid signature algorithm")
	}

	// verify certificate signatures
	signed := signedMessage(sigHash, serverSignatureContext, transcript)
	if err := verifyHandshakeSignature(sigType, td.peerCertificates[0].PublicKey,
		sigHash, signed, certVerify.signature); err != nil {
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}

	return nil
}

func (td *TrafficData) verifyServerCertificate(certificates [][]byte) error {

	// initialize certificates
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			log.Error().Err(err).Msg("failed to parse certificate from server")
			return err
		}
		certs[i] = cert
	}
	opts := x509.VerifyOptions{
		Roots:         td.certPool,
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	var err error
	td.verifiedChains, err = certs[0].Verify(opts)
	if err != nil {
		return err
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		break
	default:
		return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	// set peer certificates
	td.peerCertificates = certs

	return nil
}

func (td *TrafficData) getCertificateVerifyTranscript(clientHello *clientHelloMsg) (hash.Hash, error) {

	// get transcript
	cipher := cipherSuiteTLS13ByID(td.cipherID)
	transcript := cipher.hash.New()

	// deserialize transcripts
	chTranscript, err := clientHello.marshal()
	if err != nil {
		log.Error().Err(err).Msg("clientHello.marshal()")
		return transcript, err
	}
	shTranscript, err := td.serverHello.marshal()
	if err != nil {
		log.Error().Err(err).Msg("serverHello.marshal()")
		return transcript, err
	}
	eeTranscript, err := td.encryptedExtensions.marshal()
	if err != nil {
		log.Error().Err(err).Msg("encryptedExtensions.marshal()")
		return transcript, err
	}

	// compute transcript hash
	transcript.Write(chTranscript)
	transcript.Write(shTranscript)
	transcript.Write(eeTranscript)

	return transcript, nil
}

func (td *TrafficData) addCertReqTranscript(transcript hash.Hash) (hash.Hash, error) {
	crTranscript, err := td.certReq.marshal()
	if err != nil {
		log.Error().Err(err).Msg("td.certReq.marshal()")
		return transcript, err
	}
	transcript.Write(crTranscript)
	return transcript, nil
}

func (td *TrafficData) addCertMsgTranscript(transcript hash.Hash) (hash.Hash, error) {
	cmTranscript, err := td.certMsg.marshal()
	if err != nil {
		log.Error().Err(err).Msg("td.certMsg.marshal()")
		return transcript, err
	}
	transcript.Write(cmTranscript)
	return transcript, nil
}

func (td *TrafficData) ParseFinishedMsg() error {
	msg, err := td.parseHandshake()
	if err != nil {
		return err
	}
	finished, ok := msg.(*finishedMsg)
	if !ok {
		return errors.New("cannot typecast finishedMsg")
	}
	td.finished = finished
	return nil
}

func (td *TrafficData) ParseRecordData() (map[string]map[string]string, error) {

	// reset sequence counter for record layer traffic
	for i := range td.seq {
		td.seq[i] = 0
	}

	// init return data structure
	recordPerSequence := make(map[string]map[string]string)

	// stop when done parsing chunks
	for {

		// stop criteria
		if td.rawInput.Len() <= 0 {
			log.Debug().Msg("done parsing record layer")
			break
		}
		handshakeComplete := td.handshakeComplete

		td.input.Reset()

		hdr := td.rawInput.Bytes()[:recordHeaderLen]
		typ := recordType(hdr[0])

		// No valid TLS record has a type of 0x80, however SSLv2 handshakes
		// start with a uint16 length where the MSB is set and the first record
		// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
		// an SSLv2 client.
		if !handshakeComplete && typ == 0x80 {
			log.Debug().Msg("tls parser: unsupported SSLv2 handshake received\n")
			// log.Fatalf("tls parser: unsupported SSLv2 handshake received\n")
			return nil, alertProtocolVersion
		}

		//vers := uint16(hdr[1])<<8 | uint16(hdr[2])
		n := int(hdr[3])<<8 | int(hdr[4])

		if n > maxCiphertextTLS13 {
			log.Debug().Msg("tls parser: oversized record received with length")
			// log.Fatalf("tls parser: oversized record received with length %d", n)
			return nil, alertRecordOverflow
		}

		record := td.rawInput.Next(recordHeaderLen + n)

		// inside decrypt
		// typ := recordType(record[0])
		payload := record[recordHeaderLen:]

		explicitNonceLen := 0

		if len(payload) < explicitNonceLen {
			break
		}
		nonce := payload[:explicitNonceLen]
		if len(nonce) == 0 {
			nonce = td.seq[:]
		}
		payload = payload[explicitNonceLen:]

		// payload = payload[explicitNonceLen:]
		additionalData := record[:recordHeaderLen]

		// outside decrypt
		td.input.Reset()

		// record data
		jsonData := make(map[string]string)

		// fmt.Println("======record======")
		// fmt.Println("payload:", hex.EncodeToString(payload), len(hex.EncodeToString(payload))/32)
		// fmt.Println("recordHeaderLen:", recordHeaderLen)
		// fmt.Println("nonce:", hex.EncodeToString(nonce))
		// fmt.Println("additionalData:", hex.EncodeToString(additionalData))

		jsonData["ciphertext"] = hex.EncodeToString(payload)
		jsonData["additionalData"] = hex.EncodeToString(additionalData)
		recordPerSequence[hex.EncodeToString(nonce)] = jsonData

		// increment record sequence counter
		td.incSeq()
	}

	return recordPerSequence, nil

}

////////////////////
// wrapper functions to access values from parser package which is outside of tls_fork
////////////////////

func NewHashCipherSuiteTLS13ByID(cipherID uint16) hash.Hash {
	cipher := cipherSuiteTLS13ByID(cipherID)
	return cipher.hash.New()
}

func (td *TrafficData) GetClientHello() *clientHelloMsg {
	return td.clientHello
}

func (td *TrafficData) GetClientHelloMarshal() ([]byte, error) {
	return td.clientHello.marshal()
}

func (td *TrafficData) GetServerHelloMarshal() ([]byte, error) {
	return td.serverHello.marshal()
}

func (td *TrafficData) GetEncryptedExtensionsMarshal() ([]byte, error) {
	return td.encryptedExtensions.marshal()
}

func (td *TrafficData) GetCertReqMarshal() ([]byte, error) {
	return td.certReq.marshal()
}

func (td *TrafficData) GetCertMsgMarshal() ([]byte, error) {
	return td.certMsg.marshal()
}

func (td *TrafficData) GetCertVerifyMarshal() ([]byte, error) {
	return td.certVerify.marshal()
}

func (td *TrafficData) GetFinishedMarshal() ([]byte, error) {
	return td.finished.marshal()
}

func (td *TrafficData) GetFinishedRaw() []byte {
	return td.finished.raw
}
