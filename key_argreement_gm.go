package gmtls

/*
 国密用的 keyExchange 相关的处理
*/
import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	slog "github.com/cihub/seelog"
	"github.com/piligo/gmsm/sm2"
)

type EncryptClientKey struct {
	X    *big.Int // C1 X
	Y    *big.Int // C1 Y
	Hash []byte   // byte  C3
	Data []byte   // byte  C2
}

func (eck *EncryptClientKey) Sm2EncryptData() []byte {
	out := make([]byte, 0)
	out = append(out, []byte{0x04}...)
	out = append(out, eck.X.Bytes()...)
	out = append(out, eck.Y.Bytes()...)
	out = append(out, eck.Hash...)
	out = append(out, eck.Data...)
	return out
}

func asn1EncryptClientKey(eck EncryptClientKey) ([]byte, error) {
	data, err := asn1.Marshal(eck)
	if err != nil {
		slog.Error(" EncryptClientKey marshal err -> ", err)
		return nil, err
	}
	return data, nil
}

func asn1DecryptClientKey(data []byte) (*EncryptClientKey, error) {
	var eck EncryptClientKey
	_, err := asn1.Unmarshal(data, &eck)
	if err != nil {
		fmt.Println(" EncryptClientKey marshal err -> ", err)
		return nil, err
	}
	return &eck, nil
}

type gmsm2KeyAgreement struct{}

/*
 GM STL（ECC_SM2_SM4_SM3 ）ServerKeyExchange：
 data:=SS_CERT->Signture(client_radom+server_radom+len(SE_CERT)+SE_SERT)
*/

func (ka gmsm2KeyAgreement) generateServerKeyExchange(config *Config, certs []*Certificate, clientHello *clientHelloMsg, svrhello *serverHelloMsg) (*serverKeyExchangeMsg, error) {

	slog.Debug(">>-------------generateServerKeyExchange start ----------------<<")
	defer slog.Debug(">>-------------generateServerKeyExchange end ----------------<<")

	slog.Debug("certs nums->", len(certs))
	if len(certs) < 2 {
		return nil, errors.New("tls: unexpected generateServerKeyExchange ")
	}

	ss_prvkey, ok := certs[0].PrivateKey.(*sm2.PrivateKey)
	if !ok {
		slog.Error("tls: unexpected generateServerKeyExchange sm2.PrivateKey not ok")
		return nil, errors.New("tls: unexpected generateServerKeyExchange sm2.PrivateKey")
	}

	se_cert, err := sm2.ParseCertificate(certs[len(certs)-1].Certificate[0])
	if err != nil {
		slog.Error("tls: unexpected generateServerKeyExchange sm2 ParseCertificate not ok", err)
		return nil, errors.New("tls: unexpected generateServerKeyExchange " + err.Error())
	}
	se_cert_len := len(se_cert.Raw)
	slog.Debug("se_cert->\n", hex.Dump(se_cert.Raw))

	se_len := make([]byte, 3)
	se_len[0] = uint8(se_cert_len >> 16)
	se_len[1] = uint8(se_cert_len >> 8)
	se_len[2] = uint8(se_cert_len)

	slog.Debug(" SE 证书 len->", hex.EncodeToString(se_len))
	cli_random := clientHello.random
	svr_random := svrhello.random
	slog.Debug(" client_random->", hex.EncodeToString(cli_random))
	slog.Debug(" server_random->", hex.EncodeToString(svr_random))
	sigData := make([]byte, 0)
	sigData = append(sigData, cli_random...)
	sigData = append(sigData, svr_random...)
	sigData = append(sigData, se_len...)
	sigData = append(sigData, se_cert.Raw...)

	slog.Debug(" sigData->", hex.EncodeToString(sigData))

	sig, err := ss_prvkey.Sign(rand.Reader, sigData, nil)
	if err != nil {
		slog.Error("tls: unexpected generateServerKeyExchange Sign err", err)
		return nil, errors.New("tls: unexpected generateServerKeyExchange Sign err" + err.Error())
	}

	slog.Debug("SignOut->", hex.EncodeToString(sig))

	skx := new(serverKeyExchangeMsg)
	sigAndHashLen := 2 //国密算法 sig签名2位长度值
	skx.key = make([]byte, sigAndHashLen+len(sig))
	//valide := pubk.(sigData, sighash)
	skx.key[0] = byte(len(sig) >> 8)
	skx.key[1] = byte(len(sig))
	copy(skx.key[2:], sig)
	slog.Debug("serverKeyExchangeMsg Out->", hex.EncodeToString(skx.key))
	return skx, nil
}

// 这里好像是解密 client的加密的pre-master-secert
func (ka gmsm2KeyAgreement) processClientKeyExchange(config *Config, certs []*Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	slog.Info(">>-------------processClientKeyExchange start ----------------<<")
	defer slog.Info(">>-------------processClientKeyExchange end ----------------<<")

	slog.Info("certs nums->", len(certs))
	if len(certs) < 2 {
		return nil, errors.New("tls: unexpected processClientKeyExchange certs less 2")
	}

	//解密证书
	se_prvkey, ok := certs[len(certs)-1].PrivateKey.(*sm2.PrivateKey)
	if !ok {
		slog.Error("tls: unexpected processClientKeyExchange sm2.PrivateKey not ok")
		return nil, errors.New("tls: unexpected processClientKeyExchange sm2.PrivateKey")
	}
	slog.Info("se_prvkey->", se_prvkey)

	slog.Info("\n---------- clientKeyExchangeMsg --------------\n" + hex.Dump(ckx.raw))
	slog.Info("\n---------- clientKeyExchangeMsg ciphertext--------------\n" + hex.Dump(ckx.ciphertext))

	//解码数据
	eck, err := asn1DecryptClientKey(ckx.ciphertext[2:])
	if err != nil {
		slog.Error("tls: unexpected processClientKeyExchange sasn1DecryptClientKey err->", err)
		return nil, errors.New("tls: unexpected processClientKeyExchange asn1Decode err" + err.Error())
	}

	slog.Info("\n---------- clientKeyExchangeMsg Sm2EncryptData--------------\n" + hex.Dump(eck.Sm2EncryptData()))

	preMasterSecret, err := se_prvkey.Decrypt(eck.Sm2EncryptData())
	if err != nil {
		slog.Error("tls: unexpected processClientKeyExchange Decrypt err->", err)
		return nil, errors.New("tls: unexpected processClientKeyExchange Decrypt err" + err.Error())
	}
	slog.Info("processClientKeyExchange deal Success")
	slog.Info(" clientKeyExchangeMsg preMasterSecret->", hex.EncodeToString(preMasterSecret))
	return preMasterSecret, nil
}

func (ka gmsm2KeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, certs []*sm2.Certificate, skx *serverKeyExchangeMsg) error {

	slog.Debug("-------->> 国密 processServerKeyExchange start <<-------")
	slog.Debug("ServerKeyExchage Raw:\n" + hex.Dump(skx.raw))
	slog.Debug("ServerKeyExchage Key:\n" + hex.Dump(skx.key))
	defer slog.Debug("-------->> 国密 processServerKeyExchange End <<-------")
	//certs 证书为：SS|CA|SE  (CA证书不一定有)，第一个和最后一个肯定为SS和SE
	if len(certs) < 2 {
		slog.Error("tls:unexpected GM processServerKeyExchange len(certs)<2 ")
		return errors.New("tls: unexpected ServerKeyExchange Certificate is lower 2")
	}
	ss_cert := certs[0]            //第一个证书
	se_cert := certs[len(certs)-1] //最后一个证书
	se_cert_len := len(se_cert.Raw)
	slog.Debug("ServerKeyExchage Raw:\n" + hex.Dump(skx.raw))
	//这里是服务端证书
	slog.Debug("\n-------------------- SS 证书 --------------------------\n" + hex.Dump(ss_cert.Raw))
	slog.Debug("\n-------------------- SE 证书 --------------------------\n" + hex.Dump(se_cert.Raw))
	se_len := make([]byte, 3)
	se_len[0] = uint8(se_cert_len >> 16)
	se_len[1] = uint8(se_cert_len >> 8)
	se_len[2] = uint8(se_cert_len)

	slog.Debug(" SE 证书 len->", hex.EncodeToString(se_len))
	cli_random := clientHello.random
	svr_random := serverHello.random
	slog.Debug(" client_random->", hex.EncodeToString(cli_random))
	slog.Debug(" server_random->", hex.EncodeToString(svr_random))
	sigData := make([]byte, 0)
	//client_radom + server_radom + ec_len + ec_txt进行签名的数据
	sigData = append(sigData, cli_random...)
	sigData = append(sigData, svr_random...)
	sigData = append(sigData, se_len...)
	sigData = append(sigData, se_cert.Raw...)

	slog.Debug(" sigData->", hex.EncodeToString(sigData))
	pubk, ok := ss_cert.PublicKey.(*sm2.PublicKey)
	if !ok {
		slog.Error("ss_cert.PublicKey not ok pubk->", ok)
		return errors.New("tls: unexpected ServerKeyExchange not  *sm2.PublicKey ")
	}

	sighash := skx.key[2:] //除掉两个字节的长度值
	slog.Debug(" sighash->", hex.EncodeToString(sighash))
	valide := pubk.Verify(sigData, sighash)
	slog.Debug(" ServerKeyExchange Verify Out ->", valide)
	if valide {
		return nil
	}
	slog.Error("tls: unexpected ServerKeyExchange Verify Not Pass")
	return errors.New("tls: unexpected ServerKeyExchange Verify Not Pass")
}
func (ka gmsm2KeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, certs []*sm2.Certificate) ([]byte, *clientKeyExchangeMsg, error) {

	slog.Debug("---------- 国密 generateClientKeyExchange start------------")
	defer slog.Debug("---------- 国密 generateClientKeyExchange end------------\n\n")

	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8) //先生成版本信息
	preMasterSecret[1] = byte(clientHello.vers)      //生成版本信息 2个字节

	//产生一个随机值
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		slog.Error("generateClientKeyExchange rand preMasterSecret err->", err)
		return nil, nil, err
	}
	slog.Debug("preMasterSecret ->", hex.EncodeToString(preMasterSecret))
	if len(certs) < 2 {
		slog.Error("generateClientKeyExchange-> 国密证书少于2个 SS 和SE证书")
		return nil, nil, errors.New("tls: unexpected generateClientKeyExchange GM SM2 Certificate  NEED 2")
	}
	se_cert := certs[len(certs)-1]
	slog.Debug("\n-------------------- SE 证书 --------------------------\n" + hex.Dump(se_cert.Raw))
	//用的SE 的证书去加密 数据
	pubk, ok := se_cert.PublicKey.(*sm2.PublicKey)
	if !ok {
		slog.Error("cert.PublicKey not ok pubk->", ok)
		return nil, nil, errors.New("tls: unexpected generateClientKeyExchange not  *sm2.PublicKey ")
	}

	encrypted, err := pubk.Encrypt(preMasterSecret)
	if err != nil {
		slog.Error("cert.PublicKey Encrypt err ->", err)
		return nil, nil, err
	}
	slog.Debug("encrypted preMasterSecret ->", hex.EncodeToString(encrypted))

	X := encrypted[1 : 1+32]
	Y := encrypted[1+32 : 1+32+32]
	H := encrypted[1+32+32 : 1+32+32+32]
	C := encrypted[1+32+32+32:]

	slog.Debug("encrypted preMasterSecret X->", hex.EncodeToString(X))
	slog.Debug("encrypted preMasterSecret Y->", hex.EncodeToString(Y))
	slog.Debug("encrypted preMasterSecret H->", hex.EncodeToString(H))
	slog.Debug("encrypted preMasterSecret C->", hex.EncodeToString(C))
	slog.Debug("encrypted preMasterSecret C len->", len(C))

	//加密的时候生成的X和Y 有可能大于32字节 这里做一下判断如果 切分的不正确报错一下。
	if len(C) != 48 {
		fmt.Println("ciphet text len not 48->")
		return nil, nil, errors.New("tls: unexpected generateClientKeyExchange spilet encrypted data error")
	}

	bX := new(big.Int).SetBytes(X)
	bY := new(big.Int).SetBytes(Y)
	slog.Debug("encrypted X->", bX.Text(16), " Y=", bY.Text(16))

	enkey := EncryptClientKey{
		X:    bX,
		Y:    bY,
		Hash: H,
		Data: C,
	}

	endata, err := asn1EncryptClientKey(enkey)
	if err != nil {
		fmt.Println("EncryptClientKey  marshal err ->", err)
		return nil, nil, err
	}
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, len(endata)+2)
	ckx.ciphertext[0] = byte(len(endata) >> 8)
	ckx.ciphertext[1] = byte(len(endata))
	copy(ckx.ciphertext[2:], endata)
	slog.Debug("\n-------------------- ciphertext data ------------------\n" + hex.Dump(ckx.ciphertext))
	return preMasterSecret, ckx, nil
}
