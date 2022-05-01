package signer

import (
	"context"
	"encoding/asn1"
	"fmt"
	"hash/crc32"
	"math/big"
	"reflect"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/winor30/go-cloud-signer/txopts"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

var (
	secp256k1N, _                = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN               = new(big.Int).Div(secp256k1N, big.NewInt(2))
	_              txopts.Signer = (*gcpSigner)(nil)
)

type gcpSigner struct {
	chainID *big.Int
	client  *kms.KeyManagementClient
	pubkey  []byte
	keyName string
}

func NewGCPSigner() *gcpSigner {
	return &gcpSigner{}
}

func (s *gcpSigner) SignDigest(ctx context.Context, digest []byte) (signature []byte, err error) {
	req := &kmspb.AsymmetricSignRequest{}
	out, err := s.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, err
	}

	sig := new(struct {
		R *big.Int
		S *big.Int
	})
	_, err = asn1.Unmarshal(out.Signature, sig)
	if err != nil {
		return nil, err
	}

	// EIP-2
	if sig.S.Cmp(secp256k1halfN) > 0 {
		sig.S = new(big.Int).Sub(secp256k1N, sig.S)
	}

	sigr := pad32(sig.R.Bytes())
	sigs := pad32(sig.S.Bytes())

	signature = append(sigr, sigs...)

	// Calc V
	for _, v := range []int{0, 1} {
		sigv := append(signature, byte(v))
		pubkey, err := secp256k1.RecoverPubkey(digest, sigv)
		if err != nil {
			return nil, err
		}

		candidate, err := publicKeyBytesToAddress(pubkey)
		if err != nil {
			return nil, err
		}

		address, err := s.Address(ctx)
		if err != nil {
			return nil, err
		}

		if reflect.DeepEqual(address.Bytes(), candidate.Bytes()) {
			signature = append(signature, byte(v))
			break
		}
	}

	return signature, nil
}

func (s *gcpSigner) Address(ctx context.Context) (address *common.Address, err error) {
	pub, err := s.pubKey(ctx)
	if err != nil {
		return nil, err
	}

	return publicKeyBytesToAddress(pub)
}

func (s *gcpSigner) ChainID() *big.Int {
	return s.chainID
}

func (s *gcpSigner) pubKey(ctx context.Context) ([]byte, error) {
	req := &kmspb.GetPublicKeyRequest{
		Name: s.keyName,
	}
	result, err := s.client.GetPublicKey(ctx, req)
	if err != nil {
		return nil, err
	}

	pemKey := []byte(result.Pem)

	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	if int64(crc32c(pemKey)) != result.PemCrc32C.Value {
		return nil, fmt.Errorf("getPublicKey: response corrupted in-transit")
	}

	// block, _ := pem.Decode(pemKey)
	// publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	// if err != nil {
	// 	return nil, err
	// }

	// return nil, nil
	return pemKey, nil
}

func publicKeyBytesToAddress(pub []byte) (*common.Address, error) {
	pubkey, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		return nil, err
	}
	address := crypto.PubkeyToAddress(*pubkey)
	return &address, nil
}

func pad32(src []byte) []byte {
	l := 32
	if len(src) == l {
		return src
	}

	dst := make([]byte, l)
	copy(dst, src)
	return dst
}
