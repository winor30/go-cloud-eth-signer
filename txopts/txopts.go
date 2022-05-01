package txopts

import (
	"context"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type Signer interface {
	SignDigest(context.Context, []byte) (signature []byte, err error)
	Address(context.Context) (address *common.Address, err error)
	ChainID() *big.Int
}

func NewTransactionOpts(ctx context.Context, s Signer) (*bind.TransactOpts, error) {
	keyAddress, err := s.Address(ctx)
	if err != nil {
		return nil, err
	}

	hashSigner := types.LatestSignerForChainID(s.ChainID())

	return &bind.TransactOpts{
		From: *keyAddress,
		Signer: func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if *keyAddress != address {
				return nil, errors.New("not authorized to sign this account")
			}
			digest := hashSigner.Hash(tx).Bytes()

			signature, err := s.SignDigest(ctx, digest)
			if err != nil {
				return nil, err
			}

			return tx.WithSignature(hashSigner, signature)
		},
	}, nil
}
