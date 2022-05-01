package main

import (
	"context"
	"fmt"

	"github.com/winor30/go-cloud-signer/signer"
	"github.com/winor30/go-cloud-signer/txopts"
)

func main() {
	s := signer.NewGCPSigner()
	txopt, err := txopts.NewTransactionOpts(context.TODO(), s)
	fmt.Println(txopt, err)
}
