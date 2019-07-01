package config

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	ec "github.com/ethereum/go-ethereum/crypto"

	"github.com/ipfs/go-ipfs/chain/base64"
	"github.com/ipfs/go-ipfs/chain/keystore"
)

const DefaultKeystoreFile = "/chain/keystore"

const ChainTag = "Chain"
const KeystorePwdTag = "KeystorePwd"
const KeystorePwdSelector = ChainTag + "." + KeystorePwdTag

// Chain tracks the configuration of the ipw blockchain.
type Chain struct {
	URL          string `json:",omitempty"`
	KeystorePwd  string `json:",omitempty"`
}

func KeystoreFile() string {
	rootPath, err := PathRoot()
	if err != nil {
		return DefaultKeystoreFile
	}
	return rootPath + DefaultKeystoreFile
}

// WalletAddress is convertor from the users Wallet Private Key
func (c *Chain) WalletAddress() (string, error) {
	walletKey, err := c.WalletKey()
	if err != nil {
		return "", err
	}
	privateKey, err := ec.HexToECDSA(walletKey)
	if err != nil {
		return "", err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("error casting public key to ECDSA")
	}

	fromAddress := ec.PubkeyToAddress(*publicKeyECDSA)
	return fmt.Sprintf("%x", fromAddress), nil
}

func (c *Chain) WalletKey() (walletKey string, err error) {
	if c.KeystorePwd == "" {
		return "", fmt.Errorf("No keystore password")
	}

	password, err := base64.RawStdEncoding.DecodeString(c.KeystorePwd)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	privateKey, err := keystore.PrivateKeyFromKeystore(KeystoreFile(), string(password))
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	return privateKey, nil
}
