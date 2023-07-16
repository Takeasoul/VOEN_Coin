package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
) 

var (
	lastWalletID int
	idMutex      sync.Mutex
)

type Wallet struct {
	ID   int
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Balance    int
}

// Создание нового кошелька
func NewWallet() (*Wallet, error) {
	idMutex.Lock()
	lastWalletID++
	newWalletID := lastWalletID
	idMutex.Unlock()

	privateKey, err := generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey := &privateKey.PublicKey
	wallet := &Wallet{
		ID:   newWalletID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Balance:    0,
	}

	return wallet, nil
}

func generateKeyPair() (*rsa.PrivateKey, error) {
	// Генерация приватного ключа
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return privateKey, nil
}

// Сохранение приватного ключа в файл
func SavePrivateKeyToFile(filepath string, privateKey *rsa.PrivateKey) error {
	// Конвертация приватного ключа в формат PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Запись приватного ключа в файл
	privateKeyFile, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()

	err = pem.Encode(privateKeyFile, privateKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to write private key to file: %v", err)
	}

	return nil
}

// Загрузка приватного ключа из файла


func GetPublicKeyFromPrivateKey(privateKey *rsa.PrivateKey) (*rsa.PublicKey, error) {
	publicKey := &privateKey.PublicKey
	return publicKey, nil
}

func GenerateAddress(publicKey *rsa.PublicKey) string {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(publicKeyBytes)
	return hex.EncodeToString(hash[:])
}

func LoadPrivateKeyFromFile(filepath string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}

	privateKeyPEM, _ := pem.Decode(privateKeyBytes)
	if privateKeyPEM == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privateKey, nil
}
