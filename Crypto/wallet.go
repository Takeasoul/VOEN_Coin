package crypto

import (
	_ "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

// Структура кошелька
type Wallet struct {
	WalletID         int
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Balance    int
}

// Создание нового кошелька
func NewWallet() (*Wallet, error) {
	privateKey, err := generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey := &privateKey.PublicKey
	wallet := &Wallet{
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

	// Конвертация приватного ключа в формат PEM
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Запись приватного ключа в файл
	privateKeyFile, err := os.Create("private.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()
	err = pem.Encode(privateKeyFile, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to write private key to file: %v", err)
	}

	return privateKey, nil
}

// Получение публичного ключа из приватного
func getPublicKeyFromPrivateKey(privateKey *rsa.PrivateKey) (*rsa.PublicKey, error) {
	publicKey := &privateKey.PublicKey
	return publicKey, nil
}

// Генерация адреса на основе публичного ключа
func generateAddress(publicKey *rsa.PublicKey) string {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(publicKeyBytes)
	return hex.EncodeToString(hash[:])
}

// Загрузка приватного ключа из файла
func LoadPrivateKeyFromFile(filepath string) (*rsa.PrivateKey, error) {
	privateKeyFile, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open private key file: %v", err)
	}
	defer privateKeyFile.Close()

	privateKeyBytes, err := ioutil.ReadFile("private.pem")
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

// Отправка монет другому пользователю
func (bc *Blockchain) SendCoins(senderPrivateKey *rsa.PrivateKey, recipientAddress string, amount int) error {
	// Получение адреса отправителя
	senderPublicKey, err := getPublicKeyFromPrivateKey(senderPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to get public key from private key: %v", err)
	}
	senderAddress := generateAddress(senderPublicKey)

	// Проверка доступных средств у отправителя
	tx := &Transaction{
		Inputs:  []TxInput{},
		Outputs: []TxOutput{},
	}
	totalAmount := 0
	for id, amount := range bc.UTXOSet {
		tx.Inputs = append(tx.Inputs, TxInput{
			TxID:    id,
			Index:   0,
			Address: senderAddress,
		})
		totalAmount += amount
		if totalAmount >= amount {
			break
		}
	}
	if totalAmount < amount {
		return fmt.Errorf("insufficient funds")
	}

	// Создание выхода для получателя
	tx.Outputs = append(tx.Outputs, TxOutput{
		Address: recipientAddress,
		Amount:  amount,
	})

	// Создание выхода для отправителя (сдача)
	changeAmount := totalAmount - amount
	if changeAmount > 0 {
		tx.Outputs = append(tx.Outputs, TxOutput{
			Address: senderAddress,
			Amount:  changeAmount,
		})
	}

	// Установка идентификатора транзакции и подписи
	tx.SetID()
	err = tx.Sign(senderPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}

	// Верификация подписи
	err = tx.Verify(senderPublicKey)
	if err != nil {
		return fmt.Errorf("failed to verify transaction signature: %v", err)
	}

	// Добавление транзакции в цепочку
	bc.AddUTXO(tx)
	bc.Blocks[len(bc.Blocks)-1].Data = fmt.Sprintf("Transaction %s", tx.ID)

	return nil
}
