package crypto

import (
	"bufio"
	"crypto" 
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// Структура блока
type Block struct {
	Index      int
	Timestamp  time.Time
	Data       string
	PrevHash   string
	Hash       string
	Nonce      int
	Difficulty int
}

// Создание блока
func NewBlock(index int, data string, prevHash string) *Block {
	block := &Block{
		Index:     index,
		Timestamp: time.Now(),
		Data:      data,
		PrevHash:  prevHash,
		Hash:      "",
		Nonce:     0,
	}
	block.Hash = block.CalculateHash()
	return block
}

func GenerateBlock(prevBlock *Block, data string, difficulty int) *Block {
	var newBlock Block

	newBlock.Index = prevBlock.Index + 1
	newBlock.Timestamp = time.Now()
	newBlock.Data = data
	newBlock.PrevHash = prevBlock.Hash
	newBlock.Difficulty = difficulty

	return &newBlock
}

// Вычисление хэша блока
func (b *Block) CalculateHash() string {
	data := strconv.Itoa(b.Index) + b.Timestamp.String() + b.Data + b.PrevHash + strconv.Itoa(b.Nonce)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Создание генезис-блока
func CreateGenesisBlock() *Block {
	return NewBlock(0, "Genesis Block", "")
}

// Структура цепочки блоков
type Blockchain struct {
	Blocks    []*Block
	UTXOSet   map[string]int // Unspent Transaction Outputs Set
	TxOutputs []*TxOutput
	DB        *sql.DB
}

// Добавление нового блока в цепочку
func (bc *Blockchain) AddBlock(data string, difficulty int) {
	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := GenerateBlock(prevBlock, data, difficulty)
	MineBlock(newBlock, difficulty)
	bc.Blocks = append(bc.Blocks, newBlock)
	bc.SaveBlockToDB(newBlock)
}

// Сохранение блока в базу данных
func (bc *Blockchain) SaveBlockToDB(block *Block) {
	stmt, err := bc.DB.Prepare("INSERT INTO blocks (index, timestamp, data, prev_hash, hash, nonce, difficulty) VALUES ($1, $2, $3, $4, $5, $6, $7)")
	if err != nil {
		fmt.Printf("failed to prepare statement: %v\n", err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(block.Index, block.Timestamp, block.Data, block.PrevHash, block.Hash, block.Nonce, block.Difficulty)
	if err != nil {
		fmt.Printf("failed to execute statement: %v\n", err)
	}
}

// Загрузка блоков из базы данных
func (bc *Blockchain) LoadBlocksFromDB() error {
	rows, err := bc.DB.Query("SELECT * FROM blocks ORDER BY index ASC")
	if err != nil {
		return fmt.Errorf("failed to execute query: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var block Block
		err := rows.Scan(&block.Index, &block.Timestamp, &block.Data, &block.PrevHash, &block.Hash, &block.Nonce, &block.Difficulty)
		if err != nil {
			return fmt.Errorf("failed to scan row: %v", err)
		}
		bc.Blocks = append(bc.Blocks, &block)
	}

	err = rows.Err()
	if err != nil {
		return fmt.Errorf("failed to retrieve data from query: %v", err)
	}

	return nil
}

// Проверка целостности цепочки блоков
func (bc *Blockchain) IsChainValid() bool {
	for i := 1; i < len(bc.Blocks); i++ {
		currentBlock := bc.Blocks[i]
		prevBlock := bc.Blocks[i-1]

		// Проверка хэша текущего блока
		if currentBlock.Hash != currentBlock.CalculateHash() {
			return false
		}

		// Проверка ссылки на предыдущий блок
		if currentBlock.PrevHash != prevBlock.Hash {
			return false
		}
	}
	return true
}

// Вывод информации о блоках в цепочке
func (bc *Blockchain) PrintBlocks() {
	for _, block := range bc.Blocks {
		fmt.Printf("Block %d:\n", block.Index)
		fmt.Printf("Timestamp: %s\n", block.Timestamp.String())
		fmt.Printf("Data: %v\n", block.Data)
		fmt.Printf("PrevHash: %s\n", block.PrevHash)
		fmt.Printf("Hash: %s\n", block.Hash)
		fmt.Printf("Nonce: %d\n", block.Nonce)
		fmt.Println("-------------------------------")
	}
}

func MineBlock(block *Block, difficulty int) {
	target := strings.Repeat("0", difficulty)

	for {
		block.Nonce++
		block.Hash = block.CalculateHash()

		if strings.HasPrefix(block.Hash, target) {
			fmt.Println("Блок найден! Нонс:", block.Nonce)
			break
		}
	}
}

// Структура транзакции
type Transaction struct {
	ID        string
	Inputs    []TxInput
	Outputs   []TxOutput
	Signature []byte
}

// Структура входа транзакции
type TxInput struct {
	TxID    string
	Index   int
	Address string
}

// Структура выхода транзакции
type TxOutput struct {
	Address string
	Amount  int
}

// Генерация идентификатора транзакции
func (tx *Transaction) SetID() {
	inputs := ""
	for _, in := range tx.Inputs {
		inputs += in.TxID + strconv.Itoa(in.Index)
	}

	outputs := ""
	for _, out := range tx.Outputs {
		outputs += out.Address + strconv.Itoa(out.Amount)
	}

	data := inputs + outputs
	hash := sha256.Sum256([]byte(data))
	tx.ID = hex.EncodeToString(hash[:])
}

// Подпись входа транзакции
func (tx *Transaction) Sign(privateKey *rsa.PrivateKey) error {
	hash := sha256.Sum256([]byte(tx.ID))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}

	tx.Signature = signature
	return nil
}

// Верификация подписи входа транзакции
func (tx *Transaction) Verify(publicKey *rsa.PublicKey) error {
	hash := sha256.Sum256([]byte(tx.ID))
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], tx.Signature)
	if err != nil {
		return fmt.Errorf("failed to verify transaction signature: %v", err)
	}

	return nil
}

// Добавление выхода в UTXO Set
func (bc *Blockchain) AddUTXO(tx *Transaction) {
	for _, out := range tx.Outputs {
		bc.UTXOSet[out.Address] = out.Amount
	}
}

// Удаление выхода из UTXO Set
func (bc *Blockchain) RemoveUTXO(tx *Transaction) {
	for _, in := range tx.Inputs {
		delete(bc.UTXOSet, in.TxID)
	}
}

// Проверка доступных средств в UTXO Set
func (bc *Blockchain) CheckUTXO(tx *Transaction) error {
	for _, in := range tx.Inputs {
		if bc.UTXOSet[in.TxID] == 0 {
			return fmt.Errorf("непотраченный выход транзакции не найден: %s", in.TxID)
		}
	}

	return nil
}

func createRewardTransaction(senderPublicKey rsa.PublicKey, recipientAddress string, reward int) *Transaction {
	rewardInput := TxInput{
		TxID:    "", // Пустой идентификатор, так как это наградная транзакция
		Index:   -1, // Индекс -1 для награды
		Address: "", // Пустой адрес, так как это наградная транзакция
	}

	rewardOutput := TxOutput{
		Address: recipientAddress,
		Amount:  reward,
	}

	rewardTx := Transaction{
		Inputs:    []TxInput{rewardInput},
		Outputs:   []TxOutput{rewardOutput},
		Signature: nil, // Подпись не требуется для наградной транзакции
	}
	rewardTx.SetID()

	return &rewardTx
}

func RunUserInterface(blockchain *Blockchain, privateKey *rsa.PrivateKey) {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println("\nВыберите действие:")
		fmt.Println("1. Добавить новый блок")
		fmt.Println("2. Вывести информацию о блоках")
		fmt.Println("3. Проверить целостность цепочки")
		fmt.Println("4. Отправить монеты")
		fmt.Println("5. Выйти")

		fmt.Print("Ваш выбор: ")
		scanner.Scan()
		choice := scanner.Text()

		switch choice {
		case "1":
			fmt.Print("Введите данные для нового блока: ")
			scanner.Scan()
			data := scanner.Text()
			fmt.Print("Введите сложность майнинга (число нулей в начале хэша): ")
			scanner.Scan()
			difficultyStr := scanner.Text()
			difficulty, err := strconv.Atoi(difficultyStr)
			if err != nil {
				fmt.Println("Некорректная сложность. Попробуйте снова.")
				continue
			}
			blockchain.AddBlock(data, difficulty)
			minedBlock := blockchain.Blocks[len(blockchain.Blocks)-1]
			reward := 10 // Количество монет в качестве награды за добытый блок
			rewardTx := createRewardTransaction(privateKey.PublicKey, "Ваш адрес", reward)
			minedBlock.Data = fmt.Sprintf("Transaction %s (Reward)", rewardTx.ID)
			blockchain.AddUTXO(rewardTx)
			fmt.Println("Новый блок добавлен в цепочку.")
		case "2":
			fmt.Println("Информация о блоках в цепочке:")
			blockchain.PrintBlocks()
		case "3":
			isValid := blockchain.IsChainValid()
			if isValid {
				fmt.Println("Цепочка блоков валидна.")
			} else {
				fmt.Println("Цепочка блоков повреждена.")
			}
		case "4":
			fmt.Println("Введите адрес получателя: ")
			scanner.Scan()
			recipientAddress := scanner.Text()
			fmt.Println("Введите количество монет для отправки: ")
			scanner.Scan()
			amountStr := scanner.Text()
			amount, err := strconv.Atoi(amountStr)
			if err != nil {
				fmt.Println("Некорректное количество монет. Попробуйте снова.")
				continue
			}
			err = blockchain.SendCoins(privateKey, recipientAddress, amount)
			if err != nil {
				fmt.Printf("Ошибка при отправке монет: %v\n", err)
				continue
			}
			fmt.Println("Монеты успешно отправлены.")
		case "5":
			fmt.Println("Выход из программы.")
			return
		default:
			fmt.Println("Некорректный выбор. Попробуйте снова.")
		}
	}
}

func main() {
	privateKey, err := generateKeyPair()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Подключение к базе данных PostgreSQL
	db, err := sql.Open("postgres", "host=localhost port=5432 user=postgres password=89818286905Niki dbname=postgres sslmode=disable")
	if err != nil {
		fmt.Printf("Failed to connect to the database: %v\n", err)
		return
	}
	defer db.Close()

	// Проверка соединения с базой данных
	err = db.Ping()
	if err != nil {
		fmt.Printf("Failed to ping the database: %v\n", err)
		return
	}

	fmt.Println("Key pair loaded successfully.")
	// Создание цепочки блоков
	blockchain := &Blockchain{
		Blocks:    []*Block{CreateGenesisBlock()},
		UTXOSet:   make(map[string]int),
		TxOutputs: []*TxOutput{},
		DB:        db,
	}

	// Загрузка блоков из базы данных
	err = blockchain.LoadBlocksFromDB()
	if err != nil {
		fmt.Printf("Failed to load blocks from database: %v\n", err)
		return
	}

	// Вывод информации о блоках
	blockchain.PrintBlocks()

	// Проверка целостности цепочки блоков
	isValid := blockchain.IsChainValid()
	fmt.Printf("Is blockchain valid? %v\n", isValid)

	RunUserInterface(blockchain, privateKey)
}
