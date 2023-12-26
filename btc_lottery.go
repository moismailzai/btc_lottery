package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	_ "github.com/lib/pq"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

var (
	counterInterval       = flag.Int("c", 0, "Interval for reporting wallet generation count")
	dbConn                = flag.String("db", "postgres://btc:btc@localhost:5432/btc?sslmode=disable", "Database connection string")
	pushoverNotifications = flag.Bool("pn", true, "Enable Pushover notifications for wallet generation updates")
	pushoverToken         = flag.String("pt", "", "Pushover application token")
	pushoverUser          = flag.String("pu", "", "Pushover user key")
	readBatchSize         = flag.Int("rb", 10000, "Batch size for generating wallets before checking in DB")
	writeBatchSize        = flag.Int("wb", 1000, "Batch size for writing wallets to DB")
	workers               = flag.Int("w", 50, "Number of concurrent workers to generate wallets")
	// use these flags for debugging only since they'll dramatically reduce performance
	recordAllWallets = flag.Bool("a", false, "Record all wallets in the database, irrespective of matches")
	recordMisses     = flag.Bool("m", false, "Record addresses that don't match in the misses table")
	verbose          = flag.Bool("v", false, "Enable verbose output for debugging")

	counter          int64
	overflows        int64
	walletInsertStmt *sql.Stmt
	missInsertStmt   *sql.Stmt
)

func logVerbose(verbose bool, format string, args ...interface{}) {
	if verbose {
		log.Printf(format, args...)
	}
}

func prepareStatements(db *sql.DB) error {
	var err error
	walletInsertStmt, err = db.Prepare(`
		INSERT INTO wallets (private_key, public_key, address, mnemonic)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (address)
		DO UPDATE SET private_key = EXCLUDED.private_key, public_key = EXCLUDED.public_key, mnemonic = EXCLUDED.mnemonic`)
	if err != nil {
		return err
	}

	missInsertStmt, err = db.Prepare("INSERT INTO misses (address) VALUES ($1) ON CONFLICT (address) DO NOTHING")
	return err
}

func sendPushoverNotification(token, user, title, message string) error {
	form := url.Values{}
	form.Set("token", token)
	form.Set("user", user)
	form.Set("title", title)
	form.Set("message", message)

	req, err := http.NewRequest("POST", "https://api.pushover.net/1/messages.json", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK response from Pushover: %s", resp.Status)
	}

	return nil
}

func generateAddressFromMnemonic() (address, privateKey, publicKey, mnemonic string, err error) {
	// Generate a 12-word mnemonic
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		log.Println("Error generating entropy:", err)
		return
	}
	mnemonic, err = bip39.NewMnemonic(entropy)
	if err != nil {
		log.Println("Error creating mnemonic:", err)
		return
	}

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	// Derive master key from seed
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Println("Error creating master key:", err)
		return
	}

	// Derive first child key
	childKey, err := masterKey.NewChildKey(0)
	if err != nil {
		log.Println("Error creating child key:", err)
		return
	}

	// Convert child key to WIF
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), childKey.Key)
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, false)
	if err != nil {
		log.Println("Error creating WIF from private key:", err)
		return
	}

	addresspubkey, err := btcutil.NewAddressPubKey(wif.SerializePubKey(), &chaincfg.MainNetParams)
	if err != nil {
		log.Println("Error creating public key address:", err)
		return
	}

	address = addresspubkey.EncodeAddress()
	privateKey = wif.String()
	publicKey = addresspubkey.String()

	if *verbose {
		log.Printf("Generated address %s: %s\n", address, mnemonic)
	}

	return address, privateKey, publicKey, mnemonic, nil
}

func checkAddressesInDatabase(db *sql.DB, addresses []string) (map[string]bool, error) {
	exists := make(map[string]bool)
	if len(addresses) == 0 {
		return exists, nil
	}

	query := "SELECT address FROM btc_addresses WHERE address IN ("
	args := make([]interface{}, len(addresses))
	for i, addr := range addresses {
		args[i] = addr
		query += fmt.Sprintf("$%d,", i+1)
	}
	query = strings.TrimRight(query, ",") + ")"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		exists[addr] = true
	}

	return exists, nil
}

func batchProcessAddresses(db *sql.DB, addressData []addressInfo) {
	if len(addressData) == 0 {
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v\n", err)
		return
	}

	var addresses []string
	for _, data := range addressData {
		addresses = append(addresses, data.address)
	}

	exists, err := checkAddressesInDatabase(db, addresses)
	if err != nil {
		log.Printf("Error checking addresses: %v\n", err)
		tx.Rollback()
		return
	}

	for _, data := range addressData {
		if *recordAllWallets || exists[data.address] {
			_, err := walletInsertStmt.Exec(data.privateKey, data.publicKey, data.address, data.mnemonic)
			if err != nil {
				log.Printf("Error executing wallet insert statement: %v\n", err)
				tx.Rollback()
				return
			}

			if exists[data.address] {
				logMatch(data.address) // Log match immediately
			}
		}

		if *recordMisses && !exists[data.address] {
			_, err := missInsertStmt.Exec(data.address)
			if err != nil {
				log.Printf("Error executing miss insert statement: %v\n", err)
				tx.Rollback()
				return
			}
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v\n", err)
		tx.Rollback()
	}
}

func logMatch(address string) {
	// Print to console
	fmt.Printf("Match found: %s\n", address)

	// Append to a file
	file, err := os.OpenFile("matches.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(fmt.Sprintf("Match found: %s\n", address)); err != nil {
		log.Printf("Error writing to file: %v\n", err)
	}
}

type addressInfo struct {
	address    string
	privateKey string
	publicKey  string
	mnemonic   string
}

func updateCounter() {
	currentCounter := atomic.AddInt64(&counter, 1)
	if currentCounter == math.MaxInt64 {
		atomic.AddInt64(&overflows, 1)
		atomic.StoreInt64(&counter, 0)
	} else if currentCounter%int64(*counterInterval) == 0 {
		overflowCount := atomic.LoadInt64(&overflows)
		counterMessage := fmt.Sprintf("Generated %d wallets (overflows: %d)", currentCounter, overflowCount)
		log.Println(counterMessage)

		if *pushoverNotifications {
			if err := sendPushoverNotification(*pushoverToken, *pushoverUser, "Wallet Generation Update", counterMessage); err != nil {
				log.Printf("Error sending notification: %v\n", err)
			}
		}
	}
}
func main() {
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := sql.Open("postgres", *dbConn)
	if err != nil {
		log.Println("Error connecting to database:", err)
		return
	}
	defer db.Close()

	// Set connection pool parameters
	db.SetMaxOpenConns(*workers)
	db.SetMaxIdleConns(10) // Adjust as needed
	db.SetConnMaxLifetime(5 * time.Minute)

	logVerbose(*verbose, "Starting address generation...")

	// Prepare statements
	if err := prepareStatements(db); err != nil {
		log.Fatal("Error preparing statements: ", err)
	}
	defer walletInsertStmt.Close()
	defer missInsertStmt.Close()

	// Initialize worker goroutines
	var wg sync.WaitGroup
	var readBatch []addressInfo
	var writeBatch []addressInfo
	tasks := make(chan struct{})

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range tasks {
				address, privKey, pubKey, mnemonic, err := generateAddressFromMnemonic()
				if err != nil {
					log.Println("Error generating address data:", err)
					continue
				}
				readBatch = append(readBatch, addressInfo{address, privKey, pubKey, mnemonic})

				if *counterInterval > 0 {
					updateCounter()
				}

				if len(readBatch) >= *readBatchSize {
					// Process for writing
					writeBatch = append(writeBatch, readBatch...)
					readBatch = make([]addressInfo, 0) // Reset the read batch

					if len(writeBatch) >= *writeBatchSize {
						batchProcessAddresses(db, writeBatch)
						writeBatch = make([]addressInfo, 0) // Reset the write batch
					}
				}
			}
		}()
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				if len(writeBatch) > 0 {
					batchProcessAddresses(db, writeBatch)
				}
				if len(readBatch) > 0 {
					batchProcessAddresses(db, readBatch)
				}
				close(tasks)
				return
			default:
				tasks <- struct{}{}
			}
		}
	}()

	wg.Wait()
	logVerbose(*verbose, "Address generation completed.")
}
