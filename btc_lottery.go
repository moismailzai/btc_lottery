package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lib/pq"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

var (
	counterInterval       = flag.Int("c", 0, "Interval for reporting wallet generation count")
	dbConn                = flag.String("db", "postgres://btc:btc@localhost:5432/btc?sslmode=disable", "Database connection string")
	pushoverNotifications = flag.Bool("pn", true, "Enable Pushover notifications for wallet generation updates")
	pushoverToken         = flag.String("pt", "", "Pushover application token")
	pushoverUser          = flag.String("pu", "", "Pushover user key")
	batchSize             = flag.Int("b", 1000, "Batch size for checking addresses in DB")
	workers               = flag.Int("w", 50, "Number of concurrent workers to generate wallets")
	addressIndexes        = flag.Int("i", 20, "Number of address indexes to check per mnemonic (0-n)")
	// use these flags for debugging only since they'll dramatically reduce performance
	recordAllWallets = flag.Bool("a", false, "Record all wallets in the database, irrespective of matches")
	recordMisses     = flag.Bool("m", false, "Record addresses that don't match in the misses table")
	verbose          = flag.Bool("v", false, "Enable verbose output for debugging")

	counter   int64
	overflows int64

	// Bloom filter for fast negative lookups
	addressBloomFilter *bloom.BloomFilter
)

// addressInfo holds all data for a generated address
type addressInfo struct {
	address    string
	privateKey string
	publicKey  string
	mnemonic   string
	addrType   string // "p2pkh" or "p2wpkh"
}

func logVerbose(verbose bool, format string, args ...interface{}) {
	if verbose {
		log.Printf(format, args...)
	}
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

	client := &http.Client{Timeout: 10 * time.Second}
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

// deriveChildKey derives a child key following BIP44/BIP84 path
// purpose: 44 for BIP44 (P2PKH), 84 for BIP84 (P2WPKH)
// addressIndex: which address index to derive (0, 1, 2, ...)
func deriveChildKey(masterKey *bip32.Key, purpose uint32, addressIndex uint32) (*bip32.Key, error) {
	// BIP44 path: m/44'/0'/0'/0/index (for P2PKH)
	// BIP84 path: m/84'/0'/0'/0/index (for P2WPKH)

	purposeKey, err := masterKey.NewChildKey(bip32.FirstHardenedChild + purpose)
	if err != nil {
		return nil, fmt.Errorf("deriving purpose key: %w", err)
	}

	coinType, err := purposeKey.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		return nil, fmt.Errorf("deriving coin type key: %w", err)
	}

	account, err := coinType.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		return nil, fmt.Errorf("deriving account key: %w", err)
	}

	change, err := account.NewChildKey(0)
	if err != nil {
		return nil, fmt.Errorf("deriving change key: %w", err)
	}

	addressKey, err := change.NewChildKey(addressIndex)
	if err != nil {
		return nil, fmt.Errorf("deriving address key: %w", err)
	}

	return addressKey, nil
}

// generateAddressesFromMnemonic generates both P2PKH and P2WPKH addresses from a mnemonic
// using compressed public keys and standard BIP44/84 derivation paths
// Generates multiple address indexes (0 to addressIndexes-1) for each type
func generateAddressesFromMnemonic() ([]addressInfo, error) {
	// Generate a 12-word mnemonic (128 bits of entropy)
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return nil, fmt.Errorf("generating entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("creating mnemonic: %w", err)
	}

	// Generate seed from mnemonic (no passphrase)
	seed := bip39.NewSeed(mnemonic, "")

	// Derive master key from seed
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("creating master key: %w", err)
	}

	// Pre-allocate for 2 address types × addressIndexes
	addresses := make([]addressInfo, 0, 2*(*addressIndexes))

	// Generate addresses for each index
	for idx := uint32(0); idx < uint32(*addressIndexes); idx++ {
		// BIP44 path (m/44'/0'/0'/0/idx) for P2PKH addresses
		p2pkhChildKey, err := deriveChildKey(masterKey, 44, idx)
		if err != nil {
			return nil, fmt.Errorf("deriving BIP44 child key at index %d: %w", idx, err)
		}

		privKey, _ := btcec.PrivKeyFromBytes(p2pkhChildKey.Key)
		wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
		if err != nil {
			return nil, fmt.Errorf("creating WIF: %w", err)
		}

		pubKeyBytes := wif.SerializePubKey()
		pubKeyHash := btcutil.Hash160(pubKeyBytes)

		p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
		if err != nil {
			return nil, fmt.Errorf("creating P2PKH address: %w", err)
		}

		addresses = append(addresses, addressInfo{
			address:    p2pkhAddr.EncodeAddress(),
			privateKey: wif.String(),
			publicKey:  fmt.Sprintf("%x", pubKeyBytes),
			mnemonic:   mnemonic,
			addrType:   fmt.Sprintf("p2pkh/%d", idx),
		})

		// BIP84 path (m/84'/0'/0'/0/idx) for P2WPKH addresses
		p2wpkhChildKey, err := deriveChildKey(masterKey, 84, idx)
		if err != nil {
			return nil, fmt.Errorf("deriving BIP84 child key at index %d: %w", idx, err)
		}

		privKey84, _ := btcec.PrivKeyFromBytes(p2wpkhChildKey.Key)
		wif84, err := btcutil.NewWIF(privKey84, &chaincfg.MainNetParams, true)
		if err != nil {
			return nil, fmt.Errorf("creating WIF for BIP84: %w", err)
		}

		pubKeyBytes84 := wif84.SerializePubKey()
		pubKeyHash84 := btcutil.Hash160(pubKeyBytes84)

		p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash84, &chaincfg.MainNetParams)
		if err != nil {
			return nil, fmt.Errorf("creating P2WPKH address: %w", err)
		}

		addresses = append(addresses, addressInfo{
			address:    p2wpkhAddr.EncodeAddress(),
			privateKey: wif84.String(),
			publicKey:  fmt.Sprintf("%x", pubKeyBytes84),
			mnemonic:   mnemonic,
			addrType:   fmt.Sprintf("p2wpkh/%d", idx),
		})
	}

	if *verbose {
		log.Printf("Generated %d addresses from mnemonic: %s", len(addresses), mnemonic)
	}

	return addresses, nil
}

// checkAddressesInDatabase uses Bloom filter for fast rejection, then DB for confirmation
func checkAddressesInDatabase(db *sql.DB, addresses []string) (map[string]bool, error) {
	exists := make(map[string]bool)
	if len(addresses) == 0 {
		return exists, nil
	}

	var candidates []string

	// If Bloom filter is available, use it for fast rejection
	if addressBloomFilter != nil {
		for _, addr := range addresses {
			if addressBloomFilter.TestString(addr) {
				// Bloom filter says "maybe present" - need to verify with DB
				candidates = append(candidates, addr)
			}
			// If Bloom filter says "definitely not present", skip DB lookup
		}

		// If no candidates after Bloom filter, return empty result
		if len(candidates) == 0 {
			return exists, nil
		}

		logVerbose(*verbose, "Bloom filter passed %d/%d addresses to DB", len(candidates), len(addresses))
	} else {
		// No Bloom filter - check all addresses against DB
		candidates = addresses
	}

	// Use ANY($1::text[]) for efficient array-based lookup of candidates only
	query := "SELECT address FROM btc_addresses WHERE address = ANY($1::text[])"
	rows, err := db.Query(query, pq.Array(candidates))
	if err != nil {
		return nil, fmt.Errorf("querying addresses: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, fmt.Errorf("scanning address: %w", err)
		}
		exists[addr] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating rows: %w", err)
	}

	return exists, nil
}

// batchProcessAddresses processes a batch of addresses and stores matches
// Removed the pointless transaction wrapper - individual inserts are fine for this use case
func batchProcessAddresses(db *sql.DB, addressData []addressInfo) error {
	if len(addressData) == 0 {
		return nil
	}

	// Extract addresses for lookup
	addresses := make([]string, len(addressData))
	for i, data := range addressData {
		addresses[i] = data.address
	}

	// Check which addresses exist in the database
	exists, err := checkAddressesInDatabase(db, addresses)
	if err != nil {
		return fmt.Errorf("checking addresses: %w", err)
	}

	// Process each address
	for _, data := range addressData {
		if *recordAllWallets || exists[data.address] {
			_, err := db.Exec(`
				INSERT INTO wallets (private_key, public_key, address, mnemonic, addr_type)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (address)
				DO UPDATE SET private_key = EXCLUDED.private_key,
				              public_key = EXCLUDED.public_key,
				              mnemonic = EXCLUDED.mnemonic,
				              addr_type = EXCLUDED.addr_type`,
				data.privateKey, data.publicKey, data.address, data.mnemonic, data.addrType)
			if err != nil {
				log.Printf("Error inserting wallet: %v", err)
				continue
			}

			if exists[data.address] {
				logMatch(data)
			}
		}

		if *recordMisses && !exists[data.address] {
			_, err := db.Exec("INSERT INTO misses (address) VALUES ($1) ON CONFLICT (address) DO NOTHING", data.address)
			if err != nil {
				log.Printf("Error inserting miss: %v", err)
			}
		}
	}

	return nil
}

func logMatch(data addressInfo) {
	msg := fmt.Sprintf("MATCH FOUND! Address: %s Type: %s Mnemonic: %s", data.address, data.addrType, data.mnemonic)

	// Print to console with emphasis
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println(msg)
	fmt.Println(strings.Repeat("=", 60))

	// Append to a file
	file, err := os.OpenFile("matches.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening matches.log: %v", err)
		return
	}
	defer file.Close()

	timestamp := time.Now().Format(time.RFC3339)
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, msg)
	if _, err := file.WriteString(logLine); err != nil {
		log.Printf("Error writing to matches.log: %v", err)
	}

	// Send push notification for matches
	if *pushoverNotifications && *pushoverToken != "" && *pushoverUser != "" {
		if err := sendPushoverNotification(*pushoverToken, *pushoverUser, "BTC LOTTERY MATCH!", msg); err != nil {
			log.Printf("Error sending match notification: %v", err)
		}
	}
}

func updateCounter(count int) {
	currentCounter := atomic.AddInt64(&counter, int64(count))
	if currentCounter < 0 { // Overflow detection
		atomic.AddInt64(&overflows, 1)
		atomic.StoreInt64(&counter, int64(count))
		currentCounter = int64(count)
	}

	if *counterInterval > 0 && currentCounter%int64(*counterInterval) == 0 {
		overflowCount := atomic.LoadInt64(&overflows)
		counterMessage := fmt.Sprintf("Generated %d addresses (overflows: %d)", currentCounter, overflowCount)
		log.Println(counterMessage)

		if *pushoverNotifications && *pushoverToken != "" && *pushoverUser != "" {
			if err := sendPushoverNotification(*pushoverToken, *pushoverUser, "Wallet Generation Update", counterMessage); err != nil {
				log.Printf("Error sending notification: %v", err)
			}
		}
	}
}

// worker processes address generation with its own LOCAL batch
// This fixes the data race - each worker has independent state
func worker(ctx context.Context, db *sql.DB, wg *sync.WaitGroup) {
	defer wg.Done()

	// Each worker has its OWN local batch - no shared state
	batch := make([]addressInfo, 0, *batchSize)
	consecutiveErrors := 0
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			// Flush remaining batch on shutdown
			if len(batch) > 0 {
				if err := batchProcessAddresses(db, batch); err != nil {
					log.Printf("Error processing final batch: %v", err)
				}
			}
			return
		default:
			// Generate addresses from a new mnemonic
			addresses, err := generateAddressesFromMnemonic()
			if err != nil {
				log.Printf("Error generating addresses: %v", err)
				continue
			}

			// Add to local batch
			batch = append(batch, addresses...)

			// Update counter (only if interval is set)
			if *counterInterval > 0 {
				updateCounter(len(addresses))
			}

			// Process batch when full
			if len(batch) >= *batchSize {
				if err := batchProcessAddresses(db, batch); err != nil {
					log.Printf("Error processing batch: %v", err)
					consecutiveErrors++
					// Exponential backoff on repeated errors
					if consecutiveErrors > 1 {
						backoff := time.Duration(1<<uint(consecutiveErrors-1)) * time.Second
						if backoff > maxBackoff {
							backoff = maxBackoff
						}
						log.Printf("Backing off for %v after %d consecutive errors", backoff, consecutiveErrors)
						select {
						case <-ctx.Done():
							return
						case <-time.After(backoff):
						}
					}
				} else {
					consecutiveErrors = 0
				}
				// Reuse slice capacity instead of reallocating
				batch = batch[:0]
			}
		}
	}
}

// initBloomFilter loads all addresses from the database into a Bloom filter
func initBloomFilter(db *sql.DB, count int64) error {
	log.Println("Initializing Bloom filter...")
	start := time.Now()

	// Create Bloom filter with estimated capacity and 0.01% false positive rate
	// Using 0.0001 (0.01%) FPR for very low false positives
	addressBloomFilter = bloom.NewWithEstimates(uint(count), 0.0001)

	// Stream addresses from DB using cursor-based pagination (much faster than OFFSET for large tables)
	const batchSize = 100000
	var lastAddr string
	var loaded int64 = 0
	lastLogTime := time.Now()

	for {
		var rows *sql.Rows
		var err error

		if lastAddr == "" {
			// First batch
			rows, err = db.Query("SELECT address FROM btc_addresses ORDER BY address LIMIT $1", batchSize)
		} else {
			// Subsequent batches - cursor-based pagination
			rows, err = db.Query("SELECT address FROM btc_addresses WHERE address > $1 ORDER BY address LIMIT $2", lastAddr, batchSize)
		}

		if err != nil {
			return fmt.Errorf("querying addresses for bloom filter: %w", err)
		}

		rowCount := 0
		for rows.Next() {
			var addr string
			if err := rows.Scan(&addr); err != nil {
				rows.Close()
				return fmt.Errorf("scanning address for bloom filter: %w", err)
			}
			addressBloomFilter.AddString(addr)
			lastAddr = addr
			rowCount++
		}
		rows.Close()

		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterating rows for bloom filter: %w", err)
		}

		loaded += int64(rowCount)

		// Log progress every 5 seconds or on completion
		if time.Since(lastLogTime) > 5*time.Second || rowCount < batchSize {
			log.Printf("Loaded %d/%d addresses into Bloom filter (%.1f%%)", loaded, count, float64(loaded)/float64(count)*100)
			lastLogTime = time.Now()
		}

		if rowCount < batchSize {
			break
		}
	}

	log.Printf("Bloom filter initialized with %d addresses in %v (size: ~%.1f MB)",
		loaded, time.Since(start), float64(addressBloomFilter.ApproximatedSize())/(1024*1024))

	return nil
}

func main() {
	flag.Parse()

	log.Println("Starting BTC Lottery...")
	log.Printf("Workers: %d, Batch size: %d, Address indexes: %d", *workers, *batchSize, *addressIndexes)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := sql.Open("postgres", *dbConn)
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}
	defer db.Close()

	// Set connection pool parameters - idle should be closer to max
	db.SetMaxOpenConns(*workers + 10) // A few extra for batch processing
	db.SetMaxIdleConns(*workers)      // Keep connections ready
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatal("Error pinging database:", err)
	}
	log.Println("Database connection established")

	// Check if btc_addresses table has data
	var count int64
	if err := db.QueryRow("SELECT COUNT(*) FROM btc_addresses").Scan(&count); err != nil {
		log.Fatal("Error checking btc_addresses table:", err)
	}
	log.Printf("Found %d addresses in btc_addresses table", count)

	if count == 0 {
		log.Fatal("btc_addresses table is empty - please import address data first")
	}

	// Initialize Bloom filter for fast negative lookups
	if err := initBloomFilter(db, count); err != nil {
		log.Fatal("Error initializing Bloom filter:", err)
	}

	logVerbose(*verbose, "Starting address generation with %d workers...", *workers)

	// Start workers - each with its own goroutine and local state
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(ctx, db, &wg)
	}

	// Wait for shutdown signal
	<-ctx.Done()
	log.Println("Shutdown signal received, waiting for workers to finish...")

	// Wait for all workers to complete
	wg.Wait()

	finalCount := atomic.LoadInt64(&counter)
	log.Printf("Shutdown complete. Total addresses checked: %d", finalCount)
}
