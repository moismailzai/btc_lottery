# Running the binary
1. Copy `./build/btc_lottery` into your `$PATH`
2. Download the latest raw data:
    ```
    curl -L -o blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz
    gunzip blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz
    ```
3. Bring up the database:
    ```shell
    docker-compose up -d
    ```
4. Import the data (go grab a coffee, this will take a while):
    ```shell
    sudo docker exec -it btc_lottery-postgres-1 psql -h localhost -U btc -d btc -c "\copy btc_addresses FROM '/blockchair_bitcoin_addresses_and_balance_LATEST.tsv' WITH (FORMAT text, DELIMITER E'\t', HEADER);"
    ```
5. Run the lottery using the -v flag to ensure it's working:
    ```shell
    btc_lottery -v
    ```

# Building from source

First, install dependencies:

```shell
go get github.com/btcsuite/btcd/btcec
go get github.com/btcsuite/btcd/chaincfg
go get github.com/btcsuite/btcutil
go get github.com/tyler-smith/go-bip39
go get github.com/tyler-smith/go-bip32
go get github.com/lib/pq
```

Then, make an optimized build:

```shell
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" btc_wallet_clash.go
```

# Sourcing the data

The wallet addresses are sourced from [Blockchair.com's daily dumps](https://blockchair.com/dumps), as they're captured
by a [proxy site](http://addresses.loyce.club/).

See [this bitcointalk.org thread](https://bitcointalk.org/index.php?topic=5254914.0) for more details on motivations
and methodology.

# Bootstrapping the SQL database
Instead of the docker database, you can bootstrap your own database like so:

* run `persist/initdb/init.psql.sql` for schema and index generation.
* download and import the latest data:
  ```shell
  curl -L -o blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz
  gunzip blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz
  psql -h localhost -U btc -d btc -c "\copy btc_addresses FROM '/blockchair_bitcoin_addresses_and_balance_LATEST.tsv' WITH (FORMAT text, DELIMITER E'\t', HEADER);"
  ```