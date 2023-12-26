# Introduction

## Bitcoin wallets and private keyspace

Your Bitcoin wallet is derived from a single number. This number is used to generate a private key, public key, and
wallet address. If someone else could guess this number, they could sign transactions using your private key and control
your funds.

The only thing protecting your Bitcoin is the sheer size of the private key space, which is incredibly large. As humans,
it's very difficult for us to reason about numbers beyond a certain size, so I find comparisons and practical
applications are helpful.

If we consider storing the entire Bitcoin key space, which comprises all possible Bitcoin addresses, the total number is
around 2^160, amounting to approximately 1.46×10^48 unique addresses. Assuming each address requires an average size of
34 bytes, the total file size to represent the entire key space would be 34 bytes × 1.46×10^48 addresses, or
approximately 4.96×10^49 bytes.

To store this data using hypothetical 1 billion TB (or 1×10^15 bytes) hard drives, we would need about 4.96×10^34 hard
drives.

With the dimensions of a standard 3.5-inch HDD being 5.8 in x 4 in x 0.8 in, the surface area of each hard drive is
approximately 23.2 square inches. Therefore, with 4.96×10^34 hard drives, the total area covered would be 23.2 square
inches × 4.96×10^34, which equals approximately 1.15×10^36 square inches.

Comparing this to the surface area of the Sun, which is about 6.09×10^22 square inches, these hard drives would cover
the surface of the Sun roughly 1.89×10^13 times.

Considering the total height if the hard drives were stacked, with each being approximately 0.8 inches in height, the
total height of the stack would be 0.8 inches × 4.96×10^34, equaling approximately 3.91×10^34 inches. Given that the
diameter of the Sun is about 864,575,959 inches, this stack would reach a height approximately 4.59×10^25 times the
diameter of the Sun.

Therefore, if the hard drives were layered in such a way that each layer covers the entire surface of the Sun, and
considering each layer to be 0.8 inches in height, the total height of these layers would be approximately 3.97 x 10^34
inches. This is about 4.59 x 10^25 times the diameter of the Sun, indicating an immensely tall stack that far exceeds
the scale of our solar system.

## Practical impossibility of guessing an existing key

Because Bitcoin wallets are ultimately derived from a single number, it should be possible to use a computer to guess
random numbers until it finds one that matches an existing wallet. To do this, we only need a program to do the guessing
and a list of all existing wallets.

To decrease the scope of our task, let's limit the private keys to only those that are derived from a 12-word key
phrase (a common default on most wallets). This removes a large number of keys from the poll of possible keys, making it
more likely to find an existing one.

And to make this worth our time, we'll focus only on wallets that have Bitcoin in them... which would effectively give
us control of the corresponding wallet. For this portion, we'll use the dump of all wallets and their balances as
published by https://blockchair.com/dumps.

# Running the binary

1. Copy `./build/btc_lottery` into your `$PATH`
2. Download the latest raw wallet and balances data:
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
6. Once you've verified everything is working as expected, run the application without the verbose flag and enable Pushover notifications so you can be notified when you win the Bitcoin lottery (it's not going to happen):
    ```shell
    btc_lottery -pt $PUSHOVER_APPLICATION_TOKEN -pu $PUSHOVER_USER_KEY
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