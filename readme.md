# Bitcoin Key Generator with Intel QAT Acceleration

This program uses Intel QuickAssist Technology (QAT) hardware acceleration to efficiently generate Bitcoin private/public key pairs and check them against a list of high-value Bitcoin addresses.

## Overview

The Bitcoin Key Generator leverages Intel QAT hardware to perform elliptic curve operations on the secp256k1 curve (used by Bitcoin) at accelerated speeds. It can generate millions of key pairs per second and efficiently check them against a pre-loaded list of high-value Bitcoin addresses using binary search for optimal performance. It will also generate keypairs and save them to disk when that mode is selected. Throughput is thermally limited on the QAT card which only has a heat seat. Without fan assistance the throughput is limited to 6312.01 keys/sec. With a fan forcing air over the cooling fins the throughput stabilises at around 120000 keys/sec with an initial maximum of over 100,000,000 keys/sec. In this respect it exceeds gpu performance.

Collision Probability Analysis:
- High-value addresses loaded: 84910
- Collision probability: 7.33e-73 (1 in 1.36e+72)
- Expected keys to check before match: 1.36e+72
- At current rate (6312.01 keys/sec):
  * Estimated time to find a match: 6.85e+60 years
  * Time to search all keys (2^256): 5.82e+65 years
16000000 iterations completed in 2534.85 seconds (42 minutes)
256000000 iterations will complete in 11.26 hours 10
3840000000 the max limit would complete in 7 days.


### Features

- Hardware-accelerated secp256k1 key generation using Intel QAT
- Multi-threaded operation for maximum performance
- Binary search for efficient lookup of public keys
- Support for both random and sequential key generation
- Debug mode for troubleshooting
- Configurable batch size and thread count
- Real-time progress reporting
- Performance statistics

## Prerequisites

- Intel QuickAssist Technology (QAT) hardware
- QAT driver installed and configured
- GCC compiler and Make build system

## Compilation

To compile the program, navigate to the source directory and run make:



```bash
cd /QAT/quickassist/lookaside/access_layer/src/sample_code/functional/asym/secp256k1/
make clean
make
```

This will create the executable `secp256k1` in the current directory.

## Preparing the Address Database

The program requires a CSV file containing high-value Bitcoin addresses to check against. The file should have the following format:

```
address,pubkey,balance
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa,04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f,10.0
```

By default, the program looks for this file at `/home/damien/Python/Bitcoin/blocks/master_high_value_addresses.csv`. You can specify a different path using command-line options.

## Usage

### Basic Usage

```bash
./secp256k1
```

This will run the program with default settings:
- Random key generation
- Default batch size (1000)
- Auto-detect thread count based on available QAT instances
- No debug output
- Using `/home/damien/Python/Bitcoin/blocks/master_high_value_addresses.csv` as the address database

### Command-Line Options

```
Usage: ./cpa_eddsa_sample [options]
Options:
  -f, --file=PATH       Path to CSV file with high-value addresses
                         (default: /home/damien/Python/Bitcoin/blocks/master_high_value_addresses.csv)
  -b, --batch=SIZE      Batch size for key generation
                         (default: 1000)
  -s, --sequential      Generate keys sequentially instead of randomly
  -d, --debug           Enable debug mode to print one key pair per batch
  -t, --threads=NUM     Number of threads to use (default: auto)
  -h, --help            Display this help and exit
```

### Examples

#### Run with Debug Mode

```bash
./secp256k1 --debug
```

This will print one key pair from each batch to help with troubleshooting and verification. The output will show the complete key values without truncation.

#### Use Sequential Key Generation

```bash
./secp256k1 --sequential
```

This will generate keys sequentially rather than randomly, which can be useful for systematic testing.

#### Specify Custom CSV File

```bash
./secp256k1 --file=/path/to/your/addresses.csv
```

Use a custom file containing high-value Bitcoin addresses.

#### Set Batch Size and Thread Count

```bash
./secp256k1 --batch=5000 --threads=4
```

Process keys in batches of 5000 using 4 threads.

### normal usage
./secp256k1 --max-keys 8000000 --threads=64 --batch=1000 --sequential

### key generation storage mode
./secp256k1-k -p /DATA_DISK_1/bitcoin_keys -i 0 -n 1000000 -t 64

### fill disk storage mode
./secp256k1 -k -n 0 -t 64


## Output

The program provides real-time progress information and statistics:

- Configuration summary at startup
- Progress bar showing completion percentage
- Current key generation rate (keys/second)
- Notification when a matching key is found
- Final statistics including:
  - Total keys checked
  - Number of matches found
  - Time taken
  - Average throughput
  - Estimated time to try all possible keys

## Termination

The program will run indefinitely until:

1. A matching key is found (if configured to stop on match)
2. You press Ctrl+C to gracefully terminate
3. An error occurs

## Performance Considerations

- Performance is highly dependent on the QAT hardware capabilities
- The number of threads should generally match the number of QAT instances
- Larger batch sizes typically improve performance but use more memory
- Binary search performance depends on the size of the address database

## Troubleshooting

If you encounter issues:

1. Enable debug mode (`--debug`) to see key pairs being generated
2. Check that the CSV file is properly formatted
3. Verify that QAT hardware is properly installed and configured
4. Ensure you have sufficient memory for the address database

## License

This software is provided under the BSD license. See the LICENSE file for details.