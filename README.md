# Twilight Client SDK

A comprehensive Rust SDK for interacting with the Twilight blockchain ecosystem. This SDK provides client-side functionality for managing transactions, interacting with Twilight relayers, and handling decentralized trading operations.

## 🚀 Features

### Core Functionality
- **Secure Key Management**: AES-128-CBC encrypted key storage with password protection
- **Private Transfers**: Zero-knowledge transaction creation and verification
- **UTXO Management**: Complete support for Coin, Memo, and State UTXOs
- **Account Operations**: Account management and transaction handling

### Trading & DeFi Features
- **Trading Orders**: Create, execute, and cancel trader orders with leverage support
- **Lending Operations**: Lending functionality for Twilight pool
- **Order Management**: Position tracking, margin calculations, and order status management
- **Market Data**: Real-time price feeds and Relayer integration

### Smart Contract System
- **Program Management**: Add, import, and export smart contract programs
- **Merkle Tree Verification**: Cryptographic proof generation for contract calls
- **Contract Addressing**: Script address generation and management
- **VM Integration**: ZkOS virtual machine interaction

### Privacy & Security
- **Zero-Knowledge Proofs**: Quisquis protocol integration for transaction privacy
- **Schnorr Signatures**: Advanced cryptographic signature schemes
- **Anonymous Transactions**: Complete transaction anonymity and unlinkability

### Advanced Features
- **Network Communication**: Robust RPC client implementation

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
twilight-client-sdk = { git = "https://github.com/twilight-project/twilight-client-sdk.git" }
```

## 🛠️ Setup

### Environment Configuration

Set the required environment variable:

```bash
export ZKOS_SERVER_URL="https://your-zkos-server.com"
```

### Database Setup

Run the migrations to set up the database schema:

```bash
# Ensure you have a PostgreSQL database configured
# Run migrations (requires diesel_cli)
diesel migration run
```

## 📖 Usage Examples

### Basic Key Operations

```rust
use twilight_client_sdk::*;

// Initialize a new key storage
let password = b"your_secure_password";
let iv = b"initialization_vec";
let seed = "your_wallet_seed_here";

let wallet = keys_management::init_wallet(
    password,
    "wallet.txt".to_string(),
    iv,
    Some(seed.to_string()),
)?;
```

### Creating Private Transfers

```rust
use twilight_client_sdk::transfer::*;

// Create a private transfer transaction
let tx_hex = create_private_transfer_tx_single(
    secret_key,
    sender_input,
    receiver_address,
    amount,
    true, // address_input flag
    updated_balance,
    fee,
);
```

### Trading Operations

```rust
use twilight_client_sdk::relayer::*;

// Create a trader order
let order_hex = create_trader_order_zkos(
    input_coin,
    output_memo,
    secret_key,
    rscalar_hex,
    value,
    account_id,
    position_type,
    order_type,
    leverage,
    initial_margin,
    available_margin,
    order_status,
    entry_price,
    execution_price,
)?;
```

### Blockchain Interaction

```rust
use twilight_client_sdk::chain::*;

// Get UTXOs for an address
let utxos = get_coin_utxo_by_address_hex(address_hex)?;

// Broadcast a transaction
let tx_hash = tx_commit_broadcast_transaction(transaction)?;
```

---

### 📝 More Examples

You can find runnable examples in the [`examples/`](./examples) directory.

#### Run the Basic Example

```bash
cargo run --example basic
```

## 🏗️ Architecture

### Core Modules

| Module | Purpose | Key Features |
|--------|---------|--------------|
| `keys_management` | Seed Security | Key generation, encryption, secure storage |
| `transfer` | Transactions | ZK transfers, burn messages, transaction verification |
| `relayer` | Trading | Order management, trading operations, market interaction |
| `chain` | Blockchain | RPC communication, UTXO queries, transaction broadcasting |
| `programcontroller` | Smart Contracts | Program management, call proofs, contract addresses |
| `script` | VM Operations | Script execution and virtual machine interaction |


### Supported Transaction Types

- **Private Transfers**: Zero-knowledge transfers between dark accounts
- **Burn Messages**: Transfer to Standard cosmos chain account with cryptographic proofs  
- **Script Transactions**: ZK Smart contract interactions
- **Trader Orders**: Leveraged trading with margin support
- **Lending Orders**: Twilight pool lending 

## 🔧 Configuration

### Required Environment Variables

```bash
# ZkOS server endpoint
export ZKOS_SERVER_URL="https://nykschain.twilight.rest/zkos/"

# Database configuration (if using database features)
export DATABASE_URL="postgresql://username:password@localhost/zkos_wallet"
```

### Smart Contract Programs

The wallet includes pre-configured programs for:

- Trading order creation and settlement
- Lending operations
- Order liquidation
- Margin management
- Relayer initialization

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test keys_management
cargo test transfer
cargo test relayer
```

## 📚 API Documentation

Generate and view the documentation:

```bash
cargo doc --open
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [Twilight Protocol App](https://frontend.twilight.rest)
- [Twilight Documentation](https://docs.twilight.org)
- [zkos-rust](https://github.com/twilight-project/zkos-rust) - Core ZkOS blockchain implementation
- [quisquis-rust](https://github.com/twilight-project/quisquis-rust) - Privacy protocol implementation
- [zk-schnorr](https://github.com/twilight-project/zk-schnorr) - Schnorr signature library

## Support

For support and questions:
- Open an issue on GitHub

## ⚠️ Security Notice

This wallet handles cryptographic keys and financial transactions. Always:
- Use secure passwords for wallet encryption
- Keep your seed phrases safe and private
- Test thoroughly before using in production
- Review code before handling mainnet funds

---

**Built with privacy and security in mind for the Twilight ecosystem** 🔒

 

install diesel cli in the repository

cargo install diesel_cli
 or 
cargo install diesel_cli --no-default-features --features postgres


This will create a new DB named order_book_staging as defined in the .env file

run the following command to setup the diesel 
diesel setup

The migrations are already set up

run following to create tables
diesel migration run  

to recheck
diesel migration redo 

