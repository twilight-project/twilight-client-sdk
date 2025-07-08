# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-07-08

### Initial Public Release

This marks the first public release of the Twilight Client SDK, a comprehensive Rust library for interacting with the Twilight blockchain ecosystem.

### Added

#### Core Features
- **Secure Key Management**: AES-128-CBC encrypted key storage with password protection
- **Private Transfers**: Zero-knowledge transaction creation and verification using Quisquis protocol
- **UTXO Management**: Complete support for Coin, Memo, and State UTXOs
- **Account Operations**: Dark account management and transaction handling

#### Trading & DeFi Integration
- **Trading Orders**: Create, execute, and cancel trader orders with leverage support
- **Lending Operations**: Interface with Twilight lending pools
- **Order Management**: Position tracking, margin calculations, and order status management
- **Market Data**: Real-time price feeds and relayer integration

#### Smart Contract System
- **Program Management**: Add, import, and export smart contract programs
- **Merkle Tree Verification**: Cryptographic proof generation for contract calls
- **Contract Addressing**: Script address generation and management
- **VM Integration**: ZkOS virtual machine interaction

#### Privacy & Security
- **Zero-Knowledge Proofs**: Complete transaction anonymity and unlinkability
- **Schnorr Signatures**: Advanced cryptographic signature schemes using zk-schnorr
- **Anonymous Transactions**: Privacy-preserving transaction mechanisms

#### Development & Documentation
- **Comprehensive Examples**: Runnable examples in `/examples` directory
- **API Documentation**: Full Rust documentation with `cargo doc`
- **CI/CD Pipeline**: GitHub Actions workflow with testing, linting, and security audits
- **Contributing Guidelines**: Complete contribution guide and code of conduct
- **Security Policy**: Comprehensive security policy with vulnerability reporting

#### Core Modules
- `keys_management` - Seed security, key generation, encryption, secure storage
- `transfer` - ZK transfers, burn messages, transaction verification
- `relayer` - Trading operations, order management, market interaction
- `chain` - Blockchain RPC communication, UTXO queries, transaction broadcasting
- `programcontroller` - Smart contract program management and call proofs
- `script` - Script execution and virtual machine interaction
- `util` - Utility functions for cryptographic operations

### Security

#### Security Improvements
- **Removed Hardcoded Secrets**: Eliminated all hardcoded seeds, passwords, and test keys
- **Environment Variable Integration**: Secure configuration through environment variables
- **Test Data Cleanup**: Removed sensitive test files and artifacts
- **Git History Sanitization**: Complete removal of sensitive information from git history

#### Known Security Considerations
- ⚠️ **Not Audited**: This library has not been formally audited and is not recommended for production use
- **Testnet Use Only**: Intended for experimental and testnet use only
- **Dependency Vulnerability**: Uses curve25519-dalek v3.2.1 which has a timing vulnerability ([RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html))
  - Will be resolved in v0.2.0 by upgrading to curve25519-dalek v4.1.3+
  - Current version maintained for ecosystem compatibility

### Dependencies

#### Core Dependencies
- `curve25519-dalek` 3.2.1 - Elliptic curve cryptography
- `serde` 1.0 - Serialization framework
- `rand` 0.7 - Random number generation
- `reqwest` 0.11 - HTTP client for blockchain communication
- `aes` 0.7 - AES encryption for key storage
- `sha3` 0.9.1, `sha2` 0.10.7 - Cryptographic hashing
- `dotenvy` 0.15.7 - Environment variable management

#### Twilight Ecosystem Dependencies
- `zkvm` - ZkOS virtual machine (from twilight-project/zkos-rust)
- `transaction` - Transaction types and operations (from twilight-project/zkos-rust)
- `transactionapi` - Transaction API client (from twilight-project/zkos-rust)
- `address` - Address generation and management (from twilight-project/zkos-rust)
- `zkschnorr` - Schnorr signature implementation (from twilight-project/zk-schnorr)
- `quisquis-rust` - Privacy protocol implementation (from twilight-project/quisquis-rust)

### Changed

#### Repository Structure
- **Repository Name**: Renamed from `zkos-client-wallet` to `twilight-client-sdk`
- **Public Release**: Transitioned from private internal repository to public open-source project
- **Library Name**: Changed crate name to `twilight-client-sdk`
- **Clean Architecture**: Organized code structure for public consumption

#### Code Quality
- **Reduced Warnings**: Minimized compiler warnings
- **Code Formatting**: Applied consistent rustfmt formatting
- **Lint Compliance**: Addressed clippy warnings and suggestions
- **Documentation**: Added comprehensive inline documentation

#### Configuration
- **Environment-Driven**: Replaced hardcoded values with environment variable configuration
- **Secure Defaults**: Implemented secure configuration patterns

### Removed

#### Security Cleanup
- **Sensitive Files**: Removed wallet.txt, foo.txt, foo_response.txt, and other test artifacts
- **Hardcoded Credentials**: Eliminated all hardcoded seeds, passwords, and keys
- **Personal Information**: Removed personal paths and internal references
- **Test Data**: Cleaned up development and testing artifacts

#### Code Cleanup
- **Dead Code**: Removed unused imports and variables
- **Commented Code**: Eliminated unnecessary commented-out code blocks
- **Deprecated Features**: Temporarily disabled database module due to compatibility issues

### Technical Details

#### Supported Transaction Types
- Private and anonymous transfers between accounts
- Burn messages with cryptographic proofs
- Smart contract interactions
- Leveraged trading orders
- Lending pool operations

#### Environment Variables
```bash
ZKOS_SERVER_URL="https://nykschain.twilight.rest/zkos/"
DATABASE_URL="postgresql://username:password@localhost/zkos_wallet"
TEST_SEED="test_seed_for_unit_testing_only"
TEST_ADDRESS="0c0a2555a4de4e44e9f10e8d682b1e63f..."
```

#### Smart Contract Programs
Pre-configured programs for:
- Trading order creation and settlement
- Lending operations
- Order liquidation
- Margin management
- Relayer initialization

### Breaking Changes
- **API Changes**: Some function signatures may have changed during cleanup
- **Module Organization**: Code organization optimized for public use
- **Configuration**: Now requires environment variables for proper operation

---

## Version History

- **0.1.0** - Initial public release with comprehensive SDK features
- **Pre-0.1.0** - Internal development versions (zkos-client-wallet)

---

For more information about this release, see:
- [Contributing Guidelines](.github/CONTRIBUTING.md)
- [Security Policy](.github/SECURITY.md)
- [License](LICENSE)
- [Examples](examples/)

**⚠️ Remember**: This is experimental software for testnet use only. Do not use in production environments.
