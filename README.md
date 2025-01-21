<p align="center">
  <img src="https://raw.githubusercontent.com/pluto/.github/main/profile/assets/assets_ios_Pluto-1024%401x.png" alt="Pluto Logo" width="50" height="50">
  <span style="font-size: 28px; vertical-align: 10px; margin: 0 10px;">❤️</span>
  <img src="https://raw.githubusercontent.com/noir-lang/noir/a1cf830b3cdf17a9265b8bdbf366d65c253f0ca4/noir-logo.png" alt="The Noir Programming Language" width="50">
</p>

---

# Noir Web Prover Circuits

A collection of zero-knowledge circuits written in Noir for creating Web Proofs. These circuits enable secure authentication, HTTP request verification, and JSON data extraction in zero-knowledge applications.

## Features

- **Encryption/Plaintext Authentication Circuit**: Verify encrypted data and authenticate plaintext without revealing sensitive information
- **HTTP Parser and Header Locker**: Parse and lock HTTP headers in zero-knowledge proofs, ensuring request integrity
- **JSON Parser/Extractor**: Extract and verify specific fields from JSON data within zero-knowledge proofs
- **Constraint Counter**: Utility to analyze R1CS constraint counts for circuit optimization

## Getting Started

These instructions will help you get the circuits up and running on your local machine.

### Prerequisites

You'll need to have Rust and Cargo installed on your system. Then, install the `just` command runner:

```bash
cargo install just
```

### Installation

1. Clone the repository
   ```bash
   git clone https://github.com/pluto/noir-web-prover-circuits.git
   cd noir-web-prover-circuits
   ```

2. Set up the development environment
   ```bash
   # This will install Noirup, Nargo, and required tools
   just setup
   ```

3. Build the workspace
   ```bash
   just build
   ```

### Available Commands

- `just`: List all available commands
- `just setup`: Set up complete development environment
- `just build`: Build the entire Nargo workspace
- `just test`: Run all tests
- `just fmt`: Format code (Noir and TOML)
- `just ci`: Run all CI checks

## Usage

### Using the Constraint Counter

After running `just setup` you will also get access to the `constraint_counter` utility helps analyze the R1CS constraints in your circuits:

```bash
constraint_counter --circuit <circuit_name> --public-io-length <#_of_pub_inputs> --private-input-length <#_of_priv_inputs>
```

## Contributing

We welcome contributions to our open-source projects. If you want to contribute or follow along with contributor discussions, join our main [Telegram channel](https://t.me/pluto_xyz/1) to chat about Pluto's development.

Our contributor guidelines can be found in our [CONTRIBUTING.md](https://github.com/pluto/.github/blob/main/profile/CONTRIBUTING.md).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.

## License

This project is licensed under the Apache V2 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The [Noir Programming Language](https://noir-lang.org/) team for their ZK circuit development framework