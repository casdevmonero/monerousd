# MoneroUSD

MoneroUSD is an independent payment network with its own block-DAG, a dollar-denominated asset called USDm, and a mining reward asset called SAT. The project operates a public testnet with free test coins. [Project website](https://monerousd.org/) · [Testnet guide](https://monerousd.org/testnet)

## Repository map

| Directory | What lives there |
| --- | --- |
| `monerousd-node-zkdag/` | Rust node, ledger, proof system and bundled web apps. |
| `monerousd-wallet-v2/` | Tauri desktop wallet, its web interface and wallet command harness. |
| `monerousd-goods/` | Rust library for signed merchant offers, purchase rules and delivery notices. |
| `monerousd-checkout/` | Python checkout helper, embedded pay panel, and Shopify and WooCommerce integrations. |
| `tools/` | The `musd` command-line tool and network measurement scripts. |

Run `python3 tools/musd help` to list the node, chain and wallet commands. Set `MUSD_HOME` to choose where the CLI stores its data. The default is `~/.musd`.

## First checks

Run these commands from the repository root. The first two use the Python 3 standard library. The checkout suite uses a local HTTP server, and the CLI test uses a temporary node directory. The Rust command tests the goods library and its fixtures using its committed dependency lockfile.

```sh
python3 tools/test_musd.py
python3 monerousd-checkout/helper/test_musd_checkout.py
cargo test --locked --manifest-path monerousd-goods/Cargo.toml
```

If you change custody vault seating or transitions, run the standalone model. It imports the node's seat rules and exercises deposits, withdrawals, merges, and member departures.

```sh
cargo test --locked --release --manifest-path monerousd-node-zkdag/models/custody-lifecycle/Cargo.toml
```

For changes to the desktop wallet or IonSwap front end, check their local asset references with `node scripts/audit-broken-paths.js`.

For desktop development, the build workflow lists the platform dependencies, builds the Rust node, and packages it with the wallet and web apps. [Wallet build workflow](.github/workflows/wallet-builds.yml)

The root license covers the project code, with separate terms for the IonSwap front end and notices for vendored components. [License](LICENSE) · [Third-party and IonSwap notices](NOTICE)
