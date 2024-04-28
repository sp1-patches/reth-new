# Examples

These examples demonstrate the main features of some of Reth's crates and how to use them.

To run an example, use the command `cargo run -p <example>`.

If you've got an example you'd like to see here, please feel free to open an
issue. Otherwise if you've got an example you'd like to add, please feel free
to make a PR!

## Node Builder

| Example                                                       | Description                                                                                      |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| [Additional RPC namespace](./additional-rpc-namespace-in-cli) | Illustrates how to add custom CLI parameters and set up a custom RPC namespace                   |
| [Custom event hooks](./cli-extension-event-hooks)             | Illustrates how to hook to various node lifecycle events                                         |
| [Custom dev node](./custom-dev-node)                          | Illustrates how to run a custom dev node programmatically and submit a transaction to it via RPC |
| [Custom EVM](./custom-evm)                                    | Illustrates how to implement a node with a custom EVM                                            |
| [Custom inspector](./custom-inspector)                        | Illustrates how to use a custom EVM inspector to trace new transactions                          |
| [Custom node](./custom-node)                                  | Illustrates how to create a node with custom engine types                                        |
| [Custom node components](./custom-node-components)            | Illustrates how to configure custom node components                                              |
| [Custom payload builder](./custom-payload-builder)            | Illustrates how to use a custom payload builder                                                  |

## ExEx

| Example                            | Description                                                                       |
| ---------------------------------- | --------------------------------------------------------------------------------- |
| [Minimal ExEx](./exex/minimal)     | Illustrates how to build a simple ExEx                                            |
| [OP Bridge ExEx](./exex/op-bridge) | Illustrates an ExEx that decodes Optimism deposit and withdrawal receipts from L1 |

## RPC

| Example                 | Description                                                                 |
| ----------------------- | --------------------------------------------------------------------------- |
| [DB over RPC](./rpc-db) | Illustrates how to run a standalone RPC server over a Rethdatabase instance |

## Database

| Example                     | Description                                                     |
| --------------------------- | --------------------------------------------------------------- |
| [DB access](./db-access.rs) | Illustrates how to access Reth's database in a separate process |

## Network

| Example                            | Description                                                  |
| ---------------------------------- | ------------------------------------------------------------ |
| [Standalone network](./network.rs) | Illustrates how to use the network as a standalone component |

## Mempool

| Example                                               | Description                                                                                                                |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| [Trace pending transactions](./trace-transaction-cli) | Illustrates how to trace pending transactions as they arrive in the mempool                                                |
| [Standalone txpool](./network-txpool.rs)              | Illustrates how to use the network as a standalone component together with a transaction pool with a custom pool validator |

## P2P

| Example                     | Description                                                       |
| --------------------------- | ----------------------------------------------------------------- |
| [Manual P2P](./manual-p2p)  | Illustrates how to connect and communicate with a peer            |
| [Polygon P2P](./manual-p2p) | Illustrates how to connect and communicate with a peer on Polygon |

## Misc

| Example                            | Description                                                 |
| ---------------------------------- | ----------------------------------------------------------- |
| [Beacon API SSE](./beacon-api-sse) | Illustrates how to subscribe to beacon chain events via SSE |
