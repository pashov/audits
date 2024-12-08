# About

Pashov Audit Group consists of multiple teams of some of the best smart contract security researchers in the space. Having a combined reported security vulnerabilities count of over 1000, the group strives to create the absolute very best audit journey possible - although 100% security can never be guaranteed, we do guarantee the best efforts of our experienced researchers for your blockchain protocol. Check our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# Introduction

A time-boxed security review of the **celestiaorg/optimism** repository was done by **Pashov Audit Group**, with a focus on the security aspects of the application's smart contracts implementation.

# About Pepe Unchained

Pepe Unchained Blockchain forks Optimism, an Ethereum layer-2 blockchain that enhances scalability and reduces transaction costs, making decentralized applications faster and more affordable. Paired with Celestia's modular data availability network, it empowers developers to launch scalable, customizable blockchains efficiently.

# Risk Classification

| Severity               | Impact: High | Impact: Medium | Impact: Low |
| ---------------------- | ------------ | -------------- | ----------- |
| **Likelihood: High**   | Critical     | High           | Medium      |
| **Likelihood: Medium** | High         | Medium         | Low         |
| **Likelihood: Low**    | Medium       | Low            | Low         |

## Impact

- High - leads to a significant material loss of assets in the protocol or significantly harms a group of users.

- Medium - leads to a moderate material loss of assets in the protocol or moderately harms a group of users.

- Low - leads to a minor material loss of assets in the protocol or harms a small group of users.

## Likelihood

- High - attack path is possible with reasonable assumptions that mimic on-chain conditions, and the cost of the attack is relatively low compared to the amount of funds that can be stolen or lost.

- Medium - only a conditionally incentivized attack vector, but still relatively likely.

- Low - has too many or too unlikely assumptions or requires a significant stake by the attacker with little or no incentive.

## Action required for severity levels

- Critical - Must fix as soon as possible (if already deployed)

- High - Must fix (before deployment if not already deployed)

- Medium - Should fix

- Low - Could fix

# Security Assessment Summary

_review commit hash_ - [8c535c615fea063b85257335128e97b73589b9fa](https://github.com/celestiaorg/optimism/tree/8c535c615fea063b85257335128e97b73589b9fa)

### Scope

The following repositories were in scope of the audit:

- https://github.com/celestiaorg/optimism/releases/tag/v1.3.0-OP_v1.9.2-CN_v0.15.0
- https://github.com/Uniswap/v3-core/tree/d8b1c635c275d2a9450bd6a78f3fa2484fef73eb
- https://github.com/Uniswap/v3-periphery/tree/0682387198a24c7cd63566a2c58398533860a5d1

# Findings

# [L-01] Missing validation for daConfig when creating new op-node

When creating a new op-node, all the configuration is validated except for the `daConfig`.

```go
// Check verifies that the given configuration makes sense
func (cfg *Config) Check() error {
	...
	if err := cfg.AltDA.Check(); err != nil {
		return fmt.Errorf("altDA config error: %w", err)
	}
	if cfg.AltDA.Enabled {
		log.Warn("Alt-DA Mode is a Beta feature of the MIT licensed OP Stack.  While it has received initial review from core contributors, it is still undergoing testing, and may have bugs or other issues.")
	}
	if err := cfg.DaConfig.Check(); err != nil { // @audit no validate config
		return fmt.Errorf("da config error: %w", err)
	}
	return nil
}
```

The `Check()` function for daConfig is empty:

```go
func (c CLIConfig) Check() error {
	return nil
}
```

It's recommended to validate the config such as `RpcURL` or `FallbackMode` in the `daConfig` struct.

# [L-02] Redundancy when AltDA is enabled in op-batcher driver.sendTransaction

When AltDA is enabled in `op-batcher/batcher/driver.go`, the current flow of sendTransaction is as follows: the original transaction data is sent to the AltDA server, which returns a commitment. This commitment is then sent to Celestia.

```go
		if l.Config.UseAltDA {
			comm, err := l.AltDA.SetInput(ctx, data)
			if err != nil {
				l.Log.Error("Failed to post input to Alt DA", "error", err)
				// requeue frame if we fail to post to the DA Provider so it can be retried
				l.recordFailedTx(txdata.ID(), err)
				return nil
			}
			l.Log.Info("Set AltDA input", "commitment", comm, "tx", txdata.ID())
			// signal AltDA commitment tx with TxDataVersion1
			data = comm.TxData()
		}
		candidate, err = l.celestiaTxCandidate(data)
		if err != nil {
			l.Log.Error("celestia: blob submission failed", "err", err)
			candidate, err = l.fallbackTxCandidate(ctx, txdata)
			if err != nil {
				l.Log.Error("celestia: fallback failed", "err", err)
				l.recordFailedTx(txdata.ID(), err)
				return nil
			}
		}

```

We have two scenarios:

`Double commitment storage case`: When AltDA is used and the AltDA commitment submission to Celestia succeeds, the commitment (not the transaction data) is stored in Celestia. This creates redundancy as the commitment is stored in both AltDA and Celestia. So when the roll-up node tries to reconstruct the L2 blocks from the L1 data, because the first byte is `0xce`, it would retrieve the data from Celestia (not AltDA). However, this data is the AltDA commitment rather than the actual transaction data.
[link](https://github.com/celestiaorg/optimism/blob/04a1755dcfff1397bfc7b55a0960434cd170a5bc/op-node/rollup/derive/calldata_source.go#L106-L139)

`AltDA Bypass case`: If the Celestia submission fails while attempting to store the AltDA commitment, then L2 transaction data is sent to L1 instead of AltDa commitment even though the AltDa works correctly. This means AltDa is completely bypassed.

It's recommended to store only in AltDA when it's enabled, without redundant Celestia storage.
