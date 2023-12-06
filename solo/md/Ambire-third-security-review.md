# About

Krum Pashov, or **pashov**, is an independent smart contract security researcher. Having found numerous security vulnerabilities in various protocols, he does his best to contribute to the blockchain ecosystem and its protocols by putting time and effort into security research & reviews. Check his previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where I try to find as many vulnerabilities as possible. I can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# Introduction

A time-boxed security review of the **Pashov** protocol was done by **pashov**, with a focus on the security aspects of the application's smart contracts implementation.

# About Ambire

**Copied from the previous security reviews**

Ambire is a smart wallet protocol. Users have wallets (accounts) which are controlled by them or other addresses that have "privileges" to do so. A user can do an off-chain signature of a bundle of transactions and anyone can execute it on-chain. Different signature schemes are allowed, for example EIP712, Schnorr, Multisig and others. The protocol works in a counterfactual manner, meaning a user wallet gets deployed only on its first transaction. The actual deployment is an EIP1167 minimal proxy for the wallet smart contract.

The `Ambire` protocol extended its signature validator options by adding an "external signature validator" option. One such option is the `DKIMRecoverySigValidator`, which is basically a way to recover access to your smart wallet by using your email. In the case that you have access & control over your secondary key and your email but you lost your primary key, you can instantly recover access to your account. If you have lost access/control over either of them you can still queue a recovery but you'd have to wait for a timelock to pass.

**Continued**

Ambire added ERC4337 support in their `AmbireAccount` contract with the `validateUserOp` functionality. Its implementation has a special caveat allowing an account to easily enable 4337 on it. There is also the new `AmbirePaymaster` contract which will allow users to delegate the gas costs for their transactions to it.

[ERC4337 standard](https://eips.ethereum.org/EIPS/eip-4337)

## Observations

The protocol has a special ERC4337 implementation that allows the `AmbireAccount` contract to not use the `UserOperation` signature field when it is about to call `executeMultiple` on the account.

The `AmbirePaymaster` contract omits functionality for staking to the ERC4337 system since it is not reading/writing from/to storage and doesn't have a `postOp` implementation.

## Privileged Roles & Actors

- Paymaster - makes possible to cover user transaction gas costs

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

**_review commit hash_ - [da3ba641a004d1f0143a20ddde48049b619431ad](https://github.com/AmbireTech/ambire-common/tree/da3ba641a004d1f0143a20ddde48049b619431ad)**

**_fixes review commit hash_ - [62ba7dc8eaca4c1a1f66a777aecc475735449ef3](https://github.com/AmbireTech/ambire-common/tree/62ba7dc8eaca4c1a1f66a777aecc475735449ef3)**

# Findings

# [L-01] The DKIM logic to verify headers allows weird cases

The `_verifyHeaders` method in `DKIMRecoverySigValidator` now allows for the following two anomalies:

1. A valid set of headers that have extra text in between them, which is in between two `\r\n` expressions
2. Reordered `subject`, `to` and `from` headers are now allowed - previously the order - `from`, `to`, `subject` was expected

You can change the code to be a sequential state machine, basically enforcing an order of text in headers.

# [L-02] No `withdrawTo` functionality in `AmbirePaymaster`

The ERC4337 implementation on Ethereum has a `StakeMaster` contract with a `withdrawTo` functionality, allowing a paymaster to withdraw his deposit as seen [here](https://github.com/eth-infinitism/account-abstraction/blob/674b1f51164e641a18d5c141895bab9c96a68e9d/contracts/core/StakeManager.sol#L137-L148). The issue is that `AmbirePaymaster` doesn't implement a direct way to call this functionality but it does, however, have the arbitrary call functionality allowed for the `relayer` address. Through that functionality the `withdrawTo` method can be called, but the `call` method has the following comment in its NatSpec:

```solidity
* @notice  This method can be used to withdraw stuck tokens or airdrops
```

which means it wasn't expected to do so. If you plan on using `call` for other things as well, consider making it `payable` since it uses a `value` argument but the contract doesn't have a way to receive ETH.
