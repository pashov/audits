# About

**Pashov Audit Group** consists of multiple teams of some of the best smart contract security researchers in the space. Having a combined reported security vulnerabilities count of over 1000, the group strives to create the absolute very best audit journey possible - although 100% security can never be guaranteed, we do guarantee the best efforts of our experienced researchers for your blockchain protocol. Check our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# Introduction

A time-boxed security review of the **ethena** repository was done by **Pashov Audit Group**, with a focus on the security aspects of the application's smart contracts implementation.

# About Ethena

StakingRewardsDistributor is the contract from Ethena Finance - a synthetic dollar protocol built on Ethereum. The contract is a piece of the new staking rewards distribution system and the intermediary between the Off-chain service and the actual staking contract.

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

**_review commit hash_ - [974992cbde8c5305578ba4edad357e64c25e14da](https://github.com/ethena-labs/ethena/tree/974992cbde8c5305578ba4edad357e64c25e14da)**

**_fixes review commit hash_ - [995dcfed3424e628be9de763a562503594c08c51](https://github.com/ethena-labs/ethena/tree/995dcfed3424e628be9de763a562503594c08c51)**

### Scope

The following smart contracts were in scope of the audit:

- `StakingRewardsDistributor`

# Findings

# [L-01] Renounce approvals from the previous mintContract

`StakingRewardsDistributor` gives approvals for a list of `_assets` to `mint_contract`. `setMintingContract()` can set the new `mint_contract`.
But previous asset approvals given to the previous `mintContract` are not revoked.

Consider implementing a function to renounce approvals from addresses.
