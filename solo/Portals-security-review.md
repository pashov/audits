# Introduction

A time-boxed security review of the **Portals** protocol was done by **pashov**, with a focus on the security aspects of the application's implementation.

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where I try to find as many vulnerabilities as possible. I can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# About **pashov**

Krum Pashov, or **pashov**, is an independent smart contract security researcher. Having found numerous security vulnerabilities in various protocols, he does his best to contribute to the blockchain ecosystem and its protocols by putting time and effort into security research & reviews. Reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum)

# About **Portals**

Portals is a platform that aggregates multiple calls allowing for best-route swap, stake, LP etc mechanisms. It optimizes for highest USD output + least gas consumption. A user requests a quote from the Portals API by choosing input & output tokens, input amount and sender/recipient. A Smart Order Routing algorithm is used to find the best path for the swap or action. Example use case is adding liquidity to a Curve pool (swapping to the underlying token and calling `add_liquidity`) or executing a folding strategy (borrow, swap, borrow etc). The protocol has a slippage tolerance mechanism implemented.

[More docs](https://docs.portals.fi/)

## Observations

`PortalsRouter` is the contract handling all approvals/allowances. The contracts make heavy usage of signed approvals & ERC20's permits.

The protocol does revenue sharing, where 50% of the fees go to the `partner` or the front-end from which the on-chain orders come from. The `partner` is only logged in an event and then the revenue sharing is executed off-chain, which is not trustless.

The protocol is non-custodial, meaning it doesn't hold funds in between any transaction calls. Only time it holds funds/fees is intra-transaction. This drastically narrows down the attack surface.

The `PortalsMulticall` contract allows for arbitrary code execution by anyone.

## Privileged Roles & Actors

- Router owner - can pause/unpause the `PortalsRouter` contract, set the `Multicall` contract address and also receives recovered stuck tokens in the router
- Multicall fees receiver - set by the back end off-chain (added in the `calls` array in `aggregate`), receives some fee
- Portal broadcaster - executes `SignedOrder`s by calling `PortalsRouter`
- Portal user - executes `Order`s by calling `PortalsRouter`, gives `PortalsRouter` spending allowance

# Severity classification

| Severity               | Impact: High | Impact: Medium | Impact: Low |
| ---------------------- | ------------ | -------------- | ----------- |
| **Likelihood: High**   | Critical     | High           | Medium      |
| **Likelihood: Medium** | High         | Medium         | Low         |
| **Likelihood: Low**    | Medium       | Low            | Low         |

**Impact** - the technical, economic and reputation damage of a successful attack

**Likelihood** - the chance that a particular vulnerability gets discovered and exploited

**Severity** - the overall criticality of the risk

# Security Assessment Summary

**_review commit hash_ - [d8be537304c8cd0bd3433b3aca5770d9375fc2ce](https://github.com/portals-fi/portals-sc/tree/d8be537304c8cd0bd3433b3aca5770d9375fc2ce)**

**_fixes review commit hash_ - [c1c223697b1a796623162148e1fd821e109c4107](https://github.com/portals-fi/portals-sc/tree/c1c223697b1a796623162148e1fd821e109c4107)**

### Scope

The following smart contracts were in scope of the audit:

- `portals/multicall/interface/**`
- `portals/multicall/PortalsMulticall`
- `portals/router/interface/**`
- `portals/router/RouterBase`
- `portals/router/PortalsRouter`

The following number of issues were found, categorized by their severity:

- Critical & High: 0 issues
- Medium: 0 issues
- Low: 3 issues

---

# Findings Summary

| ID     | Title                                           | Severity |
| ------ | ----------------------------------------------- | -------- |
| [L-01] | Fees recipient can arbitrage slippage tolerance | Low      |
| [L-02] | The `chainId` is cached but might change        | Low      |
| [L-03] | The protocol is using a vulnerable library      | Low      |

# Detailed Findings

# [L-01] Fees recipient can arbitrage slippage tolerance

The `calls` array in `PortalsMulticall::aggregate` are always expected to include a fee payment transaction, where fees from the swaps would be transferred to a protocol-controlled account. Also it is sometimes expected that a "sweep ETH" call is included in the end of the array, so that all leftover ETH is swept back to the original caller. The problem is that in this specific scenario, when the fees are sent before the sweep, the fees recipient can reenter the contract by calling `transferEth` and transfer just enough ETH that the caller balance would still be at the slippage tolerance level.

This attack requires multiple conditions (Low likelihood) and is also limited to up to slippage tolerance values (Low to Medium impact), hence the Low severity, but it is still a possible attack vector. One possible solution is to add the `nonReentrant` modifier to the `transferEth` function, but this will disallow calling it as part of the `aggregate` calls.

## Discussion

**pashov:** Acknowledged.

# [L-02] The `chainId` is cached but might change

Caching the `chainId` value (`RouterBase`'s constructor) is not a good practice as hard forks might change the chainId for a network. The better solution is to always check if the current `block.chainid` is the same as the cached one and if not, to update it. Follow the approach in [OpenZeppelin's EIP712 implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/2271e2c58d007894c5fe23c4f03a95f645ac9175/contracts/utils/cryptography/EIP712.sol#L81-L87) or just inherit from the OpenZeppelin's EIP712 contract.

## Discussion

**pashov:** Fixed.

# [L-03] The protocol is using a vulnerable library

The 4.8.0 version of the OpenZeppelin library has security vulnerabilities that are listed [here](https://github.com/OpenZeppelin/openzeppelin-contracts/security). While currently the vulnerable code is not used in the codebase, the library should be updated to contain the latest security patches.

## Discussion

**pashov:** Fixed.
