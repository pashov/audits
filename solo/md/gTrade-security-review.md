# Introduction

A time-boxed security review of the **gTrade** protocol was done by **pashov**, with a focus on the security aspects of the application's smart contracts implementation.

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where I try to find as many vulnerabilities as possible. I can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# About **pashov**

Krum Pashov, or **pashov**, is an independent smart contract security researcher. Having found numerous security vulnerabilities in various protocols, he does his best to contribute to the blockchain ecosystem and its protocols by putting time and effort into security research & reviews. Check his previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).

# About **gTrade**

The `gTrade` protocol is a leveraged trading platform developed by Gains Network. It allows for up to 150x on crypto tokens, 1000x on forex and 250x on commodities. The architecture mainly revolves around the `GNS` ERC20 token and ERC721 utility tokens, both of which provide different utility when using the platform - reduced spread, governance and others.

The protocol added two new features:

- Staking, which allows users to stake `GNS` and receive `DAI` rewards from trading activity on the platform
- Compensation Handler, which is currently used to compensate holders of the utility ERC721 tokens, because they are getting deprecated

The Compensation Handler will also compensate the dev fund because the deprecated ERC721 tokens were a source of revenue to the fund up until now.

## Observations

Anyone holding the `MINTER_ROLE` can mint `GNS` tokens freely.

The dev fund compensation can be executed only on the Arbitrum network.

There is no lock on staking, users can stake and unstake in the same block.

The reward "distribution" happens on a per-trade (open, close, liquidation) basis. Because of this, distribution can't be timed as it can happen many times in a minute or zero times in hours.

## Privileged Roles & Actors

- `GNS`'s `MINTER_ROLE` - holder of the role can freely mint `GNS` tokens to any address, the `CompensationHandler` contract will have this role
- Unlock Manager - can create revocable unlock schedules
- Governance - the governance account address, can call `scheduleDevFundUnlock` to start the cliff vesting for dev fund compensation, create/revoke revocable unlock schedules and set `unlockManagers`
- User - can create non-revocable unlock schedules for himself

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

**_review commit hash_ - [5dfd04b320b6f14ccbabfe2b790987826422b545](https://github.com/GainsNetwork-org/gTrade-contracts/tree/5dfd04b320b6f14ccbabfe2b790987826422b545)**

**_fixes review commit hash_ - [cf0e7aae00542b479e34ed7a0fbc77c9b0c3084e](https://github.com/GainsNetwork-org/gTrade-contracts/tree/cf0e7aae00542b479e34ed7a0fbc77c9b0c3084e)**

### Scope

The following smart contracts were in scope of the audit:

- `GNSCompensationHandlerV6_4_1`
- `GNSStakingV6_4_1`

---

# Findings Summary

| ID     | Title                                          | Severity | Status |
| ------ | ---------------------------------------------- | -------- | ------ |
| [M-01] | Insufficient input validation                  | Medium   | Fixed  |
| [L-01] | Implementation contract can be initialized     | Low      | Fixed  |
| [L-02] | Use a two-step access control transfer pattern | Low      | Fixed  |

# Detailed Findings

# [M-01] Insufficient input validation

## Severity

**Impact:**
High, as it can lead to stuck funds

**Likelihood:**
Low, as it requires a bad user error

## Description

In `GNSStakingV6_4_1::createUnlockSchedule` we have the `UnlockScheduleInput calldata _input` parameter, where most of the fields in the struct are properly validated to be in range of valid values. The issue is that the `start` field of the `UnlockScheduleInput` is not sufficiently validated, as it can be too further away in the future - for example 50 years in the future, due to a user error when choosing the timestamp. This would result in (almost) permanent lock of the `GNS` funds sent to the method.

## Recommendations

Add a validation that the `start` field is not too further away in the future, for example it should be max 1 year in the future.

# [L-01] Implementation contract can be initialized

The `GNSStakingV6_4_1` is an implementation contract that is expected to be used through a proxy. Since implementation contracts shouldn't be used, it is a convention to disallow their initialization. Consider adding an empty constructor that calls `_disableInitializers()` in `GNSStakingV6_4_1`.

# [L-02] Use a two-step access control transfer pattern

The `GNSStakingV6_4_1::setGovFund` uses a single-step access control transfer pattern. This means that if the current `govFund` account calls `setGovFund` with an incorrect address, then this `govFund` role will be lost forever along with all the functionality that depends on it. Follow the pattern from OpenZeppelin's [Ownable2Step](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable2Step.sol) and implement a two-step transfer pattern for the action.
