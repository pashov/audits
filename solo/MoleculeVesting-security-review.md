# Introduction

A time-boxed security review of the **Molecule Vesting** protocol was done by **pashov**, with a focus on the security aspects of the application's implementation.

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where I try to find as many vulnerabilities as possible. I can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# About **pashov**

Krum Pashov, or **pashov**, is an independent smart contract security researcher. Having found numerous security vulnerabilities in various protocols, he does his best to contribute to the blockchain ecosystem and its protocols by putting time and effort into security research & reviews. Reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum)

# About **Molecule Vesting**

The protocol represents an on-chain vesting scheme. It uses a typical vesting scheme that includes a cliff and vesting period. Multiple vesting schedules per user are allowed, while non-vested token amounts are revokable by a centralized entity (the contracts' owner). The vesting schedules are represented by a non-transferable ERC20 balance for users, which can also be utilized for governance purposes.

More docs [here](https://github.com/moleculeprotocol/token-vesting-contract/blob/main/README.md).

## Observations

Only 18 decimal tokens are allowed.

The contract uses a `nonReentrant` modifier for many of its methods so it is protected against ERC777-type reentrancy attacks.

The contract does not use `transferFrom` to receive tokens to vest, but expects tokens will be directly transferred to it.

When admin revokes a vesting schedule, all of the already vested tokens are transferred to the user.

# Threat Model

## Privileged Roles & Actors

- Contract Owner - can create vesting schedules, revoke them, pause the contract, withdraw excessive balance and also release vested tokens to users
- Vesting user - can claim his vested tokens from the contract

## Security Interview

**Q:** What in the protocol has value in the market?

**A:** The contract's balance in terms of the tokens that will be vested.

**Q:** In what case can the protocol/users lose money?

**A:** If the vesting calculations are incorrect or if the contract gets into a state of DoS.

**Q:** What are some ways that an attacker achieves his goals?

**A:** By making other user's claim transactions always revert or by exploiting a calculations error in the vested tokens math.

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

**_review commit hash_ - [88c1cda0e77d881fffb8a9deab1f65585503d504](https://github.com/moleculeprotocol/token-vesting-contract/tree/88c1cda0e77d881fffb8a9deab1f65585503d504)**

### Scope

The following smart contracts were in scope of the audit:

- `TokenVesting`
- `TokenVestingMerkle`

The following number of issues were found, categorized by their severity:

- Critical & High: 0 issues
- Medium: 4 issues
- Low: 2 issues

---

# Findings Summary

| ID     | Title                                                                                                                | Severity |
| ------ | -------------------------------------------------------------------------------------------------------------------- | -------- |
| [M-01] | The `revoke` mechanics are not compatible with tokens that implement a block list feature                            | Medium   |
| [M-02] | Insufficient input validation in function `createVestingSchedule`                                                    | Medium   |
| [M-03] | Contract can receive ETH but has no withdraw function for it                                                         | Medium   |
| [M-04] | Users won't be able to claim vested tokens when contract is paused                                                   | Medium   |
| [L-01] | Limit the max size of the `vestingSchedulesIds` array and `holdersVestingScheduleCount`                              | Low      |
| [L-02] | The `onlyIfVestingScheduleNotRevoked` modifier will not revert even if the given `vestingScheduleId` is non-existent | Low      |

# Detailed Findings

# [M-01] The `revoke` mechanics are not compatible with tokens that implement a block list feature

## Severity

**Impact:**
High, as important functionality in the protocol won't work

**Likelihood:**
Low, as a special type of ERC20 token has to be used as well as the attacker's address has to be in a block list

## Description

Some tokens, for example `USDC` and `USDT` implement an admin controlled address block list. All transfer to a blocked address will revert. Since the `revoke` functionality forcefully transfers the claimable vested tokens to an address with a `vestingSchedule`, all calls to `revoke` will revert if such an address has claimable balance and is in the token's block list.

## Recommendations

Use the [Pull over Push](https://fravoll.github.io/solidity-patterns/pull_over_push.html) pattern to send tokens out of the contract in a `revoke` scenario.

## Discussion

**pashov:** Acknowledged, as the team listed in the protocol docs that such tokens won't be supported.

# [M-02] Insufficient input validation in function `createVestingSchedule`

## Severity

**Impact:**
High, as it can lead to users never vesting their tokens

**Likelihood:**
Low, as it requires a malicious/compromised admin or an error on his side

## Description

The input arguments of the `createVestingSchedule` function are not sufficiently validated. Here are some problematic scenarios:

1. `_start` can be a timestamp that has already passed or is too far away in the future
2. `_cliff` can be too big, users won't be able to claim
3. 1 is a valid value for `duration`, the `!= 0` check is insufficient
4. If `_slicePeriodSeconds` is too big then the math in `_computeReleasableAmount` will have rounding errors

## Recommendations

Add sensible lower and upper bounds for all arguments of the `createVestingSchedule` method.

## Discussion

**pashov:** Fixed.

# [M-03] Contract can receive ETH but has no withdraw function for it

## Severity

**Impact:**
High, as value can be stuck forever

**Likelihood:**
Low, as it should be an error that someone sends ETH to the contract

## Description

The `TokenVesting` contract has `receive` and `fallback` functions that are `payable`. If someone sends a transaction with `msg.value != 0` then the ETH will be stuck in the contract forever without a way for anyone to withdraw it.

## Recommendations

Remove the `receive` and `fallback` functions since the ETH balance is not used in the contract anyway.

## Discussion

**pashov:** Fixed.

# [M-04] Users won't be able to claim vested tokens when contract is paused

## Severity

**Impact:**
High, as owner has the power to make it so that users can't claim any vested tokens

**Likelihood:**
Low, as it requires a malicious or a compromised owner

## Description

The owner can currently execute the following attack:

1. Call `setPaused` with `paused == true`, so pause the contract
2. Now all user calls to `releaseAvailableTokensForHolder` will fail, since it has the `whenNotPaused` modifier
3. He can not unpause the contract forever or even renounce ownership

This is a common centralization problem which means the contract owner can "rug" users.

## Recommendations

Remove the `whenNotPaused` modifier from `releaseAvailableTokensForHolder`, so users can claim vested tokens even if admin pauses the contract.

## Discussion

**pashov:** Fixed.

# [L-01] Limit the max size of the `vestingSchedulesIds` array and `holdersVestingScheduleCount`

If too many vesting schedules are added for a user it is possible that the `getVestingSchedulesIds` method will take too much gas and won't be executable (if it gets over the block gas limit, for example). Also in `releaseAvailableTokensForHolder` there is a `for` loop that loops `vestingScheduleCount` number of times, which can also be problematic, as it can lead to a DoS state with the function. Limit the max size of both, for example up to 500 vesting schedules created from the contract.

## Discussion

**pashov:** Fixed.

# [L-02] The `onlyIfVestingScheduleNotRevoked` modifier will not revert even if the given `vestingScheduleId` is non-existent

The modifier will pass successfully when the `vestingScheduleId` passed is of a non-existent vesting schedule, because the default `Status` of a vesting schedule is `INITIALIZED` anyway. Validate that the `vestingSchedules` exists, by checking that `vestingSchedules[vestingScheduleId].duration != 0`.

## Discussion

**pashov:** Fixed.
