# Introduction

A time-boxed security review of the **Azuro** protocol was done by pashov, with a focus on the security aspects of the application's implementation.

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where I try to find as many vulnerabilities as possible. I can not guarantee 100% security after the review or if even the review will find any problems with your smart contracts.

# Protocol Overview

**Copied from the first security review**

Azuro is a decentralized betting protocol. Anyone can launch a frontend service that connects to the smart contracts and to receive an affiliate bonus for each bet made through the given frontend. Different betting events can be hosted, for example a football game. Odds are provided once by a Data Feed provider (Oracle) for initialization and then odds change based on the betting on the platform. A user bet gets automatically converted to an NFT in the user's wallet.

# Severity classification

| Severity               | Impact: High | Impact: Medium | Impact: Low |
| ---------------------- | ------------ | -------------- | ----------- |
| **Likelihood: High**   | Critical     | High           | Medium      |
| **Likelihood: Medium** | High         | Medium         | Low         |
| **Likelihood: Low**    | Medium       | Low            | Low         |

# Security Assessment Summary

**_review commit hash_ - [1c475b43e47798ae0a49716fe949b523a2663d0a](https://github.com/Azuro-protocol/Azuro-v2/tree/1c475b43e47798ae0a49716fe949b523a2663d0a)**

### Scope

The following smart contracts were in scope of the audit:

- `BetExpress`

The following number of issues were found, categorized by their severity:

- Critical & High: 1 issues
- Medium: 2 issues
- Low: 1 issues
- Informational: 8 issues

---

# Findings Summary

| ID     | Title                                                                              | Severity      |
| ------ | ---------------------------------------------------------------------------------- | ------------- |
| [C-01] | Value of `leaf` argument when calling `addReserve` is hardcoded incorrectly        | Critical      |
| [M-01] | The protection check for `maxBetShare` can be gamed                                | Medium        |
| [M-02] | Tokens with a no-op fallback function can be used to steal the ETH balance of `LP` | Medium        |
| [L-01] | Using 0 as an argument value is error-prone                                        | Low           |
| [I-01] | Off-by-one error on timestamp check                                                | Informational |
| [I-02] | The word "core" has multiple meanings in the protocol which raises complexity      | Informational |
| [I-03] | Redundant getter                                                                   | Informational |
| [I-04] | Missing event emission                                                             | Informational |
| [I-05] | Missing `override` keyword                                                         | Informational |
| [I-06] | Unused imports                                                                     | Informational |
| [I-07] | Incorrect comment                                                                  | Informational |
| [I-08] | Use a safe pragma statement                                                        | Informational |

# Detailed Findings

# [C-01] Value of `leaf` argument when calling `addReserve` is hardcoded incorrectly

## Severity

**Impact:**
High, because liquidity won't be returned to the LiquidityTree

**Likelihood:**
High, because the incorrect value is hardcoded and can't be changed

## Description

In `BetExpress::resolvePayout` we can see the following code:

```solidity
uint128 reward = lp.addReserve(
    0,
    fullPayout - amount,
    fullPayout - payout,
    0
    );
```

where the last argument is 0 sent as a value for the `leaf` parameter. Since the leafs counting begins at 1, this will always be wrong and the liquidity won't be returned to the LiquidityTree.

## Recommendation

The value of `leaf` should be the `leaf` value of each `condition` in the bet. The current design of `resolvePayout` does not allow to work on each `condition` in isolation, so this would need a redesign where you handle each `condition` separately.

# [M-01] The protection check for `maxBetShare` can be gamed

## Severity

**Impact:**
Medium, because a protocol invariant can be broken and the code gives a false sense of security

**Likelihood:**
Medium, as it can easily be gamed but there is no incentive for an attacker

## Description

The `lockLiquidity` method tries to block a single bet from taking up too much of the LP's allowed liquidity limit, but this can be gamed by splitting a very large bet into a big number of smaller ones, so this `LargeBet` custom error check would give a false sense of security as it doesn't guarantee what it intended to.

## Recommendations

Change the validation to be based on all bets made through `BetExpress` instead of on each bet in isolation.

# [M-02] Tokens with a no-op fallback function can be used to steal the ETH balance of `LP`

## Severity

**Impact:**
High, because it can lead to stolen funds from the protocol

**Likelihood:**
Low, as it requires a token with a fallback function but without a `withdraw` function

## Description

In `LP::withdrawPayout` we have the following code:

```solidty
if (isNative) {
    IWNative(token).withdraw(amount);
    TransferHelper.safeTransferETH(account, amount);
} else {
    TransferHelper.safeTransfer(token, account, amount);
}
```

Now imagine the following scenario:

1. The `token` used in the contract is one that does not have a `withdraw` function but has a fallback function
2. An attacker has a winning bet of 100 \* 1e18 tokens
3. Now he calls `withdrawPayout` but sets the `isNative` flag to `true`
4. The `IWNative(token).withdraw(amount);` will not revert but will be a no-op because of the fallback function of `token`
5. The attacker will receive 100 ETH instead of 100 \* 1e18 tokens

The attack is similar to [this one](https://medium.com/dedaub/phantom-functions-and-the-billion-dollar-no-op-c56f062ae49f) and even though it requires a special token and the `LP` to hold liquidity it is still a potential attack vector.

## Recommendations

You can implement team processes about adding specific `token` contracts to be used in `LP`, where you have a checklist that contains not including tokens with a fallback function that are missing a `withdraw` function. You can also check the balance of `LP` before and after the `withdraw` call so you see it changed accordingly.

# [L-01] Using 0 as an argument value is error-prone

It is a best practice to overload methods so they have signatures that omit the arguments where 0 is a valid value. Intentionally using 0 as a valid value is error-prone and has lead to high severity issues in multiple protocols in the past.

# [I-01] Off-by-one error on timestamp check

The code in `_conditionIsRunning` reverts when `block.timestamp >= startsAt` but if `block.timestamp == startsAt` this should mean condition is running, so shouldn't result in a revert.

```diff
- block.timestamp >= startsAt
+ block.timestamp > startsAt
```

# [I-02] The word "core" has multiple meanings in the protocol which raises complexity

The word "core" is used both as a contract name (`Core`, `CoreBase`) as well as a word that means something that is a part of the protocol, for example `BetExpress`. This is non-intuitive and raises the complexity of the protocol which is non-ideal - consider using different wording for both meanings of "core" in the codebase.

# [I-03] Redundant getter

`_baseURI` getter is redundant since there is already `baseURI` getter automatically generated.

# [I-04] Missing event emission

The `setBaseURI` method in `BetExpress.sol`does not emit an event which might not be good for off-chain monitoring. Emit an event on state change.

# [I-05] Missing `override` keyword

Methods `initialize` & `viewPayout` in `BetExpress.sol` are missing override keyword despite inheriting their function's signature from `ICoreBased.sol` & `IBet.sol` respectively.

# [I-06] Unused imports

`import "./libraries/Math.sol"` and `"@uniswap/lib/contracts/libraries/TransferHelper.sol"` are not used in `BetExpress.sol` and can be removed.

# [I-07] Incorrect comment

We have the following comment in `putBet` method in `BetExpress.sol`:

```solidity
@notice Liquidity Pool: See {IBetEngine-putBet}.
```

The right interface in this case is `IBet.sol` instead of `IBetEngine.sol`
Also in `putBet` method in `IBet.sol`, the `@return` field is missing. Consider adding one.

# [I-08] Use a safe pragma statement

Always use stable pragma statement to lock the compiler version. Also there are different versions of the compiler used throughout the codebase, use only one. Finally consider upgrading the version to a newer one to use bugfixes and optimizations in the compiler.
