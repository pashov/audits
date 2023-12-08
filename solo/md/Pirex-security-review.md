# About

Krum Pashov, or **pashov**, is an independent smart contract security researcher. Having found numerous security vulnerabilities in various protocols, he does his best to contribute to the blockchain ecosystem and its protocols by putting time and effort into security research & reviews. Check his previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where I try to find as many vulnerabilities as possible. I can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# Introduction

A time-boxed security review of the **Pirex** protocol was done by **pashov**, with a focus on the security aspects of the application's smart contracts implementation.

# About Pirex

Pirex allows ETH holders to receive staking rewards through pooling. Staking through Pirex you benefit through block validation/attestation & MEV yield and compounding rewards through `pxETH`. The `pxETH` token is the Pirex-wrapped version of ETH, where its holders can earn yield by staking in `AutoPxETH` or just redeem their tokens for ETH.

[More docs](https://github.com/redacted-cartel/pirex-eth-contracts/blob/master/README.md)

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

**_review commit hash_ - [12b25265e17d141faf1c10fa84d9826838107e67](https://github.com/redacted-cartel/dinero-pirex-eth/tree/12b25265e17d141faf1c10fa84d9826838107e67)**

**_fixes review commit hash_ - [277ca47a598694a51261beac86dc21ec4937a699](https://github.com/redacted-cartel/dinero-pirex-eth/tree/277ca47a598694a51261beac86dc21ec4937a699)**

# Findings

# [M-01] The `emergencyWithdraw` method can leave `PirexEth` in a broken state

## Severity

**Impact:**
High, as the logic in `PirexEth` will be broken

**Likelihood:**
Low, as it requires an emergency and using the contract after it

## Description

The `emergencyWithdraw` method in `PirexEth` allows for withdrawal of ETH. This ETH could have been the `pendingDeposit` balance, which is not yet deposited to the ETH 2.0 deposit contract, and if it is withdrawn from the `emergencyWithdraw` method then the contract will be in a broken state. The `pendingDeposit` variable will have a value that is more than the ETH balance in the contract which will make deposit transactions revert if they are used post `emergencyWithdraw` call.

## Recommendations

Change the `emergencyWithdraw` method so that it can withdraw only excessive balance without the `pendingDeposit` one, or when using `pendingDeposit` force it to withdraw the whole balance and zero out the state variable.

# [L-01] Updating `withdrawalCredentials` is flawed

The `setContract` method in `PirexEthValidators` updates the `withdrawalCredentials` state variable when the `RewardRecipient` contract address is updated. If there already are validators in the `_initializedValidators` array, they would have been configured with different `withdrawalCredentials`. This is not an issue, as if a validator has deposited even 1 ETH, when depositing more the `withdrawalCredentials` argument is not used in the deposit contract, but ignored. Still, for extra safety and logical correctness, make sure to only allow updating `withdrawalCredentials` when there are no elements in the `_initializedValidators` array.

# [L-02] Penalty calculation in `previewRedeem` rounds in the wrong direction

The `previewRedeem` method in `AutoPxEth` calculates the penalty with the following code:

```solidity
uint256 penalty = (_totalSupply == 0 || _totalSupply - shares == 0)
    ? 0
    : assets.mulDivDown(withdrawalPenalty, FEE_DENOMINATOR);
```

The issue is that the math rounds down the penalty, but following the ERC4626 standard you should follow best security for the vault and when calculating the assets a user will receive when burning shares, the assets amount should be rounded down, where here since the penalty is rounded down, but penalty is subtracted from the `assets`, now the opposite effect happens. Make sure to use `mulDivUp` instead `mulDivDown` in the `penalty` calculation.

# [L-03] Upper bound setter checks missing

In `PirexEth` the `setMaxFee` method is missing an upper bound. Setting the max fee to be more than 100% allows setting the fee to be more than 100% as well, which shouldn't be possible. Add a max upper bound for the `setMaxFee` method, for example 50%.

Same issue with the `setMaxProcessedValidatorCount` method in `PirexEthValidators`, where putting a very high value can lead to a DoS of deposits. Add a max value for the `_count` argument, for example 20.

# [L-04] Setting allowances to 0 should be a valid operation

The `operatorApprove` method of `PxEth` currently reverts when the allowance amount is 0 which is a logical error - removing allowance (or setting it to 0) should be a valid operation. Remove the following line from `operatorApprove`:

```solidity
if (_amount == 0) revert Errors.ZeroAmount();
```
