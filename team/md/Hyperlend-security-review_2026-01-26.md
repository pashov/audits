
# About Pashov Audit Group


Pashov Audit Group consists of 40+ freelance security researchers, who are well proven in the space - most have earned over $100k in public contest rewards, are multi-time champions or have truly excelled in audits with us. We only work with proven and motivated talent.

With over 300 security audits completed — uncovering and helping patch thousands of vulnerabilities — the group strives to create the absolute very best audit journey possible. While 100% security is never possible to guarantee, we do guarantee you our team's best efforts for your project. 

Check out our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).
    

# Disclaimer


A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.


# Introduction

<p>A time-boxed security review of the <strong>hyperlendx/hpl-staking-contracts</strong> repository was done by Pashov Audit Group, during which <strong>BengalCatBalu, Ch_301, Hals</strong> engaged to review <strong>HPL Staking</strong>. A total of <strong>4</strong> issues were uncovered.</p>

# About HPL Staking

<p>HPL Staking is a smart contract that lets users deposit (stake) HPL tokens into the contract under an active lock option (including a default flexible, no-lock option), tracking each user’s stakes by index and enforcing a minimum stake amount. Users can later withdraw their stake once unlocked, or withdraw early by opting into a penalty fee that is sent to a fee recipient.</p>

# Security Assessment Summary

**Review commit hash:**<br>• [e8baa1fa367aaf1833cad4c9d4cace089bee7b1c](https://github.com/hyperlendx/hpl-staking-contracts/tree/e8baa1fa367aaf1833cad4c9d4cace089bee7b1c)<br>&nbsp;&nbsp;(hyperlendx/hpl-staking-contracts)

**Fixes review commit hash:**<br>• [b1c0506d49df0885f7b636b32472c3ffd203de86](https://github.com/hyperlendx/hpl-staking-contracts/tree/b1c0506d49df0885f7b636b32472c3ffd203de86)<br>&nbsp;&nbsp;(hyperlendx/hpl-staking-contracts)

# Scope

- `HplStalking.sol`

# Findings



# [L-01] `LockPeriodAdded` and `LockPeriodUpdated` events missing unlockFeeBps field

_Resolved_

## Impact

Off-chain indexers and monitoring systems cannot track `unlockFeeBps` changes through events alone.

## Remediation

Add `unlockFeeBps` to both events:

```solidity
event LockPeriodAdded(
    uint256 indexed id,
    uint256 duration,
    uint256 multiplierBps,
    uint256 unlockFeeBps
);

event LockPeriodUpdated(
    uint256 indexed id,
    uint256 duration,
    uint256 multiplierBps,
    uint256 unlockFeeBps,
    bool isActive
);
```




# [L-02] Missing unlock fee bounds can cause early unstaking reverts

_Resolved_

## Description

The contract does not validate `unlockFeeBps` when adding or updating lock periods. As a result, the owner can configure an unlock fee greater than 10,000 bps (100%).

During early unstaking, the penalty is computed as `penalty = amount * unlockFeeBps / 10000` and then `amount -= penalty`. If `unlockFeeBps > 10000`, the penalty will exceed the original amount and the subtraction will underflow, causing a revert.

## Recommendations
Enforce `unlockFeeBps <= 10000` when creating and updating lock periods. Consider also documenting the intended penalty range and adding explicit custom errors for invalid fee configurations.




# [L-03] Penalty terms are not fixed at the time of staking

_Resolved_

## Description

When a user unstakes before the lock end time using `unlockWithPenalty == true`, the penalty is calculated using the **current** `unlockFeeBps` stored in `lockPeriods[userStake.lockPeriodId]`, not the value that was in effect when the user originally staked.

```solidity
function unstake(uint256 stakeIndex, bool unlockWithPenalty) external nonReentrant {
    //...
@177>LockPeriod memory lockPeriod = lockPeriods[userStake.lockPeriodId];
    //...
    if (userStake.lockPeriodId > 0 && block.timestamp < unlockTime) {
        if (unlockWithPenalty){
@184>       penalty = amount * lockPeriod.unlockFeeBps / 10000;
@185>       amount -= penalty;
        } else {
            revert StakeStillLocked();
        }
    }
    //...
}
```

Since the owner can update a lock period via `updateLockPeriod()` (including changing `unlockFeeBps`), the penalty percentage can be modified after users have already committed funds. This means users may be charged a different penalty than what they implicitly agreed to at stake creation time, which can be perceived as unfair and breaks the expectation that stake terms are fixed once entered.

This retroactive application can also create inconsistent user outcomes where two users who staked under the same initial lock parameters face different early-unstake penalties depending on when the owner updates the configuration.

## Recommendations 
Snapshot the `unlockFeeBps` at stake creation time (store it in the `Stake` struct) and use that snapshotted value when computing early-unstake penalties.




# [L-04] Missing bounds checks in stake view functions cause out of bounds revert

_Resolved_

## Description

The `getUserTotalStakedOffset()` function does not validate the `offset` and `length` parameters against the user’s total number of stakes. If `offset` is greater than or equal to `stakes.length`, the first array access will revert due to an out-of-bounds read. Similarly, if `length > 0` and `offset + length` exceeds `stakes.length`, the loop will eventually revert when accessing an invalid index.

```solidity
function getUserTotalStakedOffset(address user, uint256 length, uint256 offset) public view returns (uint256 returnAmount) {
    uint256 total = 0;
    Stake[] storage stakes = userStakes[user];

    uint256 len = length > 0 ? offset + length : stakes.length;
    for (uint256 i = offset; i < len; i++) {
        if (stakes[i].isActive) {
            total += stakes[i].amount;
        }
    }

    return total;
}
```

## Recommendations
Add explicit bounds checks for `offset` and `offset + length` before entering the loop, and either clamp the iteration range to `stakes.length` or revert with a clear, custom error indicating invalid parameters.


