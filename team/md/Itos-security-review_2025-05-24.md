# About
 Pashov Audit Group consists of multiple teams of some of the best smart contract security researchers in the space. Having a combined reported security vulnerabilities count of over 1000, the group strives to create the absolute very best audit journey possible - although 100% security can never be guaranteed, we do guarantee the best efforts of our experienced researchers for your blockchain protocol. Check our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).
# Disclaimer
 A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.
# Introduction
 A time-boxed security review of the **itos-finance/Commons** repository was done by **Pashov Audit Group**, with a focus on the security aspects of the application's smart contracts implementation.
# About Itos
 
Itos Finance is a platform that uses an on-chain derivative engine to create customizable financial payoffs, combined with a portfolio management system that enables cross-margin trading, siloed portfolios, performance tracking, while allowing multiple protocols to share liquidity. The scope was focused on RFT contract, which provides utilities for handling token requests and payments between contracts, including both non-reentrant and reentrant settlement functions, with support for ERC165-compliant RFT payers.

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
 _review commit hash_ - [cba52b0e2fbd57746869d15ee48bbd83667dc38a](https://github.com/itos-finance/Commons/tree/cba52b0e2fbd57746869d15ee48bbd83667dc38a)

_fixes review commit hash_ - [bb73627474b3fdb8e1e341132a146171b603778e](https://github.com/itos-finance/Commons/tree/bb73627474b3fdb8e1e341132a146171b603778e)

### Scope

The following smart contracts were in scope of the audit:

- `RFT` 

# Findings
 # [H-01] Payers exploit `reentrantSettle` to bypass payments with self-transfers

## Severity

**Impact:** High

**Likelihood:** Medium

## Description

The `reentrantSettle` function in RFTLib contains a vulnerability that allows malicious contracts to implement the `IRFTPayer` interface to completely avoid payment obligations. The vulnerability is from how the function tracks cumulative balance changes (`transact.delta`) across nested calls.

When a contract requests tokens using `reentrantSettle`, the function:
- Records the expected balance change in `transact.delta[token]`.
- Calls the payer's `tokenRequestCB` if they implement `IRFTPayer`.
- Validates final balances against the cumulative delta.

However, a malicious payer can exploit this by calling back into the requesting contract during `tokenRequestCB`, causing it to call `reentrantSettle` again with `payer = requester address` and a negative amount. This results in a self-transfer that:

- Doesn't change the contract's actual token balance.
- Zeros out the tracked delta (`+X` from original request, `-X` from the callback).
- Passes the final balance validation despite no tokens being received.

```solidity
    function reentrantSettle(
>>>     address payer, // @audit payer is set to requester
        address[] memory tokens,
        int256[] memory balanceChanges,
        bytes memory data
    ) internal returns (bytes memory cbData) {
         ...      
            // Handle and track all balance changes.
            int256 change = balanceChanges[i];
            if (change < 0) {
>>>             TransferHelper.safeTransfer(token, payer, uint256(-change)); // @audit if payer == address(this), this is a self-transfer
            }
            // If we want tokens we transfer from when it is not an RFTPayer. Otherwise we wait to request at the end.
            if (change > 0 && !isRFTPayer) {
                TransferHelper.safeTransferFrom(token, payer, address(this), uint256(change));
            }

            // Handle bookkeeping.
>>>         transact.delta[token] += change; // @audit delta is reduced because change is negative
        }
         ...
        }
    }
```

Consider a scenario:

- VictimContract calls `reentrantSettle(MaliciousPayer, +1 ETH)`
   -> transact.delta[token] = +1 ETH
   
- `MaliciousPayer.tokenRequestCB` executes:
   -> Calls VictimContract to trigger `reentrantSettle(VictimContract, -1 ETH)`
   
- VictimContract self-transfers 1 ETH (balance unchanged)
   -> transact.delta[token] = +1 ETH - 1 ETH = 0
   
- Final validation: Expected delta (0) == Actual change (0)
   -> Attack succeeds, MaliciousPayer pays nothing


It leads to loss of fund for the VictimContract.

## Recommendations

Prevent self-transfers in RFTLib**: Add a check to ensure `payer != address(this)`:

```diff
function reentrantSettle(...) internal returns (bytes memory cbData) {
+   require(payer != address(this), "Self-transfer not allowed");
    ...
}
```



# [M-01] Potential gas griefing attack from malicious payer

## Severity

**Impact:** Medium

**Likelihood:** Medium

## Description

`RFTLib` provides a series of functions which allow caller to request token payment from a RFT payer by calling [`IRFTPayer(payer).tokenRequestCB()`](https://github.com/itos-finance/Commons/blob/cba52b0e2fbd57746869d15ee48bbd83667dc38a/src/Util/RFT.sol#L117).  

When executing [`RFTLib#settle()`](https://github.com/itos-finance/Commons/blob/cba52b0e2fbd57746869d15ee48bbd83667dc38a/src/Util/RFT.sol#L82-L133) or [`RFTLib#reentrantSettle()`](https://github.com/itos-finance/Commons/blob/cba52b0e2fbd57746869d15ee48bbd83667dc38a/src/Util/RFT.sol#L148-L240), it will verify that the actual balance change matches the expected amount, preventing payers from evading payment. 

However, the caller doesn't know whether `payer` is trustworthy. Since there is no gas cap on the call of `IRFTPayer(payer).tokenRequestCB()`, an attacker can craft a malicious payer contract and caller could be subject to gas griefing.

## Recommendations

Allow caller to set gas cap on call of `payer#tokenRequestCB()`.  Besides the call of `payer#supportsInterface()` should have a fixed gas limit.



# [L-01] RFTLib incompatible with fee-on-transfer tokens

When the RFT library requests tokens from a non-RFTPayer address (EOA or non-RFTPayer contract), it uses `safeTransferFrom` to pull the exact requested amount. However, with `fee-on-transfer` tokens, the actual received amount will be less than the requested amount due to transfer fees being deducted.

The issue occurs in both `settle` and `reentrantSettle` functions:

```solidity
    function settle(
        address payer,
        address[] memory tokens,
        int256[] memory balanceChanges,
        bytes memory data
    ) internal returns (int256[] memory actualDeltas, bytes memory cbData) {
         ...
            // If we want tokens we transfer from when it is not an RFTPayer. Otherwise we wait to request at the end.
            if (change > 0 && !isRFTPayer) {
                TransferHelper.safeTransferFrom(token, payer, address(this), uint256(change));
            }
        
         ...

            // Validate our balances.
            uint256 finalBalance = IERC20(token).balanceOf(address(this));
            actualDeltas[i] = U256Ops.sub(finalBalance, startBalances[i]);
            if (actualDeltas[i] < balanceChanges[i]) {
                revert InsufficientReceive(token, balanceChanges[i], actualDeltas[i]);
            }
        

        transact.status = ReentrancyStatus.Idle;
    }
```

```solidity
    function reentrantSettle(
        address payer,
        address[] memory tokens,
        int256[] memory balanceChanges,
        bytes memory data
    ) internal returns (bytes memory cbData) {
       ...
            // If we want tokens we transfer from when it is not an RFTPayer. Otherwise we wait to request at the end.
            if (change > 0 && !isRFTPayer) {
                TransferHelper.safeTransferFrom(token, payer, address(this), uint256(change));
            }

            // Handle bookkeeping.
            transact.delta[token] += change;
        }
        ...
    }
```

It's recommended to calculate the actual received amount: Instead of assuming the full amount is received, calculate the actual difference in balance before and after transferring.



# [L-02] Reentrancy protection bypass allows unauthorized reentrant calls

The RFTLib implements reentrancy protection between `settle()` and `reentrantSettle()` functions, but fails to protect against reentrancy through `request()` and `requestOrTransfer()` functions. 

While `settle()` and `reentrantSettle()` properly check and update the `ReentrancyStatus`, the `request()` and `requestOrTransfer()` functions make external calls to `IRFTPayer(payer).tokenRequestCB()` and `isSupported()` without any reentrancy protection. 
This allows a malicious payer contract to reenter and call either `settle()` or `reentrantSettle()`, potentially bypassing intended transaction flow and balance validation logic.

The vulnerability occurs because:
- `request()` and `requestOrTransfer()` don't check or modify `transact.status`.
- External calls in these functions can trigger callbacks that reenter protected functions.
- This breaks the assumption that balance tracking in `settle()`/`reentrantSettle()` is atomic.

To resolve this, add reentrancy protection to `request()` and `requestOrTransfer()` functions by updating `ReentrancyStatus` to `Locked`.



# [L-03] Manipulation in `settle` and `reentrantSettle` lets payers bypass validation

Both the `settle` and `reentrantSettle` functions in RFTLib use a balance accounting mechanism that assumes exclusive control over token balance changes during execution. Both functions track the starting balance and expected delta for each token, then validate the final balance against these values. However, during the `tokenRequestCB` callback, the payer has full execution control and can arbitrarily modify the requester's token balance by calling a separate, unrelated public function on the requester contract that also affects token balances, or by triggering a callback from another protocol the requester interacts with.

For example transfer less than requested, then use other mechanisms to increase the requester's balance (e.g., trigger third-party contract transfers, claimming rewards, token balance rebasing).

```solidity
   transact.startBalance[token] = IERC20(token).balanceOf(address(this));

   ...

   // Payer callback - can execute arbitrary code
   cbData = IRFTPayer(payer).tokenRequestCB(tokens, balanceChanges, data); // @audit Payer callback - can execute arbitrary code
   
   ...

   uint256 expectedBalance = U256Ops.add(transact.startBalance[token], expectedDelta);
   uint256 finalBalance = IERC20(token).balanceOf(address(this)); // @audit Final validation assumes only tracked changes occurred
   if (finalBalance < expectedBalance) {
      revert InsufficientReceive(token, expectedDelta, actualDelta);
   }
```

It can lead to the loss of funds for the requester.

**Recommendations**

- Limit calling `settle` and `reentrantSettle` to trusted payer.
- For untrusted payers, use `transferFrom` flow.



# [L-04] Unbounded loops in `reentrantSettle()` risk out-of-gas errors in calls


The `reentrantSettle()` function contains multiple unbounded loops that can lead to out-of-gas errors, particularly problematic since this function is designed to be called multiple times in nested/reentrant scenarios within the same transaction. The gas consumption compounds across nested calls, making the function susceptible to gas limit failures.

The `reentrantSettle()` function contains several gas-intensive operations that scale with the number of tokens and the depth of reentrancy:
- **Primary processing loop** - Iterates through all tokens for transfers and bookkeeping:
```solidity
for (uint256 i = 0; i < tokens.length; ++i) {
    address token = tokens[i];
    // ... token processing including potential transfers and storage updates
}
```
- **Cleanup loop in outer context** - Iterates through all accumulated tokens:
```solidity
if (outerContext) {
    uint256 lastIdx = transact.tokens.length - 1;
    for (uint256 i = 0; i <= lastIdx; ++i) {
        // ... balance validation and cleanup operations
    }
}
```
- **External callback** - Makes calls to IRFTPayer.tokenRequestCB() which must process token arrays:
```solidity
if (isRFTPayer) {
    cbData = IRFTPayer(payer).tokenRequestCB(tokens, balanceChanges, data);
}
```
This could lead to:
- Transaction failures due to gas limit exceeded.
- Potential for griefing attacks by forcing expensive operations.
- Denial of service for protocols relying on `reentrantSettle()`.

**Recommendations**

Add maximum bounds for token arrays to prevent excessive gas consumption.


