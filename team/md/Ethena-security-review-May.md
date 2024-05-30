# About

Pashov Audit Group consists of multiple teams of some of the best smart contract security researchers in the space. Having a combined reported security vulnerabilities count of over 1000, the group strives to create the absolute very best audit journey possible - although 100% security can never be guaranteed, we do guarantee the best efforts of our experienced researchers for your blockchain protocol. Check our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# Introduction

A time-boxed security review of the **ethena-labs/ethena-mint-contract-audit** repository was done by **Pashov Audit Group**, with a focus on the security aspects of the application's smart contracts implementation.

# About Ethena

Ethena Mint V2 introduces delta limits for price divergence, distinct mint/redeem limits, an on-chain identity whitelist, and EIP-1271 signature verification, all configurable via Ethena multi-sig.

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

_review commit hash_ - [b60b7193636d499ce7f89c4f5afe3b99cf31a2b6](https://github.com/ethena-labs/ethena-mint-contract-audit/tree/b60b7193636d499ce7f89c4f5afe3b99cf31a2b6)

_fixes review commit hash_ - [9cd4ad7b46acc35f6b3340c808200279fbe75de0](https://github.com/ethena-labs/ethena-mint-contract-audit/tree/9cd4ad7b46acc35f6b3340c808200279fbe75de0)

### Scope

The following smart contracts were in scope of the audit:

- `EthenaMinting`
- `SingleAdminAccessControl`

# Findings

# [M-01] Some orders can be executed multiple times

## Severity

**Impact:** High

**Likelihood:** Low

## Description

Functions `_deduplicateOrder()` and `verifyNonce()` are in charge of deduplicating orders and making sure that the same nonce can't be used twice. The issue is that in `verifyNonce()` code converts `invalidatorBit` to `uint128` with unsafe cast and the value of `invalidatorBit` could become 0 while overflow happens and in that case, the `invalidator` won't be set to 1 and that order can be executed multiple times by minter and redeemer role. The issue impact is that users' funds can be manipulated without their consent which could cause them loss.

The issue will happen whenever `uint8(nonce) > 128`:

```solidity
 uint128 invalidatorSlot = uint64(nonce) >> 8;
 uint128 invalidatorBit = uint128(1 << uint8(nonce));
 uint128 invalidator = _orderBitmaps[sender][invalidatorSlot];
 if (invalidator & invalidatorBit != 0) revert InvalidNonce();
```

## Recommendations

Don't cast `invalidatorBit` to `uint128` or use `uint7(nonce)`

# [L-01] Missing sanity checks when setting the `tokenConfig`

The `addSupportedAsset()` function allows the admin to add new tokens with built-in sanity checks to ensure token validity:

```solidity
    if (tokenConfig[asset].isActive || asset == address(0) || asset == address(usde)) {
      revert InvalidAssetAddress();
    }
```

However, during deployment, new tokens are added using the internal `_setTokenConfig()` function, which lacks these validations:

```solidity
    for (uint128 k = 0; k < _tokenConfig.length;) {
      _setTokenConfig(_assets[k], _tokenConfig[k]);
      unchecked {
        ++k;
      }
    }
```

To prevent errors during deployment, consider adding similar checks:

```solidity
    for (uint128 k = 0; k < _tokenConfig.length;) {
      if (_assets[k] == address(0) || _assets[k] == address(usde)) revert InvalidAssetAddress();
      _setTokenConfig(_assets[k], _tokenConfig[k]);
      unchecked {
        ++k;
      }
    }
```

# [L-02] ETH and WETH redemption limits can be combined

The `EthenaMinting.sol` contract introduced asset based limits for minting and redemption in addition to global limits.

```solidity
  modifier belowMaxMintPerBlock(uint128 mintAmount, address asset) {
    TokenConfig memory _config = tokenConfig[asset];
    if (!_config.isActive) revert UnsupportedAsset();
 >> if (totalPerBlockPerAsset[block.number][asset].mintedPerBlock + mintAmount > _config.maxMintPerBlock) {
      revert MaxMintPerBlockExceeded();
    }
    _;
  }
  modifier belowMaxRedeemPerBlock(uint128 redeemAmount, address asset) {
    TokenConfig memory _config = tokenConfig[asset];
    if (!_config.isActive) revert UnsupportedAsset();
>>  if (totalPerBlockPerAsset[block.number][asset].redeemedPerBlock + redeemAmount > _config.maxRedeemPerBlock) {
      revert MaxRedeemPerBlockExceeded();
    }
    _;
  }
```

In one case, these limits can be bypassed. When redeeming USDe for ETH and WETH tokens, the different `totalPerBlockPerAsset[block.number]` accumulators are incremented, even though the user basically receives the same ETH asset (WETH can be easily unwrapped). This allows users to redeem USDe beyond their block limits.

```solidity
  function redeem(Order calldata order, Signature calldata signature)
    external
    override
    nonReentrant
    onlyRole(REDEEMER_ROLE)
>>  belowMaxRedeemPerBlock(order.usde_amount, order.collateral_asset)
    belowGlobalMaxRedeemPerBlock(order.usde_amount)
  {
    ---SNIP---
>>  totalPerBlockPerAsset[block.number][order.collateral_asset].redeemedPerBlock += order.usde_amount;
```

It is recommended to increment both accumulators if the asset is WETH or ETH.
