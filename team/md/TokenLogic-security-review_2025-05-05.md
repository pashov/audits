# About

Pashov Audit Group consists of multiple teams of some of the best smart contract security researchers in the space. Having a combined reported security vulnerabilities count of over 1000, the group strives to create the absolute very best audit journey possible - although 100% security can never be guaranteed, we do guarantee the best efforts of our experienced researchers for your blockchain protocol. Check our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# Introduction

A time-boxed security review of the **TokenLogic-com-au/asset-manager** repository was done by **Pashov Audit Group**, with a focus on the security aspects of the application's smart contracts implementation.

# About Arbitrum Strategy Manager

Arbitrum Strategy Manager is a smart contract that manages the Arbitrum Foundation's wstETH holdings on Aave V3, enabling yield generation through deposits, withdrawals, and reward claims. It includes automated position scaling and emergency functions to adjust exposure based on Aave's liquidity conditions.

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

_review commit hash_ - [bf3b2f80c56de0bacf9bfee54527f8dce1883576](https://github.com/TokenLogic-com-au/asset-manager/tree/bf3b2f80c56de0bacf9bfee54527f8dce1883576)

_fixes review commit hash_ - [af9e8308b1a036a97cc6faf5de81a159831454a1](https://github.com/TokenLogic-com-au/asset-manager/tree/af9e8308b1a036a97cc6faf5de81a159831454a1)

### Scope

The following smart contracts were in scope of the audit:

- `ArbitrumStrategyManager`

# Findings

# [L-01] Missing threshold check in `depositIntoAaveV3()` may cause scale-down

The `depositIntoAaveV3()` function allows addresses with the `CONFIGURATOR_ROLE` to deposit arbitrary amounts of `wstETH` into the Aave V3 pool. However, it does not check whether the resulting position will exceed the `_maxPositionThreshold + BPS_BUFFER`, which is the upper bound that triggers an emergency scale-down in the `scaleDown()` function.

This omission allows the `CONFIGURATOR_ROLE` to unintentionally deposit an amount that will immediately make the position non-compliant with the threshold limit. As a result, an automated scale-down might be triggered soon after deposit, leading to unnecessary gas usage and increased operational overhead.

```solidity
    function depositIntoAaveV3(
        uint256 amount
    ) external onlyRole(CONFIGURATOR_ROLE) {
        require(amount > 0, InvalidZeroAmount());

        IERC20(WST_ETH).forceApprove(_aaveV3Pool, amount);
        IPool(_aaveV3Pool).supply(WST_ETH, amount, address(this), 0);

        emit DepositIntoAaveV3(amount);
    }
```

Recommendation:
Add a check in `depositIntoAaveV3()` to ensure that the resulting position percentage remains below `_maxPositionThreshold + BPS_BUFFER`.

# [L-02] No automatic check for `scaleDown` after `updateMaxPositionThreshold`

The `updateMaxPositionThreshold` function in the `ArbitrumStrategyManager` contract allows the configurator role to update the maximum position threshold.

```solidity
        uint256 old = _maxPositionThreshold;
        _maxPositionThreshold = newThreshold;
```

However, there is currently no mechanism in place to **automatically trigger a check for the `scaleDown` function after the threshold is updated**. This oversight could lead to situations where the position percentage exceeds the newly set threshold without the necessary adjustments being made in time, potentially exposing the contract to risks.

# [L-03] Hardcoded Aave V3 pool address may not match future upgrade

In the `ArbitrumStrategyManager` contract, the `_aaveV3Pool` variable is defined as an `immutable` address and is set to a hardcoded value of `0x794a61358D6845594F94dc1DB02A252b5b4814aD` during deployment.

```solidity
    /// @dev Address of the Aave V3 Pool
    address internal immutable _aaveV3Pool;
```

```solidity
    address public constant AAVE_V3_POOL =
        0x794a61358D6845594F94dc1DB02A252b5b4814aD;
    address public constant MERKL_DISTRIBUTOR =
        0x3Ef3D8bA38EBe18DB133cEc108f4D14CE00Dd9Ae;

    function run() public {
        vm.startBroadcast();

        manager = new ArbitrumStrategyManager(
            ADMIN,
            AAVE_V3_POOL,
            TREASURY,
            MERKL_DISTRIBUTOR,
            HYPERNATIVE
        );

        vm.stopBroadcast();
    }
```

However, hardcoding the Aave V3 pool address poses a risk:

The `AaveV3 pool` address is typically managed through the `Aave Addresses Provider`, which allows for updates to the pool address if necessary.

[Link](https://arbiscan.io/address/0xa97684ead0e402dc232d5a977953df7ecbab3cdb#code)
[Link](https://aave.com/docs/developers/smart-contracts/pool-addresses-provider)

> `setAddress` Sets the address of the protocol contract stored at the given
> id, replacing the address saved in the addresses map.

```solidity
  /// @inheritdoc IPoolAddressesProvider
  function setAddress(bytes32 id, address newAddress) external override onlyOwner {
    address oldAddress = _addresses[id];
    _addresses[id] = newAddress;
    emit AddressSet(id, oldAddress, newAddress);
  }
```

```solidity
  /// @inheritdoc IPoolAddressesProvider
  function getPool() external view override returns (address) {
    return getAddress(POOL);
  }
```

Even though `setAddress` should be called with care, it's still possible that it is called and does a hard replacement of the current pool address in the addresses map.

Currently, the `pool` address is hardcoded and may not catch up with the address upgrade.

By hardcoding the address, the contract may interact with an outdated pool, leading to potential issues in functionality and security.

A recommended approach is to use `IPoolAddressesProvider(addressProviderAddress).getPool()` to reference `pool` instead of `hardcoding`

# [L-04] Sub-optimal role ID implementation

The `ArbitrumStrategyManager` contract defines role identifiers as public constants using string literals, specifically for the `CONFIGURATOR_ROLE` and `EMERGENCY_ACTION_ROLE`.

```solidity
    /// @notice Returns the identifier of the Configurator Role
    /// @return The bytes32 id of the Configurator role
    bytes32 public constant CONFIGURATOR_ROLE = "CONFIGURATOR";

    /// @notice Returns the identifier of the Emergency Action Role
    /// @return The bytes32 id of the Emergency Action role
    bytes32 public constant EMERGENCY_ACTION_ROLE = "EMERGENCY_ACTION";
```

According to the `OpenZeppelin` [documentation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/9393147db73ae6261b67cb03003370e9a7fa2448/contracts/access/AccessControl.sol#L17C1-L23C7) on `AccessControl`, role identifiers should be defined using the `keccak256` hash function to ensure uniqueness and security. The current implementation does not follow this best practice.

````
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```solidity
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
````

# [L-05] Missing claim for Aave incentives leads to unclaimed rewards

The `ArbitrumStrategyManager` contract supplies `wstETH` into the Aave V3 pool to earn yield. However, it does not implement any function to claim incentive rewards from **Aave's `RewardsController`**. As a result, any LP incentives accrued from Aave remain unclaimed and locked in the Aave pool, never being utilized.

This contradicts the intended design stated in the project documentation, which indicates that funds (including rewards) should be transferred to the `_arbFoundation` address. Without an explicit claim mechanism, the Arbitrum Foundation loses access to yield opportunities provided by Aave’s incentive system.

**Recommendations**

Introduce a function that allows claiming rewards from Aave's `RewardsController`.

# [L-06] Inefficiency from fixed `BPS_BUFFER` value in position scaling

The `BPS_BUFFER` constant is currently set to `500`, representing a 5% buffer when scaling down positions in the `ArbitrumStrategyManager` contract.

```solidity
    /// @dev Buffer used when scaling down a position to not be close to threshold
    uint256 public constant BPS_BUFFER = 500;
```

This fixed value can lead to **inefficiencies in liquidity management**, particularly when the position percentage (`positionPct`) approaches the maximum position threshold (`_maxPositionThreshold`).

```solidity
        if (positionPct >= _maxPositionThreshold) {
            uint256 bpsToReduce = positionPct + BPS_BUFFER - _maxPositionThreshold;
            uint256 excessAmount = (availableLiquidity * bpsToReduce) / MAX_BPS;

            /// this happens when positionPct and _maxPositionThreshold
            /// have lower values compared to BPS_BUFFER
            /// for example: if positionPct is 2 bps and _maxPositionThreshold is 1 bps
            /// due to BPS_BUFFER being 500 bps, the amount needed to be withdrawn
            /// (excessAmount) will be bigger than current position.
            /// aave only allows to have a withdraw amount value above
            /// the current position amount, if type(uint256).max is used
            if (excessAmount > suppliedAmount) {
                excessAmount = suppliedAmount;
            }
```

For instance, if both `positionPct` and `_maxPositionThreshold` are equal to `400` (4%), the calculation for `excessAmount` could lead to a situation where all liquidity is withdrawn, even though the position is precisely at the threshold. This creates a cliff operation:

1. If `positionPct` is less than `_maxPositionThreshold`, no action will be taken.
2. If `positionPct` equals `_maxPositionThreshold`, all available liquidity is suddenly withdrawn.

This behavior can result in unintended consequences, **as it does not allow for any buffer or flexibility when the position is at the threshold.**

This behavior contradicts the expected functionality, as the buffer's presence can lead to unnecessary liquidity removal at some times, ultimately causing inefficiencies in fund utilization.

**Also, under such circumstances, interest rates usually rise as a result of high utilization. Fully withdrawing the deposit may also hinder effective yield generation.**

**Recommendations**

The comments in the code acknowledge this potential issue, but the reliance on a static buffer value does not allow for adjustments based on changing market conditions or the specific context of the position. As `_maxPositionThreshold` is a variable, it would be prudent for the `BPS_BUFFER` to also be adjustable to better align with the current position dynamics.
