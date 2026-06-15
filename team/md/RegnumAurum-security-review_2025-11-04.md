
# About Pashov Audit Group


Pashov Audit Group consists of 40+ freelance security researchers, who are well proven in the space - most have earned over $100k in public contest rewards, are multi-time champions or have truly excelled in audits with us. We only work with proven and motivated talent.

With over 300 security audits completed — uncovering and helping patch thousands of vulnerabilities — the group strives to create the absolute very best audit journey possible. While 100% security is never possible to guarantee, we do guarantee you our team's best efforts for your project. 

Check out our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).
    

# Disclaimer


A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.


# Introduction

<p>A time-boxed security review of the <strong>RegnumAurumAcquisitionCorp/contracts</strong> repository was done by Pashov Audit Group, during which <strong>Shaka, 0xTheBlackPanther, 0xdeadbeef</strong> engaged to review <strong>Regnum Aurum</strong>. A total of <strong>6</strong> issues were uncovered.</p>

# About Regnum Aurum

<p>Regnum Aurum (RAAC) is a fractionalization platform that tokenizes real estate into NFTs (RAACNFT) and fractional index tokens (iRAAC), enabling on-chain lending, borrowing, and liquidity against property value. By combining Chainlink-powered appraisals, a hybrid RWA Vault, and veRAAC governance the protocol enables programmable debt positions against real estate assets with on-chain liquidation mechanisms.</p>

# Security Assessment Summary

**Review commit hash:**<br>• [9846f571615b7a51d815fbc8841300ca75780a70](https://github.com/RegnumAurumAcquisitionCorp/contracts/tree/9846f571615b7a51d815fbc8841300ca75780a70)<br>&nbsp;&nbsp;(RegnumAurumAcquisitionCorp/contracts)

**Fixes review commit hash:**<br>• [486262a135c0405f5f18e20bf042ab256082686c](https://github.com/RegnumAurumAcquisitionCorp/contracts/tree/486262a135c0405f5f18e20bf042ab256082686c)<br>&nbsp;&nbsp;(RegnumAurumAcquisitionCorp/contracts)




# Scope

- `RWAIndexTokenOracle.sol`
- `LendingPool.sol`
- `LendingPoolStorage.solLiquidationSwap.sol`
- `StabilityPool.sol`
- `DEToken.sol`
- `RAACNFT.sol`
- `RToken.sol`
- `RAACNFTVaultAdapterOracle.sol`
- `RAACNFTVaultAdapterV2.sol`
- `RWAVault.sol`
- `ILendingPool.sol`
- `IDEToken.sol`
- `IRToken.sol`
- `WadRayMath.sol`

# Findings



# [L-01] Position scaled debt can be underestimated

_Resolved_

`LendingPool._positionScaledDebt()` calculates the scaled debt for a given position by multiplying the raw debt balance by the index multiplier. This operation has been updated to round down instead of rounding to the nearest value.

Generally, it should be avoided to underestimate debt values so that lenders and the protocol are never exposed to unexpected losses.

It is recommended to round up or at least round to the nearest value when calculating debt amounts.



# [L-02] Missing setter function for mutable oracle address in `RWAIndexTokenOracle`

_Resolved_

In `contracts/contracts/core/oracles/RWAIndexTokenOracle.sol` the `crvusdToUSDOracle` state variable is declared as mutable (_non-immutable_) but lacks a setter function to update it

```solidity
address public crvusdToUSDOracle; // Mutable but no setter @audit
```

This is problematic if the crvUSD oracle is compromised, deprecated, or contains bugs, there is no way to update the reference without redeploying all dependent contracts.

**Recommendation**

Add an owner-controlled setter function with proper access control and validation.

```solidity
event CrvUSDOracleUpdated(address indexed oldOracle, address indexed newOracle);

function setCrvUSDOracle(address _newOracle) external onlyOwner {
    require(_newOracle != address(0), "Zero address");
    require(_newOracle != crvusdToUSDOracle, "Same oracle");
    
    address oldOracle = crvusdToUSDOracle;
    crvusdToUSDOracle = _newOracle;
    
    emit CrvUSDOracleUpdated(oldOracle, _newOracle);
}
```

Of if the oracle should never change, make it immutable.

```solidity
address public immutable crvusdToUSDOracle;
```



# [L-03] Incorrect comment in `LiquiditySwap`

_Resolved_

The following comment has not been changed, even though the use of an oracle to convert `crvUSD` to `USD` is in place:

```
// Price per share returns 1e18 price of the iRAAC in crvUSD.
```



# [L-04] `rateData.maxRate` incorrect comment

_Resolved_

`rateData.maxRate` is set to `83.63` although comment suggests `83.75`:
```solidity
83.75% in RAY (27 decimals) based on 7.25% US Prime Rate
```



# [L-05] Liquidations occur during paused `lendingPool` preventing fair repayment

_Acknowledged_

`StabilityPool.liquidateBorrower` can be called if the underlying `LendingPool` is paused. Because repayment in `LendingPool` is gated by `whenNotPaused`, pausing the `LendingPool` prevents borrowers from repaying or closing liquidation within the grace period, while liquidation can still be initiated/finalized from the `StabilityPool` side. This creates an unfair situation: borrowers cannot cure their positions, yet their collateral can still be liquidated.

**Recommendations**

Prevent liquidation initiation/finalization when the LendingPool is paused.



# [L-06] `LiquidationSwap` lacks constructor-set oracle

_Resolved_

`LiquidationSwap` uses the external `crvusdToUSDOracle` but does not require the oracle to be set in the constructor.

The contract provides `setCrvusdToUSDOracle(address)` but the constructor does not initialize it.
`_swap()` unconditionally calls `ICrvUSDToUSDOracle(crvusdToUSDOracle).getPrice()`.

If the oracle address is unset or misconfigured, the call reverts, causing a DOS.

Impact: Liquidations can be blocked.

**Recommendations**

Add oracle on contract construction.

