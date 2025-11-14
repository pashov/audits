
# About Pashov Audit Group


Pashov Audit Group consists of 40+ freelance security researchers, who are well proven in the space - most have earned over $100k in public contest rewards, are multi-time champions or have truly excelled in audits with us. We only work with proven and motivated talent.

With over 300 security audits completed — uncovering and helping patch thousands of vulnerabilities — the group strives to create the absolute very best audit journey possible. While 100% security is never possible to guarantee, we do guarantee you our team's best efforts for your project. 

Check out our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).
    

# Disclaimer


A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.


# Introduction

<p>A time-boxed security review of the <strong>RegnumAurumAcquisitionCorp/fx-contracts</strong> repository was done by Pashov Audit Group, during which <strong>rvierdiiev, merlinboii, Shaka</strong> engaged to review <strong>RWf(x)</strong>. A total of <strong>2</strong> issues were uncovered.</p>

# About RWf(x)

<p>RWf(x) is a protocol that uses RWA-backed tokens like fractionalized gold (fGOLD) as collateral to mint stablecoins (fToken) and leveraged tokens (xToken). It enables splitting yield-bearing assets into a stable, yield-backed coin (goldUSD) and a leveraged asset (xGOLD), balancing stability and exposure to volatility.</p>

# Security Assessment Summary

**Review commit hash:**<br>• [f6e865df2dd46d67a49391d94e54b26e6a8af43c](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/tree/f6e865df2dd46d67a49391d94e54b26e6a8af43c)<br>&nbsp;&nbsp;(RegnumAurumAcquisitionCorp/fx-contracts)

**Fixes review commit hash:**<br>• [80c514e163f5f8effaa3ba0c4b25cf658a939434](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/tree/80c514e163f5f8effaa3ba0c4b25cf658a939434)<br>&nbsp;&nbsp;(RegnumAurumAcquisitionCorp/fx-contracts)




# Scope

- `FxLowVolatilityMath.sol`
- `HarvestableTreasury.sol`
- `Market.sol`
- `Treasury.sol`
- `IFxMarket.sol`
- `IFxTreasury.sol`
- `IRWAVaultPriceOracle.sol`

# Findings



# [H-01] Critical functions revert if system is undercollateralized

_Resolved_

## Severity

**Impact:** High

**Likelihood:** Medium

## Description

The internal function `Treasury._loadSwapState()` calculates the `xNav` as follows:

```solidity
_state.xNav = _state.baseSupply.mul(_state.baseNav).sub(_state.fSupply.mul(_state.fNav)).div(_state.xSupply);
```

This is equivalent to:

```js
(baseSupplyNav - fSupplyNav) / xSupply
```

In the case of the system being undercollateralized (`baseSupplyNav < fSupplyNav`), the calculation of `xNav` will revert due to subtraction underflow. All transactions involving the execution of `_loadSwapState()` will fail, including all operations that aim to raise the collateral ratio so that it can return to a healthy state.

As a result, the protocol will lack any mechanism to recover the collateralization ratio once it falls below 100%.

### Proof of concept

Add the following code to the `Market.spec.ts` test file.

```ts
  context.only("audit", async () => {
    beforeEach(async () => {
      await oracle.setPrice(100000000000); // $1000 with 8 decimals
      await treasury.initializePrice();
      await weth.deposit({ value: ethers.parseEther("10") });
      await weth.approve(market.getAddress(), MaxUint256);
      await market.mint(ethers.parseEther("1"), deployer.address, 0, 0);
    });

    it("reverts when collateral ratio is below 100%", async () => {
      // The system becomes undercollateralized
      await oracle.setPrice(65000000000); // $650 with 8 decimals

      // Manager tries to raise collateral ratio, but transactions revert
      await expect(market.mintXToken(ethers.parseEther("1"), signer.address, 0))
        .to.revertedWith("SafeMath: subtraction overflow");
      await expect(market.addBaseToken(ethers.parseEther("1"), signer.address, 0))
        .to.revertedWith("SafeMath: subtraction overflow");
    });
  });
```

## Recommendations

```diff
  function redeem(
(...)
-   _baseOut = _state.redeem(_fTokenIn, _xTokenIn);
+   if (_state.xNav == 0) {
+     require (_xTokenIn == 0, "Undercollateralalized");
+     // only redeem fToken proportionally when under collateral.
+     _baseOut = _fTokenIn.mul( _state.baseSupply).div(_state.fSupply);
+   } else {
+     _baseOut = _state.redeem(_fTokenIn, _xTokenIn);
+   }

(...)

    if (_state.xSupply == 0) {
        // no xToken, treat the nav of xToken as 1.0
        _state.xNav = PRECISION;
	} else {
-		_state.xNav = _state.baseSupply.mul(_state.baseNav).sub(_state.fSupply.mul(_state.fNav)).div(_state.xSupply);
+		uint256 baseSupplyNav = _state.baseSupply.mul(_state.baseNav);
+		uint256 fSupplyNav = _state.fSupply.mul(_state.fNav);
+		if (baseSupplyNav <= fSupplyNav) {
+			_state.xNav = 0;
+		} else {
+			_state.xNav = baseSupplyNav.sub(fSupplyNav).div(_state.xSupply);
+		}
	}
```



# [M-01] Minting of `fToken` and `xToken` allowed during stability mode

_Resolved_

## Severity

**Impact:** Medium  

**Likelihood:** Medium  

## Description

The `Market.mint()` function mints both fToken and xToken [based on the current collateral ratio](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/blob/main/contracts/f(x)/math/FxLowVolatilityMath.sol#L293-L307).  
In the original Aladdin implementation, this function could be called only once. However, RegnumFx [removed this restriction](https://github.com/RegnumAurumAcquisitionCorp/fx-contracts/compare/bbb461cba879349c24c02d87872e93ec0a1a1975...f6e865df2dd46d67a49391d94e54b26e6a8af43c#diff-2c8d19ba3d13b72d110c2a9536e5e9915118ad919b38848357200e91afb683faL252), allowing it to be called multiple times.

When the system enters stability mode, the collateral ratio has fallen below the defined safe threshold. This indicates that additional base tokens need to be deposited to restore the ratio.

Allowing `mint()` during stability mode worsens the problem: each new mint increases the number of fTokens in circulation, which in turn raises the amount of base tokens required to bring the system back to a healthy state. As a result, recovery becomes more difficult, and the system may remain undercollateralized for longer.

The severity chosen for this issue is medium, because only whitelisted managers can use the function, and they are trusted entities that are not interested in making stablecoin depeg.

## Recommendations

Restrict `mint()` from being called when the system is in stability mode to prevent further dilution of collateralization and to simplify recovery.

