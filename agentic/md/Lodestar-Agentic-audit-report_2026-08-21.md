# Lodestar Agentic Security Review

**Pashov Audit Group**  
August 21st 2026

## Executive Summary

A security review of Lodestar was conducted entirely by Pashov Audit Group's agentic auditing system. This report documents 7 issues across the reviewed codebase.

| | |
| --- | --- |
| Project | Lodestar |
| Repository | github.com/lodestarprotocol/lodestar - main - c1bd24a |

## Scope

**Reviewed commit:** `c1bd24a` on `main` - the last commit touching `src/`; `git diff c1bd24a..main -- src/` is empty and the scope is frozen for the engagement.

**In scope** (1,199 nSLOC / 2,146 lines incl. comments):

- `src/LodestarLoanBook.sol` - 835
- `src/LodestarPool.sol` - 161
- `src/LodestarOracle.sol` - 133
- `src/flare/*.sol` and `src/interfaces/*.sol` - 70

**Out of scope:** `web/`, `webapp/`, `script/`, `test/`, and the off-repo keeper.

**Build:** Solidity 0.8.28, OpenZeppelin 5.1.0, Foundry (optimizer 200, `via_ir = true`).

**Tests:** 373 unit tests plus 27 fork tests (Flare + Coston2), all green.

## About

Pashov Audit Group is a security research collective focused on smart-contract and protocol security. This report documents the issues surfaced during a security review conducted entirely by Pashov Audit Group's agentic auditing system.

**Methodology**

This security review was conducted entirely by Pashov Audit Group's agentic auditing system, which reviewed the in-scope code and reported the issues it found. Each issue was then triaged and validated, with duplicates merged and severities finalized. Every accepted issue appears below with its impact and a recommended remediation. The client's response to each issue was then reviewed, and its resolution status - fixed, acknowledged, or invalidated - is recorded with the finding.

**Disclaimer**

A security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where our agentic auditing system tries to find as many issues as possible. We can not guarantee 100% security after the review. Subsequent reviews, bug bounty programs and on-chain monitoring are strongly recommended. The client's remediation of each issue was reviewed after the audit; the outcome is recorded in the finding's Resolution section.

## Risk Classification

| Severity | Description |
| --- | --- |
| Critical | Loss or compromise of critical assets, or protocol-wide impact. Must be fixed before launch. |
| High | Significant material loss of assets, or serious harm to a group of users. |
| Medium | Moderate material loss, or moderate harm, often under conditional assumptions. |
| Low | Minor impact, limited scope, or requires unlikely conditions to trigger. |
| Info | No direct security impact - best-practice, code-quality or hardening suggestion. |

## Findings

### Medium Severity

#### [M-01] Changing an LST rate provider retroactively invalidates openRate snapshots

**Severity:** Medium · **Status:** Fixed

**Location:** `LodestarOracle:setFeed:92-100`

**Summary**

Each loan snapshots the collateral's opening rate in `openRate` so that only appreciation after opening is subject to the configured yield skim. Repayment must therefore compare a live rate that is measured on the same basis as that snapshot.

`setFeed` lets an admin replace a token's rate provider while loans opened under the old provider still hold their old `openRate`. Repayment and partial-release paths then call `oracle.rateOf`, which reads the new provider, and compare it directly against the stale snapshot. Clearing the oracle's rate clamp does not fix the loan-level snapshot.

For example, a loan opened at `openRate = 1.05e18` under provider A is later evaluated against provider B returning `1.20e18` on a different basis. `_returnCollateralPortion` treats the full `1.20e18 - 1.05e18` difference as post-opening yield even though it is not.

**Impact**

After a rate-provider migration, appreciation on open loans can be over- or under-counted depending on how the new provider's basis relates to the old one.

Borrowers may lose excess collateral to the reserve, or the reserve may collect less than its configured skim.

**Exploit Path**

1. A borrower opens an sFLR loan while provider A returns `1.05e18`, stored as `openRate`.
2. An admin replaces the feed's rate provider with provider B, which returns `1.20e18` on a different accounting basis.
3. The loan is repaid or partially repaid; `_returnCollateralPortion` computes gain from `1.20e18 - 1.05e18`.
4. The reserve receives an incorrect skim and the borrower receives an incorrect net collateral amount.

**Prerequisites**

Triggered by a normal administrative provider migration via `setFeed`; no attacker setup is required, but it only affects loans that were open before the migration.

**Recommendation**

Block provider changes while active loans exist for the token:

```solidity
if (activeLoanCountForToken[token] != 0 && feeds[token].rateProvider != rateProvider) {
    revert ActiveLoans();
}
```

Alternatively, version the feed and snapshot that version in each loan, then skip or specially migrate the skim whenever a loan's provider version differs from the current feed version.

**Resolution — Fixed**

Fixed in commit `f3e83c5` - the second pass, after the initial partial fix.

---

#### [M-02] Gross impairment can orphan reserve-backed recovery after lender exits

**Severity:** Medium · **Status:** Fixed

**Location:** `LodestarLoanBook:_markLoanRaise:1718-1734`

**Summary**

Impairment is meant to reduce lender NAV only for the portion of an active loan that is not expected to be recovered, while keeping a coherent ownership claim over any later repayment or first-loss reserve coverage. Reserve capital is held separately in the LoanBook and applied only during settlement, so the pool must account for that delayed recovery consistently with its share supply.

Instead, the implementation marks the gross collateral shortfall directly against pool NAV. `totalAssets()` subtracts `impairedLoss` but has no corresponding asset or claim for `reserveBalance`. Withdrawals only require fresh impairment synchronization and sufficient idle liquidity, so all remaining shares can be redeemed while the impaired loan is still open.

When settlement later calls `_clearImpairment()` and `_distribute()`, the pool receives the recovery after the shares that absorbed the impairment may already have been burned, leaving that recovery without the intended lender ownership.

**Impact**

Reserve-backed recovery can arrive after all lender shares have been redeemed, leaving recovered assets in a shareless pool with no ownership record. This can trap or misallocate protocol funds.

**Exploit Path**

1. A collateral crash causes `impair(id)` to mark an active loan's expected loss up to approximately its full principal.

2. `LodestarPool.totalAssets()` falls by that impairment, while the LoanBook's separate reserve remains available but unrepresented in pool NAV.

3. Lenders call `withdraw` or `redeem`; synchronization succeeds and idle liquidity is sufficient, so their shares are burned.

4. A later `buyout` or `settleSwap` clears the impairment and transfers repayment or reserve coverage to the pool, but the exited lender cohort holds no shares representing that recovery.

**Recommendation**

Include the reserve claim in the pool's impairment accounting before allowing exits, capping the claim by the reserve actually available for the loan:
```solidity
uint256 reserveClaim = loanBook.reserveCoverage(id, newLoss);
uint256 netLoss = newLoss > reserveClaim ? newLoss - reserveClaim : 0;
```
Alternatively, prohibit full share exit while impaired loans with unclaimed reserve-backed recovery remain outstanding, or maintain a separate recovery-credit ledger that follows the lender shares and is settled when the loan closes.

**Resolution — Fixed**

Fixed by the client.

---

#### [M-03] Loan origination bypasses the impairment checkpoint used by utilization limits

**Severity:** Medium · **Status:** Acknowledged

**Location:** `LodestarPool:disburse:167-176`

**Summary**

The utilization ceiling is meant to limit new lending against the pool's current risk-adjusted assets, including losses already observable from the live oracle. New originations should not consume liquidity based on a stale, pre-impairment denominator.

When a loan is opened, `_open` prices only the new collateral and then calls `pool.disburse`. `disburse` reads `totalAssets()`, but that value subtracts only the stored `impairedLoss`; it does not derive or refresh losses from current oracle prices. An existing underwater loan therefore stays fully counted until a separate permissionless synchronization runs.

As a result, a new borrower can be funded while the denominator is stale-high. Once impairment is later synchronized, the pool's utilization jumps relative to its now-lower asset base, showing the origination never enforced the configured limit against current state.

**Impact**

The max-utilization control can be bypassed in the window between a collateral price deterioration and the next impairment synchronization.

Extra stable is lent while the pool's current risk-adjusted asset base is overstated, leaving the pool more utilized and less liquid than its configured risk limit permits.

**Exploit Path**

1. Loan A is active and healthy, with `pool.impairedLoss` recorded as zero.

2. Loan A's collateral price falls enough that `_markLoanRaise` would record a loss, but no impairment synchronization has happened yet.

3. A borrower opens loan B; `_open` calls `pool.disburse` without synchronizing loan A, so utilization is checked against the stale-high `totalAssets()`.

4. A later `impair` or exit sweep marks loan A's loss, leaving the pool above its configured utilization ratio after loan B has already drained additional idle liquidity.

**Recommendation**

Refresh impairment before the utilization check, preferably through a dedicated LoanBook-to-Pool synchronization hook:

```solidity
function disburse(address to, uint256 net, uint256 principal)
    external
    onlyLoanBook
{
    ILoanBookSync(msg.sender).syncImpairment();
    uint256 ta = totalAssets();
    if ((principalOut + principal) * 10_000 > ta * maxUtilizationBps)
        revert OverUtilized();
    // update principalOut and transfer funds
}
```

If strict oracle availability is required for risk checks, use the strict synchronization variant and revert origination when the active book cannot be freshly priced, rather than permitting a stale utilization decision.

**Resolution — Acknowledged**

Acknowledged. The finding is unreachable once `totalAssets` clears `sum(exposureCaps) * 10000 / maxUtilizationBps`, which holds at the launch caps; that bound is pinned in CI so it cannot reopen silently.

---

#### [M-04] Reserve losses do not reduce the contributed-capital floor

**Severity:** Medium · **Status:** Fixed

**Location:** `LodestarLoanBook:_distribute:1238-1248`

**Summary**

The reserve floor is meant to track the remaining externally contributed first-loss capital, while fee and penalty income above that floor is protocol-owned surplus that the owner can withdraw. When a settlement shortfall consumes reserve funds, the contributed portion should shrink before any protocol surplus is treated as at risk.

The settlement waterfall only reduces the aggregate balance and clamps the floor to that balance:

```solidity
reserveBalance -= cover;
if (reserveFloor > reserveBalance) reserveFloor = reserveBalance;
```

With a balance of 200, a floor of 100, and a 50-unit loss, this leaves a balance of 150 and a floor still at 100. The loss silently consumed 50 units of protocol surplus, but the floor never dropped to 50 to reflect it.

**Impact**

Settlement losses permanently overstate how much reserve capital is protected from owner withdrawal. This locks protocol-owned surplus behind an inflated floor and leaves reserve accounting inconsistent with the documented first-loss waterfall.

The issue arises during normal settlement whenever surplus exists above contributed reserve capital, with no attacker required, and causes `withdrawReserve` to reject otherwise legitimate withdrawals.

**Exploit Path**

1. Call `fundReserve(100)`, then accrue 100 units of fee or penalty income, so `reserveBalance = 200` and `reserveFloor = 100`.

2. Settle a defaulted loan whose waterfall has a 50-unit uncovered principal gap.

3. `_distribute` transfers 50 reserve units to the pool but leaves `reserveFloor` at 100.

4. The owner calls `withdrawReserve(100)` and it reverts, because the code still requires 100 units to remain protected instead of 50.

**Recommendation**

Decrease the floor by the reserve loss consumed:

```solidity
reserveBalance -= cover;
reserveFloor = reserveFloor > cover ? reserveFloor - cover : 0;
```

If a different loss-priority model is intended, maintain separate contributed and protocol-surplus balances and update both explicitly during `_distribute`.

**Resolution — Fixed**

Fixed by the client.

---

#### [M-05] Withdrawals can consume cash backing unvested fees

**Severity:** Medium · **Status:** Fixed

**Location:** `LodestarPool:totalAssets:111-126; LodestarPool:withdraw:227-236; LodestarPool:redeem:238-247`

**Summary**

The pool holds fee income but intentionally excludes it from lender asset value until it vests. The idle stable cash backing that `lockedFee` must be preserved until vesting completes, otherwise the deferred accounting no longer has real cash behind it.

The withdrawal guard uses the entire token balance through `available()` and never reserves `unvestedFee()`. A permitted withdrawal can therefore leave `balanceOf(pool) < unvestedFee()`. The next `totalAssets()` call clamps the fee deduction to whatever balance is left:

```solidity
uint256 uf = unvestedFee();
if (uf > bal) uf = bal;
if (uf >= net) return net;
return net - uf;
```

Once the backing cash is gone, `uf` is clamped down and the missing portion of the fee appears earned before it has vested.

**Impact**

Remaining lenders and later entrants receive distorted share pricing because unvested fee income is counted as earned once its idle stable backing has been withdrawn.

This is a real share-accounting inconsistency that transfers deferred fee value into current share valuation, and it can be triggered through ordinary withdrawals.

**Exploit Path**

1. A pool with 300 idle stable and 800 principalOut receives a 100-unit fee recorded as unvested via `lockFee(100)`.
2. Before vesting completes, a lender withdraws 300 units; the check passes because `assets <= available()` and `available()` returns the full 300.
3. The pool balance becomes zero while `unvestedFee()` still reports 100.
4. `totalAssets()` computes `net = 800`, clamps `uf` to zero, and reports 800 instead of 700, folding the deferred fee into the remaining share valuation.

**Recommendation**

Reserve the outstanding fee lock from exit liquidity:

```solidity
function available() public view returns (uint256) {
    uint256 bal = IERC20(asset()).balanceOf(address(this));
    uint256 uf = unvestedFee();
    return bal > uf ? bal - uf : 0;
}
```

Alternatively, enforce the same invariant directly in `withdraw()` and `redeem()` by requiring the post-withdrawal balance to remain at least `unvestedFee()`. Changing the shared `available()` helper is less error-prone since both exit paths already rely on it.

**Resolution — Fixed**

Fixed by the client.

---

### Low Severity

#### [L-01] Haircuted oracle price can reject honest settlement proceeds

**Severity:** Low · **Status:** Fixed

**Location:** `LodestarLoanBook:settleSwap:1237-1244; LodestarOracle:priceUsd18:212-219`

**Summary**

The proceeds sanity check in `settleSwap()` is meant to reject implausibly large stable balance deltas while allowing an honest sale at roughly market value. The problem is that the oracle already applies the collateral haircut before returning `priceUsd18`, and the loan book caches that haircuted result in `lastPrice18`.

A haircut is a risk-management discount for underwriting and recovery math; it does not mean the collateral cannot sell for its full unhaircuted market value. Because `settleSwap()` multiplies the already-haircuted price by 1.5 to build `saneMax`, the haircut is effectively applied a second time to the market-value ceiling.

With a 50% permitted haircut, a normal sale at true market value exceeds the resulting 75%-of-market ceiling and reverts with `ProceedsTooHigh`.

**Impact**

Legitimate DEX settlements revert with `ProceedsTooHigh` when the collateral carries a substantial conservative haircut, even though the router returned honest proceeds.

This is a liveness failure under valid configuration: it can force users toward the separate buyout path or delay default resolution, reducing settlement liveness.

**Exploit Path**

1. Configure a collateral feed with `haircutBps = 5000`, where the unhaircuted market value of the sale amount is 1,000 USDT.
2. The oracle returns and caches a haircuted value of 500 USDT.
3. `settleSwap()` computes `saneMax = 500 * 150% = 750 USDT`.
4. The whitelisted router honestly returns 1,000 USDT, but the function reverts because proceeds exceed the haircuted ceiling.

**Recommendation**

Expose an unhaircuted market-price value for the sanity check while keeping the haircuted value for risk accounting.

```solidity
function marketPriceUsd18(address token) external view returns (uint256) {
    return _rawPriceUsd18(token);
}
```

```solidity
uint256 p18 = oracle.marketPriceUsd18(L.collateral);
uint256 saneMax =
    (_usd18ToStable((p18 * toSell) / _unit(L.collateral)) * 15_000) / 10_000;
if (proceeds > saneMax) revert ProceedsTooHigh();
```

**Resolution — Fixed**

Fixed in commit `f3e83c5` - the second pass, after the initial partial fix.

---

#### [L-02] previewRedeem can overstate proceeds before mandatory impairment synchronization

**Severity:** Low · **Status:** Fixed

**Location:** `LodestarPool:previewRedeem/redeem:132-158, 250-255`

**Summary**

`previewRedeem` is inherited unchanged from ERC-4626, so it reads `totalAssets()` directly without running the loan-book impairment synchronization that the real redemption path performs.

`redeem()` calls `syncImpairmentForExit()` before pricing shares. That call can raise `impairedLoss` and reduce `totalAssets()` for underwater loans, but the preview never sees this reduction.

As a result, a quote taken just before redemption can report more assets than the redemption actually returns whenever a fresh collateral crash has not yet been marked.

**Impact**

Lenders, routers, and integrators can receive a redemption quote higher than the amount they actually get back after impairment is swept in.

Transactions that depend on the preview for minimum-output checks or downstream accounting can fail or proceed on materially stale assumptions during a collateral crash. This causes mis-sized or failed exits rather than direct unauthorized value extraction.

**Exploit Path**

1. A pool holds active loans whose collateral has fallen below recovery value, but `impairedLoss` has not yet been raised.
2. A lender calls `previewRedeem(shares)`, which converts shares using the higher pre-synchronization `totalAssets()`.
3. The lender calls `redeem()` with a live oracle; `syncImpairmentForExit()` raises `impairedLoss` for the underwater loans.
4. `super.redeem()` prices shares against the reduced `totalAssets()`, returning fewer stable assets than the earlier preview reported.

**Recommendation**

Make the preview apply the same impairment model as the redemption path, either through a view-only simulation or a synchronized quote path whose result `redeem` uses:

```solidity
function previewRedeem(uint256 shares) public view override returns (uint256) {
    uint256 loss = loanBook.previewImpairment();
    uint256 assets = totalAssets() - loss;
    return _convertToAssets(shares, Math.Rounding.Floor, assets);
}
```

This requires the loan book to expose a view-only `previewImpairment()` that reproduces `_markLoanRaise` without storage writes. If that simulation is too expensive, provide an explicit synchronized quote transaction or clearly document that integrations must tolerate the mandatory pre-redemption revaluation.

**Resolution — Fixed**

Fixed in commit `f3e83c5` - the second pass, after the initial partial fix.

---

