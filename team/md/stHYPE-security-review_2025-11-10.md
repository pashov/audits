
# About Pashov Audit Group


Pashov Audit Group consists of 40+ freelance security researchers, who are well proven in the space - most have earned over $100k in public contest rewards, are multi-time champions or have truly excelled in audits with us. We only work with proven and motivated talent.

With over 300 security audits completed — uncovering and helping patch thousands of vulnerabilities — the group strives to create the absolute very best audit journey possible. While 100% security is never possible to guarantee, we do guarantee you our team's best efforts for your project. 

Check out our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).
    

# Disclaimer


A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.


# Introduction

<p>A time-boxed security review of the <strong>ValantisLabs/sthype-contracts</strong> repository was done by Pashov Audit Group, during which <strong>Shurikenzer, 0xAlix2, 0xunforgiven</strong> engaged to review <strong>stHYPE</strong>. A total of <strong>4</strong> issues were uncovered.</p>

# About stHYPE

<p>stHYPE is a Liquid Staking Protocol built for Hyperliquid HyperEVM that allows users to stake native HYPE tokens and receive stHYPE, a liquid staking derivative that accrues rewards while remaining tradable. It features modular staking through the Overseer contract, a rebasing stHYPE token, and a wrapped non-rebasing wstHYPE version for DeFi integrations.</p>

# Security Assessment Summary

**Review commit hash:**<br>• [0661f1972e3d02fcd923d1584022db5fa4ad621f](https://github.com/ValantisLabs/sthype-contracts/tree/0661f1972e3d02fcd923d1584022db5fa4ad621f)<br>&nbsp;&nbsp;(ValantisLabs/sthype-contracts)

**Fixes review commit hash:**<br>• [0478fc5a8a62da4f8e46ca0ef0d4030e4723abbe](https://github.com/ValantisLabs/sthype-contracts/tree/0478fc5a8a62da4f8e46ca0ef0d4030e4723abbe)<br>&nbsp;&nbsp;(ValantisLabs/sthype-contracts)




# Scope

- `StakingModuleExternalManagement.sol`

# Findings



# [L-01] `StakingModuleExternalManagement` does not expose `depositCap` and `amountDeposited`

_Resolved_

`StakingModuleExternalManagement` defines internal storage variables `depositCap` and `amountDeposited` but does not provide any public or external getter functions for them.

**Recommendations:**
Consider adding view functions to expose both fields.



# [L-02] ExternalManagement module uses the same storage slot as HyperCore StakingModule

_Resolved_

`StakingModuleExternalManagement` defines its storage under the same ERC-7201 namespace (`"stHYPE.storage.StakingModule"`) that is also used by `HyperCoreStakingModule`. 
This violates EIP-7201’s requirement that each namespace must avoid collisions with others.

**Recommendations:**

Consider using a unique namespace for `StakingModuleExternalManagement`, to maintain proper storage isolation.



# [L-03] Rebase does not have protection for sudden balance drops

_Acknowledged_

Even though the stake account is trusted, sometimes the `rebase()` call might be delayed and run when the account’s balance isn’t up to date.
This could make the system think the balance dropped a lot (for example, N%) when it really didn’t, and mess up the rebase math.
in `Overseer.sol`:
```solidity
function rebase() external onlyRole(REBASER) {
    ...
    uint256 newSupply = getNewSupply();
    ...
}
```

`getNewSupply()` aggregates balances from all staking modules:
```solidity
    function getNewSupply() public view returns (uint256) {
        ...
            totalBalance += IStakingModule(stakingModule).getTotalBalance();
        ...
    }
```

And in `StakingModuleExternalManagement.sol`, `getTotalBalance()` depends on the external `stakeAccount`, which may not always reflect the correct current balance:
```solidity
    function getTotalBalance() external view override returns (uint256) {
        address stakeAccount = _getStakingModuleStorage().stakeAccount;
        // WARNING: This will be temporarily incorrect if either:
        // - stake account has not deposited the received HYPE into its staking balance (see `deposit()`)
        // - the stake account's stake balance has been unstaked into spot balance,
        //   but not yet sent to this contract's HyperCore spot balance (see `requestWithdraw()`)
        // It is important that `manager` (Overseer) does not call `rebase()` in these scenarios,
        // so that stHYPE supply does not get adjusted incorrectly.
        return address(this).getHypeSpotBalance() * E10 + address(this).balance
            + stakeAccount.getHypeStakingBalance() * E10;
    }
```
Recommendation:
Add a check that stops the rebase if the balance suddenly drops too much, unless the manager manually allows it with a special flag.



# [L-04] `amountDeposited` is never decremented, blocking new deposits

_Acknowledged_

In `deposit()`, the module increases `_getStakingModuleStorage().amountDeposited` by the deposited amount, but never decreases it when funds are withdrawn. Because the deposit cap check compares against the cumulative total, once the cap is reached, all future deposits will revert, even if the manager has withdrawn funds.

```solidity
if (_getStakingModuleStorage().amountDeposited + amountEvm > _getStakingModuleStorage().depositCap) {
    revert StakingModuleExternalManagement__deposit_ExceedsDepositCap();
}

// Update the amount deposited (measured in EVM decimals)
_getStakingModuleStorage().amountDeposited += amountEvm;
```

This behavior effectively locks the module from accepting new deposits after reaching the cap, even though capacity may be available again. 

**Recommendations**

Consider decrementing the `amountDeposited` whenever a withdrawal is fulfilled.

