# About
 Pashov Audit Group consists of multiple teams of some of the best smart contract security researchers in the space. Having a combined reported security vulnerabilities count of over 1000, the group strives to create the absolute very best audit journey possible - although 100% security can never be guaranteed, we do guarantee the best efforts of our experienced researchers for your blockchain protocol. Check our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).
# Disclaimer
 A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.
# Introduction
 A time-boxed security review of the **agora-finance/contracts** repository was done by **Pashov Audit Group**, with a focus on the security aspects of the application's smart contracts implementation.
# About Agora Access Control
 Agora Access Control contracts provide a modular, role-based permission system with support for multiple managers, upgradeable proxies, and strict access verification. They include components for managing roles (`AgoraAccessControl`), executing arbitrary calls (`AgoraAccessControlWithExecutor`), handling upgradeable proxy logic and access (`AgoraProxyAdmin`, `AgoraTransparentUpgradeableProxy`), and exposing low-level storage slot access for ERC-1967 proxy admin and implementation addresses (`Erc1967Implementation`).

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
 _review commit hash:_
- [4f1387699378ff67e8d4bf29bd853184c86d1216](https://github.com/agora-finance/contracts/tree/4f1387699378ff67e8d4bf29bd853184c86d1216)


### Scope

The following smart contracts were in scope of the audit:

- `AgoraAccessControl` 
- `AgoraAccessControlWithExecutor` 
- `AgoraProxyAdmin` 
- `AgoraTransparentUpgradeableProxy` 
- `Erc1967Implementation` 

# Findings
 # [L-01] Manager revocation front-running keeps unauthorized access possible

The public `assignRole` function in `AgoraAccessControl.sol` allows any existing manager to both add and remove the manager role in one atomic call, with only a guard against removing the *last* manager. A malicious manager (M₂) can exploit two front‐running vectors:

1. **Revocation Front‐run**
   M₂ sees M₁’s pending revocation of M₂ and front‐runs it by revoking M₁ first. This causes M₁’s revocation tx to revert the moment it executes (because M₁ is no longer a manager code line 52), leaving M₂ as manager.
2. **Reassignment Front‐run**
   Before any attempt to remove M₂ occurs, M₂ can preemptively call `assignRole` to grant the `ACCESS_CONTROL_MANAGER_ROLE` to a fresh address (M₃). Even if later M₂ is revoked, M₃ remains a manager—effectively evading removal.

```solidity
50: function assignRole(string memory _role, address _newAddress, bool _addRole) public virtual {
51:     // Checks: Only Admin can transfer role
52:@>   _requireIsRole({ _role: ACCESS_CONTROL_MANAGER_ROLE, _address: msg.sender });
53:
54:@>   _assignRole({ _role: _role, _newAddress: _newAddress, _addRole: _addRole });
55:@>   if (
56:         bytes(_role).length == bytes(ACCESS_CONTROL_MANAGER_ROLE).length &&
57:         keccak256(bytes(_role)) == keccak256(bytes(ACCESS_CONTROL_MANAGER_ROLE)) &&
58:         _getPointerToAgoraAccessControlStorage().roleMembership[_role].length() == 0
59:     ) revert CannotRemoveLastManager();
60: }
```

* At **line 52**, the contract checks the caller holds the manager role.
* At **line 54**, it performs either an add or remove.
* The guard at **lines 55–59** only prevents *removing the final manager*, but does not stop reassignment to a new address.

Consider the following scenario:

1. **Initial state:** `managers = [M₁, M₂]`.
2. M₁ submits tx (pending):
   ```solidity
   assignRole("ACCESS_CONTROL_MANAGER_ROLE", M₂, false);
   ```
3. **Reassignment Front‐run:** M₂ preempts with:
   ```solidity
   assignRole("ACCESS_CONTROL_MANAGER_ROLE", M₃, true);
   ```
   * After tx: `managers = [M₁, M₂, M₃]`.
4. Transaction from step 2 is executed:
   ```solidity
   assignRole("ACCESS_CONTROL_MANAGER_ROLE", M₂, false);
   ```
   * After tx: `managers = [M₁, M₃]`.
5. **Result:** M₂ remains a manager and has a co‐manager M₃ under its control—evading any removal attempt.

Recommendations:
Disallow granting the manager role to any address for the "reassignment front-run" problem. For the "Revocation Front-run" problem, I consider it's best to not allow instant revocation between managers and to have a better mechanism for manager roles.


