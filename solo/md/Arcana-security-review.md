# Arcana protocol security review by pashov

***review commit hash* - [51fc65fdd6474c9632975294c560ddee24135f2f](https://github.com/Prominence-Games/arcana-foundry-erc721a/tree/51fc65fdd6474c9632975294c560ddee24135f2f)**

**Scope: `ArcanaPrime.sol`**

---

# [H-01] There is no way to withdraw the ETH paid by minters

## Proof of Concept

There is currently no possible way for the contract deployer/owner to withdraw the ETH that was paid by miners. This means that value will be stuck & lost forever.
This is also the case for the `ERC721A` standard, which this project actually extends as well, but it was verified in a conversation with the developer that the `ArcanaPrime` contract is expected to be used as-is, without a need for inheritance/extension.

## Impact

This will mean hundreds of thousands of dollars (since `MAX_SUPPLY = 10_000` and `MINT_PRICE = 0.08 ether`) will be irretrievable, essentially drying the runway of the NFT project, so it is High severity.

## Recommendation

Add a method to withdraw the value in the contract, for example
```solidity
  function withdrawBalance() external onlyOwner {
    (bool success, ) = msg.sender.call{value: address(this).balance}("");
    require(success);
  }
```

# [M-01] If address is a smart contract that can't handle ERC721 tokens they will be stuck after a whitelisted mint

## Proof of Concept

The `mintPublic` method has a check that allows only EOAs to call it
```solidity
if (tx.origin != msg.sender) revert ContractsNotAllowed();
```
but it is missing in the whitelisted mint methods (`mintArcanaList`, `mintAspirantList`, `mintAllianceList`). This means that if the address that is whitelisted is a contract and it calls those functions but it can't handle ERC721 tokens correctly, they will be stuck. This problem is usually handled by using `_safeMint` instead of `_mint` but all `mint` functionality in `ArcanaPrime` uses `_mint`.

## Impact

This can result in a user losing his newly minted tokens forever, which is a potential values loss. It requires the user to be using a smart contract that does not handle ERC721 properly, so it is Medium severity.

## Recommendation

In `mintArcanaList`, `mintAspirantList` and `mintAllianceList` change the `_mint` call to `_safeMint`. Keep in mind this adds a reentrancy possibility, so it is best to add a `nonReentrant` modifier as well.


# [L-01] Usage of `ecrecover` should be replaced with usage of OpenZeppelin's `ECDSA` library

[Signature malleability](https://swcregistry.io/docs/SWC-117) is one of the potential issues with ecrecover. Even though it is not a threat to the current implementation using the highest security standards is always good. `ECDSA` is already imported, but not actually used. Replace the usage of `ecrecover` with the `ECDSA.recover` functionality.

# Gas optimisation report

## [G-01] Remove pausability as it is not useful

The pausability functionality (the `isNotPaused` modifier and the `togglePause` method) behaves the same way as if you just use the `setCurrentPhase` method with `Phases.Closed`. Using only the latter will save a lot of storage reads. 

## [G-02] Remove `public` visibility from `constant` variables

`constant` variables are custom to the contract and won't need to be read on-chain - anyone can just see their values from the source code and, if needed, hardcode them into other contracts. Removing the `public` visibility will optimise deployment cost since no automatically generated getters will exist in the bytecode of the contract.

## [G-03] Use `external` instead of `public` for functions not called internally

Functions that are `external` always read their arguments directly from `calldata` without a need to copy them to `memory`, which results in gas savings. Do this for the following methods:
- `transferFrom`
- `safeTransferFrom` (both overrides)
- `setOperatorFilteringEnabled`
- `approve`
- `setApprovalForAll`
- `repeatRegistration`
- `registerCustomBlacklist`

## [G-04] Remove `nextStartTime` storage variable and setter as it is not mandatory

Remove both the `nextStartTime` storage variable and the `setNextStartTime` function. If this functionality is still needed, move it off-chain.