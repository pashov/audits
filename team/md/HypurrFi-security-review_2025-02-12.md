# About

Pashov Audit Group consists of multiple teams of some of the best smart contract security researchers in the space. Having a combined reported security vulnerabilities count of over 1000, the group strives to create the absolute very best audit journey possible - although 100% security can never be guaranteed, we do guarantee the best efforts of our experienced researchers for your blockchain protocol. Check our previous work [here](https://github.com/pashov/audits) or reach out on Twitter [@pashovkrum](https://twitter.com/pashovkrum).

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where we try to find as many vulnerabilities as possible. We can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# Introduction

A time-boxed security review of the **lastdotnet/hypurrfi-deployments** repository was done by **Pashov Audit Group**, with a focus on the security aspects of the application's smart contracts implementation.

# About HypurrFi

HypurrFi is a leveraged lending marketplace on Hyperliquid, enabling clean leverage loops while maintaining spot positions on native assets like HYPE and stHYPE. Its stablecoin, $USDXL, is backed by protocol revenue and a growing reserve of tokenized U.S. Treasuries.

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

_review commit hashes:_

- [2509ece7be02e22c1db54e2238ba4c1715ca2bae](https://github.com/lastdotnet/hypurrfi-deployments/commit/2509ece7be02e22c1db54e2238ba4c1715ca2bae)
- [2490d3ca12a081a8c49981935c2b11eddcb5d519](https://github.com/lastdotnet/usdxl-core/commit/2490d3ca12a081a8c49981935c2b11eddcb5d519)

_fixes review commit hashes:_

- [a049c7dcad5ce0c9af0f9f369b984023d324bd9b](https://github.com/lastdotnet/usdxl-core/commit/a049c7dcad5ce0c9af0f9f369b984023d324bd9b)
- [df0d50f3a37f3c199214b6c1e460e390a7a03e17](https://github.com/lastdotnet/hypurrfi-deployments/commit/df0d50f3a37f3c199214b6c1e460e390a7a03e17)

### Scope

The following smart contracts were in scope of the audit:

- `ConfigurrHyFiReservesMainnet`
- `ConfigurrHyFiReservesTestnet`
- `DeployCapAutomator`
- `DeployHyFi`
- `DeployWHYPE`
- `SupplyHyFi`
- `TransferOwnership`
- `USDfSilo`
- `HyperTestnetReservesConfigs`
- `DeployHyFiUtils`
- `DeployUtils`
- `BorrowUsdxlHyperTestnet`
- `DeployUsdxlGsmHyperTestnet`
- `DeployUsdxlHyperTestnet`
- `RepayUsdxlHyperTestnet`
- `HyperTestnetReservesConfigs`
- `DeployUsdxlFileUtils`
- `DeployUsdxlUtils`

# Findings

# [H-01] `DeployUsdxlUtils` does not transfer ownership of usdxlToken to `admin`

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

The `_deployUsdxl` function, deploys usdxlTokenProxy and sets `deployer` as the owner of `usdxlToken`

```solidity
    function _deployUsdxl(address proxyAdmin, IDeployConfigTypes.HypurrDeployRegistry memory deployRegistry) internal {
        --snip--
        // 1. Deploy USDXL token implementation and proxy
        UpgradeableUsdxlToken usdxlTokenImpl = new UpgradeableUsdxlToken();

        bytes memory initParams = abi.encodeWithSignature("initialize(address)", deployer);

        usdxlTokenProxy = address(new TransparentUpgradeableProxy(address(usdxlTokenImpl), proxyAdmin, initParams));

        usdxlToken = IUsdxlToken(usdxlTokenProxy);

        --snip--
     }
```

But it does not transfer the ownership (admin rights) from `deployer` to `admin`

## Recommendations

Transfer ownership of `usdxlToken` to admin after deployment and config

# [H-02] Deployer does not transfer ownership of `CapAutomator` to admin

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

The function `DeployCapAutomator.run` deploys an instance of `CapAutomator`, assigning `msg.sender` (the `deployer`) as the initial owner. But it does not transfer the ownership to the designated `admin`.

```solidity
    function run() external {
        --snip--
        poolAddressesProvider = IPoolAddressesProvider(deployedContracts.readAddress(".poolAddressesProvider"));

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));

        capAutomator = new CapAutomator(address(poolAddressesProvider));

        vm.stopBroadcast();
        --snip--
    }
```

```solidity
contract CapAutomator is ICapAutomator, Ownable {
    --snip--
    constructor(address poolAddressesProvider) Ownable(msg.sender) {
        pool             = IPool(IPoolAddressesProvider(poolAddressesProvider).getPool());
        poolConfigurator = IPoolConfigurator(IPoolAddressesProvider(poolAddressesProvider).getPoolConfigurator());
    }
```

## Recommendations

Transfer ownership of `capAutomator` to `admin` after deployment.

# [H-03] Incorrect proxy address tracking misconfigures USDXL pool tokens

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

The `DeployUsdxlUtils._getUsdxlATokenProxy()` and `DeployUsdxlUtils._getUsdxlVariableDebtTokenProxy()` functions incorrectly return implementation contract addresses instead of proxy addresses.

```solidity
//File: src/deployments/utils/DeployUsdxlUtils.sol

function _getUsdxlATokenProxy() internal view returns (address) {
    return address(usdxlAToken);    // Returns implementation instead of proxy
}

function _getUsdxlVariableDebtTokenProxy() internal view returns (address) {
    return address(usdxlVariableDebtToken); // Returns implementation instead of proxy
}
```

This causes four main issues:

1. Incorrect contract exports in deployment artifacts in the `_initializeUsdxlReserve()` function.
2. Incorrect token configurations in the `_setUsdxlAddresses()` function, leaving the USDXL pool's `AToken` and `VariableDebtToken` unconfigured.
3. Incorrect facilitator configurations for the USDXL token in the `_addUsdxlATokenAsEntity()` function.
4. Incorrect discount token and strategy configurations in the `_setDiscountTokenAndStrategy()` function.

## Recommendation

Track the actual proxy addresses that are configured in the USDXL pool instead of using implementation addresses. This ensures that token configurations are applied to the correct contract instances that the pool interacts with.

To implement this:

1. Get and track proxy addresses from pool's reserve data after pool initialization:

```diff
function _initializeUsdxlReserve(
    address token,
    IDeployConfigTypes.HypurrDeployRegistry memory deployRegistry
)
    internal
{
    --- SNIPPED ---
    // set reserves configs
    _getPoolConfigurator(deployRegistry).initReserves(inputs);

+   IPoolAddressesProvider poolAddressesProvider = _getPoolAddressesProvider(deployRegistry);
    //@audit DataTypes should be additional imported
+   DataTypes.ReserveData memory reserveData = IPool(poolAddressesProvider.getPool()).getReserveData(token);

    //@audit Introduce new two state variables to track proxy addresses
+   usdxlATokenProxy = UsdxlAToken(reserveData.aTokenAddress);
+   usdxlVariableDebtTokenProxy = UsdxlVariableDebtToken(reserveData.variableDebtTokenAddress);

    // export contract addresses
    DeployUsdxlFileUtils.exportContract(instanceId, "usdxlATokenProxy", _getUsdxlATokenProxy());
    DeployUsdxlFileUtils.exportContract(instanceId, "usdxlVariableDebtTokenProxy", _getUsdxlVariableDebtTokenProxy());
}
```

2. Update getter functions to return proxy addresses:

```diff
function _getUsdxlATokenProxy() internal view returns (address) {
-    return address(usdxlAToken);
+    return address(usdxlATokenProxy);
}

function _getUsdxlVariableDebtTokenProxy() internal view returns (address) {
-    return address(usdxlVariableDebtToken);
+    return address(usdxlVariableDebtTokenProxy);
}
```

3. Update treasury configuration to use proxy:

```diff
function _setUsdxlAddresses(IDeployConfigTypes.HypurrDeployRegistry memory deployRegistry)
    internal
{
-    usdxlAToken.updateUsdxlTreasury(deployRegistry.treasury);
+    UsdxlAToken(_getUsdxlATokenProxy()).updateUsdxlTreasury(deployRegistry.treasury);

    UsdxlAToken(_getUsdxlATokenProxy()).setVariableDebtToken(_getUsdxlVariableDebtTokenProxy());
    UsdxlVariableDebtToken(_getUsdxlVariableDebtTokenProxy()).setAToken(_getUsdxlATokenProxy());
}
```

# [M-01] DeployHyFiConfigEngine: double deployment of `proxyAdmin`

## Severity

**Impact:** Medium

**Likelihood:** Medium

## Description

`DeployHyFiConfigEngine.run` creates a `ProxyAdmin` using `transparentProxyFactory` :

```solidity
    function run() external {
        --snip--
        transparentProxyFactory = new TransparentProxyFactory();
        proxyAdmin = ProxyAdmin(transparentProxyFactory.createProxyAdmin(admin));

        (ratesFactory,) = DeployRatesFactoryLib._createAndSetupRatesFactory(
             poolAddressesProvider, address(transparentProxyFactory), address(proxyAdmin), reservesToSkip);
       --snip--
     }
```

then calls `_createAndSetupRatesFactory` and passes the address of `proxyAdmin` as `ownerForFactory`:

```solidity
    function _createAndSetupRatesFactory(
        IPoolAddressesProvider addressesProvider,
        address transparentProxyFactory,
        address ownerForFactory,
        address[] memory reservesToSkip
    ) internal returns (V3RateStrategyFactory, address[] memory) {
        --snip--
        V3RateStrategyFactory ratesFactory = V3RateStrategyFactory(
            ITransparentProxyFactory(transparentProxyFactory).create(
                address(new V3RateStrategyFactory(addressesProvider)),
                ownerForFactory,
                abi.encodeWithSelector(V3RateStrategyFactory.initialize.selector, uniqueStrategies)
            )
        );
       --snip--
}
```

It calls `ITransparentProxyFactory(transparentProxyFactory).create` and passes the address of `ownerForFactory` (already deployed`proxyAdmin`) as `initialOwner`:
The problem is that `create` function expects the address of owner and deploys its own `adminProxy`:

https://github.com/bgd-labs/solidity-utils/blob/90266e46868fe61ed0b54496c10458c247acdb51/src/contracts/transparent-proxy/TransparentProxyFactoryBase.sol#L29

```solidity
function create(
    address logic,
    address initialOwner,
    bytes calldata data
  ) external returns (address) {
    address proxy = address(new TransparentUpgradeableProxy(logic, initialOwner, data));
    _storeProxyInRegistry(proxy);

    emit ProxyCreated(proxy, logic, initialOwner);

    return proxy;
  }
```

So the pattern will be like:
proxyAdmin(1) > proxyAdmin(2) > transparentProxy > Impl
As a result, the admin will not be able to upgrade the contract.

Note:
`import {ITransparentProxyFactory} from "solidity-utils/contracts/transparent-proxy/interfaces/ITransparentProxyFactory.sol"; `
The code for the above interface is here:
https://github.com/bgd-labs/solidity-utils/blob/main/src/contracts/transparent-proxy/interfaces/ITransparentProxyFactory.sol

## Recommendations

Dont deploy a separate `proxyAdmin` and just pass address of `admin` to `create` function.

# [M-02] `DeployUsdxlUtils`: Wrong setting for mint limits

## Severity

**Impact:** Medium

**Likelihood:** Medium

## Description

Functions `_addUsdxlATokenAsEntity()` and `_addUsdxlFlashMinterAsEntity()` set mint limit as 1B instead of 100mil:

```solidity
   function _addUsdxlATokenAsEntity(IDeployConfigTypes.HypurrDeployRegistry memory deployRegistry)
        internal
    {
        // pull aToken proxy from reserves config
        _getUsdxlToken().addFacilitator(
          address(_getUsdxlATokenProxy()),
          'HypurrFi Market Loans', // entity label
          1e27 // entity mint limit (100mil)
        );
    }

    function _addUsdxlFlashMinterAsEntity(IDeployConfigTypes.HypurrDeployRegistry memory deployRegistry)
        internal
    {
      _getUsdxlToken().addFacilitator(
        address(flashMinter),
        'HypurrFi Market Flash Loans', // entity label
        1e27 // entity mint limit (100mil)
      );
    }
```

## Recommendations

Use 1e26 instead of 1e27 to set it to 100mil

# [M-03] Pool reserves should be initialized and supplied in same transaction

## Severity

**Impact:** High

**Likelihood:** Low

## Description

Currently, for the **HyperEVM testnet**, the pool is initialized with the reserve tokens in the `ConfigurrHyFiReserves` script, and the tokens are supplied in a different script, `SupplyHyFi`. This approach leaves the system vulnerable to a **inflation attack** by the first depositor on an empty reserve.
Ideally, both actions (initializing and supplying reserves) should happen in the same transaction to ensure that the system is correctly configured and cannot be exploited by an attacker who may manipulate the pool before the liquidity is added.

Instances:

- **USDC** and **sUSDe** tokens are supplied to the pool, but their respective reserves are not initialized by any of the deployment scripts as the `ConfigurrHyFiReserves` script only initializes the **KHYPE** token reserves.
- The **KHYPE reserve** is initialized by the `ConfigurrHyFiReserves` script but not supplied with liquidity.

## Recommendations

Update the deployment process so that the pool reserves are both initialized and supplied with a minimum liquidity (seed amount) in the same transaction.

# [M-04] Uncompilable `DeployUsdxlHyperTestnet` script

## Severity

**Impact:** Low

**Likelihood:** High

## Description

The `DeployUsdxlHyperTestnet` script attempts to use `usdxlConfig` for deployment configuration but fails to declare it as a state variable. This causes compilation failures and renders the deployment script unusable.

```solidity
//File: script/DeployUsdxlHyperTestnet.sol

function _deploy() internal {
    vm.setEnv('FOUNDRY_ROOT_CHAINID', vm.toString(block.chainid));
    instanceId = 'hypurrfi-testnet';

    config = DeployUsdxlFileUtils.readInput(instanceId);
@>  usdxlConfig = DeployUsdxlFileUtils.readUsdxlInput(instanceId);  // @audit usdxlConfig not declared
    --- SNIPPED ---

    _deployUsdxl(usdxlConfig.readAddress('.usdxlAdmin'), deployRegistry);  // Fails: usdxlConfig not declared
}
```

## Recommendation

Declare the `usdxlConfig` state variable in the `DeployUsdxlHyperTestnet`.

# [L-01] `DeployUsdxlUtils`: `UsdxlInterestRateStrategy` contract is deployed twice

`DeployUsdxlUtils`: The function `_deployUsdxl` deploys `UsdxlInterestRateStrategy` in step 3 :

```solidity

    function _deployUsdxl(address proxyAdmin, IDeployConfigTypes.HypurrDeployRegistry memory deployRegistry) internal {
        --snip--
          // 3. Deploy USDXL Interest Rate Strategy
        usdxlInterestRateStrategy = new UsdxlInterestRateStrategy(
            deployRegistry.poolAddressesProvider,
            0.02e27 // 2% base rate
        );
        --snip--
    }
```

But in step 10 of `_deployUsdxl`, calls `_updateUsdxlInterestRateStrategy()` which deploys `UsdxlInterestRateStrategy` for the second time:

```solidity
    function _updateUsdxlInterestRateStrategy(IDeployConfigTypes.HypurrDeployRegistry memory deployRegistry)
        internal
    {
        UsdxlInterestRateStrategy interestRateStrategy = new UsdxlInterestRateStrategy(
          address(deployRegistry.poolAddressesProvider),
          0.02e27
        );

        _getPoolConfigurator(deployRegistry).setReserveInterestRateStrategyAddress(address(_getUsdxlToken()), address(interestRateStrategy));
    }
```

Use the already deployed `UsdxlInterestRateStrategy` contract address, instead of deploying it again.

# [L-02] Remove deprecated `Göerli testnet` files from deployment

The input folder contains a folder with `primary.json` for deployment on the **Göerli testnet**. However, the Göerli testnet has been deprecated and can no longer be used for test deployments. As a result, the presence of the `primary.json` file for Göerli is redundant and may cause confusion or lead to errors when attempting to deploy on this testnet.

Recommendation: remove the **Göerli testnet** related entries, files, and folders from the deployment process to avoid issues and ensure that only supported chains are used for deployments.

# [L-03] Incorrect tokenName set during `hyTokenImpl` initialization

When the `hyTokenImpl` is initialized in the `DeployHyFiUtils` script, the `aTokenName` is set to `"SPTOKEN_IMPL"`, which is specific to the SparkLend protocol, while this should be set to the specific name corresponding to the **HypurrFi** protocol instead.

```solidity
   hyTokenImpl = new HyToken(pool);
        hyTokenImpl.initialize(
            pool, address(0), address(0), IHyFiIncentivesController(address(0)), 0, "SPTOKEN_IMPL", "SPTOKEN_IMPL", ""
        );
```

Recommendation: update the `DeployHyFiUtils` script to set the `aTokenName` to the appropriate name for the **HypurrFi** protocol during the initialization of `hyTokenImpl`.

# [L-04] `_deployUsdxl()` doesn’t initialize `usdxlVariableDebtToken`

The `_deployUsdxl()` function is designed to deploy the **usdxl token** and the required contracts to initialize the **usdx reserve**, however, it was noticed that when the **`usdxlVariableDebtToken`** is deployed, it is not initialized in the script, which allows any malicious actor to initialize it with unintended, incorrect, or irrelevant parameters as the `usdxlVariableDebtToken.initialize()` function is unrestricted.

Recommendation: ensure that the **`usdxlVariableDebtToken`** is properly initialized within the script during the deployment process.

# [L-05] `_deployUsdxl()` doesn't initialize `usdxlAToken`

The `_deployUsdxl()` function is designed to deploy the **usdxl token** and the required contracts to initialize the **usdx reserve**, however, it was noticed that when the **`usdxlAToken`** is deployed, it is not initialized in the script, which allows any malicious actor to initialize it with unintended, incorrect, or irrelevant parameters as the `usdxlAToken.initialize()` function is unrestrictred.

Recommendation: ensure that the **`usdxlAToken`** is properly initialized within the script during the deployment process.

# [L-06] `TODO` resolution required for GSM proxy admin and unique interest rate strategy handling

The following unresolved `TODOs` introduce crucial issues in deployment and configuration logic:

1. Hardcoded `address(0)` as a proxy admin in `DeployUsdxlUtils._deployGsm()`. Currently, the proxy admin is hardcoded as `address(0)`, meaning no one can manage upgrades or administrative functions of the proxy.

```solidity
//File: (usdxl-core) src/deployments/utils/DeployUsdxlUtils.sol

function _deployGsm() internal returns (address) {
    AdminUpgradeabilityProxy proxy = new AdminUpgradeabilityProxy(
        address(gsmImpl),
@>      address(0), // TODO: set admin to timelock
        ""
    );
    --- SNIPPED ---
}
```

2. Duplicate strategy contracts in `DeployHyFiConfigEngine._getUniqueStrategiesOnPool()`.

```solidity
//File: (hypurrfi-deployment) script/DeployHyFiConfigEngine.s.sol

library DeployRatesFactoryLib {
@>   // TODO check also by param, potentially there could be different contracts, but with exactly same params
    function _getUniqueStrategiesOnPool(IPool pool, address[] memory reservesToSkip) {...}
```

The function currently checks for duplicate strategies only by contract address, but not by actual parameters. However, in `V3RateStrategyFactory.initialize()`, strategies are identified using a hash of their parameters. This means the same configuration can be registered multiple times under different contracts, leading to unnecessary duplication.

```solidity
//File: (hypurrfi-deployment) lib/aave-helpers/src/v3-config-engine/V3RateStrategyFactory.sol

function initialize(IDefaultInterestRateStrategy[] memory liveStrategies) external initializer {
for (uint256 i = 0; i < liveStrategies.length; i++) {
    RateStrategyParams memory params = getStrategyData(liveStrategies[i]);

    bytes32 hashedParams = strategyHashFromParams(params);

@>  _strategyByParamsHash[hashedParams] = address(liveStrategies[i]);
@>  _strategies.push(address(liveStrategies[i]));

    emit RateStrategyCreated(address(liveStrategies[i]), hashedParams, params);
}
}
```

Recommendation

- For `DeployUsdxlUtils._deployGsm()` function:
  If the proxy admin is meant to be a contract (such as a timelock contract), deploy it as part of the script and assign it properly. Otherwise, pass the proxy admin address as a parameter to `_deployGsm()` instead of hardcoding `address(0)`.

- For `DeployHyFiConfigEngine._getUniqueStrategiesOnPool()`:
  Before adding a new unique strategy, check if another strategy with the same parameters already exists.

# [L-07] DeployUsdxlUtils: `_deployGsm()` should use `usdxlToken`'s proxy address instead of implementation

`DeployUsdxlUtils`: The `_deployGsm()` function should use proxy address (`_getUsdxlToken()`) instead of its implementation when deploying new Gsm:

```solidity
   function _deployGsm(
        address token,
        address gsmOwner,
        uint256 maxCapacity,
        IDeployConfigTypes.HypurrDeployRegistry memory deployRegistry
    ) internal returns (address gsmProxy) {
        --snip--

        // Deploy GSM implementation
        Gsm gsmImpl = new Gsm(address(usdxlToken), address(token), address(fixedPriceStrategy));

        --snip--
```

Recommendations:

Use `_getUsdxlToken()` instead of `address(usdxlToken)`.

# [L-08] `DeployUsdxlUtils`: `usdxlAToken` and `usdxlVariableDebtToken` contracts are deployed twice

Function `_deployUsdxl` deploys `usdxlAToken` and `usdxlVariableDebtToken` token contracts in step 4 and uses their address in different configurations:

```solidity

    function _deployUsdxl(address proxyAdmin, IDeployConfigTypes.HypurrDeployRegistry memory deployRegistry) internal {
        --snip--

        // 4. Deploy USDXL AToken and Variable Debt Token
        usdxlAToken = new UsdxlAToken(IPool(IPoolAddressesProvider(deployRegistry.poolAddressesProvider).getPool()));

        usdxlVariableDebtToken =
            new UsdxlVariableDebtToken(IPool(IPoolAddressesProvider(deployRegistry.poolAddressesProvider).getPool()));

        // 5. Deploy Flash Minter
        flashMinter = new UsdxlFlashMinter(
            address(usdxlToken),
            deployRegistry.treasury,
            0, // no fee
            deployRegistry.poolAddressesProvider
        );

```

But in step 8 of `_deployUsdxl`, calls `_initializeUsdxlReserve()` which deploys `usdxlAToken` and `usdxlVariableDebtToken` tokens and exports their address for the second time:

```solidity
    function _initializeUsdxlReserve(address token, IDeployConfigTypes.HypurrDeployRegistry memory deployRegistry) internal {
        ConfiguratorInputTypes.InitReserveInput[] memory inputs = new ConfiguratorInputTypes.InitReserveInput[](1);

        usdxlAToken = new UsdxlAToken(_getPoolInstance(deployRegistry));

        usdxlVariableDebtToken = new UsdxlVariableDebtToken(_getPoolInstance(deployRegistry));

        DeployUsdxlFileUtils.exportContract(instanceId, "usdxlATokenImpl", address(usdxlAToken));
        DeployUsdxlFileUtils.exportContract(instanceId, "usdxlVariableDebtTokenImpl", address(usdxlVariableDebtToken));

        --snip--
    }

```

Recommendations:

Use the already deployed `usdxlAToken` and `usdxlVariableDebtToken` contract addresses, instead of deploying them again.
