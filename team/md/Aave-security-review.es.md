# Acerca de

Pashov Audit Group está formado por múltiples equipos de algunos de los mejores investigadores de seguridad de contratos inteligentes en el espacio. Con un recuento combinado de vulnerabilidades de seguridad reportadas de más de 1000, el grupo se esfuerza por crear el mejor viaje de auditoría posible: aunque nunca se puede garantizar una seguridad del 100%, garantizamos los mejores esfuerzos de nuestros investigadores experimentados para su protocolo blockchain. Revisa nuestro trabajo anterior [aquí](https://github.com/pashov/audits) o contáctanos en Twitter [@pashovkrum](https://twitter.com/pashovkrum).

# Descargo de Responsabilidad

Una revisión de seguridad de contratos inteligentes nunca puede verificar la ausencia total de vulnerabilidades. Este es un esfuerzo limitado por tiempo, recursos y experiencia donde intentamos encontrar tantas vulnerabilidades como sea posible. No podemos garantizar una seguridad del 100% después de la revisión o incluso que la revisión encuentre algún problema con sus contratos inteligentes. Se recomiendan encarecidamente revisiones de seguridad posteriores, programas de recompensas por errores (bug bounties) y monitoreo on-chain.

# Introducción

Una revisión de seguridad con tiempo limitado del repositorio **bgd-labs/aave-v3-origin-pashov** fue realizada por **Pashov Audit Group**, con un enfoque en los aspectos de seguridad de la implementación de los contratos inteligentes de la aplicación.

# Acerca de Aave V3.2

El Protocolo Aave es un sistema descentralizado donde los usuarios pueden suministrar liquidez para ganar intereses, tomar prestados activos con más garantía de la que piden prestada, o participar en liquidaciones. Aave v3 introdujo eMode, que permite a los usuarios agrupar activos relacionados, como ETH y WETH, para configuraciones de mayor riesgo, pero cada activo solo podía pertenecer a un eMode, limitando la flexibilidad. La actualización Aave v3.2 introduce eModes líquidos, permitiendo que los activos sean parte de múltiples eModes con configuraciones más detalladas, como si un activo puede ser prestado o usado como garantía dentro de un eMode, y nuevas opciones de configuración ofrecen un control más granular sobre el uso de activos en diferentes eModes.

# Clasificación de Riesgos

| Severidad              | Impacto: Alto | Impacto: Medio | Impacto: Bajo |
| ---------------------- | ------------ | -------------- | ----------- |
| **Probabilidad: Alta** | Crítica      | Alta           | Media       |
| **Probabilidad: Media**| Alta         | Media          | Baja        |
| **Probabilidad: Baja** | Media        | Baja           | Baja        |

## Impacto

- Alto - conduce a una pérdida material significativa de activos en el protocolo o daña significativamente a un grupo de usuarios.

- Medio - conduce a una pérdida material moderada de activos en el protocolo o daña moderadamente a un grupo de usuarios.

- Bajo - conduce a una pérdida material menor de activos en el protocolo o daña a un pequeño grupo de usuarios.

## Probabilidad

- Alta - la ruta de ataque es posible con suposiciones razonables que imitan las condiciones on-chain, y el costo del ataque es relativamente bajo en comparación con la cantidad de fondos que se pueden robar o perder.

- Media - solo un vector de ataque condicionalmente incentivado, pero aún relativamente probable.

- Baja - tiene demasiadas suposiciones o muy improbables o requiere una participación significativa por parte del atacante con poco o ningún incentivo.

## Acción requerida para niveles de severidad

- Crítica - Debe arreglarse lo antes posible (si ya está desplegado)

- Alta - Debe arreglarse (antes del despliegue si aún no está desplegado)

- Media - Debería arreglarse

- Baja - Podría arreglarse

# Resumen de la Evaluación de Seguridad

_review commit hash_ - [a4849111a0ce57e3af1ca5cd9a9b8c6a8cdad1e0](https://github.com/bgd-labs/aave-v3-origin-pashov/tree/a4849111a0ce57e3af1ca5cd9a9b8c6a8cdad1e0)

_fixes review commit hash_ - [dd0bbecb90a53628fe15c076217eac3a7275182f](https://github.com/bgd-labs/aave-v3-origin-pashov/tree/dd0bbecb90a53628fe15c076217eac3a7275182f)

### Alcance

Los siguientes contratos inteligentes estuvieron dentro del alcance de la auditoría:

- `AaveProtocolDataProvider`
- `IPoolConfigurator`
- `IPoolDataProvider`
- `EModeConfiguration`
- `ReserveConfiguration`
- `Errors`
- `ConfiguratorLogic`
- `EModeLogic`
- `GenericLogic`
- `LiquidationLogic`
- `ValidationLogic`
- `DataTypes`
- `PoolConfigurator`

### Vectores de ataque cubiertos

#### 1. LTV y Umbral de Liquidación Subóptimos

##### Descripción

Un atacante intenta manipular la selección de activos para aprovechar tasas subóptimas en E-Mode, ganando potencialmente términos más favorables de lo previsto. ¿Podría el nuevo EMode resultar inesperadamente en un LTV o umbral de liquidación más bajo que el modo predeterminado? O, cuando los usuarios habilitan EMode, ¿obtienen LTV y umbrales de liquidación subóptimos debido a nuevas suposiciones?

##### Protección

El sistema siempre utiliza los parámetros más conservadores (seguros) entre E-Mode y el modo regular para cada activo, asegurando que los usuarios no puedan explotar discrepancias para obtener ventajas injustas. Que el LT de EMode sea siempre mayor que el LT sin eMode para todos los activos no es una restricción, por lo que no es un problema. Para LTV y umbrales de liquidación subóptimos, no se indica en la documentación pero es el comportamiento previsto.

#### 2. Persistencia de Parámetros de E-Mode

##### Descripción

Un atacante intenta adelantarse (front-run) a la eliminación de un activo de un E-Mode para bloquear parámetros favorables de LTV y umbral de liquidación.

##### Protección

Los parámetros de E-Mode se aplican dinámicamente durante los cálculos del factor de salud. Incluso si un activo se elimina de E-Mode, el sistema utilizará los parámetros del modo regular para ese activo, evitando la explotación de configuraciones de E-Mode obsoletas.

#### 3. Liquidaciones Instantáneas al Eliminar Garantía (Collateral)

##### Descripción

Un atacante intenta explotar el período de transición cuando la garantía se elimina de E-Mode, desencadenando potencialmente liquidaciones injustas.

##### Protección

El sistema requiere que el factor de salud permanezca por encima de 1 al cambiar de E-Modes o cuando cambian los parámetros de E-Mode. Esto asegura que las posiciones permanezcan saludables durante las transiciones, evitando liquidaciones instantáneas.

#### 4. Manejo Asimétrico de Préstamos y Garantías

##### Descripción

Un atacante intenta aprovechar la diferencia en el tratamiento entre los activos prestados y la garantía en E-Mode para crear una posición explotable.

##### Protección

El sistema aplica reglas consistentes tanto para préstamos como para garantías dentro de E-Mode. Los activos deben estar explícitamente habilitados para ambas funciones en E-Mode, y siempre se utilizan los parámetros más conservadores, evitando la explotación de asimetrías.

#### 5. Riesgo de Corrupción de Almacenamiento Debido a Nuevas Variables

##### Descripción

Existe un riesgo de corrupción de almacenamiento debido a los cambios en la estructura `EModeCategory`, particularmente con la introducción de nuevas variables como `isCollateralBitmap` y `isBorrowableBitmap`.

##### Protección

Las nuevas variables son totalmente compatibles con el diseño de almacenamiento anterior, y no ocurre corrupción de datos. El sistema asegura que esto siga siendo cierto, asumiendo que Aave no ha establecido una dirección distinta de cero en el campo `priceSource` dentro de `EModeCategory`.

#### 6. Corrupción de Datos Inducida por el Administrador

##### Descripción

Un administrador podría corromper sin saberlo la estructura de datos al cambiar el Loan-to-Value (LTV), Umbral de Liquidación (LT) o Bono de Liquidación (LB) para un eMode.

##### Protección

Los administradores pueden ajustar de forma segura LTV, LT o LB sin causar ninguna corrupción a los campos de datos `isCollateralBitmap` y `isBorrowableBitmap`. La arquitectura del sistema asegura la integridad de estos campos durante los cambios administrativos.

#### 7. Deshabilitación de Categoría E-Mode

##### Descripción

Un atacante intenta explotar una categoría E-Mode activa pero no deseada que no se puede deshabilitar fácilmente, manipulando potencialmente el sistema a su favor.

##### Protección

El sistema está diseñado para operar de forma segura incluso con categorías E-Mode activas. Deshabilitar una categoría E-Mode es una operación sensible que requiere una consideración cuidadosa de las posiciones existentes, haciendo que sea intencionalmente difícil para prevenir consecuencias no deseadas.

#### 8. Granularidad Limitada en la Gestión de Riesgos

##### Descripción

Un atacante intenta explotar la aplicación amplia de parámetros de E-Mode en todos los activos dentro de una categoría, encontrando potencialmente casos extremos donde se subestima el riesgo.

##### Protección

Aunque los parámetros de E-Mode se aplican ampliamente a una categoría, el sistema aún considera los parámetros de activos individuales. Utiliza la opción más conservadora entre E-Mode y los parámetros de activos individuales, asegurando que el riesgo no se subestime para ningún activo específico.

#### 9. Precedencia de Parámetros de E-Mode

##### Descripción

Un atacante intenta manipular la interacción entre los parámetros globales de activos y los parámetros de E-Mode para crear una posición más favorable de lo previsto.

##### Protección

El sistema tiene reglas de precedencia claras, utilizando siempre la opción más conservadora entre parámetros globales y de E-Mode. Esto asegura que siempre se aplique el enfoque de gestión de riesgos más estricto, evitando la explotación de interacciones de parámetros.

#### 10. La secuencia de Cambios de Configuración de EMode

##### Descripción

Encontrar todas las secuencias posibles de cambios de configuración de EMode, acciones de usuario y estados de usuario que no tengan en cuenta esta actualización actual. (por ejemplo, EMode ya activado, queriendo desactivar EMode, queriendo pedir prestado, ya prestado, queriendo proporcionar garantía, garantía ya proporcionada, queriendo liquidar)

##### Protección

Ya existen comprobaciones y salvaguardas para asegurar que todas las operaciones sean correctas. Todas las operaciones dependen de la misma validación dentro de `ValidationLogic`, por lo que actualizar las salvaguardas en un lugar asegura que todas las operaciones sigan siendo correctas.

#### 11. Consecuencias No Deseadas de Cambios en EMode durante Préstamos

##### Descripción

¿Hay alguna consecuencia no deseada si los usuarios cambian EMode mientras tienen un activo prestado (por ejemplo, liquidable instantáneamente, no liquidable, garantía no contada, etc.)?

##### Protección

`ValidationLogic` y `calculateUserAccountData` dentro de `GenericLogic` ya están actualizados correctamente, por lo que no hay consecuencias no deseadas.

#### 12. Impacto de la Eliminación de Activos Prestados de EMode

##### Descripción

¿Pueden los usuarios seguir beneficiándose de EMode una vez que un activo prestado se elimina de EMode, dado que `calculateUserAccountData` no verifica si el activo prestado está registrado en EMode?

##### Protección

Es posible, pero los desarrolladores afirman que es por diseño: "Deshabilitar el préstamo es una acción muy poco intrusiva, dentro y fuera de eMode.
Las posiciones existentes permanecen intactas, la gente simplemente ya no puede aumentar su exposición a través de mayores préstamos."

#### 13. Eludir Restricciones de EMode con Flash Loans

##### Descripción

¿Pueden los usuarios eludir alguna restricción de EMode aprovechando los flash loans, por ejemplo, tomando prestados activos que no están registrados dentro de su EMode configurado?

##### Protección

Cuando los usuarios utilizan un flash loan y eligen no pagar los activos prestados, `BorrowLogic.executeBorrow` ya está en su lugar para asegurar que los activos prestados sean válidos, incluyendo la validación de EMode.

#### 14. Manipulación del Bono de Liquidación de EMode

##### Descripción

EMode tiene un umbral de liquidación y un bono de liquidación separados. No usar ambos valores de EMode puede causar problemas graves para el protocolo. ¿Pueden los prestatarios manipular o cambiar el bono de liquidación de EMode?

##### Protección

`LiquidationLogic` tiene la misma verificación de estado exacta al decidir si los usuarios están utilizando el bono de liquidación de EMode que `GenericLogic.calculateUserAccountData`. Por lo tanto, ambos (el bono de liquidación y el umbral de liquidación) siempre usarán valores de EMode o no EMode.

#### 15. Impacto Lógico en el Alcance de la Actualización de EMode

##### Descripción

¿Hay alguna operación existente que deba considerar este nuevo comportamiento pero que actualmente no lo haga? Comprobando toda la lógica dentro del alcance que no tiene diferencias dentro del commit.

##### Protección

Todas ellas (lógica dentro del alcance que no tiene diferencias dentro del commit), si no interactúan o dependen de la configuración de EMode, ya están usando `ValidationLogic`. Por lo tanto, son seguras y no requieren ningún cambio.

#### 16. Impacto de EMode en Otras Características

##### Descripción

¿El nuevo EMode impacta inesperadamente otras características (por ejemplo, Préstamos Aislados - Siloed Borrowing, Modo de Aislamiento - Isolation Mode, etc.)? Por ejemplo, ¿activar EMode deshabilita accidentalmente otras características o modos?

##### Protección

Las salvaguardas y validaciones para cada característica son independientes dentro de sus respectivas bibliotecas y `ValidationLogic`, por lo que no hay impacto.

#### 17. Manejo de Casos eMode = 0

##### Descripción

¿Se manejan correctamente todos los casos donde eMode = 0? eMode = 0 es el caso predeterminado, así que asegúrese de que no haya funciones o lógica que accedan accidentalmente a eMode = 0 y utilicen el LTV y umbral de liquidación de EMode del usuario. Además, asegúrese de que no sea posible que un administrador configure eMode = 0.

##### Protección

Las funciones dentro de `ValidationLogic` y `GenericLogic` ya excluyen eMode = 0 (asegurando `params.userEModeCategory != 0`), y `configureEModeCategory` ya asegura que los cambios de configuración a eMode = 0 estén restringidos (asegurando `id != 0`).

#### 18. Llamadas Simultáneas a Funciones de Administrador

##### Descripción

Dos administradores pueden intentar llamar a las funciones `setCollateral` y `setBorrowable` simultáneamente con los mismos argumentos, potencialmente corrompiendo el estado final.

##### Protección

Tanto `setCollateral` como `setBorrowable` son funciones idempotentes, lo que significa que múltiples llamadas con los mismos parámetros no cambiarán el estado final. Esto evita cualquier cambio de estado no deseado por transacciones repetidas de diferentes administradores.

#### 19. Disminución del Factor de Salud por Cambio de EMode

##### Descripción

Un usuario podría intentar cambiar su eMode, disminuyendo sin saberlo el HF (Health Factor), resultando en una liquidación instantánea.

##### Protección

El sistema verifica el Factor de Salud (HF) después de permitir que cualquier usuario cambie su eMode. Si el Factor de Salud cae por debajo de 1 como resultado del cambio, la acción se bloquea, asegurando que los usuarios no puedan hacerlo.

#### 20. Riesgo de Corrupción de Datos y Eliminación de Máscara eMode

##### Descripción

La eliminación de la máscara eMode dentro del mapa de bits de configuración de activos podría conducir potencialmente a la corrupción de datos.

##### Protección

La máscara eMode se ha eliminado limpiamente sin afectar el resto de los datos almacenados en el mapa de bits, asegurando que no haya corrupción de datos ni efectos secundarios no deseados.

#### 21. Impacto de la Actualización de EMode en Usuarios Existentes

##### Descripción

Los usuarios actualmente en un eMode específico pueden experimentar problemas o explotar cambios introducidos por la actualización.

##### Protección

Los usuarios en eMode no se ven afectados por la actualización. El mapeo que rastrea los eModes de los usuarios (`_usersEModeCategory`) permanece sin cambios. Además, siempre que los valores de LTs y LTVs se mantengan, las funciones `calculateUserAccountData` y `executeLiquidationCall` se comportarán como antes de la actualización.

#### 22. Riesgo de Desbordamiento en `setCollateral()`

##### Descripción

Desbordamiento en la función `setCollateral()` al establecer la variable `bit`.

##### Protección

Este problema se mitiga ya que el reserveIndex se valida para asegurar que siempre sea menor que 128.

#### 23. Riesgo de Colisión de Ranura de Almacenamiento en Biblioteca `DataTypes`

##### Descripción

Colisión de ranura de almacenamiento en la biblioteca DataTypes.

##### Protección

Las ranuras de almacenamiento se gestionan adecuadamente para prevenir colisiones.

# Hallazgos

# [L-01] `setUserEMode` debería comprobar si `categoryId` es el mismo para evitar validación innecesaria

Cuando el usuario llama a `setUserEmode`, la ejecución no comprueba si el `categoryId` proporcionado es el mismo que la configuración anterior del usuario. Esto requerirá que los usuarios realicen una validación innecesaria del factor de salud y gasten gas extra. Comparado con cuando los usuarios llaman a `setUserUseReserveAsCollateral` para configurar una reserva como garantía, este retornará antes si la bandera proporcionada es la misma que la bandera existente.

```solidity
  function executeUseReserveAsCollateral(
    mapping(address => DataTypes.ReserveData) storage reservesData,
    mapping(uint256 => address) storage reservesList,
    mapping(uint8 => DataTypes.EModeCategory) storage eModeCategories,
    DataTypes.UserConfigurationMap storage userConfig,
    address asset,
    bool useAsCollateral,
    uint256 reservesCount,
    address priceOracle,
    uint8 userEModeCategory
  ) external {
    DataTypes.ReserveData storage reserve = reservesData[asset];
    DataTypes.ReserveCache memory reserveCache = reserve.cache();

    uint256 userBalance = IERC20(reserveCache.aTokenAddress).balanceOf(msg.sender);

    ValidationLogic.validateSetUseReserveAsCollateral(reserveCache, userBalance);

>>> if (useAsCollateral == userConfig.isUsingAsCollateral(reserve.id)) return;
    // ...
}
```

Considere usar el mismo patrón dentro de `setUserEmode` / `executeSetUserEMode`. Si la categoría proporcionada es la misma que la existente, retornar antes para evitar validación innecesaria.

```diff
  function executeSetUserEMode(
    mapping(address => DataTypes.ReserveData) storage reservesData,
    mapping(uint256 => address) storage reservesList,
    mapping(uint8 => DataTypes.EModeCategory) storage eModeCategories,
    mapping(address => uint8) storage usersEModeCategory,
    DataTypes.UserConfigurationMap storage userConfig,
    DataTypes.ExecuteSetUserEModeParams memory params
  ) external {
    ValidationLogic.validateSetUserEMode(
      eModeCategories,
      userConfig,
      params.reservesCount,
      params.categoryId
    );

+   if (usersEModeCategory[msg.sender] == params.categoryId) return;
    usersEModeCategory[msg.sender] = params.categoryId;
    ValidationLogic.validateHealthFactor(
      reservesData,
      reservesList,
      eModeCategories,
      userConfig,
      msg.sender,
      params.categoryId,
      params.reservesCount,
      params.oracle
    );
    emit UserEModeSet(msg.sender, params.categoryId);
  }
```
