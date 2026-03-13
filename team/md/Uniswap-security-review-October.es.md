# Acerca de

Pashov Audit Group está formado por múltiples equipos de algunos de los mejores investigadores de seguridad de contratos inteligentes en el espacio. Con un recuento combinado de vulnerabilidades de seguridad reportadas de más de 1000, el grupo se esfuerza por crear el mejor viaje de auditoría posible: aunque nunca se puede garantizar una seguridad del 100%, garantizamos los mejores esfuerzos de nuestros investigadores experimentados para su protocolo blockchain. Revisa nuestro trabajo anterior [aquí](https://github.com/pashov/audits) o contáctanos en Twitter [@pashovkrum](https://twitter.com/pashovkrum).

# Descargo de Responsabilidad

Una revisión de seguridad de contratos inteligentes nunca puede verificar la ausencia total de vulnerabilidades. Este es un esfuerzo limitado por tiempo, recursos y experiencia donde intentamos encontrar tantas vulnerabilidades como sea posible. No podemos garantizar una seguridad del 100% después de la revisión o incluso que la revisión encuentre algún problema con sus contratos inteligentes. Se recomiendan encarecidamente revisiones de seguridad posteriores, programas de recompensas por errores (bug bounties) y monitoreo on-chain.

# Introducción

Una revisión de seguridad con tiempo limitado del repositorio **timeless-fi/bunni-v2** fue realizada por **Pashov Audit Group**, con un enfoque en los aspectos de seguridad de la implementación de los contratos inteligentes de la aplicación.

# Acerca de Uniswap V4 Periphery

Uniswap v4 conserva las mejoras de eficiencia de capital de Uniswap v3, al tiempo que introduce flexibilidad a través de hooks y optimiza el uso de gas en todo el proceso. El contrato SVG en los contratos periféricos define una biblioteca llamada NFTSVG, que proporciona funciones para generar imágenes SVG utilizadas en los NFTs de Uniswap, combinando elementos gráficos personalizables como curvas, colores y posiciones basadas en varios parámetros como IDs de tokens, rangos de precios y símbolos de tokens.

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

_review commit hash_ - [7faae4718eecda1b33dc3abd894431ed2d16c929](https://github.com/timeless-fi/bunni-v2/tree/7faae4718eecda1b33dc3abd894431ed2d16c929)

_fixes review commit hash_ - [1a21920085fc712ca745361bf397e8a7be25dc1c](https://github.com/timeless-fi/bunni-v2/tree/1a21920085fc712ca745361bf397e8a7be25dc1c)

### Alcance

Los siguientes contratos inteligentes estuvieron dentro del alcance de la auditoría:

- `PositionDescriptor`
- `PositionManager`
- `ERC721Permit_v4`
- `SafeCurrencyMetadata`
- `AddressStringUtils`
- `HexStrings`
- `Descriptor`
- `SVG`
- `SafeCurrencyMetadata`

# Hallazgos

# [M-01] La dirección del Hook no se representa correctamente en el SVG

## Severidad

**Impacto:** Bajo

**Probabilidad:** Alta

## Descripción

La función `generateSVGPositionDataAndLocationCurve` de la biblioteca `SVG` genera el SVG para los datos de la posición. Estos datos incluyen la dirección del contrato hook, que no se representa completa, sino solo los primeros y últimos caracteres con puntos suspensivos en el medio.

Para procesar la dirección del hook, primero se llama a la función `toHexString` para transformar la dirección en una cadena, por lo que la variable `hookStr` tiene 42 caracteres de longitud y el rango de sus índices de bytes es de 0 a 41.

Luego, la dirección cortada se genera concatenando los primeros 5 caracteres, los puntos suspensivos y los últimos 3 caracteres de la variable `hookStr`. Sin embargo, los valores pasados a la función `substring` son incorrectos para los últimos caracteres, ya que `endIndex` debería ser 42 en lugar de 40.

```solidity
    function generateSVGPositionDataAndLocationCurve(
        string memory tokenId,
        address hook,
        int24 tickLower,
        int24 tickUpper
    ) private pure returns (string memory svg) {
@>      string memory hookStr = (uint256(uint160(hook))).toHexString(20);
        string memory tickLowerStr = tickToString(tickLower);
        string memory tickUpperStr = tickToString(tickUpper);
        uint256 str1length = bytes(tokenId).length + 4;
@>      string memory hookSlice = string(abi.encodePacked(substring(hookStr, 0, 5), "...", substring(hookStr, 37, 40)));
```

Esto significa que si la dirección del hook es `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`, el SVG mostrará el siguiente texto:

```
Hook: 0xa0b...6eb
```

Esto resultará en que los usuarios no puedan identificar el contrato hook.

## Recomendaciones

```diff
-    string memory hookSlice = string(abi.encodePacked(substring(hookStr, 0, 5), "...", substring(hookStr, 37, 40)));
+    string memory hookSlice = string(abi.encodePacked(substring(hookStr, 0, 5), "...", substring(hookStr, 39, 42)));
```

# [L-01] La dirección del Hook podría no estar establecida

En `Descriptor.sol` y `SVG.sol` parece que existe la expectativa de que cada posición tendrá un contrato hook asociado, sin embargo, como se indica en [esta página](https://docs.uniswap.org/contracts/v4/concepts/hooks), los hooks son opcionales para los pools de liquidez, por lo que las posiciones pueden no tener un hook asociado.

Por ejemplo, los SVGs que se generan en `SVG.sol` podrían ser confusos para los usuarios que tienen posiciones en pools de liquidez sin un contrato hook. En los SVGs generados actualmente habrá secciones que se verán algo así como `Hook: 0x0000...0000`. Para el usuario no educado, podría parecer que el SVG se generó incorrectamente o que el hook está de hecho en la dirección mostrada.

Sería mejor si hubiera una lógica condicional para cuando una posición no tiene un hook asociado. Algunas posibilidades incluyen:

- Generar SVGs (o descriptores) sin secciones específicas de hooks si el pool de liquidez relevante no utiliza un contrato hook.
- En lugar de mostrar `0x0000...00000` mostrar una cadena como `No hook` (Sin hook).

Por supuesto, podría ser más fácil/mejor quedarse con la dirección 0 para algunos componentes como URIs que necesitan confirmarse con un formato específico esperado. Sin embargo, para el contenido visible por el usuario, sería mejor ser más transparente/explícito.

# [L-02] Cambio disruptivo en los hashes de permiso (permit hashes)

Aunque v4 aún no se ha desplegado en mainnet, se ha desplegado en testnet, por lo que vale la pena mencionar que el pequeño cambio en la cadena de nombre en `PositionManager.sol` de `V4` a `v4` romperá todos los permisos existentes que han sido firmados pero no utilizados aún. Esto puede afectar a cualquier integrador que esté probando con v4.

Si este cambio se entiende y se comunica a cualquier integrador de testnet posterior, entonces este cambio puede persistir.

# [L-03] Usar la dirección cero para el token nativo puede ser confuso para los usuarios finales

Internamente, Uniswap v4 utiliza la dirección cero para representar el token nativo de la cadena. Esto significa que `tokenURI` para los NFTs de pools que usan el token nativo contendrá el siguiente texto en el campo "description" de sus metadatos:

```
ETH Address: 0x0000000000000000000000000000000000000000
```

De la misma manera, la imagen SVG para el NFT contendrá el siguiente texto en el borde de la imagen:

```
0x0000000000000000000000000000000000000000 • ETH
```

Esto podría ser confuso para los usuarios finales, ya que podrían interpretar la dirección cero como la dirección real del token nativo.

Considere gestionar el caso especial de que la moneda sea el token nativo y no mostrar la dirección en ese caso o usar una representación diferente, como la palabra "Native" (Nativo).

# [L-04] Caracteres especiales no escapados pueden producir JSON inválido

El `Descriptor.constructTokenURI` genera un JSON codificado en Base64 que será devuelto por la función `PositionDescriptor.tokenURI`. La función no sanitiza completamente los símbolos de entrada, que pueden contener caracteres especiales que producirán un JSON inválido.

Los siguientes caracteres deben escaparse de la misma manera que se hace para el carácter de comillas dobles:

- `\u000c` (form feed - salto de página)
- `\n` (newline - salto de línea)
- `\r` (carriage return - retorno de carro)
- `\t` (tab - tabulación)

# [L-05] Cadenas de símbolos largas pueden causar que `tokenURI` revierta o artefactos en la imagen SVG

La función `currencySymbol` en la biblioteca `SafeCurrencyMetadata` se utiliza para extraer el símbolo del token del contrato del token. Si el valor devuelto por el contrato es demasiado largo, puede causar los siguientes problemas:

1. Si la longitud del símbolo es mayor a 255 caracteres, la función `Descriptor.escapeQuotes` revertirá debido a un error de desbordamiento (overflow), ya que `symbolBytes.length` no cabrá en un `uint8`:

```solidity
    for (uint8 i = 0; i < symbolBytes.length; i++) {
        if (symbolBytes[i] == '"') {
            quotesCount++;
        }
    }
```

2. Para longitudes inferiores a 255 pero aún largas, el texto con los datos de los tokens colocado en el borde de la imagen SVG se superpondrá y la salida será ilegible ([ver ejemplo](https://raw.githubusercontent.com/gist/shaka0x/3261ae647d8ad1a004e6512d72a04dc5/raw/b7f9e9294d2c1a4710d7db59eab89081182e4b83/nft.svg)).

Considere recortar la salida de la función `currencySymbol` a una longitud sensata para evitar estos problemas.

# [L-06] `currencyDecimals` no comprueba si el valor devuelto es uint8

En `SafeCurrencyMetadata`, el NatSpec de la función `currencyDecimals` establece lo siguiente:

```solidity
/// @notice attempts to extract the token decimals, returns 0 if not implemented or not a uint8
```

Sin embargo, la función no comprueba si el valor devuelto por el contrato del token es un uint8, por lo que en caso de que el valor sea mayor a 255, la función revertirá en la fase de decodificación:

```solidity
    if (data.length == 32) {
        return abi.decode(data, (uint8));
    }
```

Aunque un valor decimal mayor a 255 podría no esperarse, ya que no es posible representar un número con más de 77 decimales en 32 bytes, la función debería evitar revertir y devolver el valor de respaldo de 0 en su lugar.

Considere agregar los siguientes cambios al código:

```diff
    if (data.length == 32) {
-       return abi.decode(data, (uint8));
+       uint256 decimals = abi.decode(data, (uint256));
+       if (decimals <= type(uint8).max) {
+           return uint8(decimals);
+       }
    }
    return (false, 0);
```
