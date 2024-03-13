# Report


## Gas Optimizations


| |Issue|Instances|
|-|:-|:-:|
| [GAS-1](#GAS-1) | `a = a + b` is more gas effective than `a += b` for state variables (excluding arrays and mappings) | 1 |
| [GAS-2](#GAS-2) | Comparing to a Boolean constant | 1 |
| [GAS-3](#GAS-3) | Using bools for storage incurs overhead | 2 |
| [GAS-4](#GAS-4) | Cache array length outside of loop | 2 |
| [GAS-5](#GAS-5) | For Operations that will not overflow, you could use unchecked | 80 |
| [GAS-6](#GAS-6) | Functions guaranteed to revert when called by normal users can be marked `payable` | 4 |
| [GAS-7](#GAS-7) | `++i` costs less gas compared to `i++` or `i += 1` (same for `--i` vs `i--` or `i -= 1`) | 2 |
| [GAS-8](#GAS-8) | Using `private` rather than `public` for constants, saves gas | 1 |
| [GAS-9](#GAS-9) | Use shift right/left instead of division/multiplication if possible | 1 |
| [GAS-10](#GAS-10) | Increments/decrements can be unchecked in for-loops | 1 |
| [GAS-11](#GAS-11) | Use != 0 instead of > 0 for unsigned integer comparison | 3 |
### <a name="GAS-1"></a>[GAS-1] `a = a + b` is more gas effective than `a += b` for state variables (excluding arrays and mappings)
This saves **16 gas per instance.**

*Instances (1)*:
```solidity
File: src/MagicSpend/MagicSpend.sol

141:         withdrawableFunds[userOp.sender] += excess;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

### <a name="GAS-2"></a>[GAS-2] Comparing to a Boolean constant
Comparing to a constant (`true` or `false`) is a bit more expensive than directly checking the returned boolean value.

Consider using `if(directValue)` instead of `if(directValue == true)` and `if(!directValue)` instead of `if(directValue == false)`

*Instances (1)*:
```solidity
File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

55:         if (alreadyDeployed == false) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol)

### <a name="GAS-3"></a>[GAS-3] Using bools for storage incurs overhead
Use uint256(1) and uint256(2) for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from ‘false’ to ‘true’, after having been ‘true’ in the past. See [source](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27).

*Instances (2)*:
```solidity
File: src/MagicSpend/MagicSpend.sol

37:     mapping(uint256 nonce => mapping(address user => bool used))

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/MultiOwnable.sol

24:     mapping(bytes account => bool isOwner_) isOwner;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

### <a name="GAS-4"></a>[GAS-4] Cache array length outside of loop
If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

*Instances (2)*:
```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

236:         for (uint256 i; i < calls.length; ) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

```solidity
File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

### <a name="GAS-5"></a>[GAS-5] For Operations that will not overflow, you could use unchecked

*Instances (80)*:
```solidity
File: src/FreshCryptoLib/FCL.sol

67:         x1 = addmod(x1, n - r, n);

83:             uint256 LHS = mulmod(y, y, p); // y^2

84:             uint256 RHS = addmod(mulmod(mulmod(x, x, p), x, p), mulmod(x, a, p), p); // x^3+ax

85:             RHS = addmod(RHS, b, p); // x^3 + a*x + b

119:         uint256 Q1, //affine rep for input point Q

135:                 (H0 == 0) && (H1 == 0) //handling Q=-G

137:                 scalar_u = addmod(scalar_u, n - scalar_v, n);

166:                     let T1 := mulmod(2, Y, p) //U = 2*Y1, y free

167:                     let T2 := mulmod(T1, T1, p) // V=U^2

168:                     let T3 := mulmod(X, T2, p) // S = X1*V

169:                     T1 := mulmod(T1, T2, p) // W=UV

170:                     let T4 := mulmod(3, mulmod(addmod(X, sub(p, zz), p), addmod(X, zz, p), p), p) //M=3*(X1-ZZ1)*(X1+ZZ1)

171:                     zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1

172:                     zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free

174:                     X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S

175:                     T2 := mulmod(T4, addmod(X, sub(p, T3), p), p) //-M(S-X3)=M(X3-S)

176:                     Y := addmod(mulmod(T1, Y, p), T2, p) //-Y3= W*Y1-M(S-X3), we replace Y by -Y to avoid a sub in ecAdd

183:                             Y := sub(p, Y) //restore the -Y inversion

185:                         } // if T4!=0

210:                         let y2 := addmod(mulmod(T2, zzz, p), Y, p) //R

211:                         T2 := addmod(mulmod(T1, zz, p), sub(p, X), p) //P

217:                                 T1 := mulmod(minus_2, Y, p) //U = 2*Y1, y free

218:                                 T2 := mulmod(T1, T1, p) // V=U^2

219:                                 T3 := mulmod(X, T2, p) // S = X1*V

221:                                 T1 := mulmod(T1, T2, p) // W=UV

222:                                 y2 := mulmod(addmod(X, zz, p), addmod(X, sub(p, zz), p), p) //(X-ZZ)(X+ZZ)

223:                                 T4 := mulmod(3, y2, p) //M=3*(X-ZZ)(X+ZZ)

225:                                 zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1

226:                                 zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free

228:                                 X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S

229:                                 T2 := mulmod(T4, addmod(T3, sub(p, X), p), p) //M(S-X3)

231:                                 Y := addmod(T2, mulmod(T1, Y, p), p) //Y3= M(S-X3)-W*Y1

237:                         T4 := mulmod(T2, T2, p) //PP

238:                         let TT1 := mulmod(T4, T2, p) //PPP, this one could be spared, but adding this register spare gas

240:                         zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1

247:                 } //end loop

267:                 X := mulmod(X, mload(T), p) //X/zz

268:             } //end assembly

269:         } //end unchecked

306:         uint256 zzzInv = FCL_pModInv(zzz); //1/zzz

307:         y1 = mulmod(y, zzzInv, p); //Y/zzz

308:         uint256 _b = mulmod(zz, zzzInv, p); //1/z

309:         zzzInv = mulmod(_b, _b, p); //1/zz

310:         x1 = mulmod(x, zzzInv, p); //X/zz

325:                 P0 := mulmod(2, y, p) //U = 2*Y1

326:                 P2 := mulmod(P0, P0, p) // V=U^2

327:                 P3 := mulmod(x, P2, p) // S = X1*V

328:                 P1 := mulmod(P0, P2, p) // W=UV

329:                 P2 := mulmod(P2, zz, p) //zz3=V*ZZ1

330:                 zz := mulmod(3, mulmod(addmod(x, sub(p, zz), p), addmod(x, zz, p), p), p) //M=3*(X1-ZZ1)*(X1+ZZ1)

331:                 P0 := addmod(mulmod(zz, zz, p), mulmod(minus_2, P3, p), p) //X3=M^2-2S

332:                 x := mulmod(zz, addmod(P3, sub(p, P0), p), p) //M(S-X3)

333:                 P3 := mulmod(P1, zzz, p) //zzz3=W*zzz1

334:                 P1 := addmod(x, sub(p, mulmod(P1, y, p)), p) //Y3= M(S-X3)-W*Y1

358:                 P0 := mulmod(x2, x2, p) //PP = P^2

359:                 P1 := mulmod(P0, x2, p) //PPP = P*PP

360:                 P2 := mulmod(zz1, P0, p) ////ZZ3 = ZZ1*PP

361:                 P3 := mulmod(zzz1, P1, p) ////ZZZ3 = ZZZ1*PPP

362:                 zz1 := mulmod(x1, P0, p) //Q = X1*PP

363:                 P0 := addmod(addmod(mulmod(y2, y2, p), sub(p, P1), p), mulmod(minus_2, zz1, p), p) //R^2-PPP-2*Q

364:                 P1 := addmod(mulmod(addmod(zz1, sub(p, P0), p), y2, p), mulmod(y1, P1, p), p) //R*(Q-X3)

367:         } //end unchecked

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol)

```solidity
File: src/MagicSpend/MagicSpend.sol

140:         uint256 excess = withdrawRequest.amount - maxCost;

141:         withdrawableFunds[userOp.sender] += excess;

164:         uint256 withdrawable = withdrawableFunds[account] +

165:             (maxCost - actualGasCost);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

99:         assembly ("memory-safe") {

239:                 ++i;

305:             assembly ("memory-safe") {

339:             assembly ("memory-safe") {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

```solidity
File: src/SmartWallet/ERC1271.sol

50:         fields = hex"0f"; // `0b1111`.

54:         salt = salt; // `bytes32(0)`.

55:         extensions = extensions; // `new uint256[](0)`.

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol)

```solidity
File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) {

172:             _addOwnerAtIndex(owners[i], _getMultiOwnableStorage().nextOwnerIndex++);

180:         _addOwnerAtIndex(owner, _getMultiOwnableStorage().nextOwnerIndex++);

213:         assembly ("memory-safe") {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

```solidity
File: src/WebAuthnSol/WebAuthn.sol

47:     uint256 private constant P256_N_DIV_2 = FCL.n / 2;

121:             webAuthnAuth.typeIndex + 21

133:             webAuthnAuth.challengeIndex + expectedChallenge.length

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol)

### <a name="GAS-6"></a>[GAS-6] Functions guaranteed to revert when called by normal users can be marked `payable`
If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.

*Instances (4)*:
```solidity
File: src/MagicSpend/MagicSpend.sol

261:     function entryPointUnlockStake() external onlyOwner {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/MultiOwnable.sol

85:     function addOwnerAddress(address owner) public virtual onlyOwner {

93:     function addOwnerPublicKey(bytes32 x, bytes32 y) public virtual onlyOwner {

102:     function removeOwnerAtIndex(uint256 index) public virtual onlyOwner {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

### <a name="GAS-7"></a>[GAS-7] `++i` costs less gas compared to `i++` or `i += 1` (same for `--i` vs `i--` or `i -= 1`)
Pre-increments and pre-decrements are cheaper.

For a `uint256 i` variable, the following is true with the Optimizer enabled at 10k:

**Increment:**

- `i += 1` is the most expensive form
- `i++` costs 6 gas less than `i += 1`
- `++i` costs 5 gas less than `i++` (11 gas less than `i += 1`)

**Decrement:**

- `i -= 1` is the most expensive form
- `i--` costs 11 gas less than `i -= 1`
- `--i` costs 5 gas less than `i--` (16 gas less than `i -= 1`)

Note that post-increments (or post-decrements) return the old value before incrementing or decrementing, hence the name *post-increment*:

```solidity
uint i = 1;  
uint j = 2;
require(j == i++, "This will be false as i is incremented after the comparison");
```
  
However, pre-increments (or pre-decrements) return the new value:
  
```solidity
uint i = 1;  
uint j = 2;
require(j == ++i, "This will be true as i is incremented before the comparison");
```

In the pre-increment case, the compiler has to create a temporary variable (when used) for returning `1` instead of `2`.

Consider using pre-increments and pre-decrements where they are relevant (meaning: not where post-increments/decrements logic are relevant).

*Saves 5 gas per instance*

*Instances (2)*:
```solidity
File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) {

180:         _addOwnerAtIndex(owner, _getMultiOwnableStorage().nextOwnerIndex++);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

### <a name="GAS-8"></a>[GAS-8] Using `private` rather than `public` for constants, saves gas
If needed, the values can be read from the verified contract source code, or if there are multiple values there can be a single getter function that [returns a tuple](https://github.com/code-423n4/2022-08-frax/blob/90f55a9ce4e25bceed3a74290b854341d8de6afa/src/contracts/FraxlendPair.sol#L156-L178) of the values of all currently-public constants. Saves **3406-3606 gas** in deployment gas due to the compiler not having to create non-payable getter functions for deployment calldata, not having to store the bytes of the value outside of where it's used, and not adding another entry to the method ID table

*Instances (1)*:
```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

48:     uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

### <a name="GAS-9"></a>[GAS-9] Use shift right/left instead of division/multiplication if possible
While the `DIV` / `MUL` opcode uses 5 gas, the `SHR` / `SHL` opcode only uses 3 gas. Furthermore, beware that Solidity's division operation also includes a division-by-0 prevention which is bypassed using shifting. Eventually, overflow checks are never performed for shift operations as they are done for arithmetic operations. Instead, the result is always truncated, so the calculation can be unchecked in Solidity version `0.8+`
- Use `>> 1` instead of `/ 2`
- Use `>> 2` instead of `/ 4`
- Use `<< 3` instead of `* 8`
- ...
- Use `>> 5` instead of `/ 2^5 == / 32`
- Use `<< 6` instead of `* 2^6 == * 64`

TL;DR:
- Shifting left by N is like multiplying by 2^N (Each bits to the left is an increased power of 2)
- Shifting right by N is like dividing by 2^N (Each bits to the right is a decreased power of 2)

*Saves around 2 gas + 20 for unchecked per instance*

*Instances (1)*:
```solidity
File: src/WebAuthnSol/WebAuthn.sol

47:     uint256 private constant P256_N_DIV_2 = FCL.n / 2;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol)

### <a name="GAS-10"></a>[GAS-10] Increments/decrements can be unchecked in for-loops
In Solidity 0.8+, there's a default overflow check on unsigned integers. It's possible to uncheck this in for-loops and save some gas at each iteration, but at the cost of some code readability, as this uncheck cannot be made inline.

[ethereum/solidity#10695](https://github.com/ethereum/solidity/issues/10695)

The change would be:

```diff
- for (uint256 i; i < numIterations; i++) {
+ for (uint256 i; i < numIterations;) {
 // ...  
+   unchecked { ++i; }
}  
```

These save around **25 gas saved** per instance.

The same can be applied with decrements (which should use `break` when `i == 0`).

The risk of overflow is non-existent for `uint256`.

*Instances (1)*:
```solidity
File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

### <a name="GAS-11"></a>[GAS-11] Use != 0 instead of > 0 for unsigned integer comparison

*Instances (3)*:
```solidity
File: src/FreshCryptoLib/FCL.sol

24: pragma solidity >=0.8.19 <0.9.0;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol)

```solidity
File: src/MagicSpend/MagicSpend.sol

168:         if (withdrawable > 0) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/WebAuthnSol/WebAuthn.sol

181:         bool valid = ret.length > 0;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol)


## Non Critical Issues


| |Issue|Instances|
|-|:-|:-:|
| [NC-1](#NC-1) | Use `string.concat()` or `bytes.concat()` instead of `abi.encodePacked` | 2 |
| [NC-2](#NC-2) | Constants should be in CONSTANT_CASE | 9 |
| [NC-3](#NC-3) | `constant`s should be defined rather than using magic numbers | 15 |
| [NC-4](#NC-4) | Control structures do not follow the Solidity Style Guide | 21 |
| [NC-5](#NC-5) | Default Visibility for constants | 10 |
| [NC-6](#NC-6) | Consider disabling `renounceOwnership()` | 1 |
| [NC-7](#NC-7) | Functions should not be longer than 50 lines | 43 |
| [NC-8](#NC-8) | Change int to int256 | 3 |
| [NC-9](#NC-9) | Use a `modifier` instead of a `require/if` statement for a special `msg.sender` actor | 5 |
| [NC-10](#NC-10) | `address`s shouldn't be hard-coded | 3 |
| [NC-11](#NC-11) | Take advantage of Custom Error's return value property | 10 |
| [NC-12](#NC-12) | Strings should use double quotes rather than single quotes | 2 |
| [NC-13](#NC-13) | Use Underscores for Number Literals (add an underscore every 3 digits) | 1 |
### <a name="NC-1"></a>[NC-1] Use `string.concat()` or `bytes.concat()` instead of `abi.encodePacked`
Solidity version 0.8.4 introduces `bytes.concat()` (vs `abi.encodePacked(<bytes>,<bytes>)`)

Solidity version 0.8.12 introduces `string.concat()` (vs `abi.encodePacked(<str>,<str>), which catches concatenation errors (in the event of a `bytes` data mixed in the concatenation)`)

*Instances (2)*:
```solidity
File: src/SmartWallet/ERC1271.sol

122:         return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), _hashStruct(hash)));

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol)

```solidity
File: src/WebAuthnSol/WebAuthn.sol

165:             abi.encodePacked(webAuthnAuth.authenticatorData, clientDataJSONHash)

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol)

### <a name="NC-2"></a>[NC-2] Constants should be in CONSTANT_CASE
For `constant` variable names, each word should use all capital letters, with underscores separating each word (CONSTANT_CASE)

*Instances (9)*:
```solidity
File: src/FreshCryptoLib/FCL.sol

31:     uint256 constant p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;

33:     uint256 constant a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;

35:     uint256 constant b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;

37:     uint256 constant gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;

38:     uint256 constant gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;

40:     uint256 constant n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

42:     uint256 constant minus_2 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD;

44:     uint256 constant minus_2modn = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F;

46:     uint256 constant minus_1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol)

### <a name="NC-3"></a>[NC-3] `constant`s should be defined rather than using magic numbers
Even [assembly](https://github.com/code-423n4/2022-05-opensea-seaport/blob/9d7ce4d08bf3c3010304a0476a785c70c0e90ae7/contracts/lib/TokenTransferrer.sol#L35-L39) can benefit from using readable constants instead of hex/numeric literals

*Instances (15)*:
```solidity
File: src/FreshCryptoLib/FCL.sol

126:         uint256 index = 255;

151:                 if eq(zz, 2) {

155:                 if eq(zz, 3) {

191:                         if eq(T4, 2) {

195:                         if eq(T4, 3) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol)

```solidity
File: src/MagicSpend/MagicSpend.sol

138:             (uint256(withdrawRequest.expiry) << 160);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

164:         uint256 key = userOp.nonce >> 64;

168:             userOp.callData.length >= 4 &&

306:                 revert(add(result, 32), mload(result))

331:         if (ownerBytes.length == 32) {

340:                 owner := mload(add(ownerBytes, 32))

351:         if (ownerBytes.length == 64) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

```solidity
File: src/SmartWallet/MultiOwnable.sol

164:             if (owners[i].length != 32 && owners[i].length != 64) {

168:             if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

```solidity
File: src/WebAuthnSol/WebAuthn.sol

121:             webAuthnAuth.typeIndex + 21

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol)

### <a name="NC-4"></a>[NC-4] Control structures do not follow the Solidity Style Guide
See the [control structures](https://docs.soliditylang.org/en/latest/style-guide.html#control-structures) section of the Solidity Style Guide

*Instances (21)*:
```solidity
File: src/FreshCryptoLib/FCL.sol

131:             if (scalar_u == 0 && scalar_v == 0) return 0;

134:             if (

185:                         } // if T4!=0

278:         if (ecAff_IsZero(x0, y0)) return (x1, y1);

279:         if (ecAff_IsZero(x1, y1)) return (x0, y0);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol)

```solidity
File: src/MagicSpend/MagicSpend.sol

93:         if (msg.sender != entryPoint()) revert Unauthorized();

184:         if (amount == 0) revert NoExcess();

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

167:         if (

283:         if (

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

```solidity
File: src/SmartWallet/ERC1271.sol

45:             address verifyingContract,

53:         verifyingContract = address(this);

104:                 keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol)

```solidity
File: src/SmartWallet/MultiOwnable.sol

104:         if (owner.length == 0) revert NoOwnerAtIndex(index);

190:         if (isOwnerBytes(owner)) revert AlreadyOwner(owner);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

```solidity
File: src/WebAuthnSol/WebAuthn.sol

51:     address private constant VERIFIER = address(0x100);

105:     function verify(

142:         if (

150:         if (

175:         (bool success, bytes memory ret) = VERIFIER.staticcall(args);

182:         if (success && valid) return abi.decode(ret, (uint256)) == 1;

185:             FCL.ecdsa_verify(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol)

### <a name="NC-5"></a>[NC-5] Default Visibility for constants
Some constants are using the default visibility. For readability, consider explicitly declaring them as `internal`.

*Instances (10)*:
```solidity
File: src/FreshCryptoLib/FCL.sol

29:     address constant MODEXP_PRECOMPILE = 0x0000000000000000000000000000000000000005;

31:     uint256 constant p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;

33:     uint256 constant a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;

35:     uint256 constant b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;

37:     uint256 constant gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;

38:     uint256 constant gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;

40:     uint256 constant n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

42:     uint256 constant minus_2 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD;

44:     uint256 constant minus_2modn = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F;

46:     uint256 constant minus_1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol)

### <a name="NC-6"></a>[NC-6] Consider disabling `renounceOwnership()`
If the plan for your project does not include eventually giving up all ownership control, consider overwriting OpenZeppelin's `Ownable`'s `renounceOwnership()` function in order to disable it.

*Instances (1)*:
```solidity
File: src/MagicSpend/MagicSpend.sol

18: contract MagicSpend is Ownable, IPaymaster {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

### <a name="NC-7"></a>[NC-7] Functions should not be longer than 50 lines
Overly complex code can make understanding functionality more difficult, try to further modularize your code to ensure readability 

*Instances (43)*:
```solidity
File: src/FreshCryptoLib/FCL.sol

50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) {

78:     function ecAff_isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {

94:     function FCL_nModInv(uint256 u) internal view returns (uint256 result) {

274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) {

293:     function ecAff_IsZero(uint256, uint256 y) internal pure returns (bool flag) {

301:     function ecZZ_SetAff(uint256 x, uint256 y, uint256 zz, uint256 zzz)

318:     function ecZZ_Dbl(uint256 x, uint256 y, uint256 zz, uint256 zzz)

344:     function ecZZ_AddN(uint256 x1, uint256 y1, uint256 zz1, uint256 zzz1, uint256 x2, uint256 y2)

374:     function FCL_pModInv(uint256 u) internal view returns (uint256 result) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol)

```solidity
File: src/MagicSpend/MagicSpend.sol

193:     function withdraw(WithdrawRequest memory withdrawRequest) external {

228:     function entryPointDeposit(uint256 amount) external payable onlyOwner {

261:     function entryPointUnlockStake() external onlyOwner {

270:     function entryPointWithdrawStake(address payable to) external onlyOwner {

335:     function entryPoint() public pure returns (address) {

373:     function _withdraw(address asset, address to, uint256 amount) internal {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

129:     function initialize(bytes[] calldata owners) public payable virtual {

247:     function entryPoint() public view virtual returns (address) {

269:     function implementation() public view returns (address $) {

284:             functionSelector == MultiOwnable.addOwnerPublicKey.selector ||

285:             functionSelector == MultiOwnable.addOwnerAddress.selector ||

286:             functionSelector == MultiOwnable.removeOwnerAtIndex.selector ||

287:             functionSelector == UUPSUpgradeable.upgradeToAndCall.selector

302:     function _call(address target, uint256 value, bytes memory data) internal {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

80:     function initCodeHash() public view virtual returns (bytes32 result) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol)

```solidity
File: src/SmartWallet/ERC1271.sol

69:     function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4 result) {

90:     function replaySafeHash(bytes32 hash) public view virtual returns (bytes32) {

100:     function domainSeparator() public view returns (bytes32) {

121:     function _eip712Hash(bytes32 hash) internal view virtual returns (bytes32) {

133:     function _hashStruct(bytes32 hash) internal view virtual returns (bytes32) {

143:     function _domainNameAndVersion() internal view virtual returns (string memory name, string memory version);

155:     function _validateSignature(bytes32 message, bytes calldata signature) internal view virtual returns (bool);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol)

```solidity
File: src/SmartWallet/MultiOwnable.sol

85:     function addOwnerAddress(address owner) public virtual onlyOwner {

93:     function addOwnerPublicKey(bytes32 x, bytes32 y) public virtual onlyOwner {

102:     function removeOwnerAtIndex(uint256 index) public virtual onlyOwner {

117:     function isOwnerAddress(address account) public view virtual returns (bool) {

127:     function isOwnerPublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) {

136:     function isOwnerBytes(bytes memory account) public view virtual returns (bool) {

145:     function ownerAtIndex(uint256 index) public view virtual returns (bytes memory) {

152:     function nextOwnerIndex() public view virtual returns (uint256) {

162:     function _initializeOwners(bytes[] memory owners) internal virtual {

179:     function _addOwner(bytes memory owner) internal virtual {

189:     function _addOwnerAtIndex(bytes memory owner, uint256 index) internal virtual {

212:     function _getMultiOwnableStorage() internal pure returns (MultiOwnableStorage storage $) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

### <a name="NC-8"></a>[NC-8] Change int to int256
Throughout the code base, some variables are declared as `int`. To favor explicitness, consider changing all instances of `int` to `int256`

*Instances (3)*:
```solidity
File: src/FreshCryptoLib/FCL.sol

119:         uint256 Q1, //affine rep for input point Q

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol)

```solidity
File: src/MagicSpend/MagicSpend.sol

151:     ) external onlyEntryPoint {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

204:     ) public payable virtual onlyEntryPoint {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

### <a name="NC-9"></a>[NC-9] Use a `modifier` instead of a `require/if` statement for a special `msg.sender` actor
If a function is supposed to be access-controlled, a `modifier` should be used instead of a `require/if` statement for more readability.

*Instances (5)*:
```solidity
File: src/MagicSpend/MagicSpend.sol

93:         if (msg.sender != entryPoint()) revert Unauthorized();

196:         if (!isValidWithdrawSignature(msg.sender, withdrawRequest)) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

71:         if (msg.sender != entryPoint()) {

80:         if (msg.sender != entryPoint()) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

```solidity
File: src/SmartWallet/MultiOwnable.sol

202:         if (isOwnerAddress(msg.sender) || (msg.sender == address(this))) {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

### <a name="NC-10"></a>[NC-10] `address`s shouldn't be hard-coded
It is often better to declare `address`es as `immutable`, and assign them via constructor arguments. This allows the code to remain the same across deployments on different networks, and avoids recompilation when addresses need to change.

*Instances (3)*:
```solidity
File: src/FreshCryptoLib/FCL.sol

29:     address constant MODEXP_PRECOMPILE = 0x0000000000000000000000000000000000000005;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol)

```solidity
File: src/MagicSpend/MagicSpend.sol

336:         return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

248:         return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

### <a name="NC-11"></a>[NC-11] Take advantage of Custom Error's return value property
An important feature of Custom Error is that values such as address, tokenID, msg.value can be written inside the () sign, this kind of approach provides a serious advantage in debugging and examining the revert details of dapps such as tenderly.

*Instances (10)*:
```solidity
File: src/MagicSpend/MagicSpend.sol

89:     error UnexpectedPostOpRevertedMode();

93:         if (msg.sender != entryPoint()) revert Unauthorized();

154:             revert UnexpectedPostOpRevertedMode();

184:         if (amount == 0) revert NoExcess();

197:             revert InvalidSignature();

201:             revert Expired();

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

72:             revert Unauthorized();

131:             revert Initialized();

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

43:             revert OwnerRequired();

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol)

```solidity
File: src/SmartWallet/MultiOwnable.sol

206:         revert Unauthorized();

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

### <a name="NC-12"></a>[NC-12] Strings should use double quotes rather than single quotes
See the Solidity Style Guide: https://docs.soliditylang.org/en/v0.8.20/style-guide.html#other-recommendations

*Instances (2)*:
```solidity
File: src/WebAuthnSol/WebAuthn.sol

56:         keccak256('"type":"webauthn.get"');

129:             string.concat('"challenge":"', Base64.encodeURL(challenge), '"')

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol)

### <a name="NC-13"></a>[NC-13] Use Underscores for Number Literals (add an underscore every 3 digits)

*Instances (1)*:
```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

48:     uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)


## Low Issues


| |Issue|Instances|
|-|:-|:-:|
| [L-1](#L-1) | Use a 2-step ownership transfer pattern | 1 |
| [L-2](#L-2) | `domainSeparator()` isn't protected against replay attacks in case of a future chain split  | 2 |
| [L-3](#L-3) | External call recipient may consume all transaction gas | 3 |
| [L-4](#L-4) | Initializers could be front-run | 2 |
| [L-5](#L-5) | Unspecific compiler version pragma | 1 |
| [L-6](#L-6) | Upgradeable contract is missing a `__gap[50]` storage variable to allow for new storage variables in later versions | 3 |
| [L-7](#L-7) | Upgradeable contract not initialized | 11 |
### <a name="L-1"></a>[L-1] Use a 2-step ownership transfer pattern
Recommend considering implementing a two step process where the owner or admin nominates an account and the nominated account needs to call an `acceptOwnership()` function for the transfer of ownership to fully succeed. This ensures the nominated EOA account is a valid and active account. Lack of two-step procedure for critical operations leaves them error-prone. Consider adding two step procedure on the critical functions.

*Instances (1)*:
```solidity
File: src/MagicSpend/MagicSpend.sol

18: contract MagicSpend is Ownable, IPaymaster {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

### <a name="L-2"></a>[L-2] `domainSeparator()` isn't protected against replay attacks in case of a future chain split 
Severity: Low.
Description: See <https://eips.ethereum.org/EIPS/eip-2612#security-considerations>.
Remediation: Consider using the [implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/EIP712.sol#L77-L90) from OpenZeppelin, which recalculates the domain separator if the current `block.chainid` is not the cached chain ID.
Past occurrences of this issue:
- [Reality Cards Contest](https://github.com/code-423n4/2021-06-realitycards-findings/issues/166)
- [Swivel Contest](https://github.com/code-423n4/2021-09-swivel-findings/issues/98)
- [Malt Finance Contest](https://github.com/code-423n4/2021-11-malt-findings/issues/349)

*Instances (2)*:
```solidity
File: src/SmartWallet/ERC1271.sol

100:     function domainSeparator() public view returns (bytes32) {

122:         return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), _hashStruct(hash)));

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol)

### <a name="L-3"></a>[L-3] External call recipient may consume all transaction gas
There is no limit specified on the amount of gas used, so the recipient can use up all of the transaction's gas, causing it to revert. Use `addr.call{gas: <amount>}("")` or [this](https://github.com/nomad-xyz/ExcessivelySafeCall) library instead.

*Instances (3)*:
```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

168:             userOp.callData.length >= 4 &&

169:             bytes4(userOp.callData[0:4]) == 0xbf6ba1fc

303:         (bool success, bytes memory result) = target.call{value: value}(data);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

### <a name="L-4"></a>[L-4] Initializers could be front-run
Initializers could be front-run, allowing an attacker to either set their own values, take ownership of the contract, and in the best case forcing a re-deployment

*Instances (2)*:
```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

129:     function initialize(bytes[] calldata owners) public payable virtual {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

56:             account.initialize(owners);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol)

### <a name="L-5"></a>[L-5] Unspecific compiler version pragma

*Instances (1)*:
```solidity
File: src/FreshCryptoLib/FCL.sol

24: pragma solidity >=0.8.19 <0.9.0;

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol)

### <a name="L-6"></a>[L-6] Upgradeable contract is missing a `__gap[50]` storage variable to allow for new storage variables in later versions
See [this](https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps) link for a description of this storage variable. While some contracts may not currently be sub-classed, adding the variable now protects against forgetting to add it in the future.

*Instances (3)*:
```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

22:     UUPSUpgradeable,

287:             functionSelector == UUPSUpgradeable.upgradeToAndCall.selector

377:     ) internal view virtual override(UUPSUpgradeable) onlyOwner {}

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

### <a name="L-7"></a>[L-7] Upgradeable contract not initialized
Upgradeable contracts are initialized via an initializer function rather than by a constructor. Leaving such a contract uninitialized may lead to it being taken over by a malicious user

*Instances (11)*:
```solidity
File: src/MagicSpend/MagicSpend.sol

101:         Ownable._initializeOwner(_owner);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

22:     UUPSUpgradeable,

51:     error Initialized();

121:         _initializeOwners(owners);

129:     function initialize(bytes[] calldata owners) public payable virtual {

131:             revert Initialized();

134:         _initializeOwners(owners);

287:             functionSelector == UUPSUpgradeable.upgradeToAndCall.selector

377:     ) internal view virtual override(UUPSUpgradeable) onlyOwner {}

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

56:             account.initialize(owners);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol)

```solidity
File: src/SmartWallet/MultiOwnable.sol

162:     function _initializeOwners(bytes[] memory owners) internal virtual {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)


## Medium Issues


| |Issue|Instances|
|-|:-|:-:|
| [M-1](#M-1) | Centralization Risk for trusted owners | 16 |
| [M-2](#M-2) | Solady's SafeTransferLib does not check for token contract's existence | 1 |
### <a name="M-1"></a>[M-1] Centralization Risk for trusted owners

#### Impact:
Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

*Instances (16)*:
```solidity
File: src/MagicSpend/MagicSpend.sol

18: contract MagicSpend is Ownable, IPaymaster {

219:     ) external onlyOwner {

228:     function entryPointDeposit(uint256 amount) external payable onlyOwner {

241:     ) external onlyOwner {

254:     ) external payable onlyOwner {

261:     function entryPointUnlockStake() external onlyOwner {

270:     function entryPointWithdrawStake(address payable to) external onlyOwner {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)

```solidity
File: src/SmartWallet/CoinbaseSmartWallet.sol

21:     MultiOwnable,

354:             WebAuthn.WebAuthnAuth memory auth = abi.decode(

377:     ) internal view virtual override(UUPSUpgradeable) onlyOwner {}

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol)

```solidity
File: src/SmartWallet/MultiOwnable.sol

32: contract MultiOwnable {

85:     function addOwnerAddress(address owner) public virtual onlyOwner {

93:     function addOwnerPublicKey(bytes32 x, bytes32 y) public virtual onlyOwner {

102:     function removeOwnerAtIndex(uint256 index) public virtual onlyOwner {

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol)

```solidity
File: src/WebAuthnSol/WebAuthn.sol

21:     struct WebAuthnAuth {

108:         WebAuthnAuth memory webAuthnAuth,

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol)

### <a name="M-2"></a>[M-2] Solady's SafeTransferLib does not check for token contract's existence
There is a subtle difference between the implementation of solady’s SafeTransferLib and OZ’s SafeERC20: OZ’s SafeERC20 checks if the token is a contract or not, solady’s SafeTransferLib does not.
https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol#L10 
`@dev Note that none of the functions in this library check that a token has code at all! That responsibility is delegated to the caller` 


*Instances (1)*:
```solidity
File: src/MagicSpend/MagicSpend.sol

377:             SafeTransferLib.safeTransfer(asset, to, amount);

```
[Link to code](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol)
