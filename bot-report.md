# Winning bot race submission
This is the top-ranked automated findings report, from Pechenkata bot. All findings in this report will be considered known issues for the purposes of your C4 audit.

🔥

## Summary

| |Issue|Instances| Gas Savings
|-|:-|:-:|:-:|
| [[L-01](#l-01)] | Centralization risk for trusted owners | 16| 0|
| [[L-02](#l-02)] | Consider bounding input array length | 1| 0|
| [[L-03](#l-03)] | Consider disabling `renounceOwnership()` | 2| 0|
| [[L-04](#l-04)] | `constructor`/`initialize` function lacks parameter validation | 3| 0|
| [[L-05](#l-05)] | Deleting mapping in struct will not delete the mapping | 1| 0|
| [[L-06](#l-06)] | Low level calls to custom `address`es | 1| 0|
| [[L-07](#l-07)] | Missing contract-existence checks before low-level calls | 1| 0|
| [[L-08](#l-08)] | Missing `_disableInitializer()` in upgradeable constructor body | 1| 0|
| [[L-09](#l-09)] | Missing zero address check in functions with address parameters | 10| 0|
| [[L-10](#l-10)] | `onlyOwner` functions not accessible if `owner` renounces ownership | 9| 0|
| [[L-11](#l-11)] | `pure` function accesses storage | 1| 0|
| [[L-12](#l-12)] | `require()` should be used instead of `assert()` | 1| 0|
| [[L-13](#l-13)] | Some tokens may revert when zero value transfers are made | 1| 0|
| [[L-14](#l-14)] | Unused/empty `receive()/fallback()` function | 1| 0|
| [[L-15](#l-15)] | Upgradeable contract is missing a `__gap[50]` storage variable at the end to allow for new storage variables in later versions | 1| 0|
| [[L-16](#l-16)] | Use `Ownable2Step` rather than `Ownable` | 1| 0|
| [[G-01](#g-01)] | `++i` costs less gas than `i++`/`i += 1` (same for `--i` vs `i--`/`i -+ 1`) | 1| 5|
| [[G-02](#g-02)] | `++i`/`i++` should be `unchecked` when it is not possible for them to overflow | 1| 60|
| [[G-03](#g-03)] | `>=`/`<=` costs less gas than `>`/`<` | 10| 3|
| [[G-04](#g-04)] | `abi.encode()` is less efficient than `abi.encodePacked()` | 2| 0|
| [[G-05](#g-05)] | Add `unchecked {}` for subtractions where the operands cannot underflow because of a previous `require()` or `if-statement` | 1| 60|
| [[G-06](#g-06)] | Alternative Solady library can be used instead of OpenZeppelin to save gas | 1| 1000|
| [[G-07](#g-07)] | Avoid contract existence checks by using low-level calls | 4| 100|
| [[G-08](#g-08)] | Avoid unnecessary `public` variables | 1| 22000|
| [[G-09](#g-09)] | `bytes.concat()` can be used in place of `abi.encodePacked` | 2| 0|
| [[G-10](#g-10)] | Cache array length outside of loop | 2| 4|
| [[G-11](#g-11)] | Consider pre-calculating the address of `address(this)` | 7| 0|
| [[G-12](#g-12)] | Consider using OpenZeppelin's `EnumerateSet` instead of nested mappings | 1| 1000|
| [[G-13](#g-13)] | Consider using Solady's gas optimized lib for Math | 2| 0|
| [[G-14](#g-14)] | Constructors can be marked `payable` | 2| 21|
| [[G-15](#g-15)] | Counting down in `for` statements is more gas efficient | 2| 16|
| [[G-16](#g-16)] | Do not calculate constants | 1| 0|
| [[G-17](#g-17)] | `do`-`while` is cheaper than `for`-loops when the initial check can be skipped | 2| 255|
| [[G-18](#g-18)] | Don't transfer with zero amount to save gas | 1| 20|
| [[G-19](#g-19)] | Empty blocks should be removed or emit something | 2| 0|
| [[G-20](#g-20)] | Function names can be optimized | 5| 128|
| [[G-21](#g-21)] | Functions guaranteed to revert when called by normal users can be marked `payable` | 10| 21|
| [[G-22](#g-22)] | Integer increments by one can be unchecked | 3| 60|
| [[G-23](#g-23)] | Low-level `call` can be optimized with assembly | 2| 159|
| [[G-24](#g-24)] | Multiple accesses of the same mapping/array key/index should be cached | 2| 42|
| [[G-25](#g-25)] | Nesting `if`-statements is cheaper than using `&&` | 8| 30|
| [[G-26](#g-26)] | Newer versions of solidity are more gas efficient | 7| 0|
| [[G-27](#g-27)] | Not using the named return variables when a function returns, wastes deployment gas | 41| 0|
| [[G-28](#g-28)] | Optimize Deployment Size by Fine-tuning IPFS Hash | 7| 10600|
| [[G-29](#g-29)] | Simple checks for zero can be done using assembly to save gas | 11| 6|
| [[G-30](#g-30)] | Sort Solidity operations using short-circuit mode | 9| 0|
| [[G-31](#g-31)] | Stack variable is only used once | 10| 3|
| [[G-32](#g-32)] | State variables should be cached in stack variables rather than re-reading them from storage | 2| 100|
| [[G-33](#g-33)] | Struct can be reordered to fit into fewer storage slots | 1| 20000|
| [[G-34](#g-34)] | The result of a function call should be cached rather than re-calling the function | 1| 50|
| [[G-35](#g-35)] | Usage of `uints`/`ints` smaller than 32 bytes (256 bits) incurs overhead | 2| 6|
| [[G-36](#g-36)] | Use `Array.unsafeAccess()` to avoid repeated array length checks | 4| 2100|
| [[G-37](#g-37)] | Use assembly for small `keccak256` hashes, in order to save gas | 6| 80|
| [[G-38](#g-38)] | Use assembly in place of `abi.decode` to save gas | 6| 112|
| [[G-39](#g-39)] | Use assembly scratch space to build calldata for external calls | 4| 220|
| [[G-40](#g-40)] | Use assembly to validate `msg.sender` | 2| 12|
| [[G-41](#g-41)] | Use `assembly` to write address/contract storage values | 3| 50|
| [[G-42](#g-42)] | Use `calldata` instead of `memory` for function arguments that do not get mutated | 4| 300|
| [[G-43](#g-43)] | Use constants instead of `type(uint<n>).max` / `.min` | 2| 4|
| [[G-44](#g-44)] | Use scratch space when building emitted events with two data arguments | 2| 38|
| [[G-45](#g-45)] | Use `selfbalance()` instead of `address(this).balance` | 1| 0|
| [[G-46](#g-46)] | Use shift right/left instead of division/multiplication if possible | 1| 20|
| [[G-47](#g-47)] | Use `uint256(1)`/`uint256(2)` instead of `true`/`false` to save gas for changes | 1| 17100|
| [[G-48](#g-48)] | Using `private` rather than `public`, saves gas | 2| 3606|
| [[G-49](#g-49)] | Using `storage` instead of `memory` for structs/arrays saves gas | 4| 2100|
| [[G-50](#g-50)] | x + y is more efficient than using += for state variables (likewise for -=) | 1| 248|
| [[N-01](#n-01)] | Add inline comments for unnamed variables | 2| 0|
| [[N-02](#n-02)] | `address` shouldn't be hard-coded | 3| 0|
| [[N-03](#n-03)] | Assembly block creates dirty bits | 3| 0|
| [[N-04](#n-04)] | Assembly blocks should have extensive comments | 8| 0|
| [[N-05](#n-05)] | Avoid mutating `function`/`modifier` parameters | 2| 0|
| [[N-06](#n-06)] | Avoid revertible function calls in a constructor | 1| 0|
| [[N-07](#n-07)] | Avoid the use of sensitive terms | 14| 0|
| [[N-08](#n-08)] | Common functions should be refactored to a common base contract | 1| 0|
| [[N-09](#n-09)] | Complicated functions should have explicit comments | 1| 0|
| [[N-10](#n-10)] | Consider adding a block/deny-list | 4| 0|
| [[N-11](#n-11)] | Consider making contracts `Upgradeable` | 4| 0|
| [[N-12](#n-12)] | Consider using `delete` rather than assigning zero to clear values | 1| 0|
| [[N-13](#n-13)] | Constants in comparisons should appear on the left side | 13| 0|
| [[N-14](#n-14)] | `constant`s should be defined rather than using magic numbers | 17| 0|
| [[N-15](#n-15)] | `constant`s/`immutable`s redefined elsewhere | 18| 0|
| [[N-16](#n-16)] | `constructor` should emit an event | 3| 0|
| [[N-17](#n-17)] | Contracts should have all `public`/`external` functions exposed by `interface`s | 4| 0|
| [[N-18](#n-18)] | Control structures do not follow the Solidity Style Guide | 17| 0|
| [[N-19](#n-19)] | Custom `error` without details | 7| 0|
| [[N-20](#n-20)] | Empty bytes check is missing | 9| 0|
| [[N-21](#n-21)] | Empty function body | 1| 0|
| [[N-22](#n-22)] | Enum values should be used instead of constant array indexes | 3| 0|
| [[N-23](#n-23)] | Event is missing `indexed` fields | 3| 0|
| [[N-24](#n-24)] | Events are missing sender information | 3| 0|
| [[N-25](#n-25)] | Expressions for `constant` values should use `immutable` rather than constant | 4| 0|
| [[N-26](#n-26)] | For loops in `public` or `external` functions should be avoided due to high gas costs and possible DOS | 1| 0|
| [[N-27](#n-27)] | Function called does not exist in the contract interface | 4| 0|
| [[N-28](#n-28)] | Function ordering in the contract does not follow the Solidity style guide | 13| 0|
| [[N-29](#n-29)] | Functions not used internally could be marked external | 1| 0|
| [[N-30](#n-30)] | Functions should be named in mixedCase style | 10| 0|
| [[N-31](#n-31)] | High cyclomatic complexity | 3| 0|
| [[N-32](#n-32)] | `if`-statement can be converted to a ternary | 1| 0|
| [[N-33](#n-33)] | Imports could be organized more systematically | 2| 0|
| [[N-34](#n-34)] | Inconsistent method of specifying a floating pragma | 1| 0|
| [[N-35](#n-35)] | Inconsistent spacing in comments | 32| 0|
| [[N-36](#n-36)] | Large numeric literals should use underscores for readability | 1| 0|
| [[N-37](#n-37)] | Layout order does not comply with best practices | 1| 0|
| [[N-38](#n-38)] | Lines are too long | 18| 0|
| [[N-39](#n-39)] | Long functions should be refactored into multiple, smaller, functions | 1| 0|
| [[N-40](#n-40)] | Make use of Solidity's `using` keyword | 12| 0|
| [[N-41](#n-41)] | Misplaced SPDX identifier | 1| 0|
| [[N-42](#n-42)] | Missing checks for `address(0x0)` in the constructor | 2| 0|
| [[N-43](#n-43)] | Missing events in initializers | 1| 0|
| [[N-44](#n-44)] | Multiple type casts create complexity within the code | 2| 0|
| [[N-45](#n-45)] | NatSpec: Contract declarations should have `@author` tags | 1| 0|
| [[N-46](#n-46)] | NatSpec: Contract declarations should have `@dev` tags | 4| 0|
| [[N-47](#n-47)] | NatSpec: Contract declarations should have `@notice` tags | 1| 0|
| [[N-48](#n-48)] | NatSpec: Contract declarations should have `@title` tags | 1| 0|
| [[N-49](#n-49)] | NatSpec: Contract declarations should have NatSpec descriptions | 1| 0|
| [[N-50](#n-50)] | NatSpec: Error missing NatSpec `@dev` tag | 12| 0|
| [[N-51](#n-51)] | NatSpec: Error missing NatSpec `@param` tag | 2| 0|
| [[N-52](#n-52)] | NatSpec: Event missing NatSpec `@dev` tag | 3| 0|
| [[N-53](#n-53)] | NatSpec: File is missing NatSpec Documentation | 1| 0|
| [[N-54](#n-54)] | NatSpec: Function declarations should have `@notice` tags | 6| 0|
| [[N-55](#n-55)] | NatSpec: Function declarations should have NatSpec descriptions | 2| 0|
| [[N-56](#n-56)] | NatSpec: Functions missing NatSpec `@dev` tag | 28| 0|
| [[N-57](#n-57)] | NatSpec: Functions missing NatSpec `@param` tag | 20| 0|
| [[N-58](#n-58)] | NatSpec: Functions missing NatSpec `@return` tag | 18| 0|
| [[N-59](#n-59)] | NatSpec: Modifier missing NatSpec `@dev` tag | 3| 0|
| [[N-60](#n-60)] | NatSpec: Modifier missing NatSpec `@param` tag | 1| 0|
| [[N-61](#n-61)] | Natspec: Use `@inheritdoc` rather than using a non-standard tags | 2| 0|
| [[N-62](#n-62)] | Non-`external`/`public` function names should begin with an underscore | 11| 0|
| [[N-63](#n-63)] | Non-library/interface files should use fixed compiler versions, not floating ones | 3| 0|
| [[N-64](#n-64)] | Not using the latest versions of project dependencies | 1| 0|
| [[N-65](#n-65)] | Not using the named return variables anywhere in the function is confusing | 6| 0|
| [[N-66](#n-66)] | Outdated Solidity version | 7| 0|
| [[N-67](#n-67)] | Parameter change does not emit event | 2| 0|
| [[N-68](#n-68)] | Prefer skip over revert model in iteration | 1| 0|
| [[N-69](#n-69)] | `public` functions not called by the contract should be declared `external` instead | 13| 0|
| [[N-70](#n-70)] | `receive()`/`payable fallback()` function does not authorize requests | 1| 0|
| [[N-71](#n-71)] | Returning a struct instead of a bunch of variables is better | 3| 0|
| [[N-72](#n-72)] | Some variables have a implicit default visibility | 9| 0|
| [[N-73](#n-73)] | State variables should include comments | 2| 0|
| [[N-74](#n-74)] | Top-level declarations should be separated by at least two lines | 9| 0|
| [[N-75](#n-75)] | Typos | 89| 0|
| [[N-76](#n-76)] | Unnecessary struct attribute prefix | 1| 0|
| [[N-77](#n-77)] | Unspecific compiler version pragma | 1| 0|
| [[N-78](#n-78)] | Unused `error` definition | 1| 0|
| [[N-79](#n-79)] | Upgradeable contract not initialized | 1| 0|
| [[N-80](#n-80)] | Use a single file for system wide constants | 17| 0|
| [[N-81](#n-81)] | Use a struct to encapsulate multiple function parameters | 2| 0|
| [[N-82](#n-82)] | Use `bytes.concat()` on bytes instead of `abi.encodePacked()` for clearer semantic meaning | 2| 0|
| [[N-83](#n-83)] | Use EIP-5627 to describe EIP-712 domains | 1| 0|
| [[N-84](#n-84)] | Use of `override` is unnecessary | 3| 0|
| [[N-85](#n-85)] | Use UPPER_CASE for `constant` | 8| 0|
| [[N-86](#n-86)] | Use UPPER_CASE for `immutable` | 1| 0|
| [[N-87](#n-87)] | Variables should be named in mixedCase style | 15| 0|
| [[N-88](#n-88)] | Zero as a function argument should have a descriptive meaning | 1| 0|
| [[D-01](#d-01)] | File allows a version of solidity that is susceptible to `.selector`-related optimizer bug | 6| 0|
| [[D-02](#d-02)] | Functions contain the same code | 16| 0|
| [[D-03](#d-03)] | Inline `modifier`s that are only used once, to save gas | 1| 0|
| [[D-04](#d-04)] | State variable read in a loop | 14| 0|
| [[D-05](#d-05)] | `++i` costs less gas than `i++`, especially when it's used in for-loops (`--i`/`i--` too) | 2| 0|
| [[D-06](#d-06)] | All interfaces used within a project should be imported | 5| 0|
| [[D-07](#d-07)] | Array lengths not checked | 6| 0|
| [[D-08](#d-08)] | Assembly blocks should have comments | 2| 0|
| [[D-09](#d-09)] | Avoid double casting | 1| 0|
| [[D-10](#d-10)] | Consider adding a block/deny-list | 3| 0|
| [[D-11](#d-11)] | Consider merging sequential for loops | 2| 0|
| [[D-12](#d-12)] | Default `bool` values are manually reset | 2| 0|
| [[D-13](#d-13)] | Event names should use CamelCase | 3| 0|
| [[D-14](#d-14)] | Function can be declared as `pure` | 1| 0|
| [[D-15](#d-15)] | Function definition modifier order does not follow Solidity style guide | 11| 0|
| [[D-16](#d-16)] | Functions missing NatSpec `@param` tag | 4| 0|
| [[D-17](#d-17)] | Inconsistent comment spacing | 24| 0|
| [[D-18](#d-18)] | Integer increments by one can be unchecked to save on gas fees | 1| 0|
| [[D-19](#d-19)] | Low level calls with Solidity before `0.8.14` result in an optimiser bug | 1| 0|
| [[D-20](#d-20)] | Magic numbers should be replaced with constants | 9| 0|
| [[D-21](#d-21)] | Misplaced SPDX identifier | 6| 0|
| [[D-22](#d-22)] | Multiple mappings with same keys can be combined into a single struct mapping for readability | 1| 0|
| [[D-23](#d-23)] | Prefer double quotes for string quoting | 4| 0|
| [[D-24](#d-24)] | Timestamp may be manipulation | 1| 0|
| [[D-25](#d-25)] | Unsafe downcast | 19| 0|
| [[D-26](#d-26)] | Unused named return variables without optimizer waste gas | 10| 0|
| [[D-27](#d-27)] | Use != 0 instead of > 0 for unsigned integer comparison | 1| 0|
| [[D-28](#d-28)] | Use assembly to emit events, in order to save gas | 1| 0|
| [[D-29](#d-29)] | Use SafeCast to safely cast variables | 19| 0|
| [[D-30](#d-30)] | Use `string.concat()` on strings instead of `abi.encodePacked()` for clearer semantic meaning | 2| 0|
| [[D-31](#d-31)] | Using `bool`s for storage incurs overhead | 2| 0|

### Low Risk Issues

### [L-01]<a name="l-01"></a> Centralization risk for trusted owners

Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

*There are 16 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit onlyEntryPoint
109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost) 
110:         external
111:         onlyEntryPoint
112:         returns (bytes memory context, uint256 validationData)
113:     {
/// @audit onlyEntryPoint
143:     function postOp(IPaymaster.PostOpMode mode, bytes calldata context, uint256 actualGasCost) 
144:         external
145:         onlyEntryPoint
146:     {
/// @audit onlyOwner
203:     function ownerWithdraw(address asset, address to, uint256 amount) external onlyOwner { 
/// @audit onlyOwner
212:     function entryPointDeposit(uint256 amount) external payable onlyOwner { 
/// @audit onlyOwner
222:     function entryPointWithdraw(address payable to, uint256 amount) external onlyOwner { 
/// @audit onlyOwner
232:     function entryPointAddStake(uint256 amount, uint32 unstakeDelaySeconds) external payable onlyOwner { 
/// @audit onlyOwner
239:     function entryPointUnlockStake() external onlyOwner { 
/// @audit onlyOwner
248:     function entryPointWithdrawStake(address payable to) external onlyOwner { 
```


*GitHub* : [222](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L222-L222), [232](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L232-L232), [239](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L239-L239), [248](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L248-L248), [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L109-L113), [143](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L143-L146), [203](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L203-L203), [212](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L212-L212)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit onlyEntryPoint
137:     function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
138:         public
139:         payable
140:         virtual
141:         onlyEntryPoint
142:         payPrefund(missingAccountFunds)
143:         returns (uint256 validationData)
144:     {
/// @audit onlyEntryPoint
180:     function executeWithoutChainIdValidation(bytes calldata data) public payable virtual onlyEntryPoint { 
/// @audit onlyEntryPointOrOwner
196:     function execute(address target, uint256 value, bytes calldata data) public payable virtual onlyEntryPointOrOwner { 
/// @audit onlyEntryPointOrOwner
205:     function executeBatch(Call[] calldata calls) public payable virtual onlyEntryPointOrOwner { 
/// @audit onlyOwner
330:     function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {} 
```


*GitHub* : [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L137-L144), [330](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L330-L330), [205](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L205-L205), [196](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L196-L196), [180](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L180-L180)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit onlyOwner
85:     function addOwnerAddress(address owner) public virtual onlyOwner { 
/// @audit onlyOwner
93:     function addOwnerPublicKey(bytes32 x, bytes32 y) public virtual onlyOwner { 
/// @audit onlyOwner
102:     function removeOwnerAtIndex(uint256 index) public virtual onlyOwner { 
```


*GitHub* : [102](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L102-L102), [85](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L85-L85), [93](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L93-L93)

### [L-02]<a name="l-02"></a> Consider bounding input array length

The functions below take in an unbounded array, and make function calls for entries in the array. While the function will revert if it eventually runs out of gas, it may be a nicer user experience to `require()` that the length of the array is below some reasonable maximum, so that the user doesn't have to use up a full transaction's gas only to see that the transaction reverts.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit calls.length not bounded
206:         for (uint256 i; i < calls.length;) { 
207:             _call(calls[i].target, calls[i].value, calls[i].data);
208:             unchecked {
209:                 ++i;
210:             }
211:         }
```


*GitHub* : [206](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L206-L211)

### [L-03]<a name="l-03"></a> Consider disabling `renounceOwnership()`

Typically, the contract's owner is the account that deploys the contract. As a result, the owner is able to perform certain privileged activities. The OpenZeppelin's `Ownable` is used in this project contract implements `renounceOwnership`. This can represent a certain risk if the ownership is renounced for any other reason than by design. Renouncing ownership will leave the contract without an owner, thereby removing any functionality that is only available to the owner.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

18: contract MagicSpend is Ownable, IPaymaster { 
```


*GitHub* : [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L18-L18)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

20: contract CoinbaseSmartWallet is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 { 
```


*GitHub* : [20](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L20-L20)

### [L-04]<a name="l-04"></a> `constructor`/`initialize` function lacks parameter validation

Constructors and initialization functions play a critical role in contracts by setting important initial states when the contract is first deployed before the system starts. The parameters passed to the constructor and initialization functions directly affect the behavior of the contract / protocol. If incorrect parameters are provided, the system may fail to run, behave abnormally, be unstable, or lack security. Therefore, it's crucial to carefully check each parameter in the constructor and initialization functions. If an exception is found, the transaction should be rolled back.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit _owner 
101:     constructor(address _owner) { 
```


*GitHub* : [101](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L101-L101)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit owners 
114:     function initialize(bytes[] calldata owners) public payable virtual { 
```


*GitHub* : [114](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L114-L114)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit erc4337 
24:     constructor(address erc4337) payable { 
```


*GitHub* : [24](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L24-L24)

### [L-05]<a name="l-05"></a> Deleting mapping in struct will not delete the mapping

_

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

106:         delete _getMultiOwnableStorage().isOwner[owner]; 
107:         delete _getMultiOwnableStorage().ownerAtIndex[index];
```


*GitHub* : [106](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L106-L107)

### [L-06]<a name="l-06"></a> Low level calls to custom `address`es

Low-level calls (such as `.call()`, `.delegatecall()`, or `.callcode()`) in Solidity provide a way to interact with other contracts or addresses. However, when these calls are made to addresses that are provided as parameters or are not well-validated, they pose a significant security risk. Untrusted addresses might contain malicious code leading to unexpected behavior, loss of funds, or vulnerabilities.

**Resolution**: Prefer using high-level Solidity function calls or interface-based interactions with known contracts to ensure security. If low-level calls are necessary, rigorously validate the addresses and test all possible interactions. Implementing additional checks and fail-safes can help mitigate potential risks associated with low-level calls.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit low level call to 'target' on line 273
272:     function _call(address target, uint256 value, bytes memory data) internal { 
273:         (bool success, bytes memory result) = target.call{value: value}(data);
274:         if (!success) {
275:             assembly ("memory-safe") {
276:                 revert(add(result, 32), mload(result))
277:             }
278:         }
279:     }
```


*GitHub* : [272](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L272-L279)

### [L-07]<a name="l-07"></a> Missing contract-existence checks before low-level calls

Low-level calls return success if there is no code present at the specified address.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit line 273
272:     function _call(address target, uint256 value, bytes memory data) internal { 
273:         (bool success, bytes memory result) = target.call{value: value}(data);
274:         if (!success) {
275:             assembly ("memory-safe") {
276:                 revert(add(result, 32), mload(result))
277:             }
278:         }
279:     }
```


*GitHub* : [272](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L272-L279)

### [L-08]<a name="l-08"></a> Missing `_disableInitializer()` in upgradeable constructor body

Avoid leaving a contract uninitialized.
An uninitialized contract can be taken over by an attacker. This applies to both a proxy and its implementation contract, which may impact the proxy. To prevent the implementation contract from being used, you should invoke the `_disableInitializers()` function in the constructor to automatically lock it when it is deployed.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

102:     constructor() { 
103:         // Implementation should not be initializable (does not affect proxies which use their own storage).
104:         bytes[] memory owners = new bytes[](1);
105:         owners[0] = abi.encode(address(0));
106:         _initializeOwners(owners);
107:     }
```


*GitHub* : [102](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L102-L107)

### [L-09]<a name="l-09"></a> Missing zero address check in functions with address parameters

Adding a zero address check for each address type parameter can prevent errors.

*There are 10 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit asset, to
203:     function ownerWithdraw(address asset, address to, uint256 amount) external onlyOwner { 
/// @audit account
260:     function isValidWithdrawSignature(address account, WithdrawRequest memory withdrawRequest) 
261:         public
262:         view
263:         returns (bool)
264:     {
/// @audit account
279:     function getHash(address account, WithdrawRequest memory withdrawRequest) public view returns (bytes32) { 
/// @audit account
299:     function nonceUsed(address account, uint256 nonce) external view returns (bool) { 
/// @audit account
315:     function _validateRequest(address account, WithdrawRequest memory withdrawRequest) internal { 
/// @audit asset, to
334:     function _withdraw(address asset, address to, uint256 amount) internal { 
```


*GitHub* : [279](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L279-L279), [299](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L299-L299), [260](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L260-L264), [315](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L315-L315), [203](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L203-L203), [334](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L334-L334)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit target
196:     function execute(address target, uint256 value, bytes calldata data) public payable virtual onlyEntryPointOrOwner { 
/// @audit target
272:     function _call(address target, uint256 value, bytes memory data) internal { 
```


*GitHub* : [196](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L196-L196), [272](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L272-L272)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit owner
85:     function addOwnerAddress(address owner) public virtual onlyOwner { 
/// @audit account
117:     function isOwnerAddress(address account) public view virtual returns (bool) { 
```


*GitHub* : [85](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L85-L85), [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L117-L117)

### [L-10]<a name="l-10"></a> `onlyOwner` functions not accessible if `owner` renounces ownership

The `owner` is able to perform certain privileged activities, but it's possible to set the owner to `address(0)`. This can represent a certain risk if the ownership is renounced for any other reason than by design.

Renouncing ownership will leave the contract without an `owner`, therefore limiting any functionality that needs authority.

*There are 9 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

203:     function ownerWithdraw(address asset, address to, uint256 amount) external onlyOwner { 
212:     function entryPointDeposit(uint256 amount) external payable onlyOwner { 
222:     function entryPointWithdraw(address payable to, uint256 amount) external onlyOwner { 
232:     function entryPointAddStake(uint256 amount, uint32 unstakeDelaySeconds) external payable onlyOwner { 
239:     function entryPointUnlockStake() external onlyOwner { 
248:     function entryPointWithdrawStake(address payable to) external onlyOwner { 
```


*GitHub* : [203](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L203-L203), [212](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L212-L212), [222](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L222-L222), [232](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L232-L232), [239](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L239-L239), [248](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L248-L248)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

196:     function execute(address target, uint256 value, bytes calldata data) public payable virtual onlyEntryPointOrOwner { 
205:     function executeBatch(Call[] calldata calls) public payable virtual onlyEntryPointOrOwner { 
330:     function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {} 
```


*GitHub* : [196](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L196-L196), [205](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L205-L205), [330](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L330-L330)

### [L-11]<a name="l-11"></a> `pure` function accesses storage

While the compiler currently flags functions like these as being `pure`, this is a [bug](https://github.com/ethereum/solidity/issues/11573) which will be fixed in a future version, so it's best to not use `pure` visibility, in order to not break when this bug is fixed.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

212:     function _getMultiOwnableStorage() internal pure returns (MultiOwnableStorage storage $) { 
213:         assembly ("memory-safe") {
214:             $.slot := MUTLI_OWNABLE_STORAGE_LOCATION
215:         }
216:     }
```


*GitHub* : [212](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L212-L216)

### [L-12]<a name="l-12"></a> `require()` should be used instead of `assert()`

Prior to solidity version 0.8.0, hitting an assert consumes the **remainder of the transaction's available gas** rather than returning it, as `require()`/`revert()` do. `assert()` should be avoided even past solidity version 0.8.0 as its [documentation](https://docs.soliditylang.org/en/v0.8.14/control-structures.html#panic-via-assert-and-error-via-require) states that "The assert function creates an error of type Panic(uint256). ... Properly functioning code should never create a Panic, not even on invalid external input. If this happens, then there is a bug in your contract which you should fix".

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

150:         assert(mode != PostOpMode.postOpReverted); 
```


*GitHub* : [150](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L150)

### [L-13]<a name="l-13"></a> Some tokens may revert when zero value transfers are made

In spite of the fact that EIP-20 [states](https://github.com/ethereum/EIPs/blob/46b9b698815abbfa628cd1097311deee77dd45c5/EIPS/eip-20.md?plain=1#L116) that zero-valued transfers must be accepted, some tokens, such as `LEND` will revert if this is attempted, which may cause transactions that involve other tokens (such as batch operations) to fully revert. Consider skipping the transfer if the amount is zero, which will also save **gas**.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

338:             SafeTransferLib.safeTransfer(asset, to, amount); 
```


*GitHub* : [338](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L338-L338)

### [L-14]<a name="l-14"></a> Unused/empty `receive()/fallback()` function

If the intention is for the Ether to be used, the function should call another function or emit an event, otherwise it should revert.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

106:     receive() external payable {} 
```


*GitHub* : [106](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L106-L106)

### [L-15]<a name="l-15"></a> Upgradeable contract is missing a `__gap[50]` storage variable at the end to allow for new storage variables in later versions

See [this](https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps) link for a description of this storage variable. While some contracts may not currently be sub-classed, adding the variable now protects against forgetting to add it in the future.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

20: contract CoinbaseSmartWallet is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 { 
21:     /// @notice Wrapper struct, used during signature validation, tie a signature with its signer.
22:     struct SignatureWrapper {
23:         /// @dev The index indentifying owner (see MultiOwnable) who signed.
24:         uint256 ownerIndex;
25:         /// @dev An ABI encoded ECDSA signature (r, s, v) or WebAuthnAuth struct.
```


*GitHub* : [20](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L20-L25)

### [L-16]<a name="l-16"></a> Use `Ownable2Step` rather than `Ownable`

[`Ownable2Step`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/3d7a93876a2e5e1d7fe29b5a0e96e222afdc4cfa/contracts/access/Ownable2Step.sol#L31-L56) and [`Ownable2StepUpgradeable`](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/25aabd286e002a1526c345c8db259d57bdf0ad28/contracts/access/Ownable2StepUpgradeable.sol#L47-L63) prevent the contract ownership from mistakenly being transferred to an address that cannot handle it (e.g. due to a typo in the address), by requiring that the recipient of the owner permissions actively accept via a contract call of its own.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

18: contract MagicSpend is Ownable, IPaymaster { 
```


*GitHub* : [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L18-L18)

### Gas Risk Issues

### [G-01]<a name="g-01"></a> `++i` costs less gas than `i++`/`i += 1` (same for `--i` vs `i--`/`i -+ 1`)

_

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) { 
```


*GitHub* : [163](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L163-L163)

### [G-02]<a name="g-02"></a> `++i`/`i++` should be `unchecked` when it is not possible for them to overflow

The `unchecked` keyword is new in solidity version 0.8.0, so this only applies to that version or higher, which these instances are. This saves **30-40 gas [per loop](https://gist.github.com/hrkrshnn/ee8fabd532058307229d65dcd5836ddc#the-increment-in-for-loop-post-condition-can-be-made-unchecked)**

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) { 
```


*GitHub* : [163](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L163-L163)

### [G-03]<a name="g-03"></a> `>=`/`<=` costs less gas than `>`/`<`

The compiler uses opcodes `GT` and `ISZERO` for code that uses `>`, but only requires `LT` for `>=`. A similar behaviour applies for `>`, which uses opcodes `LT` and `ISZERO`, but only requires `GT` for `<=`.

*There are 10 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

117:         if (withdrawAmount < maxCost) { 
133:         if (address(this).balance < withdrawAmount) { 
160:         if (withdrawable > 0) { 
188:         if (block.timestamp > withdrawRequest.expiry) { 
```


*GitHub* : [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L117-L117), [133](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L133-L133), [160](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L160-L160), [188](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L188-L188)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

206:         for (uint256 i; i < calls.length;) { 
302:             if (uint256(bytes32(ownerBytes)) > type(uint160).max) { 
```


*GitHub* : [206](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L206-L206), [302](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L302-L302)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) { 
168:             if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) { 
```


*GitHub* : [163](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L163-L163), [168](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L168-L168)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

109:         if (webAuthnAuth.s > P256_N_DIV_2) { 
157:         bool valid = ret.length > 0; 
```


*GitHub* : [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L109-L109), [157](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L157-L157)

### [G-04]<a name="g-04"></a> `abi.encode()` is less efficient than `abi.encodePacked()`

See for more information: https://github.com/ConnorBlockchain/Solidity-Encode-Gas-Comparison

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/ERC1271.sol

122:         return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), _hashStruct(hash))); 
```


*GitHub* : [122](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L122)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

148:         bytes32 messageHash = sha256(abi.encodePacked(webAuthnAuth.authenticatorData, clientDataJSONHash)); 
```


*GitHub* : [148](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L148)

### [G-05]<a name="g-05"></a> Add `unchecked {}` for subtractions where the operands cannot underflow because of a previous `require()` or `if-statement`


1. `require(a <= b); x = b - a` => `require(a <= b); unchecked { x = b - a }`
2. `require(b >= a); x = b - a` => `require(a <= b); unchecked { x = b - a }`

3. `if (b < a) revert(...);  x = b - a` => `if (b < a) revert(...);  unchecked { x = b - a }`
4. `if (a > b) revert(...);  x = b - a` => `if (b < a) revert(...);  unchecked { x = b - a }`

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

138:         _withdrawableETH[userOp.sender] += withdrawAmount - maxCost; 
```


*GitHub* : [138](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L138-L138)

### [G-06]<a name="g-06"></a> Alternative Solady library can be used instead of OpenZeppelin to save gas

The following OpenZeppelin imports have a [Solady](https://github.com/Vectorized/solady) equivalent, as such they can be used to save GAS as Solady modules have been specifically designed to be as GAS efficient as possible.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

5: import {Base64} from "openzeppelin-contracts/contracts/utils/Base64.sol"; 
```


*GitHub* : [5](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L5-L5)

### [G-07]<a name="g-07"></a> Avoid contract existence checks by using low-level calls

Prior to 0.8.10 the compiler inserted extra code, including `EXTCODESIZE` (**100 gas**), to check for contract existence for external function calls. In more recent solidity versions, the compiler will not insert these checks if the external call has a return value. Similar behavior can be achieved in earlier versions by using low-level calls, since low-level calls never check for contract existence

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

223:         IEntryPoint(entryPoint()).withdrawTo(to, amount); 
233:         IEntryPoint(entryPoint()).addStake{value: amount}(unstakeDelaySeconds); 
240:         IEntryPoint(entryPoint()).unlockStake(); 
249:         IEntryPoint(entryPoint()).withdrawStake(to); 
```


*GitHub* : [223](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L223-L223), [233](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L233-L233), [240](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L240-L240), [249](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L249-L249)

### [G-08]<a name="g-08"></a> Avoid unnecessary `public` variables

Public state variables in Solidity automatically generate getter functions, increasing contract size and potentially leading to higher deployment and interaction costs. To optimize gas usage and contract efficiency, minimize the use of public variables unless external access is necessary. Instead, use internal or private visibility combined with explicit getter functions when required. This practice not only reduces contract size but also provides better control over data access and manipulation, enhancing security and readability. Prioritize lean, efficient contracts to ensure cost-effectiveness and better performance on the blockchain.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

15:     address public immutable implementation; 
```


*GitHub* : [15](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L15-L15)

### [G-09]<a name="g-09"></a> `bytes.concat()` can be used in place of `abi.encodePacked`

Given concatenation is not going to be used for hashing `bytes.concat` is the preferred method to use as its more gas efficient

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/ERC1271.sol

122:         return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), _hashStruct(hash))); 
```


*GitHub* : [122](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L122-L122)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

148:         bytes32 messageHash = sha256(abi.encodePacked(webAuthnAuth.authenticatorData, clientDataJSONHash)); 
```


*GitHub* : [148](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L148-L148)

### [G-10]<a name="g-10"></a> Cache array length outside of loop

If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

206:         for (uint256 i; i < calls.length;) { 
```


*GitHub* : [206](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L206)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) { 
```


*GitHub* : [163](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L163)

### [G-11]<a name="g-11"></a> Consider pre-calculating the address of `address(this)`

It can be more gas-efficient to use a hardcoded address instead of the `address(this)` expression, especially if you need to use the same address multiple times in your contract.

The reason for this, is that using `address(this)` requires an additional `EXTCODESIZE` operation to retrieve the contract’s address from its bytecode, which can increase the gas cost of your contract. By pre-calculating and using a hardcoded address, you can avoid this additional operation and reduce the overall gas cost of your contract.

*There are 7 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

133:         if (address(this).balance < withdrawAmount) { 
134:             revert InsufficientBalance(withdrawAmount, address(this).balance);
282:                 address(this), 
```


*GitHub* : [133](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L133-L134), [282](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L282)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

186:         _call(address(this), 0, data); 
```


*GitHub* : [186](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L186)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

65:         predicted = LibClone.predictDeterministicAddress(initCodeHash(), _getSalt(owners, nonce), address(this)); 
```


*GitHub* : [65](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L65)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

53:         verifyingContract = address(this); 
108:                 address(this) 
```


*GitHub* : [53](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L53), [108](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L108)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

202:         if (isOwnerAddress(msg.sender) || (msg.sender == address(this))) { 
```


*GitHub* : [202](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L202)

### [G-12]<a name="g-12"></a> Consider using OpenZeppelin's `EnumerateSet` instead of nested mappings

Nested mappings and multi-dimensional arrays in Solidity operate through a process of double hashing, wherein the original storage slot and the first key are concatenated and hashed, and then this hash is again concatenated with the second key and hashed. This process can be quite gas expensive due to the double-hashing operation and subsequent storage operation (sstore).

OpenZeppelin's `EnumerableSet` provides a potential solution to this problem. It creates a data structure that combines the benefits of set operations with the ability to enumerate stored elements, which is not natively available in Solidity. EnumerableSet handles the element uniqueness internally and can therefore provide a more gas-efficient and collision-resistant alternative to nested mappings or multi-dimensional arrays in certain scenarios.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

37:     mapping(uint256 nonce => mapping(address user => bool used)) internal _nonceUsed; 
```


*GitHub* : [37](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L37-L37)

### [G-13]<a name="g-13"></a> Consider using Solady's gas optimized lib for Math

Utilizing gas-optimized math functions from libraries like [Solady](https://github.com/Vectorized/solady/blob/main/src/utils/FixedPointMathLib.sol) can lead to more efficient smart contracts.
This is particularly beneficial in contracts where these operations are frequently used.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

128:         validationData = (sigFailed ? 1 : 0) | (uint256(withdrawRequest.expiry) << 160); 
156:         uint256 withdrawable = _withdrawableETH[account] + (maxGasCost - actualGasCost); 
```


*GitHub* : [128](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L128-L128), [156](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L156-L156)

### [G-14]<a name="g-14"></a> Constructors can be marked `payable`

Payable functions cost less gas to execute, since the compiler does not have to add extra checks to ensure that a payment wasn't provided. A constructor can safely be marked as payable, since only the deployer would be able to pass funds, and the project itself would not pass any funds.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

101:     constructor(address _owner) { 
```


*GitHub* : [101](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L101)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

102:     constructor() { 
```


*GitHub* : [102](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L102)

### [G-15]<a name="g-15"></a> Counting down in `for` statements is more gas efficient

Counting down is more gas efficient than counting up because neither we are making zero variable to non-zero variable and also we will get gas refund in the last transaction when making non-zero to zero variable. [More info](https://solodit.xyz/issues/g-02-counting-down-in-for-statements-is-more-gas-efficient-code4rena-pooltogether-pooltogether-git)

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit increments @ line 209
206:         for (uint256 i; i < calls.length;) { 
207:             _call(calls[i].target, calls[i].value, calls[i].data);
208:             unchecked {
209:                 ++i;
210:             }
211:         }
```


*GitHub* : [206](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L206-L211)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) { 
```


*GitHub* : [163](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L163-L163)

### [G-16]<a name="g-16"></a> Do not calculate constants

Due to how constant variables are implemented (replacements at compile-time), an expression assigned to a constant variable is recomputed each time that the variable is used, which wastes some gas.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

47:     uint256 private constant P256_N_DIV_2 = FCL.n / 2; 
```


*GitHub* : [47](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L47-L47)

### [G-17]<a name="g-17"></a> `do`-`while` is cheaper than `for`-loops when the initial check can be skipped

Using `do-while` loops instead of `for` loops can be more gas-efficient.
Even if you add an `if` condition to account for the case where the loop doesn't execute at all, a `do-while` loop can still be cheaper in terms of gas.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

206:         for (uint256 i; i < calls.length;) { 
```


*GitHub* : [206](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L206-L206)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) { 
```


*GitHub* : [163](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L163-L163)

### [G-18]<a name="g-18"></a> Don't transfer with zero amount to save gas

In Solidity, unnecessary operations can waste gas. For example, a transfer function without a zero amount check uses gas even if called with a zero amount, since the contract state remains unchanged. Implementing a zero amount check avoids these unnecessary function calls, saving gas and improving efficiency.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit check for zero amount on the 'amount' variable
338:             SafeTransferLib.safeTransfer(asset, to, amount); 
```


*GitHub* : [338](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L338-L338)

### [G-19]<a name="g-19"></a> Empty blocks should be removed or emit something

Some functions don't have a body: consider commenting why, or add some logic. Otherwise, refactor the code and remove these functions.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

106:     receive() external payable {} 
```


*GitHub* : [106](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L106-L106)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

330:     function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {} 
```


*GitHub* : [330](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L330-L330)

### [G-20]<a name="g-20"></a> Function names can be optimized

Function that are `public`/`external` and `public` state variable names can be optimized to save gas.

Method IDs that have two leading zero bytes can save **128 gas** each during deployment, and renaming functions to have lower method IDs will save **22 gas** per call, per sorted position shifted. [Reference](https://blog.emn178.cc/en/post/solidity-gas-optimization-function-name/)

*There are 5 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit optimized order: validatePaymasterUserOp(), entryPointWithdrawStake(), withdraw(), entryPointUnlockStake(), entryPoint(), postOp(), entryPointWithdraw(), entryPointDeposit(), entryPointAddStake(), getHash(), ownerWithdraw(), nonceUsed(), withdrawGasExcess(), isValidWithdrawSignature(), _validateRequest(), _withdraw()
18: contract MagicSpend is Ownable, IPaymaster { 
```


*GitHub* : [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L18)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit optimized order: executeWithoutChainIdValidation(), execute(), entryPoint(), canSkipChainIdValidation(), initialize(), implementation(), getUserOpHashWithoutChainId(), validateUserOp(), executeBatch(), _call(), _validateSignature(), _authorizeUpgrade(), _domainNameAndVersion()
20: contract CoinbaseSmartWallet is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 { 
```


*GitHub* : [20](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L20)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit optimized order: initCodeHash(), createAccount(), getAddress(), _getSalt()
13: contract CoinbaseSmartWalletFactory { 
```


*GitHub* : [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L13)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit optimized order: domainSeparator(), replaySafeHash(), eip712Domain(), isValidSignature(), _eip712Hash(), _hashStruct(), _domainNameAndVersion(), _validateSignature()
16: abstract contract ERC1271 { 
```


*GitHub* : [16](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L16)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit optimized order: nextOwnerIndex(), isOwnerAddress(), ownerAtIndex(), removeOwnerAtIndex(), addOwnerPublicKey(), isOwnerBytes(), addOwnerAddress(), isOwnerPublicKey(), _initializeOwners(), _addOwner(), _addOwnerAtIndex(), _checkOwner(), _getMultiOwnableStorage()
32: contract MultiOwnable { 
```


*GitHub* : [32](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L32)

### [G-21]<a name="g-21"></a> Functions guaranteed to revert when called by normal users can be marked `payable`

If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.

*There are 10 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost) 
110:         external
111:         onlyEntryPoint
112:         returns (bytes memory context, uint256 validationData)
113:     {
143:     function postOp(IPaymaster.PostOpMode mode, bytes calldata context, uint256 actualGasCost) 
144:         external
145:         onlyEntryPoint
146:     {
203:     function ownerWithdraw(address asset, address to, uint256 amount) external onlyOwner { 
222:     function entryPointWithdraw(address payable to, uint256 amount) external onlyOwner { 
239:     function entryPointUnlockStake() external onlyOwner { 
248:     function entryPointWithdrawStake(address payable to) external onlyOwner { 
```


*GitHub* : [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L109-L113), [143](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L143-L146), [203](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L203-L203), [222](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L222-L222), [239](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L239-L239), [248](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L248-L248)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

330:     function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {} 
```


*GitHub* : [330](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L330-L330)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

85:     function addOwnerAddress(address owner) public virtual onlyOwner { 
93:     function addOwnerPublicKey(bytes32 x, bytes32 y) public virtual onlyOwner { 
102:     function removeOwnerAtIndex(uint256 index) public virtual onlyOwner { 
```


*GitHub* : [85](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L85-L85), [93](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L93-L93), [102](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L102-L102)

### [G-22]<a name="g-22"></a> Integer increments by one can be unchecked

Using unchecked increments in Solidity can save on gas fees by bypassing built-in overflow checks, thus optimizing gas usage, but requires careful assessment of potential risks and edge cases to avoid unintended consequences.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) { 
172:             _addOwnerAtIndex(owners[i], _getMultiOwnableStorage().nextOwnerIndex++); 
180:         _addOwnerAtIndex(owner, _getMultiOwnableStorage().nextOwnerIndex++); 
```


*GitHub* : [163](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L163-L163), [172](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L172-L172), [180](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L180-L180)

### [G-23]<a name="g-23"></a> Low-level `call` can be optimized with assembly

`returnData` is copied to memory even if the variable is not utilized: the proper way to handle this is through a low level assembly call and save **159** [gas](https://gist.github.com/IllIllI000/0e18a40f3afb0b83f9a347b10ee89ad2).

```solidity
 // before (bool success,) = payable(receiver).call{gas: gas, value: value}("");
//after bool success; assembly { success := call(gas, receiver, value, 0, 0, 0, 0) }
```


*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

273:         (bool success, bytes memory result) = target.call{value: value}(data); 
```


*GitHub* : [273](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L273)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

151:         (bool success, bytes memory ret) = VERIFIER.staticcall(args); 
```


*GitHub* : [151](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L151)

### [G-24]<a name="g-24"></a> Multiple accesses of the same mapping/array key/index should be cached

The instances below point to the second+ access of a value inside a mapping/array key/index, within a function. Caching a mapping's value in a local storage or calldata variable when the value is accessed [multiple times](https://gist.github.com/IllIllI000/ec23a57daa30a8f8ca8b9681c8ccefb0), saves ~42 gas per access due to not having to recalculate the key's keccak256 hash (Gkeccak256 - 30 gas) and that calculation's associated stack operations. Caching an array's struct avoids recalculating the array offsets into memory/calldata

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit _nonceUsed[withdrawRequest.nonce][account] is also accessed on line 316
320:         _nonceUsed[withdrawRequest.nonce][account] = true; 
```


*GitHub* : [320](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L320-L320)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit webAuthnAuth.authenticatorData[32] is also accessed on line 133
138:         if (requireUV && (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV) { 
```


*GitHub* : [138](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L138-L138)

### [G-25]<a name="g-25"></a> Nesting `if`-statements is cheaper than using `&&`

Using a double if statement instead of logical AND (&&) can provide similar short-circuiting behavior whereas double if is slightly more efficient.

*There are 8 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

131:             if (scalar_u == 0 && scalar_v == 0) return 0; 
134:             if ( 
135:                 (H0 == 0) && (H1 == 0) //handling Q=-G
280:         if ((x0 == x1) && (y0 == y1)) { 
```


*GitHub* : [131](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L131-L131), [134](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L134-L135), [280](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L280-L280)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

148:         if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) { 
```


*GitHub* : [148](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L148-L148)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

164:             if (owners[i].length != 32 && owners[i].length != 64) { 
168:             if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) { 
```


*GitHub* : [164](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L164-L164), [168](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L168-L168)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

138:         if (requireUV && (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV) { 
158:         if (success && valid) return abi.decode(ret, (uint256)) == 1; 
```


*GitHub* : [138](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L138-L138), [158](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L158-L158)

### [G-26]<a name="g-26"></a> Newer versions of solidity are more gas efficient

The solidity language continues to pursue more efficient gas optimization schemes. Adopting a [newer version of solidity](https://github.com/ethereum/solc-js/tags) can be more gas efficient.

*There are 7 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

24: pragma solidity >=0.8.19 <0.9.0; 
```


*GitHub* : [24](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L24)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

2: pragma solidity 0.8.23; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L2)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

2: pragma solidity 0.8.23; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L2)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L2)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L2)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L2)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

2: pragma solidity ^0.8.0; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L2)

### [G-27]<a name="g-27"></a> Not using the named return variables when a function returns, wastes deployment gas

The solidity compiler outputs more efficient code when the variable is declared in the return statement. There seem to be very few exceptions to this in practice, so if you see an anonymous return, you should test it with a named return instead to determine which case is most efficient.

*There are 41 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit Parameter of type 'bool' at index '0'
50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) { 
/// @audit Parameter of type 'bool' at index '0'
78:     function ecAff_isOnCurve(uint256 x, uint256 y) internal pure returns (bool) { 
94:     function FCL_nModInv(uint256 u) internal view returns (uint256 result) { 
95:         assembly {
96:             let pointer := mload(0x40)
97:             // Define length of base, exponent and modulus. 0x20 == 32 bytes
98:             mstore(pointer, 0x20)
99:             mstore(add(pointer, 0x20), 0x20)
100:             mstore(add(pointer, 0x40), 0x20)
101:             // Define variables base, exponent and modulus
102:             mstore(add(pointer, 0x60), u)
103:             mstore(add(pointer, 0x80), minus_2modn)
104:             mstore(add(pointer, 0xa0), n)
105: 
106:             // Call the precompiled contract 0x05 = ModExp
107:             if iszero(staticcall(not(0), 0x05, pointer, 0xc0, pointer, 0x20)) { revert(0, 0) }
108:             result := mload(pointer)
109:         }
110:     }
117:     function ecZZ_mulmuladd_S_asm( 
118:         uint256 Q0,
119:         uint256 Q1, //affine rep for input point Q
120:         uint256 scalar_u,
121:         uint256 scalar_v
122:     ) internal view returns (uint256 X) {
123:         uint256 zz;
124:         uint256 zzz;
125:         uint256 Y;
126:         uint256 index = 255;
127:         uint256 H0;
128:         uint256 H1;
129: 
130:         unchecked {
131:             if (scalar_u == 0 && scalar_v == 0) return 0;
132: 
133:             (H0, H1) = ecAff_add(gx, gy, Q0, Q1);
134:             if (
135:                 (H0 == 0) && (H1 == 0) //handling Q=-G
136:             ) {
137:                 scalar_u = addmod(scalar_u, n - scalar_v, n);
138:                 scalar_v = 0;
139:             }
140:             assembly {
141:                 for { let T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1)) } eq(T4, 0) {
142:                     index := sub(index, 1)
143:                     T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
144:                 } {}
145:                 zz := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
146: 
147:                 if eq(zz, 1) {
148:                     X := gx
149:                     Y := gy
150:                 }
151:                 if eq(zz, 2) {
152:                     X := Q0
153:                     Y := Q1
154:                 }
155:                 if eq(zz, 3) {
156:                     X := H0
157:                     Y := H1
158:                 }
159: 
160:                 index := sub(index, 1)
161:                 zz := 1
162:                 zzz := 1
163: 
164:                 for {} gt(minus_1, index) { index := sub(index, 1) } {
165:                     // inlined EcZZ_Dbl
166:                     let T1 := mulmod(2, Y, p) //U = 2*Y1, y free
167:                     let T2 := mulmod(T1, T1, p) // V=U^2
168:                     let T3 := mulmod(X, T2, p) // S = X1*V
169:                     T1 := mulmod(T1, T2, p) // W=UV
170:                     let T4 := mulmod(3, mulmod(addmod(X, sub(p, zz), p), addmod(X, zz, p), p), p) //M=3*(X1-ZZ1)*(X1+ZZ1)
171:                     zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
172:                     zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
173: 
174:                     X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
175:                     T2 := mulmod(T4, addmod(X, sub(p, T3), p), p) //-M(S-X3)=M(X3-S)
176:                     Y := addmod(mulmod(T1, Y, p), T2, p) //-Y3= W*Y1-M(S-X3), we replace Y by -Y to avoid a sub in ecAdd
177: 
178:                     {
179:                         //value of dibit
180:                         T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
181: 
182:                         if iszero(T4) {
183:                             Y := sub(p, Y) //restore the -Y inversion
184:                             continue
185:                         } // if T4!=0
186: 
187:                         if eq(T4, 1) {
188:                             T1 := gx
189:                             T2 := gy
190:                         }
191:                         if eq(T4, 2) {
192:                             T1 := Q0
193:                             T2 := Q1
194:                         }
195:                         if eq(T4, 3) {
196:                             T1 := H0
197:                             T2 := H1
198:                         }
199:                         if iszero(zz) {
200:                             X := T1
201:                             Y := T2
202:                             zz := 1
203:                             zzz := 1
204:                             continue
205:                         }
206:                         // inlined EcZZ_AddN
207: 
208:                         //T3:=sub(p, Y)
209:                         //T3:=Y
210:                         let y2 := addmod(mulmod(T2, zzz, p), Y, p) //R
211:                         T2 := addmod(mulmod(T1, zz, p), sub(p, X), p) //P
212: 
213:                         //special extremely rare case accumulator where EcAdd is replaced by EcDbl, no need to optimize this
214:                         //todo : construct edge vector case
215:                         if iszero(y2) {
216:                             if iszero(T2) {
217:                                 T1 := mulmod(minus_2, Y, p) //U = 2*Y1, y free
218:                                 T2 := mulmod(T1, T1, p) // V=U^2
219:                                 T3 := mulmod(X, T2, p) // S = X1*V
220: 
221:                                 T1 := mulmod(T1, T2, p) // W=UV
222:                                 y2 := mulmod(addmod(X, zz, p), addmod(X, sub(p, zz), p), p) //(X-ZZ)(X+ZZ)
223:                                 T4 := mulmod(3, y2, p) //M=3*(X-ZZ)(X+ZZ)
224: 
225:                                 zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
226:                                 zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
227: 
228:                                 X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
229:                                 T2 := mulmod(T4, addmod(T3, sub(p, X), p), p) //M(S-X3)
230: 
231:                                 Y := addmod(T2, mulmod(T1, Y, p), p) //Y3= M(S-X3)-W*Y1
232: 
233:                                 continue
234:                             }
235:                         }
236: 
237:                         T4 := mulmod(T2, T2, p) //PP
238:                         let TT1 := mulmod(T4, T2, p) //PPP, this one could be spared, but adding this register spare gas
239:                         zz := mulmod(zz, T4, p)
240:                         zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1
241:                         let TT2 := mulmod(X, T4, p)
242:                         T4 := addmod(addmod(mulmod(y2, y2, p), sub(p, TT1), p), mulmod(minus_2, TT2, p), p)
243:                         Y := addmod(mulmod(addmod(TT2, sub(p, T4), p), y2, p), mulmod(Y, TT1, p), p)
244: 
245:                         X := T4
246:                     }
247:                 } //end loop
248:                 let T := mload(0x40)
249:                 mstore(add(T, 0x60), zz)
250:                 //(X,Y)=ecZZ_SetAff(X,Y,zz, zzz);
251:                 //T[0] = inverseModp_Hard(T[0], p); //1/zzz, inline modular inversion using precompile:
252:                 // Define length of base, exponent and modulus. 0x20 == 32 bytes
253:                 mstore(T, 0x20)
254:                 mstore(add(T, 0x20), 0x20)
255:                 mstore(add(T, 0x40), 0x20)
256:                 // Define variables base, exponent and modulus
257:                 //mstore(add(pointer, 0x60), u)
258:                 mstore(add(T, 0x80), minus_2)
259:                 mstore(add(T, 0xa0), p)
260: 
261:                 // Call the precompiled contract 0x05 = ModExp
262:                 if iszero(staticcall(not(0), 0x05, T, 0xc0, T, 0x20)) { revert(0, 0) }
263: 
264:                 //Y:=mulmod(Y,zzz,p)//Y/zzz
265:                 //zz :=mulmod(zz, mload(T),p) //1/z
266:                 //zz:= mulmod(zz,zz,p) //1/zz
267:                 X := mulmod(X, mload(T), p) //X/zz
268:             } //end assembly
269:         } //end unchecked
270: 
271:         return X;
272:     }
/// @audit Parameter of type 'uint256' at index '0'
/// @audit Parameter of type 'uint256' at index '1'
274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) { 
293:     function ecAff_IsZero(uint256, uint256 y) internal pure returns (bool flag) { 
294:         return (y == 0);
295:     }
301:     function ecZZ_SetAff(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
302:         internal
303:         view
304:         returns (uint256 x1, uint256 y1)
305:     {
306:         uint256 zzzInv = FCL_pModInv(zzz); //1/zzz
307:         y1 = mulmod(y, zzzInv, p); //Y/zzz
308:         uint256 _b = mulmod(zz, zzzInv, p); //1/z
309:         zzzInv = mulmod(_b, _b, p); //1/zz
310:         x1 = mulmod(x, zzzInv, p); //X/zz
311:     }
318:     function ecZZ_Dbl(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
319:         internal
320:         pure
321:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
322:     {
323:         unchecked {
324:             assembly {
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
335:             }
336:         }
337:         return (P0, P1, P2, P3);
338:     }
344:     function ecZZ_AddN(uint256 x1, uint256 y1, uint256 zz1, uint256 zzz1, uint256 x2, uint256 y2) 
345:         internal
346:         pure
347:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
348:     {
349:         unchecked {
350:             if (y1 == 0) {
351:                 return (x2, y2, 1, 1);
352:             }
353: 
354:             assembly {
355:                 y1 := sub(p, y1)
356:                 y2 := addmod(mulmod(y2, zzz1, p), y1, p)
357:                 x2 := addmod(mulmod(x2, zz1, p), sub(p, x1), p)
358:                 P0 := mulmod(x2, x2, p) //PP = P^2
359:                 P1 := mulmod(P0, x2, p) //PPP = P*PP
360:                 P2 := mulmod(zz1, P0, p) ////ZZ3 = ZZ1*PP
361:                 P3 := mulmod(zzz1, P1, p) ////ZZZ3 = ZZZ1*PPP
362:                 zz1 := mulmod(x1, P0, p) //Q = X1*PP
363:                 P0 := addmod(addmod(mulmod(y2, y2, p), sub(p, P1), p), mulmod(minus_2, zz1, p), p) //R^2-PPP-2*Q
364:                 P1 := addmod(mulmod(addmod(zz1, sub(p, P0), p), y2, p), mulmod(y1, P1, p), p) //R*(Q-X3)
365:             }
366:             //end assembly
367:         } //end unchecked
368:         return (P0, P1, P2, P3);
369:     }
374:     function FCL_pModInv(uint256 u) internal view returns (uint256 result) { 
375:         assembly {
376:             let pointer := mload(0x40)
377:             // Define length of base, exponent and modulus. 0x20 == 32 bytes
378:             mstore(pointer, 0x20)
379:             mstore(add(pointer, 0x20), 0x20)
380:             mstore(add(pointer, 0x40), 0x20)
381:             // Define variables base, exponent and modulus
382:             mstore(add(pointer, 0x60), u)
383:             mstore(add(pointer, 0x80), minus_2)
384:             mstore(add(pointer, 0xa0), p)
385: 
386:             // Call the precompiled contract 0x05 = ModExp
387:             if iszero(staticcall(not(0), 0x05, pointer, 0xc0, pointer, 0x20)) { revert(0, 0) }
388:             result := mload(pointer)
389:         }
390:     }
```


*GitHub* : [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L50-L50), [78](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L78-L78), [94](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L94-L110), [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L117-L272), [274](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L274-L274), [293](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L293-L295), [301](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L301-L311), [318](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L318-L338), [344](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L344-L369), [374](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L374-L390)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost) 
110:         external
111:         onlyEntryPoint
112:         returns (bytes memory context, uint256 validationData)
113:     {
114:         WithdrawRequest memory withdrawRequest = abi.decode(userOp.paymasterAndData[20:], (WithdrawRequest));
115:         uint256 withdrawAmount = withdrawRequest.amount;
116: 
117:         if (withdrawAmount < maxCost) {
118:             revert RequestLessThanGasMaxCost(withdrawAmount, maxCost);
119:         }
120: 
121:         if (withdrawRequest.asset != address(0)) {
122:             revert UnsupportedPaymasterAsset(withdrawRequest.asset);
123:         }
124: 
125:         _validateRequest(userOp.sender, withdrawRequest);
126: 
127:         bool sigFailed = !isValidWithdrawSignature(userOp.sender, withdrawRequest);
128:         validationData = (sigFailed ? 1 : 0) | (uint256(withdrawRequest.expiry) << 160);
129: 
130:         // Ensure at validation that the contract has enough balance to cover the requested funds.
131:         // NOTE: This check is necessary to enforce that the contract will be able to transfer the remaining funds
132:         //       when `postOp()` is called back after the `UserOperation` has been executed.
133:         if (address(this).balance < withdrawAmount) {
134:             revert InsufficientBalance(withdrawAmount, address(this).balance);
135:         }
136: 
137:         // NOTE: Do not include the gas part in withdrawable funds as it will be handled in `postOp()`.
138:         _withdrawableETH[userOp.sender] += withdrawAmount - maxCost;
139:         context = abi.encode(maxCost, userOp.sender);
140:     }
260:     function isValidWithdrawSignature(address account, WithdrawRequest memory withdrawRequest) 
/// @audit Parameter of type 'bytes32' at index '0'
279:     function getHash(address account, WithdrawRequest memory withdrawRequest) public view returns (bytes32) { 
/// @audit Parameter of type 'bool' at index '0'
299:     function nonceUsed(address account, uint256 nonce) external view returns (bool) { 
/// @audit Parameter of type 'address' at index '0'
304:     function entryPoint() public pure returns (address) { 
```


*GitHub* : [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L109-L140), [260](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L260-L260), [279](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L279-L279), [299](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L299-L299), [304](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L304-L304)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

137:     function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
138:         public
139:         payable
140:         virtual
141:         onlyEntryPoint
142:         payPrefund(missingAccountFunds)
143:         returns (uint256 validationData)
144:     {
145:         uint256 key = userOp.nonce >> 64;
146: 
147:         // 0xbf6ba1fc = bytes4(keccak256("executeWithoutChainIdValidation(bytes)"))
148:         if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) {
149:             userOpHash = getUserOpHashWithoutChainId(userOp);
150:             if (key != REPLAYABLE_NONCE_KEY) {
151:                 revert InvalidNonceKey(key);
152:             }
153:         } else {
154:             if (key == REPLAYABLE_NONCE_KEY) {
155:                 revert InvalidNonceKey(key);
156:             }
157:         }
158: 
159:         // Return 0 if the recovered address matches the owner.
160:         if (_validateSignature(userOpHash, userOp.signature)) {
161:             return 0;
162:         }
163: 
164:         // Else return 1, which is equivalent to:
165:         // `(uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)`
166:         // where `validUntil` is 0 (indefinite) and `validAfter` is 0.
167:         return 1;
168:     }
/// @audit Parameter of type 'address' at index '0'
217:     function entryPoint() public view virtual returns (address) { 
229:     function getUserOpHashWithoutChainId(UserOperation calldata userOp) 
230:         public
231:         view
232:         virtual
233:         returns (bytes32 userOpHash)
234:     {
235:         return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
236:     }
241:     function implementation() public view returns (address $) { 
242:         assembly {
243:             $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
244:         }
245:     }
/// @audit Parameter of type 'bool' at index '0'
252:     function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) { 
291:     function _validateSignature(bytes32 message, bytes calldata signature) 
/// @audit Parameter of type 'string' at index '0'
/// @audit Parameter of type 'string' at index '1'
333:     function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) { 
```


*GitHub* : [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L137-L168), [217](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L217-L217), [229](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L229-L236), [241](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L241-L245), [252](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L252-L252), [291](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L291-L291), [333](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L333-L333)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

38:     function createAccount(bytes[] calldata owners, uint256 nonce) 
39:         public
40:         payable
41:         virtual
42:         returns (CoinbaseSmartWallet account)
43:     {
44:         if (owners.length == 0) {
45:             revert OwnerRequired();
46:         }
47: 
48:         (bool alreadyDeployed, address accountAddress) =
49:             LibClone.createDeterministicERC1967(msg.value, implementation, _getSalt(owners, nonce));
50: 
51:         account = CoinbaseSmartWallet(payable(accountAddress));
52: 
53:         if (alreadyDeployed == false) {
54:             account.initialize(owners);
55:         }
56:     }
64:     function getAddress(bytes[] calldata owners, uint256 nonce) external view returns (address predicted) { 
65:         predicted = LibClone.predictDeterministicAddress(initCodeHash(), _getSalt(owners, nonce), address(this));
66:     }
71:     function initCodeHash() public view virtual returns (bytes32 result) { 
72:         result = LibClone.initCodeHashERC1967(implementation);
73:     }
81:     function _getSalt(bytes[] calldata owners, uint256 nonce) internal pure returns (bytes32 salt) { 
82:         salt = keccak256(abi.encode(owners, nonce));
83:     }
```


*GitHub* : [38](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L38-L56), [64](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L64-L66), [71](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L71-L73), [81](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L81-L83)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

36:     function eip712Domain() 
37:         external
38:         view
39:         virtual
40:         returns (
41:             bytes1 fields,
42:             string memory name,
43:             string memory version,
44:             uint256 chainId,
45:             address verifyingContract,
46:             bytes32 salt,
47:             uint256[] memory extensions
48:         )
49:     {
50:         fields = hex"0f"; // `0b1111`.
51:         (name, version) = _domainNameAndVersion();
52:         chainId = block.chainid;
53:         verifyingContract = address(this);
54:         salt = salt; // `bytes32(0)`.
55:         extensions = extensions; // `new uint256[](0)`.
56:     }
69:     function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4 result) { 
70:         if (_validateSignature({message: replaySafeHash(hash), signature: signature})) {
71:             // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
72:             return 0x1626ba7e;
73:         }
74: 
75:         return 0xffffffff;
76:     }
/// @audit Parameter of type 'bytes32' at index '0'
90:     function replaySafeHash(bytes32 hash) public view virtual returns (bytes32) { 
/// @audit Parameter of type 'bytes32' at index '0'
100:     function domainSeparator() public view returns (bytes32) { 
/// @audit Parameter of type 'bytes32' at index '0'
121:     function _eip712Hash(bytes32 hash) internal view virtual returns (bytes32) { 
/// @audit Parameter of type 'bytes32' at index '0'
133:     function _hashStruct(bytes32 hash) internal view virtual returns (bytes32) { 
143:     function _domainNameAndVersion() internal view virtual returns (string memory name, string memory version); 
/// @audit Parameter of type 'bool' at index '0'
155:     function _validateSignature(bytes32 message, bytes calldata signature) internal view virtual returns (bool); 
```


*GitHub* : [36](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L36-L56), [69](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L69-L76), [90](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L90-L90), [100](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L100-L100), [121](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L121-L121), [133](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L133-L133), [143](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L143-L143), [155](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L155-L155)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit Parameter of type 'bool' at index '0'
117:     function isOwnerAddress(address account) public view virtual returns (bool) { 
/// @audit Parameter of type 'bool' at index '0'
127:     function isOwnerPublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) { 
/// @audit Parameter of type 'bool' at index '0'
136:     function isOwnerBytes(bytes memory account) public view virtual returns (bool) { 
/// @audit Parameter of type 'bytes' at index '0'
145:     function ownerAtIndex(uint256 index) public view virtual returns (bytes memory) { 
/// @audit Parameter of type 'uint256' at index '0'
152:     function nextOwnerIndex() public view virtual returns (uint256) { 
212:     function _getMultiOwnableStorage() internal pure returns (MultiOwnableStorage storage $) { 
213:         assembly ("memory-safe") {
214:             $.slot := MUTLI_OWNABLE_STORAGE_LOCATION
215:         }
216:     }
```


*GitHub* : [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L117-L117), [127](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L127-L127), [136](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L136-L136), [145](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L145-L145), [152](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L152-L152), [212](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L212-L216)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

104:     function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory webAuthnAuth, uint256 x, uint256 y) 
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L104-L104)

### [G-28]<a name="g-28"></a> Optimize Deployment Size by Fine-tuning IPFS Hash

The Solidity compiler appends 53 bytes of metadata to the smart contract code, incurring an extra cost of 10,600 gas. This additional expense arises from 200 gas per bytecode, plus calldata cost, which amounts to 16 gas for non-zero bytes and 4 gas for zero bytes. This results in a maximum of 848 extra gas in calldata cost.

Reducing this cost is crucial for the following reasons:

The metadata's 53-byte addition leads to a deployment cost increase of 10,600 gas.
It can also result in an additional calldata cost of up to 848 gas.
Ways to Minimize Gas Consumption:

Employ the `--no-cbor-metadata` compiler option to exclude metadata. Be cautious as this might impact contract verification.
Search for code comments that yield an IPFS hash with more zeros, thereby reducing calldata costs.

*There are 7 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit Consider optimizing the IPFS hash during deployment.
1: //curve order (number of points) 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L1-L1)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit Consider optimizing the IPFS hash during deployment.
1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L1-L1)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit Consider optimizing the IPFS hash during deployment.
1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L1-L1)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit Consider optimizing the IPFS hash during deployment.
1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L1-L1)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit Consider optimizing the IPFS hash during deployment.
1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L1-L1)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit Consider optimizing the IPFS hash during deployment.
1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L1-L1)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit Consider optimizing the IPFS hash during deployment.
1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L1-L1)

### [G-29]<a name="g-29"></a> Simple checks for zero can be done using assembly to save gas

_

*There are 11 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

51:         if (r == 0 || r >= n || s == 0 || s >= n) { 
79:         if (((0 == x) && (0 == y)) || x == p || y == p) { 
131:             if (scalar_u == 0 && scalar_v == 0) return 0; 
134:             if ( 
135:                 (H0 == 0) && (H1 == 0) //handling Q=-G
350:             if (y1 == 0) { 
```


*GitHub* : [51](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L51-L51), [79](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L79-L79), [131](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L131-L131), [134](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L134-L135), [350](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L350-L350)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

121:         if (withdrawRequest.asset != address(0)) { 
172:         if (amount == 0) revert NoExcess(); 
335:         if (asset == address(0)) { 
```


*GitHub* : [121](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L121-L121), [172](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L172-L172), [335](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L335-L335)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

115:         if (nextOwnerIndex() != 0) { 
```


*GitHub* : [115](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L115-L115)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

44:         if (owners.length == 0) { 
```


*GitHub* : [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L44-L44)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

104:         if (owner.length == 0) revert NoOwnerAtIndex(index); 
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L104-L104)

### [G-30]<a name="g-30"></a> Sort Solidity operations using short-circuit mode

In Solidity, boolean expressions utilize short-circuiting. For || (logical OR) operations, the second expression is evaluated only if the first one is false. Similarly, for && (logical AND) operations, the second expression is evaluated only if the first one is true. This optimization saves gas by avoiding unnecessary evaluations. For instance, in require(msg.sender == owner || msg.sender == manager), if msg.sender == owner evaluates to true, msg.sender == manager isn't checked. It's recommended to place the less expensive expression first to optimize gas usage.

*There are 9 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit Lines: 51 
/// @audit Lines: 51 
/// @audit Lines: 51 
50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) { 
51:         if (r == 0 || r >= n || s == 0 || s >= n) {
52:             return false;
53:         }
54: 
55:         if (!ecAff_isOnCurve(Qx, Qy)) {
56:             return false;
57:         }
58: 
59:         uint256 sInv = FCL_nModInv(s);
60: 
61:         uint256 scalar_u = mulmod(uint256(message), sInv, n);
62:         uint256 scalar_v = mulmod(r, sInv, n);
63:         uint256 x1;
64: 
65:         x1 = ecZZ_mulmuladd_S_asm(Qx, Qy, scalar_u, scalar_v);
66: 
67:         x1 = addmod(x1, n - r, n);
68: 
69:         return x1 == 0;
70:     }
/// @audit Lines: 79 
/// @audit Lines: 79 
/// @audit Lines: 79 
78:     function ecAff_isOnCurve(uint256 x, uint256 y) internal pure returns (bool) { 
79:         if (((0 == x) && (0 == y)) || x == p || y == p) {
80:             return false;
81:         }
82:         unchecked {
83:             uint256 LHS = mulmod(y, y, p); // y^2
84:             uint256 RHS = addmod(mulmod(mulmod(x, x, p), x, p), mulmod(x, a, p), p); // x^3+ax
85:             RHS = addmod(RHS, b, p); // x^3 + a*x + b
86: 
87:             return LHS == RHS;
88:         }
89:     }
/// @audit Lines: 131 
/// @audit Lines: 134 to 135
117:     function ecZZ_mulmuladd_S_asm( 
118:         uint256 Q0,
119:         uint256 Q1, //affine rep for input point Q
120:         uint256 scalar_u,
121:         uint256 scalar_v
122:     ) internal view returns (uint256 X) {
123:         uint256 zz;
124:         uint256 zzz;
125:         uint256 Y;
126:         uint256 index = 255;
127:         uint256 H0;
128:         uint256 H1;
129: 
130:         unchecked {
131:             if (scalar_u == 0 && scalar_v == 0) return 0;
132: 
133:             (H0, H1) = ecAff_add(gx, gy, Q0, Q1);
134:             if (
135:                 (H0 == 0) && (H1 == 0) //handling Q=-G
136:             ) {
137:                 scalar_u = addmod(scalar_u, n - scalar_v, n);
138:                 scalar_v = 0;
139:             }
140:             assembly {
141:                 for { let T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1)) } eq(T4, 0) {
142:                     index := sub(index, 1)
143:                     T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
144:                 } {}
145:                 zz := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
146: 
147:                 if eq(zz, 1) {
148:                     X := gx
149:                     Y := gy
150:                 }
151:                 if eq(zz, 2) {
152:                     X := Q0
153:                     Y := Q1
154:                 }
155:                 if eq(zz, 3) {
156:                     X := H0
157:                     Y := H1
158:                 }
159: 
160:                 index := sub(index, 1)
161:                 zz := 1
162:                 zzz := 1
163: 
164:                 for {} gt(minus_1, index) { index := sub(index, 1) } {
165:                     // inlined EcZZ_Dbl
166:                     let T1 := mulmod(2, Y, p) //U = 2*Y1, y free
167:                     let T2 := mulmod(T1, T1, p) // V=U^2
168:                     let T3 := mulmod(X, T2, p) // S = X1*V
169:                     T1 := mulmod(T1, T2, p) // W=UV
170:                     let T4 := mulmod(3, mulmod(addmod(X, sub(p, zz), p), addmod(X, zz, p), p), p) //M=3*(X1-ZZ1)*(X1+ZZ1)
171:                     zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
172:                     zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
173: 
174:                     X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
175:                     T2 := mulmod(T4, addmod(X, sub(p, T3), p), p) //-M(S-X3)=M(X3-S)
176:                     Y := addmod(mulmod(T1, Y, p), T2, p) //-Y3= W*Y1-M(S-X3), we replace Y by -Y to avoid a sub in ecAdd
177: 
178:                     {
179:                         //value of dibit
180:                         T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
181: 
182:                         if iszero(T4) {
183:                             Y := sub(p, Y) //restore the -Y inversion
184:                             continue
185:                         } // if T4!=0
186: 
187:                         if eq(T4, 1) {
188:                             T1 := gx
189:                             T2 := gy
190:                         }
191:                         if eq(T4, 2) {
192:                             T1 := Q0
193:                             T2 := Q1
194:                         }
195:                         if eq(T4, 3) {
196:                             T1 := H0
197:                             T2 := H1
198:                         }
199:                         if iszero(zz) {
200:                             X := T1
201:                             Y := T2
202:                             zz := 1
203:                             zzz := 1
204:                             continue
205:                         }
206:                         // inlined EcZZ_AddN
207: 
208:                         //T3:=sub(p, Y)
209:                         //T3:=Y
210:                         let y2 := addmod(mulmod(T2, zzz, p), Y, p) //R
211:                         T2 := addmod(mulmod(T1, zz, p), sub(p, X), p) //P
212: 
213:                         //special extremely rare case accumulator where EcAdd is replaced by EcDbl, no need to optimize this
214:                         //todo : construct edge vector case
215:                         if iszero(y2) {
216:                             if iszero(T2) {
217:                                 T1 := mulmod(minus_2, Y, p) //U = 2*Y1, y free
218:                                 T2 := mulmod(T1, T1, p) // V=U^2
219:                                 T3 := mulmod(X, T2, p) // S = X1*V
220: 
221:                                 T1 := mulmod(T1, T2, p) // W=UV
222:                                 y2 := mulmod(addmod(X, zz, p), addmod(X, sub(p, zz), p), p) //(X-ZZ)(X+ZZ)
223:                                 T4 := mulmod(3, y2, p) //M=3*(X-ZZ)(X+ZZ)
224: 
225:                                 zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
226:                                 zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
227: 
228:                                 X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
229:                                 T2 := mulmod(T4, addmod(T3, sub(p, X), p), p) //M(S-X3)
230: 
231:                                 Y := addmod(T2, mulmod(T1, Y, p), p) //Y3= M(S-X3)-W*Y1
232: 
233:                                 continue
234:                             }
235:                         }
236: 
237:                         T4 := mulmod(T2, T2, p) //PP
238:                         let TT1 := mulmod(T4, T2, p) //PPP, this one could be spared, but adding this register spare gas
239:                         zz := mulmod(zz, T4, p)
240:                         zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1
241:                         let TT2 := mulmod(X, T4, p)
242:                         T4 := addmod(addmod(mulmod(y2, y2, p), sub(p, TT1), p), mulmod(minus_2, TT2, p), p)
243:                         Y := addmod(mulmod(addmod(TT2, sub(p, T4), p), y2, p), mulmod(Y, TT1, p), p)
244: 
245:                         X := T4
246:                     }
247:                 } //end loop
248:                 let T := mload(0x40)
249:                 mstore(add(T, 0x60), zz)
250:                 //(X,Y)=ecZZ_SetAff(X,Y,zz, zzz);
251:                 //T[0] = inverseModp_Hard(T[0], p); //1/zzz, inline modular inversion using precompile:
252:                 // Define length of base, exponent and modulus. 0x20 == 32 bytes
253:                 mstore(T, 0x20)
254:                 mstore(add(T, 0x20), 0x20)
255:                 mstore(add(T, 0x40), 0x20)
256:                 // Define variables base, exponent and modulus
257:                 //mstore(add(pointer, 0x60), u)
258:                 mstore(add(T, 0x80), minus_2)
259:                 mstore(add(T, 0xa0), p)
260: 
261:                 // Call the precompiled contract 0x05 = ModExp
262:                 if iszero(staticcall(not(0), 0x05, T, 0xc0, T, 0x20)) { revert(0, 0) }
263: 
264:                 //Y:=mulmod(Y,zzz,p)//Y/zzz
265:                 //zz :=mulmod(zz, mload(T),p) //1/z
266:                 //zz:= mulmod(zz,zz,p) //1/zz
267:                 X := mulmod(X, mload(T), p) //X/zz
268:             } //end assembly
269:         } //end unchecked
270: 
271:         return X;
272:     }
/// @audit Lines: 280 to 281
274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) { 
275:         uint256 zz0;
276:         uint256 zzz0;
277: 
278:         if (ecAff_IsZero(x0, y0)) return (x1, y1);
279:         if (ecAff_IsZero(x1, y1)) return (x0, y0);
280:         if ((x0 == x1) && (y0 == y1)) {
281:             (x0, y0, zz0, zzz0) = ecZZ_Dbl(x0, y0, 1, 1);
282:         } else {
283:             (x0, y0, zz0, zzz0) = ecZZ_AddN(x0, y0, 1, 1, x1, y1);
284:         }
285: 
286:         return ecZZ_SetAff(x0, y0, zz0, zzz0);
287:     }
```


*GitHub* : [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L50-L70), [78](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L78-L89), [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L117-L272), [274](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L274-L287)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit Lines: 148 to 154
137:     function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
138:         public
139:         payable
140:         virtual
141:         onlyEntryPoint
142:         payPrefund(missingAccountFunds)
143:         returns (uint256 validationData)
144:     {
145:         uint256 key = userOp.nonce >> 64;
146: 
147:         // 0xbf6ba1fc = bytes4(keccak256("executeWithoutChainIdValidation(bytes)"))
148:         if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) {
149:             userOpHash = getUserOpHashWithoutChainId(userOp);
150:             if (key != REPLAYABLE_NONCE_KEY) {
151:                 revert InvalidNonceKey(key);
152:             }
153:         } else {
154:             if (key == REPLAYABLE_NONCE_KEY) {
155:                 revert InvalidNonceKey(key);
156:             }
157:         }
158: 
159:         // Return 0 if the recovered address matches the owner.
160:         if (_validateSignature(userOpHash, userOp.signature)) {
161:             return 0;
162:         }
163: 
164:         // Else return 1, which is equivalent to:
165:         // `(uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)`
166:         // where `validUntil` is 0 (indefinite) and `validAfter` is 0.
167:         return 1;
168:     }
/// @audit Lines: 253 to 259
/// @audit Lines: 253 to 259
/// @audit Lines: 253 to 259
252:     function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) { 
253:         if (
254:             functionSelector == MultiOwnable.addOwnerPublicKey.selector
255:                 || functionSelector == MultiOwnable.addOwnerAddress.selector
256:                 || functionSelector == MultiOwnable.removeOwnerAtIndex.selector
257:                 || functionSelector == UUPSUpgradeable.upgradeToAndCall.selector
258:         ) {
259:             return true;
260:         }
261:         return false;
262:     }
```


*GitHub* : [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L137-L168), [252](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L252-L262)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit Lines: 164 to 168
/// @audit Lines: 168 to 172
162:     function _initializeOwners(bytes[] memory owners) internal virtual { 
163:         for (uint256 i; i < owners.length; i++) {
164:             if (owners[i].length != 32 && owners[i].length != 64) {
165:                 revert InvalidOwnerBytesLength(owners[i]);
166:             }
167: 
168:             if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) {
169:                 revert InvalidEthereumAddressOwner(owners[i]);
170:             }
171: 
172:             _addOwnerAtIndex(owners[i], _getMultiOwnableStorage().nextOwnerIndex++);
173:         }
174:     }
/// @audit Lines: 202 to 204
201:     function _checkOwner() internal view virtual { 
202:         if (isOwnerAddress(msg.sender) || (msg.sender == address(this))) {
203:             return;
204:         }
205: 
206:         revert Unauthorized();
207:     }
```


*GitHub* : [162](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L162-L174), [201](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L201-L207)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit Lines: 138 to 141
104:     function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory webAuthnAuth, uint256 x, uint256 y) 
105:         internal
106:         view
107:         returns (bool)
108:     {
109:         if (webAuthnAuth.s > P256_N_DIV_2) {
110:             // guard against signature malleability
111:             return false;
112:         }
113: 
114:         // 11. Verify that the value of C.type is the string webauthn.get.
115:         // bytes("type":"webauthn.get").length = 21
116:         string memory _type = webAuthnAuth.clientDataJSON.slice(webAuthnAuth.typeIndex, webAuthnAuth.typeIndex + 21);
117:         if (keccak256(bytes(_type)) != EXPECTED_TYPE_HASH) {
118:             return false;
119:         }
120: 
121:         // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
122:         bytes memory expectedChallenge = bytes(string.concat('"challenge":"', Base64.encodeURL(challenge), '"'));
123:         string memory actualChallenge = webAuthnAuth.clientDataJSON.slice(
124:             webAuthnAuth.challengeIndex, webAuthnAuth.challengeIndex + expectedChallenge.length
125:         );
126:         if (keccak256(bytes(actualChallenge)) != keccak256(expectedChallenge)) {
127:             return false;
128:         }
129: 
130:         // Skip 13., 14., 15.
131: 
132:         // 16. Verify that the UP bit of the flags in authData is set.
133:         if (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UP != AUTH_DATA_FLAGS_UP) {
134:             return false;
135:         }
136: 
137:         // 17. If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set.
138:         if (requireUV && (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV) {
139:             return false;
140:         }
141: 
142:         // skip 18.
143: 
144:         // 19. Let hash be the result of computing a hash over the cData using SHA-256.
145:         bytes32 clientDataJSONHash = sha256(bytes(webAuthnAuth.clientDataJSON));
146: 
147:         // 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
148:         bytes32 messageHash = sha256(abi.encodePacked(webAuthnAuth.authenticatorData, clientDataJSONHash));
149:         bytes memory args = abi.encode(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);
150:         // try the RIP-7212 precompile address
151:         (bool success, bytes memory ret) = VERIFIER.staticcall(args);
152:         // staticcall will not revert if address has no code
153:         // check return length
154:         // note that even if precompile exists, ret.length is 0 when verification returns false
155:         // so an invalid signature will be checked twice: once by the precompile and once by FCL.
156:         // Ideally this signature failure is simulated offchain and no one actually pay this gas.
157:         bool valid = ret.length > 0;
158:         if (success && valid) return abi.decode(ret, (uint256)) == 1;
159: 
160:         return FCL.ecdsa_verify(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);
161:     }
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L104-L161)

### [G-31]<a name="g-31"></a> Stack variable is only used once

If the variable is only accessed once, it's cheaper to use the assigned value directly that one time, and save the 3 gas the extra stack assignment would spend.

*There are 10 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

61:         uint256 scalar_u = mulmod(uint256(message), sInv, n); 
62:         uint256 scalar_v = mulmod(r, sInv, n);
83:             uint256 LHS = mulmod(y, y, p); // y^2 
```


*GitHub* : [61](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L61-L62), [83](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L83-L83)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

127:         bool sigFailed = !isValidWithdrawSignature(userOp.sender, withdrawRequest); 
```


*GitHub* : [127](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L127-L127)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

308:             address owner; 
319:             WebAuthn.WebAuthnAuth memory auth = abi.decode(sigWrapper.signatureData, (WebAuthn.WebAuthnAuth)); 
```


*GitHub* : [308](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L308-L308), [319](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L319-L319)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

116:         string memory _type = webAuthnAuth.clientDataJSON.slice(webAuthnAuth.typeIndex, webAuthnAuth.typeIndex + 21); 
123:         string memory actualChallenge = webAuthnAuth.clientDataJSON.slice( 
145:         bytes32 clientDataJSONHash = sha256(bytes(webAuthnAuth.clientDataJSON)); 
149:         bytes memory args = abi.encode(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y); 
157:         bool valid = ret.length > 0; 
```


*GitHub* : [116](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L116-L116), [123](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L123-L123), [145](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L145-L145), [149](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L149-L149), [157](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L157-L157)

### [G-32]<a name="g-32"></a> State variables should be cached in stack variables rather than re-reading them from storage

When performing multiple operations on a state variable in a function, it is recommended to cache it first. Either multiple reads or multiple writes to a state variable can save gas by caching it on the stack. Caching of a state variable replaces each Gwarmaccess (100 gas) with a much cheaper stack read. Other less obvious fixes/optimizations include having local memory caches of state variable structs, or having local caches of state variable contracts/addresses. *Saves 100 gas per instance*.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit _withdrawableETH: 2 reads 
143:     function postOp(IPaymaster.PostOpMode mode, bytes calldata context, uint256 actualGasCost) 
144:         external
145:         onlyEntryPoint
146:     {
/// @audit _withdrawableETH: 2 reads 
169:     function withdrawGasExcess() external { 
```


*GitHub* : [143](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L143-L146), [169](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L169-L169)

### [G-33]<a name="g-33"></a> Struct can be reordered to fit into fewer storage slots

In Solidity, data type packing within struct variables is a recommended practice to optimize gas usage and efficiency in smart contracts.

This technique leverages the fact that Ethereum’s storage model stores variables in slots, with each slot offering a capacity of 32 bytes. When data types that consume less than 32 bytes, such as **uint8**, **bool**, or **address**, are declared individually, each occupies a whole storage slot. However, when these smaller variables are grouped into a struct, they can share a storage slot, resulting in a significant reduction in storage requirements and, by extension, gas costs.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit use this order:  signature, amount, nonce, asset, expiry
/// @audit 1 storage slot(s) saved, (before 5, after 4)
20:     struct WithdrawRequest { 
```


*GitHub* : [20](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L20-L20)

### [G-34]<a name="g-34"></a> The result of a function call should be cached rather than re-calling the function

External calls are expensive. Results of external function calls should be cached rather than call them multiple times. Consider caching the following:

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit _getMultiOwnableStorage called on lines 192, 193
189:     function _addOwnerAtIndex(bytes memory owner, uint256 index) internal virtual { 
190:         if (isOwnerBytes(owner)) revert AlreadyOwner(owner);
191: 
192:         _getMultiOwnableStorage().isOwner[owner] = true;
193:         _getMultiOwnableStorage().ownerAtIndex[index] = owner;
194: 
195:         emit AddOwner(index, owner);
196:     }
```


*GitHub* : [189](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L189-L196)

### [G-35]<a name="g-35"></a> Usage of `uints`/`ints` smaller than 32 bytes (256 bits) incurs overhead

Citing the [documentation](https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html):

> When using elements that are smaller than 32 bytes, your contract’s gas usage may be higher.This is because the EVM operates on 32 bytes at a time.Therefore, if the element is smaller than that, the EVM must use more operations in order to reduce the size of the element from 32 bytes to the desired size.

For example, each operation involving a `uint8` costs an extra ** 22 - 28 gas ** (depending on whether the other operand is also a variable of type `uint8`) as compared to ones involving`uint256`, due to the compiler having to clear the higher bits of the memory word before operating on the`uint8`, as well as the associated stack operations of doing so.

Consider using a larger size, then downcast where needed.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

30:         uint48 expiry; 
232:     function entryPointAddStake(uint256 amount, uint32 unstakeDelaySeconds) external payable onlyOwner { 
```


*GitHub* : [30](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L30), [232](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L232)

### [G-36]<a name="g-36"></a> Use `Array.unsafeAccess()` to avoid repeated array length checks

When using storage arrays, solidity adds an internal lookup of the array's length (a Gcoldsload **2100 gas**) to ensure you don't read past the array's end. You can avoid this lookup by using [`Array.unsafeAccess()`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/94697be8a3f0dfcd95dfb13ffbd39b5973f5c65d/contracts/utils/Arrays.sol#L57) in cases where the length has already been checked, as is the case with the instances below

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

207:             _call(calls[i].target, calls[i].value, calls[i].data); 
```


*GitHub* : [207](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L207-L207)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

164:             if (owners[i].length != 32 && owners[i].length != 64) { 
165:                 revert InvalidOwnerBytesLength(owners[i]);
168:             if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) { 
169:                 revert InvalidEthereumAddressOwner(owners[i]);
172:             _addOwnerAtIndex(owners[i], _getMultiOwnableStorage().nextOwnerIndex++); 
```


*GitHub* : [164](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L164-L165), [168](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L168-L169), [172](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L172-L172)

### [G-37]<a name="g-37"></a> Use assembly for small `keccak256` hashes, in order to save gas

The assembly version of the keccak256 hashing function can be more gas efficient than the high-level Solidity version.

*There are 6 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

235:         return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint())); 
```


*GitHub* : [235](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L235-L235)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

102:         return keccak256( 
103:             abi.encode(
104:                 keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
105:                 keccak256(bytes(name)),
106:                 keccak256(bytes(version)),
107:                 block.chainid,
108:                 address(this)
109:             )
110:         );
122:         return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), _hashStruct(hash))); 
134:         return keccak256(abi.encode(_MESSAGE_TYPEHASH, hash)); 
```


*GitHub* : [102](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L102-L110), [122](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L122-L122), [134](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L134-L134)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

117:         if (keccak256(bytes(_type)) != EXPECTED_TYPE_HASH) { 
126:         if (keccak256(bytes(actualChallenge)) != keccak256(expectedChallenge)) { 
```


*GitHub* : [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L117-L117), [126](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L126-L126)

### [G-38]<a name="g-38"></a> Use assembly in place of `abi.decode` to save gas

Instead of using abi.decode, we can use assembly to decode our desired calldata values directly. This will allow us to avoid decoding calldata values that we will not use.

*There are 6 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

114:         WithdrawRequest memory withdrawRequest = abi.decode(userOp.paymasterAndData[20:], (WithdrawRequest)); 
152:         (uint256 maxGasCost, address account) = abi.decode(context, (uint256, address)); 
```


*GitHub* : [114](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L114-L114), [152](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L152-L152)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

298:         SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper)); 
317:             (uint256 x, uint256 y) = abi.decode(ownerBytes, (uint256, uint256)); 
319:             WebAuthn.WebAuthnAuth memory auth = abi.decode(sigWrapper.signatureData, (WebAuthn.WebAuthnAuth)); 
```


*GitHub* : [298](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L298-L298), [317](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L317-L317), [319](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L319-L319)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

158:         if (success && valid) return abi.decode(ret, (uint256)) == 1; 
```


*GitHub* : [158](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L158-L158)

### [G-39]<a name="g-39"></a> Use assembly scratch space to build calldata for external calls

Using Solidity's assembly scratch space for constructing calldata in external calls with one or two arguments can be a gas-efficient approach. This method leverages the designated memory area (the first 64 bytes of memory) for temporary data storage during assembly operations. By directly writing arguments into this scratch space, it eliminates the need for additional memory allocation typically required for calldata preparation. This technique can lead to notable gas savings, especially in high-frequency or gas-sensitive operations. However, it requires careful implementation to avoid data corruption and should be used with a thorough understanding of low-level EVM operations and memory handling. Proper testing and validation are crucial when employing such optimizations.

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

223:         IEntryPoint(entryPoint()).withdrawTo(to, amount); 
233:         IEntryPoint(entryPoint()).addStake{value: amount}(unstakeDelaySeconds); 
249:         IEntryPoint(entryPoint()).withdrawStake(to); 
```


*GitHub* : [223](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L223-L223), [233](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L233-L233), [249](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L249-L249)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

54:             account.initialize(owners); 
```


*GitHub* : [54](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L54-L54)

### [G-40]<a name="g-40"></a> Use assembly to validate `msg.sender`

We can use assembly to efficiently validate msg.sender with the least amount of opcodes necessary. For more details check the following report [Here](https://code4rena.com/reports/2023-05-juicebox#g-06-use-assembly-to-validate-msgsender)

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

184:         if (!isValidWithdrawSignature(msg.sender, withdrawRequest)) { 
```


*GitHub* : [184](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L184-L184)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

202:         if (isOwnerAddress(msg.sender) || (msg.sender == address(this))) { 
```


*GitHub* : [202](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L202-L202)

### [G-41]<a name="g-41"></a> Use `assembly` to write address/contract storage values

Using `assembly { sstore(state.slot, addr) }` instead of `state = addr` can save gas.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

25:         implementation = erc4337; 
65:         predicted = LibClone.predictDeterministicAddress(initCodeHash(), _getSalt(owners, nonce), address(this)); 
```


*GitHub* : [25](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L25-L25), [65](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L65-L65)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

53:         verifyingContract = address(this); 
```


*GitHub* : [53](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L53-L53)

### [G-42]<a name="g-42"></a> Use `calldata` instead of `memory` for function arguments that do not get mutated

Mark data types as `calldata` instead of `memory` where possible. This makes it so that the data is not automatically loaded into memory. If the data passed into the function does not need to be changed (like updating values in an array), it can be passed in as `calldata`. The one exception to this is if the argument must later be passed into another function that takes an argument that specifies `memory` storage.

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit withdrawRequest
181:     function withdraw(WithdrawRequest memory withdrawRequest) external { 
/// @audit withdrawRequest
260:     function isValidWithdrawSignature(address account, WithdrawRequest memory withdrawRequest) 
261:         public
262:         view
263:         returns (bool)
264:     {
/// @audit withdrawRequest
279:     function getHash(address account, WithdrawRequest memory withdrawRequest) public view returns (bytes32) { 
```


*GitHub* : [181](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L181-L181), [260](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L260-L264), [279](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L279-L279)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit account
136:     function isOwnerBytes(bytes memory account) public view virtual returns (bool) { 
```


*GitHub* : [136](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L136-L136)

### [G-43]<a name="g-43"></a> Use constants instead of `type(uint<n>).max` / `.min`

_

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
302:             if (uint256(bytes32(ownerBytes)) > type(uint160).max) { 
```


*GitHub* : [302](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L302-L302)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
168:             if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) { 
```


*GitHub* : [168](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L168-L168)

### [G-44]<a name="g-44"></a> Use scratch space when building emitted events with two data arguments

We can use assembly to emit events efficiently by utilizing `scratch space` and the `free memory pointer`. This will allow us to potentially avoid memory expansion costs.
Note: In order to do this optimization safely, we will need to cache and restore the free memory pointer.

For example, for a generic `emit` event for `eventSentAmountExample`: 
```solidity
// uint256 id, uint256 value, uint256 amount
emit eventSentAmountExample(id, value, amount);
```


*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

109:         emit RemoveOwner(index, owner); 
195:         emit AddOwner(index, owner); 
```


*GitHub* : [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L109), [195](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L195)

### [G-45]<a name="g-45"></a> Use `selfbalance()` instead of `address(this).balance`

Use assembly when getting a contract's balance of ETH.

You can use `selfbalance()` instead of `address(this).balance` when getting your contract's balance of ETH to save gas.
Additionally, you can use `balance(address)` instead of `address().balance` when getting an external contract's balance of ETH.

*Saves 15 gas when checking internal balance, 6 for external*

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

133:         if (address(this).balance < withdrawAmount) { 
134:             revert InsufficientBalance(withdrawAmount, address(this).balance);
```


*GitHub* : [133](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L133-L134)

### [G-46]<a name="g-46"></a> Use shift right/left instead of division/multiplication if possible

`<x> * 2` is the same as `<x> << 1`. While the compiler uses the `SHL` opcode to accomplish both, the version that uses multiplication incurs an overhead of **20 gas** due to `JUMP`s to and from a compiler utility function that introduces checks which can be avoided by using `unchecked {}` around the division by two.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

47:     uint256 private constant P256_N_DIV_2 = FCL.n / 2; 
```


*GitHub* : [47](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L47)

### [G-47]<a name="g-47"></a> Use `uint256(1)`/`uint256(2)` instead of `true`/`false` to save gas for changes

Use uint256(1) and uint256(2) for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from ‘false’ to ‘true’, after having been ‘true’ in the past. Refer to the [source](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/5ae630684a0f57de400ef69499addab4c32ac8fb/contracts/security/ReentrancyGuard.sol#L23-L27).

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

37:     mapping(uint256 nonce => mapping(address user => bool used)) internal _nonceUsed; 
```


*GitHub* : [37](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L37-L37)

### [G-48]<a name="g-48"></a> Using `private` rather than `public`, saves gas

For constants, the values can be read from the verified contract source code, or if there are multiple values there can be a single getter function that returns a tuple of the values of all currently-public constants. Saves 3406-3606 gas in deployment gas due to the compiler not having to create non-payable getter functions for deployment calldata, not having to store the bytes of the value outside of where it's used, and not adding another entry to the method ID table

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

43:     uint256 public constant REPLAYABLE_NONCE_KEY = 8453; 
```


*GitHub* : [43](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L43-L43)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

15:     address public immutable implementation; 
```


*GitHub* : [15](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L15-L15)

### [G-49]<a name="g-49"></a> Using `storage` instead of `memory` for structs/arrays saves gas

When fetching data from a storage location, assigning the data to a `memory` variable causes all fields of the struct/array to be read from storage, which incurs a Gcoldsload (**2100 gas**) for *each* field of the struct/array. If the fields are read from the new memory variable, they incur an additional `MLOAD` rather than a cheap stack read. Instead of declearing the variable with the `memory` keyword, declaring the variable with the `storage` keyword and caching any fields that need to be re-read in stack variables, will be much cheaper, only incuring the Gcoldsload for the fields actually read. The only time it makes sense to read the whole struct/array into a `memory` variable, is if the full struct/array is being returned by the function, is being passed to a function that requires `memory`, or if the array/struct is being read from another `memory` array/struct

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

114:         WithdrawRequest memory withdrawRequest = abi.decode(userOp.paymasterAndData[20:], (WithdrawRequest)); 
```


*GitHub* : [114](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L114-L114)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

104:         bytes[] memory owners = new bytes[](1); 
298:         SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper)); 
319:             WebAuthn.WebAuthnAuth memory auth = abi.decode(sigWrapper.signatureData, (WebAuthn.WebAuthnAuth)); 
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L104-L104), [298](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L298-L298), [319](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L319-L319)

### [G-50]<a name="g-50"></a> x + y is more efficient than using += for state variables (likewise for -=)

In instances found where either += or -= are used against state variables use x = x + y instead

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

138:         _withdrawableETH[userOp.sender] += withdrawAmount - maxCost; 
```


*GitHub* : [138](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L138)

### NonCritical Risk Issues

### [N-01]<a name="n-01"></a> Add inline comments for unnamed variables

`function foo(address x, address)` -> `function foo(address x, address /* y */)`

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost) 
110:         external
111:         onlyEntryPoint
112:         returns (bytes memory context, uint256 validationData)
113:     {
```


*GitHub* : [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L109-L113)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

330:     function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {} 
```


*GitHub* : [330](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L330-L330)

### [N-02]<a name="n-02"></a> `address` shouldn't be hard-coded

It is often better to declare `address`es as `immutable` (instead of constant), and assign them via constructor arguments. This allows the code to remain the same across deployments on different networks, and avoids recompilation when addresses need to change.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit 0x0000000000000000000000000000000000000005
29:     address constant MODEXP_PRECOMPILE = 0x0000000000000000000000000000000000000005; 
```


*GitHub* : [29](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L29-L29)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
305:         return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789; 
```


*GitHub* : [305](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L305-L305)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
218:         return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789; 
```


*GitHub* : [218](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L218-L218)

### [N-03]<a name="n-03"></a> Assembly block creates dirty bits

Writing data to the free memory pointer without later updating the free memory pointer will cause there to be dirty bits at that memory location. Not updating the free memory pointer will make it [harder](https://docs.soliditylang.org/en/latest/ir-breaking-changes.html#cleanup) for the optimizer to reason about whether the memory needs to be cleaned before use, which will lead to worse optimizations.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

95:         assembly { 
96:             let pointer := mload(0x40)
97:             // Define length of base, exponent and modulus. 0x20 == 32 bytes
98:             mstore(pointer, 0x20)
99:             mstore(add(pointer, 0x20), 0x20)
100:             mstore(add(pointer, 0x40), 0x20)
101:             // Define variables base, exponent and modulus
102:             mstore(add(pointer, 0x60), u)
103:             mstore(add(pointer, 0x80), minus_2modn)
104:             mstore(add(pointer, 0xa0), n)
105: 
106:             // Call the precompiled contract 0x05 = ModExp
107:             if iszero(staticcall(not(0), 0x05, pointer, 0xc0, pointer, 0x20)) { revert(0, 0) }
108:             result := mload(pointer)
109:         }
140:             assembly { 
141:                 for { let T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1)) } eq(T4, 0) {
142:                     index := sub(index, 1)
143:                     T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
144:                 } {}
145:                 zz := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
146: 
147:                 if eq(zz, 1) {
148:                     X := gx
149:                     Y := gy
150:                 }
151:                 if eq(zz, 2) {
152:                     X := Q0
153:                     Y := Q1
154:                 }
155:                 if eq(zz, 3) {
156:                     X := H0
157:                     Y := H1
158:                 }
159: 
160:                 index := sub(index, 1)
161:                 zz := 1
162:                 zzz := 1
163: 
164:                 for {} gt(minus_1, index) { index := sub(index, 1) } {
165:                     // inlined EcZZ_Dbl
166:                     let T1 := mulmod(2, Y, p) //U = 2*Y1, y free
167:                     let T2 := mulmod(T1, T1, p) // V=U^2
168:                     let T3 := mulmod(X, T2, p) // S = X1*V
169:                     T1 := mulmod(T1, T2, p) // W=UV
170:                     let T4 := mulmod(3, mulmod(addmod(X, sub(p, zz), p), addmod(X, zz, p), p), p) //M=3*(X1-ZZ1)*(X1+ZZ1)
171:                     zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
172:                     zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
173: 
174:                     X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
175:                     T2 := mulmod(T4, addmod(X, sub(p, T3), p), p) //-M(S-X3)=M(X3-S)
176:                     Y := addmod(mulmod(T1, Y, p), T2, p) //-Y3= W*Y1-M(S-X3), we replace Y by -Y to avoid a sub in ecAdd
177: 
178:                     {
179:                         //value of dibit
180:                         T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
181: 
182:                         if iszero(T4) {
183:                             Y := sub(p, Y) //restore the -Y inversion
184:                             continue
185:                         } // if T4!=0
186: 
187:                         if eq(T4, 1) {
188:                             T1 := gx
189:                             T2 := gy
190:                         }
191:                         if eq(T4, 2) {
192:                             T1 := Q0
193:                             T2 := Q1
194:                         }
195:                         if eq(T4, 3) {
196:                             T1 := H0
197:                             T2 := H1
198:                         }
199:                         if iszero(zz) {
200:                             X := T1
201:                             Y := T2
202:                             zz := 1
203:                             zzz := 1
204:                             continue
205:                         }
206:                         // inlined EcZZ_AddN
207: 
208:                         //T3:=sub(p, Y)
209:                         //T3:=Y
210:                         let y2 := addmod(mulmod(T2, zzz, p), Y, p) //R
211:                         T2 := addmod(mulmod(T1, zz, p), sub(p, X), p) //P
212: 
213:                         //special extremely rare case accumulator where EcAdd is replaced by EcDbl, no need to optimize this
214:                         //todo : construct edge vector case
215:                         if iszero(y2) {
216:                             if iszero(T2) {
217:                                 T1 := mulmod(minus_2, Y, p) //U = 2*Y1, y free
218:                                 T2 := mulmod(T1, T1, p) // V=U^2
219:                                 T3 := mulmod(X, T2, p) // S = X1*V
220: 
221:                                 T1 := mulmod(T1, T2, p) // W=UV
222:                                 y2 := mulmod(addmod(X, zz, p), addmod(X, sub(p, zz), p), p) //(X-ZZ)(X+ZZ)
223:                                 T4 := mulmod(3, y2, p) //M=3*(X-ZZ)(X+ZZ)
224: 
225:                                 zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
226:                                 zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
227: 
228:                                 X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
229:                                 T2 := mulmod(T4, addmod(T3, sub(p, X), p), p) //M(S-X3)
230: 
231:                                 Y := addmod(T2, mulmod(T1, Y, p), p) //Y3= M(S-X3)-W*Y1
232: 
233:                                 continue
234:                             }
235:                         }
236: 
237:                         T4 := mulmod(T2, T2, p) //PP
238:                         let TT1 := mulmod(T4, T2, p) //PPP, this one could be spared, but adding this register spare gas
239:                         zz := mulmod(zz, T4, p)
240:                         zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1
241:                         let TT2 := mulmod(X, T4, p)
242:                         T4 := addmod(addmod(mulmod(y2, y2, p), sub(p, TT1), p), mulmod(minus_2, TT2, p), p)
243:                         Y := addmod(mulmod(addmod(TT2, sub(p, T4), p), y2, p), mulmod(Y, TT1, p), p)
244: 
245:                         X := T4
246:                     }
247:                 } //end loop
248:                 let T := mload(0x40)
249:                 mstore(add(T, 0x60), zz)
250:                 //(X,Y)=ecZZ_SetAff(X,Y,zz, zzz);
251:                 //T[0] = inverseModp_Hard(T[0], p); //1/zzz, inline modular inversion using precompile:
252:                 // Define length of base, exponent and modulus. 0x20 == 32 bytes
253:                 mstore(T, 0x20)
254:                 mstore(add(T, 0x20), 0x20)
255:                 mstore(add(T, 0x40), 0x20)
256:                 // Define variables base, exponent and modulus
257:                 //mstore(add(pointer, 0x60), u)
258:                 mstore(add(T, 0x80), minus_2)
259:                 mstore(add(T, 0xa0), p)
260: 
261:                 // Call the precompiled contract 0x05 = ModExp
262:                 if iszero(staticcall(not(0), 0x05, T, 0xc0, T, 0x20)) { revert(0, 0) }
263: 
264:                 //Y:=mulmod(Y,zzz,p)//Y/zzz
265:                 //zz :=mulmod(zz, mload(T),p) //1/z
266:                 //zz:= mulmod(zz,zz,p) //1/zz
267:                 X := mulmod(X, mload(T), p) //X/zz
268:             } //end assembly
375:         assembly { 
376:             let pointer := mload(0x40)
377:             // Define length of base, exponent and modulus. 0x20 == 32 bytes
378:             mstore(pointer, 0x20)
379:             mstore(add(pointer, 0x20), 0x20)
380:             mstore(add(pointer, 0x40), 0x20)
381:             // Define variables base, exponent and modulus
382:             mstore(add(pointer, 0x60), u)
383:             mstore(add(pointer, 0x80), minus_2)
384:             mstore(add(pointer, 0xa0), p)
385: 
386:             // Call the precompiled contract 0x05 = ModExp
387:             if iszero(staticcall(not(0), 0x05, pointer, 0xc0, pointer, 0x20)) { revert(0, 0) }
388:             result := mload(pointer)
389:         }
```


*GitHub* : [95](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L95-L109), [140](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L140-L268), [375](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L375-L389)

### [N-04]<a name="n-04"></a> Assembly blocks should have extensive comments

Assembly blocks take a lot more time to audit than normal Solidity code, and often have gotchas and side-effects that the Solidity versions of the same code do not. Consider adding more comments explaining what is being done in every step of the assembly code, and describe why assembly is being used instead of Solidity.

*There are 8 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

95:         assembly { 
96:             let pointer := mload(0x40)
97:             // Define length of base, exponent and modulus. 0x20 == 32 bytes
98:             mstore(pointer, 0x20)
99:             mstore(add(pointer, 0x20), 0x20)
100:             mstore(add(pointer, 0x40), 0x20)
101:             // Define variables base, exponent and modulus
102:             mstore(add(pointer, 0x60), u)
103:             mstore(add(pointer, 0x80), minus_2modn)
104:             mstore(add(pointer, 0xa0), n)
105: 
106:             // Call the precompiled contract 0x05 = ModExp
107:             if iszero(staticcall(not(0), 0x05, pointer, 0xc0, pointer, 0x20)) { revert(0, 0) }
108:             result := mload(pointer)
109:         }
140:             assembly { 
141:                 for { let T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1)) } eq(T4, 0) {
142:                     index := sub(index, 1)
143:                     T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
144:                 } {}
145:                 zz := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
146: 
147:                 if eq(zz, 1) {
148:                     X := gx
149:                     Y := gy
150:                 }
151:                 if eq(zz, 2) {
152:                     X := Q0
153:                     Y := Q1
154:                 }
155:                 if eq(zz, 3) {
156:                     X := H0
157:                     Y := H1
158:                 }
159: 
160:                 index := sub(index, 1)
161:                 zz := 1
162:                 zzz := 1
163: 
164:                 for {} gt(minus_1, index) { index := sub(index, 1) } {
165:                     // inlined EcZZ_Dbl
166:                     let T1 := mulmod(2, Y, p) //U = 2*Y1, y free
167:                     let T2 := mulmod(T1, T1, p) // V=U^2
168:                     let T3 := mulmod(X, T2, p) // S = X1*V
169:                     T1 := mulmod(T1, T2, p) // W=UV
170:                     let T4 := mulmod(3, mulmod(addmod(X, sub(p, zz), p), addmod(X, zz, p), p), p) //M=3*(X1-ZZ1)*(X1+ZZ1)
171:                     zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
172:                     zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
173: 
174:                     X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
175:                     T2 := mulmod(T4, addmod(X, sub(p, T3), p), p) //-M(S-X3)=M(X3-S)
176:                     Y := addmod(mulmod(T1, Y, p), T2, p) //-Y3= W*Y1-M(S-X3), we replace Y by -Y to avoid a sub in ecAdd
177: 
178:                     {
179:                         //value of dibit
180:                         T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
181: 
182:                         if iszero(T4) {
183:                             Y := sub(p, Y) //restore the -Y inversion
184:                             continue
185:                         } // if T4!=0
186: 
187:                         if eq(T4, 1) {
188:                             T1 := gx
189:                             T2 := gy
190:                         }
191:                         if eq(T4, 2) {
192:                             T1 := Q0
193:                             T2 := Q1
194:                         }
195:                         if eq(T4, 3) {
196:                             T1 := H0
197:                             T2 := H1
198:                         }
199:                         if iszero(zz) {
200:                             X := T1
201:                             Y := T2
202:                             zz := 1
203:                             zzz := 1
204:                             continue
205:                         }
206:                         // inlined EcZZ_AddN
207: 
208:                         //T3:=sub(p, Y)
209:                         //T3:=Y
210:                         let y2 := addmod(mulmod(T2, zzz, p), Y, p) //R
211:                         T2 := addmod(mulmod(T1, zz, p), sub(p, X), p) //P
212: 
213:                         //special extremely rare case accumulator where EcAdd is replaced by EcDbl, no need to optimize this
214:                         //todo : construct edge vector case
215:                         if iszero(y2) {
216:                             if iszero(T2) {
217:                                 T1 := mulmod(minus_2, Y, p) //U = 2*Y1, y free
218:                                 T2 := mulmod(T1, T1, p) // V=U^2
219:                                 T3 := mulmod(X, T2, p) // S = X1*V
220: 
221:                                 T1 := mulmod(T1, T2, p) // W=UV
222:                                 y2 := mulmod(addmod(X, zz, p), addmod(X, sub(p, zz), p), p) //(X-ZZ)(X+ZZ)
223:                                 T4 := mulmod(3, y2, p) //M=3*(X-ZZ)(X+ZZ)
224: 
225:                                 zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
226:                                 zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
227: 
228:                                 X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
229:                                 T2 := mulmod(T4, addmod(T3, sub(p, X), p), p) //M(S-X3)
230: 
231:                                 Y := addmod(T2, mulmod(T1, Y, p), p) //Y3= M(S-X3)-W*Y1
232: 
233:                                 continue
234:                             }
235:                         }
236: 
237:                         T4 := mulmod(T2, T2, p) //PP
238:                         let TT1 := mulmod(T4, T2, p) //PPP, this one could be spared, but adding this register spare gas
239:                         zz := mulmod(zz, T4, p)
240:                         zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1
241:                         let TT2 := mulmod(X, T4, p)
242:                         T4 := addmod(addmod(mulmod(y2, y2, p), sub(p, TT1), p), mulmod(minus_2, TT2, p), p)
243:                         Y := addmod(mulmod(addmod(TT2, sub(p, T4), p), y2, p), mulmod(Y, TT1, p), p)
244: 
245:                         X := T4
246:                     }
247:                 } //end loop
248:                 let T := mload(0x40)
249:                 mstore(add(T, 0x60), zz)
250:                 //(X,Y)=ecZZ_SetAff(X,Y,zz, zzz);
251:                 //T[0] = inverseModp_Hard(T[0], p); //1/zzz, inline modular inversion using precompile:
252:                 // Define length of base, exponent and modulus. 0x20 == 32 bytes
253:                 mstore(T, 0x20)
254:                 mstore(add(T, 0x20), 0x20)
255:                 mstore(add(T, 0x40), 0x20)
256:                 // Define variables base, exponent and modulus
257:                 //mstore(add(pointer, 0x60), u)
258:                 mstore(add(T, 0x80), minus_2)
259:                 mstore(add(T, 0xa0), p)
260: 
261:                 // Call the precompiled contract 0x05 = ModExp
262:                 if iszero(staticcall(not(0), 0x05, T, 0xc0, T, 0x20)) { revert(0, 0) }
263: 
264:                 //Y:=mulmod(Y,zzz,p)//Y/zzz
265:                 //zz :=mulmod(zz, mload(T),p) //1/z
266:                 //zz:= mulmod(zz,zz,p) //1/zz
267:                 X := mulmod(X, mload(T), p) //X/zz
268:             } //end assembly
375:         assembly { 
376:             let pointer := mload(0x40)
377:             // Define length of base, exponent and modulus. 0x20 == 32 bytes
378:             mstore(pointer, 0x20)
379:             mstore(add(pointer, 0x20), 0x20)
380:             mstore(add(pointer, 0x40), 0x20)
381:             // Define variables base, exponent and modulus
382:             mstore(add(pointer, 0x60), u)
383:             mstore(add(pointer, 0x80), minus_2)
384:             mstore(add(pointer, 0xa0), p)
385: 
386:             // Call the precompiled contract 0x05 = ModExp
387:             if iszero(staticcall(not(0), 0x05, pointer, 0xc0, pointer, 0x20)) { revert(0, 0) }
388:             result := mload(pointer)
389:         }
```


*GitHub* : [375](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L375-L389), [95](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L95-L109), [140](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L140-L268)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

94:         assembly ("memory-safe") { 
95:             if missingAccountFunds {
96:                 // Ignore failure (it's EntryPoint's job to verify, not the account's).
97:                 pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
98:             }
99:         }
242:         assembly { 
243:             $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
244:         }
275:             assembly ("memory-safe") { 
276:                 revert(add(result, 32), mload(result))
277:             }
309:             assembly ("memory-safe") { 
310:                 owner := mload(add(ownerBytes, 32))
311:             }
```


*GitHub* : [94](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L94-L99), [242](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L242-L244), [275](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L275-L277), [309](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L309-L311)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

213:         assembly ("memory-safe") { 
214:             $.slot := MUTLI_OWNABLE_STORAGE_LOCATION
215:         }
```


*GitHub* : [213](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L213-L215)

### [N-05]<a name="n-05"></a> Avoid mutating `function`/`modifier` parameters

Use a local variable instead

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit scalar_u
137:                 scalar_u = addmod(scalar_u, n - scalar_v, n); 
/// @audit scalar_v
138:                 scalar_v = 0;
```


*GitHub* : [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L137-L138)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit userOpHash
149:             userOpHash = getUserOpHashWithoutChainId(userOp); 
```


*GitHub* : [149](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L149-L149)

### [N-06]<a name="n-06"></a> Avoid revertible function calls in a constructor

It is advisable to to perform validation within the constructor itself rather than in function calls it makes. This is because contract deployement may be performed through a frontend or manually so by having all of the validation conditions viewable in a single place allows for greater transparency during deployment for both the team and project users.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

102:     constructor() { 
103:         // Implementation should not be initializable (does not affect proxies which use their own storage).
104:         bytes[] memory owners = new bytes[](1);
105:         owners[0] = abi.encode(address(0));
/// @audit '_initializeOwners can revert'
106:         _initializeOwners(owners);
107:     }
```


*GitHub* : [102](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L102-L107)

### [N-07]<a name="n-07"></a> Avoid the use of sensitive terms

Use [alternative variants](https://www.zdnet.com/article/mysql-drops-master-slave-and-blacklist-whitelist-terminology/), e.g. allowlist/denylist instead of whitelist/blacklist

*There are 14 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

8: import {IPaymaster} from "account-abstraction/interfaces/IPaymaster.sol"; 
15: /// @notice ERC4337 Paymaster implementation compatible with Entrypoint v0.6. 
17: /// @dev See https://eips.ethereum.org/EIPS/eip-4337#extension-paymasters. 
18: contract MagicSpend is Ownable, IPaymaster {
73:     error UnsupportedPaymasterAsset(address asset); 
108:     /// @inheritdoc IPaymaster 
109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost)
114:         WithdrawRequest memory withdrawRequest = abi.decode(userOp.paymasterAndData[20:], (WithdrawRequest)); 
122:             revert UnsupportedPaymasterAsset(withdrawRequest.asset); 
142:     /// @inheritdoc IPaymaster 
143:     function postOp(IPaymaster.PostOpMode mode, bytes calldata context, uint256 actualGasCost)
```


*GitHub* : [8](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L8-L8), [15](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L15), [17](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L17-L18), [73](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L73), [108](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L108-L109), [114](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L114), [122](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L122), [142](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L142-L143)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

51:     /// @dev Whitelisting of `UserOperation`s that are allowed to skip the chain ID validation is 
90:     ///                            paymaster. 
247:     /// @notice Check if the given function selector is whitelisted to skip the chain ID validation. 
251:     /// @return `true` is the function selector is whitelisted to skip the chain ID validation, else `false`. 
```


*GitHub* : [51](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L51), [90](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L90), [247](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L247), [251](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L251)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

17: /// @author Daimo (https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol) 
50:     ///      See https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md. 
```


*GitHub* : [17](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L17), [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L50)

### [N-08]<a name="n-08"></a> Common functions should be refactored to a common base contract

The functions below have the same implementation as is seen in other files. The functions should be refactored into functions of a common base contract

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit also seen in src/SmartWallet/ERC1271.sol
291:     function _validateSignature(bytes32 message, bytes calldata signature) 
```


*GitHub* : [291](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L291-L291)

### [N-09]<a name="n-09"></a> Complicated functions should have explicit comments

Large and/or complex functions should have more comments to better explain the purpose of each logic step.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit function is 155 lines long
117:     function ecZZ_mulmuladd_S_asm( 
118:         uint256 Q0,
119:         uint256 Q1, //affine rep for input point Q
120:         uint256 scalar_u,
121:         uint256 scalar_v
122:     ) internal view returns (uint256 X) {
```


*GitHub* : [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L117-L122)

### [N-10]<a name="n-10"></a> Consider adding a block/deny-list

Doing so will significantly increase centralization, but will help to prevent hackers from using stolen tokens

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

18: contract MagicSpend is Ownable, IPaymaster { 
19:     /// @notice Signed withdraw request allowing accounts to withdraw funds from this contract.
20:     struct WithdrawRequest {
21:         /// @dev The signature associated with this withdraw request.
22:         bytes signature;
23:         /// @dev The asset to withdraw. NOTE: Only ETH (associated with zero address) is supported for now.
24:         address asset;
25:         /// @dev The requested amount to withdraw.
26:         uint256 amount;
27:         /// @dev Unique nonce used to prevent replays.
28:         uint256 nonce;
```


*GitHub* : [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L18-L28)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

20: contract CoinbaseSmartWallet is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 { 
21:     /// @notice Wrapper struct, used during signature validation, tie a signature with its signer.
22:     struct SignatureWrapper {
23:         /// @dev The index indentifying owner (see MultiOwnable) who signed.
24:         uint256 ownerIndex;
25:         /// @dev An ABI encoded ECDSA signature (r, s, v) or WebAuthnAuth struct.
26:         bytes signatureData;
27:     }
28: 
29:     /// @notice Wrapper struct, used in `executeBatch`, describing a raw call to execute.
30:     struct Call {
```


*GitHub* : [20](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L20-L30)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

13: contract CoinbaseSmartWalletFactory { 
14:     /// @notice Address of the ERC-4337 implementation used as implementation for new accounts.
15:     address public immutable implementation;
16: 
17:     /// @notice Thrown when trying to create a new `CoinbaseSmartWallet` account without any owner.
18:     error OwnerRequired();
19: 
20:     /// @notice Factory constructor used to initialize the implementation address to use for future
21:     ///         ERC-4337 account deployments.
22:     ///
23:     /// @param erc4337 The address of the ERC-4337 implementation used to deploy new cloned accounts.
```


*GitHub* : [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L13-L23)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

32: contract MultiOwnable { 
33:     /// @dev Slot for the `MultiOwnableStorage` struct in storage.
34:     ///      Computed from: keccak256(abi.encode(uint256(keccak256("coinbase.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
35:     ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
36:     bytes32 private constant MUTLI_OWNABLE_STORAGE_LOCATION =
37:         0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;
38: 
39:     /// @notice Thrown when the sender is not an owner and is trying to call a privileged function.
40:     error Unauthorized();
41: 
42:     /// @notice Thrown when trying to add an already registered owner.
```


*GitHub* : [32](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L32-L42)

### [N-11]<a name="n-11"></a> Consider making contracts `Upgradeable`

This allows for bugs to be fixed in production, at the expense of *significantly* increasing centralization.

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit contract MagicSpend is not upgradeable
18: contract MagicSpend is Ownable, IPaymaster { 
```


*GitHub* : [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L18-L18)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit contract CoinbaseSmartWalletFactory is not upgradeable
13: contract CoinbaseSmartWalletFactory { 
```


*GitHub* : [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L13-L13)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit contract ERC1271 is not upgradeable
16: abstract contract ERC1271 { 
```


*GitHub* : [16](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L16-L16)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit contract MultiOwnable is not upgradeable
32: contract MultiOwnable { 
```


*GitHub* : [32](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L32-L32)

### [N-12]<a name="n-12"></a> Consider using `delete` rather than assigning zero to clear values

The `delete` keyword more closely matches the semantics of what is being done, and draws more attention to the changing of state, which may lead to a more thorough audit of its associated logic.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

138:                 scalar_v = 0; 
```


*GitHub* : [138](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L138-L138)

### [N-13]<a name="n-13"></a> Constants in comparisons should appear on the left side

Putting constants on the left side of comparison statements is a best practice known as [Yoda conditions](https://en.wikipedia.org/wiki/Yoda_conditions). Although solidity's static typing system prevents accidental assignments within conditionals, adopting this practice can improve code readability and consistency, especially when working across multiple languages.

*There are 13 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit move 0 to the left
/// @audit move 0 to the left
51:         if (r == 0 || r >= n || s == 0 || s >= n) { 
/// @audit move 0 to the left
/// @audit move 0 to the left
131:             if (scalar_u == 0 && scalar_v == 0) return 0; 
/// @audit move 0 to the left
/// @audit move 0 to the left
134:             if ( 
135:                 (H0 == 0) && (H1 == 0) //handling Q=-G
/// @audit move 0 to the left
350:             if (y1 == 0) { 
```


*GitHub* : [51](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L51-L51), [131](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L131-L131), [134](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L134-L135), [350](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L350-L350)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit move 0 to the left
172:         if (amount == 0) revert NoExcess(); 
```


*GitHub* : [172](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L172-L172)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit move 0 to the left
115:         if (nextOwnerIndex() != 0) { 
/// @audit move 0xbf6ba1fc to the left
148:         if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) { 
/// @audit move 32 to the left
301:         if (ownerBytes.length == 32) { 
/// @audit move 64 to the left
316:         if (ownerBytes.length == 64) { 
```


*GitHub* : [115](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L115-L115), [148](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L148-L148), [301](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L301-L301), [316](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L316-L316)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit move 0 to the left
44:         if (owners.length == 0) { 
```


*GitHub* : [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L44-L44)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit move 0 to the left
104:         if (owner.length == 0) revert NoOwnerAtIndex(index); 
/// @audit move 32 to the left
/// @audit move 64 to the left
164:             if (owners[i].length != 32 && owners[i].length != 64) { 
/// @audit move 32 to the left
168:             if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) { 
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L104-L104), [164](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L164-L164), [168](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L168-L168)

### [N-14]<a name="n-14"></a> `constant`s should be defined rather than using magic numbers

Even [assembly](https://github.com/code-423n4/2022-05-opensea-seaport/blob/9d7ce4d08bf3c3010304a0476a785c70c0e90ae7/contracts/lib/TokenTransferrer.sol#L35-L39) can benefit from using readable constants instead of hex/numeric literals

*There are 17 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

126:         uint256 index = 255; 
```


*GitHub* : [126](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L126)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

114:         WithdrawRequest memory withdrawRequest = abi.decode(userOp.paymasterAndData[20:], (WithdrawRequest)); 
128:         validationData = (sigFailed ? 1 : 0) | (uint256(withdrawRequest.expiry) << 160); 
305:         return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789; 
```


*GitHub* : [114](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L114), [128](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L128), [305](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L305)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

145:         uint256 key = userOp.nonce >> 64; 
148:         if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) { 
181:         bytes4 selector = bytes4(data[0:4]); 
218:         return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789; 
301:         if (ownerBytes.length == 32) { 
316:         if (ownerBytes.length == 64) { 
```


*GitHub* : [145](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L145), [148](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L148-L148), [181](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L181), [218](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L218), [301](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L301), [316](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L316)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

72:             return 0x1626ba7e; 
75:         return 0xffffffff; 
```


*GitHub* : [72](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L72), [75](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L75)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

164:             if (owners[i].length != 32 && owners[i].length != 64) { 
168:             if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) { 
```


*GitHub* : [164](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L164-L164), [168](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L168)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

116:         string memory _type = webAuthnAuth.clientDataJSON.slice(webAuthnAuth.typeIndex, webAuthnAuth.typeIndex + 21); 
133:         if (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UP != AUTH_DATA_FLAGS_UP) { 
138:         if (requireUV && (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV) { 
```


*GitHub* : [138](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L138), [116](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L116), [133](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L133)

### [N-15]<a name="n-15"></a> `constant`s/`immutable`s redefined elsewhere

Consider defining each of these in only one contract so that values cannot become out of sync when only one location is updated (i.e. having `ContA.X`,`ContB.Y` is fine since they're different constant names in different files, but `ContA.X`, `ContB.X` is not since it's the same constant defined in multiple files with the same value). Even things like `decimals` and `VERSION` can employ file-level constants such as `PREFERRED_DECIMALS = 18` and `INITIAL_VERSION = "1.0.0"`

*There are 18 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

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


*GitHub* : [29](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L29-L29), [31](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L31-L31), [33](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L33-L33), [35](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L35-L35), [37](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L37-L38), [40](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L40-L40), [42](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L42-L42), [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L44-L44), [46](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L46-L46)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

43:     uint256 public constant REPLAYABLE_NONCE_KEY = 8453; 
```


*GitHub* : [43](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L43-L43)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

15:     address public immutable implementation; 
```


*GitHub* : [15](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L15-L15)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

23:     bytes32 private constant _MESSAGE_TYPEHASH = keccak256("CoinbaseSmartWalletMessage(bytes32 hash)"); 
```


*GitHub* : [23](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L23-L23)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

36:     bytes32 private constant MUTLI_OWNABLE_STORAGE_LOCATION = 
37:         0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;
```


*GitHub* : [36](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L36-L37)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

40:     bytes1 private constant AUTH_DATA_FLAGS_UP = 0x01; 
44:     bytes1 private constant AUTH_DATA_FLAGS_UV = 0x04; 
47:     uint256 private constant P256_N_DIV_2 = FCL.n / 2; 
51:     address private constant VERIFIER = address(0x100); 
55:     bytes32 private constant EXPECTED_TYPE_HASH = keccak256('"type":"webauthn.get"'); 
```


*GitHub* : [40](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L40-L40), [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L44-L44), [47](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L47-L47), [51](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L51-L51), [55](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L55-L55)

### [N-16]<a name="n-16"></a> `constructor` should emit an event

Use events to signal significant changes to off-chain monitoring tools.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

101:     constructor(address _owner) { 
```


*GitHub* : [101](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L101-L101)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

102:     constructor() { 
```


*GitHub* : [102](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L102-L102)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

24:     constructor(address erc4337) payable { 
```


*GitHub* : [24](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L24-L24)

### [N-17]<a name="n-17"></a> Contracts should have all `public`/`external` functions exposed by `interface`s

The `contract`s should expose an `interface` so that other projects can more easily integrate with it, without having to develop their own non-standard variants.

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit validatePaymasterUserOp, postOp, withdrawGasExcess, withdraw, ownerWithdraw, entryPointDeposit, entryPointWithdraw, entryPointAddStake, entryPointUnlockStake, entryPointWithdrawStake, isValidWithdrawSignature, getHash, nonceUsed, entryPoint
18: contract MagicSpend is Ownable, IPaymaster { 
19:     /// @notice Signed withdraw request allowing accounts to withdraw funds from this contract.
20:     struct WithdrawRequest {
```


*GitHub* : [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L18-L20)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit implementation, canSkipChainIdValidation
20: contract CoinbaseSmartWallet is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 { 
21:     /// @notice Wrapper struct, used during signature validation, tie a signature with its signer.
22:     struct SignatureWrapper {
```


*GitHub* : [20](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L20-L22)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit getAddress
13: contract CoinbaseSmartWalletFactory { 
14:     /// @notice Address of the ERC-4337 implementation used as implementation for new accounts.
15:     address public immutable implementation;
```


*GitHub* : [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L13-L15)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit domainSeparator
16: abstract contract ERC1271 { 
17:     /// @dev Precomputed `typeHash` used to produce EIP-712 compliant hash when applying the anti
18:     ///      cross-account-replay layer.
19:     ///
20:     ///      The original hash must either be:
21:     ///         - An EIP-191 hash: keccak256("\x19Ethereum Signed Message:\n" || len(someMessage) || someMessage)
22:     ///         - An EIP-712 hash: keccak256("\x19\x01" || someDomainSeparator || hashStruct(someStruct))
23:     bytes32 private constant _MESSAGE_TYPEHASH = keccak256("CoinbaseSmartWalletMessage(bytes32 hash)");
```


*GitHub* : [16](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L16-L23)

### [N-18]<a name="n-18"></a> Control structures do not follow the Solidity Style Guide

See the [control structures](https://docs.soliditylang.org/en/latest/style-guide.html#control-structures) section of the Solidity Style Guide

*There are 17 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
301:     function ecZZ_SetAff(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
302:         internal
303:         view
304:         returns (uint256 x1, uint256 y1)
305:     {
/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
318:     function ecZZ_Dbl(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
319:         internal
320:         pure
321:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
322:     {
/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
344:     function ecZZ_AddN(uint256 x1, uint256 y1, uint256 zz1, uint256 zzz1, uint256 x2, uint256 y2) 
345:         internal
346:         pure
347:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
348:     {
```


*GitHub* : [301](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L301-L305), [318](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L318-L322), [344](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L344-L348)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit opening brace should be preceded by a single space
93:     modifier onlyEntryPoint() virtual { 
/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost) 
110:         external
111:         onlyEntryPoint
112:         returns (bytes memory context, uint256 validationData)
113:     {
/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
143:     function postOp(IPaymaster.PostOpMode mode, bytes calldata context, uint256 actualGasCost) 
144:         external
145:         onlyEntryPoint
146:     {
/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
260:     function isValidWithdrawSignature(address account, WithdrawRequest memory withdrawRequest) 
261:         public
262:         view
263:         returns (bool)
264:     {
```


*GitHub* : [93](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L93), [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L109-L113), [143](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L143-L146), [260](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L260-L264)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit opening brace should be preceded by a single space
65:     modifier onlyEntryPoint() virtual { 
/// @audit opening brace should be preceded by a single space
74:     modifier onlyEntryPointOrOwner() virtual { 
/// @audit opening brace should be preceded by a single space
91:     modifier payPrefund(uint256 missingAccountFunds) virtual { 
/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
137:     function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
138:         public
139:         payable
140:         virtual
141:         onlyEntryPoint
142:         payPrefund(missingAccountFunds)
143:         returns (uint256 validationData)
144:     {
/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
229:     function getUserOpHashWithoutChainId(UserOperation calldata userOp) 
230:         public
231:         view
232:         virtual
233:         returns (bytes32 userOpHash)
234:     {
/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
291:     function _validateSignature(bytes32 message, bytes calldata signature) 
292:         internal
293:         view
294:         virtual
295:         override
296:         returns (bool)
297:     {
```


*GitHub* : [65](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L65), [74](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L74), [91](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L91), [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L137-L144), [229](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L229-L234), [291](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L291-L297)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
38:     function createAccount(bytes[] calldata owners, uint256 nonce) 
39:         public
40:         payable
41:         virtual
42:         returns (CoinbaseSmartWallet account)
43:     {
```


*GitHub* : [38](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L38-L43)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
36:     function eip712Domain() 
37:         external
38:         view
39:         virtual
40:         returns (
41:             bytes1 fields,
42:             string memory name,
43:             string memory version,
44:             uint256 chainId,
45:             address verifyingContract,
46:             bytes32 salt,
47:             uint256[] memory extensions
48:         )
49:     {
```


*GitHub* : [36](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L36-L49)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit opening brace should be preceded by a single space
77:     modifier onlyOwner() virtual { 
```


*GitHub* : [77](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L77)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit opening brace should be on the same line as the declaration
/// @audit opening brace should be preceded by a single space
104:     function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory webAuthnAuth, uint256 x, uint256 y) 
105:         internal
106:         view
107:         returns (bool)
108:     {
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L104-L108)

### [N-19]<a name="n-19"></a> Custom `error` without details

Consider adding some parameters to the error to indicate which user or values caused the failure.

*There are 7 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

53:     error InvalidSignature(); 
56:     error Expired(); 
83:     error NoExcess(); 
90:     error UnexpectedPostOpRevertedMode(); 
```


*GitHub* : [53](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L53), [56](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L56), [83](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L83), [90](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L90)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

46:     error Initialized(); 
```


*GitHub* : [46](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L46)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

18:     error OwnerRequired(); 
```


*GitHub* : [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L18)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

40:     error Unauthorized(); 
```


*GitHub* : [40](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L40)

### [N-20]<a name="n-20"></a> Empty bytes check is missing

Passing empty bytes to a function can cause unexpected behavior, such as certain operations failing, producing incorrect results, or wasting gas. It is recommended to check that all byte parameters are not empty.

*There are 9 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost) 
110:         external
111:         onlyEntryPoint
112:         returns (bytes memory context, uint256 validationData)
113:     {
/// @audit context
143:     function postOp(IPaymaster.PostOpMode mode, bytes calldata context, uint256 actualGasCost) 
144:         external
145:         onlyEntryPoint
146:     {
```


*GitHub* : [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L109-L113), [143](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L143-L146)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit userOpHash
137:     function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
138:         public
139:         payable
140:         virtual
141:         onlyEntryPoint
142:         payPrefund(missingAccountFunds)
143:         returns (uint256 validationData)
144:     {
/// @audit data
180:     function executeWithoutChainIdValidation(bytes calldata data) public payable virtual onlyEntryPoint { 
/// @audit data
196:     function execute(address target, uint256 value, bytes calldata data) public payable virtual onlyEntryPointOrOwner { 
/// @audit data
272:     function _call(address target, uint256 value, bytes memory data) internal { 
```


*GitHub* : [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L137-L144), [180](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L180-L180), [196](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L196-L196), [272](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L272-L272)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit x
/// @audit y
93:     function addOwnerPublicKey(bytes32 x, bytes32 y) public virtual onlyOwner { 
/// @audit owner
179:     function _addOwner(bytes memory owner) internal virtual { 
/// @audit owner
189:     function _addOwnerAtIndex(bytes memory owner, uint256 index) internal virtual { 
```


*GitHub* : [93](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L93-L93), [179](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L179-L179), [189](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L189-L189)

### [N-21]<a name="n-21"></a> Empty function body

Empty function body in solidity is not recommended, consider adding some comments to the body.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

106:     receive() external payable {} 
```


*GitHub* : [106](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L106-L106)

### [N-22]<a name="n-22"></a> Enum values should be used instead of constant array indexes

Create a commented enum value to use instead of constant array indexes, this makes the code far easier to understand.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit 0
105:         owners[0] = abi.encode(address(0)); 
```


*GitHub* : [105](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L105)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit 32
133:         if (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UP != AUTH_DATA_FLAGS_UP) { 
/// @audit 32
138:         if (requireUV && (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV) { 
```


*GitHub* : [133](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L133), [138](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L138)

### [N-23]<a name="n-23"></a> Event is missing `indexed` fields

Index event fields make the field more quickly accessible to off-chain tools that parse events. However, note that each index field costs extra gas during emission, so it's not necessarily best to index the maximum allowed per event (three fields). Each event should use three indexed fields if there are three or more fields, and gas usage is not particularly of concern for the events in question. If there are fewer than three fields, all of the fields should be indexed.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

45:     event MagicSpendWithdrawal(address indexed account, address indexed asset, uint256 amount, uint256 nonce); 
```


*GitHub* : [45](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L45-L45)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

68:     event AddOwner(uint256 indexed index, bytes owner); 
74:     event RemoveOwner(uint256 indexed index, bytes owner); 
```


*GitHub* : [68](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L68-L68), [74](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L74-L74)

### [N-24]<a name="n-24"></a> Events are missing sender information

When an action is triggered based on a user's action, not being able to filter based on who triggered the action makes event processing a lot more cumbersome. Including the msg.sender the events of these types of action will make events much more useful to end users, especially when `msg.sender` is not `tx.origin`.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

323:         emit MagicSpendWithdrawal(account, withdrawRequest.asset, withdrawRequest.amount, withdrawRequest.nonce); 
```


*GitHub* : [323](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L323-L323)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

109:         emit RemoveOwner(index, owner); 
195:         emit AddOwner(index, owner); 
```


*GitHub* : [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L109-L109), [195](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L195-L195)

### [N-25]<a name="n-25"></a> Expressions for `constant` values should use `immutable` rather than constant

While it does not save gas for some simple binary expressions because the compiler knows that developers often make this mistake, it's still best to use the right tool for the task at hand. There is a difference between `constant` variables and `immutable` variables, and they should each be used in their appropriate contexts. `constants` should be used for literal values written into the code, and `immutable` variables should be used for expressions, or values calculated in, or passed into the constructor.

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/ERC1271.sol

23:     bytes32 private constant _MESSAGE_TYPEHASH = keccak256("CoinbaseSmartWalletMessage(bytes32 hash)"); 
```


*GitHub* : [23](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L23-L23)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

47:     uint256 private constant P256_N_DIV_2 = FCL.n / 2; 
51:     address private constant VERIFIER = address(0x100); 
55:     bytes32 private constant EXPECTED_TYPE_HASH = keccak256('"type":"webauthn.get"'); 
```


*GitHub* : [47](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L47-L47), [51](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L51-L51), [55](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L55-L55)

### [N-26]<a name="n-26"></a> For loops in `public` or `external` functions should be avoided due to high gas costs and possible DOS

In Solidity, for loops can potentially cause Denial of Service (DoS) attacks if not handled carefully. DoS attacks can occur when an attacker intentionally exploits the gas cost of a function, causing it to run out of gas or making it too expensive for other users to call. Below are some scenarios where for loops can lead to DoS attacks: Nested for loops can become exceptionally gas expensive and should be used sparingly.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit line 206
205:     function executeBatch(Call[] calldata calls) public payable virtual onlyEntryPointOrOwner { 
206:         for (uint256 i; i < calls.length;) {
207:             _call(calls[i].target, calls[i].value, calls[i].data);
208:             unchecked {
209:                 ++i;
210:             }
211:         }
212:     }
```


*GitHub* : [205](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L205-L212)

### [N-27]<a name="n-27"></a> Function called does not exist in the contract interface

_

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

223:         IEntryPoint(entryPoint()).withdrawTo(to, amount); 
233:         IEntryPoint(entryPoint()).addStake{value: amount}(unstakeDelaySeconds); 
240:         IEntryPoint(entryPoint()).unlockStake(); 
249:         IEntryPoint(entryPoint()).withdrawStake(to); 
```


*GitHub* : [223](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L223-L223), [233](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L233-L233), [240](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L240-L240), [249](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L249-L249)

### [N-28]<a name="n-28"></a> Function ordering in the contract does not follow the Solidity style guide

Source: [https://docs.soliditylang.org/en/v0.8.17/style-guide.html#order-of-layout](https://docs.soliditylang.org/en/v0.8.17/style-guide.html#order-of-layout)

*There are 13 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

106:     receive() external payable {} 
109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost) 
143:     function postOp(IPaymaster.PostOpMode mode, bytes calldata context, uint256 actualGasCost) 
169:     function withdrawGasExcess() external { 
181:     function withdraw(WithdrawRequest memory withdrawRequest) external { 
203:     function ownerWithdraw(address asset, address to, uint256 amount) external onlyOwner { 
212:     function entryPointDeposit(uint256 amount) external payable onlyOwner { 
222:     function entryPointWithdraw(address payable to, uint256 amount) external onlyOwner { 
232:     function entryPointAddStake(uint256 amount, uint32 unstakeDelaySeconds) external payable onlyOwner { 
239:     function entryPointUnlockStake() external onlyOwner { 
248:     function entryPointWithdrawStake(address payable to) external onlyOwner { 
299:     function nonceUsed(address account, uint256 nonce) external view returns (bool) { 
```


*GitHub* : [106](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L106), [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L109), [143](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L143), [169](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L169), [181](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L181), [203](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L203), [212](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L212), [222](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L222), [232](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L232), [239](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L239), [248](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L248), [299](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L299)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

64:     function getAddress(bytes[] calldata owners, uint256 nonce) external view returns (address predicted) { 
```


*GitHub* : [64](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L64)

### [N-29]<a name="n-29"></a> Functions not used internally could be marked external

Contracts [are allowed](https://docs.soliditylang.org/en/latest/contracts.html#function-overriding) to override their parents' functions and change the visibility from `external` to `public`.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

241:     function implementation() public view returns (address $) { 
```


*GitHub* : [241](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L241-L241)

### [N-30]<a name="n-30"></a> Functions should be named in mixedCase style

According to the Solidity [style guide](https://docs.soliditylang.org/en/latest/style-guide.html#function-names) function names should be in `mixedCase` (lowerCamelCase)Rule exceptions
- Allow `_` at the beginning of the mixedCase match for `private`/`internal` functions.

*There are 10 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit ecdsa_verify
50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) { 
/// @audit ecAff_isOnCurve
78:     function ecAff_isOnCurve(uint256 x, uint256 y) internal pure returns (bool) { 
/// @audit FCL_nModInv
94:     function FCL_nModInv(uint256 u) internal view returns (uint256 result) { 
/// @audit ecZZ_mulmuladd_S_asm
117:     function ecZZ_mulmuladd_S_asm( 
/// @audit ecAff_add
274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) { 
/// @audit ecAff_IsZero
293:     function ecAff_IsZero(uint256, uint256 y) internal pure returns (bool flag) { 
/// @audit ecZZ_SetAff
301:     function ecZZ_SetAff(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
/// @audit ecZZ_Dbl
318:     function ecZZ_Dbl(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
/// @audit ecZZ_AddN
344:     function ecZZ_AddN(uint256 x1, uint256 y1, uint256 zz1, uint256 zzz1, uint256 x2, uint256 y2) 
/// @audit FCL_pModInv
374:     function FCL_pModInv(uint256 u) internal view returns (uint256 result) { 
```


*GitHub* : [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L50-L50), [78](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L78-L78), [94](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L94-L94), [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L117-L117), [274](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L274-L274), [293](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L293-L293), [301](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L301-L301), [318](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L318-L318), [344](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L344-L344), [374](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L374-L374)

### [N-31]<a name="n-31"></a> High cyclomatic complexity

Functions with high cyclomatic complexity are harder to understand, test, and maintain. Consider breaking down these blocks into more manageable units, by splitting things into utility functions, by reducing nesting, and by using early returns.

[Learn More About Cyclomatic Complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity)

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost) 
110:         external
111:         onlyEntryPoint
112:         returns (bytes memory context, uint256 validationData)
113:     {
114:         WithdrawRequest memory withdrawRequest = abi.decode(userOp.paymasterAndData[20:], (WithdrawRequest));
115:         uint256 withdrawAmount = withdrawRequest.amount;
116: 
117:         if (withdrawAmount < maxCost) {
118:             revert RequestLessThanGasMaxCost(withdrawAmount, maxCost);
119:         }
120: 
121:         if (withdrawRequest.asset != address(0)) {
122:             revert UnsupportedPaymasterAsset(withdrawRequest.asset);
123:         }
124: 
125:         _validateRequest(userOp.sender, withdrawRequest);
126: 
127:         bool sigFailed = !isValidWithdrawSignature(userOp.sender, withdrawRequest);
128:         validationData = (sigFailed ? 1 : 0) | (uint256(withdrawRequest.expiry) << 160);
129: 
130:         // Ensure at validation that the contract has enough balance to cover the requested funds.
131:         // NOTE: This check is necessary to enforce that the contract will be able to transfer the remaining funds
132:         //       when `postOp()` is called back after the `UserOperation` has been executed.
133:         if (address(this).balance < withdrawAmount) {
134:             revert InsufficientBalance(withdrawAmount, address(this).balance);
135:         }
136: 
137:         // NOTE: Do not include the gas part in withdrawable funds as it will be handled in `postOp()`.
138:         _withdrawableETH[userOp.sender] += withdrawAmount - maxCost;
139:         context = abi.encode(maxCost, userOp.sender);
140:     }
```


*GitHub* : [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L109-L140)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

137:     function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
138:         public
139:         payable
140:         virtual
141:         onlyEntryPoint
142:         payPrefund(missingAccountFunds)
143:         returns (uint256 validationData)
144:     {
145:         uint256 key = userOp.nonce >> 64;
146: 
147:         // 0xbf6ba1fc = bytes4(keccak256("executeWithoutChainIdValidation(bytes)"))
148:         if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) {
149:             userOpHash = getUserOpHashWithoutChainId(userOp);
150:             if (key != REPLAYABLE_NONCE_KEY) {
151:                 revert InvalidNonceKey(key);
152:             }
153:         } else {
154:             if (key == REPLAYABLE_NONCE_KEY) {
155:                 revert InvalidNonceKey(key);
156:             }
157:         }
158: 
159:         // Return 0 if the recovered address matches the owner.
160:         if (_validateSignature(userOpHash, userOp.signature)) {
161:             return 0;
162:         }
163: 
164:         // Else return 1, which is equivalent to:
165:         // `(uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)`
166:         // where `validUntil` is 0 (indefinite) and `validAfter` is 0.
167:         return 1;
168:     }
```


*GitHub* : [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L137-L168)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

104:     function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory webAuthnAuth, uint256 x, uint256 y) 
105:         internal
106:         view
107:         returns (bool)
108:     {
109:         if (webAuthnAuth.s > P256_N_DIV_2) {
110:             // guard against signature malleability
111:             return false;
112:         }
113: 
114:         // 11. Verify that the value of C.type is the string webauthn.get.
115:         // bytes("type":"webauthn.get").length = 21
116:         string memory _type = webAuthnAuth.clientDataJSON.slice(webAuthnAuth.typeIndex, webAuthnAuth.typeIndex + 21);
117:         if (keccak256(bytes(_type)) != EXPECTED_TYPE_HASH) {
118:             return false;
119:         }
120: 
121:         // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
122:         bytes memory expectedChallenge = bytes(string.concat('"challenge":"', Base64.encodeURL(challenge), '"'));
123:         string memory actualChallenge = webAuthnAuth.clientDataJSON.slice(
124:             webAuthnAuth.challengeIndex, webAuthnAuth.challengeIndex + expectedChallenge.length
125:         );
126:         if (keccak256(bytes(actualChallenge)) != keccak256(expectedChallenge)) {
127:             return false;
128:         }
129: 
130:         // Skip 13., 14., 15.
131: 
132:         // 16. Verify that the UP bit of the flags in authData is set.
133:         if (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UP != AUTH_DATA_FLAGS_UP) {
134:             return false;
135:         }
136: 
137:         // 17. If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set.
138:         if (requireUV && (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV) {
139:             return false;
140:         }
141: 
142:         // skip 18.
143: 
144:         // 19. Let hash be the result of computing a hash over the cData using SHA-256.
145:         bytes32 clientDataJSONHash = sha256(bytes(webAuthnAuth.clientDataJSON));
146: 
147:         // 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
148:         bytes32 messageHash = sha256(abi.encodePacked(webAuthnAuth.authenticatorData, clientDataJSONHash));
149:         bytes memory args = abi.encode(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);
150:         // try the RIP-7212 precompile address
151:         (bool success, bytes memory ret) = VERIFIER.staticcall(args);
152:         // staticcall will not revert if address has no code
153:         // check return length
154:         // note that even if precompile exists, ret.length is 0 when verification returns false
155:         // so an invalid signature will be checked twice: once by the precompile and once by FCL.
156:         // Ideally this signature failure is simulated offchain and no one actually pay this gas.
157:         bool valid = ret.length > 0;
158:         if (success && valid) return abi.decode(ret, (uint256)) == 1;
159: 
160:         return FCL.ecdsa_verify(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);
161:     }
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L104-L161)

### [N-32]<a name="n-32"></a> `if`-statement can be converted to a ternary

The code can be made more compact while also increasing readability by converting the following `if`-statements to ternaries (e.g. `foo += (x > y) ? a : b`)

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

335:         if (asset == address(0)) { 
336:             SafeTransferLib.safeTransferETH(to, amount);
337:         } else {
338:             SafeTransferLib.safeTransfer(asset, to, amount);
339:         }
```


*GitHub* : [335](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L335-L339)

### [N-33]<a name="n-33"></a> Imports could be organized more systematically

The contract's interface should be imported first, followed by each of the interfaces it uses, followed by all other files. The examples below do not follow this layout.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

2: pragma solidity 0.8.23; 
3: 
4: import {Ownable} from "solady/auth/Ownable.sol";
5: import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
6: import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
7: import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
8: import {IPaymaster} from "account-abstraction/interfaces/IPaymaster.sol";
9: import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L2-L9)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

2: pragma solidity 0.8.23; 
3: 
4: import {Receiver} from "solady/accounts/Receiver.sol";
5: import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
6: import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
7: import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
8: import {WebAuthn} from "../WebAuthnSol/WebAuthn.sol";
9: 
10: import {ERC1271} from "./ERC1271.sol";
11: import {MultiOwnable} from "./MultiOwnable.sol";
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L2-L11)

### [N-34]<a name="n-34"></a> Inconsistent method of specifying a floating pragma

Some files use >=, while others use ^. The instances below are examples of the method that has the fewest instances for a specific version.



*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

24: pragma solidity >=0.8.19 <0.9.0; 
```


*GitHub* : [24](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L24)

### [N-35]<a name="n-35"></a> Inconsistent spacing in comments

Some lines use `// x` and some use `//x`. The instances below point out the usages that don't follow the majority, within each file

*There are 32 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit Space: `7`
/// @audit No space: `42`
1: //curve order (number of points) 
4: // | __| _ ___ __| |_    / __|_ _ _  _ _ __| |_ ___  | |  (_) |__ 
5: // | _| '_/ -_|_-< ' \  | (__| '_| || | '_ \  _/ _ \ | |__| | '_ \
6: // |_||_| \___/__/_||_|  \___|_|  \_, | .__/\__\___/ |____|_|_.__/
19: // Code is optimized for a=-3 only curves with prime order, constant like -1, -2 shall be replaced 
20: // if ever used for other curve than sec256R1
21: // Abstract: https://eprint.iacr.org/2023/939.pdf
22: // Github code: https://github.com/rdubois-crypto/FreshCryptoLib/blob/d9bb3b0fc6b737af2c70dab246cabbc7d05afc3c/solidity/src/FCL_ecdsa.sol#L40
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L1-L1), [4](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L4-L6), [19](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L19-L22)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit Space: `4`
/// @audit No space: `140`
1: // SPDX-License-Identifier: MIT 
11: /// @title Magic Spend 
13: /// @author Coinbase (https://github.com/coinbase/magic-spend) 
15: /// @notice ERC4337 Paymaster implementation compatible with Entrypoint v0.6. 
17: /// @dev See https://eips.ethereum.org/EIPS/eip-4337#extension-paymasters. 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L1-L1), [11](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L11), [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L13), [15](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L15), [17](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L17)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit Space: `5`
/// @audit No space: `127`
1: // SPDX-License-Identifier: MIT 
13: /// @title Coinbase Smart Wallet 
15: /// @notice ERC4337-compatible smart contract wallet, based on Solady ERC4337 account implementation 
16: ///         with inspiration from Alchemy's LightAccount and Daimo's DaimoAccount.
18: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
19: /// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol)
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L1-L1), [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L13), [15](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L15-L16), [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L18-L19)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit Space: `4`
/// @audit No space: `31`
1: // SPDX-License-Identifier: MIT 
7: /// @title Coinbase Smart Wallet Factory 
9: /// @notice CoinbaseSmartWallet factory, based on Solady's ERC4337Factory. 
11: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
12: /// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337Factory.sol)
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L1-L1), [7](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L7), [9](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L9), [11](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L11-L12)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit Space: `9`
/// @audit No space: `79`
1: // SPDX-License-Identifier: MIT 
4: /// @title ERC-1271 With Cross Account Replay Protection 
6: /// @notice Abstract ERC-1271 implementation (based on Solady's) with guards to handle the same 
7: ///         signer being used on multiple accounts.
9: /// @dev To prevent the same signature from being validated on different accounts owned by the samer signer, 
10: ///      we introduce an anti cross-account-replay layer: the original hash is input into a new EIP-712 compliant
11: ///      hash. The domain separator of this outer hash contains the chain id and address of this contract, so that
12: ///      it cannot be used on two accounts (see `replaySafeHash()` for the implementation details).
14: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
15: /// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC1271.sol)
```


*GitHub* : [9](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L9-L12), [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L1-L1), [4](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L4), [6](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L6-L7), [14](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L14-L15)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit Space: `5`
/// @audit No space: `98`
1: // SPDX-License-Identifier: MIT 
4: /// @notice Storage layout used by this contract. 
6: /// @custom:storage-location erc7201:coinbase.storage.MultiOwnable 
27: /// @title Multi Ownable 
29: /// @notice Auth contract allowing multiple owners, each identified as bytes. 
31: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L1-L1), [4](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L4), [6](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L6), [27](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L27), [29](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L29), [31](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L31)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit Space: `7`
/// @audit No space: `80`
1: // SPDX-License-Identifier: MIT 
8: /// @title WebAuthn 
10: /// @notice A library for verifying WebAuthn Authentication Assertions, built off the work 
11: ///         of Daimo.
13: /// @dev Attempts to use the RIP-7212 precompile for signature verification. 
14: ///      If precompile verification fails, it falls back to FreshCryptoLib.
16: /// @author Coinbase (https://github.com/base-org/webauthn-sol) 
17: /// @author Daimo (https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol)
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L1-L1), [8](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L8), [10](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L10-L11), [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L13-L14), [16](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L16-L17)

### [N-36]<a name="n-36"></a> Large numeric literals should use underscores for readability

_

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

43:     uint256 public constant REPLAYABLE_NONCE_KEY = 8453; 
```


*GitHub* : [43](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L43)

### [N-37]<a name="n-37"></a> Layout order does not comply with best practices

This is a [best practice](https://docs.soliditylang.org/en/latest/style-guide.html#order-of-layout) that should be followed.

Inside each contract, library or interface, use the following order:

1. Type declarations
2. State variables
3. Events
4. Errors
5. Modifiers
6. Functions

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit struct declaration `Call` after variable declaration
20: contract CoinbaseSmartWallet is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 { 
```


*GitHub* : [20](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L20-L20)

### [N-38]<a name="n-38"></a> Lines are too long

Usually lines in source code are limited to 80 characters. Today's screens are much larger so it's reasonable to stretch this in some cases. Since the files will most likely reside in GitHub, and GitHub starts using a scroll bar in all cases when the length is over 164 characters, the lines below should be split when they reach that length Reference: https://docs.soliditylang.org/en/v0.8.10/style-guide.html#maximum-line-length

*There are 18 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit 141 chars long
22: // Github code: https://github.com/rdubois-crypto/FreshCryptoLib/blob/d9bb3b0fc6b737af2c70dab246cabbc7d05afc3c/solidity/src/FCL_ecdsa.sol#L40 
/// @audit 121 chars long
170:                     let T4 := mulmod(3, mulmod(addmod(X, sub(p, zz), p), addmod(X, zz, p), p), p) //M=3*(X1-ZZ1)*(X1+ZZ1) 
/// @audit 124 chars long
213:                         //special extremely rare case accumulator where EcAdd is replaced by EcDbl, no need to optimize this 
```


*GitHub* : [22](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L22), [170](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L170), [213](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L213)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit 125 chars long
115:     /// @dev Implements encode(domainSeparator : 𝔹²⁵⁶, message : 𝕊) = "\x19\x01" || domainSeparator || hashStruct(message). 
/// @audit 121 chars long
125:     /// @notice Returns the EIP-712 `hashStruct` result of the `CoinbaseSmartWalletMessage(bytes32 hash)` data structure. 
```


*GitHub* : [115](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L115), [125](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L125)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit 132 chars long
34:     ///      Computed from: keccak256(abi.encode(uint256(keccak256("coinbase.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff)) 
```


*GitHub* : [34](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L34)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit 125 chars long
66:     ///           a well-formed assertion with the user present bit set. If `requireUV` is set, checks that the authenticator 
/// @audit 124 chars long
67:     ///           enforced user verification. User verification should be required if, and only if, options.userVerification
/// @audit 121 chars long
69:     ///         - Verifies that the client JSON is of type "webauthn.get", i.e. the client was responding to a request to 
/// @audit 126 chars long
72:     ///         - Verifies that (r, s) constitute a valid signature over both the authenicatorData and client JSON, for public 
/// @audit 126 chars long
76:     ///         - Does NOT verify that the origin in the `clientDataJSON` matches the Relying Party's origin: tt is considered 
/// @audit 125 chars long
78:     ///           enforced by most high quality authenticators properly, particularly the iCloud Keychain and Google Password 
/// @audit 128 chars long
80:     ///         - Does NOT verify That `topOrigin` in `clientDataJSON` is well-formed: We assume it would never be present, i.e. 
/// @audit 121 chars long
81:     ///           the credentials are never used in a cross-origin/iframe context. The website/app set up should disallow
/// @audit 130 chars long
82:     ///           cross-origin usage of the credentials. This is the default behaviour for created credentials in common settings.
/// @audit 133 chars long
83:     ///         - Does NOT verify that the `rpIdHash` in `authenticatorData` is the SHA-256 hash of the RP ID expected by the Relying
/// @audit 136 chars long
84:     ///           Party: this means that we rely on the authenticator to properly enforce credentials to be used only by the correct RP.
/// @audit 130 chars long
85:     ///           This is generally enforced with features like Apple App Site Association and Google Asset Links. To protect from
/// @audit 129 chars long
86:     ///           edge cases in which a previously-linked RP ID is removed from the authorised RP IDs, we recommend that messages
/// @audit 134 chars long
88:     ///         - Does NOT verify the credential backup state: this assumes the credential backup state is NOT used as part of Relying 
/// @audit 133 chars long
90:     ///         - Does NOT verify the values of the client extension outputs: this assumes that the Relying Party does not use client 
/// @audit 134 chars long
92:     ///         - Does NOT verify the signature counter: signature counters are intended to enable risk scoring for the Relying Party. 
/// @audit 134 chars long
94:     ///         - Does NOT verify the attestation object: this assumes that response.attestationObject is NOT present in the response, 
/// @audit 134 chars long
137:         // 17. If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set. 
/// @audit 130 chars long
147:         // 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash. 
```


*GitHub* : [66](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L66-L67), [69](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L69), [72](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L72), [76](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L76), [78](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L78), [80](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L80-L86), [88](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L88), [90](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L90), [92](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L92), [94](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L94), [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L137), [147](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L147)

### [N-39]<a name="n-39"></a> Long functions should be refactored into multiple, smaller, functions

Functions with too many lines are difficult to understand. It is recommended to refactor complex functions into multiple shorter and easier to understand functions.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit 57 lines long
104:     function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory webAuthnAuth, uint256 x, uint256 y) 
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L104-L104)

### [N-40]<a name="n-40"></a> Make use of Solidity's `using` keyword

The `using`-`for` [syntax](https://docs.soliditylang.org/en/latest/contracts.html#using-for) is the more common way of calling library functions.

*There are 12 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit SafeTransferLib
161:             SafeTransferLib.forceSafeTransferETH(account, withdrawable, SafeTransferLib.GAS_STIPEND_NO_STORAGE_WRITES); 
/// @audit SafeTransferLib
213:         SafeTransferLib.safeTransferETH(entryPoint(), amount); 
/// @audit SignatureCheckerLib
265:         return SignatureCheckerLib.isValidSignatureNow( 
266:             owner(), getHash(account, withdrawRequest), withdrawRequest.signature
267:         );
/// @audit SignatureCheckerLib
280:         return SignatureCheckerLib.toEthSignedMessageHash( 
281:             abi.encode(
282:                 address(this),
283:                 account,
284:                 block.chainid,
285:                 withdrawRequest.asset,
286:                 withdrawRequest.amount,
287:                 withdrawRequest.nonce,
288:                 withdrawRequest.expiry
289:             )
290:         );
/// @audit SafeTransferLib
336:             SafeTransferLib.safeTransferETH(to, amount); 
/// @audit SafeTransferLib
338:             SafeTransferLib.safeTransfer(asset, to, amount); 
```


*GitHub* : [161](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L161-L161), [213](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L213-L213), [265](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L265-L267), [280](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L280-L290), [336](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L336-L336), [338](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L338-L338)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit UserOperationLib
235:         return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint())); 
/// @audit SignatureCheckerLib
313:             return SignatureCheckerLib.isValidSignatureNow(owner, message, sigWrapper.signatureData); 
/// @audit WebAuthn
321:             return WebAuthn.verify({challenge: abi.encode(message), requireUV: false, webAuthnAuth: auth, x: x, y: y}); 
```


*GitHub* : [235](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L235-L235), [313](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L313-L313), [321](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L321-L321)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit LibClone
49:             LibClone.createDeterministicERC1967(msg.value, implementation, _getSalt(owners, nonce)); 
/// @audit LibClone
65:         predicted = LibClone.predictDeterministicAddress(initCodeHash(), _getSalt(owners, nonce), address(this)); 
/// @audit LibClone
72:         result = LibClone.initCodeHashERC1967(implementation); 
```


*GitHub* : [49](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L49-L49), [65](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L65-L65), [72](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L72-L72)

### [N-41]<a name="n-41"></a> Misplaced SPDX identifier

The SPDX identifier should be on the very first line of each source file.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

1: //curve order (number of points) 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L1)

### [N-42]<a name="n-42"></a> Missing checks for `address(0x0)` in the constructor

_

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit _owner missing zero address validation
101:     constructor(address _owner) { 
```


*GitHub* : [101](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L101-L101)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit erc4337 missing zero address validation
24:     constructor(address erc4337) payable { 
```


*GitHub* : [24](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L24-L24)

### [N-43]<a name="n-43"></a> Missing events in initializers

As a best practice, consider emitting an event when the contract is initialized. In this way, it's easy for the user to track the exact point in time when the contract was initialized, by filtering the emitted events.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

114:     function initialize(bytes[] calldata owners) public payable virtual { 
```


*GitHub* : [114](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L114-L114)

### [N-44]<a name="n-44"></a> Multiple type casts create complexity within the code

To ensure reliable and precise data handling in Solidity contracts, developers should avoid double type casting. Multiple type casts can lead to unintended consequences, such as truncation, rounding errors, or loss of precision. This compromises the contract's functionality and readability, making debugging more challenging. Instead, its crucial to use appropriate data types and minimize unnecessary type casting for a more dependable and robust contract execution.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit uint256(bytes32)
302:             if (uint256(bytes32(ownerBytes)) > type(uint160).max) { 
```


*GitHub* : [302](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L302-L302)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit uint256(bytes32)
168:             if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) { 
```


*GitHub* : [168](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L168-L168)

### [N-45]<a name="n-45"></a> NatSpec: Contract declarations should have `@author` tags

_

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

25:  
26: library FCL {
27:     //*******************************Constants*******************************************************/
```


*GitHub* : [25](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L25-L27)

### [N-46]<a name="n-46"></a> NatSpec: Contract declarations should have `@dev` tags

_

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

25:  
26: library FCL {
27:     //*******************************Constants*******************************************************/
```


*GitHub* : [25](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L25-L27)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

19: /// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol) 
20: contract CoinbaseSmartWallet is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 {
21:     /// @notice Wrapper struct, used during signature validation, tie a signature with its signer.
```


*GitHub* : [19](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L19-L21)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

12: /// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337Factory.sol) 
13: contract CoinbaseSmartWalletFactory {
14:     /// @notice Address of the ERC-4337 implementation used as implementation for new accounts.
```


*GitHub* : [12](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L12-L14)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

31: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
32: contract MultiOwnable {
33:     /// @dev Slot for the `MultiOwnableStorage` struct in storage.
```


*GitHub* : [31](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L31-L33)

### [N-47]<a name="n-47"></a> NatSpec: Contract declarations should have `@notice` tags

`@notice` is used to explain to end users what the contract does, and the compiler interprets `///` or `/**` comments as this tag if one was't explicitly provided

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

26: library FCL { 
27:     //*******************************Constants*******************************************************/
28:     // address of the ModExp precompiled contract (Arbitrary-precision exponentiation under modulo)
29:     address constant MODEXP_PRECOMPILE = 0x0000000000000000000000000000000000000005;
30:     //curve prime field modulus
31:     uint256 constant p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
32:     //short weierstrass first coefficient
```


*GitHub* : [26](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L26-L32)

### [N-48]<a name="n-48"></a> NatSpec: Contract declarations should have `@title` tags

_

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

25:  
26: library FCL {
27:     //*******************************Constants*******************************************************/
```


*GitHub* : [25](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L25-L27)

### [N-49]<a name="n-49"></a> NatSpec: Contract declarations should have NatSpec descriptions

It is recommended that Solidity libraries and contracts are fully annotated using NatSpec for all public interfaces (everything in the ABI). It is clearly stated in the Solidity official documentation. In complex projects such as DeFi, the interpretation of all functions and their arguments and returns is important for code readability and auditability.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

26: library FCL { 
27:     //*******************************Constants*******************************************************/
28:     // address of the ModExp precompiled contract (Arbitrary-precision exponentiation under modulo)
29:     address constant MODEXP_PRECOMPILE = 0x0000000000000000000000000000000000000005;
30:     //curve prime field modulus
31:     uint256 constant p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
32:     //short weierstrass first coefficient
```


*GitHub* : [26](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L26-L32)

### [N-50]<a name="n-50"></a> NatSpec: Error missing NatSpec `@dev` tag

_

*There are 12 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

55:     /// @notice Thrown when trying to use a withdraw request after its expiry has been reched. 
56:     error Expired();
57: 
60:     /// @param nonce The already used nonce. 
61:     error InvalidNonce(uint256 nonce);
62: 
67:     /// @param maxCost   The max gas cost required by the Entrypoint. 
68:     error RequestLessThanGasMaxCost(uint256 requested, uint256 maxCost);
69: 
72:     /// @param asset The requested asset. 
73:     error UnsupportedPaymasterAsset(address asset);
74: 
79:     /// @param balance         The current contract balance. 
80:     error InsufficientBalance(uint256 requestedAmount, uint256 balance);
81: 
82:     /// @notice Thrown when trying to withdraw funds but nothing is available.
83:     error NoExcess();
84: 
```


*GitHub* : [55](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L55-L57), [60](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L60-L62), [67](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L67-L69), [72](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L72-L74), [79](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L79-L84)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

45:     /// @notice Thrown when trying to re-initialize an account. 
46:     error Initialized();
47: 
```


*GitHub* : [45](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L45-L47)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

17:     /// @notice Thrown when trying to create a new `CoinbaseSmartWallet` account without any owner. 
18:     error OwnerRequired();
19: 
```


*GitHub* : [17](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L17-L19)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

39:     /// @notice Thrown when the sender is not an owner and is trying to call a privileged function. 
40:     error Unauthorized();
41: 
44:     /// @param owner The raw abi encoded owner bytes. 
45:     error AlreadyOwner(bytes owner);
46: 
49:     /// @param index The targeted index for removal. 
50:     error NoOwnerAtIndex(uint256 index);
51: 
55:     /// @param owner The invalid raw abi encoded owner bytes. 
56:     error InvalidOwnerBytesLength(bytes owner);
57: 
61:     /// @param owner The invalid raw abi encoded owner bytes. 
62:     error InvalidEthereumAddressOwner(bytes owner);
63: 
```


*GitHub* : [39](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L39-L41), [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L44-L46), [49](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L49-L51), [55](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L55-L57), [61](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L61-L63)

### [N-51]<a name="n-51"></a> NatSpec: Error missing NatSpec `@param` tag

_

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit Missing @param for `maxCost`
68:     error RequestLessThanGasMaxCost(uint256 requested, uint256 maxCost); 
/// @audit Missing @param for `requestedAmount`
80:     error InsufficientBalance(uint256 requestedAmount, uint256 balance); 
```


*GitHub* : [68](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L68-L68), [80](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L80-L80)

### [N-52]<a name="n-52"></a> NatSpec: Event missing NatSpec `@dev` tag

_

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

44:     /// @param nonce   The request nonce. 
45:     event MagicSpendWithdrawal(address indexed account, address indexed asset, uint256 amount, uint256 nonce);
46: 
```


*GitHub* : [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L44-L46)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

67:     /// @param owner The raw abi encoded owner bytes. 
68:     event AddOwner(uint256 indexed index, bytes owner);
69: 
73:     /// @param owner The raw abi encoded owner bytes. 
74:     event RemoveOwner(uint256 indexed index, bytes owner);
75: 
```


*GitHub* : [67](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L67-L69), [73](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L73-L75)

### [N-53]<a name="n-53"></a> NatSpec: File is missing NatSpec Documentation

_

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

1: //curve order (number of points) 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L1)

### [N-54]<a name="n-54"></a> NatSpec: Function declarations should have `@notice` tags

`@notice` is used to explain to end users what the function does, and the compiler interprets `///` or `/**` comments as this tag if one was't explicitly provided

*There are 6 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) { 
78:     function ecAff_isOnCurve(uint256 x, uint256 y) internal pure returns (bool) { 
274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) { 
293:     function ecAff_IsZero(uint256, uint256 y) internal pure returns (bool flag) { 
```


*GitHub* : [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L50-L50), [78](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L78-L78), [274](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L274-L274), [293](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L293-L293)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

252:     function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) { 
```


*GitHub* : [252](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L252-L252)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

121:     function _eip712Hash(bytes32 hash) internal view virtual returns (bytes32) { 
```


*GitHub* : [121](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L121-L121)

### [N-55]<a name="n-55"></a> NatSpec: Function declarations should have NatSpec descriptions

It is recommended that Solidity contracts are fully annotated using NatSpec for all public interfaces (everything in the ABI). It is clearly stated in the Solidity official documentation. In complex projects such as DeFi, the interpretation of all functions and their arguments and returns is important for code readability and auditability.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) { 
274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) { 
```


*GitHub* : [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L50-L50), [274](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L274-L274)

### [N-56]<a name="n-56"></a> NatSpec: Functions missing NatSpec `@dev` tag

_

*There are 28 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

49:  
50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) {
51:         if (r == 0 || r >= n || s == 0 || s >= n) {
93:      */ 
94:     function FCL_nModInv(uint256 u) internal view returns (uint256 result) {
95:         assembly {
273:  
274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) {
275:         uint256 zz0;
```


*GitHub* : [49](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L49-L51), [93](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L93-L95), [273](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L273-L275)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

100:     /// @param _owner The initial owner of this contract. 
101:     constructor(address _owner) {
102:         Ownable._initializeOwner(_owner);
105:     /// @notice Receive function allowing ETH to be deposited in this contract. 
106:     receive() external payable {}
107: 
108:     /// @inheritdoc IPaymaster
109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost)
110:         external
142:     /// @inheritdoc IPaymaster 
143:     function postOp(IPaymaster.PostOpMode mode, bytes calldata context, uint256 actualGasCost)
144:         external
180:     /// @param withdrawRequest The withdraw request. 
181:     function withdraw(WithdrawRequest memory withdrawRequest) external {
182:         _validateRequest(msg.sender, withdrawRequest);
298:     /// @return `true` if the nonce has already been used by the account, else `false`. 
299:     function nonceUsed(address account, uint256 nonce) external view returns (bool) {
300:         return _nonceUsed[nonce][account];
303:     /// @notice Returns the canonical ERC-4337 EntryPoint v0.6 contract. 
304:     function entryPoint() public pure returns (address) {
305:         return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
```


*GitHub* : [100](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L100-L102), [105](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L105-L110), [142](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L142-L144), [180](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L180-L182), [298](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L298-L300), [303](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L303-L305)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

101:  
102:     constructor() {
103:         // Implementation should not be initializable (does not affect proxies which use their own storage).
216:     /// @return The address of the EntryPoint v0.6 
217:     function entryPoint() public view virtual returns (address) {
218:         return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
240:     /// @return $ The address of implementation contract. 
241:     function implementation() public view returns (address $) {
242:         assembly {
251:     /// @return `true` is the function selector is whitelisted to skip the chain ID validation, else `false`. 
252:     function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
253:         if (
332:     /// @inheritdoc ERC1271 
333:     function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
334:         return ("Coinbase Smart Wallet", "1");
```


*GitHub* : [101](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L101-L103), [216](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L216-L218), [240](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L240-L242), [251](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L251-L253), [332](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L332-L334)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

23:     /// @param erc4337 The address of the ERC-4337 implementation used to deploy new cloned accounts. 
24:     constructor(address erc4337) payable {
25:         implementation = erc4337;
63:     /// @return predicted The predicted account deployment address. 
64:     function getAddress(bytes[] calldata owners, uint256 nonce) external view returns (address predicted) {
65:         predicted = LibClone.predictDeterministicAddress(initCodeHash(), _getSalt(owners, nonce), address(this));
70:     /// @return result The initialization code hash. 
71:     function initCodeHash() public view virtual returns (bytes32 result) {
72:         result = LibClone.initCodeHashERC1967(implementation);
80:     /// @return salt The computed salt. 
81:     function _getSalt(bytes[] calldata owners, uint256 nonce) internal pure returns (bytes32 salt) {
82:         salt = keccak256(abi.encode(owners, nonce));
```


*GitHub* : [23](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L23-L25), [63](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L63-L65), [70](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L70-L72), [80](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L80-L82)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

120:     /// @return The resulting EIP-712 hash. 
121:     function _eip712Hash(bytes32 hash) internal view virtual returns (bytes32) {
122:         return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), _hashStruct(hash)));
```


*GitHub* : [120](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L120-L122)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

84:     /// @param owner The owner address. 
85:     function addOwnerAddress(address owner) public virtual onlyOwner {
86:         _addOwner(abi.encode(owner));
92:     /// @param y The owner public key y coordinate. 
93:     function addOwnerPublicKey(bytes32 x, bytes32 y) public virtual onlyOwner {
94:         _addOwner(abi.encode(x, y));
116:     /// @return `true` if the account is an owner, else `false`. 
117:     function isOwnerAddress(address account) public view virtual returns (bool) {
118:         return _getMultiOwnableStorage().isOwner[abi.encode(account)];
126:     /// @return `true` if the account is an owner, else `false`. 
127:     function isOwnerPublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) {
128:         return _getMultiOwnableStorage().isOwner[abi.encode(x, y)];
135:     /// @return `true` if the account is an owner, else `false`. 
136:     function isOwnerBytes(bytes memory account) public view virtual returns (bool) {
137:         return _getMultiOwnableStorage().isOwner[account];
144:     /// @return The owner bytes (empty if no owner is registered at this `index`). 
145:     function ownerAtIndex(uint256 index) public view virtual returns (bytes memory) {
146:         return _getMultiOwnableStorage().ownerAtIndex[index];
151:     /// @return The next index that will be used to add a new owner. 
152:     function nextOwnerIndex() public view virtual returns (uint256) {
153:         return _getMultiOwnableStorage().nextOwnerIndex;
178:     /// @param owner The owner raw bytes to add. 
179:     function _addOwner(bytes memory owner) internal virtual {
180:         _addOwnerAtIndex(owner, _getMultiOwnableStorage().nextOwnerIndex++);
211:     /// @return $ A storage reference to the `MultiOwnableStorage` struct. 
212:     function _getMultiOwnableStorage() internal pure returns (MultiOwnableStorage storage $) {
213:         assembly ("memory-safe") {
```


*GitHub* : [84](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L84-L86), [92](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L92-L94), [116](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L116-L118), [126](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L126-L128), [135](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L135-L137), [144](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L144-L146), [151](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L151-L153), [178](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L178-L180), [211](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L211-L213)

### [N-57]<a name="n-57"></a> NatSpec: Functions missing NatSpec `@param` tag

It is recommended that Solidity contracts are fully annotated using NatSpec for all public interfaces (everything in the ABI). It is clearly stated in the Solidity official documentation. In complex projects such as DeFi, the interpretation of all functions and their arguments and returns is important for code readability and auditability.

*There are 20 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit Missing @param for all function parameters
50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) { 
/// @audit Missing @param for all function parameters
78:     function ecAff_isOnCurve(uint256 x, uint256 y) internal pure returns (bool) { 
/// @audit Missing @param for all function parameters
94:     function FCL_nModInv(uint256 u) internal view returns (uint256 result) { 
/// @audit Missing @param for all function parameters
117:     function ecZZ_mulmuladd_S_asm( 
118:         uint256 Q0,
119:         uint256 Q1, //affine rep for input point Q
120:         uint256 scalar_u,
121:         uint256 scalar_v
122:     ) internal view returns (uint256 X) {
/// @audit Missing @param for all function parameters
274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) { 
/// @audit Missing @param for all function parameters
293:     function ecAff_IsZero(uint256, uint256 y) internal pure returns (bool flag) { 
/// @audit Missing @param for all function parameters
301:     function ecZZ_SetAff(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
302:         internal
303:         view
304:         returns (uint256 x1, uint256 y1)
305:     {
/// @audit Missing @param for all function parameters
318:     function ecZZ_Dbl(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
319:         internal
320:         pure
321:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
322:     {
/// @audit Missing @param for all function parameters
344:     function ecZZ_AddN(uint256 x1, uint256 y1, uint256 zz1, uint256 zzz1, uint256 x2, uint256 y2) 
345:         internal
346:         pure
347:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
348:     {
/// @audit Missing @param for all function parameters
374:     function FCL_pModInv(uint256 u) internal view returns (uint256 result) { 
```


*GitHub* : [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L50-L50), [78](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L78-L78), [94](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L94-L94), [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L117-L122), [274](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L274-L274), [293](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L293-L293), [301](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L301-L305), [318](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L318-L322), [344](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L344-L348), [374](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L374-L374)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit Missing @param for all function parameters
181:     function withdraw(WithdrawRequest memory withdrawRequest) external { 
/// @audit Missing @param for `unstakeDelaySeconds`
232:     function entryPointAddStake(uint256 amount, uint32 unstakeDelaySeconds) external payable onlyOwner { 
/// @audit Missing @param for `withdrawRequest`
260:     function isValidWithdrawSignature(address account, WithdrawRequest memory withdrawRequest) 
261:         public
262:         view
263:         returns (bool)
264:     {
/// @audit Missing @param for `withdrawRequest`
279:     function getHash(address account, WithdrawRequest memory withdrawRequest) public view returns (bytes32) { 
/// @audit Missing @param for `withdrawRequest`
315:     function _validateRequest(address account, WithdrawRequest memory withdrawRequest) internal { 
```


*GitHub* : [181](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L181-L181), [232](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L232-L232), [260](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L260-L264), [279](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L279-L279), [315](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L315-L315)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit Missing @param for all function parameters
137:     function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
138:         public
139:         payable
140:         virtual
141:         onlyEntryPoint
142:         payPrefund(missingAccountFunds)
143:         returns (uint256 validationData)
144:     {
/// @audit Missing @param for all function parameters
229:     function getUserOpHashWithoutChainId(UserOperation calldata userOp) 
230:         public
231:         view
232:         virtual
233:         returns (bytes32 userOpHash)
234:     {
/// @audit Missing @param for all function parameters
252:     function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) { 
```


*GitHub* : [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L137-L144), [229](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L229-L234), [252](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L252-L252)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit Missing @param for all function parameters
121:     function _eip712Hash(bytes32 hash) internal view virtual returns (bytes32) { 
```


*GitHub* : [121](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L121-L121)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit Missing @param for `requireUV`, `webAuthnAuth`
104:     function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory webAuthnAuth, uint256 x, uint256 y) 
105:         internal
106:         view
107:         returns (bool)
108:     {
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L104-L108)

### [N-58]<a name="n-58"></a> NatSpec: Functions missing NatSpec `@return` tag

It is recommended that Solidity contracts are fully annotated using NatSpec for all public interfaces (everything in the ABI). It is clearly stated in the Solidity official documentation. In complex projects such as DeFi, the interpretation of all functions and their arguments and returns is important for code readability and auditability.

*There are 18 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit Missing @return for all function parameters
50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) { 
/// @audit Missing @return for all function parameters
78:     function ecAff_isOnCurve(uint256 x, uint256 y) internal pure returns (bool) { 
/// @audit Missing @return for all function parameters
94:     function FCL_nModInv(uint256 u) internal view returns (uint256 result) { 
/// @audit Missing @return for all function parameters
117:     function ecZZ_mulmuladd_S_asm( 
118:         uint256 Q0,
119:         uint256 Q1, //affine rep for input point Q
120:         uint256 scalar_u,
121:         uint256 scalar_v
122:     ) internal view returns (uint256 X) {
/// @audit Missing @return for all function parameters
274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) { 
/// @audit Missing @return for all function parameters
293:     function ecAff_IsZero(uint256, uint256 y) internal pure returns (bool flag) { 
/// @audit Missing @return for all function parameters
301:     function ecZZ_SetAff(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
302:         internal
303:         view
304:         returns (uint256 x1, uint256 y1)
305:     {
/// @audit Missing @return for all function parameters
318:     function ecZZ_Dbl(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
319:         internal
320:         pure
321:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
322:     {
/// @audit Missing @return for all function parameters
344:     function ecZZ_AddN(uint256 x1, uint256 y1, uint256 zz1, uint256 zzz1, uint256 x2, uint256 y2) 
345:         internal
346:         pure
347:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
348:     {
/// @audit Missing @return for all function parameters
374:     function FCL_pModInv(uint256 u) internal view returns (uint256 result) { 
```


*GitHub* : [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L50-L50), [78](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L78-L78), [94](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L94-L94), [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L117-L122), [274](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L274-L274), [293](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L293-L293), [301](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L301-L305), [318](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L318-L322), [344](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L344-L348), [374](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L374-L374)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit Missing @return for all function parameters
109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost) 
110:         external
111:         onlyEntryPoint
112:         returns (bytes memory context, uint256 validationData)
113:     {
/// @audit Missing @return for all function parameters
304:     function entryPoint() public pure returns (address) { 
```


*GitHub* : [109](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L109-L113), [304](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L304-L304)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit Missing @return for all function parameters
137:     function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
138:         public
139:         payable
140:         virtual
141:         onlyEntryPoint
142:         payPrefund(missingAccountFunds)
143:         returns (uint256 validationData)
144:     {
/// @audit Missing @return for all function parameters
229:     function getUserOpHashWithoutChainId(UserOperation calldata userOp) 
230:         public
231:         view
232:         virtual
233:         returns (bytes32 userOpHash)
234:     {
/// @audit Missing @return for all function parameters
291:     function _validateSignature(bytes32 message, bytes calldata signature) 
292:         internal
293:         view
294:         virtual
295:         override
296:         returns (bool)
297:     {
/// @audit Missing @return for all function parameters
333:     function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) { 
```


*GitHub* : [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L137-L144), [229](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L229-L234), [291](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L291-L297), [333](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L333-L333)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit Missing @return for all function parameters
38:     function createAccount(bytes[] calldata owners, uint256 nonce) 
39:         public
40:         payable
41:         virtual
42:         returns (CoinbaseSmartWallet account)
43:     {
```


*GitHub* : [38](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L38-L43)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit Missing @return for `chainId`, `verifyingContract`
36:     function eip712Domain() 
37:         external
38:         view
39:         virtual
40:         returns (
41:             bytes1 fields,
42:             string memory name,
43:             string memory version,
44:             uint256 chainId,
45:             address verifyingContract,
46:             bytes32 salt,
47:             uint256[] memory extensions
48:         )
49:     {
```


*GitHub* : [36](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L36-L49)

### [N-59]<a name="n-59"></a> NatSpec: Modifier missing NatSpec `@dev` tag

_

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

64:     /// @notice Reverts if the caller is not the EntryPoint. 
65:     modifier onlyEntryPoint() virtual {
66:         if (msg.sender != entryPoint()) {
73:     /// @notice Reverts if the caller is neither the EntryPoint, the owner, nor the account itself. 
74:     modifier onlyEntryPointOrOwner() virtual {
75:         if (msg.sender != entryPoint()) {
```


*GitHub* : [64](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L64-L66), [73](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L73-L75)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

76:     /// @notice Access control modifier ensuring the caller is an authorized owner 
77:     modifier onlyOwner() virtual {
78:         _checkOwner();
```


*GitHub* : [76](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L76-L78)

### [N-60]<a name="n-60"></a> NatSpec: Modifier missing NatSpec `@param` tag

It is recommended that Solidity contracts are fully annotated using NatSpec for all public interfaces (everything in the ABI). It is clearly stated in the Solidity official documentation. In complex projects such as DeFi, the interpretation of all functions and their arguments and returns is important for code readability and auditability.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit Missing @param for all modifier parameters
91:     modifier payPrefund(uint256 missingAccountFunds) virtual { 
```


*GitHub* : [91](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L91-L91)

### [N-61]<a name="n-61"></a> Natspec: Use `@inheritdoc` rather than using a non-standard tags

Using non-standard annotations like `@dev see Ellipsis` can lead to inconsistencies and lack of clarity in your smart contract documentation. It's recommended to use the `@inheritdoc` annotation for enhanced clarity and uniformity in smart contract development.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

11: /// @title Magic Spend 
12: ///
13: /// @author Coinbase (https://github.com/coinbase/magic-spend)
14: ///
15: /// @notice ERC4337 Paymaster implementation compatible with Entrypoint v0.6.
```


*GitHub* : [11](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L11-L15)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

125:     /// @notice Returns the EIP-712 `hashStruct` result of the `CoinbaseSmartWalletMessage(bytes32 hash)` data structure. 
126:     ///
127:     /// @dev Implements hashStruct(s : 𝕊) = keccak256(typeHash || encodeData(s)).
128:     /// @dev See https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct.
```


*GitHub* : [125](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L125-L128)

### [N-62]<a name="n-62"></a> Non-`external`/`public` function names should begin with an underscore

According to the Solidity Style Guide, Non-`external`/`public` function names should begin with an <a href="https://docs.soliditylang.org/en/latest/style-guide.html#underscore-prefix-for-non-external-functions-and-variables">underscore</a>.

*There are 11 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit _ecdsa_verify
50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) { 
51:         if (r == 0 || r >= n || s == 0 || s >= n) {
52:             return false;
53:         }
54: 
55:         if (!ecAff_isOnCurve(Qx, Qy)) {
56:             return false;
57:         }
58: 
59:         uint256 sInv = FCL_nModInv(s);
60: 
61:         uint256 scalar_u = mulmod(uint256(message), sInv, n);
62:         uint256 scalar_v = mulmod(r, sInv, n);
63:         uint256 x1;
64: 
65:         x1 = ecZZ_mulmuladd_S_asm(Qx, Qy, scalar_u, scalar_v);
66: 
67:         x1 = addmod(x1, n - r, n);
68: 
69:         return x1 == 0;
70:     }
/// @audit _ecAff_isOnCurve
78:     function ecAff_isOnCurve(uint256 x, uint256 y) internal pure returns (bool) { 
79:         if (((0 == x) && (0 == y)) || x == p || y == p) {
80:             return false;
81:         }
82:         unchecked {
83:             uint256 LHS = mulmod(y, y, p); // y^2
84:             uint256 RHS = addmod(mulmod(mulmod(x, x, p), x, p), mulmod(x, a, p), p); // x^3+ax
85:             RHS = addmod(RHS, b, p); // x^3 + a*x + b
86: 
87:             return LHS == RHS;
88:         }
89:     }
/// @audit _FCL_nModInv
94:     function FCL_nModInv(uint256 u) internal view returns (uint256 result) { 
95:         assembly {
96:             let pointer := mload(0x40)
97:             // Define length of base, exponent and modulus. 0x20 == 32 bytes
98:             mstore(pointer, 0x20)
99:             mstore(add(pointer, 0x20), 0x20)
100:             mstore(add(pointer, 0x40), 0x20)
101:             // Define variables base, exponent and modulus
102:             mstore(add(pointer, 0x60), u)
103:             mstore(add(pointer, 0x80), minus_2modn)
104:             mstore(add(pointer, 0xa0), n)
105: 
106:             // Call the precompiled contract 0x05 = ModExp
107:             if iszero(staticcall(not(0), 0x05, pointer, 0xc0, pointer, 0x20)) { revert(0, 0) }
108:             result := mload(pointer)
109:         }
110:     }
/// @audit _ecZZ_mulmuladd_S_asm
117:     function ecZZ_mulmuladd_S_asm( 
118:         uint256 Q0,
119:         uint256 Q1, //affine rep for input point Q
120:         uint256 scalar_u,
121:         uint256 scalar_v
122:     ) internal view returns (uint256 X) {
123:         uint256 zz;
124:         uint256 zzz;
125:         uint256 Y;
126:         uint256 index = 255;
127:         uint256 H0;
128:         uint256 H1;
129: 
130:         unchecked {
131:             if (scalar_u == 0 && scalar_v == 0) return 0;
132: 
133:             (H0, H1) = ecAff_add(gx, gy, Q0, Q1);
134:             if (
135:                 (H0 == 0) && (H1 == 0) //handling Q=-G
136:             ) {
137:                 scalar_u = addmod(scalar_u, n - scalar_v, n);
138:                 scalar_v = 0;
139:             }
140:             assembly {
141:                 for { let T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1)) } eq(T4, 0) {
142:                     index := sub(index, 1)
143:                     T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
144:                 } {}
145:                 zz := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
146: 
147:                 if eq(zz, 1) {
148:                     X := gx
149:                     Y := gy
150:                 }
151:                 if eq(zz, 2) {
152:                     X := Q0
153:                     Y := Q1
154:                 }
155:                 if eq(zz, 3) {
156:                     X := H0
157:                     Y := H1
158:                 }
159: 
160:                 index := sub(index, 1)
161:                 zz := 1
162:                 zzz := 1
163: 
164:                 for {} gt(minus_1, index) { index := sub(index, 1) } {
165:                     // inlined EcZZ_Dbl
166:                     let T1 := mulmod(2, Y, p) //U = 2*Y1, y free
167:                     let T2 := mulmod(T1, T1, p) // V=U^2
168:                     let T3 := mulmod(X, T2, p) // S = X1*V
169:                     T1 := mulmod(T1, T2, p) // W=UV
170:                     let T4 := mulmod(3, mulmod(addmod(X, sub(p, zz), p), addmod(X, zz, p), p), p) //M=3*(X1-ZZ1)*(X1+ZZ1)
171:                     zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
172:                     zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
173: 
174:                     X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
175:                     T2 := mulmod(T4, addmod(X, sub(p, T3), p), p) //-M(S-X3)=M(X3-S)
176:                     Y := addmod(mulmod(T1, Y, p), T2, p) //-Y3= W*Y1-M(S-X3), we replace Y by -Y to avoid a sub in ecAdd
177: 
178:                     {
179:                         //value of dibit
180:                         T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
181: 
182:                         if iszero(T4) {
183:                             Y := sub(p, Y) //restore the -Y inversion
184:                             continue
185:                         } // if T4!=0
186: 
187:                         if eq(T4, 1) {
188:                             T1 := gx
189:                             T2 := gy
190:                         }
191:                         if eq(T4, 2) {
192:                             T1 := Q0
193:                             T2 := Q1
194:                         }
195:                         if eq(T4, 3) {
196:                             T1 := H0
197:                             T2 := H1
198:                         }
199:                         if iszero(zz) {
200:                             X := T1
201:                             Y := T2
202:                             zz := 1
203:                             zzz := 1
204:                             continue
205:                         }
206:                         // inlined EcZZ_AddN
207: 
208:                         //T3:=sub(p, Y)
209:                         //T3:=Y
210:                         let y2 := addmod(mulmod(T2, zzz, p), Y, p) //R
211:                         T2 := addmod(mulmod(T1, zz, p), sub(p, X), p) //P
212: 
213:                         //special extremely rare case accumulator where EcAdd is replaced by EcDbl, no need to optimize this
214:                         //todo : construct edge vector case
215:                         if iszero(y2) {
216:                             if iszero(T2) {
217:                                 T1 := mulmod(minus_2, Y, p) //U = 2*Y1, y free
218:                                 T2 := mulmod(T1, T1, p) // V=U^2
219:                                 T3 := mulmod(X, T2, p) // S = X1*V
220: 
221:                                 T1 := mulmod(T1, T2, p) // W=UV
222:                                 y2 := mulmod(addmod(X, zz, p), addmod(X, sub(p, zz), p), p) //(X-ZZ)(X+ZZ)
223:                                 T4 := mulmod(3, y2, p) //M=3*(X-ZZ)(X+ZZ)
224: 
225:                                 zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
226:                                 zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
227: 
228:                                 X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
229:                                 T2 := mulmod(T4, addmod(T3, sub(p, X), p), p) //M(S-X3)
230: 
231:                                 Y := addmod(T2, mulmod(T1, Y, p), p) //Y3= M(S-X3)-W*Y1
232: 
233:                                 continue
234:                             }
235:                         }
236: 
237:                         T4 := mulmod(T2, T2, p) //PP
238:                         let TT1 := mulmod(T4, T2, p) //PPP, this one could be spared, but adding this register spare gas
239:                         zz := mulmod(zz, T4, p)
240:                         zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1
241:                         let TT2 := mulmod(X, T4, p)
242:                         T4 := addmod(addmod(mulmod(y2, y2, p), sub(p, TT1), p), mulmod(minus_2, TT2, p), p)
243:                         Y := addmod(mulmod(addmod(TT2, sub(p, T4), p), y2, p), mulmod(Y, TT1, p), p)
244: 
245:                         X := T4
246:                     }
247:                 } //end loop
248:                 let T := mload(0x40)
249:                 mstore(add(T, 0x60), zz)
250:                 //(X,Y)=ecZZ_SetAff(X,Y,zz, zzz);
251:                 //T[0] = inverseModp_Hard(T[0], p); //1/zzz, inline modular inversion using precompile:
252:                 // Define length of base, exponent and modulus. 0x20 == 32 bytes
253:                 mstore(T, 0x20)
254:                 mstore(add(T, 0x20), 0x20)
255:                 mstore(add(T, 0x40), 0x20)
256:                 // Define variables base, exponent and modulus
257:                 //mstore(add(pointer, 0x60), u)
258:                 mstore(add(T, 0x80), minus_2)
259:                 mstore(add(T, 0xa0), p)
260: 
261:                 // Call the precompiled contract 0x05 = ModExp
262:                 if iszero(staticcall(not(0), 0x05, T, 0xc0, T, 0x20)) { revert(0, 0) }
263: 
264:                 //Y:=mulmod(Y,zzz,p)//Y/zzz
265:                 //zz :=mulmod(zz, mload(T),p) //1/z
266:                 //zz:= mulmod(zz,zz,p) //1/zz
267:                 X := mulmod(X, mload(T), p) //X/zz
268:             } //end assembly
269:         } //end unchecked
270: 
271:         return X;
272:     }
/// @audit _ecAff_add
274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) { 
275:         uint256 zz0;
276:         uint256 zzz0;
277: 
278:         if (ecAff_IsZero(x0, y0)) return (x1, y1);
279:         if (ecAff_IsZero(x1, y1)) return (x0, y0);
280:         if ((x0 == x1) && (y0 == y1)) {
281:             (x0, y0, zz0, zzz0) = ecZZ_Dbl(x0, y0, 1, 1);
282:         } else {
283:             (x0, y0, zz0, zzz0) = ecZZ_AddN(x0, y0, 1, 1, x1, y1);
284:         }
285: 
286:         return ecZZ_SetAff(x0, y0, zz0, zzz0);
287:     }
/// @audit _ecAff_IsZero
293:     function ecAff_IsZero(uint256, uint256 y) internal pure returns (bool flag) { 
294:         return (y == 0);
295:     }
/// @audit _ecZZ_SetAff
301:     function ecZZ_SetAff(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
302:         internal
303:         view
304:         returns (uint256 x1, uint256 y1)
305:     {
306:         uint256 zzzInv = FCL_pModInv(zzz); //1/zzz
307:         y1 = mulmod(y, zzzInv, p); //Y/zzz
308:         uint256 _b = mulmod(zz, zzzInv, p); //1/z
309:         zzzInv = mulmod(_b, _b, p); //1/zz
310:         x1 = mulmod(x, zzzInv, p); //X/zz
311:     }
/// @audit _ecZZ_Dbl
318:     function ecZZ_Dbl(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
319:         internal
320:         pure
321:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
322:     {
323:         unchecked {
324:             assembly {
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
335:             }
336:         }
337:         return (P0, P1, P2, P3);
338:     }
/// @audit _ecZZ_AddN
344:     function ecZZ_AddN(uint256 x1, uint256 y1, uint256 zz1, uint256 zzz1, uint256 x2, uint256 y2) 
345:         internal
346:         pure
347:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
348:     {
349:         unchecked {
350:             if (y1 == 0) {
351:                 return (x2, y2, 1, 1);
352:             }
353: 
354:             assembly {
355:                 y1 := sub(p, y1)
356:                 y2 := addmod(mulmod(y2, zzz1, p), y1, p)
357:                 x2 := addmod(mulmod(x2, zz1, p), sub(p, x1), p)
358:                 P0 := mulmod(x2, x2, p) //PP = P^2
359:                 P1 := mulmod(P0, x2, p) //PPP = P*PP
360:                 P2 := mulmod(zz1, P0, p) ////ZZ3 = ZZ1*PP
361:                 P3 := mulmod(zzz1, P1, p) ////ZZZ3 = ZZZ1*PPP
362:                 zz1 := mulmod(x1, P0, p) //Q = X1*PP
363:                 P0 := addmod(addmod(mulmod(y2, y2, p), sub(p, P1), p), mulmod(minus_2, zz1, p), p) //R^2-PPP-2*Q
364:                 P1 := addmod(mulmod(addmod(zz1, sub(p, P0), p), y2, p), mulmod(y1, P1, p), p) //R*(Q-X3)
365:             }
366:             //end assembly
367:         } //end unchecked
368:         return (P0, P1, P2, P3);
369:     }
/// @audit _FCL_pModInv
374:     function FCL_pModInv(uint256 u) internal view returns (uint256 result) { 
375:         assembly {
376:             let pointer := mload(0x40)
377:             // Define length of base, exponent and modulus. 0x20 == 32 bytes
378:             mstore(pointer, 0x20)
379:             mstore(add(pointer, 0x20), 0x20)
380:             mstore(add(pointer, 0x40), 0x20)
381:             // Define variables base, exponent and modulus
382:             mstore(add(pointer, 0x60), u)
383:             mstore(add(pointer, 0x80), minus_2)
384:             mstore(add(pointer, 0xa0), p)
385: 
386:             // Call the precompiled contract 0x05 = ModExp
387:             if iszero(staticcall(not(0), 0x05, pointer, 0xc0, pointer, 0x20)) { revert(0, 0) }
388:             result := mload(pointer)
389:         }
390:     }
```


*GitHub* : [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L50-L70), [78](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L78-L89), [94](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L94-L110), [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L117-L272), [274](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L274-L287), [293](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L293-L295), [301](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L301-L311), [318](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L318-L338), [344](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L344-L369), [374](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L374-L390)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit _verify
104:     function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory webAuthnAuth, uint256 x, uint256 y) 
105:         internal
106:         view
107:         returns (bool)
108:     {
109:         if (webAuthnAuth.s > P256_N_DIV_2) {
110:             // guard against signature malleability
111:             return false;
112:         }
113: 
114:         // 11. Verify that the value of C.type is the string webauthn.get.
115:         // bytes("type":"webauthn.get").length = 21
116:         string memory _type = webAuthnAuth.clientDataJSON.slice(webAuthnAuth.typeIndex, webAuthnAuth.typeIndex + 21);
117:         if (keccak256(bytes(_type)) != EXPECTED_TYPE_HASH) {
118:             return false;
119:         }
120: 
121:         // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
122:         bytes memory expectedChallenge = bytes(string.concat('"challenge":"', Base64.encodeURL(challenge), '"'));
123:         string memory actualChallenge = webAuthnAuth.clientDataJSON.slice(
124:             webAuthnAuth.challengeIndex, webAuthnAuth.challengeIndex + expectedChallenge.length
125:         );
126:         if (keccak256(bytes(actualChallenge)) != keccak256(expectedChallenge)) {
127:             return false;
128:         }
129: 
130:         // Skip 13., 14., 15.
131: 
132:         // 16. Verify that the UP bit of the flags in authData is set.
133:         if (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UP != AUTH_DATA_FLAGS_UP) {
134:             return false;
135:         }
136: 
137:         // 17. If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set.
138:         if (requireUV && (webAuthnAuth.authenticatorData[32] & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV) {
139:             return false;
140:         }
141: 
142:         // skip 18.
143: 
144:         // 19. Let hash be the result of computing a hash over the cData using SHA-256.
145:         bytes32 clientDataJSONHash = sha256(bytes(webAuthnAuth.clientDataJSON));
146: 
147:         // 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
148:         bytes32 messageHash = sha256(abi.encodePacked(webAuthnAuth.authenticatorData, clientDataJSONHash));
149:         bytes memory args = abi.encode(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);
150:         // try the RIP-7212 precompile address
151:         (bool success, bytes memory ret) = VERIFIER.staticcall(args);
152:         // staticcall will not revert if address has no code
153:         // check return length
154:         // note that even if precompile exists, ret.length is 0 when verification returns false
155:         // so an invalid signature will be checked twice: once by the precompile and once by FCL.
156:         // Ideally this signature failure is simulated offchain and no one actually pay this gas.
157:         bool valid = ret.length > 0;
158:         if (success && valid) return abi.decode(ret, (uint256)) == 1;
159: 
160:         return FCL.ecdsa_verify(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);
161:     }
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L104-L161)

### [N-63]<a name="n-63"></a> Non-library/interface files should use fixed compiler versions, not floating ones

To prevent the actual contracts being deployed from behaving differently depending on the compiler version, it is recommended to use fixed solidity versions for contracts and libraries.

Although we can configure a specific version through config (like hardhat, forge config files), it is recommended to **set the fixed version in the solidity pragma directly** before deploying to the mainnet.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L2)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L2)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L2)

### [N-64]<a name="n-64"></a> Not using the latest versions of project dependencies

Update the project dependencies to their latest versions wherever possible.

Use tools such as `retire.js`, `npm audit`, and `yarn audit` to confirm that no vulnerable dependencies remain.

|Dependency|Current Version|Latest Version|
|:-:|:-:|:-:|
|`forge-std`|1.7.6|1.8.0|
|`solady`|0.0.177|0.0.168|


*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L1)

### [N-65]<a name="n-65"></a> Not using the named return variables anywhere in the function is confusing

Declaring named returns, but not using them, is confusing to the reader. Consider either completely removing them (by declaring just the type without a name), or remove the return statement and do a variable assignment.

This would improve the readability of the code, and it may also help reduce regressions during future code refactors.

If the optimizer is not turned on, leaving the code as it is will also waste gas for the stack variable.

*There are 6 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit flag is unused
293:     function ecAff_IsZero(uint256, uint256 y) internal pure returns (bool flag) { 
294:         return (y == 0);
295:     }
```


*GitHub* : [293](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L293-L295)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit validationData is unused
137:     function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
138:         public
139:         payable
140:         virtual
141:         onlyEntryPoint
142:         payPrefund(missingAccountFunds)
143:         returns (uint256 validationData)
144:     {
145:         uint256 key = userOp.nonce >> 64;
146: 
147:         // 0xbf6ba1fc = bytes4(keccak256("executeWithoutChainIdValidation(bytes)"))
148:         if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) {
149:             userOpHash = getUserOpHashWithoutChainId(userOp);
150:             if (key != REPLAYABLE_NONCE_KEY) {
151:                 revert InvalidNonceKey(key);
152:             }
153:         } else {
154:             if (key == REPLAYABLE_NONCE_KEY) {
155:                 revert InvalidNonceKey(key);
156:             }
157:         }
158: 
159:         // Return 0 if the recovered address matches the owner.
160:         if (_validateSignature(userOpHash, userOp.signature)) {
161:             return 0;
162:         }
163: 
164:         // Else return 1, which is equivalent to:
165:         // `(uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)`
166:         // where `validUntil` is 0 (indefinite) and `validAfter` is 0.
167:         return 1;
168:     }
/// @audit userOpHash is unused
229:     function getUserOpHashWithoutChainId(UserOperation calldata userOp) 
230:         public
231:         view
232:         virtual
233:         returns (bytes32 userOpHash)
234:     {
235:         return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
236:     }
```


*GitHub* : [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L137-L168), [229](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L229-L236)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit result is unused
69:     function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4 result) { 
70:         if (_validateSignature({message: replaySafeHash(hash), signature: signature})) {
71:             // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
72:             return 0x1626ba7e;
73:         }
74: 
75:         return 0xffffffff;
76:     }
/// @audit name is unused
/// @audit version is unused
143:     function _domainNameAndVersion() internal view virtual returns (string memory name, string memory version); 
```


*GitHub* : [69](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L69-L76), [143](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L143-L143)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit $ is unused
212:     function _getMultiOwnableStorage() internal pure returns (MultiOwnableStorage storage $) { 
213:         assembly ("memory-safe") {
214:             $.slot := MUTLI_OWNABLE_STORAGE_LOCATION
215:         }
216:     }
```


*GitHub* : [212](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L212-L216)

### [N-66]<a name="n-66"></a> Outdated Solidity version

Upgrade to the latest solidity version.

<a href="https://blog.soliditylang.org/2021/04/21/solidity-0.8.4-release-announcement/">0.8.4</a>: bytes.concat() instead of abi.encodePacked(<bytes>,<bytes>) 
<a href="https://blog.soliditylang.org/2022/02/16/solidity-0.8.12-release-announcement/">0.8.12</a>: string.concat() instead of abi.encodePacked(<str>,<str>) 
<a href="https://blog.soliditylang.org/2022/03/16/solidity-0.8.13-release-announcement/">0.8.13</a>:
- Ability to use using for with a list of free functions

<a href="https://blog.soliditylang.org/2022/05/18/solidity-0.8.14-release-announcement/">0.8.14</a>:
- ABI Encoder: When ABI-encoding values from calldata that contain nested arrays, correctly validate the nested array length against calldatasize() in all cases.
- Override Checker: Allow changing data location for parameters only when overriding external functions.

<a href="https://blog.soliditylang.org/2022/06/15/solidity-0.8.15-release-announcement/">0.8.15</a>:
- Code Generation: Avoid writing dirty bytes to storage when copying bytes arrays.
- Yul Optimizer: Keep all memory side-effects of inline assembly blocks.

<a href="https://blog.soliditylang.org/2022/08/08/solidity-0.8.16-release-announcement/">0.8.16</a>:
 - Code Generation: Fix data corruption that affected ABI-encoding of calldata values represented by tuples: structs at any nesting level; argument lists of external functions, events and errors; return value lists of external functions. The 32 leading bytes of the first dynamically-encoded value in the tuple would get zeroed when the last component contained a statically-encoded array.

<a href="https://blog.soliditylang.org/2022/09/08/solidity-0.8.17-release-announcement/">0.8.17</a>:
 - Yul Optimizer: Prevent the incorrect removal of storage writes before calls to Yul functions that conditionally terminate the external EVM call.

<a href="https://blog.soliditylang.org/2023/02/22/solidity-0.8.19-release-announcement/">0.8.19</a>:
- SMTChecker: New trusted mode that assumes that any compile-time available code is the actual used code, even in external calls.

Bug Fixes:
- Assembler: Avoid duplicating subassembly bytecode where possible.
- Code Generator: Avoid including references to the deployed label of referenced functions if they are called right away.
- ContractLevelChecker: Properly distinguish the case of missing base constructor arguments from having an unimplemented base function.
- SMTChecker: Fix internal error caused by unhandled z3 expressions that come from the solver when bitwise operators are used.
- SMTChecker: Fix internal error when using the custom NatSpec annotation to abstract free functions.
- TypeChecker: Also allow external library functions in using for.

<a href="https://blog.soliditylang.org/2023/05/10/solidity-0.8.20-release-announcement/">0.8.20</a>:
- Assembler: Use push0 for placing 0 on the stack for EVM versions starting from “Shanghai”. This decreases the deployment and runtime costs.
- Optimizer: Re-implement simplified version of UnusedAssignEliminator and UnusedStoreEliminator. It can correctly remove some unused assignments in deeply nested loops that were ignored by the old version.
- Parser: Unary plus is no longer recognized as a unary operator in the AST and triggers an error at the parsing stage (rather than later during the analysis).
- SMTChecker: Group all messages about unsupported language features in a single warning. The CLI option --model-checker-show-unsupported and the JSON option settings.modelChecker.showUnsupported can be enabled to show the full list.
- SMTChecker: Properties that are proved safe are now reported explicitly at the end of analysis. By default, only the number of safe properties is shown. The CLI option --model-checker-show-proved-safe and the JSON option settings.modelChecker.showProvedSafe can be enabled to show the full list of safe properties.
- Standard JSON Interface: Add experimental support for importing ASTs via Standard JSON.
- Yul EVM Code Transform: If available, use push0 instead of codesize to produce an arbitrary value on stack in order to create equal stack heights between branches.

<a href="https://soliditylang.org/blog/2023/07/19/solidity-0.8.21-release-announcement">0.8.21</a>:
- Code Generator: Always generate code for the expression in `<expression>.selector` in the legacy code generation pipeline.
- Yul Optimizer: Fix FullInliner step (i) not preserving the evaluation order of arguments passed into inlined functions in code that is not in expression-split form.
- Allow qualified access to events from other contracts.
- Relax restrictions on initialization of immutable variables. Reads and writes may now happen at any point at construction time outside of functions and modifiers. Explicit initialization is no longer mandatory.


*There are 7 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

24: pragma solidity >=0.8.19 <0.9.0; 
```


*GitHub* : [24](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L24)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

2: pragma solidity 0.8.23; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L2)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

2: pragma solidity 0.8.23; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L2)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L2)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L2)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L2)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

2: pragma solidity ^0.8.0; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L2)

### [N-67]<a name="n-67"></a> Parameter change does not emit event

Events help non-contract tools to track changes

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

85:     function addOwnerAddress(address owner) public virtual onlyOwner { 
86:         _addOwner(abi.encode(owner));
87:     }
179:     function _addOwner(bytes memory owner) internal virtual { 
180:         _addOwnerAtIndex(owner, _getMultiOwnableStorage().nextOwnerIndex++);
181:     }
```


*GitHub* : [85](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L85-L87), [179](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L179-L181)

### [N-68]<a name="n-68"></a> Prefer skip over revert model in iteration

It is preferable to skip operations on an array index when a condition is not met rather than reverting the whole transaction as reverting can introduce the possiblity of malicous actors purposefully introducing array objects which fail conditional checks within for/while loops so group operations fail. As such it is recommended to simply skip such array indices over reverting unless there is a valid security or logic reason behind not doing so.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit reverts on line: 165, 169
163:         for (uint256 i; i < owners.length; i++) { 
```


*GitHub* : [163](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L163-L163)

### [N-69]<a name="n-69"></a> `public` functions not called by the contract should be declared `external` instead

Contracts are allowed to override their parents’ functions and change the visibility from public to external.

*There are 13 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

114:     function initialize(bytes[] calldata owners) public payable virtual { 
137:     function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
180:     function executeWithoutChainIdValidation(bytes calldata data) public payable virtual onlyEntryPoint { 
196:     function execute(address target, uint256 value, bytes calldata data) public payable virtual onlyEntryPointOrOwner { 
205:     function executeBatch(Call[] calldata calls) public payable virtual onlyEntryPointOrOwner { 
241:     function implementation() public view returns (address $) { 
```


*GitHub* : [114](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L114), [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L137), [180](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L180), [196](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L196), [205](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L205), [241](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L241)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

38:     function createAccount(bytes[] calldata owners, uint256 nonce) 
```


*GitHub* : [38](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L38)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

69:     function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4 result) { 
```


*GitHub* : [69](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L69)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

85:     function addOwnerAddress(address owner) public virtual onlyOwner { 
93:     function addOwnerPublicKey(bytes32 x, bytes32 y) public virtual onlyOwner { 
102:     function removeOwnerAtIndex(uint256 index) public virtual onlyOwner { 
127:     function isOwnerPublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) { 
152:     function nextOwnerIndex() public view virtual returns (uint256) { 
```


*GitHub* : [85](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L85), [93](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L93), [102](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L102), [127](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L127), [152](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L152)

### [N-70]<a name="n-70"></a> `receive()`/`payable fallback()` function does not authorize requests

If the intention is for the Ether to be used, the function should call another function, otherwise it should revert (e.g. `require(msg.sender == address(weth))`). Having no access control on the function means that someone may send Ether to the contract, and have no way to get anything back out, which is a loss of funds. If the concern is having to spend a small amount of gas to check the sender against an immutable address, the code should at least have a function to rescue unused Ether.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

106:     receive() external payable {} 
```


*GitHub* : [106](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L106-L106)

### [N-71]<a name="n-71"></a> Returning a struct instead of a bunch of variables is better

If a function returns [too many variables](https://docs.soliditylang.org/en/v0.8.21/contracts.html#returning-multiple-values), replacing them with a struct can improve code readability, maintainability and reusability.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

318:     function ecZZ_Dbl(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
319:         internal
320:         pure
321:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
322:     {
344:     function ecZZ_AddN(uint256 x1, uint256 y1, uint256 zz1, uint256 zzz1, uint256 x2, uint256 y2) 
345:         internal
346:         pure
347:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
348:     {
```


*GitHub* : [318](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L318-L322), [344](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L344-L348)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

36:     function eip712Domain() 
37:         external
38:         view
39:         virtual
40:         returns (
41:             bytes1 fields,
42:             string memory name,
43:             string memory version,
44:             uint256 chainId,
45:             address verifyingContract,
46:             bytes32 salt,
47:             uint256[] memory extensions
48:         )
49:     {
```


*GitHub* : [36](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L36-L49)

### [N-72]<a name="n-72"></a> Some variables have a implicit default visibility

Consider always adding an explicit visibility modifier for variables, as the default is `internal`.

*There are 9 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

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


*GitHub* : [29](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L29), [31](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L31), [33](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L33), [35](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L35), [37](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L37-L38), [40](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L40), [42](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L42), [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L44), [46](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L46)

### [N-73]<a name="n-73"></a> State variables should include comments

Consider adding some comments on critical state variables to explain what they are supposed to do: this will help for future code reviews.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

38:     uint256 constant gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5; 
46:     uint256 constant minus_1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF; 
```


*GitHub* : [38](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L38-L38), [46](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L46-L46)

### [N-74]<a name="n-74"></a> Top-level declarations should be separated by at least two lines

_

*There are 9 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

26: library FCL { 
27:     //*******************************Constants*******************************************************/
28:     // address of the ModExp precompiled contract (Arbitrary-precision exponentiation under modulo)
29:     address constant MODEXP_PRECOMPILE = 0x0000000000000000000000000000000000000005;
272:     } 
273: 
274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) {
```


*GitHub* : [26](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L26-L29), [272](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L272-L274)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

18: contract MagicSpend is Ownable, IPaymaster { 
19:     /// @notice Signed withdraw request allowing accounts to withdraw funds from this contract.
20:     struct WithdrawRequest {
340:     } 
```


*GitHub* : [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L18-L20), [340](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L340-L34)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

20: contract CoinbaseSmartWallet is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 { 
21:     /// @notice Wrapper struct, used during signature validation, tie a signature with its signer.
22:     struct SignatureWrapper {
```


*GitHub* : [20](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L20-L22)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

13: contract CoinbaseSmartWalletFactory { 
14:     /// @notice Address of the ERC-4337 implementation used as implementation for new accounts.
15:     address public immutable implementation;
```


*GitHub* : [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L13-L15)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

16: abstract contract ERC1271 { 
17:     /// @dev Precomputed `typeHash` used to produce EIP-712 compliant hash when applying the anti
18:     ///      cross-account-replay layer.
19:     ///
20:     ///      The original hash must either be:
21:     ///         - An EIP-191 hash: keccak256("\x19Ethereum Signed Message:\n" || len(someMessage) || someMessage)
22:     ///         - An EIP-712 hash: keccak256("\x19\x01" || someDomainSeparator || hashStruct(someStruct))
23:     bytes32 private constant _MESSAGE_TYPEHASH = keccak256("CoinbaseSmartWalletMessage(bytes32 hash)");
```


*GitHub* : [16](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L16-L23)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

32: contract MultiOwnable { 
33:     /// @dev Slot for the `MultiOwnableStorage` struct in storage.
34:     ///      Computed from: keccak256(abi.encode(uint256(keccak256("coinbase.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
35:     ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
36:     bytes32 private constant MUTLI_OWNABLE_STORAGE_LOCATION =
```


*GitHub* : [32](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L32-L36)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

18: library WebAuthn { 
19:     using LibString for string;
20: 
21:     struct WebAuthnAuth {
```


*GitHub* : [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L18-L21)

### [N-75]<a name="n-75"></a> Typos

_

*There are 89 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit ecdsa -> sades
15: ///* DESCRIPTION: ecdsa verification implementation 
/// @audit Github -> GitHub
22: // Github code: https://github.com/rdubois-crypto/FreshCryptoLib/blob/d9bb3b0fc6b737af2c70dab246cabbc7d05afc3c/solidity/src/FCL_ecdsa.sol#L40 
/// @audit precompiled -> recompiled
28:     // address of the ModExp precompiled contract (Arbitrary-precision exponentiation under modulo) 
/// @audit weierstrass -> Weierstrass
32:     //short weierstrass first coefficient 
/// @audit weierstrass -> Weierstrass
34:     //short weierstrass second coefficient 
/// @audit precompiled -> recompiled
106:             // Call the precompiled contract 0x05 = ModExp 
/// @audit inlined -> unlined
165:                     // inlined EcZZ_Dbl 
/// @audit dibit -> debit
179:                         //value of dibit 
/// @audit inlined -> unlined
206:                         // inlined EcZZ_AddN 
/// @audit todo -> too
214:                         //todo : construct edge vector case 
/// @audit precompiled -> recompiled
261:                 // Call the precompiled contract 0x05 = ModExp 
/// @audit zz -> z
265:                 //zz :=mulmod(zz, mload(T),p) //1/z 
/// @audit precompiled -> recompiled
386:             // Call the precompiled contract 0x05 = ModExp 
```


*GitHub* : [15](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L15), [22](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L22), [28](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L28), [32](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L32), [34](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L34), [106](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L106), [165](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L165), [179](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L179), [206](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L206), [214](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L214), [261](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L261), [265](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L265), [386](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L386)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit Coinbase -> Coin base
13: /// @author Coinbase (https://github.com/coinbase/magic-spend) 
/// @audit Entrypoint -> Entry point
15: /// @notice ERC4337 Paymaster implementation compatible with Entrypoint v0.6. 
/// @audit reched -> retied
55:     /// @notice Thrown when trying to use a withdraw request after its expiry has been reched. 
/// @audit withraw -> withdraw
/// @audit reques -> request
63:     /// @notice Thrown during validation in the context of ERC4337, when the withraw reques amount is insufficient 
/// @audit Entrypoint -> Entry point
67:     /// @param maxCost   The max gas cost required by the Entrypoint. 
/// @audit  exluding -> exuding
76:     ///         requested amount (exluding the `maxGasCost` set by the Entrypoint). 
/// @audit withdrwable -> withdrawal
87:     /// @dev This should only really occur if for unknown reasons the transfer of the withdrwable 
/// @audit withdrawable -> withdraw able
137:         // NOTE: Do not include the gas part in withdrawable funds as it will be handled in `postOp()`. 
/// @audit accout -> account
154:         // Compute the total remaining funds available for the user accout. 
/// @audit consummed -> consumed
155:         // NOTE: Take into account the user operation gas that was not consummed.
/// @audit accout -> account
158:         // Send the all remaining funds to the user accout. 
/// @audit Entrypoint -> Entry point
211:     /// @param amount The amount to deposit on the the Entrypoint. 
/// @audit Entrypoint -> Entry point
221:     /// @param amount The amount to withdraw from the Entrypoint. 
/// @audit Entrypoint -> Entry point
230:     /// @param amount              The amount to stake in the Entrypoint. 
```


*GitHub* : [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L13), [15](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L15), [55](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L55), [63](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L63-L63), [67](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L67), [76](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L76), [87](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L87), [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L137), [154](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L154-L155), [158](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L158), [211](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L211), [221](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L221), [230](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L230)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit Coinbase -> Coin base
13: /// @title Coinbase Smart Wallet 
/// @audit Solady -> So lady
15: /// @notice ERC4337-compatible smart contract wallet, based on Solady ERC4337 account implementation 
/// @audit Alchemys -> Alchemy
/// @audit Daimos -> Deimos
16: ///         with inspiration from Alchemy's LightAccount and Daimo's DaimoAccount.
/// @audit Coinbase -> Coin base
18: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
/// @audit Solady -> So lady
19: /// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol)
/// @audit struct -> strict
21:     /// @notice Wrapper struct, used during signature validation, tie a signature with its signer. 
/// @audit indentifying -> identifying
23:         /// @dev The index indentifying owner (see MultiOwnable) who signed. 
/// @audit struct -> strict
25:         /// @dev An ABI encoded ECDSA signature (r, s, v) or WebAuthnAuth struct. 
/// @audit struct -> strict
29:     /// @notice Wrapper struct, used in `executeBatch`, describing a raw call to execute. 
/// @audit replayable -> repayable
39:     /// @notice Reserved nonce key (upper 192 bits of `UserOperation.nonce`) for cross-chain replayable 
/// @audit replayable -> repayable
42:     /// @dev Helps enforce sequential sequencing of replayable transactions. 
/// @audit initializable -> initialization
103:         // Implementation should not be initializable (does not affect proxies which use their own storage). 
/// @audit implemenentation -> implementation
122:     /// @notice Custom implemenentation of the ERC-4337 `validateUserOp` method. The EntryPoint will 
/// @audit mentionned -> mentioned
130:     /// @dev Reverts if the signature verification fails (except for the case mentionned earlier). 
/// @audit Entrypoint -> Entry point
134:     /// @param missingAccountFunds The missing account funds that must be deposited on the Entrypoint. 
/// @audit Entrypoint -> Entry point
172:     /// @dev Can only be called by the Entrypoint. 
/// @audit validtion -> validation
173:     /// @dev Reverts if the given call is not authorized to skip the chain ID validtion.
/// @audit befor -> before
/// @audit validatin -> validation
174:     /// @dev `validateUserOp()` will recompute the `userOpHash` without the chain ID befor validatin
/// @audit Entrypoint -> Entry point
191:     /// @dev Can only be called by the Entrypoint or an owner of this account (including itself). 
/// @audit Entrypoint -> Entry point
202:     /// @dev Can only be called by the Entrypoint or an owner of this account (including itself). 
/// @audit Impl -> Imp
267:     /// @dev Impl taken from https://github.com/alchemyplatform/light-account/blob/main/src/LightAccount.sol#L347 
/// @audit abi -> ab
285:     /// @dev Reverts if the signature does not correspond to an ERC-1271 signature or to the abi 
/// @audit struct -> strict
286:     ///      encoded version of a `WebAuthnAuth` struct.
/// @audit abi -> ab
/// @audit struct -> strict
290:     /// @param signature The abi encoded `SignatureWrapper` struct. 
/// @audit incase -> encase
304:                 // addOwnerAddress and addOwnerPublicKey, but we leave incase of future changes. 
```


*GitHub* : [15](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L15-L16), [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L13), [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L18-L19), [21](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L21), [23](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L23), [25](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L25), [29](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L29), [39](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L39), [42](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L42), [103](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L103), [122](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L122), [130](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L130), [134](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L134), [172](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L172-L174), [191](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L191), [202](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L202), [267](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L267), [285](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L285-L286), [290](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L290-L290), [304](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L304)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit Coinbase -> Coin base
7: /// @title Coinbase Smart Wallet Factory 
/// @audit Soladys -> Gladys
9: /// @notice CoinbaseSmartWallet factory, based on Solady's ERC4337Factory. 
/// @audit Coinbase -> Coin base
11: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
/// @audit Solady -> So lady
12: /// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337Factory.sol)
/// @audit Webauthn -> Autobahn
33:     ///      scheme used (respectively ERC-1271 or Webauthn authentication). 
```


*GitHub* : [7](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L7), [9](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L9), [11](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L11-L12), [33](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L33)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit samer -> maser
9: /// @dev To prevent the same signature from being validated on different accounts owned by the samer signer, 
/// @audit Coinbase -> Coin base
14: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
/// @audit Solady -> So lady
15: /// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC1271.sol)
/// @audit Precomputed -> Recomputed
17:     /// @dev Precomputed `typeHash` used to produce EIP-712 compliant hash when applying the anti 
/// @audit fron -> from
78:     /// @notice Wrapper around `_eip712Hash()` to produce a replay-safe hash fron the given `hash`. 
/// @audit usecase -> use case
149:     ///      of the implementation to decode `signature` depending on its usecase. 
```


*GitHub* : [9](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L9), [14](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L14-L15), [17](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L17), [78](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L78), [149](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L149)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit idenfitied -> identified
10:     /// @dev Mapping of indices to raw owner bytes, used to idenfitied owners by their 
/// @audit calldata -> call data
14:     ///      requires the caller to assert which owner signed. To economize calldata, 
/// @audit abi -> ab
19:     ///         - An abi encoded ethereum address 
/// @audit abi -> ab
20:     ///         - The abi encoded public key (x, y) coordinates when using passkey.
/// @audit booleans -> boolean
22:     /// @dev Mapping of raw bytes accounts to booleans indicating whether or not the 
/// @audit Ownable -> Own able
27: /// @title Multi Ownable 
/// @audit Coinbase -> Coin base
31: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
/// @audit abi -> ab
44:     /// @param owner The raw abi encoded owner bytes. 
/// @audit intialize -> initialize
52:     /// @notice Thrown when trying to intialize the contracts owners if a provided owner is neither 
/// @audit abi -> ab
55:     /// @param owner The invalid raw abi encoded owner bytes. 
/// @audit intialize -> initialize
58:     /// @notice Thrown when trying to intialize the contracts owners if a provided owner is 32 bytes 
/// @audit abi -> ab
61:     /// @param owner The invalid raw abi encoded owner bytes. 
/// @audit abi -> ab
67:     /// @param owner The raw abi encoded owner bytes. 
/// @audit abi -> ab
73:     /// @param owner The raw abi encoded owner bytes. 
/// @audit intiial -> initial
161:     /// @param owners The intiial list of owners to register. 
/// @audit fo -> few
200:     /// @dev Revert if the sender is not an owner fo the contract itself. 
/// @audit struct -> strict
209:     /// @notice Helper function to get a storage reference to the `MultiOwnableStorage` struct. 
/// @audit struct -> strict
211:     /// @return $ A storage reference to the `MultiOwnableStorage` struct. 
```


*GitHub* : [10](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L10), [14](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L14), [19](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L19-L20), [22](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L22), [27](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L27), [31](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L31), [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L44), [52](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L52), [55](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L55), [58](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L58), [61](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L61), [67](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L67), [73](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L73), [161](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L161), [200](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L200), [209](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L209), [211](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L211)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit Daimo -> Daimler
11: ///         of Daimo. 
/// @audit precompile -> recompile
13: /// @dev Attempts to use the RIP-7212 precompile for signature verification. 
/// @audit precompile -> recompile
14: ///      If precompile verification fails, it falls back to FreshCryptoLib.
/// @audit Coinbase -> Coin base
16: /// @author Coinbase (https://github.com/base-org/webauthn-sol) 
/// @audit Daimo -> Daimler
17: /// @author Daimo (https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol)
/// @audit authenticator -> authentication
22:         /// @dev The WebAuthn authenticator data. 
/// @audit authenticator -> authentication
/// @audit struct -> strict
38:     /// @dev Bit 0 of the authenticator data struct, corresponding to the "User Present" bit. 
/// @audit authenticator -> authentication
/// @audit struct -> strict
42:     /// @dev Bit 2 of the authenticator data struct, corresponding to the "User Verified" bit. 
/// @audit precompiled -> recompiled
49:     /// @dev The precompiled contract address to use for signature verification in the “secp256r1” elliptic curve. 
/// @audit Webauthn -> Autobahn
58:     /// @notice Verifies a Webauthn Authentication Assertion as described 
/// @audit authenticator -> authentication
65:     ///         - Verify that authenticatorData (which comes from the authenticator, such as iCloud Keychain) indicates 
/// @audit authenticator -> authentication
66:     ///           a well-formed assertion with the user present bit set. If `requireUV` is set, checks that the authenticator
/// @audit verifier -> versifier
75:     ///      We make some assumptions about the particular use case of this verifier, so we do NOT verify the following: 
/// @audit Partys -> Party
/// @audit tt -> rt
76:     ///         - Does NOT verify that the origin in the `clientDataJSON` matches the Relying Party's origin: tt is considered
/// @audit authenticators -> authentication
77:     ///           the authenticator's responsibility to ensure that the user is interacting with the correct RP. This is
/// @audit authenticators -> authentication
/// @audit Keychain -> Key chain
78:     ///           enforced by most high quality authenticators properly, particularly the iCloud Keychain and Google Password
/// @audit behaviour -> behavior
82:     ///           cross-origin usage of the credentials. This is the default behaviour for created credentials in common settings. 
/// @audit authenticator -> authentication
84:     ///           Party: this means that we rely on the authenticator to properly enforce credentials to be used only by the correct RP. 
/// @audit authorised -> authorized
86:     ///           edge cases in which a previously-linked RP ID is removed from the authorised RP IDs, we recommend that messages 
/// @audit authenticator -> authentication
87:     ///           signed by the authenticator include some expiry mechanism.
/// @audit struct -> strict
99:     /// @param webAuthnAuth The `WebAuthnAuth` struct. 
/// @audit precompile -> recompile
150:         // try the RIP-7212 precompile address 
/// @audit staticcall -> static call
152:         // staticcall will not revert if address has no code 
/// @audit precompile -> recompile
154:         // note that even if precompile exists, ret.length is 0 when verification returns false 
/// @audit precompile -> recompile
155:         // so an invalid signature will be checked twice: once by the precompile and once by FCL.
/// @audit offchain -> off chain
156:         // Ideally this signature failure is simulated offchain and no one actually pay this gas.
```


*GitHub* : [11](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L11), [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L13-L14), [16](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L16-L17), [22](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L22), [38](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L38-L38), [42](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L42-L42), [49](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L49), [58](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L58), [65](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L65-L66), [75](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L75-L78), [82](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L82), [84](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L84), [86](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L86-L87), [99](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L99), [150](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L150), [152](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L152), [154](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L154-L156)

### [N-76]<a name="n-76"></a> Unnecessary struct attribute prefix

Attributes within a struct are redundantly prefixed, which is unnecessary as they are inherently associated with the struct. Consider simplifying the attribute names by removing the redundant prefix.

By removing the repetitive prefix, the code maintains its contextual clarity while becoming more concise and easy to read.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit signatureData
22:     struct SignatureWrapper { 
23:         /// @dev The index indentifying owner (see MultiOwnable) who signed.
24:         uint256 ownerIndex;
25:         /// @dev An ABI encoded ECDSA signature (r, s, v) or WebAuthnAuth struct.
26:         bytes signatureData;
27:     }
```


*GitHub* : [22](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L22-L27)

### [N-77]<a name="n-77"></a> Unspecific compiler version pragma

Some files use `>=`, some use `^`. The instances below are examples of the method that has the fewest instances for a specific version. Note that using `>=` without also specifying `<=` will lead to failures to compile, or external project incompatability, when the major version changes and there are breaking-changes, so `^` should be preferred regardless of the instance counts

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

24: pragma solidity >=0.8.19 <0.9.0; 
```


*GitHub* : [24](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L24)

### [N-78]<a name="n-78"></a> Unused `error` definition

The following errors are never used, consider to remove them.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

90:     error UnexpectedPostOpRevertedMode(); 
```


*GitHub* : [90](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L90-L90)

### [N-79]<a name="n-79"></a> Upgradeable contract not initialized

Upgradeable contracts are initialized via an initializer function rather than by a constructor. Leaving such a contract uninitialized may lead to it being taken over by a malicious user.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit __UUPS_init();
20: contract CoinbaseSmartWallet is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 { 
```


*GitHub* : [20](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L20-L20)

### [N-80]<a name="n-80"></a> Use a single file for system wide constants

Consider grouping all the system constants under a single file. This finding shows only the first constant for each file, for brevity.

*There are 17 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

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


*GitHub* : [29](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L29-L29), [31](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L31-L31), [33](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L33-L33), [35](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L35-L35), [37](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L37-L38), [40](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L40-L40), [42](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L42-L42), [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L44-L44), [46](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L46-L46)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

43:     uint256 public constant REPLAYABLE_NONCE_KEY = 8453; 
```


*GitHub* : [43](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L43-L43)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

23:     bytes32 private constant _MESSAGE_TYPEHASH = keccak256("CoinbaseSmartWalletMessage(bytes32 hash)"); 
```


*GitHub* : [23](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L23-L23)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

36:     bytes32 private constant MUTLI_OWNABLE_STORAGE_LOCATION = 
37:         0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;
```


*GitHub* : [36](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L36-L37)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

40:     bytes1 private constant AUTH_DATA_FLAGS_UP = 0x01; 
44:     bytes1 private constant AUTH_DATA_FLAGS_UV = 0x04; 
47:     uint256 private constant P256_N_DIV_2 = FCL.n / 2; 
51:     address private constant VERIFIER = address(0x100); 
55:     bytes32 private constant EXPECTED_TYPE_HASH = keccak256('"type":"webauthn.get"'); 
```


*GitHub* : [40](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L40-L40), [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L44-L44), [47](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L47-L47), [51](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L51-L51), [55](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L55-L55)

### [N-81]<a name="n-81"></a> Use a struct to encapsulate multiple function parameters

If a function has too many parameters, replacing them with a struct can improve code readability and maintainability, increase reusability, and reduce the likelihood of errors when passing the parameters.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) { 
344:     function ecZZ_AddN(uint256 x1, uint256 y1, uint256 zz1, uint256 zzz1, uint256 x2, uint256 y2) 
345:         internal
346:         pure
347:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
348:     {
```


*GitHub* : [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L50-L50), [344](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L344-L348)

### [N-82]<a name="n-82"></a> Use `bytes.concat()` on bytes instead of `abi.encodePacked()` for clearer semantic meaning

Starting with version 0.8.4, Solidity has the `bytes.concat()` function, which allows one to concatenate a list of bytes/strings, without extra padding. Using this function rather than `abi.encodePacked()` makes the intended operation more clear, leading to less reviewer confusion.

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/ERC1271.sol

122:         return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), _hashStruct(hash))); 
```


*GitHub* : [122](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L122-L122)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

148:         bytes32 messageHash = sha256(abi.encodePacked(webAuthnAuth.authenticatorData, clientDataJSONHash)); 
```


*GitHub* : [148](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L148-L148)

### [N-83]<a name="n-83"></a> Use EIP-5627 to describe EIP-712 domains

EIP-5267 is a standard which allows for the retrieval and description of EIP-712 hash domains. This enable external tools to allow users to view the fields and values that describe their domain.

This is especially useful when a project may exist on multiple chains and or in multiple contracts, and allows users/tools to verify that the signature is for the right fork, chain, version, contract, etc.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/ERC1271.sol

104:                 keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"), 
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L104)

### [N-84]<a name="n-84"></a> Use of `override` is unnecessary

Starting with Solidity version [0.8.8](https://docs.soliditylang.org/en/v0.8.20/contracts.html#function-overriding), using the override keyword when the function solely overrides an interface function, and the function doesn't exist in multiple base contracts, is unnecessary.

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

291:     function _validateSignature(bytes32 message, bytes calldata signature) 
292:         internal
293:         view
294:         virtual
295:         override
296:         returns (bool)
297:     {
330:     function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {} 
333:     function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) { 
```


*GitHub* : [291](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L291-L297), [330](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L330-L330), [333](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L333-L333)

### [N-85]<a name="n-85"></a> Use UPPER_CASE for `constant`

Constants should be in CONSTANT_CASE as stated [Solidity style guide](https://docs.soliditylang.org/en/latest/style-guide.html#constants).

*There are 8 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

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


*GitHub* : [31](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L31-L31), [33](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L33-L33), [35](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L35-L35), [37](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L37-L38), [40](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L40-L40), [42](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L42-L42), [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L44-L44), [46](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L46-L46)

### [N-86]<a name="n-86"></a> Use UPPER_CASE for `immutable`

Immutables should be in uppercase as stated [Solidity style guide](https://docs.soliditylang.org/en/latest/style-guide.html#constants).

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

15:     address public immutable implementation; 
```


*GitHub* : [15](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L15-L15)

### [N-87]<a name="n-87"></a> Variables should be named in mixedCase style

As the [Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html#naming-styles) suggests: arguments, local variables and mutable state variables should be named in mixedCase style.

Rule exceptions
- Allow constant variable name/symbol/decimals to be lowercase (ERC20).
- Allow `_` at the beginning of the mixedCase match for `private variables` and `unused parameters`.

*There are 15 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit Qx
/// @audit Qy
50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) { 
/// @audit scalar_u
61:         uint256 scalar_u = mulmod(uint256(message), sInv, n); 
/// @audit scalar_v
62:         uint256 scalar_v = mulmod(r, sInv, n);
/// @audit LHS
83:             uint256 LHS = mulmod(y, y, p); // y^2 
/// @audit RHS
84:             uint256 RHS = addmod(mulmod(mulmod(x, x, p), x, p), mulmod(x, a, p), p); // x^3+ax
/// @audit Q0
118:         uint256 Q0, 
/// @audit Q1
119:         uint256 Q1, //affine rep for input point Q
/// @audit scalar_u
120:         uint256 scalar_u,
/// @audit scalar_v
121:         uint256 scalar_v
/// @audit X
122:     ) internal view returns (uint256 X) {
/// @audit Y
125:         uint256 Y; 
/// @audit H0
127:         uint256 H0; 
/// @audit H1
128:         uint256 H1;
/// @audit P0
/// @audit P1
/// @audit P2
/// @audit P3
321:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3) 
/// @audit P0
/// @audit P1
/// @audit P2
/// @audit P3
347:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3) 
```


*GitHub* : [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L50-L50), [61](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L61-L62), [83](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L83-L84), [118](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L118-L122), [125](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L125-L125), [127](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L127-L128), [321](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L321-L321), [347](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L347-L347)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit _withdrawableETH
34:     mapping(address user => uint256 amount) internal _withdrawableETH; 
/// @audit _owner
101:     constructor(address _owner) { 
```


*GitHub* : [34](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L34-L34), [101](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L101-L101)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit $
241:     function implementation() public view returns (address $) { 
```


*GitHub* : [241](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L241-L241)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit $
212:     function _getMultiOwnableStorage() internal pure returns (MultiOwnableStorage storage $) { 
```


*GitHub* : [212](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L212-L212)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit clientDataJSON
27:         string clientDataJSON; 
/// @audit requireUV
104:     function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory webAuthnAuth, uint256 x, uint256 y) 
/// @audit clientDataJSONHash
145:         bytes32 clientDataJSONHash = sha256(bytes(webAuthnAuth.clientDataJSON)); 
```


*GitHub* : [27](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L27-L27), [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L104-L104), [145](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L145-L145)

### [N-88]<a name="n-88"></a> Zero as a function argument should have a descriptive meaning

Consider using descriptive constants or an enum instead of passing zero directly on function calls, as that might be error-prone, to fully describe the caller's intention.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

186:         _call(address(this), 0, data); 
```


*GitHub* : [186](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L186-L186)

### Disputed Risk Issues

### [D-01]<a name="d-01"></a> File allows a version of solidity that is susceptible to `.selector`-related optimizer bug

File uses a version of solidity that is susceptible to `.selector`-related optimizer bug, but does not use `.selector`.

*There are 6 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

24: pragma solidity >=0.8.19 <0.9.0; 
```


*GitHub* : [24](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L24-L24)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

2: pragma solidity 0.8.23; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L2-L2)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L2-L2)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L2-L2)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

2: pragma solidity ^0.8.4; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L2-L2)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

2: pragma solidity ^0.8.0; 
```


*GitHub* : [2](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L2-L2)

### [D-02]<a name="d-02"></a> Functions contain the same code

The rule is valid, but the following findings are invalid.

*There are 16 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

293:     function ecAff_IsZero(uint256, uint256 y) internal pure returns (bool flag) { 
294:         return (y == 0);
295:     }
```


*GitHub* : [293](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L293-L295)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

260:     function isValidWithdrawSignature(address account, WithdrawRequest memory withdrawRequest) 
261:         public
262:         view
263:         returns (bool)
264:     {
265:         return SignatureCheckerLib.isValidSignatureNow(
266:             owner(), getHash(account, withdrawRequest), withdrawRequest.signature
267:         );
268:     }
279:     function getHash(address account, WithdrawRequest memory withdrawRequest) public view returns (bytes32) { 
280:         return SignatureCheckerLib.toEthSignedMessageHash(
281:             abi.encode(
282:                 address(this),
283:                 account,
284:                 block.chainid,
285:                 withdrawRequest.asset,
286:                 withdrawRequest.amount,
287:                 withdrawRequest.nonce,
288:                 withdrawRequest.expiry
289:             )
290:         );
291:     }
299:     function nonceUsed(address account, uint256 nonce) external view returns (bool) { 
300:         return _nonceUsed[nonce][account];
301:     }
304:     function entryPoint() public pure returns (address) { 
305:         return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
306:     }
```


*GitHub* : [260](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L260-L268), [279](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L279-L291), [299](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L299-L301), [304](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L304-L306)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

217:     function entryPoint() public view virtual returns (address) { 
218:         return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
219:     }
229:     function getUserOpHashWithoutChainId(UserOperation calldata userOp) 
230:         public
231:         view
232:         virtual
233:         returns (bytes32 userOpHash)
234:     {
235:         return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
236:     }
333:     function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) { 
334:         return ("Coinbase Smart Wallet", "1");
335:     }
```


*GitHub* : [217](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L217-L219), [229](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L229-L236), [333](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L333-L335)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

90:     function replaySafeHash(bytes32 hash) public view virtual returns (bytes32) { 
91:         return _eip712Hash(hash);
92:     }
121:     function _eip712Hash(bytes32 hash) internal view virtual returns (bytes32) { 
122:         return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), _hashStruct(hash)));
123:     }
133:     function _hashStruct(bytes32 hash) internal view virtual returns (bytes32) { 
134:         return keccak256(abi.encode(_MESSAGE_TYPEHASH, hash));
135:     }
```


*GitHub* : [90](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L90-L92), [121](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L121-L123), [133](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L133-L135)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

117:     function isOwnerAddress(address account) public view virtual returns (bool) { 
118:         return _getMultiOwnableStorage().isOwner[abi.encode(account)];
119:     }
127:     function isOwnerPublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) { 
128:         return _getMultiOwnableStorage().isOwner[abi.encode(x, y)];
129:     }
136:     function isOwnerBytes(bytes memory account) public view virtual returns (bool) { 
137:         return _getMultiOwnableStorage().isOwner[account];
138:     }
145:     function ownerAtIndex(uint256 index) public view virtual returns (bytes memory) { 
146:         return _getMultiOwnableStorage().ownerAtIndex[index];
147:     }
152:     function nextOwnerIndex() public view virtual returns (uint256) { 
153:         return _getMultiOwnableStorage().nextOwnerIndex;
154:     }
```


*GitHub* : [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L117-L119), [127](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L127-L129), [136](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L136-L138), [145](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L145-L147), [152](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L152-L154)

### [D-03]<a name="d-03"></a> Inline `modifier`s that are only used once, to save gas

Inlining modifiers does not save gas

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

91:     modifier payPrefund(uint256 missingAccountFunds) virtual { 
92:         _;
93: 
94:         assembly ("memory-safe") {
95:             if missingAccountFunds {
96:                 // Ignore failure (it's EntryPoint's job to verify, not the account's).
97:                 pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
98:             }
99:         }
100:     }
```


*GitHub* : [91](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L91-L100)

### [D-04]<a name="d-04"></a> State variable read in a loop

These references to the variable cannot be cached, or that are 'constant' / 'immutable'

*There are 14 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

169:                     T1 := mulmod(T1, T2, p) // W=UV 
171:                     zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1 
172:                     zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
174:                     X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S 
175:                     T2 := mulmod(T4, addmod(X, sub(p, T3), p), p) //-M(S-X3)=M(X3-S)
176:                     Y := addmod(mulmod(T1, Y, p), T2, p) //-Y3= W*Y1-M(S-X3), we replace Y by -Y to avoid a sub in ecAdd
183:                             Y := sub(p, Y) //restore the -Y inversion 
188:                             T1 := gx 
189:                             T2 := gy
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
239:                         zz := mulmod(zz, T4, p) 
240:                         zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1
242:                         T4 := addmod(addmod(mulmod(y2, y2, p), sub(p, TT1), p), mulmod(minus_2, TT2, p), p) 
243:                         Y := addmod(mulmod(addmod(TT2, sub(p, T4), p), y2, p), mulmod(Y, TT1, p), p)
```


*GitHub* : [169](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L169-L169), [171](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L171-L172), [174](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L174-L176), [183](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L183-L183), [188](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L188-L189), [211](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L211-L211), [217](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L217-L219), [221](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L221-L223), [225](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L225-L226), [228](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L228-L229), [231](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L231-L231), [237](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L237-L237), [239](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L239-L240), [242](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L242-L243)

### [D-05]<a name="d-05"></a> `++i` costs less gas than `i++`, especially when it's used in for-loops (`--i`/`i--` too)

Changing to a pre-increment for the examples below will break the code

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

172:             _addOwnerAtIndex(owners[i], _getMultiOwnableStorage().nextOwnerIndex++); 
180:         _addOwnerAtIndex(owner, _getMultiOwnableStorage().nextOwnerIndex++); 
```


*GitHub* : [172](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L172-L172), [180](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L180-L180)

### [D-06]<a name="d-06"></a> All interfaces used within a project should be imported

These contracts don't rely on other contracts for their definitions, so there's nothing to import

*There are 5 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

26: library FCL { 
```


*GitHub* : [26](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L26)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

13: contract CoinbaseSmartWalletFactory { 
```


*GitHub* : [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L13)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

16: abstract contract ERC1271 { 
```


*GitHub* : [16](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L16)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

32: contract MultiOwnable { 
```


*GitHub* : [32](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L32)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

18: library WebAuthn { 
```


*GitHub* : [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L18)

### [D-07]<a name="d-07"></a> Array lengths not checked

These instances only have one array

*There are 6 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

114:     function initialize(bytes[] calldata owners) public payable virtual { 
205:     function executeBatch(Call[] calldata calls) public payable virtual onlyEntryPointOrOwner { 
```


*GitHub* : [114](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L114-L114), [205](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L205-L205)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

38:     function createAccount(bytes[] calldata owners, uint256 nonce) 
39:         public
40:         payable
41:         virtual
42:         returns (CoinbaseSmartWallet account)
43:     {
64:     function getAddress(bytes[] calldata owners, uint256 nonce) external view returns (address predicted) { 
81:     function _getSalt(bytes[] calldata owners, uint256 nonce) internal pure returns (bytes32 salt) { 
```


*GitHub* : [38](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L38-L43), [64](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L64-L64), [81](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L81-L81)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

162:     function _initializeOwners(bytes[] memory owners) internal virtual { 
```


*GitHub* : [162](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L162-L162)

### [D-08]<a name="d-08"></a> Assembly blocks should have comments

These blocks already have comments

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

324:             assembly { 
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
335:             }
354:             assembly { 
355:                 y1 := sub(p, y1)
356:                 y2 := addmod(mulmod(y2, zzz1, p), y1, p)
357:                 x2 := addmod(mulmod(x2, zz1, p), sub(p, x1), p)
358:                 P0 := mulmod(x2, x2, p) //PP = P^2
359:                 P1 := mulmod(P0, x2, p) //PPP = P*PP
360:                 P2 := mulmod(zz1, P0, p) ////ZZ3 = ZZ1*PP
361:                 P3 := mulmod(zzz1, P1, p) ////ZZZ3 = ZZZ1*PPP
362:                 zz1 := mulmod(x1, P0, p) //Q = X1*PP
363:                 P0 := addmod(addmod(mulmod(y2, y2, p), sub(p, P1), p), mulmod(minus_2, zz1, p), p) //R^2-PPP-2*Q
364:                 P1 := addmod(mulmod(addmod(zz1, sub(p, P0), p), y2, p), mulmod(y1, P1, p), p) //R*(Q-X3)
365:             }
```


*GitHub* : [324](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L324-L335), [354](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L354-L365)

### [D-09]<a name="d-09"></a> Avoid double casting

The rule is valid, but the following findings are invalid.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

51:         account = CoinbaseSmartWallet(payable(accountAddress)); 
```


*GitHub* : [51](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L51-L51)

### [D-10]<a name="d-10"></a> Consider adding a block/deny-list

Contract doesn't handle tokens

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

13: contract CoinbaseSmartWalletFactory { 
14:     /// @notice Address of the ERC-4337 implementation used as implementation for new accounts.
15:     address public immutable implementation;
16: 
17:     /// @notice Thrown when trying to create a new `CoinbaseSmartWallet` account without any owner.
18:     error OwnerRequired();
19: 
20:     /// @notice Factory constructor used to initialize the implementation address to use for future
21:     ///         ERC-4337 account deployments.
22:     ///
23:     /// @param erc4337 The address of the ERC-4337 implementation used to deploy new cloned accounts.
```


*GitHub* : [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L13-L23)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

16: abstract contract ERC1271 { 
17:     /// @dev Precomputed `typeHash` used to produce EIP-712 compliant hash when applying the anti
18:     ///      cross-account-replay layer.
19:     ///
20:     ///      The original hash must either be:
21:     ///         - An EIP-191 hash: keccak256("\x19Ethereum Signed Message:\n" || len(someMessage) || someMessage)
22:     ///         - An EIP-712 hash: keccak256("\x19\x01" || someDomainSeparator || hashStruct(someStruct))
23:     bytes32 private constant _MESSAGE_TYPEHASH = keccak256("CoinbaseSmartWalletMessage(bytes32 hash)");
24: 
25:     /// @notice Returns information about the `EIP712Domain` used to create EIP-712 compliant hashes.
26:     ///
```


*GitHub* : [16](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L16-L26)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

32: contract MultiOwnable { 
33:     /// @dev Slot for the `MultiOwnableStorage` struct in storage.
34:     ///      Computed from: keccak256(abi.encode(uint256(keccak256("coinbase.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
35:     ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
36:     bytes32 private constant MUTLI_OWNABLE_STORAGE_LOCATION =
37:         0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;
38: 
39:     /// @notice Thrown when the sender is not an owner and is trying to call a privileged function.
40:     error Unauthorized();
41: 
42:     /// @notice Thrown when trying to add an already registered owner.
```


*GitHub* : [32](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L32-L42)

### [D-11]<a name="d-11"></a> Consider merging sequential for loops

The general rule is valid, but the instances below are invalid

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

206:         for (uint256 i; i < calls.length;) { 
```


*GitHub* : [206](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L206-L206)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

163:         for (uint256 i; i < owners.length; i++) { 
```


*GitHub* : [163](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L163-L163)

### [D-12]<a name="d-12"></a> Default `bool` values are manually reset

Using delete instead of assigning zero/false to state variables does not save any extra gas with the optimizer [on](https://gist.github.com/IllIllI000/ef8ec3a70aede7f12433fe63dc418515#with-the-optimizer-set-at-200-runs) (saves 5-8 gas with optimizer completely off), so this finding is invalid, especially since if they were interested in gas savings, they'd have the optimizer enabled. Some bots are also flagging `true` rather than just `false`

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

320:         _nonceUsed[withdrawRequest.nonce][account] = true; 
```


*GitHub* : [320](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L320-L320)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

192:         _getMultiOwnableStorage().isOwner[owner] = true; 
```


*GitHub* : [192](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L192-L192)

### [D-13]<a name="d-13"></a> Event names should use CamelCase

The instances below are already CamelCase (events are supposed to use CamelCase, not lowerCamelCase).

*There are 3 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

45:     event MagicSpendWithdrawal(address indexed account, address indexed asset, uint256 amount, uint256 nonce); 
```


*GitHub* : [45](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L45-L45)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

68:     event AddOwner(uint256 indexed index, bytes owner); 
74:     event RemoveOwner(uint256 indexed index, bytes owner); 
```


*GitHub* : [68](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L68-L68), [74](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L74-L74)

### [D-14]<a name="d-14"></a> Function can be declared as `pure`

The general rule is valid, but the instances below are invalid

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit contains sload
                  } call
241:     function implementation() public view returns (address $) { 
```


*GitHub* : [241](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L241-L241)

### [D-15]<a name="d-15"></a> Function definition modifier order does not follow Solidity style guide

This rule does not apply to internal library functions, so these instances are invalid.

*There are 11 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

50:     function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy) internal view returns (bool) { 
78:     function ecAff_isOnCurve(uint256 x, uint256 y) internal pure returns (bool) { 
94:     function FCL_nModInv(uint256 u) internal view returns (uint256 result) { 
117:     function ecZZ_mulmuladd_S_asm( 
118:         uint256 Q0,
119:         uint256 Q1, //affine rep for input point Q
120:         uint256 scalar_u,
121:         uint256 scalar_v
122:     ) internal view returns (uint256 X) {
274:     function ecAff_add(uint256 x0, uint256 y0, uint256 x1, uint256 y1) internal view returns (uint256, uint256) { 
293:     function ecAff_IsZero(uint256, uint256 y) internal pure returns (bool flag) { 
301:     function ecZZ_SetAff(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
302:         internal
303:         view
304:         returns (uint256 x1, uint256 y1)
305:     {
318:     function ecZZ_Dbl(uint256 x, uint256 y, uint256 zz, uint256 zzz) 
319:         internal
320:         pure
321:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
322:     {
344:     function ecZZ_AddN(uint256 x1, uint256 y1, uint256 zz1, uint256 zzz1, uint256 x2, uint256 y2) 
345:         internal
346:         pure
347:         returns (uint256 P0, uint256 P1, uint256 P2, uint256 P3)
348:     {
374:     function FCL_pModInv(uint256 u) internal view returns (uint256 result) { 
```


*GitHub* : [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L50-L50), [78](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L78-L78), [94](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L94-L94), [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L117-L122), [274](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L274-L274), [293](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L293-L293), [301](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L301-L305), [318](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L318-L322), [344](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L344-L348), [374](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L374-L374)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

104:     function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory webAuthnAuth, uint256 x, uint256 y) 
105:         internal
106:         view
107:         returns (bool)
108:     {
```


*GitHub* : [104](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L104-L108)

### [D-16]<a name="d-16"></a> Functions missing NatSpec `@param` tag

_

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

108:     /// @inheritdoc IPaymaster 
109:     function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost)
142:     /// @inheritdoc IPaymaster 
143:     function postOp(IPaymaster.PostOpMode mode, bytes calldata context, uint256 actualGasCost)
```


*GitHub* : [108](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L108-L109), [142](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L142-L143)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

327:     /// @inheritdoc UUPSUpgradeable 
328:     ///
329:     /// @dev Authorization logic is only based on the sender being an owner of this account.
330:     function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {}
332:     /// @inheritdoc ERC1271 
333:     function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
```


*GitHub* : [327](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L327-L330), [332](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L332-L333)

### [D-17]<a name="d-17"></a> Inconsistent comment spacing

URLs are not comments

*There are 24 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

21: // Abstract: https://eprint.iacr.org/2023/939.pdf 
22: // Github code: https://github.com/rdubois-crypto/FreshCryptoLib/blob/d9bb3b0fc6b737af2c70dab246cabbc7d05afc3c/solidity/src/FCL_ecdsa.sol#L40
300:     /*    https://hyperelliptic.org/EFD/g1p/auto-shortw-xyzz-3.html#addition-add-2008-s*/ 
```


*GitHub* : [21](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L21-L22), [300](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L300)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

13: /// @author Coinbase (https://github.com/coinbase/magic-spend) 
17: /// @dev See https://eips.ethereum.org/EIPS/eip-4337#extension-paymasters. 
273:     ///      https://eips.ethereum.org/EIPS/eip-191. 
```


*GitHub* : [13](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L13), [17](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L17), [273](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L273)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

18: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
19: /// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol)
267:     /// @dev Impl taken from https://github.com/alchemyplatform/light-account/blob/main/src/LightAccount.sol#L347 
```


*GitHub* : [18](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L18-L19), [267](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L267)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

11: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
12: /// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337Factory.sol)
```


*GitHub* : [11](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L11-L12)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

14: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
15: /// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC1271.sol)
27:     /// @dev Follows ERC-5267 (see https://eips.ethereum.org/EIPS/eip-5267). 
60:     /// @dev This implementation follows ERC-1271. See https://eips.ethereum.org/EIPS/eip-1271. 
97:     ///      See https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator. 
116:     /// @dev See https://eips.ethereum.org/EIPS/eip-712#specification. 
128:     /// @dev See https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct. 
```


*GitHub* : [14](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L14-L15), [27](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L27), [60](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L60), [97](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L97), [116](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L116), [128](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L128)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

31: /// @author Coinbase (https://github.com/coinbase/smart-wallet) 
35:     ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201). 
```


*GitHub* : [31](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L31), [35](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L35)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

16: /// @author Coinbase (https://github.com/base-org/webauthn-sol) 
17: /// @author Daimo (https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol)
23:         ///      See https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata. 
26:         ///      See https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson. 
39:     ///      See https://www.w3.org/TR/webauthn-2/#flags. 
43:     ///      See https://www.w3.org/TR/webauthn-2/#flags. 
50:     ///      See https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md. 
54:     ///      See https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type 
59:     /// in https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion. 
```


*GitHub* : [16](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L16-L17), [23](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L23), [26](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L26), [39](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L39), [43](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L43), [50](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L50), [54](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L54), [59](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L59)

### [D-18]<a name="d-18"></a> Integer increments by one can be unchecked to save on gas fees

The instances below are already in an unchecked block.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

209:                 ++i; 
```


*GitHub* : [209](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L209-L209)

### [D-19]<a name="d-19"></a> Low level calls with Solidity before `0.8.14` result in an optimiser bug

This assembly block does not call `mstore()`, so it's not possible to hit the bug here even if there are small future changes, so this doesn't seem low severity.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

213:         assembly ("memory-safe") { 
214:             $.slot := MUTLI_OWNABLE_STORAGE_LOCATION
215:         }
```


*GitHub* : [213](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L213-L215)

### [D-20]<a name="d-20"></a> Magic numbers should be replaced with constants

The rule is valid, but the following findings are invalid.

*There are 9 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

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


*GitHub* : [31](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L31-L31), [33](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L33-L33), [35](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L35-L35), [37](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L37-L38), [40](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L40-L40), [42](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L42-L42), [44](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L44-L44), [46](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L46-L46)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

43:     uint256 public constant REPLAYABLE_NONCE_KEY = 8453; 
```


*GitHub* : [43](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L43-L43)

### [D-21]<a name="d-21"></a> Misplaced SPDX identifier

It's already on the first line

*There are 6 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L1)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L1)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L1)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L1)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L1)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

1: // SPDX-License-Identifier: MIT 
```


*GitHub* : [1](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L1)

### [D-22]<a name="d-22"></a> Multiple mappings with same keys can be combined into a single struct mapping for readability

The general rule is valid, but the instances below are invalid

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

34:     mapping(address user => uint256 amount) internal _withdrawableETH; 
```


*GitHub* : [34](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L34-L34)

### [D-23]<a name="d-23"></a> Prefer double quotes for string quoting

The examples below are not strings. Furthermore it's perfectly reasonable to use single quotes within text ([p. 16](https://www.ox.ac.uk/sites/files/oxford/media_wysiwyg/University%20of%20Oxford%20Style%20Guide.pdf)).

*There are 4 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

5: // | _| '_/ -_|_-< ' \  | (__| '_| || | '_ \  _/ _ \ | |__| | '_ \ 
```


*GitHub* : [5](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L5-L5)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

16: ///         with inspiration from Alchemy's LightAccount and Daimo's DaimoAccount. 
96:                 // Ignore failure (it's EntryPoint's job to verify, not the account's). 
```


*GitHub* : [16](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L16), [96](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L96)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

76:     ///         - Does NOT verify that the origin in the `clientDataJSON` matches the Relying Party's origin: tt is considered 
```


*GitHub* : [76](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L76)

### [D-24]<a name="d-24"></a> Timestamp may be manipulation

Use of `block.timestamp`, in and of itself, is not evidence of an issue; there must be an incorrect usage in the code in order for there to be a vulnerability. There should also be a corresponding suggested fix.

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

188:         if (block.timestamp > withdrawRequest.expiry) { 
```


*GitHub* : [188](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L188)

### [D-25]<a name="d-25"></a> Unsafe downcast

When a type is downcast to a smaller type, the higher order bits are truncated, effectively applying a modulo to the original value. Without any other checks, this wrapping will lead to unexpected behavior and bugs

*There are 19 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit bytes32 -> uint256
61:         uint256 scalar_u = mulmod(uint256(message), sInv, n); 
```


*GitHub* : [61](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L61-L61)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit uint48 -> uint256
128:         validationData = (sigFailed ? 1 : 0) | (uint256(withdrawRequest.expiry) << 160); 
/// @audit contract MagicSpend -> address
133:         if (address(this).balance < withdrawAmount) { 
/// @audit contract MagicSpend -> address
134:             revert InsufficientBalance(withdrawAmount, address(this).balance);
/// @audit contract MagicSpend -> address
282:                 address(this), 
```


*GitHub* : [128](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L128-L128), [133](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L133-L134), [282](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L282-L282)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit bytes calldata slice -> bytes4
148:         if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) { 
/// @audit bytes calldata slice -> bytes4
181:         bytes4 selector = bytes4(data[0:4]); 
/// @audit contract CoinbaseSmartWallet -> address
186:         _call(address(this), 0, data); 
/// @audit bytes32 -> uint256
/// @audit bytes memory -> bytes32
302:             if (uint256(bytes32(ownerBytes)) > type(uint160).max) { 
```


*GitHub* : [148](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L148-L148), [181](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L181-L181), [186](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L186-L186), [302](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L302-L302)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit address -> address
51:         account = CoinbaseSmartWallet(payable(accountAddress)); 
/// @audit contract CoinbaseSmartWalletFactory -> address
65:         predicted = LibClone.predictDeterministicAddress(initCodeHash(), _getSalt(owners, nonce), address(this)); 
```


*GitHub* : [51](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L51-L51), [65](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L65-L65)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit contract ERC1271 -> address
53:         verifyingContract = address(this); 
/// @audit string memory -> bytes
105:                 keccak256(bytes(name)), 
/// @audit string memory -> bytes
106:                 keccak256(bytes(version)),
/// @audit contract ERC1271 -> address
108:                 address(this) 
```


*GitHub* : [53](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L53-L53), [105](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L105-L106), [108](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L108-L108)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit bytes32 -> uint256
/// @audit bytes memory -> bytes32
168:             if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) { 
/// @audit contract MultiOwnable -> address
202:         if (isOwnerAddress(msg.sender) || (msg.sender == address(this))) { 
```


*GitHub* : [168](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L168-L168), [202](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L202-L202)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit string memory -> bytes
117:         if (keccak256(bytes(_type)) != EXPECTED_TYPE_HASH) { 
/// @audit string memory -> bytes
122:         bytes memory expectedChallenge = bytes(string.concat('"challenge":"', Base64.encodeURL(challenge), '"')); 
/// @audit string memory -> bytes
126:         if (keccak256(bytes(actualChallenge)) != keccak256(expectedChallenge)) { 
/// @audit string memory -> bytes
145:         bytes32 clientDataJSONHash = sha256(bytes(webAuthnAuth.clientDataJSON)); 
```


*GitHub* : [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L117-L117), [122](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L122-L122), [126](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L126-L126), [145](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L145-L145)

### [D-26]<a name="d-26"></a> Unused named return variables without optimizer waste gas

Suggestions that only apply when the optimizer is _off_ are not useful to sponsors. Why would they pay for gas optimizations if they don't have the optimizer on, and don't plan to turn it on? Only a [small minority](https://github.com/search?q=org%3Acode-423n4+%22optimizer+%3D+false%22&type=code) have the optimizer off; the majority have it set to more than [200](https://github.com/search?q=org%3Acode-423n4+optimizer_runs&type=code) runs

*There are 10 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

94:     function FCL_nModInv(uint256 u) internal view returns (uint256 result) { 
95:         assembly {
96:             let pointer := mload(0x40)
97:             // Define length of base, exponent and modulus. 0x20 == 32 bytes
98:             mstore(pointer, 0x20)
99:             mstore(add(pointer, 0x20), 0x20)
100:             mstore(add(pointer, 0x40), 0x20)
101:             // Define variables base, exponent and modulus
102:             mstore(add(pointer, 0x60), u)
103:             mstore(add(pointer, 0x80), minus_2modn)
104:             mstore(add(pointer, 0xa0), n)
105: 
106:             // Call the precompiled contract 0x05 = ModExp
107:             if iszero(staticcall(not(0), 0x05, pointer, 0xc0, pointer, 0x20)) { revert(0, 0) }
108:             result := mload(pointer)
109:         }
110:     }
117:     function ecZZ_mulmuladd_S_asm( 
118:         uint256 Q0,
119:         uint256 Q1, //affine rep for input point Q
120:         uint256 scalar_u,
121:         uint256 scalar_v
122:     ) internal view returns (uint256 X) {
123:         uint256 zz;
124:         uint256 zzz;
125:         uint256 Y;
126:         uint256 index = 255;
127:         uint256 H0;
128:         uint256 H1;
129: 
130:         unchecked {
131:             if (scalar_u == 0 && scalar_v == 0) return 0;
132: 
133:             (H0, H1) = ecAff_add(gx, gy, Q0, Q1);
134:             if (
135:                 (H0 == 0) && (H1 == 0) //handling Q=-G
136:             ) {
137:                 scalar_u = addmod(scalar_u, n - scalar_v, n);
138:                 scalar_v = 0;
139:             }
140:             assembly {
141:                 for { let T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1)) } eq(T4, 0) {
142:                     index := sub(index, 1)
143:                     T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
144:                 } {}
145:                 zz := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
146: 
147:                 if eq(zz, 1) {
148:                     X := gx
149:                     Y := gy
150:                 }
151:                 if eq(zz, 2) {
152:                     X := Q0
153:                     Y := Q1
154:                 }
155:                 if eq(zz, 3) {
156:                     X := H0
157:                     Y := H1
158:                 }
159: 
160:                 index := sub(index, 1)
161:                 zz := 1
162:                 zzz := 1
163: 
164:                 for {} gt(minus_1, index) { index := sub(index, 1) } {
165:                     // inlined EcZZ_Dbl
166:                     let T1 := mulmod(2, Y, p) //U = 2*Y1, y free
167:                     let T2 := mulmod(T1, T1, p) // V=U^2
168:                     let T3 := mulmod(X, T2, p) // S = X1*V
169:                     T1 := mulmod(T1, T2, p) // W=UV
170:                     let T4 := mulmod(3, mulmod(addmod(X, sub(p, zz), p), addmod(X, zz, p), p), p) //M=3*(X1-ZZ1)*(X1+ZZ1)
171:                     zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
172:                     zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
173: 
174:                     X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
175:                     T2 := mulmod(T4, addmod(X, sub(p, T3), p), p) //-M(S-X3)=M(X3-S)
176:                     Y := addmod(mulmod(T1, Y, p), T2, p) //-Y3= W*Y1-M(S-X3), we replace Y by -Y to avoid a sub in ecAdd
177: 
178:                     {
179:                         //value of dibit
180:                         T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
181: 
182:                         if iszero(T4) {
183:                             Y := sub(p, Y) //restore the -Y inversion
184:                             continue
185:                         } // if T4!=0
186: 
187:                         if eq(T4, 1) {
188:                             T1 := gx
189:                             T2 := gy
190:                         }
191:                         if eq(T4, 2) {
192:                             T1 := Q0
193:                             T2 := Q1
194:                         }
195:                         if eq(T4, 3) {
196:                             T1 := H0
197:                             T2 := H1
198:                         }
199:                         if iszero(zz) {
200:                             X := T1
201:                             Y := T2
202:                             zz := 1
203:                             zzz := 1
204:                             continue
205:                         }
206:                         // inlined EcZZ_AddN
207: 
208:                         //T3:=sub(p, Y)
209:                         //T3:=Y
210:                         let y2 := addmod(mulmod(T2, zzz, p), Y, p) //R
211:                         T2 := addmod(mulmod(T1, zz, p), sub(p, X), p) //P
212: 
213:                         //special extremely rare case accumulator where EcAdd is replaced by EcDbl, no need to optimize this
214:                         //todo : construct edge vector case
215:                         if iszero(y2) {
216:                             if iszero(T2) {
217:                                 T1 := mulmod(minus_2, Y, p) //U = 2*Y1, y free
218:                                 T2 := mulmod(T1, T1, p) // V=U^2
219:                                 T3 := mulmod(X, T2, p) // S = X1*V
220: 
221:                                 T1 := mulmod(T1, T2, p) // W=UV
222:                                 y2 := mulmod(addmod(X, zz, p), addmod(X, sub(p, zz), p), p) //(X-ZZ)(X+ZZ)
223:                                 T4 := mulmod(3, y2, p) //M=3*(X-ZZ)(X+ZZ)
224: 
225:                                 zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
226:                                 zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free
227: 
228:                                 X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
229:                                 T2 := mulmod(T4, addmod(T3, sub(p, X), p), p) //M(S-X3)
230: 
231:                                 Y := addmod(T2, mulmod(T1, Y, p), p) //Y3= M(S-X3)-W*Y1
232: 
233:                                 continue
234:                             }
235:                         }
236: 
237:                         T4 := mulmod(T2, T2, p) //PP
238:                         let TT1 := mulmod(T4, T2, p) //PPP, this one could be spared, but adding this register spare gas
239:                         zz := mulmod(zz, T4, p)
240:                         zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1
241:                         let TT2 := mulmod(X, T4, p)
242:                         T4 := addmod(addmod(mulmod(y2, y2, p), sub(p, TT1), p), mulmod(minus_2, TT2, p), p)
243:                         Y := addmod(mulmod(addmod(TT2, sub(p, T4), p), y2, p), mulmod(Y, TT1, p), p)
244: 
245:                         X := T4
246:                     }
247:                 } //end loop
248:                 let T := mload(0x40)
249:                 mstore(add(T, 0x60), zz)
250:                 //(X,Y)=ecZZ_SetAff(X,Y,zz, zzz);
251:                 //T[0] = inverseModp_Hard(T[0], p); //1/zzz, inline modular inversion using precompile:
252:                 // Define length of base, exponent and modulus. 0x20 == 32 bytes
253:                 mstore(T, 0x20)
254:                 mstore(add(T, 0x20), 0x20)
255:                 mstore(add(T, 0x40), 0x20)
256:                 // Define variables base, exponent and modulus
257:                 //mstore(add(pointer, 0x60), u)
258:                 mstore(add(T, 0x80), minus_2)
259:                 mstore(add(T, 0xa0), p)
260: 
261:                 // Call the precompiled contract 0x05 = ModExp
262:                 if iszero(staticcall(not(0), 0x05, T, 0xc0, T, 0x20)) { revert(0, 0) }
263: 
264:                 //Y:=mulmod(Y,zzz,p)//Y/zzz
265:                 //zz :=mulmod(zz, mload(T),p) //1/z
266:                 //zz:= mulmod(zz,zz,p) //1/zz
267:                 X := mulmod(X, mload(T), p) //X/zz
268:             } //end assembly
269:         } //end unchecked
270: 
271:         return X;
272:     }
293:     function ecAff_IsZero(uint256, uint256 y) internal pure returns (bool flag) { 
294:         return (y == 0);
295:     }
374:     function FCL_pModInv(uint256 u) internal view returns (uint256 result) { 
375:         assembly {
376:             let pointer := mload(0x40)
377:             // Define length of base, exponent and modulus. 0x20 == 32 bytes
378:             mstore(pointer, 0x20)
379:             mstore(add(pointer, 0x20), 0x20)
380:             mstore(add(pointer, 0x40), 0x20)
381:             // Define variables base, exponent and modulus
382:             mstore(add(pointer, 0x60), u)
383:             mstore(add(pointer, 0x80), minus_2)
384:             mstore(add(pointer, 0xa0), p)
385: 
386:             // Call the precompiled contract 0x05 = ModExp
387:             if iszero(staticcall(not(0), 0x05, pointer, 0xc0, pointer, 0x20)) { revert(0, 0) }
388:             result := mload(pointer)
389:         }
390:     }
```


*GitHub* : [94](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L94-L110), [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L117-L272), [293](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L293-L295), [374](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L374-L390)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

137:     function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
138:         public
139:         payable
140:         virtual
141:         onlyEntryPoint
142:         payPrefund(missingAccountFunds)
143:         returns (uint256 validationData)
144:     {
145:         uint256 key = userOp.nonce >> 64;
146: 
147:         // 0xbf6ba1fc = bytes4(keccak256("executeWithoutChainIdValidation(bytes)"))
148:         if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) {
149:             userOpHash = getUserOpHashWithoutChainId(userOp);
150:             if (key != REPLAYABLE_NONCE_KEY) {
151:                 revert InvalidNonceKey(key);
152:             }
153:         } else {
154:             if (key == REPLAYABLE_NONCE_KEY) {
155:                 revert InvalidNonceKey(key);
156:             }
157:         }
158: 
159:         // Return 0 if the recovered address matches the owner.
160:         if (_validateSignature(userOpHash, userOp.signature)) {
161:             return 0;
162:         }
163: 
164:         // Else return 1, which is equivalent to:
165:         // `(uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)`
166:         // where `validUntil` is 0 (indefinite) and `validAfter` is 0.
167:         return 1;
168:     }
229:     function getUserOpHashWithoutChainId(UserOperation calldata userOp) 
230:         public
231:         view
232:         virtual
233:         returns (bytes32 userOpHash)
234:     {
235:         return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
236:     }
241:     function implementation() public view returns (address $) { 
242:         assembly {
243:             $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
244:         }
245:     }
```


*GitHub* : [137](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L137-L168), [229](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L229-L236), [241](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L241-L245)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

69:     function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4 result) { 
70:         if (_validateSignature({message: replaySafeHash(hash), signature: signature})) {
71:             // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
72:             return 0x1626ba7e;
73:         }
74: 
75:         return 0xffffffff;
76:     }
143:     function _domainNameAndVersion() internal view virtual returns (string memory name, string memory version); 
```


*GitHub* : [69](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L69-L76), [143](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L143-L143)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

212:     function _getMultiOwnableStorage() internal pure returns (MultiOwnableStorage storage $) { 
213:         assembly ("memory-safe") {
214:             $.slot := MUTLI_OWNABLE_STORAGE_LOCATION
215:         }
216:     }
```


*GitHub* : [212](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L212-L216)

### [D-27]<a name="d-27"></a> Use != 0 instead of > 0 for unsigned integer comparison

Only valid prior to Solidity version 0.8.13, and only for `require()` statements, and at least one of those is not true for the examples below

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

160:         if (withdrawable > 0) { 
```


*GitHub* : [160](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L160-L160)

### [D-28]<a name="d-28"></a> Use assembly to emit events, in order to save gas

For these instances, the arguments are too large to fit in the scratch space, so the finding is invalid

*There are 1 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

323:         emit MagicSpendWithdrawal(account, withdrawRequest.asset, withdrawRequest.amount, withdrawRequest.nonce); 
```


*GitHub* : [323](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L323)

### [D-29]<a name="d-29"></a> Use SafeCast to safely cast variables

There's no risk of casting smaller type to a higher one

*There are 19 instance(s) of this issue:*

```solidity
📁 File: src/FreshCryptoLib/FCL.sol

/// @audit bytes32 -> uint256
61:         uint256 scalar_u = mulmod(uint256(message), sInv, n); 
```


*GitHub* : [61](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol/#L61-L61)

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

/// @audit uint48 -> uint256
128:         validationData = (sigFailed ? 1 : 0) | (uint256(withdrawRequest.expiry) << 160); 
/// @audit contract MagicSpend -> address
133:         if (address(this).balance < withdrawAmount) { 
/// @audit contract MagicSpend -> address
134:             revert InsufficientBalance(withdrawAmount, address(this).balance);
/// @audit contract MagicSpend -> address
282:                 address(this), 
```


*GitHub* : [128](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L128-L128), [133](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L133-L134), [282](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L282-L282)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWallet.sol

/// @audit bytes calldata slice -> bytes4
148:         if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) { 
/// @audit bytes calldata slice -> bytes4
181:         bytes4 selector = bytes4(data[0:4]); 
/// @audit contract CoinbaseSmartWallet -> address
186:         _call(address(this), 0, data); 
/// @audit bytes32 -> uint256
/// @audit bytes memory -> bytes32
302:             if (uint256(bytes32(ownerBytes)) > type(uint160).max) { 
```


*GitHub* : [148](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L148-L148), [181](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L181-L181), [186](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L186-L186), [302](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol/#L302-L302)

```solidity
📁 File: src/SmartWallet/CoinbaseSmartWalletFactory.sol

/// @audit address -> address
51:         account = CoinbaseSmartWallet(payable(accountAddress)); 
/// @audit contract CoinbaseSmartWalletFactory -> address
65:         predicted = LibClone.predictDeterministicAddress(initCodeHash(), _getSalt(owners, nonce), address(this)); 
```


*GitHub* : [51](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L51-L51), [65](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol/#L65-L65)

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit contract ERC1271 -> address
53:         verifyingContract = address(this); 
/// @audit string memory -> bytes
105:                 keccak256(bytes(name)), 
/// @audit string memory -> bytes
106:                 keccak256(bytes(version)),
/// @audit contract ERC1271 -> address
108:                 address(this) 
```


*GitHub* : [53](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L53-L53), [105](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L105-L106), [108](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L108-L108)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

/// @audit bytes32 -> uint256
/// @audit bytes memory -> bytes32
168:             if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) { 
/// @audit contract MultiOwnable -> address
202:         if (isOwnerAddress(msg.sender) || (msg.sender == address(this))) { 
```


*GitHub* : [168](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L168-L168), [202](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L202-L202)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit string memory -> bytes
117:         if (keccak256(bytes(_type)) != EXPECTED_TYPE_HASH) { 
/// @audit string memory -> bytes
122:         bytes memory expectedChallenge = bytes(string.concat('"challenge":"', Base64.encodeURL(challenge), '"')); 
/// @audit string memory -> bytes
126:         if (keccak256(bytes(actualChallenge)) != keccak256(expectedChallenge)) { 
/// @audit string memory -> bytes
145:         bytes32 clientDataJSONHash = sha256(bytes(webAuthnAuth.clientDataJSON)); 
```


*GitHub* : [117](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L117-L117), [122](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L122-L122), [126](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L126-L126), [145](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L145-L145)

### [D-30]<a name="d-30"></a> Use `string.concat()` on strings instead of `abi.encodePacked()` for clearer semantic meaning

These instances don't use only bytes/strings or the solidity pragma is below 0.8.12, so they're invalid

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/SmartWallet/ERC1271.sol

/// @audit solidity pragma is below 0.8.12
122:         return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), _hashStruct(hash))); 
```


*GitHub* : [122](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol/#L122-L122)

```solidity
📁 File: src/WebAuthnSol/WebAuthn.sol

/// @audit solidity pragma is below 0.8.12
148:         bytes32 messageHash = sha256(abi.encodePacked(webAuthnAuth.authenticatorData, clientDataJSONHash)); 
```


*GitHub* : [148](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol/#L148-L148)

### [D-31]<a name="d-31"></a> Using `bool`s for storage incurs overhead

The general rule is valid, but the instances below are invalid

*There are 2 instance(s) of this issue:*

```solidity
📁 File: src/MagicSpend/MagicSpend.sol

37:     mapping(uint256 nonce => mapping(address user => bool used)) internal _nonceUsed; 
```


*GitHub* : [37](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol/#L37-L37)

```solidity
📁 File: src/SmartWallet/MultiOwnable.sol

24:     mapping(bytes account => bool isOwner_) isOwner; 
```


*GitHub* : [24](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol/#L24-L24)