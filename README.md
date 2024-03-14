

# Smart Wallet audit details
- Total Prize Pool: $49,000 in USDC
  - HM awards: $24,750 in USDC 
  - QA awards: $750 in USDC
  - Bot Race awards: $2,250 in USDC
  - Analysis awards: $1,500 in USDC
  - Gas awards: $750 in USDC
  - Judge awards: $5,600 in USDC
  - Lookout awards: $2,400 in USDC
  - Scout awards: $500 in USDC
  - Mitigation Review: $10,500 in USDC (Opportunity goes to top 3 certified wardens based on placement in this audit.)
 
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings [using the C4 form](https://code4rena.com/contests/2024-03-smart-wallet/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts March 14, 2024 20:00 UTC
- Ends March 21, 2024 20:00 UTC

## Automated Findings / Publicly Known Issues

The 4naly3er report can be found [here](https://github.com/code-423n4/2024-03-coinbase/blob/main/4naly3er-report.md).

Automated findings output for the audit can be found [here](https://github.com/code-423n4/2024-03-coinbase/blob/main/bot-report.md) within 24 hours of audit opening.

_Note for C4 wardens: Anything included in this `Automated Findings / Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._

- SmartWallet
  - Crosschain replay via executeWithoutChainIdValidation relies on gas values from one chain being valid and accepted by a bundler on other chains. This may not be the case.
- WebAuthnSol
  - Read comments on `WebAuthn.sol` for details on validation steps we are knowingly skipping
- FreshCryptoLib
  - Exploits should only be considered in the context of a call path starting with `ecdsa_verify`. Other functions are not intended to be called directly.
  - Issues discovered in a previous audit 
    1. ecAff_isOnCurve line 79 has a conditional error, fixed here https://github.com/rdubois-crypto/FreshCryptoLib/pull/60
```if (((0 == x) && (0 == y)) || x == p || y == p)```
 should be:
```if (((0 == x) && (0 == y)) || (x == p && y == p)) {```
  
    2. A case in ecZZ_mulmuladd_S_asm where an infinite loop could happen if the points (-Gx, -Gy, 1, 1) are passed as arguments, fixed here https://github.com/rdubois-crypto/FreshCryptoLib/pull/61
There should be a line line after line 138 with
```if (scalar_u == 0 && scalar_v == 0) return 0;```
to safely exit early
- MagicSpend
  - When acting as a paymaster, EntryPoint will debit MagicSpend slightly more than actualGasCost, meaning what is withheld on a gas-paying withdraw will not cover 100% of MagicSpend's balance decrease in the EntryPoint.
  - `validatePaymasterUserOp` checks address.balance, which currently violates ERC-7562 rules, however there is [PR](https://github.com/eth-infinitism/account-abstraction/pull/460) to change this. 


# Overview

This audit covers four separate but related groups of code
- SmartWallet is a smart contract wallet. In addition to Ethereum address owners, it supports passkey owners and validates their signatures via WebAuthnSol. It supports multiple owners and allows for signing account-changing user operations such that they can be replayed across any EVM chain where the account has the same address. It is ERC-4337 compliant and can be used with paymasters such as MagicSpend. 
- WebAuthnSol is a library for verifying WebAuthn Authentication Assertions onchain. 
- FreshCryptoLib is an excerpt from [FreshCryptoLib](https://github.com/rdubois-crypto/FreshCryptoLib/tree/master/solidity), including the function `ecdsa_verify` and all code this function depends on. `ecdsa_verify` is used by WebAuthnSol onchains without the RIP-7212 verifier, and `FCL.n` is used to check for signature malleability. 
- MagicSpend is a contract that allows for signature-based withdraws. MagicSpend is a EntryPoint v0.6 compliant paymaster and also allows using withdraws to pay transaction gas, in this way. 

## Links

- **Previous audits:** 
  - SmartWallet
    - [Cantina](https://github.com/coinbase/smart-wallet/blob/main/audits/report-Base%20Paymaster%20%26%20Smart%20Account.pdf)
  - WebAuthnSol
    - [Cantina](https://github.com/base-org/webauthn-sol/blob/main/audits/report-review-coinbase-webauthn.pdf)
    - Certora (link pending)
  - FreshCryptoLib
    - Coinbase completed an audit of FreshCryptoLib with artifacts [here](https://github.com/base-org/FCL-ecdsa-verify-audit/tree/main).
      - [Audit doc](https://github.com/base-org/FCL-ecdsa-verify-audit/blob/main/docs/secp256r1-ecdsa-verify-solidity-review.pdf)
      - [Testing methodology](https://github.com/base-org/FCL-ecdsa-verify-audit/blob/main/docs/secp256r1-ecdsa-verify-solidity-review-testing-plan.pdf) 
  - MagicSpend
    - [Cantina](https://github.com/coinbase/magic-spend/blob/main/audit/report-review-coinbase-magicspend.pdf)
- **Documentation:** Each folder has a detailed README. Please read those.
- **Demo!:** You can try using all of these contracts together on our [demo site](https://keys.coinbase.com/developers).
- **Explainer Video:** [Here's a video](https://x.com/WilsonCusack/status/1764355750149710190?s=20) talking through the demo and what is going on behind the scenes. 



# Scope



| Contract | SLOC | Purpose | External Imports |  
| ----------- | ----------- | ----------- | ----------- |
| [src/SmartWallet/MultiOwnable.sol](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/MultiOwnable.sol) | 80 | Auth contract, supporting multiple owners and owners identified as bytes to allow for secp256r1 public keys | |
| [src/SmartWallet/ERC1271.sol](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/ERC1271.sol) | 54 | Abstract contract for ERC-1271 support for CoinbaseSmartWallet | |
| [src/SmartWallet/CoinbaseSmartWalletFactory.sol](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWalletFactory.sol) | 35 | ERC-4337 compliant Factory for CoinbaseSmartWallet | [solady/utils/LibClone.sol](https://github.com/Vectorized/solady/blob/main/src/utils/LibClone.sol) |
| [src/SmartWallet/CoinbaseSmartWallet.sol](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol) | 165 | ERC-4337 compliant smart account | [solady/accounts/Receiver.sol](https://github.com/Vectorized/solady/blob/main/src/accounts/Receiver.sol) [solady/utils/UUPSUpgradeable.sol](https://github.com/Vectorized/solady/blob/main/src/utils/UUPSUpgradeable.sol) [solady/utils/SignatureCheckerLib.sol](https://github.com/Vectorized/solady/blob/main/src/utils/SignatureCheckerLib.sol) [account-abstraction/interfaces/UserOperation.sol](https://github.com/eth-infinitism/account-abstraction/blob/abff2aca61a8f0934e533d0d352978055fddbd96/contracts/interfaces/UserOperation.sol)|
| [src/WebAuthnSol/WebAuthn.sol](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/WebAuthnSol/WebAuthn.sol) | 54 | Solidity WebAuthn verifier| [solady/utils/LibString.sol](https://github.com/Vectorized/solady/blob/main/src/utils/LibString.sol) [openzeppelin-contracts/contracts/utils/Base64](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Base64.sol) |
| [src/FreshCryptoLib/FCL.sol](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/FreshCryptoLib/FCL.sol) | 255 | Library for verifying secp256r1 signatures| |
| [src/MagicSpend/MagicSpend.sol](https://github.com/code-423n4/2024-03-coinbase/blob/main/src/MagicSpend/MagicSpend.sol) | 143 | Contract supporting signature-based withdraws. Also ERC-4337 EntryPoint v0.6 compliant paymaster |  [solady/auth/Ownable.sol](https://github.com/Vectorized/solady/blob/main/src/auth/Ownable.sol) [solady/utils/SignatureCheckerLib.sol](https://github.com/Vectorized/solady/blob/main/src/utils/SignatureCheckerLib.sol) [solady/utils/SafeTransferLib.sol](https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol) [account-abstraction/interfaces/UserOperation.sol](https://github.com/eth-infinitism/account-abstraction/blob/abff2aca61a8f0934e533d0d352978055fddbd96/contracts/interfaces/UserOperation.sol) [account-abstraction/interfaces/IPaymaster.sol](https://github.com/eth-infinitism/account-abstraction/blob/abff2aca61a8f0934e533d0d352978055fddbd96/contracts/interfaces/IPaymaster.sol) [account-abstraction/interfaces/IEntryPoint.sol](https://github.com/eth-infinitism/account-abstraction/blob/abff2aca61a8f0934e533d0d352978055fddbd96/contracts/interfaces/IEntryPoint.sol)|


## Out of scope

The complete scope of this audit is the files included in `src/`

# Additional Context

- Which blockchains will this code be deployed to, and are considered in scope for this audit?
  - We have near-term plans to deploy this code to the mainnets of the following chains: Ethereum, Base, Optimism, Arbitrum, Polygon, BNB, Avalanche, Gnosis.
- Roles/Permissions
  - SmartWallet
    - Only owner or self
      - MultiOwnable.addOwnerAddress
      - MultiOwnable.addOwnerPublicKey
      - MultiOwnable.AddOwnerAddressAtIndex
      - MultiOwnable.addOwnerPublicKeyAtIndex
      - MultiOwnable.removeOwnerAtIndex
      - UUPSUpgradable.upgradeToAndCall
    - Only EntryPoint, owner, or self
      - CoinbaseSmartWallet.execute
      - CoinbaseSmartWallet.executeBatch
    - Only EntryPoint
      - CoinbaseSmartWallet.executeWithoutChainIdValidation
      - validateUserOp
  - MagicSpend
    - Only owner
      - ownerWithdraw
      - entryPointDeposit
      - entryPointWithdraw
      - entryPointAddStake
      - entryPointUnlockStake
      - entryPointWithdrawStake

- ERC/EIP Compliance
  - `ERC1271`: Should comply with `ERC1271`
  - `CoinbaseSmartWalletFactory`: Should comply with factory behavior defined in `ERC4337`
  - `CoinbaseSmartWallet`: Should comply with account behavior defined in `ERC4337`
  - `MagicSpend`: Should comply with paymaster behavior defined in `ERC4337`

## Attack ideas (Where to look for bugs)
- SmartWallet
  - Can an attacker move funds from the account?
  - Can an attacker brick (make unusable) the account?
  - Can functions not in `canSkipChainIdValidation` be used via `executeWithoutChainIdValidation`?
- MagicSpend
  - Can an attacker withdraw using an invalid WithdrawRequest?
  - Can an attacker be credited more than WithdrawRequest.amount?
  - Are there any griefing attacks that could cause this paymaster to be banned by bundlers?
- WebAuthn
  - False positive or false negative in validation
    - Are there valid webauthn authentication assertions that do not pass our validation?
- FreshCryptoLib
  - False positive or false negative in validation


## Main invariants
- SmartWallet
  - Only current owners or EntryPoint can make calls that
    - Decrease account balance.
    - Add or remove owner.
    - Upgrade account.
  - Any current owner can add or remove any other owner.
- MagicSpend
  - Only owner can
    - Move funds from contract without a valid `WithdrawRequest`.
    - Stake and unstake in EntryPoint.
    - Add and withdraw from EntryPoint balance.
  - Every `WithdrawRequest` can only be used once.
  - A `WithdrawRequest` cannot be used past `WithdrawRequest.expiry`.
  - Withdrawers can never receive more than `WithdrawRequest.amount`.
  - Withdrawers using paymaster functionality should receive exactly `WithdrawRequest.amount - postOp_actualGasCost`.
  - At the end of a transaction, `_withdrawableETH` contains no non-zero balances.
- WebAuthn
  - Validation passes if and only if
    - `'"challenge":""<challenge>"` occurs in `clientDataJSON` starting at `challengeIndex`.
    - `'"type":"webauth.get"` is occurs in `clientDataJSON` starting at `typeIndex`.
    - User presence bit is set.
    - User verified bit is set, if required.
    - `r` and `s` are valid signature values for `x`, `y` on the message hash that results from `clientDataJSON` and `authenticatorData`.
- FreshCryptoLib
  - All calls with valid sets of message, r, s, Qx, and Qy for the secp256r1 curve should return true.
  - All calls with invalid sets of message, r, s, Qx, and Qy for the secp256r1 curve should revert or return false.

## Scoping Details 

```
- If you have a public code repo, please share it here: https://github.com/coinbase/smart-wallet, https://github.com/coinbase/magic-spend, https://github.com/base-org/webauthn-sol, https://github.com/base-org/fresh-crypto-lib-audit  
- How many contracts are in scope?: 7   
- Total SLoC for these contracts?: 786  
- How many external imports are there?: 11  
- How many separate interfaces and struct definitions are there for the contracts within scope?: 0  
- Does most of your code generally use composition or inheritance?: Composition   
- How many external calls?: 5   
- What is the overall line coverage percentage provided by your tests?: 95
- Is this an upgrade of an existing system?: False
- Check all that apply (e.g. timelock, NFT, AMM, ERC20, rollups, etc.): 
- Is there a need to understand a separate part of the codebase / get context in order to audit this part of the protocol?: False  
- Please describe required context:   
- Does it use an oracle?: No
- Describe any novel or unique curve logic or mathematical models your code uses: 
- Is this either a fork of or an alternate implementation of another project?: True   
- Does it use a side-chain?:
- Describe any specific areas you would like addressed:
```

# Tests


This repository is managed using [Foundry](https://book.getfoundry.sh).

**Install Foundry**

Run the following command and then follow the instructions.
```bash
curl -L https://foundry.paradigm.xyz | bash
```


**Install Modules**
```bash
forge install
```

**Run Tests**
```bash
forge test
```


Solidity `0.8.23` is used to compile and test the smart contracts. 

## Miscellaneous

Employees of Coinbase and employees' family members are ineligible to participate in this audit.
