// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {MultiOwnable} from "../../../src/SmartWallet/MultiOwnable.sol";

contract MockMultiOwnable is MultiOwnable {
    function init(bytes[] calldata owners) public {
        _initializeOwners(owners);
    }
}
