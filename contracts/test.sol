// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.0;

import "../lib/forge-std/src/Test.sol";

contract A is Test {
    D d;

    function setUp() public {
        d = new D();
    }

    function entry(uint _a, uint _b) external {
        for (uint i; i < 5; ++i) {
            this.mid(_a, _b);
        }
    }

    function mid(uint _a, uint _b) external out(_b) {
        console.log(_a);
    }

    modifier out(uint _c) {
        _;
        d.d(_c);
    }
}

interface ID {
    function d(uint _d) external;
}

contract D is ID {
    function d(uint _d) external {
        bool success;
        address a = address(0);

        assembly {
            success := call(gas(), a, 0, 0, 0, 0, 0)
        }

        require(success, "ETH_TRANSFER_FAILED");
    }
}
