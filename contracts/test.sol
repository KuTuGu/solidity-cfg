// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.0;

import "../lib/forge-std/src/Test.sol";
import "./outer.sol";

contract A is Test {
    D d;
    O o;

    constructor() {
        d = new D();
        o = new O();
    }

    function entry(uint _a, uint _b) external {
        for (uint i; i < 2; ++i) {
            _mid(_add(_a, _b));
        }
    }

    function _mid(uint _a) internal out(_a) {
        console.log(_a);
    }

    function _add(uint _a, uint _b) internal pure returns (uint) {
        return _a + _b;
    }

    modifier out(uint _c) {
        _;
        d.d(_c);
        o.o(_c);
    }
}

interface ID {
    function d(uint _d) external;
}

contract D is ID {
    function d(uint _d) external {
        _e(_d);
    }

    function _e(uint _d) internal {}
}
