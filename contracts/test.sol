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

        uint[] memory dynArr = new uint[](3);
        dynArr[0] = 1;
        dynArr[1] = 2;
        dynArr[2] = 3;
        uint256[3] memory fixedArr = [uint256(7), uint256(8), uint256(9)];
        this._calldata(fixedArr, bytes32("0x456"), dynArr, "123456");
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

    function _calldata(
        uint[3] calldata _a,
        bytes32 _b,
        uint[] calldata _c,
        string calldata _d
    ) external {
        _memory(_a, bytes("0x1234"), _c, _d);
    }

    function _memory(
        uint[3] memory _a,
        bytes memory _b,
        uint[] memory _c,
        string memory _d
    ) internal {}
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
