// SPDX-License-Identifier: GPL-3.0-only
pragma solidity >=0.8.0;

contract O {
    function o(uint _x) external pure returns (uint, uint) {
        return _i(_x);
    }

    function _i(uint _x) internal pure returns (uint, uint) {
        return (_x, 1);
    }
}
