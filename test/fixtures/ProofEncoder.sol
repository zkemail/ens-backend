// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ProofEncoder {
    struct SnarkProof {
        uint256[] pi_a;
        uint256[][] pi_b;
        uint256[] pi_c;
    }

    function encodeProof(
        uint256[] memory _pi_a,
        uint256[][] memory _pi_b,
        uint256[] memory _pi_c
    ) public pure returns (bytes memory) {
        SnarkProof memory proof = SnarkProof({
            pi_a: _pi_a,
            pi_b: _pi_b,
            pi_c: _pi_c
        });
        return abi.encode(proof);
    }
} 