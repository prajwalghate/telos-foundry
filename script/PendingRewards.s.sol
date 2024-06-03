pragma solidity ^0.8.4;
import "forge-std/Test.sol";
import "@openzeppelin/token/ERC20/IERC20.sol";

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import "../src/MasterchefV2.sol";
import "@openzeppelin/mocks/ERC20Mock.sol";


contract PendingRewards is Script {
    MasterchefV2 chef=MasterchefV2(0xC7c74fB5aa1b11d2e960B6cf9C057F67c8C602bc);
    uint256 pid=0;
    IERC20 poolToken=IERC20(0x67e07BFfce318ADbA7b08618CBf4B8E271499197);
    address user=0x2aCC49a84919Ab9Cf0eb6576432E9b09D78650E6;
    address wtlos=0xD102cE6A4dB07D247fcc28F366A623Df0938CA9E;


    function run() public {
        console.log("wtlos balance",IERC20(wtlos).balanceOf(user));
        uint totalSlushsPerBlock=chef.totalSlushsPerBlock();
        uint pendingSlushs=chef.pendingSlushs(pid, user);
        uint pendingExtra=chef.pendingExtra(pid, user);
        console.log("pendingSlushs",pendingSlushs);
        console.log("pendingExtra",pendingExtra);
        console.log("totalSlushsPerBlock",totalSlushsPerBlock);
    }
    
}

/*
forge script script/PendingRewards.s.sol:PendingRewards --rpc-url http://127.0.0.1:8545/ --broadcast -vvv --legacy --slow

forge script script/PendingRewards.s.sol:PendingRewards --rpc-url https://mainnet.telos.net/evm --broadcast -vvv --legacy --slow

*/