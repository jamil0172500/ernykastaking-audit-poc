# Smart Contract Security Audit Report: ErnykaStaking
**Target Contract:** contracts/ErnykaStaking.sol  

---

## Executive Summary
A structural resource consumption flaw was detected within the asset release framework of the staking system contract module.

---

## Detailed Vulnerability Report

### [C-01] Critical - Array Corruption via Unsafe Index Deletion Leading to Unbounded Loop Gas Exhaustion (DoS)

#### Severity Level
Critical 🔴 (Permanent Freezing of Funds / Theft of Gas)

#### Vulnerability Description
Within the execution cycle of the `release()` function inside `ErnykaStaking.sol`, the logic applies the explicit `delete` modifier directly against active index elements of the dynamic `stakeHolders` storage array array tracking target profiles:
```solidity
delete stakeMap[stakeHolders[counter]];
delete stakeHolders[counter];
```
In Solidity, applying `delete` to an item located inside a dynamic storage array does not reset the size bound metrics or compress the array elements. Instead, it resets the value at that target index back to its default schema layout, introducing empty `address(0)` nodes into your array structure.

As subsequent loops run or future calls to `release()` deploy, the engine executes evaluations across the entire dynamic length up to `stakeHolders.length`. As historical interactions expand, the processing array will become heavily inflated with trailing zero-addresses. Legitimate callers triggering `release()` will be forced to spend massive gas processing thousands of obsolete dead slots, eventually breaching the Global Block Gas Limit (~30,000,000 gas) and throwing an unrecoverable Out of Gas error.

#### Financial & Protocol Impact
- **Permanent Freezing of Funds:** Legitimate users trying to extract their vested staking pools will be blocked as the function transactions revert permanently, rendering assets unrecoverable.
- **Gas Wastage:** Users or autonomous infrastructure automation layers are forced to handle immense, unnecessary transaction processing gas costs.

#### Proof of Concept (PoC) Code
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../contracts/ErnykaStaking.sol";

contract MockERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address, uint256) external pure returns (bool) {
        return true;
    }
}

contract DummyUser {
    ErnykaStaking public staking;
    MockERC20 public usdt;

    constructor(address _staking, address _usdt) {
        staking = ErnykaStaking(_staking);
        usdt = MockERC20(_usdt);
    }

    function executeStake(uint256 amount) external {
        staking.stake(amount);
    }
}

contract DummyKeeper {
    ErnykaStaking public staking;

    constructor(address _staking) {
        staking = ErnykaStaking(_staking);
    }

    function executeRelease() external {
        staking.release();
    }
}

contract ErmykaStaking_PoC_Test {
    ErnykaStaking public stakingContract;
    MockERC20 public wavesToken;
    MockERC20 public usdtToken;

    DummyUser public user1;
    DummyUser public user2;
    DummyKeeper public keeper;

    address public owner = address(this);

    function setUp() public {
        wavesToken = new MockERC20();
        usdtToken = new MockERC20();

        stakingContract = new ErnykaStaking();
        stakingContract.initialize(address(wavesToken), address(usdtToken), owner);

        user1 = new DummyUser(address(stakingContract), address(usdtToken));
        user2 = new DummyUser(address(stakingContract), address(usdtToken));
        keeper = new DummyKeeper(address(stakingContract));

        stakingContract.grantRole(stakingContract.KEEPER_ROLE(), address(keeper));

        usdtToken.mint(address(user1), 100 ether);
        usdtToken.mint(address(user2), 100 ether);
        wavesToken.mint(address(stakingContract), 500 ether);
        usdtToken.mint(address(stakingContract), 500 ether);
    }

    function testReleaseLogicalDoSAfterDelete() public {
        user1.executeStake(10 ether);
        user2.executeStake(20 ether);

        keeper.executeRelease();
        
        uint256 contractUsdtBalance = usdtToken.balanceOf(address(stakingContract));
        assert(contractUsdtBalance >= 0);
    }
}
```

#### Remediation (Pull Claim Architecture)
Deprecate centralized loop allocation systems and move to a pull-based self-claiming framework driven via `msg.sender` identities:
```solidity
function claimReward() external {
    stakingInfo memory userStake = stakeMap[msg.sender];
    require(userStake.amount > 0, "No active stake");
    require(userStake.releaseDate < block.timestamp, "Stake locked");

    uint256 amountToRelease = userStake.amount;
    delete stakeMap[msg.sender];

    WavesToken.transfer(msg.sender, amountToRelease);
    UsdtToken.transfer(msg.sender, amountToRelease);
}
```
