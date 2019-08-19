# Circuit Understanding

## 1. 综合讨论（基于DepositCircuit）

1. 为什么之前提出的节省中间验证的优化不可行？

   之前优化的想法是这样的，中间状态不验证，而只有block出入的merkle tree root进行验证。

   ![image-20190723091104776](/Users/yueawang/Documents/My_Reports/loopring/images/check-status-at-the-end.png)

   该方案不可行是因为必须保证Merkle Path的一致性。如下图所示，本来Merkle Root验证电路本身比较简单，输入是path和leaf，输出是merkle root。

   ![image-20190722192752108](/Users/yueawang/Documents/My_Reports/loopring/images/merkle gadget.png)

   对于Loopring的电路设计，我们有before和after两个merkle tree需要被验证，于是有：

   ![image-20190722205208609](/Users/yueawang/Documents/My_Reports/loopring/images/before and after mkl gadget.png)

   

   这里有个问题，因为before和after完全没有联系，那么任意构造的merkle树都可以单独通过before或者after的验证，也就是说before和after可以来自完全不同的两颗merkle树，且各自符合merkle逻辑。所以为了保证内部的操作在同一棵merkle tree上完成，也就必须让before和after产生联系，目前看来只有这样一种方案，如下图所示：

   ![image-20190722205053165](/Users/yueawang/Documents/My_Reports/loopring/images/current deposit gadget link.png)

   即对before和after使用同一份merkle path做验证，这样保证了对节点状态的改动始终在同一棵merkle树上，但是此方案的副作用就是每次只能用来验证一个节点的一次改动，因为合并的多个节点的改动不可能有公用的merkle path。

2. 为什么需要sha256在电路的最后（这里指deposit/withdraw，ringsettle似乎没有这个计算），直接使用merkle root行不行？为什么合约还要计算sha256，直接拿statement行不行？如果合约不用计算的话，换个hash行不行？

   答案都是不行，或者说当前设计下不行。首先看看当前的设计：

   ![image-20190722203724585](/Users/yueawang/Documents/My_Reports/loopring/images/circuit overview.png)

   基本上有两块，上面一行是对merkle树的验证，下面一行是以block为单位的一个hash。可以对比以太坊来理解这个模型，上面一行depositGadget是对eth stateDB的操作，将每一个request对应到一个eth的tx，而下面这个sha256hash就是对应到eth block hash。

   1. 只使用merkle root不行的原因：

      类比eth，因为对statedb的操作和对block上tx记录的操作无关，如果没有这个block hash的check，那么只要statedb的check能过，block里面包含的任意tx和statedb的改动无关也能通过验证。这样block的状态和statedb的状态就不能保持一致了。

   2. 为什么合约要计算sha256hash这个statement，直接拿statement不是也能通过验证么？

      直接拿statement确实能正确地通过验证，但是这里没办法保证通过验证的就是当前提交的block的，比如有两个block有待验证，合法的block0和非法的block1，在调用合约的时候，我们提交block1的data和block0的proof，合约验证block0的proof肯定是通过的，但显然不能按照block1的tx去执行，也就是需要一个block和proof的绑定过程，这里可能是零知识证明设计上的一个需要注意的地方，就是不能仅依赖zksnark proof，还必须有业务层上的一些附加的逻辑。

   3. 因为合约必须对这个statement进行检查，所以不可以取消或者换算法（sha256在合约里面便宜）。

3. 讨论理解电路设计过程。

   Loopring的电路设计可以隐约看到以太坊的逻辑（个人猜测是受了ethsnark的影响，有时间可以过一下ethsnark的代码逻辑），原因可能是因为request本身已经组织成了一个blockchain，基本上就是request对应tx，block对应block，merkle树对应stateDB。

   下面两张图是eth的block内部两个主要数据结构tx_root和state_root的组织方式

   ![image-20190722231911683](/Users/yueawang/Documents/My_Reports/loopring/images/eth_tx_root.png)

   ![image-20190722232012755](/Users/yueawang/Documents/My_Reports/loopring/images/eth_state_root.png)

基本对应关系如下：

| Ethereum    | Loopring circuit         | 验证逻辑                | 补充说明                                                     |
| ----------- | ------------------------ | ----------------------- | ------------------------------------------------------------ |
| Transaction | Request                  | Signature(public key)   |                                                              |
| tx root     | PublicDataHash           | Hash equivalence        | eth tx root采用的merkle组织方式。但loopring这边不需要这么麻烦，直接计算full data hash效果一样。 |
| state root  | merkle Root Before/After | merkle root equivalence | ETH只有一棵MPT用于存储stateDB，但loopring需要证明所有的操作都在同一棵merkle树上。 |

这样在电路设计上的考量就比较清楚了，从0开始设计电路的流程大概是一个选型的过程，比如是用UTXO还是Account，中间状态用什么存储，状态变化用什么描述？

|                        | 账户模型 | 世界状态模型   | 状态变化描述 | 补充说明                                                     |
| ---------------------- | -------- | -------------- | ------------ | ------------------------------------------------------------ |
| BTC                    | UTXO     | ？？           | tx           |                                                              |
| ETH                    | Account  | MPT            | tx           |                                                              |
| Loopring               | Account  | layered merkle | request      | 由于zksnark，因此还有一些需要业务层的设计来保证，如前面提到的Layered merkle树唯一，以及request block和block proof绑定等等。 |
| Loopring-derivative :) | ??       | ??             | ??           |                                                              |

## 2. OrderCancel电路笔记

![image-20190803160429976](/Users/yueawang/Documents/My_Reports/loopring/images/ordercancel character view.png)

###2.1 Input : output

​	基本设置和DepositCircuit相同，输入是Cancelled Order Block的描述，输出是全部相关变量的hash，其实全部5种电路的设计都是一样的（虚线需要开启onChainData）

![image-20190803165832629](/Users/yueawang/Documents/My_Reports/loopring/images/ordercancel circuit top view.png)

具体到代码是这样的：

首先是Top level电路的描述，包含这么些东西。

```c++
    std::vector<OrderCancellationGadget> cancels; // down level OrderCancellationGadget

    libsnark::dual_variable_gadget<FieldT> publicDataHash; // Hash value as primary input/statment.
    PublicDataGadget publicData; // Data to be hashed

	// Below variables are all private witnesses.
    Constants constants;
    libsnark::dual_variable_gadget<FieldT> exchangeID;
    libsnark::dual_variable_gadget<FieldT> merkleRootBefore;
    libsnark::dual_variable_gadget<FieldT> merkleRootAfter;

    libsnark::dual_variable_gadget<FieldT> operatorAccountID;
    const jubjub::VariablePointT publicKey;
    VariableT nonce;
    VariableT balancesRoot_before;
    std::unique_ptr<UpdateAccountGadget> updateAccount_O;
```

电路的输入是OrderCancellationBlock，由Cancellation和其他一些merkle相关的变量组成。

```c++
class Cancellation
{
public:
    ethsnarks::FieldT fee;
    ethsnarks::FieldT walletSplitPercentage;
    Signature signature;

    TradeHistoryUpdate tradeHistoryUpdate_A;
    BalanceUpdate balanceUpdateT_A;
    BalanceUpdate balanceUpdateF_A;
    AccountUpdate accountUpdate_A;
    BalanceUpdate balanceUpdateF_W;
    AccountUpdate accountUpdate_W;
    BalanceUpdate balanceUpdateF_O;
};

class OrderCancellationBlock
{
public:
    ethsnarks::FieldT exchangeID;

    ethsnarks::FieldT merkleRootBefore;
    ethsnarks::FieldT merkleRootAfter;

    ethsnarks::FieldT operatorAccountID;
    AccountUpdate accountUpdate_O;

    std::vector<Loopring::Cancellation> cancels;
};
```



### 2.2. Unflatten Circuit

​	这里的电路描述的问题抽象出来是这样的

```c++
1. merkleRootBefore, merkleRootAfter满足block merkle update的条件
2. exchangeID正确
3. operatorAccountID正确
4. 一组由用户发起的Cancellation合法，单个Cancellation包括以下条件
	4.1	fee 和 walletSplitPercentage 合法
	4.2 sign 正确
	4.3 User Trading的History正确，即tradeHistoryUpdate_A
	4.4 User Trading的balance正确，即balanceUpdateT_A
	4.5 User Paid Fee的balance正确，即balanceUpdateF_A
	4.6 User Account操作正确，即accountUpdate_A
	4.7 Wallet Recieved Fee的balance正确，即balanceUpdateF_W
	4.8 Wallet Account操作正确，即accountUpdate_W
	4.9 Operator Recieved Fee的balance正确，即balanceUpdateF_O
5. Operator Account操作正确，即accountUpdate_O （为什么不在4里面对单次做check？？理由似乎是因为Operator只有一个，而User，Wallet可能是不同的。。。但是operator的balance变化了，merkle root就会变化，似乎必须每次check才行？WHY？？）
6. merkleRootBefore，merkleRootAfter，exchangeID，operatorAccountID，以及cancel.publicData()综合起来的hash值正确。（后两者需要onchainDataAvailability==true）
```

​	显然，Cancel影响到了3个账户，User，Wallet和Operator，从这里的代码看Cancel Order是付费的，而且将来Fee model可能会有变化，账户相关的电路操作都在OrderCancellationGadget里面，就是上面step 4的逻辑，和state变化有关的几个值得注意的电路如下所示：
1. fee，一个float值，是交易的总手续费，会分配给wallet和operator。

2. feeToWallet，wallet按照比例收费，是一个计算%的电路。

3. feeToOperator，total fee去掉给wallet就是给operator的费用。

4. feePaymentWallet，确保$balanceF\_A\_before-feeToWallet \equiv balanceF\_W\_before+feeToWallet​$

5. feePaymentOperator，类似的，确保$balanceF\_A\_before-feeToWallet-feeToOperator \equiv balanceF\_O\_before + feeToOperator​$

6. updateBalanceT_A，保证Token余额变化合法，这里没有value的变化，所以只检查$tradingHistoryT$

7. updateBalanceF_A，变化过程是$balanceF\_A\_before, tradingHistoryRootF\_A \to \\balanceF\_A\_before-feeToWallet-feeToOperator, tradingHistoryRootF\_A$

   一个小问题是tradingHistoryRootF没有发生变化，是因为fee改变不算trading么？

8. updateAccount_A，保证User Account的变化合法，实际上就是计算新的merkle root，注意这里的root只是临时状态，因为还有其他账户（wallet，operator）没有更新

9. 接下来就是更新wallet，updateBalanceF_W和updateBalanceF_A一样，用来检查$balanceF\_W\_before \to balanceF\_W\_before + feeToWallet​$，注意这里也不考虑tradingHistoryW

10. updateAccount_W，类似的，保证Wallet Account的变化合法

11. 最后是updateBalanceF_O，检查$balanceF\_O\_before \to balanceF\_O\_before + feeToOperator$

到此，单个cancel的主要逻辑就结束了，几个主要电路的逻辑框图如下：

1. Merkle验证电路是一系列updateXXX电路的主要组成部分，一次验证一个节点的改动

   ![image-20190731121508839](/Users/yueawang/Documents/My_Reports/loopring/images/merkle gadgets.png)

2. Fee Calculation

   ![image-20190731142721181](/Users/yueawang/Documents/My_Reports/loopring/images/fee calculation.png)

3. Balance Check

   ![image-20190731142036411](/Users/yueawang/Documents/My_Reports/loopring/images/balance check gadget.png)

4. Poseidon Hash Gadget

   就是一个计算Poseidon hash的电路，算法不复杂，主要说明一下参数

   ```c++
   template<unsigned param_t, unsigned param_c, unsigned param_F, unsigned param_P, unsigned nInputs, unsigned nOutputs, bool constrainOutputs=true>
   class Poseidon_gadget_T : public GadgetT
   {
   	...
   }
   ```

   其中，t是sbox的个数，c是padding capacity，用于保证hash的安全性，一般来说选择2x的安全比特数，比如128bit security需要选择c=256。F是full round个数，P是partial round个数，似乎没有特别的要求（论文提到$F\geq6$，可以看到代码里F都等于6），后面input和output就是输入输出的参数个数，目前电路代码内部的变量字长是256bit，因此选择t和c的时候要结合一起考虑。

   ```c++
   using HashMerkleTree = Poseidon_gadget_T<5, 1, 6, 52, 4, 1>;
   using HashAccountLeaf = Poseidon_gadget_T<5, 1, 6, 52, 4, 1>;
   using HashBalanceLeaf = Poseidon_gadget_T<5, 1, 6, 52, 2, 1>;
   using HashTradingHistoryLeaf = Poseidon_gadget_T<5, 1, 6, 52, 3, 1>;
   ```

5. merkle_path_selector_4

   这个是验证poseidon hash merkle tree的电路的一部分，有一点值得注意的地方就是下面这个真值表的计算。

   ```c++
   class merkle_path_selector_4 : public GadgetT
   {
   public:
       OrGadget bit0_or_bit1;
       AndGadget bit0_and_bit1;
   
       TernaryGadget child0;
       TernaryGadget child1p;
       TernaryGadget child1;
       TernaryGadget child2p;
       TernaryGadget child2;
       TernaryGadget child3;
   
       VariableT m_bit0;
       VariableT m_bit1;
   
       // 00   x  y0  y1 y2
       // 01   y0 x   y1 y2
       // 10   y0 y1   x y2
       // 11   y0 y1  y2  x
       merkle_path_selector_4(...)
       ...
   }
   ```

   这里是用index（0～3）对应表示的path，一个更加直观的设计是用bool电路，即1000表示第一个位置，0100表示第二个位置，逻辑上看起来简单一些，但是对于4x的merkle tree，需要多2个电路变量（variables），这里的设计逻辑略复杂，但是节约了变量（其实还有另外一个好处，ID的>>2 & 0x3[0b11]正好是merkle path上的index，因此不需要额外的逻辑处理index，直接用ID加上各个位置的mask即可），这个复杂的逻辑长这样：

   ```c++
       child0(pb, bit0_or_bit1.result(), sideNodes[0], input, FMT(prefix, ".child0")),
       child1p(pb, bit0, input, sideNodes[0], FMT(prefix, ".child1p")),
       child1(pb, bit1, sideNodes[1], child1p.result(), FMT(prefix, ".child1")),
       child2p(pb, bit0, sideNodes[2], input, FMT(prefix, ".child2p")),
       child2(pb, bit1, child2p.result(), sideNodes[1], FMT(prefix, ".child2")),
       child3(pb, bit0_and_bit1.result(), input, sideNodes[2], FMT(prefix, ".child3"))
   ```

   难以理解的地方在于1p和2p。下面用设计图来说明该选择算法：

   ![image-20190803163045704](/Users/yueawang/Documents/My_Reports/loopring/images/4x path selector view.png)

   左边表示的是4x树的path selector算法，对于child0来说，他只有input和sibling0两个选择，由于input和sibling信息都是顺序排列的，所以child0不可能选择sibling1，因此1bit信息（这里用的bit0 | bit1）就可以区分。而对于child1来说，他有3个选择，因此需要2bit的信息才能区分，同样的，child2也存在这个问题，而child3和child0一样，1bit信息足够。所以代码里面child0和child3不需要额外的处理，而child1和child2分别需要child1p和child2p（各自包含1bit信息）来区分他们走的那一条path。基于这个设计思路，我们可以比较容易（理论上）的构造一个8x的merkle path selector，如右图所示，很显然，我们要做的就是通过3个bit的信息，构造出child0, child1/1p, child2/2p, ..., child6/6p和child7。


## 3. RingSettlement电路笔记

### 3.1 相关各方：

1. 账户：A(maker/taker)，B(maker/taker)，Matcher，Protocaler和Operator（收税）
2. Token：TokenSold，TokenBuy，TokenFee。

他们之间的关系基本如下，未来不同的fee model可能有区别。

![image-20190802163217743](/Users/yueawang/Documents/My_Reports/loopring/images/ringsettlement characters view.png)

### 3.2 基本逻辑

电路的基本逻辑和之前的Deposit，OrderCancel一样，输入是RingSettlementBlock，输出是一批publicData的hash值，中间电路由若干RingSettlementGadget组成，加上一批外围验证的逻辑，top level框图如下，可以看到电路的基本设计是一致的：

![image-20190801221206000](/Users/yueawang/Documents/My_Reports/loopring/images/ringsettlement_top_view.png)

中间有些value需要开启onchainDataAvailable才会加入到hash计算中，因此用虚线标注，但不影响整体逻辑。

### 3.3 Unflatten Circuit

显然我们主要关注RingSettlementGadget的实现，结合后段的数据结构来看：

```js
class Ring
{
    orderA: Order,
    orderB: Order,

    ringMatcherAccountID: number,
    tokenID: number,
    fee: string,
    nonce: number,

    ringMatcherSignature: Signature,
    dualAuthASignature: Signature,
    dualAuthBSignature: Signature,
}

class RingSettlement
{
    ring: Ring,

    # The starting merkle root
    accountsMerkleRoot: string,

    # Trade history update data of the orders
    tradeHistoryUpdate_A: TradeHistoryUpdate,
    tradeHistoryUpdate_B: TradeHistoryUpdate,

    # OrderA:
    # Balance update data for tokenS, tokenB and tokenF
    # Account update data
    balanceUpdateS_A: BalanceUpdate,
    balanceUpdateB_A: BalanceUpdate,
    accountUpdate_A: AccountUpdate,

    # OrderB:
    # Balance update data for tokenS, tokenB and tokenF
    # Account update data
    balanceUpdateS_B: BalanceUpdate,
    balanceUpdateB_B: BalanceUpdate,
    accountUpdate_B: AccountUpdate,

    # Ring-matcher:
    # Balance update data for tokenB of orderA and orderB (fee/rebate/protocol fee)
    # and token used for paying the operator
    # Account update data
    balanceUpdateA_M: BalanceUpdate,
    balanceUpdateB_M: BalanceUpdate,
    balanceUpdateO_M: BalanceUpdate,
    accountUpdate_M: AccountUpdate,

    # Balance update data for protocol fee payments
    balanceUpdateA_P: BalanceUpdate,
    balanceUpdateB_P: BalanceUpdate,

    # Balance update data for fee payment by the ring-matcher
    balanceUpdateF_O: BalanceUpdate,
}

class RingSettlementBlock
{
    exchangeID: number,

    merkleRootBefore: string,
    merkleRootAfter: string,

    # Timestamp used in this block
    timestamp: number,

    # Protocol fees used in this block
    protocolTakerFeeBips: number;
    protocolMakerFeeBips: number;

    # Protocol fee account update data (account 0)
    accountUpdate_P: AccountUpdate,

    # Operator:
    # Account update data
    operatorAccountID: number,
    accountUpdate_O: AccountUpdate,

    ringSettlements: RingSettlement[],
}
```

关系如下：

![image-20190801223937621](/Users/yueawang/Documents/My_Reports/loopring/images/ring_backend_class_view.png)

其中RingSettlementBlock作为RingSettlementCircuit电路的输入，其中主要部分RingSettlementGadget就是在验证对RingSettlement的操作是否有效。RingSettleGadget的声明（部分）如下，显然是在验证RingSettlement的计算。

```c++
class RingSettlementGadget : public GadgetT
{
public:
    const jubjub::VariablePointT publicKey;
    libsnark::dual_variable_gadget<FieldT> ringMatcherAccountID;
    VariableArrayT tokenID;
    libsnark::dual_variable_gadget<FieldT> fee;
    FloatGadget fFee;
    EnsureAccuracyGadget ensureAccuracyFee;
    libsnark::dual_variable_gadget<FieldT> nonce_before;
    UnsafeAddGadget nonce_after;

    OrderGadget orderA;
    OrderGadget orderB;

    OrderMatchingGadget orderMatching;

    TernaryGadget uFillS_A;
    TernaryGadget uFillS_B;

    FloatGadget fillS_A;
    FloatGadget fillS_B;

    EnsureAccuracyGadget ensureAccuracyFillS_A;
    EnsureAccuracyGadget ensureAccuracyFillS_B;

    TernaryGadget filledA;
    TernaryGadget filledB;
    UnsafeAddGadget filledAfterA;
    UnsafeAddGadget filledAfterB;

    FeeCalculatorGadget feeCalculatorA;
    FeeCalculatorGadget feeCalculatorB;

    DynamicVariableGadget balanceS_A;
    DynamicVariableGadget balanceB_A;
    DynamicVariableGadget balanceS_B;
    DynamicVariableGadget balanceB_B;
    DynamicVariableGadget balanceA_P;
    DynamicVariableGadget balanceB_P;
    DynamicVariableGadget balanceA_M;
    DynamicVariableGadget balanceB_M;
    DynamicVariableGadget balanceO_M;
    DynamicVariableGadget balanceF_O;

    TransferGadget fillBB_from_balanceSA_to_balanceBB;
    TransferGadget fillSB_from_balanceSB_to_balanceBA;
    TransferGadget feeA_from_balanceBA_to_balanceAM;
    TransferGadget feeB_from_balanceBB_to_balanceBM;
    TransferGadget rebateA_from_balanceAM_to_balanceBA;
    TransferGadget rebateB_from_balanceBM_to_balanceBB;
    TransferGadget protocolFeeA_from_balanceAM_to_balanceAP;
    TransferGadget protocolFeeB_from_balanceBM_to_balanceBP;
    TransferGadget ringFee_from_balanceOM_to_balanceO;

    UpdateTradeHistoryGadget updateTradeHistoryA;
    UpdateTradeHistoryGadget updateTradeHistoryB;

    UpdateBalanceGadget updateBalanceS_A;
    UpdateBalanceGadget updateBalanceB_A;
    VariableT nonce_A;
    UpdateAccountGadget updateAccount_A;

    UpdateBalanceGadget updateBalanceS_B;
    UpdateBalanceGadget updateBalanceB_B;
    VariableT nonce_B;
    UpdateAccountGadget updateAccount_B;

    UpdateBalanceGadget updateBalanceA_M;
    UpdateBalanceGadget updateBalanceB_M;
    UpdateBalanceGadget updateBalanceO_M;
    UpdateAccountGadget updateAccount_M;

    UpdateBalanceGadget updateBalanceA_P;
    UpdateBalanceGadget updateBalanceB_P;

    UpdateBalanceGadget updateBalanceF_O;
    ...
}
```

这里UpdateXXX，TernaryGadget，feeCalculate之前都出现过。简单描述一下几个新加入的电路逻辑：

1. OrderGadget和OrderMatchingGadget

   内部验证order的创建，签名，各种参数，比如tokenS_neq_tokenB保证$tokenA \neq tokenB$。以及taker/maker的buy/sell/fill参数是否正确，具体要结合业务逻辑看，电路本身比较简单，基本都是判断等于，小于这样的关系。

2. DynamicVariableGadget

   个人感觉这个是一个电路实现上的技巧，首先声明和创建对象的地方是这样的

   ```c++
   class DynamicVariableGadget : public GadgetT
   {
   public:
       std::vector<VariableT> variables; // only 1 member
   }
   
   class RingSettlementGadget : public GadgetT
   {
   ...
   public:
       DynamicVariableGadget balanceS_A;
       DynamicVariableGadget balanceB_A;
       DynamicVariableGadget balanceS_B;
       DynamicVariableGadget balanceB_B;
       DynamicVariableGadget balanceA_P;
       DynamicVariableGadget balanceB_P;
       DynamicVariableGadget balanceA_M;
       DynamicVariableGadget balanceB_M;
       DynamicVariableGadget balanceO_M;
       DynamicVariableGadget balanceF_O;
   ...
   }
   ```

   使用起来是这样的：

   ```c++
           // Transfers tokens
           fillBB_from_balanceSA_to_balanceBB(pb, balanceS_A, balanceB_B, fillS_A.value(), FMT(prefix, ".fillBB_from_balanceSA_to_balanceBB")),
           fillSB_from_balanceSB_to_balanceBA(pb, balanceS_B, balanceB_A, fillS_B.value(), FMT(prefix, ".fillSB_from_balanceSB_to_balanceBA")),
           // Fees
           feeA_from_balanceBA_to_balanceAM(pb, balanceB_A, balanceA_M, feeCalculatorA.getFee(), FMT(prefix, ".feeA_from_balanceBA_to_balanceAM")),
           feeB_from_balanceBB_to_balanceBM(pb, balanceB_B, balanceB_M, feeCalculatorB.getFee(), FMT(prefix, ".feeB_from_balanceBB_to_balanceBM")),
           // Rebates
           rebateA_from_balanceAM_to_balanceBA(pb, balanceA_M, balanceB_A, feeCalculatorA.getRebate(), FMT(prefix, ".rebateA_from_balanceAM_to_balanceBA")),
           rebateB_from_balanceBM_to_balanceBB(pb, balanceB_M, balanceB_B, feeCalculatorB.getRebate(), FMT(prefix, ".rebateB_from_balanceBM_to_balanceBB")),
           // Protocol fees
           protocolFeeA_from_balanceAM_to_balanceAP(pb, balanceA_M, balanceA_P, feeCalculatorA.getProtocolFee(), FMT(prefix, ".protocolFeeA_from_balanceAM_to_balanceAP")),
           protocolFeeB_from_balanceBM_to_balanceBP(pb, balanceB_M, balanceB_P, feeCalculatorB.getProtocolFee(), FMT(prefix, ".protocolFeeB_from_balanceBM_to_balanceBP")),
           // Ring fee
           ringFee_from_balanceOM_to_balanceO(pb, balanceO_M, balanceF_O, fFee.value(), FMT(prefix, ".ringFee_from_balanceOM_to_balanceO")),
   ```

   这里注意每一个transfer电路都会去拿这些balance的最新的值，即balanceX_X.back()，然后每个电路的输出会把输出（也就是新的值的variableT）push_back()到这个vector里面去。注意这里其实并不是动态的挑选variable，因为每个电路的输出都是预先定义好的，理论上只要仔细加上命名合理，全部用中间的out结果是没问题的。但是这样做在代码的组织上就比较好看了，是一个值得学习的小技巧。基本的逻辑如下所示：

   ![image-20190802175614989](/Users/yueawang/Documents/My_Reports/loopring/images/dynamic_variables.png)

   当然直接拿这些中间电路的out variable是一样的，比如OrderCancel电路里面计算fee的时候就没有用这个技巧，应该是因为那边计算的级数没有这里多，所以改善代码的意义不大。

3. TransferGadget

   比较简单，就是一步一步处理交易，收取/分发各种费用。内部就是before和after的各种check了

   ```c++
      1 TransferGadget fillBB_from_balanceSA_to_balanceBB;
      2 TransferGadget fillSB_from_balanceSB_to_balanceBA;
      3 TransferGadget feeA_from_balanceBA_to_balanceAM;
      4 TransferGadget feeB_from_balanceBB_to_balanceBM;
      5 TransferGadget rebateA_from_balanceAM_to_balanceBA;
      6 TransferGadget rebateB_from_balanceBM_to_balanceBB;
      7 TransferGadget protocolFeeA_from_balanceAM_to_balanceAP;
      8 TransferGadget protocolFeeB_from_balanceBM_to_balanceBP;
      9 TransferGadget ringFee_from_balanceOM_to_balanceO;
   ```

   ![image-20190802163757644](/Users/yueawang/Documents/My_Reports/loopring/images/ring transfer sequence.png)

   