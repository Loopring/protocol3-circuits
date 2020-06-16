#ifndef _BASETRANSACTIONCIRCUIT_H_
#define _BASETRANSACTIONCIRCUIT_H_

#include "Circuit.h"
#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "../ThirdParty/BigIntHeader.hpp"
#include "ethsnarks.hpp"
#include "utils.hpp"

using namespace ethsnarks;

namespace Loopring
{

struct TransactionAccountState : public GadgetT
{
    TradeHistoryGadget tradeHistory;
    BalanceGadget balanceS;
    BalanceGadget balanceB;
    AccountGadget account;

    TransactionAccountState(
        ProtoboardT& pb,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        tradeHistory(pb, FMT(prefix, ".tradeHistory")),
        balanceS(pb, FMT(prefix, ".balanceS")),
        balanceB(pb, FMT(prefix, ".balanceB")),
        account(pb, FMT(prefix, ".account"))
    {

    }

    void generate_r1cs_witness(const Account& accountLeaf, const BalanceLeaf& balanceLeafS, const BalanceLeaf& balanceLeafB, const TradeHistoryLeaf& tradeHistoryLeaf)
    {
        tradeHistory.generate_r1cs_witness(tradeHistoryLeaf);
        balanceS.generate_r1cs_witness(balanceLeafS);
        balanceB.generate_r1cs_witness(balanceLeafB);
        account.generate_r1cs_witness(accountLeaf);
    }
};

struct TransactionAccountBalancesState : public GadgetT
{
    BalanceGadget balanceA;
    BalanceGadget balanceB;

    TransactionAccountBalancesState(
        ProtoboardT& pb,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        balanceA(pb, FMT(prefix, ".balanceA")),
        balanceB(pb, FMT(prefix, ".balanceB"))
    {

    }

    void generate_r1cs_witness(const BalanceLeaf& balanceLeafA, const BalanceLeaf& balanceLeafB)
    {
        balanceA.generate_r1cs_witness(balanceLeafA);
        balanceB.generate_r1cs_witness(balanceLeafB);
    }
};

struct TransactionState : public GadgetT
{
    const Constants& constants;

    const VariableT& exchangeID;
    const VariableT& timestamp;
    const VariableT& protocolTakerFeeBips;
    const VariableT& protocolMakerFeeBips;
    const VariableT& numConditionalTransactions;

    TransactionAccountState accountA;
    TransactionAccountState accountB;
    TransactionAccountBalancesState pool;
    TransactionAccountBalancesState oper;

    TransactionState(
        ProtoboardT& pb,
        const Constants& _constants,
        const VariableT& _exchangeID,
        const VariableT& _timestamp,
        const VariableT& _protocolTakerFeeBips,
        const VariableT& _protocolMakerFeeBips,
        const VariableT& _numConditionalTransactions,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        constants(_constants),

        exchangeID(_exchangeID),
        timestamp(_timestamp),
        protocolTakerFeeBips(_protocolTakerFeeBips),
        protocolMakerFeeBips(_protocolMakerFeeBips),
        numConditionalTransactions(_numConditionalTransactions),

        accountA(pb, FMT(prefix, ".accountA")),
        accountB(pb, FMT(prefix, ".accountB")),
        pool(pb, FMT(prefix, ".pool")),
        oper(pb, FMT(prefix, ".oper"))
    {

    }

    void generate_r1cs_witness(const Account& account_A, const BalanceLeaf& balanceLeafS_A, const BalanceLeaf& balanceLeafB_A, const TradeHistoryLeaf& tradeHistoryLeaf_A,
                               const Account& account_B, const BalanceLeaf& balanceLeafS_B, const BalanceLeaf& balanceLeafB_B, const TradeHistoryLeaf& tradeHistoryLeaf_B,
                               const BalanceLeaf& balanceLeafS_P, const BalanceLeaf& balanceLeafB_P,
                               const BalanceLeaf& balanceLeafS_O, const BalanceLeaf& balanceLeafB_O)
    {
        accountA.generate_r1cs_witness(account_A, balanceLeafS_A, balanceLeafB_A, tradeHistoryLeaf_A);
        accountB.generate_r1cs_witness(account_B, balanceLeafS_B, balanceLeafB_B, tradeHistoryLeaf_B);
        pool.generate_r1cs_witness(balanceLeafS_P, balanceLeafB_P);
        oper.generate_r1cs_witness(balanceLeafS_O, balanceLeafB_O);
    }
};


struct SelectorBitsGadget : public GadgetT
{
    std::vector<EqualGadget> bits;

    SelectorBitsGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const VariableT& type,
        unsigned int maxBits,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix)
    {
        for (unsigned int i = 0; i < maxBits; i++)
        {
            bits.emplace_back(pb, type, constants.values[i], FMT(annotation_prefix, ".bits"));
        }
    }

    void generate_r1cs_witness()
    {
        for (unsigned int i = 0; i < bits.size(); i++)
        {
            bits[i].generate_r1cs_witness();
        }
    }

    void generate_r1cs_constraints()
    {
        for (unsigned int i = 0; i < bits.size(); i++)
        {
            bits[i].generate_r1cs_constraints();
        }
    }

    std::vector<VariableT> result() const
    {
        std::vector<VariableT> res;
        for (unsigned int i = 0; i < bits.size(); i++)
        {
            res.emplace_back(bits[i].result());
        }
        return res;
    }
};

enum TxVariable
{
    tradeHistoryA_Address,
    tradeHistoryA_Filled,
    tradeHistoryA_OrderId,

    balanceA_S_Address,
    balanceA_S_Balance,
    balanceA_S_Position,
    balanceA_S_FundingIndex,

    balanceA_B_Address,
    balanceA_B_Balance,

    accountA_Address,
    accountA_Owner,
    accountA_PublicKeyX,
    accountA_PublicKeyY,
    accountA_Nonce,


    tradeHistoryB_Address,
    tradeHistoryB_Filled,
    tradeHistoryB_OrderId,

    balanceB_S_Address,
    balanceB_S_Balance,
    balanceB_S_Position,
    balanceB_S_FundingIndex,

    balanceB_B_Address,
    balanceB_B_Balance,

    accountB_Address,
    accountB_Owner,
    accountB_PublicKeyX,
    accountB_PublicKeyY,
    accountB_Nonce,


    balanceP_A_Balance,
    balanceP_B_Balance,


    balanceO_A_Balance,
    balanceO_B_Balance,


    hash_A,
    signatureRequired_A,

    hash_B,
    signatureRequired_B,


    misc_NumConditionalTransactions
};

class BaseTransactionCircuit : public GadgetT
{
public:
    const TransactionState& state;

    std::map<TxVariable, VariableT> uOutputs;
    std::map<TxVariable, VariableArrayT> aOutputs;

    BaseTransactionCircuit(
        ProtoboardT& pb,
        const TransactionState& _state,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        state(_state)
    {
        aOutputs[tradeHistoryA_Address] = VariableArrayT(NUM_BITS_TRADING_HISTORY, state.constants.zero);
        uOutputs[tradeHistoryA_Filled] = state.accountA.tradeHistory.filled;
        uOutputs[tradeHistoryA_OrderId] = state.accountA.tradeHistory.orderID;

        aOutputs[balanceA_S_Address] = VariableArrayT(NUM_BITS_TOKEN, state.constants.zero);
        uOutputs[balanceA_S_Balance] = state.accountA.balanceS.balance;

        aOutputs[balanceA_B_Address] = VariableArrayT(NUM_BITS_TOKEN, state.constants.zero);
        uOutputs[balanceA_B_Balance] = state.accountA.balanceB.balance;

        aOutputs[accountA_Address] = flatten({VariableArrayT(1, state.constants.one), VariableArrayT(NUM_BITS_ACCOUNT - 1, state.constants.zero)});
        uOutputs[accountA_Owner] = state.accountA.account.owner;
        uOutputs[accountA_PublicKeyX] = state.accountA.account.publicKey.x;
        uOutputs[accountA_PublicKeyY] = state.accountA.account.publicKey.y;
        uOutputs[accountA_Nonce] = state.accountA.account.nonce;


        aOutputs[tradeHistoryB_Address] = VariableArrayT(NUM_BITS_TRADING_HISTORY, state.constants.zero);
        uOutputs[tradeHistoryB_Filled] = state.accountB.tradeHistory.filled;
        uOutputs[tradeHistoryB_OrderId] = state.accountB.tradeHistory.orderID;

        aOutputs[balanceB_S_Address] = VariableArrayT(NUM_BITS_TOKEN, state.constants.zero);
        uOutputs[balanceB_S_Balance] = state.accountB.balanceS.balance;

        aOutputs[balanceB_B_Address] = VariableArrayT(NUM_BITS_TOKEN, state.constants.zero);
        uOutputs[balanceB_B_Balance] = state.accountB.balanceB.balance;


        aOutputs[accountB_Address] = flatten({VariableArrayT(1, state.constants.one), VariableArrayT(NUM_BITS_ACCOUNT - 1, state.constants.zero)});
        uOutputs[accountB_Owner] = state.accountB.account.owner;
        uOutputs[accountB_PublicKeyX] = state.accountB.account.publicKey.x;
        uOutputs[accountB_PublicKeyY] = state.accountB.account.publicKey.y;
        uOutputs[accountB_Nonce] = state.accountB.account.nonce;


        uOutputs[balanceP_A_Balance] = state.pool.balanceA.balance;
        uOutputs[balanceP_B_Balance] = state.pool.balanceB.balance;


        uOutputs[balanceO_A_Balance] = state.oper.balanceA.balance;
        uOutputs[balanceO_B_Balance] = state.oper.balanceB.balance;


        uOutputs[hash_A] = state.constants.zero;
        uOutputs[signatureRequired_A] = state.constants.one;

        uOutputs[hash_B] = state.constants.zero;
        uOutputs[signatureRequired_B] = state.constants.one;


        uOutputs[misc_NumConditionalTransactions] = state.numConditionalTransactions;
    }

    const VariableT& getOutput(TxVariable txVariable) const
    {
        return uOutputs.at(txVariable);
    }

    const VariableArrayT& getArrayOutput(TxVariable txVariable) const
    {
        return aOutputs.at(txVariable);
    }

    void setOutput(TxVariable txVariable, const VariableT& var)
    {
        assert(uOutputs.find(txVariable) != uOutputs.end());
        uOutputs[txVariable] = var;
    }

    void setArrayOutput(TxVariable txVariable, const VariableArrayT& var)
    {
        assert(aOutputs.find(txVariable) != aOutputs.end());
        aOutputs[txVariable] = var;
    }

    virtual const VariableArrayT getPublicData() const = 0;
};

}

#endif