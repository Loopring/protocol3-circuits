#ifndef _TRADINGHISTORYGADGETS_H_
#define _TRADINGHISTORYGADGETS_H_

#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "MerkleTree.h"

#include "ethsnarks.hpp"
#include "utils.hpp"

using namespace ethsnarks;

namespace Loopring
{

struct TradeHistoryState
{
    VariableT filled;
    VariableT cancelled;
    VariableT orderID;
};

class UpdateTradeHistoryGadget : public GadgetT
{
public:
    HashTradingHistoryLeaf leafBefore;
    HashTradingHistoryLeaf leafAfter;

    const VariableArrayT proof;
    MerklePathCheckT proofVerifierBefore;
    MerklePathT rootCalculatorAfter;

    UpdateTradeHistoryGadget(
        ProtoboardT& pb,
        const VariableT& merkleRoot,
        const VariableArrayT& address,
        const TradeHistoryState& before,
        const TradeHistoryState& after,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        leafBefore(pb, var_array({before.filled, before.cancelled, before.orderID}), FMT(prefix, ".leafBefore")),
        leafAfter(pb, var_array({after.filled, after.cancelled, after.orderID}), FMT(prefix, ".leafAfter")),

        proof(make_var_array(pb, TREE_DEPTH_TRADING_HISTORY * 3, FMT(prefix, ".proof"))),
        proofVerifierBefore(pb, TREE_DEPTH_TRADING_HISTORY, address, leafBefore.result(), merkleRoot, proof, FMT(prefix, ".pathBefore")),
        rootCalculatorAfter(pb, TREE_DEPTH_TRADING_HISTORY, address, leafAfter.result(), proof, FMT(prefix, ".pathAfter"))
    {

    }

    void generate_r1cs_witness(const Proof& _proof)
    {
        leafBefore.generate_r1cs_witness();
        leafAfter.generate_r1cs_witness();

        proof.fill_with_field_elements(pb, _proof.data);
        proofVerifierBefore.generate_r1cs_witness();
        rootCalculatorAfter.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        leafBefore.generate_r1cs_constraints();
        leafAfter.generate_r1cs_constraints();

        proofVerifierBefore.generate_r1cs_constraints();
        rootCalculatorAfter.generate_r1cs_constraints();
    }

    const VariableT& result() const
    {
        return rootCalculatorAfter.result();
    }
};

class TradeHistoryTrimmingGadget : public GadgetT
{
public:

    LeqGadget bNew;
    NotGadget bTrim;

    TernaryGadget filled;
    TernaryGadget cancelledToStore;
    TernaryGadget cancelled;
    TernaryGadget orderIDToStore;

    TradeHistoryTrimmingGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const VariableT& tradeHistoryFilled,
        const VariableT& tradeHistoryCancelled,
        const VariableT& tradeHistoryOrderID,
        const VariableT& orderID,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        bNew(pb, tradeHistoryOrderID, orderID, NUM_BITS_ORDERID, FMT(prefix, ".tradeHistoryOrderID <(=) orderID")),
        bTrim(pb, bNew.leq(), FMT(prefix, ".!bNew")),

        filled(pb, bNew.lt(), constants.zero, tradeHistoryFilled, FMT(prefix, ".filled")),
        cancelledToStore(pb, bNew.lt(), constants.zero, tradeHistoryCancelled, FMT(prefix, ".cancelledToStore")),
        cancelled(pb, bTrim.result(), constants.one, cancelledToStore.result(), FMT(prefix, ".cancelled")),
        orderIDToStore(pb, bNew.lt(), orderID, tradeHistoryOrderID, FMT(prefix, ".orderIDToStore"))
    {

    }

    void generate_r1cs_witness()
    {
        bNew.generate_r1cs_witness();
        bTrim.generate_r1cs_witness();

        filled.generate_r1cs_witness();
        cancelledToStore.generate_r1cs_witness();
        cancelled.generate_r1cs_witness();
        orderIDToStore.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        bNew.generate_r1cs_constraints();
        bTrim.generate_r1cs_constraints();

        filled.generate_r1cs_constraints();
        cancelledToStore.generate_r1cs_constraints();
        cancelled.generate_r1cs_constraints();
        orderIDToStore.generate_r1cs_constraints();
    }

    const VariableT& getFilled() const
    {
        return filled.result();
    }

    const VariableT& getCancelled() const
    {
        return cancelled.result();
    }

    const VariableT& getCancelledToStore() const
    {
        return cancelledToStore.result();
    }

    const VariableT& getOrderIDToStore() const
    {
        return orderIDToStore.result();
    }
};

}

#endif
