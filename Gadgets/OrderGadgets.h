#ifndef _ORDERGADGETS_H_
#define _ORDERGADGETS_H_

#include "TradingHistoryGadgets.h"
#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "ethsnarks.hpp"
#include "gadgets/poseidon.hpp"
#include "utils.hpp"

using namespace ethsnarks;

namespace Loopring
{

class OrderGadget : public GadgetT
{
public:

    // State
    const jubjub::VariablePointT publicKey;
    VariableT balanceS;
    VariableT balanceB;
    VariableT tradeHistoryFilled;
    VariableT tradeHistoryCancelled;
    VariableT tradeHistoryOrderID;

    // Inputs
    DualVariableGadget orderID;
    DualVariableGadget accountID;
    DualVariableGadget tokenS;
    DualVariableGadget tokenB;
    DualVariableGadget amountS;
    DualVariableGadget amountB;
    DualVariableGadget allOrNone;
    DualVariableGadget validSince;
    DualVariableGadget validUntil;
    DualVariableGadget maxFeeBips;
    DualVariableGadget buy;
    DualVariableGadget label;

    DualVariableGadget feeBips;
    DualVariableGadget rebateBips;

    // Checks
    RequireZeroAorBGadget feeOrRebateZero;
    RequireLeqGadget feeBips_leq_maxFeeBips;
    RequireNotEqualGadget tokenS_neq_tokenB;
    RequireNotZeroGadget amountS_notZero;
    RequireNotZeroGadget amountB_notZero;

    // FeeOrRebate public input
    IsNonZero bRebateNonZero;
    UnsafeAddGadget fee_plus_rebate;
    libsnark::dual_variable_gadget<FieldT> feeOrRebateBips;

    // Trade history
    TradeHistoryTrimmingGadget tradeHistory;

    // Signature
    Poseidon_gadget_T<14, 1, 6, 53, 13, 1> hash;
    SignatureVerifier signatureVerifier;

    OrderGadget(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const Constants& constants,
        const VariableT& blockExchangeID,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        // State
        publicKey(pb, FMT(prefix, ".publicKey")),
        balanceS(make_variable(pb, FMT(prefix, ".balanceS"))),
        balanceB(make_variable(pb, FMT(prefix, ".balanceB"))),
        tradeHistoryFilled(make_variable(pb, FMT(prefix, ".tradeHistoryFilled"))),
        tradeHistoryCancelled(make_variable(pb, FMT(prefix, ".tradeHistoryCancelled"))),
        tradeHistoryOrderID(make_variable(pb, FMT(prefix, ".tradeHistoryOrderID"))),

        // Inputs
        orderID(pb, NUM_BITS_ORDERID, FMT(prefix, ".orderID")),
        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        tokenS(pb, NUM_BITS_TOKEN, FMT(prefix, ".tokenS")),
        tokenB(pb, NUM_BITS_TOKEN, FMT(prefix, ".tokenB")),
        amountS(pb, NUM_BITS_AMOUNT, FMT(prefix, ".amountS")),
        amountB(pb, NUM_BITS_AMOUNT, FMT(prefix, ".amountB")),
        allOrNone(pb, 1, FMT(prefix, ".allOrNone")),
        validSince(pb, NUM_BITS_TIMESTAMP, FMT(prefix, ".validSince")),
        validUntil(pb, NUM_BITS_TIMESTAMP, FMT(prefix, ".validUntil")),
        maxFeeBips(pb, NUM_BITS_BIPS, FMT(prefix, ".maxFeeBips")),
        buy(pb, 1, FMT(prefix, ".buy")),
        label(pb, NUM_BITS_LABEL, FMT(prefix, ".label")),

        feeBips(pb, NUM_BITS_BIPS, FMT(prefix, ".feeBips")),
        rebateBips(pb, NUM_BITS_BIPS, FMT(prefix, ".rebateBips")),

        // Checks
        feeOrRebateZero(pb, feeBips.packed, rebateBips.packed, FMT(prefix, ".feeOrRebateZero")),
        feeBips_leq_maxFeeBips(pb, feeBips.packed, maxFeeBips.packed, NUM_BITS_BIPS, FMT(prefix, ".feeBips <= maxFeeBips")),
        tokenS_neq_tokenB(pb, tokenS.packed, tokenB.packed, FMT(prefix, ".tokenS != tokenB")),
        amountS_notZero(pb, amountS.packed, FMT(prefix, ".amountS != 0")),
        amountB_notZero(pb, amountB.packed, FMT(prefix, ".amountB != 0")),

        // FeeOrRebate public input
        fee_plus_rebate(pb, feeBips.packed, rebateBips.packed, FMT(prefix, ".fee_plus_rebate")),
        feeOrRebateBips(pb, fee_plus_rebate.result(), NUM_BITS_BIPS, FMT(prefix, ".feeOrRebateBips")),
        bRebateNonZero(pb, rebateBips.packed, FMT(prefix, ".bRebateNonZero")),

        // Trade history
        tradeHistory(pb, constants, tradeHistoryFilled, tradeHistoryCancelled, tradeHistoryOrderID, orderID.packed, FMT(prefix, ".tradeHistory")),

        // Signature
        hash(pb, var_array({
            blockExchangeID,
            orderID.packed,
            accountID.packed,
            tokenS.packed,
            tokenB.packed,
            amountS.packed,
            amountB.packed,
            allOrNone.packed,
            validSince.packed,
            validUntil.packed,
            maxFeeBips.packed,
            buy.packed,
            label.packed
        }), FMT(this->annotation_prefix, ".hash")),
        signatureVerifier(pb, params, publicKey, hash.result(), FMT(prefix, ".signatureVerifier"))
    {

    }

    void generate_r1cs_witness(const Order& order, const Account& account,
                               const BalanceLeaf& balanceLeafS, const BalanceLeaf& balanceLeafB,
                               const TradeHistoryLeaf& tradeHistoryLeaf)
    {
        // State
        pb.val(publicKey.x) = account.publicKey.x;
        pb.val(publicKey.y) = account.publicKey.y;
        pb.val(balanceS) = balanceLeafS.balance;
        pb.val(balanceB) = balanceLeafB.balance;
        pb.val(tradeHistoryFilled) = tradeHistoryLeaf.filled;
        pb.val(tradeHistoryCancelled) = tradeHistoryLeaf.cancelled;
        pb.val(tradeHistoryOrderID) = tradeHistoryLeaf.orderID;

        // Inputs
        orderID.generate_r1cs_witness(pb, order.orderID);
        accountID.generate_r1cs_witness(pb, order.accountID);
        tokenS.generate_r1cs_witness(pb, order.tokenS);
        tokenB.generate_r1cs_witness(pb, order.tokenB);
        amountS.generate_r1cs_witness(pb, order.amountS);
        amountB.generate_r1cs_witness(pb, order.amountB);
        allOrNone.generate_r1cs_witness(pb, order.allOrNone);
        validSince.generate_r1cs_witness(pb, order.validSince);
        validUntil.generate_r1cs_witness(pb, order.validUntil);
        maxFeeBips.generate_r1cs_witness(pb, order.maxFeeBips);
        buy.generate_r1cs_witness(pb, order.buy);
        label.generate_r1cs_witness(pb, order.label);

        feeBips.generate_r1cs_witness(pb, order.feeBips);
        rebateBips.generate_r1cs_witness(pb, order.rebateBips);

        // Checks
        feeOrRebateZero.generate_r1cs_witness();
        feeBips_leq_maxFeeBips.generate_r1cs_witness();
        tokenS_neq_tokenB.generate_r1cs_witness();
        amountS_notZero.generate_r1cs_witness();
        amountB_notZero.generate_r1cs_witness();

        // FeeOrRebate public input
        fee_plus_rebate.generate_r1cs_witness();
        feeOrRebateBips.generate_r1cs_witness_from_packed();
        bRebateNonZero.generate_r1cs_witness();

        // Trade history
        tradeHistory.generate_r1cs_witness();

        // Signature
        hash.generate_r1cs_witness();
        signatureVerifier.generate_r1cs_witness(order.signature);
    }

    void generate_r1cs_constraints()
    {
        // Inputs
        accountID.generate_r1cs_constraints(true);
        tokenS.generate_r1cs_constraints(true);
        tokenB.generate_r1cs_constraints(true);
        amountS.generate_r1cs_constraints(true);
        amountB.generate_r1cs_constraints(true);
        allOrNone.generate_r1cs_constraints(true);
        validSince.generate_r1cs_constraints(true);
        validUntil.generate_r1cs_constraints(true);
        maxFeeBips.generate_r1cs_constraints(true);
        buy.generate_r1cs_constraints(true);
        label.generate_r1cs_constraints(true);

        feeBips.generate_r1cs_constraints(true);
        rebateBips.generate_r1cs_constraints(true);

        // Checks
        feeOrRebateZero.generate_r1cs_constraints();
        feeBips_leq_maxFeeBips.generate_r1cs_constraints();
        tokenS_neq_tokenB.generate_r1cs_constraints();
        amountS_notZero.generate_r1cs_constraints();
        amountB_notZero.generate_r1cs_constraints();

        // FeeOrRebate public input
        fee_plus_rebate.generate_r1cs_constraints();
        feeOrRebateBips.generate_r1cs_constraints(true);
        bRebateNonZero.generate_r1cs_constraints();

        // Trade history
        tradeHistory.generate_r1cs_constraints();

        // Signature
        hash.generate_r1cs_constraints();
        signatureVerifier.generate_r1cs_constraints();
    }

    const VariableArrayT& getHash()
    {
        return signatureVerifier.getHash();
    }
};

}

#endif
