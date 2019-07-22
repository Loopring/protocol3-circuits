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

    libsnark::dual_variable_gadget<FieldT> orderID;
    libsnark::dual_variable_gadget<FieldT> accountID;
    libsnark::dual_variable_gadget<FieldT> tokenS;
    libsnark::dual_variable_gadget<FieldT> tokenB;
    libsnark::dual_variable_gadget<FieldT> amountS;
    libsnark::dual_variable_gadget<FieldT> amountB;
    libsnark::dual_variable_gadget<FieldT> allOrNone;
    libsnark::dual_variable_gadget<FieldT> validSince;
    libsnark::dual_variable_gadget<FieldT> validUntil;
    libsnark::dual_variable_gadget<FieldT> maxFeeBips;
    libsnark::dual_variable_gadget<FieldT> buy;

    libsnark::dual_variable_gadget<FieldT> feeBips;
    libsnark::dual_variable_gadget<FieldT> rebateBips;

    libsnark::dual_variable_gadget<FieldT> feeOrRebateBips;
    LeqGadget bRebateNonZero;
    UnsafeAddGadget feeAddRebate;
    ForceEqualGadget validateFeeOrRebateBips;

    ForceZeroAorBGadget feeOrRebateZero;
    ForceLeqGadget validateFeeBips;

    ForceNotEqualGadget tokenS_neq_tokenB;
    ForceNotZeroGadget amountS_notZero;
    ForceNotZeroGadget amountB_notZero;

    const jubjub::VariablePointT publicKey;

    VariableT tradeHistoryFilled;
    VariableT tradeHistoryCancelled;
    VariableT tradeHistoryOrderID;

    TradeHistoryTrimmingGadget tradeHistory;

    VariableT balanceS;
    VariableT balanceB;

    // Largest value in the order hash is currently 96bit so we can go up to t == 16
    // (but we need 3 inputs for capacity for 128bit security)
    // Packing small values together in a single input is also possible
    Poseidon_gadget_T<15, 1, 6, 53, 12, 1> hash;
    SignatureVerifier signatureVerifier;

    OrderGadget(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const Constants& constants,
        const VariableT& blockExchangeID,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

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

        feeBips(pb, NUM_BITS_BIPS, FMT(prefix, ".feeBips")),
        rebateBips(pb, NUM_BITS_BIPS, FMT(prefix, ".rebateBips")),

        feeOrRebateBips(pb, NUM_BITS_BIPS, FMT(prefix, ".feeOrRebateBips")),
        bRebateNonZero(pb, constants.zero, rebateBips.packed, NUM_BITS_BIPS, FMT(prefix, ".bRebateNonZero")),
        feeAddRebate(pb, feeBips.packed, rebateBips.packed, FMT(prefix, ".feeAddRebate")),
        validateFeeOrRebateBips(pb, feeAddRebate.result(), feeOrRebateBips.packed, FMT(prefix, ".validateFeeOrRebateBips")),

        feeOrRebateZero(pb, feeBips.packed, rebateBips.packed, FMT(prefix, ".feeOrRebateZero")),
        validateFeeBips(pb, feeBips.packed, maxFeeBips.packed, NUM_BITS_BIPS, FMT(prefix, ".feeBips <= maxFeeBips")),

        tokenS_neq_tokenB(pb, tokenS.packed, tokenB.packed, FMT(prefix, ".tokenS != tokenB")),
        amountS_notZero(pb, amountS.packed, FMT(prefix, ".tokenS != 0")),
        amountB_notZero(pb, amountB.packed, FMT(prefix, ".tokenB != 0")),

        publicKey(pb, FMT(prefix, ".publicKey")),

        tradeHistoryFilled(make_variable(pb, FMT(prefix, ".tradeHistoryFilled"))),
        tradeHistoryCancelled(make_variable(pb, FMT(prefix, ".tradeHistoryCancelled"))),
        tradeHistoryOrderID(make_variable(pb, FMT(prefix, ".tradeHistoryOrderID"))),

        tradeHistory(pb, constants, tradeHistoryFilled, tradeHistoryCancelled, tradeHistoryOrderID, orderID.packed, FMT(prefix, ".tradeHistory")),

        balanceS(make_variable(pb, FMT(prefix, ".balanceS"))),
        balanceB(make_variable(pb, FMT(prefix, ".balanceB"))),

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
            buy.packed
        }), FMT(this->annotation_prefix, ".hash")),
        signatureVerifier(pb, params, publicKey, hash.result(), FMT(prefix, ".signatureVerifier"))
    {

    }

    const VariableArrayT& getHash()
    {
        return signatureVerifier.getHash();
    }

    void generate_r1cs_witness(const Order& order, const Account& account,
                               const BalanceLeaf& balanceLeafS, const BalanceLeaf& balanceLeafB,
                               const TradeHistoryLeaf& tradeHistoryLeaf)
    {
        orderID.bits.fill_with_bits_of_field_element(pb, order.orderID);
        orderID.generate_r1cs_witness_from_bits();
        accountID.bits.fill_with_bits_of_field_element(pb, order.accountID);
        accountID.generate_r1cs_witness_from_bits();
        tokenS.bits.fill_with_bits_of_field_element(pb, order.tokenS);
        tokenS.generate_r1cs_witness_from_bits();
        tokenB.bits.fill_with_bits_of_field_element(pb, order.tokenB);
        tokenB.generate_r1cs_witness_from_bits();
        amountS.bits.fill_with_bits_of_field_element(pb, order.amountS);
        amountS.generate_r1cs_witness_from_bits();
        amountB.bits.fill_with_bits_of_field_element(pb, order.amountB);
        amountB.generate_r1cs_witness_from_bits();
        allOrNone.bits.fill_with_bits_of_field_element(pb, order.allOrNone);
        allOrNone.generate_r1cs_witness_from_bits();
        validSince.bits.fill_with_bits_of_field_element(pb, order.validSince);
        validSince.generate_r1cs_witness_from_bits();
        validUntil.bits.fill_with_bits_of_field_element(pb, order.validUntil);
        validUntil.generate_r1cs_witness_from_bits();
        maxFeeBips.bits.fill_with_bits_of_field_element(pb, order.maxFeeBips);
        maxFeeBips.generate_r1cs_witness_from_bits();
        buy.bits.fill_with_bits_of_field_element(pb, order.buy);
        buy.generate_r1cs_witness_from_bits();

        feeBips.bits.fill_with_bits_of_field_element(pb, order.feeBips);
        feeBips.generate_r1cs_witness_from_bits();
        rebateBips.bits.fill_with_bits_of_field_element(pb, order.rebateBips);
        rebateBips.generate_r1cs_witness_from_bits();

        feeOrRebateBips.bits.fill_with_bits_of_field_element(pb, order.feeBips + order.rebateBips);
        feeOrRebateBips.generate_r1cs_witness_from_bits();
        bRebateNonZero.generate_r1cs_witness();
        feeAddRebate.generate_r1cs_witness();
        validateFeeOrRebateBips.generate_r1cs_witness();

        feeOrRebateZero.generate_r1cs_witness();
        validateFeeBips.generate_r1cs_witness();

        tokenS_neq_tokenB.generate_r1cs_witness();
        amountS_notZero.generate_r1cs_witness();
        amountB_notZero.generate_r1cs_witness();

        pb.val(tradeHistoryFilled) = tradeHistoryLeaf.filled;
        pb.val(tradeHistoryCancelled) = tradeHistoryLeaf.cancelled;
        pb.val(tradeHistoryOrderID) = tradeHistoryLeaf.orderID;

        tradeHistory.generate_r1cs_witness();

        pb.val(balanceS) = balanceLeafS.balance;
        pb.val(balanceB) = balanceLeafB.balance;

        pb.val(publicKey.x) = account.publicKey.x;
        pb.val(publicKey.y) = account.publicKey.y;

        hash.generate_r1cs_witness();
        // print(pb, "orderHash", hash.result());
        signatureVerifier.generate_r1cs_witness(order.signature);
    }

    void generate_r1cs_constraints()
    {
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

        feeBips.generate_r1cs_constraints(true);
        rebateBips.generate_r1cs_constraints(true);

        feeOrRebateBips.generate_r1cs_constraints(true);
        bRebateNonZero.generate_r1cs_constraints();
        feeAddRebate.generate_r1cs_constraints();
        validateFeeOrRebateBips.generate_r1cs_constraints();

        feeOrRebateZero.generate_r1cs_constraints();
        validateFeeBips.generate_r1cs_constraints();

        tokenS_neq_tokenB.generate_r1cs_constraints();
        amountS_notZero.generate_r1cs_constraints();
        amountB_notZero.generate_r1cs_constraints();

        tradeHistory.generate_r1cs_constraints();

        hash.generate_r1cs_constraints();
        signatureVerifier.generate_r1cs_constraints();
    }
};

}

#endif
