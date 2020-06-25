#ifndef _SPOTTRADECIRCUIT_H_
#define _SPOTTRADECIRCUIT_H_

#include "Circuit.h"
#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "ethsnarks.hpp"
#include "utils.hpp"

using namespace ethsnarks;

namespace Loopring
{

class SpotTradeCircuit : public BaseTransactionCircuit
{
public:
    // Orders
    OrderGadget orderA;
    OrderGadget orderB;

    // Balances
    DynamicVariableGadget balanceS_A;
    DynamicVariableGadget balanceB_A;
    DynamicVariableGadget balanceS_B;
    DynamicVariableGadget balanceB_B;
    DynamicVariableGadget balanceA_P;
    DynamicVariableGadget balanceB_P;
    DynamicVariableGadget balanceA_O;
    DynamicVariableGadget balanceB_O;

    // Order fills
    FloatGadget fillS_A;
    FloatGadget fillS_B;

    // Trade history
    TradeHistoryTrimmingGadget tradeHistory_A;
    TradeHistoryTrimmingGadget tradeHistory_B;

    // Match orders
    OrderMatchingGadget orderMatching;

    // Calculate fees
    FeeCalculatorGadget feeCalculatorA;
    FeeCalculatorGadget feeCalculatorB;

    /* Token Transfers */
    // Actual trade
    TransferGadget fillSA_from_balanceSA_to_balanceBB;
    TransferGadget fillSB_from_balanceSB_to_balanceBA;
    // Fees
    TransferGadget feeA_from_balanceBA_to_balanceAO;
    TransferGadget feeB_from_balanceBB_to_balanceBO;
    // Rebates
    TransferGadget rebateA_from_balanceAO_to_balanceBA;
    TransferGadget rebateB_from_balanceBO_to_balanceBB;
    // Protocol fees
    TransferGadget protocolFeeA_from_balanceAO_to_balanceAP;
    TransferGadget protocolFeeB_from_balanceBO_to_balanceBP;

    SpotTradeCircuit(
        ProtoboardT& pb,
        const TransactionState& state,
        const std::string& prefix
    ) :
        BaseTransactionCircuit(pb, state, prefix),

        // Orders
        orderA(pb, state.constants, state.exchangeID, FMT(prefix, ".orderA")),
        orderB(pb, state.constants, state.exchangeID, FMT(prefix, ".orderB")),

        balanceS_A(pb, state.accountA.balanceS.balance, FMT(prefix, ".balanceS_A")),
        balanceB_A(pb, state.accountA.balanceB.balance, FMT(prefix, ".balanceB_A")),
        balanceS_B(pb, state.accountB.balanceS.balance, FMT(prefix, ".balanceS_B")),
        balanceB_B(pb, state.accountB.balanceB.balance, FMT(prefix, ".balanceB_B")),
        balanceA_P(pb, state.pool.balanceA.balance, FMT(prefix, ".balanceA_P")),
        balanceB_P(pb, state.pool.balanceB.balance, FMT(prefix, ".balanceB_P")),
        balanceA_O(pb, state.oper.balanceA.balance, FMT(prefix, ".balanceA_O")),
        balanceB_O(pb, state.oper.balanceB.balance, FMT(prefix, ".balanceB_O")),

        // Order fills
        fillS_A(pb, state.constants, Float24Encoding, FMT(prefix, ".fillS_A")),
        fillS_B(pb, state.constants, Float24Encoding, FMT(prefix, ".fillS_B")),

        // Trade history
        tradeHistory_A(pb, state.constants, state.accountA.tradeHistory, orderA.orderID, FMT(prefix, ".tradeHistoryA")),
        tradeHistory_B(pb, state.constants, state.accountB.tradeHistory, orderB.orderID, FMT(prefix, ".tradeHistoryB")),

        // Match orders
        orderMatching(pb, state.constants, state.timestamp, orderA, orderB, tradeHistory_A, tradeHistory_B, fillS_A.value(), fillS_B.value(), FMT(prefix, ".orderMatching")),

        // Calculate fees
        feeCalculatorA(pb, state.constants, fillS_B.value(), state.protocolTakerFeeBips, orderA.feeBips.packed, orderA.rebateBips.packed, FMT(prefix, ".feeCalculatorA")),
        feeCalculatorB(pb, state.constants, fillS_A.value(), state.protocolMakerFeeBips, orderB.feeBips.packed, orderB.rebateBips.packed, FMT(prefix, ".feeCalculatorB")),

        /* Token Transfers */
        // Actual trade
        fillSA_from_balanceSA_to_balanceBB(pb, balanceS_A, balanceB_B, fillS_A.value(), FMT(prefix, ".fillBB_from_balanceSA_to_balanceBB")),
        fillSB_from_balanceSB_to_balanceBA(pb, balanceS_B, balanceB_A, fillS_B.value(), FMT(prefix, ".fillSB_from_balanceSB_to_balanceBA")),
        // Fees
        feeA_from_balanceBA_to_balanceAO(pb, balanceB_A, balanceA_O, feeCalculatorA.getFee(), FMT(prefix, ".feeA_from_balanceBA_to_balanceAO")),
        feeB_from_balanceBB_to_balanceBO(pb, balanceB_B, balanceB_O, feeCalculatorB.getFee(), FMT(prefix, ".feeB_from_balanceBB_to_balanceBO")),
        // Rebates
        rebateA_from_balanceAO_to_balanceBA(pb, balanceA_O, balanceB_A, feeCalculatorA.getRebate(), FMT(prefix, ".rebateA_from_balanceAO_to_balanceBA")),
        rebateB_from_balanceBO_to_balanceBB(pb, balanceB_O, balanceB_B, feeCalculatorB.getRebate(), FMT(prefix, ".rebateB_from_balanceBO_to_balanceBB")),
        // Protocol fees
        protocolFeeA_from_balanceAO_to_balanceAP(pb, balanceA_O, balanceA_P, feeCalculatorA.getProtocolFee(), FMT(prefix, ".protocolFeeA_from_balanceAO_to_balanceAP")),
        protocolFeeB_from_balanceBO_to_balanceBP(pb, balanceB_O, balanceB_P, feeCalculatorB.getProtocolFee(), FMT(prefix, ".protocolFeeB_from_balanceBO_to_balanceBP"))
    {
        setArrayOutput(tradeHistoryA_Address, subArray(orderA.orderID.bits, 0, NUM_BITS_TRADING_HISTORY));
        setOutput(tradeHistoryA_Filled, orderMatching.getFilledAfter_A());
        setOutput(tradeHistoryA_OrderId, orderA.orderID.packed);
        setArrayOutput(balanceA_S_Address, orderA.tokenS.bits);
        setOutput(balanceA_S_Balance, balanceS_A.back());
        setArrayOutput(balanceA_B_Address, orderA.tokenB.bits);
        setOutput(balanceA_B_Balance, balanceB_A.back());
        setArrayOutput(accountA_Address, orderA.accountID.bits);

        setArrayOutput(tradeHistoryB_Address, subArray(orderB.orderID.bits, 0, NUM_BITS_TRADING_HISTORY));
        setOutput(tradeHistoryB_Filled, orderMatching.getFilledAfter_B());
        setOutput(tradeHistoryB_OrderId, orderB.orderID.packed);
        setArrayOutput(balanceB_S_Address, orderB.tokenS.bits);
        setOutput(balanceB_S_Balance, balanceS_B.back());
        setArrayOutput(balanceB_B_Address, orderB.tokenB.bits);
        setOutput(balanceB_B_Balance, balanceB_B.back());
        setArrayOutput(accountB_Address, orderB.accountID.bits);

        setOutput(balanceP_A_Balance, balanceA_P.back());
        setOutput(balanceP_B_Balance, balanceB_P.back());

        setOutput(balanceO_A_Balance, balanceA_O.back());
        setOutput(balanceO_B_Balance, balanceB_O.back());

        setOutput(hash_A, orderA.hash.result());
        setOutput(hash_B, orderB.hash.result());
    }

    void generate_r1cs_witness(const SpotTrade& spotTrade)
    {
        // Orders
        orderA.generate_r1cs_witness(spotTrade.orderA);
        orderB.generate_r1cs_witness(spotTrade.orderB);

        // Order fills
        fillS_A.generate_r1cs_witness(spotTrade.fillS_A);
        fillS_B.generate_r1cs_witness(spotTrade.fillS_B);

        // Trade history
        tradeHistory_A.generate_r1cs_witness();
        tradeHistory_B.generate_r1cs_witness();

        // Match orders
        orderMatching.generate_r1cs_witness();

        // Calculate fees
        feeCalculatorA.generate_r1cs_witness();
        feeCalculatorB.generate_r1cs_witness();

        /* Token Transfers */
        // Actual trade
        fillSA_from_balanceSA_to_balanceBB.generate_r1cs_witness();
        fillSB_from_balanceSB_to_balanceBA.generate_r1cs_witness();
        // Fees
        feeA_from_balanceBA_to_balanceAO.generate_r1cs_witness();
        feeB_from_balanceBB_to_balanceBO.generate_r1cs_witness();
        // Rebates
        rebateA_from_balanceAO_to_balanceBA.generate_r1cs_witness();
        rebateB_from_balanceBO_to_balanceBB.generate_r1cs_witness();
        // Protocol fees
        protocolFeeA_from_balanceAO_to_balanceAP.generate_r1cs_witness();
        protocolFeeB_from_balanceBO_to_balanceBP.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        // Orders
        orderA.generate_r1cs_constraints();
        orderB.generate_r1cs_constraints();

        // Order fills
        fillS_A.generate_r1cs_constraints();
        fillS_B.generate_r1cs_constraints();

        // Trade history
        tradeHistory_A.generate_r1cs_constraints();
        tradeHistory_B.generate_r1cs_constraints();

        // Match orders
        orderMatching.generate_r1cs_constraints();

        // Calculate fees
        feeCalculatorA.generate_r1cs_constraints();
        feeCalculatorB.generate_r1cs_constraints();

        /* Token Transfers */
        // Actual trade
        fillSA_from_balanceSA_to_balanceBB.generate_r1cs_constraints();
        fillSB_from_balanceSB_to_balanceBA.generate_r1cs_constraints();
        // Fees
        feeA_from_balanceBA_to_balanceAO.generate_r1cs_constraints();
        feeB_from_balanceBB_to_balanceBO.generate_r1cs_constraints();
        // Rebates
        rebateA_from_balanceAO_to_balanceBA.generate_r1cs_constraints();
        rebateB_from_balanceBO_to_balanceBB.generate_r1cs_constraints();
        // Protocol fees
        protocolFeeA_from_balanceAO_to_balanceAP.generate_r1cs_constraints();
        protocolFeeB_from_balanceBO_to_balanceBP.generate_r1cs_constraints();
    }

    const VariableArrayT getPublicData() const
    {
        return flattenReverse({
            VariableArrayT(1, state.constants.zero), VariableArrayT(1, tradeHistory_A.getOverwrite()), subArray(orderA.orderID.bits, 0, NUM_BITS_TRADING_HISTORY),
            VariableArrayT(1, state.constants.zero), VariableArrayT(1, tradeHistory_B.getOverwrite()), subArray(orderB.orderID.bits, 0, NUM_BITS_TRADING_HISTORY),

            orderA.accountID.bits,
            orderB.accountID.bits,

            orderA.tokenS.bits,
            orderB.tokenS.bits,

            fillS_A.bits(),
            fillS_B.bits(),

            orderA.buy.bits, VariableArrayT(1, orderA.hasRebate()), orderA.feeOrRebateBips.bits,
            orderB.buy.bits, VariableArrayT(1, orderB.hasRebate()), orderB.feeOrRebateBips.bits,
        });
    }
};

}

#endif
