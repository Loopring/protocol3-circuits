#ifndef _RINGSETTLEMENTCIRCUIT_H_
#define _RINGSETTLEMENTCIRCUIT_H_

#include "../Utils/Constants.h"
#include "../Utils/Data.h"
#include "../Utils/Utils.h"
#include "../Gadgets/MatchingGadgets.h"
#include "../Gadgets/AccountGadgets.h"
#include "../Gadgets/TradingHistoryGadgets.h"
#include "../Gadgets/MathGadgets.h"

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "gadgets/subadd.hpp"

using namespace ethsnarks;

namespace Loopring
{

// Transforms the DA data for ring settlements
class TransformRingSettlementDataGadget : public GadgetT
{
public:

    const unsigned int ringSize = 20 * 8;

    VariableArrayT data;
    Bitstream transformedData;
    unsigned int numRings;

    std::vector<XorArrayGadget> xorGadgets;

    TransformRingSettlementDataGadget(
        ProtoboardT& pb,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix)
    {
        numRings = 0;
    }

    VariableArrayT result()
    {
        return flatten(transformedData.data);
    }

    void generate_r1cs_witness()
    {
        for (unsigned int i = 0; i < xorGadgets.size(); i++)
        {
            xorGadgets[i].generate_r1cs_witness();
        }
    }

    void generate_r1cs_constraints(unsigned int numRings, const VariableArrayT& data)
    {
        this->numRings = numRings;
        this->data = data;
        assert(numRings > 0);
        assert(numRings * ringSize == data.size());

        // XOR compress
        Bitstream compressedData;
        compressedData.add(subArray(data, 0, numRings * ringSize));
        /*for (unsigned int i = 1; i < numRings; i++)
        {
            unsigned int previousRingStart = (i - 1) * ringSize;
            unsigned int ringStart = i * ringSize;

            xorGadgets.emplace_back(pb, subArray(data, previousRingStart, 5 * 8),
                                        subArray(data, ringStart, 5 * 8),
                                        std::string("xor_") + std::to_string(i));
            xorGadgets.back().generate_r1cs_constraints();
            compressedData.add(xorGadgets.back().result());
            compressedData.add(subArray(data, ringStart + 5 * 8, ringSize - 5 * 8));
        }*/

        // Transform
        struct Range
        {
            unsigned int offset;
            unsigned int length;
        };
        std::vector<std::vector<Range>> ranges;
        ranges.push_back({{0, 40}});                   // orderA.orderID + orderB.orderID
        ranges.push_back({{40, 40}});                  // orderA.accountID + orderB.accountID
        ranges.push_back({{80, 8}, {120, 8}});         // orderA.tokenS + orderB.tokenS
        ranges.push_back({{88, 24},{128, 24}});        // orderA.fillS + orderB.fillS
        ranges.push_back({{112, 8}});                  // orderA.data
        ranges.push_back({{152, 8}});                  // orderB.data
        for (const std::vector<Range>& subRanges : ranges)
        {
            for (unsigned int i = 0; i < numRings; i++)
            {
                for (const Range& subRange : subRanges)
                {
                    unsigned int ringStart = i * ringSize;
                    transformedData.add(subArray(flatten(compressedData.data), ringStart + subRange.offset, subRange.length));
                }
            }
        }
    }
};

class RingSettlementGadget : public GadgetT
{
public:

    // Balances
    DynamicVariableGadget balanceS_A;
    DynamicVariableGadget balanceB_A;
    DynamicVariableGadget balanceS_B;
    DynamicVariableGadget balanceB_B;
    DynamicVariableGadget balanceA_P;
    DynamicVariableGadget balanceB_P;
    DynamicVariableGadget balanceA_O;
    DynamicVariableGadget balanceB_O;
    // Initial balances roots
    const VariableT balancesRootA;
    const VariableT balancesRootB;
    // Initial trading history roots
    const VariableT tradingHistoryRootS_A;
    const VariableT tradingHistoryRootB_A;
    const VariableT tradingHistoryRootS_B;
    const VariableT tradingHistoryRootB_B;
    const VariableT tradingHistoryRootA_O;
    const VariableT tradingHistoryRootB_O;

    // Orders
    OrderGadget orderA;
    OrderGadget orderB;

    // Match orders
    OrderMatchingGadget orderMatching;

    // Fill amounts
    TernaryGadget uFillS_A;
    TernaryGadget uFillS_B;
    FloatGadget fillS_A;
    FloatGadget fillS_B;
    RequireAccuracyGadget requireAccuracyFillS_A;
    RequireAccuracyGadget requireAccuracyFillS_B;

    // Filled amounts
    TernaryGadget filledA;
    TernaryGadget filledB;
    AddGadget filledAfterA;
    AddGadget filledAfterB;

    // Calculate fees
    FeeCalculatorGadget feeCalculatorA;
    FeeCalculatorGadget feeCalculatorB;

    /* Token Transfers */
    // Actual trade
    TransferGadget fillBB_from_balanceSA_to_balanceBB;
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

    // Update trading history
    UpdateTradeHistoryGadget updateTradeHistoryA;
    UpdateTradeHistoryGadget updateTradeHistoryB;

    // Update UserA
    UpdateBalanceGadget updateBalanceS_A;
    UpdateBalanceGadget updateBalanceB_A;
    VariableT nonce_A;
    UpdateAccountGadget updateAccount_A;

    // Update UserB
    UpdateBalanceGadget updateBalanceS_B;
    UpdateBalanceGadget updateBalanceB_B;
    VariableT nonce_B;
    UpdateAccountGadget updateAccount_B;

    // Update Protocol pool
    UpdateBalanceGadget updateBalanceA_P;
    UpdateBalanceGadget updateBalanceB_P;

    // Update Operator
    UpdateBalanceGadget updateBalanceA_O;
    UpdateBalanceGadget updateBalanceB_O;

    RingSettlementGadget(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const Constants& constants,
        const VariableT& exchangeID,
        const VariableT& accountsRoot,
        const VariableT& timestamp,
        const VariableT& protocolTakerFeeBips,
        const VariableT& protocolMakerFeeBips,
        const VariableT& protocolBalancesRoot,
        const VariableT& operatorBalancesRoot,

        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        // Balances
        balanceS_A(pb, FMT(prefix, ".balanceS_A")),
        balanceB_A(pb, FMT(prefix, ".balanceB_A")),
        balanceS_B(pb, FMT(prefix, ".balanceS_B")),
        balanceB_B(pb, FMT(prefix, ".balanceB_B")),
        balanceA_P(pb, FMT(prefix, ".balanceA_P")),
        balanceB_P(pb, FMT(prefix, ".balanceB_P")),
        balanceA_O(pb, FMT(prefix, ".balanceA_O")),
        balanceB_O(pb, FMT(prefix, ".balanceA_O")),
        // Initial balances roots
        balancesRootA(make_variable(pb, FMT(prefix, ".balancesRootA"))),
        balancesRootB(make_variable(pb, FMT(prefix, ".balancesRootB"))),
        // Initial trading history roots
        tradingHistoryRootS_A(make_variable(pb, FMT(prefix, ".tradingHistoryRootS_A"))),
        tradingHistoryRootB_A(make_variable(pb, FMT(prefix, ".tradingHistoryRootB_A"))),
        tradingHistoryRootS_B(make_variable(pb, FMT(prefix, ".tradingHistoryRootS_B"))),
        tradingHistoryRootB_B(make_variable(pb, FMT(prefix, ".tradingHistoryRootB_B"))),
        tradingHistoryRootA_O(make_variable(pb, FMT(prefix, ".tradingHistoryRootA_O"))),
        tradingHistoryRootB_O(make_variable(pb, FMT(prefix, ".tradingHistoryRootB_O"))),

        // Orders
        orderA(pb, params, constants, exchangeID, FMT(prefix, ".orderA")),
        orderB(pb, params, constants, exchangeID, FMT(prefix, ".orderB")),

        // Match orders
        orderMatching(pb, constants, timestamp, orderA, orderB, FMT(prefix, ".orderMatching")),

        // Fill amounts
        uFillS_A(pb, orderMatching.isValid(), orderMatching.getFillA_S(), constants.zero, FMT(prefix, ".uFillS_A")),
        uFillS_B(pb, orderMatching.isValid(), orderMatching.getFillB_S(), constants.zero, FMT(prefix, ".uFillS_B")),
        fillS_A(pb, constants, Float24Encoding, FMT(prefix, ".fillS_A")),
        fillS_B(pb, constants, Float24Encoding, FMT(prefix, ".fillS_B")),
        requireAccuracyFillS_A(pb, fillS_A.value(), uFillS_A.result(), Float24Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyFillS_A")),
        requireAccuracyFillS_B(pb, fillS_B.value(), uFillS_B.result(), Float24Accuracy, NUM_BITS_AMOUNT, FMT(prefix, ".requireAccuracyFillS_B")),

        // Filled amounts
        filledA(pb, orderA.buy.packed, fillS_B.value(), fillS_A.value(), FMT(prefix, ".filledA")),
        filledB(pb, orderB.buy.packed, fillS_A.value(), fillS_B.value(), FMT(prefix, ".filledB")),
        filledAfterA(pb, orderA.tradeHistory.getFilled(), filledA.result(), NUM_BITS_AMOUNT, FMT(prefix, ".filledAfterA")),
        filledAfterB(pb, orderB.tradeHistory.getFilled(), filledB.result(), NUM_BITS_AMOUNT, FMT(prefix, ".filledAfterB")),

        // Calculate fees
        feeCalculatorA(pb, constants, fillS_B.value(), protocolTakerFeeBips, orderA.feeBips.packed, orderA.rebateBips.packed, FMT(prefix, ".feeCalculatorA")),
        feeCalculatorB(pb, constants, fillS_A.value(), protocolMakerFeeBips, orderB.feeBips.packed, orderB.rebateBips.packed, FMT(prefix, ".feeCalculatorB")),

        /* Token Transfers */
        // Actual trade
        fillBB_from_balanceSA_to_balanceBB(pb, balanceS_A, balanceB_B, fillS_A.value(), FMT(prefix, ".fillBB_from_balanceSA_to_balanceBB")),
        fillSB_from_balanceSB_to_balanceBA(pb, balanceS_B, balanceB_A, fillS_B.value(), FMT(prefix, ".fillSB_from_balanceSB_to_balanceBA")),
        // Fees
        feeA_from_balanceBA_to_balanceAO(pb, balanceB_A, balanceA_O, feeCalculatorA.getFee(), FMT(prefix, ".feeA_from_balanceBA_to_balanceAO")),
        feeB_from_balanceBB_to_balanceBO(pb, balanceB_B, balanceB_O, feeCalculatorB.getFee(), FMT(prefix, ".feeB_from_balanceBB_to_balanceBO")),
        // Rebates
        rebateA_from_balanceAO_to_balanceBA(pb, balanceA_O, balanceB_A, feeCalculatorA.getRebate(), FMT(prefix, ".rebateA_from_balanceAO_to_balanceBA")),
        rebateB_from_balanceBO_to_balanceBB(pb, balanceB_O, balanceB_B, feeCalculatorB.getRebate(), FMT(prefix, ".rebateB_from_balanceBO_to_balanceBB")),
        // Protocol fees
        protocolFeeA_from_balanceAO_to_balanceAP(pb, balanceA_O, balanceA_P, feeCalculatorA.getProtocolFee(), FMT(prefix, ".protocolFeeA_from_balanceAO_to_balanceAP")),
        protocolFeeB_from_balanceBO_to_balanceBP(pb, balanceB_O, balanceB_P, feeCalculatorB.getProtocolFee(), FMT(prefix, ".protocolFeeB_from_balanceBO_to_balanceBP")),

        // Update trading history
        updateTradeHistoryA(pb, tradingHistoryRootS_A, subArray(orderA.orderID.bits, 0, NUM_BITS_TRADING_HISTORY),
                            {orderA.tradeHistoryFilled, orderA.tradeHistoryCancelled, orderA.tradeHistoryOrderID},
                            {filledAfterA.result(), orderA.tradeHistory.getCancelledToStore(), orderA.tradeHistory.getOrderIDToStore()},
                            FMT(prefix, ".updateTradeHistoryA")),
        updateTradeHistoryB(pb, tradingHistoryRootS_B, subArray(orderB.orderID.bits, 0, NUM_BITS_TRADING_HISTORY),
                            {orderB.tradeHistoryFilled, orderB.tradeHistoryCancelled, orderB.tradeHistoryOrderID},
                            {filledAfterB.result(), orderB.tradeHistory.getCancelledToStore(), orderB.tradeHistory.getOrderIDToStore()},
                            FMT(prefix, ".updateTradeHistoryB")),

        // Update UserA
        updateBalanceS_A(pb, balancesRootA, orderA.tokenS.bits,
                         {balanceS_A.front(), tradingHistoryRootS_A},
                         {balanceS_A.back(), updateTradeHistoryA.result()},
                         FMT(prefix, ".updateBalanceS_A")),
        updateBalanceB_A(pb, updateBalanceS_A.result(), orderA.tokenB.bits,
                         {balanceB_A.front(), tradingHistoryRootB_A},
                         {balanceB_A.back(), tradingHistoryRootB_A},
                         FMT(prefix, ".updateBalanceB_A")),
        nonce_A(make_variable(pb, FMT(prefix, ".nonce_A"))),
        updateAccount_A(pb, accountsRoot, orderA.accountID.bits,
                        {orderA.publicKey.x, orderA.publicKey.y, nonce_A, balancesRootA},
                        {orderA.publicKey.x, orderA.publicKey.y, nonce_A, updateBalanceB_A.result()},
                        FMT(prefix, ".updateAccount_A")),

        // Update UserB
        updateBalanceS_B(pb, balancesRootB, orderB.tokenS.bits,
                         {balanceS_B.front(), tradingHistoryRootS_B},
                         {balanceS_B.back(), updateTradeHistoryB.result()},
                         FMT(prefix, ".updateBalanceS_B")),
        updateBalanceB_B(pb, updateBalanceS_B.result(), orderB.tokenB.bits,
                         {balanceB_B.front(), tradingHistoryRootB_B},
                         {balanceB_B.back(), tradingHistoryRootB_B},
                         FMT(prefix, ".updateBalanceB_B")),
        nonce_B(make_variable(pb, FMT(prefix, ".nonce_B"))),
        updateAccount_B(pb, updateAccount_A.result(), orderB.accountID.bits,
                        {orderB.publicKey.x, orderB.publicKey.y, nonce_B, balancesRootB},
                        {orderB.publicKey.x, orderB.publicKey.y, nonce_B, updateBalanceB_B.result()},
                        FMT(prefix, ".updateAccount_B")),

        // Update Protocol pool
        updateBalanceA_P(pb, protocolBalancesRoot, orderA.tokenB.bits,
                         {balanceA_P.front(), constants.emptyTradeHistory},
                         {balanceA_P.back(), constants.emptyTradeHistory},
                         FMT(prefix, ".updateBalanceA_P")),
        updateBalanceB_P(pb, updateBalanceA_P.result(), orderB.tokenB.bits,
                         {balanceB_P.front(), constants.emptyTradeHistory},
                         {balanceB_P.back(), constants.emptyTradeHistory},
                         FMT(prefix, ".updateBalanceB_P")),

        // Update Operator
        updateBalanceA_O(pb, operatorBalancesRoot, orderA.tokenB.bits,
                         {balanceA_O.front(), tradingHistoryRootA_O},
                         {balanceA_O.back(), tradingHistoryRootA_O},
                         FMT(prefix, ".updateBalanceA_O")),
        updateBalanceB_O(pb, updateBalanceA_O.result(), orderB.tokenB.bits,
                         {balanceB_O.front(), tradingHistoryRootB_O},
                         {balanceB_O.back(), tradingHistoryRootB_O},
                         FMT(prefix, ".updateBalanceB_O"))
    {

    }

    void generate_r1cs_witness(const RingSettlement& ringSettlement)
    {
        // Balances before
        balanceS_A.generate_r1cs_witness(ringSettlement.balanceUpdateS_A.before.balance);
        balanceB_A.generate_r1cs_witness(ringSettlement.balanceUpdateB_A.before.balance);
        balanceS_B.generate_r1cs_witness(ringSettlement.balanceUpdateS_B.before.balance);
        balanceB_B.generate_r1cs_witness(ringSettlement.balanceUpdateB_B.before.balance);
        balanceA_P.generate_r1cs_witness(ringSettlement.balanceUpdateA_P.before.balance);
        balanceB_P.generate_r1cs_witness(ringSettlement.balanceUpdateB_P.before.balance);
        balanceA_O.generate_r1cs_witness(ringSettlement.balanceUpdateA_O.before.balance);
        balanceB_O.generate_r1cs_witness(ringSettlement.balanceUpdateB_O.before.balance);
        // Initial balances roots
        pb.val(balancesRootA) = ringSettlement.balanceUpdateS_A.rootBefore;
        pb.val(balancesRootB) = ringSettlement.balanceUpdateS_B.rootBefore;
        // Trading history roots before
        pb.val(tradingHistoryRootS_A) = ringSettlement.balanceUpdateS_A.before.tradingHistoryRoot;
        pb.val(tradingHistoryRootB_A) = ringSettlement.balanceUpdateB_A.before.tradingHistoryRoot;
        pb.val(tradingHistoryRootS_B) = ringSettlement.balanceUpdateS_B.before.tradingHistoryRoot;
        pb.val(tradingHistoryRootB_B) = ringSettlement.balanceUpdateB_B.before.tradingHistoryRoot;
        pb.val(tradingHistoryRootA_O) = ringSettlement.balanceUpdateA_O.before.tradingHistoryRoot;
        pb.val(tradingHistoryRootB_O) = ringSettlement.balanceUpdateB_O.before.tradingHistoryRoot;

        // Orders
        orderA.generate_r1cs_witness(ringSettlement.ring.orderA,
                                     ringSettlement.accountUpdate_A.before,
                                     ringSettlement.balanceUpdateS_A.before,
                                     ringSettlement.balanceUpdateB_A.before,
                                     ringSettlement.tradeHistoryUpdate_A.before);
        orderB.generate_r1cs_witness(ringSettlement.ring.orderB,
                                     ringSettlement.accountUpdate_B.before,
                                     ringSettlement.balanceUpdateS_B.before,
                                     ringSettlement.balanceUpdateB_B.before,
                                     ringSettlement.tradeHistoryUpdate_B.before);

        // Match orders
        orderMatching.generate_r1cs_witness();

        // Fill amounts
        uFillS_A.generate_r1cs_witness();
        uFillS_B.generate_r1cs_witness();
        fillS_A.generate_r1cs_witness(toFloat(pb.val(uFillS_A.result()), Float24Encoding));
        fillS_B.generate_r1cs_witness(toFloat(pb.val(uFillS_B.result()), Float24Encoding));
        requireAccuracyFillS_A.generate_r1cs_witness();
        requireAccuracyFillS_B.generate_r1cs_witness();

        // Filled amounts
        filledA.generate_r1cs_witness();
        filledB.generate_r1cs_witness();
        filledAfterA.generate_r1cs_witness();
        filledAfterB.generate_r1cs_witness();

        // Calculate fees
        feeCalculatorA.generate_r1cs_witness();
        feeCalculatorB.generate_r1cs_witness();

        /* Token Transfers */
        // Actual trade
        fillBB_from_balanceSA_to_balanceBB.generate_r1cs_witness();
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

        // Update trading history
        updateTradeHistoryA.generate_r1cs_witness(ringSettlement.tradeHistoryUpdate_A.proof);
        updateTradeHistoryB.generate_r1cs_witness(ringSettlement.tradeHistoryUpdate_B.proof);

        // Update UserA
        pb.val(nonce_A) = ringSettlement.accountUpdate_A.before.nonce;
        updateBalanceS_A.generate_r1cs_witness(ringSettlement.balanceUpdateS_A.proof);
        updateBalanceB_A.generate_r1cs_witness(ringSettlement.balanceUpdateB_A.proof);
        updateAccount_A.generate_r1cs_witness(ringSettlement.accountUpdate_A.proof);

        // Update UserB
        pb.val(nonce_B) = ringSettlement.accountUpdate_B.before.nonce;
        updateBalanceS_B.generate_r1cs_witness(ringSettlement.balanceUpdateS_B.proof);
        updateBalanceB_B.generate_r1cs_witness(ringSettlement.balanceUpdateB_B.proof);
        updateAccount_B.generate_r1cs_witness(ringSettlement.accountUpdate_B.proof);

        // Update Protocol pool
        updateBalanceA_P.generate_r1cs_witness(ringSettlement.balanceUpdateA_P.proof);
        updateBalanceB_P.generate_r1cs_witness(ringSettlement.balanceUpdateB_P.proof);

        // Update Operator
        updateBalanceA_O.generate_r1cs_witness(ringSettlement.balanceUpdateA_O.proof);
        updateBalanceB_O.generate_r1cs_witness(ringSettlement.balanceUpdateB_O.proof);
    }


    void generate_r1cs_constraints()
    {
        // Orders
        orderA.generate_r1cs_constraints();
        orderB.generate_r1cs_constraints();

        // Match orders
        orderMatching.generate_r1cs_constraints();

        // Fill amounts
        uFillS_A.generate_r1cs_constraints();
        uFillS_B.generate_r1cs_constraints();
        fillS_A.generate_r1cs_constraints();
        fillS_B.generate_r1cs_constraints();
        requireAccuracyFillS_A.generate_r1cs_constraints();
        requireAccuracyFillS_B.generate_r1cs_constraints();

        // Filled amounts
        filledA.generate_r1cs_constraints();
        filledB.generate_r1cs_constraints();
        filledAfterA.generate_r1cs_constraints();
        filledAfterB.generate_r1cs_constraints();

        // Calculate fees
        feeCalculatorA.generate_r1cs_constraints();
        feeCalculatorB.generate_r1cs_constraints();

        /* Token Transfers */
        // Actual trade
        fillBB_from_balanceSA_to_balanceBB.generate_r1cs_constraints();
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

        // Update trading history
        updateTradeHistoryA.generate_r1cs_constraints();
        updateTradeHistoryB.generate_r1cs_constraints();

        // Update UserA
        updateBalanceS_A.generate_r1cs_constraints();
        updateBalanceB_A.generate_r1cs_constraints();
        updateAccount_A.generate_r1cs_constraints();

        // Update UserB
        updateBalanceS_B.generate_r1cs_constraints();
        updateBalanceB_B.generate_r1cs_constraints();
        updateAccount_B.generate_r1cs_constraints();

        // Update Protocol fee pool
        updateBalanceA_P.generate_r1cs_constraints();
        updateBalanceB_P.generate_r1cs_constraints();

        // Update Operator
        updateBalanceA_O.generate_r1cs_constraints();
        updateBalanceB_O.generate_r1cs_constraints();
    }

    const std::vector<VariableArrayT> getPublicData() const
    {
        return
        {
            orderA.orderID.bits, orderB.orderID.bits,
            orderA.accountID.bits, orderB.accountID.bits,

            orderA.tokenS.bits,
            fillS_A.bits(),
            orderA.buy.bits, VariableArrayT(1, orderA.hasRebate()), orderA.feeOrRebateBips.bits,

            orderB.tokenS.bits,
            fillS_B.bits(),
            orderB.buy.bits, VariableArrayT(1, orderB.hasRebate()), orderB.feeOrRebateBips.bits,
        };
    }

    const VariableT getNewAccountsRoot() const
    {
        return updateAccount_B.result();
    }

    const VariableT getNewProtocolBalancesRoot() const
    {
        return updateBalanceB_P.result();
    }

    const VariableT getNewOperatorBalancesRoot() const
    {
        return updateBalanceB_O.result();
    }
};

class RingSettlementCircuit : public GadgetT
{
public:

    PublicDataGadget publicData;
    Constants constants;
    jubjub::Params params;

    // State
    AccountGadget accountBefore_O;
    AccountGadget accountBefore_P;

    // Inputs
    DualVariableGadget exchangeID;
    DualVariableGadget merkleRootBefore;
    DualVariableGadget merkleRootAfter;
    DualVariableGadget timestamp;
    DualVariableGadget protocolTakerFeeBips;
    DualVariableGadget protocolMakerFeeBips;
    DualVariableGadget operatorAccountID;

    // Increment the nonce of the Operator
    AddGadget nonce_after;

    // Transform the ring data
    TransformRingSettlementDataGadget transformData;

    // Signature
    Poseidon_gadget_T<3, 1, 6, 51, 2, 1> hash;
    SignatureVerifier signatureVerifier;

    // Ring settlements
    bool onchainDataAvailability;
    unsigned int numRings;
    std::vector<RingSettlementGadget> ringSettlements;
    Bitstream dataAvailabityData;

    // Update Protocol pool
    std::unique_ptr<UpdateAccountGadget> updateAccount_P;

    // Update Operator
    std::unique_ptr<UpdateAccountGadget> updateAccount_O;

    // Labels
    std::vector<VariableT> labels;
    std::unique_ptr<LabelHasher> labelHasher;

    RingSettlementCircuit(ProtoboardT& pb, const std::string& prefix) :
        GadgetT(pb, prefix),

        publicData(pb, FMT(prefix, ".publicData")),
        constants(pb, FMT(prefix, ".constants")),

        // State
        accountBefore_O(pb, FMT(prefix, ".accountBefore_O")),
        accountBefore_P(pb, FMT(prefix, ".accountBefore_P")),

        // Inputs
        exchangeID(pb, NUM_BITS_EXCHANGE_ID, FMT(prefix, ".exchangeID")),
        merkleRootBefore(pb, 256, FMT(prefix, ".merkleRootBefore")),
        merkleRootAfter(pb, 256, FMT(prefix, ".merkleRootAfter")),
        timestamp(pb, NUM_BITS_TIMESTAMP, FMT(prefix, ".timestamp")),
        protocolTakerFeeBips(pb, NUM_BITS_PROTOCOL_FEE_BIPS, FMT(prefix, ".protocolTakerFeeBips")),
        protocolMakerFeeBips(pb, NUM_BITS_PROTOCOL_FEE_BIPS, FMT(prefix, ".protocolMakerFeeBips")),
        operatorAccountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".operatorAccountID")),

        // Increment the nonce of the Operator
        nonce_after(pb, accountBefore_O.nonce, constants.one, NUM_BITS_NONCE, FMT(prefix, ".nonce_after")),

        // Transform the ring data
        transformData(pb, FMT(prefix, ".transformData")),

        // Signature
        hash(pb, var_array({
            publicData.publicInput,
            accountBefore_O.nonce
        }), FMT(this->annotation_prefix, ".hash")),
        signatureVerifier(pb, params, jubjub::VariablePointT(accountBefore_O.publicKeyX, accountBefore_O.publicKeyY),
                          hash.result(), FMT(prefix, ".signatureVerifier"))
    {

    }

    void generate_r1cs_constraints(bool onchainDataAvailability, int numRings)
    {
        this->onchainDataAvailability = onchainDataAvailability;
        this->numRings = numRings;

        constants.generate_r1cs_constraints();

        // State
        accountBefore_O.generate_r1cs_constraints();
        accountBefore_P.generate_r1cs_constraints();

        // Inputs
        exchangeID.generate_r1cs_constraints(true);
        merkleRootBefore.generate_r1cs_constraints(true);
        merkleRootAfter.generate_r1cs_constraints(true);
        timestamp.generate_r1cs_constraints(true);
        protocolTakerFeeBips.generate_r1cs_constraints(true);
        protocolMakerFeeBips.generate_r1cs_constraints(true);
        operatorAccountID.generate_r1cs_constraints(true);

        // Increment the nonce of the Operator
        nonce_after.generate_r1cs_constraints();

        // Ring settlements
        for (size_t j = 0; j < numRings; j++)
        {
            const VariableT ringAccountsRoot = (j == 0) ? merkleRootBefore.packed : ringSettlements.back().getNewAccountsRoot();
            const VariableT& ringProtocolBalancesRoot = (j == 0) ? accountBefore_P.balancesRoot : ringSettlements.back().getNewProtocolBalancesRoot();
            const VariableT& ringOperatorBalancesRoot = (j == 0) ? accountBefore_O.balancesRoot : ringSettlements.back().getNewOperatorBalancesRoot();
            ringSettlements.emplace_back(
                pb,
                params,
                constants,
                exchangeID.packed,
                ringAccountsRoot,
                timestamp.packed,
                protocolTakerFeeBips.packed,
                protocolMakerFeeBips.packed,
                ringProtocolBalancesRoot,
                ringOperatorBalancesRoot,
                std::string("trade_") + std::to_string(j)
            );
            ringSettlements.back().generate_r1cs_constraints();

            labels.push_back(ringSettlements.back().orderA.label);
            labels.push_back(ringSettlements.back().orderB.label);

            if (onchainDataAvailability)
            {
                // Store data from ring settlement
                dataAvailabityData.add(ringSettlements.back().getPublicData());
            }
        }

        // Update Protocol pool
        updateAccount_P.reset(new UpdateAccountGadget(pb, ringSettlements.back().getNewAccountsRoot(), constants.zeroAccount,
                      {accountBefore_P.publicKeyX, accountBefore_P.publicKeyY, accountBefore_P.nonce, accountBefore_P.balancesRoot},
                      {accountBefore_P.publicKeyX, accountBefore_P.publicKeyY, accountBefore_P.nonce, ringSettlements.back().getNewProtocolBalancesRoot()},
                      FMT(annotation_prefix, ".updateAccount_P")));
        updateAccount_P->generate_r1cs_constraints();

        // Update Operator
        updateAccount_O.reset(new UpdateAccountGadget(pb, updateAccount_P->result(), operatorAccountID.bits,
                      {accountBefore_O.publicKeyX, accountBefore_O.publicKeyY, accountBefore_O.nonce, accountBefore_O.balancesRoot},
                      {accountBefore_O.publicKeyX, accountBefore_O.publicKeyY, nonce_after.result(), ringSettlements.back().getNewOperatorBalancesRoot()},
                      FMT(annotation_prefix, ".updateAccount_O")));
        updateAccount_O->generate_r1cs_constraints();

        // Labels
        labelHasher.reset(new LabelHasher(pb, constants, labels, FMT(annotation_prefix, ".labelHash")));
        labelHasher->generate_r1cs_constraints();

        // Public data
        publicData.add(exchangeID.bits);
        publicData.add(merkleRootBefore.bits);
        publicData.add(merkleRootAfter.bits);
        publicData.add(timestamp.bits);
        publicData.add(protocolTakerFeeBips.bits);
        publicData.add(protocolMakerFeeBips.bits);
        publicData.add(labelHasher->result()->bits);
        if (onchainDataAvailability)
        {
            publicData.add(constants.padding_0000);
            publicData.add(operatorAccountID.bits);
            // Transform the ring data
            transformData.generate_r1cs_constraints(numRings, flattenReverse(dataAvailabityData.data));
            publicData.add(reverse(transformData.result()));
        }
        publicData.generate_r1cs_constraints();

        // Signature
        hash.generate_r1cs_constraints();
        signatureVerifier.generate_r1cs_constraints();

        // Check the new merkle root
        forceEqual(pb, updateAccount_O->result(), merkleRootAfter.packed, "newMerkleRoot");
    }

    bool generateWitness(const RingSettlementBlock& block)
    {
        if (block.ringSettlements.size() != numRings)
        {
            std::cout << "Invalid number of rings: " << block.ringSettlements.size()  << std::endl;
            return false;
        }

        constants.generate_r1cs_witness();

        // State
        accountBefore_O.generate_r1cs_witness(block.accountUpdate_O.before);
        accountBefore_P.generate_r1cs_witness(block.accountUpdate_P.before);

        // Inputs
        exchangeID.generate_r1cs_witness(pb, block.exchangeID);
        merkleRootBefore.generate_r1cs_witness(pb, block.merkleRootBefore);
        merkleRootAfter.generate_r1cs_witness(pb, block.merkleRootAfter);
        timestamp.generate_r1cs_witness(pb, block.timestamp);
        protocolTakerFeeBips.generate_r1cs_witness(pb, block.protocolTakerFeeBips);
        protocolMakerFeeBips.generate_r1cs_witness(pb, block.protocolMakerFeeBips);
        operatorAccountID.generate_r1cs_witness(pb, block.operatorAccountID);

        // Increment the nonce of the Operator
        nonce_after.generate_r1cs_witness();

        // Ring settlements
        for(unsigned int i = 0; i < block.ringSettlements.size(); i++)
        {
            ringSettlements[i].generate_r1cs_witness(block.ringSettlements[i]);
        }

        // Update Protocol pool
        updateAccount_P->generate_r1cs_witness(block.accountUpdate_P.proof);

        // Update Operator
        updateAccount_O->generate_r1cs_witness(block.accountUpdate_O.proof);

        // Labels
        labelHasher->generate_r1cs_witness();

        // Transform the ring data
        if (onchainDataAvailability)
        {
            transformData.generate_r1cs_witness();
        }
        // Public data
        publicData.generate_r1cs_witness();

        // Signature
        hash.generate_r1cs_witness();
        signatureVerifier.generate_r1cs_witness(block.signature);

        return true;
    }

    void printInfo()
    {
        std::cout << pb.num_constraints() << " constraints (" << (pb.num_constraints() / numRings) << "/ring)" << std::endl;
    }
};

}

#endif
