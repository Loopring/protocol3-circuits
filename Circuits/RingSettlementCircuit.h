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

    const Constants& constants;

    const VariableT accountsRoot;

    const VariableT tradingHistoryRootS_A;
    const VariableT tradingHistoryRootB_A;
    const VariableT tradingHistoryRootS_B;
    const VariableT tradingHistoryRootB_B;
    const VariableT tradingHistoryRootA_O;
    const VariableT tradingHistoryRootB_O;

    const VariableT balancesRootA;
    const VariableT balancesRootB;

    VariableT blockexchangeID;

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
    DynamicVariableGadget balanceA_O;
    DynamicVariableGadget balanceB_O;

    TransferGadget fillBB_from_balanceSA_to_balanceBB;
    TransferGadget fillSB_from_balanceSB_to_balanceBA;
    TransferGadget feeA_from_balanceBA_to_balanceAO;
    TransferGadget feeB_from_balanceBB_to_balanceBO;
    TransferGadget rebateA_from_balanceAO_to_balanceBA;
    TransferGadget rebateB_from_balanceBO_to_balanceBB;
    TransferGadget protocolFeeA_from_balanceAO_to_balanceAP;
    TransferGadget protocolFeeB_from_balanceBO_to_balanceBP;

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

    UpdateBalanceGadget updateBalanceA_P;
    UpdateBalanceGadget updateBalanceB_P;

    UpdateBalanceGadget updateBalanceA_O;
    UpdateBalanceGadget updateBalanceB_O;

    RingSettlementGadget(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const Constants& _constants,
        const VariableT& _exchangeID,
        const VariableT& _accountsRoot,
        const VariableT& _timestamp,
        const VariableT& _protocolTakerFeeBips,
        const VariableT& _protocolMakerFeeBips,
        const VariableT& _protocolBalancesRoot,
        const VariableT& _operatorBalancesRoot,

        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        constants(_constants),

        orderA(pb, params, constants, _exchangeID, FMT(prefix, ".orderA")),
        orderB(pb, params, constants, _exchangeID, FMT(prefix, ".orderB")),

        // Match orders
        orderMatching(pb, constants, _timestamp, orderA, orderB, FMT(prefix, ".orderMatching")),

        // Fill amounts
        uFillS_A(pb, orderMatching.isValid(), orderMatching.getFillA_S(), constants.zero, FMT(prefix, ".uFillS_A")),
        uFillS_B(pb, orderMatching.isValid(), orderMatching.getFillB_S(), constants.zero, FMT(prefix, ".uFillS_B")),
        fillS_A(pb, constants, Float24Encoding, FMT(prefix, ".fillS_A")),
        fillS_B(pb, constants, Float24Encoding, FMT(prefix, ".fillS_B")),
        ensureAccuracyFillS_A(pb, fillS_A.value(), uFillS_A.result(), Float24Accuracy, FMT(prefix, ".ensureAccuracyFillS_A")),
        ensureAccuracyFillS_B(pb, fillS_B.value(), uFillS_B.result(), Float24Accuracy, FMT(prefix, ".ensureAccuracyFillS_B")),

        // Filled amounts
        filledA(pb, orderA.buy.packed, fillS_B.value(), fillS_A.value(), FMT(prefix, ".filledA")),
        filledB(pb, orderB.buy.packed, fillS_A.value(), fillS_B.value(), FMT(prefix, ".filledB")),
        filledAfterA(pb, orderA.tradeHistory.getFilled(), filledA.result(), FMT(prefix, ".filledAfterA")),
        filledAfterB(pb, orderB.tradeHistory.getFilled(), filledB.result(), FMT(prefix, ".filledAfterB")),

        // Calculate fees
        feeCalculatorA(pb, constants, fillS_B.value(), _protocolTakerFeeBips, orderA.feeBips.packed, orderA.rebateBips.packed, FMT(prefix, ".feeCalculatorA")),
        feeCalculatorB(pb, constants, fillS_A.value(), _protocolMakerFeeBips, orderB.feeBips.packed, orderB.rebateBips.packed, FMT(prefix, ".feeCalculatorB")),

        // Balances
        balanceS_A(pb, FMT(prefix, ".balanceS_A")),
        balanceB_A(pb, FMT(prefix, ".balanceB_A")),
        balanceS_B(pb, FMT(prefix, ".balanceS_B")),
        balanceB_B(pb, FMT(prefix, ".balanceB_B")),
        balanceA_P(pb, FMT(prefix, ".balanceA_P")),
        balanceB_P(pb, FMT(prefix, ".balanceB_P")),
        balanceA_O(pb, FMT(prefix, ".balanceA_O")),
        balanceB_O(pb, FMT(prefix, ".balanceA_O")),

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

        // Initial trading history roots
        tradingHistoryRootS_A(make_variable(pb, FMT(prefix, ".tradingHistoryRootS_A"))),
        tradingHistoryRootB_A(make_variable(pb, FMT(prefix, ".tradingHistoryRootB_A"))),
        tradingHistoryRootS_B(make_variable(pb, FMT(prefix, ".tradingHistoryRootS_B"))),
        tradingHistoryRootB_B(make_variable(pb, FMT(prefix, ".tradingHistoryRootB_B"))),
        tradingHistoryRootA_O(make_variable(pb, FMT(prefix, ".tradingHistoryRootA_O"))),
        tradingHistoryRootB_O(make_variable(pb, FMT(prefix, ".tradingHistoryRootB_O"))),

        // Initial balances roots
        balancesRootA(make_variable(pb, FMT(prefix, ".balancesRootA"))),
        balancesRootB(make_variable(pb, FMT(prefix, ".balancesRootB"))),

        // Update trading history
        updateTradeHistoryA(pb, tradingHistoryRootS_A, subArray(orderA.orderID.bits, 0, NUM_BITS_TRADING_HISTORY),
                            {orderA.tradeHistoryFilled, orderA.tradeHistoryCancelled, orderA.tradeHistoryOrderID},
                            {filledAfterA.result(), orderA.tradeHistory.getCancelledToStore(), orderA.tradeHistory.getOrderIDToStore()},
                            FMT(prefix, ".updateTradeHistoryA")),
        updateTradeHistoryB(pb, tradingHistoryRootS_B, subArray(orderB.orderID.bits, 0, NUM_BITS_TRADING_HISTORY),
                            {orderB.tradeHistoryFilled, orderB.tradeHistoryCancelled, orderB.tradeHistoryOrderID},
                            {filledAfterB.result(), orderB.tradeHistory.getCancelledToStore(), orderB.tradeHistory.getOrderIDToStore()},
                            FMT(prefix, ".updateTradeHistoryB")),

        accountsRoot(_accountsRoot),

        // Update OwnerA
        updateBalanceS_A(pb, balancesRootA, orderA.tokenS.bits,
                         {balanceS_A.front(), tradingHistoryRootS_A},
                         {balanceS_A.back(), updateTradeHistoryA.getNewRoot()},
                         FMT(prefix, ".updateBalanceS_A")),
        updateBalanceB_A(pb, updateBalanceS_A.getNewRoot(), orderA.tokenB.bits,
                         {balanceB_A.front(), tradingHistoryRootB_A},
                         {balanceB_A.back(), tradingHistoryRootB_A},
                         FMT(prefix, ".updateBalanceB_A")),
        nonce_A(make_variable(pb, FMT(prefix, ".nonce_A"))),
        updateAccount_A(pb, _accountsRoot, orderA.accountID.bits,
                        {orderA.publicKey.x, orderA.publicKey.y, nonce_A, balancesRootA},
                        {orderA.publicKey.x, orderA.publicKey.y, nonce_A, updateBalanceB_A.getNewRoot()},
                        FMT(prefix, ".updateAccount_A")),

        // Update OwnerB
        updateBalanceS_B(pb, balancesRootB, orderB.tokenS.bits,
                         {balanceS_B.front(), tradingHistoryRootS_B},
                         {balanceS_B.back(), updateTradeHistoryB.getNewRoot()},
                         FMT(prefix, ".updateBalanceS_B")),
        updateBalanceB_B(pb, updateBalanceS_B.getNewRoot(), orderB.tokenB.bits,
                         {balanceB_B.front(), tradingHistoryRootB_B},
                         {balanceB_B.back(), tradingHistoryRootB_B},
                         FMT(prefix, ".updateBalanceB_B")),
        nonce_B(make_variable(pb, FMT(prefix, ".nonce_B"))),
        updateAccount_B(pb, updateAccount_A.result(), orderB.accountID.bits,
                        {orderB.publicKey.x, orderB.publicKey.y, nonce_B, balancesRootB},
                        {orderB.publicKey.x, orderB.publicKey.y, nonce_B, updateBalanceB_B.getNewRoot()},
                        FMT(prefix, ".updateAccount_B")),

        // Update Protocol pool
        updateBalanceA_P(pb, _protocolBalancesRoot, orderA.tokenB.bits,
                         {balanceA_P.front(), constants.emptyTradeHistory},
                         {balanceA_P.back(), constants.emptyTradeHistory},
                         FMT(prefix, ".updateBalanceA_P")),
        updateBalanceB_P(pb, updateBalanceA_P.getNewRoot(), orderB.tokenB.bits,
                         {balanceB_P.front(), constants.emptyTradeHistory},
                         {balanceB_P.back(), constants.emptyTradeHistory},
                         FMT(prefix, ".updateBalanceB_P")),

        // Update Operator
        updateBalanceA_O(pb, _operatorBalancesRoot, orderA.tokenB.bits,
                         {balanceA_O.front(), tradingHistoryRootA_O},
                         {balanceA_O.back(), tradingHistoryRootA_O},
                         FMT(prefix, ".updateBalanceA_O")),
        updateBalanceB_O(pb, updateBalanceA_O.getNewRoot(), orderB.tokenB.bits,
                         {balanceB_O.front(), tradingHistoryRootB_O},
                         {balanceB_O.back(), tradingHistoryRootB_O},
                         FMT(prefix, ".updateBalanceB_O"))
    {

    }

    const VariableT getNewAccountsRoot() const
    {
        return updateAccount_B.result();
    }

    const VariableT getNewProtocolBalancesRoot() const
    {
        return updateBalanceB_P.getNewRoot();
    }

    const VariableT getNewOperatorBalancesRoot() const
    {
        return updateBalanceB_O.getNewRoot();
    }

    const std::vector<VariableArrayT> getPublicData() const
    {
        return
        {
            orderA.orderID.bits, orderB.orderID.bits,
            orderA.accountID.bits, orderB.accountID.bits,

            orderA.tokenS.bits,
            fillS_A.bits(),
            orderA.buy.bits, VariableArrayT(1, orderA.bRebateNonZero.lt()), orderA.feeOrRebateBips.bits,

            orderB.tokenS.bits,
            fillS_B.bits(),
            orderB.buy.bits, VariableArrayT(1, orderB.bRebateNonZero.lt()), orderB.feeOrRebateBips.bits,
        };
    }

    void generate_r1cs_witness(const RingSettlement& ringSettlement)
    {
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
        ensureAccuracyFillS_A.generate_r1cs_witness();
        ensureAccuracyFillS_B.generate_r1cs_witness();
        // print(pb, "fillS_A", fillS_A.value());
        // print(pb, "fillS_B", fillS_B.value());

        // Filled amounts
        filledA.generate_r1cs_witness();
        filledB.generate_r1cs_witness();
        filledAfterA.generate_r1cs_witness();
        filledAfterB.generate_r1cs_witness();

        // Calculate fees
        feeCalculatorA.generate_r1cs_witness();
        feeCalculatorB.generate_r1cs_witness();

        // Balances before
        balanceS_A.generate_r1cs_witness(ringSettlement.balanceUpdateS_A.before.balance);
        balanceB_A.generate_r1cs_witness(ringSettlement.balanceUpdateB_A.before.balance);
        balanceS_B.generate_r1cs_witness(ringSettlement.balanceUpdateS_B.before.balance);
        balanceB_B.generate_r1cs_witness(ringSettlement.balanceUpdateB_B.before.balance);
        balanceA_P.generate_r1cs_witness(ringSettlement.balanceUpdateA_P.before.balance);
        balanceB_P.generate_r1cs_witness(ringSettlement.balanceUpdateB_P.before.balance);
        balanceA_O.generate_r1cs_witness(ringSettlement.balanceUpdateA_O.before.balance);
        balanceB_O.generate_r1cs_witness(ringSettlement.balanceUpdateB_O.before.balance);

        // Calculate new balances
        fillBB_from_balanceSA_to_balanceBB.generate_r1cs_witness();
        fillSB_from_balanceSB_to_balanceBA.generate_r1cs_witness();
        feeA_from_balanceBA_to_balanceAO.generate_r1cs_witness();
        feeB_from_balanceBB_to_balanceBO.generate_r1cs_witness();
        rebateA_from_balanceAO_to_balanceBA.generate_r1cs_witness();
        rebateB_from_balanceBO_to_balanceBB.generate_r1cs_witness();
        protocolFeeA_from_balanceAO_to_balanceAP.generate_r1cs_witness();
        protocolFeeB_from_balanceBO_to_balanceBP.generate_r1cs_witness();

        // Initial trading history roots
        pb.val(tradingHistoryRootS_A) = ringSettlement.balanceUpdateS_A.before.tradingHistoryRoot;
        pb.val(tradingHistoryRootB_A) = ringSettlement.balanceUpdateB_A.before.tradingHistoryRoot;
        pb.val(tradingHistoryRootS_B) = ringSettlement.balanceUpdateS_B.before.tradingHistoryRoot;
        pb.val(tradingHistoryRootB_B) = ringSettlement.balanceUpdateB_B.before.tradingHistoryRoot;
        pb.val(tradingHistoryRootA_O) = ringSettlement.balanceUpdateA_O.before.tradingHistoryRoot;
        pb.val(tradingHistoryRootB_O) = ringSettlement.balanceUpdateB_O.before.tradingHistoryRoot;

        // Initial balances roots
        pb.val(balancesRootA) = ringSettlement.balanceUpdateS_A.rootBefore;
        pb.val(balancesRootB) = ringSettlement.balanceUpdateS_B.rootBefore;

        // Update trading history
        updateTradeHistoryA.generate_r1cs_witness(ringSettlement.tradeHistoryUpdate_A.proof);
        updateTradeHistoryB.generate_r1cs_witness(ringSettlement.tradeHistoryUpdate_B.proof);

        // Update OwnerA
        pb.val(nonce_A) = ringSettlement.accountUpdate_A.before.nonce;
        updateBalanceS_A.generate_r1cs_witness(ringSettlement.balanceUpdateS_A.proof);
        updateBalanceB_A.generate_r1cs_witness(ringSettlement.balanceUpdateB_A.proof);
        updateAccount_A.generate_r1cs_witness(ringSettlement.accountUpdate_A.proof);
        // Update OwnerB
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
        orderA.generate_r1cs_constraints();
        orderB.generate_r1cs_constraints();

        // Match orders
        orderMatching.generate_r1cs_constraints();

        // Fill amounts
        uFillS_A.generate_r1cs_constraints();
        uFillS_B.generate_r1cs_constraints();
        fillS_A.generate_r1cs_constraints();
        fillS_B.generate_r1cs_constraints();
        ensureAccuracyFillS_A.generate_r1cs_constraints();
        ensureAccuracyFillS_B.generate_r1cs_constraints();

        // Filled amounts
        filledA.generate_r1cs_constraints();
        filledB.generate_r1cs_constraints();
        filledAfterA.generate_r1cs_constraints();
        filledAfterB.generate_r1cs_constraints();

        // Calculate fees
        feeCalculatorA.generate_r1cs_constraints();
        feeCalculatorB.generate_r1cs_constraints();

        // Calculate new balances
        fillBB_from_balanceSA_to_balanceBB.generate_r1cs_constraints();
        fillSB_from_balanceSB_to_balanceBA.generate_r1cs_constraints();
        feeA_from_balanceBA_to_balanceAO.generate_r1cs_constraints();
        feeB_from_balanceBB_to_balanceBO.generate_r1cs_constraints();
        rebateA_from_balanceAO_to_balanceBA.generate_r1cs_constraints();
        rebateB_from_balanceBO_to_balanceBB.generate_r1cs_constraints();
        protocolFeeA_from_balanceAO_to_balanceAP.generate_r1cs_constraints();
        protocolFeeB_from_balanceBO_to_balanceBP.generate_r1cs_constraints();

        // Update trading history
        updateTradeHistoryA.generate_r1cs_constraints();
        updateTradeHistoryB.generate_r1cs_constraints();

        // Update OwnerA
        updateBalanceS_A.generate_r1cs_constraints();
        updateBalanceB_A.generate_r1cs_constraints();
        updateAccount_A.generate_r1cs_constraints();
        // Update OwnerB
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
};

class RingSettlementCircuit : public GadgetT
{
public:

    bool onchainDataAvailability;
    unsigned int numRings;
    jubjub::Params params;
    std::vector<RingSettlementGadget> ringSettlements;

    libsnark::dual_variable_gadget<FieldT> publicDataHash;
    Bitstream dataAvailabityData;
    TransformRingSettlementDataGadget transformData;
    PublicDataGadget publicData;

    Constants constants;

    libsnark::dual_variable_gadget<FieldT> exchangeID;
    libsnark::dual_variable_gadget<FieldT> merkleRootBefore;
    libsnark::dual_variable_gadget<FieldT> merkleRootAfter;
    libsnark::dual_variable_gadget<FieldT> timestamp;

    libsnark::dual_variable_gadget<FieldT> protocolTakerFeeBips;
    libsnark::dual_variable_gadget<FieldT> protocolMakerFeeBips;

    // Protocol fee pool
    const VariableT balancesRootP_before;
    std::unique_ptr<UpdateAccountGadget> updateAccount_P;

    // Operator
    libsnark::dual_variable_gadget<FieldT> operatorAccountID;
    const jubjub::VariablePointT publicKey;
    const VariableT balancesRootO_before;
    const VariableT nonce_before;
    UnsafeAddGadget nonce_after;
    std::unique_ptr<UpdateAccountGadget> updateAccount_O;

    std::vector<VariableT> labels;
    std::unique_ptr<LabelHasher> labelHasher;

    Poseidon_gadget_T<6, 1, 6, 52, 5, 1> hash;
    SignatureVerifier signatureVerifier;

    RingSettlementCircuit(ProtoboardT& pb, const std::string& prefix) :
        GadgetT(pb, prefix),

        publicDataHash(pb, 256, FMT(prefix, ".publicDataHash")),
        transformData(pb, FMT(prefix, ".transformData")),
        publicData(pb, publicDataHash, FMT(prefix, ".publicData")),

        constants(pb, FMT(prefix, ".constants")),

        exchangeID(pb, 32, FMT(prefix, ".exchangeID")),
        merkleRootBefore(pb, 256, FMT(prefix, ".merkleRootBefore")),
        merkleRootAfter(pb, 256, FMT(prefix, ".merkleRootAfter")),
        timestamp(pb, NUM_BITS_TIMESTAMP, FMT(prefix, ".timestamp")),
        protocolTakerFeeBips(pb, 8, FMT(prefix, ".protocolTakerFeeBips")),
        protocolMakerFeeBips(pb, 8, FMT(prefix, ".protocolMakerFeeBips")),

        balancesRootP_before(make_variable(pb, FMT(prefix, ".balancesRootP_before"))),

        operatorAccountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".operatorAccountID")),
        publicKey(pb, FMT(prefix, ".publicKey")),
        balancesRootO_before(make_variable(pb, FMT(prefix, ".balancesRootO_before"))),
        nonce_before(make_variable(pb, FMT(prefix, ".nonce_before"))),
        nonce_after(pb, nonce_before, constants.one, FMT(prefix, ".nonce_after")),

        hash(pb, var_array({
            exchangeID.packed,
            timestamp.packed,
            merkleRootBefore.packed,
            merkleRootAfter.packed,
            nonce_before
        }), FMT(this->annotation_prefix, ".hash")),
        signatureVerifier(pb, params, publicKey, hash.result(), FMT(prefix, ".signatureVerifier"))
    {

    }

    void generate_r1cs_constraints(bool onchainDataAvailability, int numRings)
    {
        this->onchainDataAvailability = onchainDataAvailability;
        this->numRings = numRings;

        pb.set_input_sizes(1);

        constants.generate_r1cs_constraints();

        exchangeID.generate_r1cs_constraints(true);
        merkleRootBefore.generate_r1cs_constraints(true);
        merkleRootAfter.generate_r1cs_constraints(true);
        timestamp.generate_r1cs_constraints(true);
        protocolTakerFeeBips.generate_r1cs_constraints(true);
        protocolMakerFeeBips.generate_r1cs_constraints(true);
        nonce_after.generate_r1cs_constraints();

        for (size_t j = 0; j < numRings; j++)
        {
            const VariableT ringAccountsRoot = (j == 0) ? merkleRootBefore.packed : ringSettlements.back().getNewAccountsRoot();
            const VariableT& ringProtocolBalancesRoot = (j == 0) ? balancesRootP_before : ringSettlements.back().getNewProtocolBalancesRoot();
            const VariableT& ringOperatorBalancesRoot = (j == 0) ? balancesRootO_before : ringSettlements.back().getNewOperatorBalancesRoot();
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

            labels.push_back(ringSettlements.back().orderA.label.packed);
            labels.push_back(ringSettlements.back().orderB.label.packed);

            if (onchainDataAvailability)
            {
                // Store data from ring settlement
                dataAvailabityData.add(ringSettlements.back().getPublicData());
            }
        }

        // Update the protocol fee pool
        updateAccount_P.reset(new UpdateAccountGadget(pb, ringSettlements.back().getNewAccountsRoot(), constants.zeroAccount,
                      {constants.zero, constants.zero, constants.zero, balancesRootP_before},
                      {constants.zero, constants.zero, constants.zero, ringSettlements.back().getNewProtocolBalancesRoot()},
                      FMT(annotation_prefix, ".updateAccount_P")));
        updateAccount_P->generate_r1cs_constraints();

        // Update the operator
        updateAccount_O.reset(new UpdateAccountGadget(pb, updateAccount_P->result(), operatorAccountID.bits,
                      {publicKey.x, publicKey.y, nonce_before, balancesRootO_before},
                      {publicKey.x, publicKey.y, nonce_after.result(), ringSettlements.back().getNewOperatorBalancesRoot()},
                      FMT(annotation_prefix, ".updateAccount_O")));
        updateAccount_O->generate_r1cs_constraints();

        // Calculate the label hash
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
            publicData.add(constants.accountPadding);
            publicData.add(operatorAccountID.bits);
            // Transform the ring data
            transformData.generate_r1cs_constraints(numRings, flattenReverse(dataAvailabityData.data));
            publicData.add(flattenReverse({transformData.result()}));
        }

        // Check the input hash
        publicDataHash.generate_r1cs_constraints(true);
        publicData.generate_r1cs_constraints();

        // Check the new merkle root
        forceEqual(pb, updateAccount_O->result(), merkleRootAfter.packed, "newMerkleRoot");

        hash.generate_r1cs_constraints();
        signatureVerifier.generate_r1cs_constraints();
    }

    void printInfo()
    {
        std::cout << pb.num_constraints() << " constraints (" << (pb.num_constraints() / numRings) << "/ring)" << std::endl;
    }

    bool generateWitness(const RingSettlementBlock& block)
    {
        if (block.ringSettlements.size() != numRings)
        {
            std::cout << "Invalid number of rings: " << block.ringSettlements.size()  << std::endl;
            return false;
        }

        constants.generate_r1cs_witness();

        exchangeID.bits.fill_with_bits_of_field_element(pb, block.exchangeID);
        exchangeID.generate_r1cs_witness_from_bits();

        merkleRootBefore.bits.fill_with_bits_of_field_element(pb, block.merkleRootBefore);
        merkleRootBefore.generate_r1cs_witness_from_bits();
        merkleRootAfter.bits.fill_with_bits_of_field_element(pb, block.merkleRootAfter);
        merkleRootAfter.generate_r1cs_witness_from_bits();

        timestamp.bits.fill_with_bits_of_field_element(pb, block.timestamp);
        timestamp.generate_r1cs_witness_from_bits();

        protocolTakerFeeBips.bits.fill_with_bits_of_field_element(pb, block.protocolTakerFeeBips);
        protocolTakerFeeBips.generate_r1cs_witness_from_bits();
        protocolMakerFeeBips.bits.fill_with_bits_of_field_element(pb, block.protocolMakerFeeBips);
        protocolMakerFeeBips.generate_r1cs_witness_from_bits();

        operatorAccountID.bits.fill_with_bits_of_field_element(pb, block.operatorAccountID);
        operatorAccountID.generate_r1cs_witness_from_bits();
        pb.val(publicKey.x) = block.accountUpdate_O.before.publicKey.x;
        pb.val(publicKey.y) = block.accountUpdate_O.before.publicKey.y;
        pb.val(balancesRootO_before) = block.accountUpdate_O.before.balancesRoot;
        pb.val(nonce_before) = block.accountUpdate_O.before.nonce;
        nonce_after.generate_r1cs_witness();
        pb.val(balancesRootP_before) = block.accountUpdate_P.before.balancesRoot;

        for(unsigned int i = 0; i < block.ringSettlements.size(); i++)
        {
            ringSettlements[i].generate_r1cs_witness(block.ringSettlements[i]);
        }
        updateAccount_P->generate_r1cs_witness(block.accountUpdate_P.proof);
        updateAccount_O->generate_r1cs_witness(block.accountUpdate_O.proof);

        // Calculate the label hash
        labelHasher->generate_r1cs_witness();

        if (onchainDataAvailability)
        {
            transformData.generate_r1cs_witness();
        }
        publicData.generate_r1cs_witness();

        hash.generate_r1cs_witness();
        signatureVerifier.generate_r1cs_witness(block.signature);

        return true;
    }
};

}

#endif
