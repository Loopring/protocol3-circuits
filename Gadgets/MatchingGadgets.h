#ifndef _MATCHINGGADGETS_H_
#define _MATCHINGGADGETS_H_

#include "../Utils/Constants.h"
#include "../Utils/Data.h"
#include "MathGadgets.h"
#include "OrderGadgets.h"
#include "TradingHistoryGadgets.h"

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "gadgets/subadd.hpp"

using namespace ethsnarks;

namespace Loopring
{

// Checks if the fill rate < 1% worse than the target rate
// (fillAmountS/fillAmountB) * 100 < (amountS/amountB) * 101
// (fillAmountS * amountB * 100) < (fillAmountB * amountS * 101)
class CheckFillRateGadget : public GadgetT
{
public:
    UnsafeMulGadget fillAmountS_mul_amountB;
    UnsafeMulGadget fillAmountS_mul_amountB_mul_100;

    UnsafeMulGadget fillAmountB_mul_amountS;
    UnsafeMulGadget fillAmountB_mul_amountS_mul_101;

    LeqGadget valid;

    CheckFillRateGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const VariableT& amountS,
        const VariableT& amountB,
        const VariableT& fillAmountS,
        const VariableT& fillAmountB,
        unsigned int n,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        fillAmountS_mul_amountB(pb, fillAmountS, amountB, FMT(prefix, ".fillAmountS_mul_amountB")),
        fillAmountS_mul_amountB_mul_100(pb, fillAmountS_mul_amountB.result(), constants._100, FMT(prefix, ".fillAmountS_mul_amountB_mul_100")),

        fillAmountB_mul_amountS(pb, fillAmountB, amountS, FMT(prefix, ".fillAmountB_mul_amountS")),
        fillAmountB_mul_amountS_mul_101(pb, fillAmountB_mul_amountS.result(), constants._101, FMT(prefix, ".fillAmountB_mul_amountS_mul_101")),

        valid(pb, fillAmountS_mul_amountB_mul_100.result(), fillAmountB_mul_amountS_mul_101.result(), n * 2 + 7 /*=ceil(log2(100))*/, FMT(prefix, ".valid"))
    {

    }

    void generate_r1cs_witness()
    {
        fillAmountS_mul_amountB.generate_r1cs_witness();
        fillAmountS_mul_amountB_mul_100.generate_r1cs_witness();

        fillAmountB_mul_amountS.generate_r1cs_witness();
        fillAmountB_mul_amountS_mul_101.generate_r1cs_witness();

        valid.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        fillAmountS_mul_amountB.generate_r1cs_constraints();
        fillAmountS_mul_amountB_mul_100.generate_r1cs_constraints();

        fillAmountB_mul_amountS.generate_r1cs_constraints();
        fillAmountB_mul_amountS_mul_101.generate_r1cs_constraints();

        valid.generate_r1cs_constraints();
    }

    const VariableT& isValid()
    {
        return valid.lt();
    }
};

// Check if an order is filled correctly
class CheckValidGadget : public GadgetT
{
public:

    LeqGadget fillAmountS_lt_amountS;
    LeqGadget fillAmountB_lt_amountB;
    NotGadget order_sell;
    AndGadget notValidAllOrNoneSell;
    AndGadget notValidAllOrNoneBuy;

    LeqGadget validSince_leq_timestamp;
    LeqGadget timestamp_leq_validUntil;

    CheckFillRateGadget checkFillRate;

    NotGadget validAllOrNoneSell;
    NotGadget validAllOrNoneBuy;

    IsNonZero isNonZeroFillAmountS;
    IsNonZero isNonZeroFillAmountB;

    AndGadget valid;

    CheckValidGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const VariableT& timestamp,
        const OrderGadget& order,
        const VariableT& fillAmountS,
        const VariableT& fillAmountB,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        // This can be combined in a single comparison (buy/sell order)
        fillAmountS_lt_amountS(pb, fillAmountS, order.amountS.packed, NUM_BITS_AMOUNT, FMT(prefix, ".fillAmountS_lt_amountS")),
        fillAmountB_lt_amountB(pb, fillAmountB, order.amountB.packed, NUM_BITS_AMOUNT, FMT(prefix, ".fillAmountB_lt_amountB")),
        order_sell(pb, order.buy.packed, FMT(prefix, ".order_sell")),
        notValidAllOrNoneSell(pb, { order.allOrNone.packed, order_sell.result(), fillAmountS_lt_amountS.lt() }, FMT(prefix, ".notValidAllOrNoneSell")),
        notValidAllOrNoneBuy(pb, { order.allOrNone.packed, order.buy.packed, fillAmountB_lt_amountB.lt() }, FMT(prefix, ".notValidAllOrNoneBuy")),

        validSince_leq_timestamp(pb, order.validSince.packed, timestamp, NUM_BITS_TIMESTAMP, FMT(prefix, "validSince <= timestamp")),
        timestamp_leq_validUntil(pb, timestamp, order.validUntil.packed, NUM_BITS_TIMESTAMP, FMT(prefix, "timestamp <= validUntil")),

        validAllOrNoneSell(pb, notValidAllOrNoneSell.result(), FMT(prefix, "validAllOrNoneSell")),
        validAllOrNoneBuy(pb, notValidAllOrNoneBuy.result(), FMT(prefix, "validAllOrNoneBuy")),

        checkFillRate(pb, constants, order.amountS.packed, order.amountB.packed, fillAmountS, fillAmountB, NUM_BITS_AMOUNT, FMT(prefix, ".checkFillRate")),

        // This is an important check that makes sure no token transfers can happen to unregistered token IDs
        isNonZeroFillAmountS(pb, fillAmountS, FMT(prefix, "isNonZeroFillAmountS")),
        isNonZeroFillAmountB(pb, fillAmountB, FMT(prefix, "isNonZeroFillAmountB")),

        valid(pb,
                {
                    validSince_leq_timestamp.leq(),
                    timestamp_leq_validUntil.leq(),
                    checkFillRate.isValid(),
                    validAllOrNoneSell.result(),
                    validAllOrNoneBuy.result(),
                    isNonZeroFillAmountS.result(),
                    isNonZeroFillAmountB.result()
                },
                FMT(prefix, ".valid")
            )
    {

    }

    void generate_r1cs_witness ()
    {
        fillAmountS_lt_amountS.generate_r1cs_witness();
        fillAmountB_lt_amountB.generate_r1cs_witness();
        order_sell.generate_r1cs_witness();
        notValidAllOrNoneSell.generate_r1cs_witness();
        notValidAllOrNoneBuy.generate_r1cs_witness();

        validSince_leq_timestamp.generate_r1cs_witness();
        timestamp_leq_validUntil.generate_r1cs_witness();

        validAllOrNoneSell.generate_r1cs_witness();
        validAllOrNoneBuy.generate_r1cs_witness();

        checkFillRate.generate_r1cs_witness();

        isNonZeroFillAmountS.generate_r1cs_witness();
        isNonZeroFillAmountB.generate_r1cs_witness();

        valid.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        fillAmountS_lt_amountS.generate_r1cs_constraints();
        fillAmountB_lt_amountB.generate_r1cs_constraints();
        order_sell.generate_r1cs_constraints();
        notValidAllOrNoneSell.generate_r1cs_constraints();
        notValidAllOrNoneBuy.generate_r1cs_constraints();

        validSince_leq_timestamp.generate_r1cs_constraints();
        timestamp_leq_validUntil.generate_r1cs_constraints();

        validAllOrNoneSell.generate_r1cs_constraints();
        validAllOrNoneBuy.generate_r1cs_constraints();

        checkFillRate.generate_r1cs_constraints();

        isNonZeroFillAmountS.generate_r1cs_constraints();
        isNonZeroFillAmountB.generate_r1cs_constraints();

        valid.generate_r1cs_constraints();
    }

    const VariableT& isValid()
    {
        return valid.result();
    }
};

// Calculates the fees for an order
class FeeCalculatorGadget : public GadgetT
{
public:

    // We could combine the fee and rebate calculations here, saving a MulDiv, but the MulDiv is cheap here,
    // so let's keep things simple.
    MulDivGadget protocolFee;
    MulDivGadget fee;
    MulDivGadget rebate;

    FeeCalculatorGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const VariableT& amountB,
        const VariableT& protocolFeeBips,
        const VariableT& feeBips,
        const VariableT& rebateBips,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        protocolFee(pb, constants, amountB, protocolFeeBips, constants._100000, NUM_BITS_AMOUNT, NUM_BITS_PROTOCOL_FEE_BIPS, 17 /*=ceil(log2(100000))*/, FMT(prefix, ".protocolFee")),
        fee(pb, constants, amountB, feeBips, constants._10000, NUM_BITS_AMOUNT, NUM_BITS_BIPS, 14 /*=ceil(log2(10000))*/, FMT(prefix, ".fee")),
        rebate(pb, constants, amountB, rebateBips, constants._10000, NUM_BITS_AMOUNT, NUM_BITS_BIPS, 14 /*=ceil(log2(10000))*/, FMT(prefix, ".rebate"))
    {

    }

    void generate_r1cs_witness()
    {
        protocolFee.generate_r1cs_witness();
        fee.generate_r1cs_witness();
        rebate.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        protocolFee.generate_r1cs_constraints();
        fee.generate_r1cs_constraints();
        rebate.generate_r1cs_constraints();
    }

    const VariableT& getProtocolFee() const
    {
        return protocolFee.result();
    }

    const VariableT& getFee() const
    {
        return fee.result();
    }

    const VariableT& getRebate() const
    {
        return rebate.result();
    }
};

// Calculate the max fill amounts of the order
class MaxFillAmountsGadget : public GadgetT
{
public:

    TernaryGadget limit;
    MinGadget filledLimited;
    UnsafeSubGadget remainingBeforeCancelled;
    TernaryGadget remaining;
    MulDivGadget remainingS_buy;
    TernaryGadget remainingS;
    MinGadget fillAmountS;
    MulDivGadget fillAmountB;

    MaxFillAmountsGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const OrderGadget& order,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        // All results here are guaranteed to fit in NUM_BITS_AMOUNT bits
        // `remainingS_buy = remaining * order.amountS // order.amountB`
        // `remainingS_buy` has a maximum value of order.amountB, so needs NUM_BITS_AMOUNT max.
        // `fillAmountB = fillAmountS * order.amountB // order.amountS`
        // `fillAmountS` has a maximum value of order.amountS, so needs NUM_BITS_AMOUNT max.

        limit(pb, order.buy.packed, order.amountB.packed, order.amountS.packed, FMT(prefix, ".limit")),
        filledLimited(pb, limit.result(), order.tradeHistory.getFilled(), NUM_BITS_AMOUNT, FMT(prefix, ".filledLimited")),
        remainingBeforeCancelled(pb, limit.result(), filledLimited.result(), FMT(prefix, ".remainingBeforeCancelled")),
        remaining(pb, order.tradeHistory.getCancelled(), constants.zero, remainingBeforeCancelled.result(), FMT(prefix, ".remaining")),
        remainingS_buy(pb, constants, remaining.result(), order.amountS.packed, order.amountB.packed, NUM_BITS_AMOUNT, NUM_BITS_AMOUNT, NUM_BITS_AMOUNT, FMT(prefix, ".remainingS_buy")),
        remainingS(pb, order.buy.packed, remainingS_buy.result(), remaining.result(), FMT(prefix, ".remainingS")),
        fillAmountS(pb, order.balanceSBefore.balance, remainingS.result(), NUM_BITS_AMOUNT, FMT(prefix, ".fillAmountS")),
        fillAmountB(pb, constants, fillAmountS.result(), order.amountB.packed, order.amountS.packed, NUM_BITS_AMOUNT, NUM_BITS_AMOUNT, NUM_BITS_AMOUNT, FMT(prefix, ".fillAmountB"))
    {

    }

    void generate_r1cs_witness()
    {
        limit.generate_r1cs_witness();
        filledLimited.generate_r1cs_witness();
        remainingBeforeCancelled.generate_r1cs_witness();
        remaining.generate_r1cs_witness();
        remainingS_buy.generate_r1cs_witness();
        remainingS.generate_r1cs_witness();
        fillAmountS.generate_r1cs_witness();
        fillAmountB.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        limit.generate_r1cs_constraints();
        filledLimited.generate_r1cs_constraints();
        remainingBeforeCancelled.generate_r1cs_constraints();
        remaining.generate_r1cs_constraints();
        remainingS_buy.generate_r1cs_constraints();
        remainingS.generate_r1cs_constraints();
        fillAmountS.generate_r1cs_constraints();
        fillAmountB.generate_r1cs_constraints();
    }

    // fillAmountS uses NUM_BITS_AMOUNT bits max
    const VariableT& getFillAmountS()
    {
        return fillAmountS.result();
    }

    // fillAmountB uses NUM_BITS_AMOUNT bits max
    const VariableT& getFillAmountB()
    {
        return fillAmountB.result();
    }
};

struct Amounts
{
    const VariableT amountS;
    const VariableT amountB;
};

struct Fill
{
    const VariableT S;
    const VariableT B;
};

// Calculates the settlement fill amounts of 2 orders
class TakerMakerMatchingGadget : public GadgetT
{
public:

    LeqGadget takerFillB_lt_makerFillS;

    TernaryGadget value;
    TernaryGadget numerator;
    TernaryGadget denominator;
    MulDivGadget newFill;

    TernaryGadget makerFillS;
    TernaryGadget makerFillB;
    TernaryGadget takerFillS;
    TernaryGadget takerFillB;

    LeqGadget bMatchable;

    TakerMakerMatchingGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const Amounts& takerOrder,
        const Fill& takerFill,
        const Amounts& makerOrder,
        const Fill& makerFill,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        takerFillB_lt_makerFillS(pb, takerFill.B, makerFill.S, NUM_BITS_AMOUNT, FMT(prefix, ".takerFill.B < makerFill.B")),

        // Do a single MulDiv for both case:
        // - if takerFill.B < makerFill.S: takerFill.B * makerOrder.amountB // makerOrder.amountS
        // - else: makerFill.S * takerOrder.amountS // takerOrder.amountB
        value(pb, takerFillB_lt_makerFillS.lt(), takerFill.B, makerFill.S, FMT(prefix, ".value")),
        numerator(pb, takerFillB_lt_makerFillS.lt(), makerOrder.amountB, takerOrder.amountS, FMT(prefix, ".numerator")),
        denominator(pb, takerFillB_lt_makerFillS.lt(), makerOrder.amountS, takerOrder.amountB, FMT(prefix, ".denominator")),
        newFill(pb, constants, value.result(), numerator.result(), denominator.result(), NUM_BITS_AMOUNT, NUM_BITS_AMOUNT, NUM_BITS_AMOUNT, FMT(prefix, ".newFill")),

        makerFillS(pb, takerFillB_lt_makerFillS.lt(), takerFill.B, makerFill.S, FMT(prefix, ".makerFillS")),
        makerFillB(pb, takerFillB_lt_makerFillS.lt(), newFill.result(), makerFill.B, FMT(prefix, ".makerFillB")),
        takerFillS(pb, takerFillB_lt_makerFillS.lt(), takerFill.S, newFill.result(), FMT(prefix, ".takerFillS")),
        takerFillB(pb, takerFillB_lt_makerFillS.lt(), takerFill.B, makerFill.S, FMT(prefix, ".takerFillB")),

        bMatchable(pb, makerFillB.result(), takerFillS.result(), NUM_BITS_AMOUNT, FMT(prefix, ".bMatchable"))
    {

    }

    void generate_r1cs_witness()
    {
        takerFillB_lt_makerFillS.generate_r1cs_witness();

        value.generate_r1cs_witness();
        numerator.generate_r1cs_witness();
        denominator.generate_r1cs_witness();
        newFill.generate_r1cs_witness();

        makerFillS.generate_r1cs_witness();
        makerFillB.generate_r1cs_witness();
        takerFillS.generate_r1cs_witness();
        takerFillB.generate_r1cs_witness();

        bMatchable.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        takerFillB_lt_makerFillS.generate_r1cs_constraints();

        value.generate_r1cs_constraints();
        numerator.generate_r1cs_constraints();
        denominator.generate_r1cs_constraints();
        newFill.generate_r1cs_constraints();

        makerFillS.generate_r1cs_constraints();
        makerFillB.generate_r1cs_constraints();
        takerFillS.generate_r1cs_constraints();
        takerFillB.generate_r1cs_constraints();

        bMatchable.generate_r1cs_constraints();
    }

    const VariableT& getTakerFillS() const
    {
        return takerFillS.result();
    }

    const VariableT& getTakerFillB() const
    {
        return takerFillB.result();
    }

    const VariableT& getMakerFillS() const
    {
        return makerFillS.result();
    }

    const VariableT& getMakerFillB() const
    {
        return makerFillB.result();
    }

    const VariableT& isMatchable() const
    {
        return bMatchable.leq();
    }
};

// Does TakerMakerMatchingGadget(orderA, orderB) if orderA is a buy order (with fillA.S = fillB.B),
// else TakerMakerMatchingGadget(orderB, orderA) (with fillA.B = fillB.S)
class MatchingGadget : public GadgetT
{
public:
    TernaryGadget takerAmountS;
    TernaryGadget takerAmountB;
    TernaryGadget takerFillS;
    TernaryGadget takerFillB;

    TernaryGadget makerAmountS;
    TernaryGadget makerAmountB;
    TernaryGadget makerFillS;
    TernaryGadget makerFillB;

    TakerMakerMatchingGadget matchingGadget;

    TernaryGadget fillA_S;
    TernaryGadget fillA_B;
    TernaryGadget fillB_S;
    TernaryGadget fillB_B;

    MatchingGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const OrderGadget& orderA,
        const Fill inFillA,
        const OrderGadget& orderB,
        const Fill inFillB,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        takerAmountS(pb, orderA.buy.packed, orderA.amountS.packed, orderB.amountS.packed, FMT(prefix, ".takerAmountS")),
        takerAmountB(pb, orderA.buy.packed, orderA.amountB.packed, orderB.amountB.packed, FMT(prefix, ".takerAmountB")),
        takerFillS(pb, orderA.buy.packed, inFillA.S, inFillB.S, FMT(prefix, ".takerFillS")),
        takerFillB(pb, orderA.buy.packed, inFillA.B, inFillB.B, FMT(prefix, ".takerFillB")),

        makerAmountS(pb, orderA.buy.packed, orderB.amountS.packed, orderA.amountS.packed, FMT(prefix, ".makerAmountS")),
        makerAmountB(pb, orderA.buy.packed, orderB.amountB.packed, orderA.amountB.packed, FMT(prefix, ".makerAmountB")),
        makerFillS(pb, orderA.buy.packed, inFillB.S, inFillA.S, FMT(prefix, ".makerFillS")),
        makerFillB(pb, orderA.buy.packed, inFillB.B, inFillA.B, FMT(prefix, ".makerFillB")),

        matchingGadget(pb, constants,
                       {takerAmountS.result(), takerAmountB.result()}, {takerFillS.result(), takerFillB.result()},
                       {makerAmountS.result(), makerAmountB.result()}, {makerFillS.result(), makerFillB.result()},
                       FMT(prefix, ".matchingGadget")),

        fillA_S(pb, orderA.buy.packed, matchingGadget.getMakerFillB(), matchingGadget.getMakerFillS(), FMT(prefix, ".fillA_S")),
        fillA_B(pb, orderA.buy.packed, matchingGadget.getTakerFillB(), matchingGadget.getTakerFillS(), FMT(prefix, ".fillA_B")),
        fillB_S(pb, orderA.buy.packed, matchingGadget.getMakerFillS(), matchingGadget.getTakerFillS(), FMT(prefix, ".fillB_S")),
        fillB_B(pb, orderA.buy.packed, matchingGadget.getMakerFillB(), matchingGadget.getTakerFillB(), FMT(prefix, ".fillB_B"))
    {

    }

    void generate_r1cs_witness()
    {
        takerAmountS.generate_r1cs_witness();
        takerAmountB.generate_r1cs_witness();
        takerFillS.generate_r1cs_witness();
        takerFillB.generate_r1cs_witness();

        makerAmountS.generate_r1cs_witness();
        makerAmountB.generate_r1cs_witness();
        makerFillS.generate_r1cs_witness();
        makerFillB.generate_r1cs_witness();

        matchingGadget.generate_r1cs_witness();

        fillA_S.generate_r1cs_witness();
        fillA_B.generate_r1cs_witness();
        fillB_S.generate_r1cs_witness();
        fillB_B.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        takerAmountS.generate_r1cs_constraints();
        takerAmountB.generate_r1cs_constraints();
        takerFillS.generate_r1cs_constraints();
        takerFillB.generate_r1cs_constraints();

        makerAmountS.generate_r1cs_constraints();
        makerAmountB.generate_r1cs_constraints();
        makerFillS.generate_r1cs_constraints();
        makerFillB.generate_r1cs_constraints();

        matchingGadget.generate_r1cs_constraints();

        fillA_S.generate_r1cs_constraints();
        fillA_B.generate_r1cs_constraints();
        fillB_S.generate_r1cs_constraints();
        fillB_B.generate_r1cs_constraints();
    }

    const VariableT& getFillA_S() const
    {
        return fillA_S.result();
    }

    const VariableT& getFillA_B() const
    {
        return fillA_B.result();
    }

    const VariableT& getFillB_S() const
    {
        return fillB_S.result();
    }

    const VariableT& getFillB_B() const
    {
        return fillB_B.result();
    }

    const VariableT& isMatchable() const
    {
        return matchingGadget.isMatchable();
    }
};

// Matches 2 orders
class OrderMatchingGadget : public GadgetT
{
public:

    // Get the max amount the orders can be filled
    MaxFillAmountsGadget maxFillAmountA;
    MaxFillAmountsGadget maxFillAmountB;

    // Match the orders
    MatchingGadget matchingGadget;

    // Check if tokenS/tokenB match
    RequireEqualGadget orderA_tokenS_eq_orderB_tokenB;
    RequireEqualGadget orderA_tokenB_eq_orderB_tokenS;

    // Check if the orders in the settlement are correctly filled
    CheckValidGadget checkValidA;
    CheckValidGadget checkValidB;
    AndGadget valid;

    OrderMatchingGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const VariableT& timestamp,
        const OrderGadget& orderA,
        const OrderGadget& orderB,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        // Get the max amount the orders can be filled
        maxFillAmountA(pb, constants, orderA, FMT(prefix, ".maxFillAmountA")),
        maxFillAmountB(pb, constants, orderB, FMT(prefix, ".maxFillAmountB")),

        // Match the orders
        matchingGadget(pb, constants,
                       orderA, {maxFillAmountA.getFillAmountS(), maxFillAmountA.getFillAmountB()},
                       orderB, {maxFillAmountB.getFillAmountS(), maxFillAmountB.getFillAmountB()},
                       FMT(prefix, ".matchingGadget")),

        // Check if tokenS/tokenB match
        orderA_tokenS_eq_orderB_tokenB(pb, orderA.tokenS.packed, orderB.tokenB.packed, FMT(prefix, ".orderA_tokenS_eq_orderB_tokenB")),
        orderA_tokenB_eq_orderB_tokenS(pb, orderA.tokenB.packed, orderB.tokenS.packed, FMT(prefix, ".orderA_tokenB_eq_orderB_tokenS")),

        // Check if the orders in the settlement are correctly filled
        checkValidA(pb, constants, timestamp, orderA, matchingGadget.getFillA_S(), matchingGadget.getFillA_B(), FMT(prefix, ".checkValidA")),
        checkValidB(pb, constants, timestamp, orderB, matchingGadget.getFillB_S(), matchingGadget.getFillB_B(), FMT(prefix, ".checkValidB")),
        valid(pb, {matchingGadget.isMatchable(), checkValidA.isValid(), checkValidB.isValid()}, FMT(prefix, ".valid"))
    {

    }

    void generate_r1cs_witness()
    {
        // Get the max amount the orders can be filled
        maxFillAmountA.generate_r1cs_witness();
        maxFillAmountB.generate_r1cs_witness();

        // Match the orders
        matchingGadget.generate_r1cs_witness();

        // Check if tokenS/tokenB match
        orderA_tokenS_eq_orderB_tokenB.generate_r1cs_witness();
        orderA_tokenB_eq_orderB_tokenS.generate_r1cs_witness();

        // Check if the orders in the settlement are correctly filled
        checkValidA.generate_r1cs_witness();
        checkValidB.generate_r1cs_witness();
        valid.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        // Get the max amount the orders can be filled
        maxFillAmountA.generate_r1cs_constraints();
        maxFillAmountB.generate_r1cs_constraints();

        // Match the orders
        matchingGadget.generate_r1cs_constraints();

        // Check if tokenS/tokenB match
        orderA_tokenS_eq_orderB_tokenB.generate_r1cs_constraints();
        orderA_tokenB_eq_orderB_tokenS.generate_r1cs_constraints();

        // Check if the orders in the settlement are correctly filled
        checkValidA.generate_r1cs_constraints();
        checkValidB.generate_r1cs_constraints();
        valid.generate_r1cs_constraints();
    }

    const VariableT& getFillA_S() const
    {
        return matchingGadget.getFillA_S();
    }

    const VariableT& getFillA_B() const
    {
        return matchingGadget.getFillA_B();
    }

    const VariableT& getFillB_S() const
    {
        return matchingGadget.getFillB_S();
    }

    const VariableT& getFillB_B() const
    {
        return matchingGadget.getFillB_B();
    }

    const VariableT& isValid() const
    {
        return valid.result();
    }
};


}

#endif
