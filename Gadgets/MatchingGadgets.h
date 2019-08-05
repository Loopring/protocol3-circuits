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

class RoundingErrorGadget : public GadgetT
{
public:
    MulDivGadget mulDiv;
    VariableT remainderx100;
    LeqGadget multiplied_lt_remainderx100;
    VariableT valid;

    RoundingErrorGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const VariableT& _value,
        const VariableT& _numerator,
        const VariableT& _denominator,
        unsigned int numBitsDenominator,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        mulDiv(pb, constants, _value, _numerator, _denominator, numBitsDenominator, FMT(prefix, ".multiplied")),
        remainderx100(make_variable(pb, FMT(prefix, ".remainderx100"))),
        multiplied_lt_remainderx100(pb, mulDiv.multiplied(), remainderx100, NUM_BITS_AMOUNT * 2, FMT(prefix, ".multiplied_lt_remainderx100")),
        valid(make_variable(pb, FMT(prefix, ".valid")))
    {

    }

    const VariableT& isValid()
    {
        return valid;
    }

    void generate_r1cs_witness()
    {
        mulDiv.generate_r1cs_witness();
        pb.val(remainderx100) = pb.val(mulDiv.getRemainder()) * 100;
        multiplied_lt_remainderx100.generate_r1cs_witness();
        pb.val(valid) = FieldT::one() - pb.val(multiplied_lt_remainderx100.lt());
    }

    void generate_r1cs_constraints()
    {
        mulDiv.generate_r1cs_constraints();
        pb.add_r1cs_constraint(ConstraintT(mulDiv.getRemainder() * 100, FieldT::one(), remainderx100), FMT(annotation_prefix, ".remainder * 100 == remainderx100"));
        multiplied_lt_remainderx100.generate_r1cs_constraints();
        pb.add_r1cs_constraint(ConstraintT(FieldT::one() - multiplied_lt_remainderx100.lt(), FieldT::one(), valid), FMT(annotation_prefix, ".valid"));
    }
};

class FeeCalculatorGadget : public GadgetT
{
public:

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

        protocolFee(pb, constants, amountB, protocolFeeBips, constants._100000, 17 /*=ceil(log2(100000))*/, FMT(prefix, ".protocolFee")),
        fee(pb, constants, amountB, feeBips, constants._10000, 14 /*=ceil(log2(10000))*/, FMT(prefix, ".fee")),
        rebate(pb, constants, amountB, rebateBips, constants._10000, 14 /*=ceil(log2(10000))*/, FMT(prefix, ".rebate"))
    {

    }

    const VariableT getProtocolFee() const
    {
        return protocolFee.result();
    }

    const VariableT getFee() const
    {
        return fee.result();
    }

    const VariableT getRebate() const
    {
        return rebate.result();
    }

    void generate_r1cs_witness()
    {
        protocolFee.generate_r1cs_witness();
        fee.generate_r1cs_witness();
        rebate.generate_r1cs_witness();

        // print(pb, "protocolFee: ", protocolFee.result());
        // print(pb, "fee: ", fee.result());
        // print(pb, "rebate: ", rebate.result());
    }

    void generate_r1cs_constraints()
    {
        protocolFee.generate_r1cs_constraints();
        fee.generate_r1cs_constraints();
        rebate.generate_r1cs_constraints();
    }
};

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

    RoundingErrorGadget checkRoundingError;

    NotGadget validAllOrNoneSell;
    NotGadget validAllOrNoneBuy;

    LeqGadget zero_lt_fillAmountS;
    LeqGadget zero_lt_fillAmountB;

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

        fillAmountS_lt_amountS(pb, fillAmountS, order.amountS.packed, NUM_BITS_AMOUNT * 2, FMT(prefix, ".fillAmountS_lt_amountS")),
        fillAmountB_lt_amountB(pb, fillAmountB, order.amountB.packed, NUM_BITS_AMOUNT * 2, FMT(prefix, ".fillAmountB_lt_amountB")),
        order_sell(pb, order.buy.packed, FMT(prefix, ".order_sell")),
        notValidAllOrNoneSell(pb, { order.allOrNone.packed, order_sell.result(), fillAmountS_lt_amountS.lt() }, FMT(prefix, ".notValidAllOrNoneSell")),
        notValidAllOrNoneBuy(pb, { order.allOrNone.packed, order.buy.packed, fillAmountB_lt_amountB.lt() }, FMT(prefix, ".notValidAllOrNoneBuy")),

        validSince_leq_timestamp(pb, order.validSince.packed, timestamp, NUM_BITS_AMOUNT * 2, FMT(prefix, "validSince <= timestamp")),
        timestamp_leq_validUntil(pb, timestamp, order.validUntil.packed, NUM_BITS_TIMESTAMP, FMT(prefix, "timestamp <= validUntil")),

        validAllOrNoneSell(pb, notValidAllOrNoneSell.result(), FMT(prefix, "validAllOrNoneSell")),
        validAllOrNoneBuy(pb, notValidAllOrNoneBuy.result(), FMT(prefix, "validAllOrNoneBuy")),

        checkRoundingError(pb, constants, fillAmountS, order.amountB.packed, order.amountS.packed, NUM_BITS_AMOUNT, FMT(prefix, ".checkRoundingError")),

        zero_lt_fillAmountS(pb, constants.zero, fillAmountS, NUM_BITS_AMOUNT, FMT(prefix, "0 < _fillAmountS")),
        zero_lt_fillAmountB(pb, constants.zero, fillAmountB, NUM_BITS_AMOUNT, FMT(prefix, "0 < _fillAmountB")),

        valid(pb,
                {
                    validSince_leq_timestamp.leq(),
                    timestamp_leq_validUntil.leq(),
                    checkRoundingError.isValid(),
                    validAllOrNoneSell.result(),
                    validAllOrNoneBuy.result(),
                    zero_lt_fillAmountS.lt(),
                    zero_lt_fillAmountB.lt()
                },
                FMT(prefix, ".valid")
            )
    {

    }

    const VariableT& isValid()
    {
        return valid.result();
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

        checkRoundingError.generate_r1cs_witness();

        zero_lt_fillAmountS.generate_r1cs_witness();
        zero_lt_fillAmountB.generate_r1cs_witness();

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

        checkRoundingError.generate_r1cs_constraints();

        zero_lt_fillAmountS.generate_r1cs_constraints();
        zero_lt_fillAmountB.generate_r1cs_constraints();

        valid.generate_r1cs_constraints();
    }
};

class MaxFillAmountsGadget : public GadgetT
{
public:
    const OrderGadget& order;

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
        const OrderGadget& _order,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        order(_order),

        limit(pb, order.buy.packed, order.amountB.packed, order.amountS.packed, FMT(prefix, ".limit")),
        filledLimited(pb, limit.result(), order.tradeHistory.getFilled(), NUM_BITS_AMOUNT, FMT(prefix, ".filledLimited")),
        remainingBeforeCancelled(pb, limit.result(), filledLimited.result(), FMT(prefix, ".remainingBeforeCancelled")),
        remaining(pb, order.tradeHistory.getCancelled(), constants.zero, remainingBeforeCancelled.result(), FMT(prefix, ".remaining")),
        remainingS_buy(pb, constants, remaining.result(), order.amountS.packed, order.amountB.packed, NUM_BITS_AMOUNT, FMT(prefix, ".remainingS_buy")),
        remainingS(pb, order.buy.packed, remainingS_buy.result(), remaining.result(), FMT(prefix, ".remainingS")),
        fillAmountS(pb, order.balanceS, remainingS.result(), NUM_BITS_AMOUNT, FMT(prefix, ".fillAmountS")),
        fillAmountB(pb, constants, fillAmountS.result(), order.amountB.packed, order.amountS.packed, NUM_BITS_AMOUNT, FMT(prefix, ".fillAmountB"))
    {

    }

    const VariableT& getAmountS()
    {
        return fillAmountS.result();
    }

    const VariableT& getAmountB()
    {
        return fillAmountB.result();
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

        // print(pb, "amountS", order.amountS.packed);
        // print(pb, "remainingBeforeCancelled", remainingBeforeCancelled.result());
        // print(pb, "remainingS", remainingS.result());
        // print(pb, "filledBefore", order.tradeHistory.getFilled());
        // print(pb, "order.balanceS", order.balanceS);
        // print(pb, "MaxFillAmountS", fillAmountS.result());
        // print(pb, "MaxFillAmountB", fillAmountB.result());
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

class TakerMakerMatchingGadget : public GadgetT
{
public:

    const Amounts _takerOrder;
    const Fill _takerFill;
    const Amounts _makerOrder;
    const Fill _makerFill;

    LeqGadget takerFillB_lt_makerFillS;

    MulDivGadget makerFillB_T;
    MulDivGadget takerFillS_F;

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

        _takerOrder(takerOrder),
        _takerFill(takerFill),
        _makerOrder(makerOrder),
        _makerFill(makerFill),

        takerFillB_lt_makerFillS(pb, takerFill.B, makerFill.S, NUM_BITS_AMOUNT * 2, FMT(prefix, ".takerFill.B < makerFill.B")),

        makerFillB_T(pb, constants, takerFill.B, makerOrder.amountB, makerOrder.amountS, NUM_BITS_AMOUNT, FMT(prefix, ".makerFillB_T")),
        takerFillS_F(pb, constants, makerFill.S, takerOrder.amountS, takerOrder.amountB, NUM_BITS_AMOUNT, FMT(prefix, ".takerFillS_F")),

        makerFillS(pb, takerFillB_lt_makerFillS.lt(), takerFill.B, makerFill.S, FMT(prefix, ".makerFillS")),
        makerFillB(pb, takerFillB_lt_makerFillS.lt(), makerFillB_T.result(), makerFill.B, FMT(prefix, ".makerFillB")),
        takerFillS(pb, takerFillB_lt_makerFillS.lt(), takerFill.S, takerFillS_F.result(), FMT(prefix, ".takerFillS")),
        takerFillB(pb, takerFillB_lt_makerFillS.lt(), takerFill.B, makerFill.S, FMT(prefix, ".takerFillB")),

        bMatchable(pb, makerFillB.result(), takerFillS.result(), NUM_BITS_AMOUNT, FMT(prefix, ".bMatchable"))
    {

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

    void generate_r1cs_witness()
    {
        takerFillB_lt_makerFillS.generate_r1cs_witness();

        makerFillB_T.generate_r1cs_witness();
        takerFillS_F.generate_r1cs_witness();

        makerFillS.generate_r1cs_witness();
        makerFillB.generate_r1cs_witness();
        takerFillS.generate_r1cs_witness();
        takerFillB.generate_r1cs_witness();

        bMatchable.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        takerFillB_lt_makerFillS.generate_r1cs_constraints();

        makerFillB_T.generate_r1cs_constraints();
        takerFillS_F.generate_r1cs_constraints();

        makerFillS.generate_r1cs_constraints();
        makerFillB.generate_r1cs_constraints();
        takerFillS.generate_r1cs_constraints();
        takerFillB.generate_r1cs_constraints();

        bMatchable.generate_r1cs_constraints();
    }
};


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
};


class OrderMatchingGadget : public GadgetT
{
public:

    MaxFillAmountsGadget maxFillAmountA;
    MaxFillAmountsGadget maxFillAmountB;

    MatchingGadget matchingGadget;

    RequireEqualGadget orderA_tokenS_eq_orderB_tokenB;
    RequireEqualGadget orderA_tokenB_eq_orderB_tokenS;

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

        maxFillAmountA(pb, constants, orderA, FMT(prefix, ".maxFillAmountA")),
        maxFillAmountB(pb, constants, orderB, FMT(prefix, ".maxFillAmountB")),

        matchingGadget(pb, constants,
                       orderA, {maxFillAmountA.getAmountS(), maxFillAmountA.getAmountB()},
                       orderB, {maxFillAmountB.getAmountS(), maxFillAmountB.getAmountB()},
                       FMT(prefix, ".matchingGadget")),

        // Check if tokenS/tokenB match
        orderA_tokenS_eq_orderB_tokenB(pb, orderA.tokenS.packed, orderB.tokenB.packed, FMT(prefix, ".orderA_tokenS_eq_orderB_tokenB")),
        orderA_tokenB_eq_orderB_tokenS(pb, orderA.tokenB.packed, orderB.tokenS.packed, FMT(prefix, ".orderA_tokenB_eq_orderB_tokenS")),

        checkValidA(pb, constants, timestamp, orderA, matchingGadget.getFillA_S(), matchingGadget.getFillA_B(), FMT(prefix, ".checkValidA")),
        checkValidB(pb, constants, timestamp, orderB, matchingGadget.getFillB_S(), matchingGadget.getFillB_B(), FMT(prefix, ".checkValidB")),
        valid(pb, {matchingGadget.isMatchable(), checkValidA.isValid(), checkValidB.isValid()}, FMT(prefix, ".valid"))
    {

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

    void generate_r1cs_witness()
    {
        maxFillAmountA.generate_r1cs_witness();
        maxFillAmountB.generate_r1cs_witness();

        matchingGadget.generate_r1cs_witness();

        orderA_tokenS_eq_orderB_tokenB.generate_r1cs_witness();
        orderA_tokenB_eq_orderB_tokenS.generate_r1cs_witness();

        checkValidA.generate_r1cs_witness();
        checkValidB.generate_r1cs_witness();
        valid.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        maxFillAmountA.generate_r1cs_constraints();
        maxFillAmountB.generate_r1cs_constraints();

        matchingGadget.generate_r1cs_constraints();

        orderA_tokenS_eq_orderB_tokenB.generate_r1cs_constraints();
        orderA_tokenB_eq_orderB_tokenS.generate_r1cs_constraints();

        checkValidA.generate_r1cs_constraints();
        checkValidB.generate_r1cs_constraints();
        valid.generate_r1cs_constraints();
    }
};


}

#endif
