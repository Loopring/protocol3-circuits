#include "../ThirdParty/catch.hpp"
#include "TestUtils.h"

#include "../Gadgets/MatchingGadgets.h"

TEST_CASE("CheckFillRate", "[CheckFillRateGadget]")
{
    unsigned int maxLength = NUM_BITS_AMOUNT;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++) {
        DYNAMIC_SECTION("Bit-length: " << n)
    {
        enum class Expected
        {
            Valid,
            Invalid,
            Automatic
        };
        auto checkFillRateChecked = [n](const BigInt& _amountS, const BigInt& _amountB,
                                        const BigInt& _fillAmountS, const BigInt& _fillAmountB,
                                        Expected expected = Expected::Automatic)
        {
            protoboard<FieldT> pb;

            VariableT amountS = make_variable(pb, toFieldElement(_amountS), "amountS");
            VariableT amountB = make_variable(pb, toFieldElement(_amountB), "amountB");
            VariableT fillAmountS = make_variable(pb, toFieldElement(_fillAmountS), "fillAmountS");
            VariableT fillAmountB = make_variable(pb, toFieldElement(_fillAmountB), "fillAmountB");

            Constants constants(pb, "constants");
            CheckFillRateGadget checkFillRateGadget(pb, constants, amountS, amountB, fillAmountS, fillAmountB, n, "checkFillRateGadget");
            checkFillRateGadget.generate_r1cs_constraints();
            checkFillRateGadget.generate_r1cs_witness();

            bool expectedAutomaticValid = (_fillAmountS * _amountB * 100) < (_fillAmountB * _amountS * 101);
            bool expectedValid = false;
            if (expected == Expected::Automatic)
            {
                expectedValid = expectedAutomaticValid;
            }
            else
            {
                expectedValid = (expected == Expected::Valid) ? true : false;
            }
            REQUIRE(expectedAutomaticValid == expectedValid);

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(checkFillRateGadget.isValid()) == (expectedValid ? 1 : 0)));
        };

        BigInt max = getMaxFieldElementAsBigInt(n);

        SECTION("order: 1/1, fill: 1/1")
        {
            checkFillRateChecked(1, 1, 1, 1, Expected::Valid);
        }

        SECTION("order: max/max, fill: max/max")
        {
            checkFillRateChecked(max, max, max, max, Expected::Valid);
        }

        SECTION("order: 1/1, fill: max/max")
        {
            checkFillRateChecked(1, 1, max, max, Expected::Valid);
        }

        SECTION("order: max/max, fill: 1/1")
        {
            checkFillRateChecked(max, max, 1, 1, Expected::Valid);
        }

        SECTION("order: max/1, fill: max/1")
        {
            checkFillRateChecked(max, 1, max, 1, Expected::Valid);
        }

        SECTION("order: 1/max, fill: 1/max")
        {
            checkFillRateChecked(1, max, 1, max, Expected::Valid);
        }

        SECTION("Random")
        {
            for (unsigned int j = 0; j < numIterations; j++)
            {
                checkFillRateChecked(getRandomFieldElementAsBigInt(n), getRandomFieldElementAsBigInt(n),
                                     getRandomFieldElementAsBigInt(n), getRandomFieldElementAsBigInt(n));
            }
        }

        // Do some specific tests
        if (n == NUM_BITS_AMOUNT)
        {
            SECTION("order: 20000/2000, fill: 10000/1000")
            {
                checkFillRateChecked(20000, 2000, 10000, 1000, Expected::Valid);
            }

            SECTION("order: 20000/2000, fill: 9000/1000")
            {
                checkFillRateChecked(20000, 2000, 9000, 1000, Expected::Valid);
            }

            SECTION("order: 20000/2000, fill: 10000/1100")
            {
                checkFillRateChecked(20000, 2000, 10000, 1100, Expected::Valid);
            }

            SECTION("Exhaustive checks against a single value")
            {
                unsigned int targetFillS = 10000;
                unsigned int targetFillB = 1000;

                // Change fillAmountS
                for(unsigned int fillS = 1; fillS < targetFillS * 2; fillS++)
                {
                    bool expectedValid = fillS < targetFillS + targetFillS / 100;
                    checkFillRateChecked(20000, 2000, fillS, targetFillB, expectedValid ? Expected::Valid : Expected::Invalid);
                }

                // Change fillAmountB
                for(unsigned int fillB = 1; fillB < targetFillB * 2; fillB++)
                {
                    bool expectedValid = fillB > targetFillB - targetFillB / 100;
                    checkFillRateChecked(20000, 2000, targetFillS, fillB, expectedValid ? Expected::Valid : Expected::Invalid);
                }
            }
        }
    }}
}

TEST_CASE("FeeCalculator", "[FeeCalculatorGadget]")
{
    unsigned int maxLength = NUM_BITS_AMOUNT;
    unsigned int numIterations = 8;

    auto feeCalculatorChecked = [](const BigInt& _fillB,
                                   unsigned int _protocolFeeBips,
                                   unsigned int _feeBips,
                                   unsigned int _rebateBips)
    {
        protoboard<FieldT> pb;

        VariableT fillB = make_variable(pb, toFieldElement(_fillB), "fillB");
        VariableT protocolFeeBips = make_variable(pb, toFieldElement(_protocolFeeBips), "protocolFeeBips");
        VariableT feeBips = make_variable(pb, toFieldElement(_feeBips), "feeBips");
        VariableT rebateBips = make_variable(pb, toFieldElement(_rebateBips), "rebateBips");

        Constants constants(pb, "constants");
        FeeCalculatorGadget feeCalculatorGadget(pb, constants, fillB, protocolFeeBips, feeBips, rebateBips, "feeCalculatorGadget");
        feeCalculatorGadget.generate_r1cs_constraints();
        feeCalculatorGadget.generate_r1cs_witness();

        FieldT expectedProtocolFee = toFieldElement(_fillB * _protocolFeeBips / 100000);
        FieldT expectedFee = toFieldElement(_fillB * _feeBips / 10000);
        FieldT expectedRebate = toFieldElement(_fillB * _rebateBips / 10000);

        REQUIRE(pb.is_satisfied());
        REQUIRE((pb.val(feeCalculatorGadget.getProtocolFee()) == expectedProtocolFee));
        REQUIRE((pb.val(feeCalculatorGadget.getFee()) == expectedFee));
        REQUIRE((pb.val(feeCalculatorGadget.getRebate()) == expectedRebate));
    };

    BigInt maxAmount = getMaxFieldElementAsBigInt(NUM_BITS_AMOUNT);

    SECTION("Protocol fee")
    {
        for (unsigned int i = 0; i < pow(2, NUM_BITS_PROTOCOL_FEE_BIPS); i++)
        {
            feeCalculatorChecked(0, i, 0, 0);
        }

        for (unsigned int i = 0; i < pow(2, NUM_BITS_PROTOCOL_FEE_BIPS); i++)
        {
            feeCalculatorChecked(maxAmount, i, 0, 0);
        }
    }

    SECTION("Fee")
    {
        for (unsigned int i = 0; i < pow(2, NUM_BITS_BIPS); i++)
        {
            feeCalculatorChecked(0, 0, i, 0);
        }

        for (unsigned int i = 0; i < pow(2, NUM_BITS_BIPS); i++)
        {
            feeCalculatorChecked(maxAmount, 0, i, 0);
        }
    }

    SECTION("Rebate")
    {
        for (unsigned int i = 0; i < pow(2, NUM_BITS_BIPS); i++)
        {
            feeCalculatorChecked(0, 0, 0, i);
        }

        for (unsigned int i = 0; i < pow(2, NUM_BITS_BIPS); i++)
        {
            feeCalculatorChecked(maxAmount, 0, 0, i);
        }
    }

    SECTION("Random")
    {
        unsigned int numIterations = 1024;
        for (unsigned int i = 0; i < numIterations; i++)
        {
            BigInt fillB = getRandomFieldElementAsBigInt(NUM_BITS_AMOUNT);
            unsigned int protocolFeeBips = rand() % int(pow(2, NUM_BITS_PROTOCOL_FEE_BIPS));
            unsigned int feeBips = rand() % int(pow(2, NUM_BITS_BIPS));
            unsigned int rebateBips = rand() % int(pow(2, NUM_BITS_BIPS));
            feeCalculatorChecked(fillB, protocolFeeBips, feeBips, rebateBips);
        }
    }
}

struct OrderState
{
    Order order;
    Account account;
    BalanceLeaf balanceLeafS;
    BalanceLeaf balanceLeafB;
    TradeHistoryLeaf tradeHistoryLeaf;
};

namespace Simulator
{
    struct Fill
    {
        FieldT S;
        FieldT B;
    };

    struct TradeHistory
    {
        FieldT filled;
        FieldT cancelled;
    };

    struct Settlement
    {
        FieldT fillS_A;
        FieldT fillS_B;
        bool valid;
    };

    bool lt(const FieldT& A, const FieldT& B)
    {
        return toBigInt(A) < toBigInt(B);
    }

    bool lte(const FieldT& A, const FieldT& B)
    {
        return toBigInt(A) <= toBigInt(B);
    }

    FieldT muldiv(const FieldT& V, const FieldT& N, const FieldT& D)
    {
        return toFieldElement(validate(toBigInt(V) * toBigInt(N)) / toBigInt(D));
    }

    TradeHistory getTradeHistory(const OrderState& orderState)
    {
        FieldT filled = lt(orderState.tradeHistoryLeaf.orderID, orderState.order.orderID) ? 0 : orderState.tradeHistoryLeaf.filled;
        FieldT cancelled = orderState.tradeHistoryLeaf.orderID == orderState.order.orderID ? orderState.tradeHistoryLeaf.cancelled :
                        lt(orderState.tradeHistoryLeaf.orderID, orderState.order.orderID) ? false : true;
        return {filled, cancelled};
    }

    Fill getMaxFillAmounts(const OrderState& orderState)
    {
        TradeHistory tradeHistory = getTradeHistory(orderState);
        FieldT remainingS = 0;
        if (orderState.order.buy == FieldT::one())
        {
            FieldT filled = lt(orderState.order.amountB, tradeHistory.filled) ? orderState.order.amountB : tradeHistory.filled;
            FieldT remainingB = (tradeHistory.cancelled == FieldT::one()) ? 0 : orderState.order.amountB - filled;
            remainingS = muldiv(remainingB, orderState.order.amountS, orderState.order.amountB);
        }
        else
        {
        FieldT filled = lt(orderState.order.amountS, tradeHistory.filled) ? orderState.order.amountS : tradeHistory.filled;
        remainingS = (tradeHistory.cancelled == FieldT::one()) ? 0 : orderState.order.amountS - filled;
        }
        FieldT fillAmountS = lt(orderState.balanceLeafS.balance, remainingS) ? orderState.balanceLeafS.balance : remainingS;
        FieldT fillAmountB = muldiv(fillAmountS, orderState.order.amountB, orderState.order.amountS);
        return {fillAmountS, fillAmountB};
    }

    bool match(const Order& takerOrder, Fill& takerFill, const Order& makerOrder, Fill& makerFill)
    {
        if (lt(takerFill.B, makerFill.S))
        {
            makerFill.S = takerFill.B;
            makerFill.B = muldiv(makerFill.S, makerOrder.amountB, makerOrder.amountS);
        }
        else
        {
            takerFill.B = makerFill.S;
            takerFill.S = muldiv(takerFill.B, takerOrder.amountS, takerOrder.amountB);
        }
        bool matchable = lte(makerFill.B, takerFill.S);
        return matchable;
    }

    bool checkFillRate(const FieldT& amountS, const FieldT& amountB, const FieldT& fillAmountS, const FieldT& fillAmountB)
    {
        return lt(fillAmountS * amountB * FieldT(100), fillAmountB * amountS * FieldT(101));
    }

    bool checkValid(const Order& order, const FieldT& fillAmountS, const FieldT& fillAmountB, const FieldT& timestamp)
    {
        bool valid = true;
        valid = valid && lte(order.validSince, timestamp);
        valid = valid && lte(timestamp, order.validUntil);

        valid = valid && !((order.buy == FieldT::zero()) && (order.allOrNone == FieldT::one()) && lt(fillAmountS, order.amountS));
        valid = valid && !((order.buy == FieldT::one()) && (order.allOrNone == FieldT::one()) && lt(fillAmountB, order.amountB));
        valid = valid && checkFillRate(order.amountS, order.amountB, fillAmountS, fillAmountB);
        valid = valid && (fillAmountS != FieldT::zero());
        valid = valid && (fillAmountB != FieldT::zero());

        return valid;
    }

    Settlement settle(const FieldT& timestamp, const OrderState& orderStateA, const OrderState& orderStateB)
    {
        Fill fillA = getMaxFillAmounts(orderStateA);
        Fill fillB = getMaxFillAmounts(orderStateB);

        bool matchable;
        if (orderStateA.order.buy == FieldT::one())
        {
            matchable = match(orderStateA.order, fillA, orderStateB.order, fillB);
            fillA.S = fillB.B;
        }
        else
        {
            matchable = match(orderStateB.order, fillB, orderStateA.order, fillA);
            fillA.B = fillB.S;
        }

        bool valid = matchable;
        valid = valid && checkValid(orderStateA.order, fillA.S, fillA.B, timestamp);
        valid = valid && checkValid(orderStateB.order, fillB.S, fillB.B, timestamp);

        return {fillA.S, fillB.S, valid};
    }
}

TEST_CASE("OrderMatching", "[OrderMatchingGadget]")
{
    auto setOrderState = [](const OrderState& orderState,
                            const FieldT& orderID,
                            const FieldT& amountS, const FieldT& amountB, bool buy,
                            const FieldT& balanceS,
                            const FieldT& filled, bool cancelled, const FieldT& tradeHistoryOrderID,
                            bool allOrNone = false)
    {
        OrderState newOrderState(orderState);
        newOrderState.order.orderID = orderID;
        newOrderState.order.amountS = amountS;
        newOrderState.order.amountB = amountB;
        newOrderState.order.buy = buy ? 1 : 0;
        newOrderState.order.allOrNone = allOrNone ? 1 : 0;
        newOrderState.balanceLeafS.balance = balanceS;
        newOrderState.balanceLeafB.balance = 0;
        newOrderState.tradeHistoryLeaf.filled = filled;
        newOrderState.tradeHistoryLeaf.cancelled = cancelled ? 1 : 0;
        newOrderState.tradeHistoryLeaf.orderID = tradeHistoryOrderID;
        return newOrderState;
    };

    enum class ExpectedValid
    {
        Valid,
        Invalid,
        Automatic
    };
    enum class ExpectedFill
    {
        Manual,
        Automatic
    };
    auto orderMatchingChecked = [](const FieldT& _exchangeID, const FieldT& _timestamp,
                                   const OrderState& orderStateA, const OrderState& orderStateB,
                                   bool expectedSatisfied, ExpectedValid expectedValid = ExpectedValid::Valid,
                                   ExpectedFill expectedFill = ExpectedFill::Automatic, const FieldT& expectedFillS_A = 0, const FieldT& expectedFillS_B = 0)
    {
        protoboard<FieldT> pb;

        VariableT exchangeID = make_variable(pb, _exchangeID, "exchangeID");
        VariableT timestamp = make_variable(pb, _timestamp, "timestamp");

        jubjub::Params params;
        Constants constants(pb, "constants");

        OrderGadget orderA(pb, params, constants, exchangeID, ".orderA");
        orderA.generate_r1cs_witness(orderStateA.order, orderStateA.account, orderStateA.balanceLeafS, orderStateA.balanceLeafB, orderStateA.tradeHistoryLeaf);

        OrderGadget orderB(pb, params, constants, exchangeID, ".orderB");
        orderB.generate_r1cs_witness(orderStateB.order, orderStateB.account, orderStateB.balanceLeafS, orderStateB.balanceLeafB, orderStateB.tradeHistoryLeaf);

        OrderMatchingGadget orderMatching(pb, constants, timestamp, orderA, orderB, "orderMatching");
        orderMatching.generate_r1cs_constraints();
        orderMatching.generate_r1cs_witness();

        REQUIRE(pb.is_satisfied() == expectedSatisfied);
        if (expectedSatisfied)
        {
            Simulator::Settlement settlement = Simulator::settle(_timestamp, orderStateA, orderStateB);

            bool expectedValidValue = settlement.valid;
            if (expectedValid != ExpectedValid::Automatic)
            {
                expectedValidValue = (expectedValid == ExpectedValid::Valid) ? true : false;
            }
            REQUIRE(expectedValidValue == settlement.valid);

            REQUIRE((pb.val(orderMatching.isValid()) == (expectedValidValue ? 1 : 0)));
            if (expectedValidValue)
            {
                FieldT fillS_A = settlement.fillS_A;
                FieldT fillS_B = settlement.fillS_B;
                if (expectedFill == ExpectedFill::Manual)
                {
                    fillS_A = expectedFillS_A;
                    fillS_B = expectedFillS_B;
                }
                REQUIRE((fillS_A == settlement.fillS_A));
                REQUIRE((fillS_B == settlement.fillS_B));

                REQUIRE((pb.val(orderMatching.getFillA_S()) == fillS_A));
                REQUIRE((pb.val(orderMatching.getFillB_S()) == fillS_B));
            }
        }
    };

    RingSettlementBlock block = getRingSettlementBlock();
    REQUIRE(block.ringSettlements.size() > 0);
    const RingSettlement& ringSettlement = block.ringSettlements[0];

    const FieldT& exchangeID = block.exchangeID;
    const FieldT& timestamp = block.timestamp;

    const Order& A_order = ringSettlement.ring.orderA;
    const Account& A_account = ringSettlement.accountUpdate_A.before;
    const BalanceLeaf& A_balanceLeafS = ringSettlement.balanceUpdateS_A.before;
    const BalanceLeaf& A_balanceLeafB = ringSettlement.balanceUpdateB_A.before;
    const TradeHistoryLeaf& A_tradeHistoryLeaf = ringSettlement.tradeHistoryUpdate_A.before;
    const OrderState orderStateA = {A_order, A_account, A_balanceLeafS, A_balanceLeafB, A_tradeHistoryLeaf};

    const Order& B_order = ringSettlement.ring.orderB;
    const Account& B_account = ringSettlement.accountUpdate_B.before;
    const BalanceLeaf& B_balanceLeafS = ringSettlement.balanceUpdateS_B.before;
    const BalanceLeaf& B_balanceLeafB = ringSettlement.balanceUpdateB_B.before;
    const TradeHistoryLeaf& B_tradeHistoryLeaf = ringSettlement.tradeHistoryUpdate_B.before;
    const OrderState orderStateB = {B_order, B_account, B_balanceLeafS, B_balanceLeafB, B_tradeHistoryLeaf};

    unsigned int numTradeHistoryLeafs = pow(2, NUM_BITS_TRADING_HISTORY);
    const FieldT A_orderID = rand() % numTradeHistoryLeafs;
    const FieldT B_orderID = rand() % numTradeHistoryLeafs;

    FieldT maxAmount = getMaxFieldElement(NUM_BITS_AMOUNT);

    SECTION("Valid order match")
    {
        orderMatchingChecked(
            exchangeID, timestamp,
            orderStateA, orderStateB,
            true
        );
    }

    SECTION("orderA.tokenS != orderB.tokenB")
    {
        OrderState orderStateA_mod = orderStateA;
        orderStateA_mod.order.tokenS += 1;
        orderMatchingChecked(
            exchangeID, timestamp,
            orderStateA_mod, orderStateB,
            false
        );
    }

    SECTION("orderA.tokenB != orderB.tokenS")
    {
        OrderState orderStateB_mod = orderStateB;
        orderStateB_mod.order.tokenS += 1;
         orderMatchingChecked(
            exchangeID, timestamp,
            orderStateA, orderStateB_mod,
            false
        );
    }

    SECTION("timestamp too early")
    {
        FieldT timestamp_mod = A_order.validSince - 1;
        orderMatchingChecked(
            exchangeID, timestamp_mod,
            orderStateA, orderStateB,
            true, ExpectedValid::Invalid
        );
    }

    SECTION("timestamp too late")
    {
        FieldT timestamp_mod = B_order.validUntil + 1;
        orderMatchingChecked(
            exchangeID, timestamp_mod,
            orderStateA, orderStateB,
            true, ExpectedValid::Invalid
        );
    }

    SECTION("orderA.amountS/B = maxAmount, orderB.amountS/B = maxAmount")
    {
        for (unsigned int i = 0; i < 4; i++)
        {
            bool buyA = i % 2;
            bool buyB = i / 2;
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                maxAmount, maxAmount, buyA,
                maxAmount,
                0, false, A_orderID
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                maxAmount, maxAmount, buyB,
                maxAmount,
                0, false, B_orderID
            );
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, ExpectedValid::Valid,
                ExpectedFill::Manual, maxAmount, maxAmount
            );
        }
    }

    SECTION("orderA.amountS/B = maxAmount, orderB.amountS/B = 1")
    {
        for (unsigned int i = 0; i < 4; i++)
        {
            bool buyA = i % 2;
            bool buyB = i / 2;
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                maxAmount, maxAmount, buyA,
                maxAmount,
                0, false, A_orderID
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                1, 1, buyB,
                maxAmount,
                0, false, B_orderID
            );
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, ExpectedValid::Valid,
                ExpectedFill::Manual, 1, 1
            );
        }
    }

    SECTION("orderA.amountS/B = 1, orderB.amountS/B = maxAmount")
    {
        for (unsigned int i = 0; i < 4; i++)
        {
            bool buyA = i % 2;
            bool buyB = i / 2;
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                1, 1, buyA,
                maxAmount,
                0, false, A_orderID
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                maxAmount, maxAmount, buyB,
                maxAmount,
                0, false, B_orderID
            );
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, ExpectedValid::Valid,
                ExpectedFill::Manual, 1, 1
            );
        }
    }

    SECTION("orderA.amountS/B = 1, orderB.amountS/B = 1")
    {
        for (unsigned int i = 0; i < 4; i++)
        {
            bool buyA = i % 2;
            bool buyB = i / 2;
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                1, 1, buyA,
                maxAmount,
                0, false, A_orderID
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                1, 1, buyB,
                maxAmount,
                0, false, B_orderID
            );
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, ExpectedValid::Valid,
                ExpectedFill::Manual, 1, 1
            );
        }
    }

    SECTION("orderA.amountS/B = maxAmount/1, orderB.amountS/B = maxAmount")
    {
        for (unsigned int i = 0; i < 4; i++)
        {
            bool buyA = i % 2;
            bool buyB = i / 2;
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                maxAmount, 1, buyA,
                maxAmount,
                0, false, A_orderID
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                maxAmount, maxAmount, buyB,
                maxAmount,
                0, false, B_orderID
            );
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, ExpectedValid::Valid,
                ExpectedFill::Manual, buyA ? 1 : maxAmount, buyA ? 1 : maxAmount
            );
        }
    }

    SECTION("orderA.amountS/B = 1/maxAmount, orderB.amountS/B = maxAmount")
    {
        for (unsigned int i = 0; i < 4; i++)
        {
            bool buyA = i % 2;
            bool buyB = i / 2;
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                1, maxAmount, buyA,
                maxAmount,
                0, false, A_orderID
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                maxAmount, maxAmount, buyB,
                maxAmount,
                0, false, B_orderID
            );
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, ExpectedValid::Invalid,
                ExpectedFill::Automatic
            );
        }
    }

    SECTION("orderA.amountS/B = [1/maxAmount], orderB.amountS/B = [1/maxAmount]")
    {
        for (unsigned int c = 0; c < pow(2, 6); c++)
        {
            FieldT A_amountS = (c >> 0) & 1 ? 1 : maxAmount;
            FieldT A_amountB = (c >> 1) & 1 ? 1 : maxAmount;
            FieldT B_amountS = (c >> 2) & 1 ? 1 : maxAmount;
            FieldT B_amountB = (c >> 3) & 1 ? 1 : maxAmount;

            FieldT A_balance = (c >> 4) & 1 ? 1 : maxAmount;
            FieldT B_balance = (c >> 4) & 1 ? 1 : maxAmount;

            for (unsigned int i = 0; i < 4; i++)
            {
                bool buyA = i % 2;
                bool buyB = i / 2;
                OrderState orderStateA_mod = setOrderState(
                    orderStateA,
                    A_orderID,
                    A_amountS, A_amountB, buyA,
                    A_balance,
                    0, false, A_orderID
                );
                OrderState orderStateB_mod = setOrderState(
                    orderStateB,
                    B_orderID,
                    B_amountS, B_amountB, buyB,
                    B_balance,
                    0, false, B_orderID
                );
                orderMatchingChecked(
                    exchangeID, timestamp,
                    orderStateA_mod, orderStateB_mod,
                    true, ExpectedValid::Automatic,
                    ExpectedFill::Automatic
                );
            }
        }
    }

    SECTION("order cancelled")
    {
        for (unsigned int c = 0; c < pow(2, 2); c++)
        {
            bool A_canceled = (c >> 0) & 1 ? true : false;
            bool B_canceled = (c >> 1) & 1 ? true : false;

            for (unsigned int i = 0; i < 4; i++)
            {
                bool buyA = i % 2;
                bool buyB = i / 2;
                OrderState orderStateA_mod = setOrderState(
                    orderStateA,
                    A_orderID,
                    maxAmount, maxAmount, buyA,
                    maxAmount,
                    0, A_canceled, A_orderID
                );
                OrderState orderStateB_mod = setOrderState(
                    orderStateB,
                    B_orderID,
                    maxAmount, maxAmount, buyB,
                    maxAmount,
                    0, B_canceled, B_orderID
                );
                ExpectedValid expectedValid = (!A_canceled && !B_canceled) ? ExpectedValid::Valid : ExpectedValid::Invalid;
                FieldT expectedFill = (!A_canceled && !B_canceled) ? maxAmount : 0;
                orderMatchingChecked(
                    exchangeID, timestamp,
                    orderStateA_mod, orderStateB_mod,
                    true, expectedValid,
                    ExpectedFill::Manual, expectedFill, expectedFill
                );
            }
        }
    }

    SECTION("orderID == tradeHistory.orderID (filled amount > amountS/amountB)")
    {
        for (unsigned int i = 0; i < 2; i++)
        {
            bool buyA = i % 2;
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                1, 1, buyA,
                maxAmount,
                maxAmount, false, A_orderID
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                1, 1, false,
                1,
                0, false, B_orderID
            );
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, ExpectedValid::Invalid,
                ExpectedFill::Manual, 0, 0
            );
        }
    }

    SECTION("orderID > tradeHistory.orderID")
    {
        for (unsigned int i = 0; i < 4; i++)
        {
            bool buyA = i % 2;
            bool buyB = i / 2;
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID + numTradeHistoryLeafs,
                maxAmount, maxAmount, buyA,
                maxAmount,
                maxAmount, false, A_orderID
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID + numTradeHistoryLeafs,
                maxAmount, maxAmount, buyB,
                maxAmount,
                maxAmount, false, B_orderID
            );
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, ExpectedValid::Valid,
                ExpectedFill::Manual, maxAmount, maxAmount
            );
        }
    }

    SECTION("orderID < tradeHistory.orderID")
    {
        for (unsigned int c = 0; c < pow(2, 2); c++)
        {
            FieldT A_filled = (c >> 0) & 1 ? 0 : maxAmount;
            FieldT B_filled = (c >> 1) & 1 ? 0 : maxAmount;
            for (unsigned int i = 0; i < 4; i++)
            {
                bool buyA = i % 2;
                bool buyB = i / 2;
                OrderState orderStateA_mod = setOrderState(
                    orderStateA,
                    A_orderID,
                    1, 1, buyA,
                    maxAmount,
                    A_filled, false, A_orderID + numTradeHistoryLeafs
                );
                OrderState orderStateB_mod = setOrderState(
                    orderStateB,
                    B_orderID,
                    1, 1, buyB,
                    maxAmount,
                    B_filled, false, B_orderID + numTradeHistoryLeafs
                );
                orderMatchingChecked(
                    exchangeID, timestamp,
                    orderStateA_mod, orderStateB_mod,
                    true, ExpectedValid::Invalid,
                    ExpectedFill::Manual, 0, 0
                );
            }
        }
    }

    SECTION("allOrNone (buy)")
    {
        for (unsigned int i = 0; i < 200; i++)
        {
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                200, 100, true,
                2*i,
                0, false, A_orderID,
                true
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                100, 100, bool(rand() % 2),
                maxAmount,
                0, false, B_orderID
            );

            ExpectedValid expectedValid = (i >= 100) ? ExpectedValid::Valid : ExpectedValid::Invalid;
            FieldT expectedFill = (i >= 100) ? 100 : 100;
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, expectedValid,
                ExpectedFill::Manual, expectedFill, expectedFill
            );
        }
    }

    SECTION("allOrNone (sell)")
    {
        for (unsigned int i = 0; i < 400; i+=2)
        {
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                200, 100, false,
                i,
                0, false, A_orderID,
                true
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                400, 400, bool(rand() % 2),
                maxAmount,
                0, false, B_orderID
            );

            ExpectedValid expectedValid = (i >= 200) ? ExpectedValid::Valid : ExpectedValid::Invalid;
            FieldT expectedFill = (i >= 200) ? 200 : 200;
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, expectedValid,
                ExpectedFill::Manual, expectedFill, expectedFill
            );
        }
    }

    SECTION("Filled (buy)")
    {
        for (unsigned int i = 0; i < 400; i+=2)
        {
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                400, 200, true,
                maxAmount,
                i, false, A_orderID
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                400, 400, bool(rand() % 2),
                maxAmount,
                0, false, B_orderID
            );

            ExpectedValid expectedValid = (i < 200) ? ExpectedValid::Valid : ExpectedValid::Invalid;
            FieldT expectedFill = (i < 200) ? 200 - i : 0;
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, expectedValid,
                ExpectedFill::Manual, expectedFill, expectedFill
            );
        }
    }

    SECTION("Filled (sell)")
    {
        for (unsigned int i = 0; i < 400; i+=2)
        {
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                200, 100, false,
                maxAmount,
                i, false, A_orderID
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                400, 400, bool(rand() % 2),
                maxAmount,
                0, false, B_orderID
            );

            ExpectedValid expectedValid = (i < 200) ? ExpectedValid::Valid : ExpectedValid::Invalid;
            FieldT expectedFill = (i < 200) ? 200 - i : 0;
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, expectedValid,
                ExpectedFill::Manual, expectedFill, expectedFill
            );
        }
    }

    SECTION("Random")
    {
        for (unsigned int i = 0; i < 64; i++)
        {
            OrderState orderStateA_mod = setOrderState(
                orderStateA,
                A_orderID,
                getRandomFieldElement(NUM_BITS_AMOUNT), getRandomFieldElement(NUM_BITS_AMOUNT), bool(rand() % 2),
                getRandomFieldElement(NUM_BITS_AMOUNT),
                getRandomFieldElement(NUM_BITS_AMOUNT), false, A_orderID
            );
            OrderState orderStateB_mod = setOrderState(
                orderStateB,
                B_orderID,
                getRandomFieldElement(NUM_BITS_AMOUNT), getRandomFieldElement(NUM_BITS_AMOUNT), bool(rand() % 2),
                getRandomFieldElement(NUM_BITS_AMOUNT),
                getRandomFieldElement(NUM_BITS_AMOUNT), false, B_orderID
            );
            orderMatchingChecked(
                exchangeID, timestamp,
                orderStateA_mod, orderStateB_mod,
                true, ExpectedValid::Automatic,
                ExpectedFill::Automatic
            );
        }
    }
}
