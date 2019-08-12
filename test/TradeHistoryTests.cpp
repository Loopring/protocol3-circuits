#include "../ThirdParty/catch.hpp"
#include "TestUtils.h"

#include "../Gadgets/TradingHistoryGadgets.h"

TEST_CASE("TradeHistoryTrimming", "[TradeHistoryTrimmingGadget]")
{
    auto tradeHistoryTrimmingChecked = [](const TradeHistoryLeaf& tradeHistoryLeaf,
                                          const FieldT& _orderID,
                                          const FieldT& expectedFilled,
                                          const FieldT& expectedCancelled,
                                          const FieldT& expectedCancelledToStore,
                                          const FieldT& expectedOrderIDToStore)
    {
        protoboard<FieldT> pb;

        TradeHistoryGadget tradeHistory(pb, "tradeHistory");
        tradeHistory.generate_r1cs_witness(tradeHistoryLeaf);

        VariableT orderID = make_variable(pb, _orderID, "orderID");

        jubjub::Params params;
        Constants constants(pb, "constants");
        TradeHistoryTrimmingGadget tradeHistoryTrimmingGadget(
            pb, constants, tradeHistory, orderID, "tradeHistoryTrimmingGadget"
        );
        tradeHistoryTrimmingGadget.generate_r1cs_witness();
        tradeHistoryTrimmingGadget.generate_r1cs_constraints();

        REQUIRE(pb.is_satisfied());
        REQUIRE((pb.val(tradeHistoryTrimmingGadget.getFilled()) == expectedFilled));
        REQUIRE((pb.val(tradeHistoryTrimmingGadget.getCancelled()) == expectedCancelled));
        REQUIRE((pb.val(tradeHistoryTrimmingGadget.getCancelledToStore()) == expectedCancelledToStore));
        REQUIRE((pb.val(tradeHistoryTrimmingGadget.getOrderIDToStore()) == expectedOrderIDToStore));
    };

    unsigned int delta = pow(2, NUM_BITS_TRADING_HISTORY);
    unsigned int orderID = rand() % delta;
    FieldT filled = getRandomFieldElement(NUM_BITS_AMOUNT);

    SECTION("orderID == tradeHistoryOrderID")
    {
        SECTION("Initial state orderID == 0")
        {
            tradeHistoryTrimmingChecked({0, 0, 0}, 0,
                                        0, 0, 0, 0);
        }
        SECTION("Initial state orderID > 0")
        {
            tradeHistoryTrimmingChecked({0, 0, 0}, orderID,
                                        0, 0, 0, orderID);
        }
        SECTION("Order filled")
        {
            tradeHistoryTrimmingChecked({filled, 0, orderID}, orderID,
                                        filled, 0, 0, orderID);
        }
        SECTION("Order cancelled")
        {
            tradeHistoryTrimmingChecked({filled, 1, orderID}, orderID,
                                        filled, 1, 1, orderID);
        }
    }

    SECTION("orderID > tradeHistoryOrderID (trimmed)")
    {
        SECTION("Previous order not filled")
        {
            tradeHistoryTrimmingChecked({0, 0, orderID}, delta + orderID,
                                        0, 0, 0, delta + orderID);
        }
        SECTION("Previous order filled")
        {
            tradeHistoryTrimmingChecked({filled, 0, orderID}, delta + orderID,
                                        0, 0, 0, delta + orderID);
        }
        SECTION("Previous order cancelled")
        {
            tradeHistoryTrimmingChecked({filled, 1, orderID}, delta + orderID,
                                        0, 0, 0, delta + orderID);
        }
    }

    SECTION("orderID < tradeHistoryOrderID (cancelled)")
    {
        SECTION("New order not filled")
        {
            tradeHistoryTrimmingChecked({0, 0, delta + orderID}, orderID,
                                        0, 1, 0, delta + orderID);
        }
        SECTION("New order filled")
        {
            tradeHistoryTrimmingChecked({filled, 0, delta + orderID}, orderID,
                                        filled, 1, 0, delta + orderID);
        }
        SECTION("New order cancelled")
        {
            tradeHistoryTrimmingChecked({filled, 1, delta + orderID}, orderID,
                                        filled, 1, 1, delta + orderID);
        }
    }
}
