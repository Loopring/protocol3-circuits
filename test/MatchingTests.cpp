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
        if (n == 96)
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
