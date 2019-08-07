#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "ThirdParty/catch.hpp"

#include "ethsnarks.hpp"
#include "Utils/Utils.h"
#include "ThirdParty/BigInt.hpp"

#include "Gadgets/MathGadgets.h"
#include "Gadgets/TradingHistoryGadgets.h"
#include "Gadgets/AccountGadgets.h"

using namespace std;
using namespace libff;
using namespace libsnark;
using namespace ethsnarks;
using namespace Loopring;

static const char* TEST_DATA_PATH = "../../../protocol3-circuits/test/data/";

FieldT toFieldElement(const BigInt& v)
{
    return FieldT(v.to_string().c_str());
}

BigInt getRandomFieldElementAsBigInt(unsigned int numBits = 254)
{
    BigInt v(rand());
    for(unsigned int i = 0; i < 32/4; i++)
    {
        v *= 32;
        v += rand();
    }

    if (numBits >= 254)
    {
        v %= BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    }
    else
    {
        BigInt m(1);
        for (unsigned int b = 0; b < numBits; b++)
        {
            m *= 2;
        }
        v %= m;
    }
    return v;
}

BigInt getMaxFieldElementAsBigInt(unsigned int numBits = 254)
{
    if (numBits >= 254)
    {
        return BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    }
    else
    {
        BigInt m(1);
        for (unsigned int b = 0; b < numBits; b++)
        {
            m *= 2;
        }
        m -= 1;
        return m;
    }
}

FieldT getRandomFieldElement(unsigned int numBits = 254)
{
    return toFieldElement(getRandomFieldElementAsBigInt(numBits));
}

FieldT getMaxFieldElement(unsigned int numBits = 254)
{
    if (numBits == 254)
    {
        return FieldT("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    }
    else
    {
        return (FieldT(2)^numBits) - 1;
    }
}

libff::bit_vector toBits(const FieldT value, unsigned int numBits)
{
    libff::bit_vector vector;
    const bigint<FieldT::num_limbs> rint = value.as_bigint();
    for (size_t i = 0; i < numBits; ++i)
    {
        vector.push_back(rint.test_bit(i));
    }
    return vector;
}

bool compareBits(const libff::bit_vector& A, const libff::bit_vector& B)
{
    if (A.size() != B.size())
    {
        return false;
    }

    for (unsigned int i = 0; i < A.size(); i++)
    {
        if (A[i] != B[i])
        {
            return false;
        }
    }
    return true;
}

AccountState createAccountState(ProtoboardT& pb, const Account& state)
{
    AccountState accountState;
    accountState.publicKeyX = make_variable(pb, state.publicKey.x, ".publicKeyX");
    accountState.publicKeyY = make_variable(pb, state.publicKey.y, ".publicKeyY");
    accountState.nonce = make_variable(pb, state.nonce, ".nonce");
    accountState.balancesRoot = make_variable(pb, state.balancesRoot, ".balancesRoot");
    return accountState;
}

BalanceState createBalanceState(ProtoboardT& pb, const BalanceLeaf& state)
{
    BalanceState balanceState;
    balanceState.balance = make_variable(pb, state.balance, ".balance");
    balanceState.tradingHistory = make_variable(pb, state.tradingHistoryRoot, ".tradingHistory");
    return balanceState;
}

TradeHistoryState createTradeHistoryState(ProtoboardT& pb, const TradeHistoryLeaf& state)
{
    TradeHistoryState tradeHistoryState;
    tradeHistoryState.filled = make_variable(pb, state.filled, ".filled");
    tradeHistoryState.cancelled = make_variable(pb, state.cancelled, ".cancelled");
    tradeHistoryState.orderID = make_variable(pb, state.orderID, ".orderID");
    return tradeHistoryState;
}

RingSettlementBlock getRingSettlementBlock()
{
    // Read the JSON file
    string filename = string(TEST_DATA_PATH) + "settlement_block.json";
    ifstream file(filename);
    if (!file.is_open())
    {
        cerr << "Cannot open input file: " << filename << endl;
        REQUIRE(false);
    }
    json input;
    file >> input;
    file.close();

    RingSettlementBlock block = input.get<RingSettlementBlock>();
    return block;
}

struct Initialize
{
    Initialize()
    {
        ethsnarks::ppT::init_public_params();
        srand(time(NULL));
    }
} initialize;


TEST_CASE("Variable selection", "[TernaryGadget]")
{
    protoboard<FieldT> pb;

    pb_variable<FieldT> b, A, B;
    b.allocate(pb, "b");
    A.allocate(pb, "A");
    B.allocate(pb, "B");

    pb.val(A) = FieldT("1");
    pb.val(B) = FieldT("2");

    TernaryGadget ternaryGadget(pb, b, A, B, "ternaryGadget");
    ternaryGadget.generate_r1cs_constraints();

    SECTION("true")
    {
        pb.val(b) = FieldT("1");
        ternaryGadget.generate_r1cs_witness();

        REQUIRE(pb.is_satisfied());
        REQUIRE((pb.val(ternaryGadget.result()) == pb.val(A)));
    }

    SECTION("false")
    {
        pb.val(b) = FieldT("0");
        ternaryGadget.generate_r1cs_witness();

        REQUIRE(pb.is_satisfied());
        REQUIRE((pb.val(ternaryGadget.result()) == pb.val(B)));
    }

    SECTION("non-boolean")
    {
        pb.val(b) = FieldT("2");
        ternaryGadget.generate_r1cs_witness();

        REQUIRE(!pb.is_satisfied());
    }
}

TEST_CASE("AND", "[AndGadget]")
{
    unsigned int maxNumInputs = 64;
    unsigned int numIterations = 128;
    for (unsigned int n = 2; n < maxNumInputs; n++) {
        DYNAMIC_SECTION("Num inputs: " << n)
    {
        for (unsigned int j = 0; j < numIterations; j++)
        {
            protoboard<FieldT> pb;
            std::vector<VariableT> inputs;
            for (unsigned int i = 0; i < n; i++)
            {
                // Bias to 1s the more inputs there are, otherwise the result is almost always 0
                inputs.emplace_back(make_variable(pb, (rand() % n == 0) ? 0 : 1, "i"));
            }

            AndGadget andGadget(pb, inputs, "andGadget");
            andGadget.generate_r1cs_constraints();
            andGadget.generate_r1cs_witness();

            bool expectedResult = true;
            for (unsigned int i = 0; i < n; i++)
            {
                expectedResult &= pb.val(inputs[i]) == FieldT::one() ? true : false;
            }
            FieldT exepectedValue = expectedResult ? 1 : 0;

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(andGadget.result()) == exepectedValue));
        }
    }}
}

TEST_CASE("OR", "[OrGadget]")
{
    unsigned int maxNumInputs = 64;
    unsigned int numIterations = 128;
    for (unsigned int n = 2; n < maxNumInputs; n++) {
        DYNAMIC_SECTION("Num inputs: " << n)
    {
        for (unsigned int j = 0; j < numIterations; j++)
        {
            protoboard<FieldT> pb;
            std::vector<VariableT> inputs;
            for (unsigned int i = 0; i < n; i++)
            {
                // Bias to 0s the more inputs there are, otherwise the result is almost always 1
                inputs.emplace_back(make_variable(pb, (rand() % n == 0) ? 1 : 0, "i"));
            }

            OrGadget orGadget(pb, inputs, "orGadget");
            orGadget.generate_r1cs_constraints();
            orGadget.generate_r1cs_witness();

            bool expectedResult = false;
            for (unsigned int i = 0; i < n; i++)
            {
                expectedResult |= pb.val(inputs[i]) == FieldT::one() ? true : false;
            }
            FieldT exepectedValue = expectedResult ? 1 : 0;

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(orGadget.result()) == exepectedValue));
        }
    }}
}

TEST_CASE("NOT", "[NotGadget]")
{
    protoboard<FieldT> pb;

    pb_variable<FieldT> b;
    b.allocate(pb, "b");

    NotGadget notGadget(pb, b, "notGadget");
    notGadget.generate_r1cs_constraints();

    SECTION("true")
    {
        pb.val(b) = FieldT("1");
        notGadget.generate_r1cs_witness();

        REQUIRE(pb.is_satisfied());
        REQUIRE((pb.val(notGadget.result()) == FieldT::zero()));
    }

    SECTION("false")
    {
        pb.val(b) = FieldT("0");
        notGadget.generate_r1cs_witness();

        REQUIRE(pb.is_satisfied());
        REQUIRE((pb.val(notGadget.result()) == FieldT::one()));
    }
}

TEST_CASE("XOR array", "[XorArrayGadget]")
{
    unsigned int maxNumInputs = 128;
    unsigned int numIterations = 16;
    for (unsigned int n = 1; n < maxNumInputs; n++) {
        DYNAMIC_SECTION("Num inputs: " << n)
    {
        for (unsigned int j = 0; j < numIterations; j++)
        {
            protoboard<FieldT> pb;
            VariableArrayT A = make_var_array(pb, n, ".A");
            VariableArrayT B = make_var_array(pb, n, ".A");
            for (unsigned int i = 0; i < n; i++)
            {
                pb.val(A[i]) = rand() % 2;
                pb.val(B[i]) = rand() % 2;
            }

            XorArrayGadget xorArrayGadget(pb, A, B, "xorArrayGadget");
            xorArrayGadget.generate_r1cs_constraints();
            xorArrayGadget.generate_r1cs_witness();

            VariableArrayT expectedResult = make_var_array(pb, n, ".expectedResult");
            for (unsigned int i = 0; i < n; i++)
            {
                pb.val(expectedResult[i]) = pb.val(A[i]).as_bigint().as_ulong() ^ pb.val(B[i]).as_bigint().as_ulong();
                REQUIRE((pb.val(xorArrayGadget.result()[i]) == pb.val(expectedResult[i])));
            }

            REQUIRE(pb.is_satisfied());
        }
    }}
}

TEST_CASE("Equal", "[EqualGadget]")
{
    unsigned int numIterations = 128;

    auto equalChecked = [](const FieldT& _A, const FieldT& _B)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> a = make_variable(pb, _A, ".A");
        pb_variable<FieldT> b = make_variable(pb, _B, ".B");

        EqualGadget equalGadget(pb, a, b, "equalGadget");
        equalGadget.generate_r1cs_constraints();
        equalGadget.generate_r1cs_witness();

        FieldT expectedResult = (_A == _B) ? FieldT::one() : FieldT::zero();
        REQUIRE(pb.is_satisfied());
        REQUIRE((pb.val(equalGadget.result()) == expectedResult));
    };

    FieldT max = getMaxFieldElement();

    SECTION("0 == 0")
    {
        equalChecked(0, 0);
    }

    SECTION("max == max")
    {
        equalChecked(max, max);
    }

    SECTION("random == random")
    {
        for (unsigned int i = 0; i < numIterations; i++)
        {
            FieldT r = getRandomFieldElement();
            equalChecked(r, r);
        }
    }

    SECTION("random")
    {
        for (unsigned int i = 0; i < numIterations; i++)
        {
            equalChecked(getRandomFieldElement(), getRandomFieldElement());
        }
    }
}

TEST_CASE("RequireEqual", "[RequireEqualGadget]")
{
    unsigned int numIterations = 128;

    auto requireEqualChecked = [](const FieldT& _A, const FieldT& _B)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> a = make_variable(pb, _A, ".A");
        pb_variable<FieldT> b = make_variable(pb, _B, ".B");

        RequireEqualGadget requireEqualGadget(pb, a, b, "requireEqualGadget");
        requireEqualGadget.generate_r1cs_constraints();
        requireEqualGadget.generate_r1cs_witness();

        bool expectedSatisfied = (_A == _B);
        REQUIRE(pb.is_satisfied() == expectedSatisfied);
    };

    FieldT max = getMaxFieldElement();

    SECTION("0 == 0")
    {
        requireEqualChecked(0, 0);
    }

    SECTION("max == max")
    {
        requireEqualChecked(max, max);
    }

    SECTION("random == random")
    {
        for (unsigned int i = 0; i < numIterations; i++)
        {
            FieldT r = getRandomFieldElement();
            requireEqualChecked(r, r);
        }
    }

    SECTION("random")
    {
        for (unsigned int i = 0; i < numIterations; i++)
        {
            requireEqualChecked(getRandomFieldElement(), getRandomFieldElement());
        }
    }
}

TEST_CASE("RequireZeroAorB", "[RequireZeroAorBGadget]")
{
    unsigned int numIterations = 128;

    auto requireZeroAorBChecked = [](const FieldT& _A, const FieldT& _B)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> a = make_variable(pb, _A, ".A");
        pb_variable<FieldT> b = make_variable(pb, _B, ".B");

        RequireZeroAorBGadget requireZeroAorBGadget(pb, a, b, "requireZeroAorBGadget");
        requireZeroAorBGadget.generate_r1cs_constraints();
        requireZeroAorBGadget.generate_r1cs_witness();

        bool expectedSatisfied = (_A == 0) || (_B == 0);
        REQUIRE(pb.is_satisfied() == expectedSatisfied);
    };

    SECTION("0 || 0")
    {
        requireZeroAorBChecked(0, 0);
    }

    SECTION("0 || random")
    {
        for (unsigned int i = 0; i < numIterations; i++)
        {
            requireZeroAorBChecked(0, getRandomFieldElement());
        }
    }

    SECTION("random || 0")
    {
        for (unsigned int i = 0; i < numIterations; i++)
        {
            requireZeroAorBChecked(getRandomFieldElement(), 0);
        }
    }

    SECTION("random || random")
    {
        for (unsigned int i = 0; i < numIterations; i++)
        {
            requireZeroAorBChecked(getRandomFieldElement(), getRandomFieldElement());
        }
    }
}

TEST_CASE("RequireNotZero", "[RequireNotZeroGadget]")
{
    unsigned int numIterations = 256;

    protoboard<FieldT> pb;

    pb_variable<FieldT> a = make_variable(pb, ".a");

    RequireNotZeroGadget requireNotZeroGadget(pb, a, "requireNotZeroGadget");
    requireNotZeroGadget.generate_r1cs_constraints();

    SECTION("0")
    {
        pb.val(a) = 0;
        requireNotZeroGadget.generate_r1cs_witness();

        REQUIRE(!pb.is_satisfied());
    }

    SECTION("non-zero")
    {
        for (unsigned int i = 0; i < numIterations; i++)
        {
            pb.val(a) = getRandomFieldElement();
            while(pb.val(a) == 0)
            {
                pb.val(a) = getRandomFieldElement();
            }
            requireNotZeroGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }
    }
}

TEST_CASE("RequireNotEqual", "[RequireNotEqualGadget]")
{
    unsigned int maxLength = 254;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++) {
        DYNAMIC_SECTION("Bit-length: " << n)
    {
        auto requireNotEqualChecked = [n](const FieldT& _A, const FieldT& _B)
        {
            protoboard<FieldT> pb;

            pb_variable<FieldT> a = make_variable(pb, _A, ".A");
            pb_variable<FieldT> b = make_variable(pb, _B, ".B");

            RequireNotEqualGadget requireNotEqualGadget(pb, a, b, "requireNotEqualGadget");
            requireNotEqualGadget.generate_r1cs_constraints();
            requireNotEqualGadget.generate_r1cs_witness();

            bool expectedSatisfied = (_A != _B);
            REQUIRE(pb.is_satisfied() == expectedSatisfied);
        };

        FieldT max = getMaxFieldElement(n);

        SECTION("0 != 0")
        {
            requireNotEqualChecked(0, 0);
        }

        SECTION("max != max")
        {
            requireNotEqualChecked(max, max);
        }

        SECTION("Random value")
        {
            FieldT r = getRandomFieldElement(n);
            requireNotEqualChecked(r, r);
        }

        SECTION("0 != max")
        {
            requireNotEqualChecked(0, max);
        }

        SECTION("max != 0")
        {
            requireNotEqualChecked(max, 0);
        }

        SECTION("Random")
        {
            for (unsigned int j = 0; j < numIterations; j++)
            {
                requireNotEqualChecked(getRandomFieldElement(n), getRandomFieldElement(n));
            }
        }
    }}
}

TEST_CASE("Min", "[MinGadget]")
{
    unsigned int maxLength = 252;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++) {
        DYNAMIC_SECTION("Bit-length: " << n)
    {
        auto requireLeqChecked = [n](const BigInt& _A, const BigInt& _B)
        {
            protoboard<FieldT> pb;

            pb_variable<FieldT> a = make_variable(pb, toFieldElement(_A), ".A");
            pb_variable<FieldT> b = make_variable(pb, toFieldElement(_B), ".B");

            MinGadget minGadget(pb, a, b, n, "minGadget");
            minGadget.generate_r1cs_constraints();
            minGadget.generate_r1cs_witness();

            BigInt expectedResult = (_A < _B) ? _A : _B;
            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(minGadget.result()) == toFieldElement(expectedResult)));
        };

        BigInt max = getMaxFieldElementAsBigInt(n);

        SECTION("min(0, 0)")
        {
            requireLeqChecked(0, 0);
        }

        SECTION("min(1, 0)")
        {
            requireLeqChecked(1, 0);
        }

        SECTION("min(0, 1)")
        {
            requireLeqChecked(0, 1);
        }

        SECTION("min(max, max)")
        {
            requireLeqChecked(max, max);
        }

        SECTION("min(max - 1, max)")
        {
            requireLeqChecked(max - 1, max);
        }

        SECTION("min(max, max - 1)")
        {
            requireLeqChecked(max, max - 1);
        }

        SECTION("min(0, max)")
        {
            requireLeqChecked(0, max);
        }

        SECTION("min(max, 0)")
        {
            requireLeqChecked(max, 0);
        }

        SECTION("Random")
        {
            requireLeqChecked(getRandomFieldElementAsBigInt(n), getRandomFieldElementAsBigInt(n));
        }
    }}
}

TEST_CASE("RequireLeq", "[RequireLeqGadget]")
{
    unsigned int maxLength = 252;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++) {
        DYNAMIC_SECTION("Bit-length: " << n)
    {
        auto requireLeqChecked = [n](const BigInt& _A, const BigInt& _B)
        {
            protoboard<FieldT> pb;

            pb_variable<FieldT> a = make_variable(pb, toFieldElement(_A), ".A");
            pb_variable<FieldT> b = make_variable(pb, toFieldElement(_B), ".B");

            RequireLeqGadget requireLeqGadget(pb, a, b, n, "requireLeqGadget");
            requireLeqGadget.generate_r1cs_constraints();
            requireLeqGadget.generate_r1cs_witness();

            bool expectedSatisfied = _A <= _B;
            REQUIRE(pb.is_satisfied() == expectedSatisfied);
        };

        BigInt max = getMaxFieldElementAsBigInt(n);

        SECTION("0 <= 0")
        {
            requireLeqChecked(0, 0);
        }

        SECTION("0 <= 1")
        {
            requireLeqChecked(0, 1);
        }

        SECTION("max <= max")
        {
            requireLeqChecked(max, max);
        }

        SECTION("max - 1 <= max")
        {
            requireLeqChecked(max - 1, max);
        }

        SECTION("max <= max - 1")
        {
            requireLeqChecked(max, max - 1);
        }

        SECTION("0 <= max")
        {
            requireLeqChecked(0, max);
        }

        SECTION("max <= 0")
        {
            requireLeqChecked(max, 0);
        }

        SECTION("Random")
        {
            for (unsigned int j = 0; j < numIterations; j++)
            {
                requireLeqChecked(getRandomFieldElementAsBigInt(n), getRandomFieldElementAsBigInt(n));
            }
        }
    }}
}

TEST_CASE("RequireLt", "[RequireLtGadget]")
{
    unsigned int maxLength = 252;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++) {
        DYNAMIC_SECTION("Bit-length: " << n)
    {
        auto requireLtChecked = [n](const BigInt& _A, const BigInt& _B)
        {
            protoboard<FieldT> pb;

            pb_variable<FieldT> a = make_variable(pb, toFieldElement(_A), ".A");
            pb_variable<FieldT> b = make_variable(pb, toFieldElement(_B), ".B");

            RequireLtGadget requireLtGadget(pb, a, b, n, "requireLtGadget");
            requireLtGadget.generate_r1cs_constraints();
            requireLtGadget.generate_r1cs_witness();

            bool expectedSatisfied = _A < _B;
            REQUIRE(pb.is_satisfied() == expectedSatisfied);
        };

        BigInt max = getMaxFieldElementAsBigInt(n);

        SECTION("0 < 0")
        {
            requireLtChecked(0, 0);
        }

        SECTION("max < max")
        {
            requireLtChecked(max, max);
        }

        SECTION("0 < max")
        {
            requireLtChecked(0, max);
        }

        SECTION("max < 0")
        {
            requireLtChecked(max, 0);
        }

        SECTION("Random")
        {
            for (unsigned int j = 0; j < numIterations; j++)
            {
                requireLtChecked(getRandomFieldElementAsBigInt(n), getRandomFieldElementAsBigInt(n));
            }
        }
    }}
}

TEST_CASE("MulDiv", "[MulDivGadget]")
{
    unsigned int maxLength = 253/2;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++) {
        DYNAMIC_SECTION("Bit-length: " << n)
    {
        auto mulDivChecked = [n](const BigInt& _value, const BigInt& _numerator, const BigInt& _denominator,
                                 bool expectedSatisfied, bool bModifyRemainder = false)
        {
            protoboard<FieldT> pb;

            pb_variable<FieldT> value = make_variable(pb, toFieldElement(_value), "value");
            pb_variable<FieldT> numerator = make_variable(pb, toFieldElement(_numerator), "numerator");
            pb_variable<FieldT> denominator = make_variable(pb, toFieldElement(_denominator), "denominator");

            Constants constants(pb, "constants");
            MulDivGadget mulDivGadget(pb, constants, value, numerator, denominator, n, n, n, "mulDivGadget");
            mulDivGadget.generate_r1cs_constraints();
            mulDivGadget.generate_r1cs_witness();

            if (bModifyRemainder)
            {
                pb.val(mulDivGadget.remainder.packed) += pb.val(denominator);
                mulDivGadget.remainder.generate_r1cs_witness_from_packed();
                pb.val(mulDivGadget.quotient) -= FieldT::one();
            }

            REQUIRE(pb.is_satisfied() == expectedSatisfied);
            if (expectedSatisfied)
            {
                BigInt product = _value * _numerator;
                BigInt remainder = product % _denominator;
                BigInt result = product / _denominator;

                REQUIRE((pb.val(mulDivGadget.result()) == toFieldElement(result)));
                REQUIRE((pb.val(mulDivGadget.getRemainder()) == toFieldElement(remainder)));
                REQUIRE((pb.val(mulDivGadget.getProduct()) == toFieldElement(product)));
            }
        };

        BigInt max = getMaxFieldElementAsBigInt(n);

        SECTION("Divide by zero")
        {
            for (unsigned int j = 0; j < numIterations; j++)
            {
                mulDivChecked(getRandomFieldElementAsBigInt(n), getRandomFieldElementAsBigInt(n), 0, false);
            }
        }

        SECTION("0 * 0 / 1 = 0")
        {
             mulDivChecked(0, 0, 1, true);
        }

        SECTION("1 * 1 / 1 = 1")
        {
             mulDivChecked(1, 1, 1, true);
        }

        SECTION("max * max / max = max")
        {
             mulDivChecked(max, max, max, true);
        }

        SECTION("max * max / 1 = max * max")
        {
             mulDivChecked(max, max, 1, true);
        }

        SECTION("remainder >= C")
        {
             mulDivChecked(max, max, max, false, true);
        }

        SECTION("Random")
        {
            for (unsigned int j = 0; j < numIterations; j++)
            {
                BigInt denominator = getRandomFieldElementAsBigInt(n);
                while (denominator == 0)
                {
                    denominator = getRandomFieldElementAsBigInt(n);
                }
                mulDivChecked(getRandomFieldElementAsBigInt(n), getRandomFieldElementAsBigInt(n), denominator, true);
            }
        }
    }}
}

TEST_CASE("UnsafeAdd", "[UnsafeAddGadget]")
{
    unsigned int numIterations = 256;

    protoboard<FieldT> pb;

    pb_variable<FieldT> a = make_variable(pb, ".a");
    pb_variable<FieldT> b = make_variable(pb, ".b");

    UnsafeAddGadget unsafeAddGadget(pb, a, b, "unsafeAddGadget");
    unsafeAddGadget.generate_r1cs_constraints();

    SECTION("Random")
    {
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement();
            pb.val(b) = getRandomFieldElement();
            unsafeAddGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(unsafeAddGadget.result()) == pb.val(a) + pb.val(b)));
        }
    }
}

TEST_CASE("UnsafeSub", "[UnsafeSubGadget]")
{
    unsigned int numIterations = 256;

    protoboard<FieldT> pb;

    pb_variable<FieldT> a = make_variable(pb, ".a");
    pb_variable<FieldT> b = make_variable(pb, ".b");

    UnsafeSubGadget unsafeSubGadget(pb, a, b, "unsafeSubGadget");
    unsafeSubGadget.generate_r1cs_constraints();

    SECTION("Random")
    {
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement();
            pb.val(b) = getRandomFieldElement();
            unsafeSubGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(unsafeSubGadget.result()) == pb.val(a) - pb.val(b)));
        }
    }
}

TEST_CASE("UnsafeMul", "[UnsafeMulGadget]")
{
    unsigned int numIterations = 256;

    protoboard<FieldT> pb;

    pb_variable<FieldT> a = make_variable(pb, ".a");
    pb_variable<FieldT> b = make_variable(pb, ".b");

    UnsafeMulGadget unsafeMulGadget(pb, a, b, "unsafeMulGadget");
    unsafeMulGadget.generate_r1cs_constraints();

    SECTION("Random")
    {
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement();
            pb.val(b) = getRandomFieldElement();
            unsafeMulGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(unsafeMulGadget.result()) == pb.val(a) * pb.val(b)));
        }
    }
}

TEST_CASE("RequireAccuracy", "[RequireAccuracyGadget]")
{
    unsigned int maxLength = 126;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++) {
        DYNAMIC_SECTION("Bit-length: " << n)
    {
        auto requireAccuracyChecked = [n](const FieldT& _A, const FieldT& _B, bool expectedSatisfied)
        {
            protoboard<FieldT> pb;

            pb_variable<FieldT> a = make_variable(pb, _A, ".A");
            pb_variable<FieldT> b = make_variable(pb, _B, ".B");

            Accuracy accuracy = {100 - 1, 100};
            RequireAccuracyGadget requireAccuracyGadget(pb, a, b, accuracy, n, "requireAccuracyGadget");
            requireAccuracyGadget.generate_r1cs_constraints();
            requireAccuracyGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied() == expectedSatisfied);
        };

        FieldT max = getMaxFieldElement(n);

        SECTION("0, 0")
        {
            requireAccuracyChecked(0, 0, true);
        }

        SECTION("0, max")
        {
            requireAccuracyChecked(0, max, false);
        }

        SECTION("max, 0")
        {
            requireAccuracyChecked(max, 0, false);
        }

        SECTION("value > original value")
        {
            FieldT A = getRandomFieldElement(n);
            while (A == FieldT::zero())
            {
                A = getRandomFieldElement(n);
            }
            FieldT B = A - 1;
            requireAccuracyChecked(A, B, false);
        }

        // Do some specific tests
        if (n == 96)
        {
            SECTION("100, 100")
            {
                requireAccuracyChecked(100, 100, true);
            }

            SECTION("101, 100")
            {
                requireAccuracyChecked(101, 100, false);
            }

            SECTION("99, 100")
            {
                requireAccuracyChecked(99, 100, true);
            }

            SECTION("max + 1, max")
            {
                requireAccuracyChecked(max + 1, max, false);
            }

            SECTION("max, 3000")
            {
                requireAccuracyChecked(max, 3000, false);
            }

            SECTION("Exhaustive checks against a single value")
            {
                unsigned int originalValue = 3000;
                for(unsigned int i = 0; i < originalValue * 3; i++)
                {
                    bool expectedSatisfied = (i >= 2970 && i <= 3000);
                    requireAccuracyChecked(i, 3000, expectedSatisfied);
                }
            }
        }
    }}
}

TEST_CASE("SignatureVerifier", "[SignatureVerifier]")
{
     auto signatureVerifierChecked = [](const FieldT& _pubKeyX, const FieldT& _pubKeyY, const FieldT& _msg,
                                        const Loopring::Signature& signature, bool expectedSatisfied)
    {
        protoboard<FieldT> pb;

        jubjub::Params params;
        jubjub::VariablePointT publicKey(pb, "publicKey");
        pb.val(publicKey.x) = _pubKeyX;
        pb.val(publicKey.y) = _pubKeyY;
        pb_variable<FieldT> message = make_variable(pb, _msg, "message");

        SignatureVerifier signatureVerifier(pb, params, publicKey, message, "signatureVerifier");
        signatureVerifier.generate_r1cs_constraints();
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(pb.is_satisfied() == expectedSatisfied);
    };

    // Correct publicKey + message + signature
    FieldT pubKeyX = FieldT("21607074953141243618425427250695537464636088817373528162920186615872448542319");
    FieldT pubKeyY = FieldT("3328786100751313619819855397819808730287075038642729822829479432223775713775");
    FieldT msg = FieldT("18996832849579325290301086811580112302791300834635590497072390271656077158490");
    FieldT Rx = FieldT("20401810397006237293387786382094924349489854205086853036638326738826249727385");
    FieldT Ry = FieldT("3339178343289311394427480868578479091766919601142009911922211138735585687725");
    FieldT s = FieldT("219593190015660463654216479865253652653333952251250676996482368461290160677");

    // Different valid public key
    FieldT pubKeyX_2 = FieldT("19818098172422229289422284899436629503222263750727977198150374245991932884258");
    FieldT pubKeyY_2 = FieldT("5951877988471485350710444403782724110196846988892201970720985561004735218817");

    // Signature of message signed by different keypair
    FieldT Rx_2 = FieldT("11724635741659369482608508002194555510423986519388485904857477054244428273528");
    FieldT Ry_2 = FieldT("1141584024686665974825800506178016776173372699473828623261155117285910293572");
    FieldT s_2 = FieldT("48808226556453260593782345205957224790810379817643725430561166968302957481");

    SECTION("All data valid")
    {
        signatureVerifierChecked(pubKeyX, pubKeyY, msg, Loopring::Signature(EdwardsPoint(Rx, Ry), s), true);
    }

    SECTION("All zeros")
    {
        signatureVerifierChecked(0, 0, 0, Loopring::Signature(EdwardsPoint(0, 0), 0), false);
    }

    SECTION("Wrong publicKey.x")
    {
        signatureVerifierChecked(pubKeyX + 1, pubKeyY, msg, Loopring::Signature(EdwardsPoint(Rx, Ry), s), false);
    }

    SECTION("Wrong publicKey.y")
    {
        signatureVerifierChecked(pubKeyX, pubKeyY + 1, msg, Loopring::Signature(EdwardsPoint(Rx, Ry), s), false);
    }

    SECTION("Different (but valid) public key")
    {
        signatureVerifierChecked(pubKeyX_2, pubKeyY_2, msg, Loopring::Signature(EdwardsPoint(Rx, Ry), s), false);
    }

    SECTION("Different message")
    {
        signatureVerifierChecked(pubKeyX, pubKeyY, msg + 1, Loopring::Signature(EdwardsPoint(Rx, Ry), s), false);
    }

    SECTION("Zero message value")
    {
        signatureVerifierChecked(pubKeyX, pubKeyY, 0, Loopring::Signature(EdwardsPoint(Rx, Ry), s), false);
    }

    SECTION("Max message value")
    {
        signatureVerifierChecked(pubKeyX, pubKeyY, getMaxFieldElement(), Loopring::Signature(EdwardsPoint(Rx, Ry), s), false);
    }

    SECTION("Different Rx")
    {
        signatureVerifierChecked(pubKeyX, pubKeyY, msg, Loopring::Signature(EdwardsPoint(Rx + 1, Ry), s), false);
    }

    SECTION("Different Ry")
    {
        signatureVerifierChecked(pubKeyX, pubKeyY, msg, Loopring::Signature(EdwardsPoint(Rx, Ry + 1), s), false);
    }

    SECTION("Different s")
    {
        signatureVerifierChecked(pubKeyX, pubKeyY, msg, Loopring::Signature(EdwardsPoint(Rx, Ry), s + 1), false);
    }

    SECTION("Signature of message of different public key")
    {
        signatureVerifierChecked(pubKeyX, pubKeyY, msg, Loopring::Signature(EdwardsPoint(Rx_2, Ry_2), s_2), false);
    }
}

TEST_CASE("Float", "[FloatGadget]")
{
    FloatEncoding encoding = Float24Encoding;
    unsigned int numBitsFloat = encoding.numBitsExponent + encoding.numBitsMantissa;

    unsigned int maxLength = 96;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++) {
        DYNAMIC_SECTION("Bit-length: " << n)
    {
        auto floatChecked = [n, encoding, numBitsFloat](const FieldT& _value)
        {
            protoboard<FieldT> pb;

            Constants constants(pb, "constants");
            FloatGadget floatGadget(pb, constants, encoding, "floatGadget");
            floatGadget.generate_r1cs_constraints();
            unsigned int f = toFloat(_value, encoding);
            floatGadget.generate_r1cs_witness(f);

            FieldT rValue = toFieldElement(fromFloat(f, encoding));
            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(floatGadget.value()) == rValue));
            REQUIRE(compareBits(floatGadget.bits().get_bits(pb), toBits(f, numBitsFloat)));
        };

        SECTION("0")
        {
            floatChecked(0);
        }

        SECTION("1")
        {
            floatChecked(1);
        }

        SECTION("max")
        {
            floatChecked(getMaxFieldElement(n));
        }

        SECTION("Random")
        {
            for (unsigned int j = 0; j < numIterations; j++)
            {
                floatChecked(getRandomFieldElement(n));
            }
        }
    }}
}

TEST_CASE("Float+Accuracy", "[FloatGadget+RequireAccuracy]")
{
    FloatEncoding encoding = Float24Encoding;
    Accuracy accuracy = Float24Accuracy;
    unsigned int n = 96;
    unsigned int numBitsFloat = encoding.numBitsExponent + encoding.numBitsMantissa;

    protoboard<FieldT> pb;

    Constants constants(pb, "constants");
    FloatGadget floatGadget(pb, constants, encoding, "floatGadget");
    floatGadget.generate_r1cs_constraints();

    pb_variable<FieldT> value = make_variable(pb, ".value");
    pb_variable<FieldT> rValue = make_variable(pb, ".rValue");
    RequireAccuracyGadget requireAccuracyGadget(pb, rValue, value, accuracy, n, "requireAccuracyGadget");
    requireAccuracyGadget.generate_r1cs_constraints();

    SECTION("Random")
    {
        unsigned int numIterations = 1024;
        for (unsigned int j = 0; j < numIterations; j++)
        {
            FieldT _value = getRandomFieldElement(n);
            unsigned int f = toFloat(_value, encoding);
            floatGadget.generate_r1cs_witness(FieldT(f));

            pb.val(value) = _value;
            pb.val(rValue) = pb.val(floatGadget.value());
            requireAccuracyGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }
    }
}

TEST_CASE("LabelHasher", "[LabelHasher]")
{
    unsigned int maxLength = 1024;
    for (unsigned int n = 1; n <= maxLength; n = n * 2 + 1) {
        DYNAMIC_SECTION("Num labels: " << n)
    {
        protoboard<FieldT> pb;

        std::vector<VariableT> labels;
        for (unsigned int i = 0; i < n; i++)
        {
            labels.emplace_back(make_variable(pb, ".label"));
            pb.val(labels.back()) = getRandomFieldElement();
        }

        Constants constants(pb, "constants");
        LabelHasher labelHasher(pb, constants, labels, "labelHasher");
        labelHasher.generate_r1cs_constraints();
        labelHasher.generate_r1cs_witness();

        REQUIRE(pb.is_satisfied());
    }}
}

TEST_CASE("subadd", "[subadd_gadget]")
{
    unsigned int maxLength = 252;
    for (unsigned int n = 1; n <= maxLength; n++) {
        DYNAMIC_SECTION("Bit-length: " << n)
    {
        auto subaddChecked = [n](const FieldT& _from, const FieldT& _to, const FieldT& _amount,
                                 bool expectedSatisfied, const FieldT& expectedFromAfter = 0, const FieldT& expectedToAfter = 0)
        {
            protoboard<FieldT> pb;

            pb_variable<FieldT> from = make_variable(pb, _from, "from");
            pb_variable<FieldT> to = make_variable(pb, _to, "to");
            pb_variable<FieldT> amount = make_variable(pb, _amount, "amount");

            subadd_gadget subAddGadget(pb, n, from, to, amount, "subAddGadget");
            subAddGadget.generate_r1cs_constraints();
            subAddGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied() == expectedSatisfied);
            if (expectedSatisfied)
            {
                REQUIRE(((pb.val(subAddGadget.X)) == expectedFromAfter));
                REQUIRE(((pb.val(subAddGadget.Y)) == expectedToAfter));
            }
        };

        FieldT max = getMaxFieldElement(n);
        FieldT halfMax = getMaxFieldElement(n - 1);

        SECTION("(0, 0) -+ 0")
        {
            subaddChecked(0, 0, 0, true, 0, 0);
        }

        SECTION("(1, 0) -+ 1")
        {
            subaddChecked(1, 0, 1, true, 0, 1);
        }

        SECTION("(max, 0) -+ 0")
        {
            subaddChecked(max, 0, 0, true, max, 0);
        }

        SECTION("(max, 0) -+ max")
        {
            subaddChecked(max, 0, max, true, 0, max);
        }

        SECTION("(halfMax, halfMax + 1) -+ halfMax")
        {
            subaddChecked(halfMax, halfMax + 1, halfMax, true, 0, max);
        }

        SECTION("(max, max) -+ max  (overflow)")
        {
            subaddChecked(max, max, max, false);
        }

        SECTION("(halfMax, halfMax + 2) -+ halfMax  (overflow)")
        {
            subaddChecked(halfMax, halfMax + 2, halfMax, false);
        }

        SECTION("(halfMax - 1, halfMax + 1) -+ halfMax (underflow)")
        {
            subaddChecked(halfMax - 1, halfMax + 1, halfMax, false);
        }

        SECTION("(0, 0) -+ 1 (underflow)")
        {
            subaddChecked(0, 0, 1, false);
        }

        SECTION("(0, 0) -+ max (underflow)")
        {
            subaddChecked(0, 0, max, false);
        }

        SECTION("(max - 1, 0) -+ max  (underflow)")
        {
            subaddChecked(max - 1, 0, max, false);
        }

        SECTION("(max, 1) -+ max  (overflow)")
        {
            subaddChecked(max, 1, max, false);
        }
    }}
}

TEST_CASE("Range limit", "[dual_variable_gadget]")
{
    unsigned int maxLength = 254;
    unsigned int numIterations = 16;
    for (unsigned int n = 1; n <= maxLength; n++) {
        DYNAMIC_SECTION("Bit-length: " << n)
    {
        auto rangeLimitChecked = [n](const FieldT& v, bool expectedSatisfied)
        {
            protoboard<FieldT> pb;

            pb_variable<FieldT> value = make_variable(pb, "value");
            libsnark::dual_variable_gadget<FieldT> rangeLimitedValue(pb, value, n, "dual_variable_gadget");
            rangeLimitedValue.generate_r1cs_constraints(true);

            pb.val(value) = v;
            rangeLimitedValue.generate_r1cs_witness_from_packed();

            REQUIRE(pb.is_satisfied() == expectedSatisfied);
            if (expectedSatisfied)
            {
                REQUIRE((pb.val(rangeLimitedValue.packed) == pb.val(value)));
                REQUIRE(compareBits(rangeLimitedValue.bits.get_bits(pb), toBits(pb.val(value), n)));
            }
        };

        SECTION("0")
        {
            rangeLimitChecked(0, true);
        }

        SECTION("max")
        {
            rangeLimitChecked(getMaxFieldElement(n), true);
        }

        SECTION("max + 1")
        {
            // max + 1 == 0 if n == 254
            if (n < 254)
            {
                rangeLimitChecked(getMaxFieldElement(n) + 1, false);
            }
        }

        SECTION("max + 1 + max (1 bit too many, LSB the same as max)")
        {
            // We need to be able to set all bits to 1s
            if (n < 253)
            {
                rangeLimitChecked(getMaxFieldElement(n) * 2 + 1, false);
            }
        }

        SECTION("max snark field element")
        {
            // max snark field element == max field element when n == 254
            if (n < 254)
            {
                rangeLimitChecked(getMaxFieldElement(), false);
            }
        }

        SECTION("random value in range")
        {
            for (unsigned int j = 0; j < numIterations; j++)
            {
                rangeLimitChecked(getRandomFieldElement(n), true);
            }
        }
    }}
}

TEST_CASE("UpdateAccount", "[UpdateAccountGadget]")
{
    RingSettlementBlock block = getRingSettlementBlock();
    REQUIRE(block.ringSettlements.size() > 0);
    const RingSettlement& ringSettlement = block.ringSettlements[0];
    const AccountUpdate& accountUpdate = ringSettlement.accountUpdate_B;

    auto updateAccountChecked = [](const AccountUpdate& accountUpdate, bool expectedSatisfied, bool expectedRootAfterCorrect = true)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> rootBefore = make_variable(pb, "rootBefore");
        VariableArrayT address = make_var_array(pb, NUM_BITS_ACCOUNT, ".address");
        AccountState stateBefore = createAccountState(pb, accountUpdate.before);
        AccountState stateAfter = createAccountState(pb, accountUpdate.after);
        address.fill_with_bits_of_field_element(pb, accountUpdate.accountID);
        pb.val(rootBefore) = accountUpdate.rootBefore;

        UpdateAccountGadget updateAccount(pb, rootBefore, address, stateBefore, stateAfter, "updateAccount");
        updateAccount.generate_r1cs_constraints();
        updateAccount.generate_r1cs_witness(accountUpdate.proof);

        REQUIRE(pb.is_satisfied() == expectedSatisfied);
        if (expectedSatisfied)
        {
            REQUIRE((pb.val(updateAccount.result()) == accountUpdate.rootAfter) == expectedRootAfterCorrect);
        }
    };

    SECTION("Everything correct")
    {
        updateAccountChecked(accountUpdate, true, true);
    }

    SECTION("Incorrect address")
    {
        AccountUpdate modifiedAccountUpdate = accountUpdate;
        modifiedAccountUpdate.accountID -= 1;
        updateAccountChecked(modifiedAccountUpdate, false);
    }

    SECTION("Incorrect leaf before")
    {
        AccountUpdate modifiedAccountUpdate = accountUpdate;
        modifiedAccountUpdate.before.nonce += 1;
        updateAccountChecked(modifiedAccountUpdate, false);
    }

    SECTION("Different leaf after")
    {
        AccountUpdate modifiedAccountUpdate = accountUpdate;
        modifiedAccountUpdate.after.nonce += 1;
        updateAccountChecked(modifiedAccountUpdate, true, false);
    }

    SECTION("Incorrect proof")
    {
        AccountUpdate modifiedAccountUpdate = accountUpdate;
        unsigned int randomIndex = rand() % modifiedAccountUpdate.proof.data.size();
        modifiedAccountUpdate.proof.data[randomIndex] += 1;
        updateAccountChecked(modifiedAccountUpdate, false);
    }
}

TEST_CASE("UpdateBalance", "[UpdateBalanceGadget]")
{
    RingSettlementBlock block = getRingSettlementBlock();
    REQUIRE(block.ringSettlements.size() > 0);
    const RingSettlement& ringSettlement = block.ringSettlements[0];
    const BalanceUpdate& balanceUpdate = ringSettlement.balanceUpdateB_B;

    auto updateBalanceChecked = [](const BalanceUpdate& balanceUpdate, bool expectedSatisfied, bool expectedRootAfterCorrect = true)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> rootBefore = make_variable(pb, "rootBefore");
        VariableArrayT address = make_var_array(pb, NUM_BITS_TOKEN, ".address");
        BalanceState stateBefore = createBalanceState(pb, balanceUpdate.before);
        BalanceState stateAfter = createBalanceState(pb, balanceUpdate.after);
        address.fill_with_bits_of_field_element(pb, balanceUpdate.tokenID);
        pb.val(rootBefore) = balanceUpdate.rootBefore;

        UpdateBalanceGadget updateBalance(pb, rootBefore, address, stateBefore, stateAfter, "updateBalance");
        updateBalance.generate_r1cs_constraints();
        updateBalance.generate_r1cs_witness(balanceUpdate.proof);

        REQUIRE(pb.is_satisfied() == expectedSatisfied);
        if (expectedSatisfied)
        {
            REQUIRE((pb.val(updateBalance.result()) == balanceUpdate.rootAfter) == expectedRootAfterCorrect);
        }
    };

    SECTION("Everything correct")
    {
        updateBalanceChecked(balanceUpdate, true, true);
    }

    SECTION("Incorrect address")
    {
        BalanceUpdate modifiedBalanceUpdate = balanceUpdate;
        modifiedBalanceUpdate.tokenID += 1;
        updateBalanceChecked(modifiedBalanceUpdate, true, false);
    }

    SECTION("Incorrect leaf before")
    {
        BalanceUpdate modifiedBalanceUpdate = balanceUpdate;
        modifiedBalanceUpdate.before.balance += 1;
        updateBalanceChecked(modifiedBalanceUpdate, false);
    }

    SECTION("Different leaf after")
    {
        BalanceUpdate modifiedBalanceUpdate = balanceUpdate;
        modifiedBalanceUpdate.after.balance += 1;
        updateBalanceChecked(modifiedBalanceUpdate, true, false);
    }

    SECTION("Incorrect proof")
    {
        BalanceUpdate modifiedBalanceUpdate = balanceUpdate;
        unsigned int randomIndex = rand() % modifiedBalanceUpdate.proof.data.size();
        modifiedBalanceUpdate.proof.data[randomIndex] += 1;
        updateBalanceChecked(modifiedBalanceUpdate, false);
    }
}

TEST_CASE("UpdateTradeHistory", "[UpdateTradeHistoryGadget]")
{
    RingSettlementBlock block = getRingSettlementBlock();
    REQUIRE(block.ringSettlements.size() > 0);
    const RingSettlement& ringSettlement = block.ringSettlements[0];
    const TradeHistoryUpdate& tradeHistoryUpdate = ringSettlement.tradeHistoryUpdate_A;

    auto updateTradeHistoryChecked = [](const TradeHistoryUpdate& tradeHistoryUpdate, bool expectedSatisfied, bool expectedRootAfterCorrect = true)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> rootBefore = make_variable(pb, "rootBefore");
        VariableArrayT address = make_var_array(pb, NUM_BITS_TRADING_HISTORY, ".address");
        TradeHistoryState stateBefore = createTradeHistoryState(pb, tradeHistoryUpdate.before);
        TradeHistoryState stateAfter = createTradeHistoryState(pb, tradeHistoryUpdate.after);
        address.fill_with_bits_of_field_element(pb, tradeHistoryUpdate.orderID);
        pb.val(rootBefore) = tradeHistoryUpdate.rootBefore;

        UpdateTradeHistoryGadget updateTradeHistory(pb, rootBefore, subArray(address, 0, NUM_BITS_TRADING_HISTORY), stateBefore, stateAfter, "updateTradeHistory");
        updateTradeHistory.generate_r1cs_constraints();
        updateTradeHistory.generate_r1cs_witness(tradeHistoryUpdate.proof);

        REQUIRE(pb.is_satisfied() == expectedSatisfied);
        if (expectedSatisfied)
        {
            REQUIRE((pb.val(updateTradeHistory.result()) == tradeHistoryUpdate.rootAfter) == expectedRootAfterCorrect);
        }
    };

    SECTION("Everything correct")
    {
        updateTradeHistoryChecked(tradeHistoryUpdate, true, true);
    }

    SECTION("Incorrect address")
    {
        TradeHistoryUpdate modifiedTradeHistoryUpdate = tradeHistoryUpdate;
        modifiedTradeHistoryUpdate.orderID += 1;
        updateTradeHistoryChecked(modifiedTradeHistoryUpdate, true, false);
    }

    SECTION("Incorrect leaf before")
    {
        TradeHistoryUpdate modifiedTradeHistoryUpdate = tradeHistoryUpdate;
        modifiedTradeHistoryUpdate.before.filled += 1;
        updateTradeHistoryChecked(modifiedTradeHistoryUpdate, false);
    }

    SECTION("Different leaf after")
    {
        TradeHistoryUpdate modifiedTradeHistoryUpdate = tradeHistoryUpdate;
        modifiedTradeHistoryUpdate.after.filled += 1;
        updateTradeHistoryChecked(modifiedTradeHistoryUpdate, true, false);
    }

    SECTION("Incorrect proof")
    {
        TradeHistoryUpdate modifiedTradeHistoryUpdate = tradeHistoryUpdate;
        unsigned int randomIndex = rand() % modifiedTradeHistoryUpdate.proof.data.size();
        modifiedTradeHistoryUpdate.proof.data[randomIndex] += 1;
        updateTradeHistoryChecked(modifiedTradeHistoryUpdate, false);
    }
}