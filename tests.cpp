#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "ThirdParty/catch.hpp"

#include "ethsnarks.hpp"
#include "Utils/Utils.h"
#include "ThirdParty/BigInt.hpp"

#include "Gadgets/MathGadgets.h"

using namespace std;
using namespace libff;
using namespace libsnark;
using namespace ethsnarks;
using namespace Loopring;

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

struct Initialize
{
    Initialize()
    {
        ethsnarks::ppT::init_public_params();
        srand(time(NULL));
    }
} initialize;

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
    for (unsigned int n = 2; n < maxNumInputs; n++)
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
    }
}

TEST_CASE("OR", "[OrGadget]")
{
    unsigned int maxNumInputs = 64;
    unsigned int numIterations = 128;
    for (unsigned int n = 2; n < maxNumInputs; n++)
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
    }
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
    for (unsigned int n = 1; n < maxNumInputs; n++)
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
    }
}

TEST_CASE("Equal", "[EqualGadget]")
{
    unsigned int maxLength = 252;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> a = make_variable(pb, ".A");
        pb_variable<FieldT> b = make_variable(pb, ".B");

        EqualGadget equalGadget(pb, a, b, n, "equalGadget");
        equalGadget.generate_r1cs_constraints();

        // 0 == 0
        {
            pb.val(a) = 0;
            pb.val(b) = 0;
            equalGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(equalGadget.result()) == FieldT::one()));
        }

        // max == max
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = getMaxFieldElement(n);
            equalGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(equalGadget.result()) == FieldT::one()));
        }

        // Random field elements ==
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement(n);
            pb.val(b) = pb.val(a);
            equalGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(equalGadget.result()) == FieldT::one()));
        }

        // 0 != max
        {
            pb.val(a) = 0;
            pb.val(b) = getMaxFieldElement(n);

            equalGadget.generate_r1cs_witness();
            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(equalGadget.result()) == FieldT::zero()));
        }

        // max != 0
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = 0;
            equalGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(equalGadget.result()) == FieldT::zero()));
        }

        // Random field elements !=
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement(n);
            pb.val(b) = getRandomFieldElement(n);
            equalGadget.generate_r1cs_witness();
            if (pb.val(a) == pb.val(b))
            {
                continue;
            }

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(equalGadget.result()) == FieldT::zero()));
        }
    }
}

TEST_CASE("RequireEqual", "[RequireEqualGadget]")
{
    unsigned int maxLength = 254;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> a = make_variable(pb, ".A");
        pb_variable<FieldT> b = make_variable(pb, ".B");

        RequireEqualGadget requireEqualGadget(pb, a, b, "requireEqualGadget");
        requireEqualGadget.generate_r1cs_constraints();

        // 0 == 0
        {
            pb.val(a) = 0;
            pb.val(b) = 0;
            requireEqualGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }

        // max == max
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = getMaxFieldElement(n);
            requireEqualGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }

        // Random field elements ==
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement(n);
            pb.val(b) = pb.val(a);
            requireEqualGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }

        // 0 != max
        {
            pb.val(a) = 0;
            pb.val(b) = getMaxFieldElement(n);

            requireEqualGadget.generate_r1cs_witness();
            REQUIRE(!pb.is_satisfied());
        }

        // max != 0
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = 0;
            requireEqualGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // Random field elements !=
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement(n);
            pb.val(b) = getRandomFieldElement(n);
            requireEqualGadget.generate_r1cs_witness();
            if (pb.val(a) == pb.val(b))
            {
                continue;
            }

            REQUIRE(!pb.is_satisfied());
        }
    }
}

TEST_CASE("RequireZeroAorB", "[RequireZeroAorBGadget]")
{
    unsigned int numIterations = 128;

    protoboard<FieldT> pb;

    pb_variable<FieldT> a = make_variable(pb, ".A");
    pb_variable<FieldT> b = make_variable(pb, ".B");

    RequireZeroAorBGadget requireZeroAorBGadget(pb, a, b, "requireZeroAorBGadget");
    requireZeroAorBGadget.generate_r1cs_constraints();

    // 0 || 0
    {
        pb.val(a) = 0;
        pb.val(b) = 0;
        requireZeroAorBGadget.generate_r1cs_witness();

        REQUIRE(pb.is_satisfied());
    }

    for (unsigned int i = 0; i < numIterations; i++)
    {
        // 0 || non-zero
        {
            pb.val(a) = 0;
            pb.val(b) = getRandomFieldElement();
            while(pb.val(b) == 0)
            {
                pb.val(b) = getRandomFieldElement();
            }
            requireZeroAorBGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }

        // non-zero || 0
        {
            pb.val(a) = getRandomFieldElement();
            pb.val(b) = 0;
            while(pb.val(a) == 0)
            {
                pb.val(a) = getRandomFieldElement();
            }
            requireZeroAorBGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }

        // non-zero || non-zero
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement();
            pb.val(b) = getRandomFieldElement();
            while(pb.val(a) == 0)
            {
                pb.val(a) = getRandomFieldElement();
            }
            while(pb.val(b) == 0)
            {
                pb.val(b) = getRandomFieldElement();
            }
            requireZeroAorBGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
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

    // 0
    {
        pb.val(a) = 0;
        requireNotZeroGadget.generate_r1cs_witness();

        REQUIRE(!pb.is_satisfied());
    }

    // non-zero
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

TEST_CASE("RequireNotEqual", "[RequireNotEqualGadget]")
{
    unsigned int maxLength = 254;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> a = make_variable(pb, ".A");
        pb_variable<FieldT> b = make_variable(pb, ".B");

        RequireNotEqualGadget requireNotEqualGadget(pb, a, b, "requireNotEqualGadget");
        requireNotEqualGadget.generate_r1cs_constraints();

        // 0 == 0
        {
            pb.val(a) = 0;
            pb.val(b) = 0;
            requireNotEqualGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // max == max
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = getMaxFieldElement(n);
            requireNotEqualGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // Random field elements ==
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement(n);
            pb.val(b) = pb.val(a);
            requireNotEqualGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // 0 != max
        {
            pb.val(a) = 0;
            pb.val(b) = getMaxFieldElement(n);

            requireNotEqualGadget.generate_r1cs_witness();
            REQUIRE(pb.is_satisfied());
        }

        // max != 0
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = 0;
            requireNotEqualGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }

        // Random field elements !=
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement(n);
            pb.val(b) = getRandomFieldElement(n);
            requireNotEqualGadget.generate_r1cs_witness();
            if (pb.val(a) == pb.val(b))
            {
                continue;
            }

            REQUIRE(pb.is_satisfied());
        }
    }
}

TEST_CASE("Min", "[MinGadget]")
{
    unsigned int maxLength = 252;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> a = make_variable(pb, ".A");
        pb_variable<FieldT> b = make_variable(pb, ".B");

        MinGadget minGadget(pb, a, b, n, "minGadget");
        minGadget.generate_r1cs_constraints();

        // min(0, 0)
        {
            pb.val(a) = 0;
            pb.val(b) = 0;
            minGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(minGadget.result()) == FieldT::zero()));
        }

        // min(max, max)
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = getMaxFieldElement(n);
            minGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(minGadget.result()) == getMaxFieldElement(n)));
        }

        // min(0, max)
        {
            pb.val(a) = 0;
            pb.val(b) = getMaxFieldElement(n);
            minGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(minGadget.result()) == FieldT::zero()));
        }

        // min(max, 0)
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = 0;
            minGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(minGadget.result()) == FieldT::zero()));
        }

        // Random
        for (unsigned int j = 0; j < numIterations; j++)
        {
            BigInt bnA = getRandomFieldElementAsBigInt(n);
            BigInt bnB = getRandomFieldElementAsBigInt(n);
            pb.val(a) = toFieldElement(bnA);
            pb.val(b) = toFieldElement(bnB);
            minGadget.generate_r1cs_witness();
            FieldT expectedValue = bnA < bnB ? pb.val(a) : pb.val(b);

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(minGadget.result()) == expectedValue));
        }
    }
}

TEST_CASE("RequireLeq", "[RequireLeqGadget]")
{
    unsigned int maxLength = 252;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> a = make_variable(pb, ".A");
        pb_variable<FieldT> b = make_variable(pb, ".B");

        RequireLeqGadget requireLeqGadget(pb, a, b, n, "requireLeqGadget");
        requireLeqGadget.generate_r1cs_constraints();

        // min(0, 0)
        {
            pb.val(a) = 0;
            pb.val(b) = 0;
            requireLeqGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }

        // min(max, max)
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = getMaxFieldElement(n);
            requireLeqGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }

        // min(0, max)
        {
            pb.val(a) = 0;
            pb.val(b) = getMaxFieldElement(n);
            requireLeqGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }

        // min(max, 0)
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = 0;
            requireLeqGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // Random
        for (unsigned int j = 0; j < numIterations; j++)
        {
            BigInt bnA = getRandomFieldElementAsBigInt(n);
            BigInt bnB = getRandomFieldElementAsBigInt(n);
            pb.val(a) = toFieldElement(bnA);
            pb.val(b) = toFieldElement(bnB);
            requireLeqGadget.generate_r1cs_witness();
            bool expectedValue = bnA <= bnB;

            REQUIRE(pb.is_satisfied() == expectedValue);
        }
    }
}

TEST_CASE("RequireLt", "[RequireLtGadget]")
{
    unsigned int maxLength = 252;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> a = make_variable(pb, ".A");
        pb_variable<FieldT> b = make_variable(pb, ".B");

        RequireLtGadget requireLtGadget(pb, a, b, n, "requireLtGadget");
        requireLtGadget.generate_r1cs_constraints();

        // min(0, 0)
        {
            pb.val(a) = 0;
            pb.val(b) = 0;
            requireLtGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // min(max, max)
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = getMaxFieldElement(n);
            requireLtGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // min(0, max)
        {
            pb.val(a) = 0;
            pb.val(b) = getMaxFieldElement(n);
            requireLtGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }

        // min(max, 0)
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = 0;
            requireLtGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // Random
        for (unsigned int j = 0; j < numIterations; j++)
        {
            BigInt bnA = getRandomFieldElementAsBigInt(n);
            BigInt bnB = getRandomFieldElementAsBigInt(n);
            pb.val(a) = toFieldElement(bnA);
            pb.val(b) = toFieldElement(bnB);
            requireLtGadget.generate_r1cs_witness();
            bool expectedValue = bnA < bnB;

            REQUIRE(pb.is_satisfied() == expectedValue);
        }
    }
}

TEST_CASE("MulDiv", "[MulDivGadget]")
{
    unsigned int maxLength = 126;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> a = make_variable(pb, ".A");
        pb_variable<FieldT> b = make_variable(pb, ".B");
        pb_variable<FieldT> c = make_variable(pb, ".C");

        Constants constants(pb, "constants");
        MulDivGadget mulDivGadget(pb, constants, a, b, c, n, "mulDivGadget");
        mulDivGadget.generate_r1cs_constraints();

        // Divide by zero
        // rand * rand / 0 = invalid
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement(n);
            pb.val(b) = getRandomFieldElement(n);
            pb.val(c) = 0;
            mulDivGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // 0 * 0 / 1 = 0
        {
            pb.val(a) = 0;
            pb.val(b) = 0;
            pb.val(c) = 1;
            mulDivGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(mulDivGadget.result()) == FieldT::zero()));
            REQUIRE((pb.val(mulDivGadget.getRemainder()) == FieldT::zero()));
        }

        // max * max / max
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = getMaxFieldElement(n);
            pb.val(c) = getMaxFieldElement(n);
            mulDivGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(mulDivGadget.result()) == getMaxFieldElement(n)));
            REQUIRE((pb.val(mulDivGadget.getRemainder()) == FieldT::zero()));
        }

        // remainder >= C
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = getMaxFieldElement(n);
            pb.val(c) = getMaxFieldElement(n);
            mulDivGadget.generate_r1cs_witness();
            pb.val(mulDivGadget.remainder.packed) += pb.val(c);
            mulDivGadget.remainder.generate_r1cs_witness_from_packed();
            pb.val(mulDivGadget._result) -= FieldT::one();

            REQUIRE(!pb.is_satisfied());
        }

        // Random
        for (unsigned int j = 0; j < numIterations; j++)
        {
            BigInt bnA = getRandomFieldElementAsBigInt(n);
            BigInt bnB = getRandomFieldElementAsBigInt(n);
            BigInt bnC = getRandomFieldElementAsBigInt(n);
            while (bnC == 0)
            {
                bnC = getRandomFieldElementAsBigInt(n);
            }
            pb.val(a) = toFieldElement(bnA);
            pb.val(b) = toFieldElement(bnB);
            pb.val(c) = toFieldElement(bnC);
            mulDivGadget.generate_r1cs_witness();

            BigInt multiplied = bnA * bnB;
            BigInt remainder = multiplied % bnC;
            BigInt result = multiplied / bnC;

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(mulDivGadget.result()) == toFieldElement(result)));
            REQUIRE((pb.val(mulDivGadget.getRemainder()) == toFieldElement(remainder)));
            REQUIRE((pb.val(mulDivGadget.multiplied()) == toFieldElement(multiplied)));
        }
    }
}

TEST_CASE("RequireAccuracy", "[RequireAccuracyGadget]")
{
    unsigned int maxLength = 126;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> a = make_variable(pb, ".A");
        pb_variable<FieldT> b = make_variable(pb, ".B");

        Accuracy accuracy = {100 - 1, 100};
        RequireAccuracyGadget requireAccuracyGadget(pb, a, b, accuracy, n, "requireAccuracyGadget");
        requireAccuracyGadget.generate_r1cs_constraints();

        // 0, 0
        {
            pb.val(a) = 0;
            pb.val(b) = 0;
            requireAccuracyGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
        }

        // 0, max
        {
            pb.val(a) = 0;
            pb.val(b) = getMaxFieldElement(n);
            requireAccuracyGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // max, 0
        {
            pb.val(a) = getMaxFieldElement(n);
            pb.val(b) = 0;
            requireAccuracyGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // value > original value
        for (unsigned int j = 0; j < numIterations; j++)
        {
            pb.val(a) = getRandomFieldElement(n);
            while (pb.val(a) == FieldT::zero())
            {
                pb.val(a) = getRandomFieldElement(n);
            }
            pb.val(b) = pb.val(a) - 1;
            requireAccuracyGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // Do some specific tests
        if (n == 96)
        {
            // 100, 100
            {
                pb.val(a) = 100;
                pb.val(b) = 100;
                requireAccuracyGadget.generate_r1cs_witness();

                REQUIRE(pb.is_satisfied());
            }

            // 101, 100
            {
                pb.val(a) = 101;
                pb.val(b) = 100;
                requireAccuracyGadget.generate_r1cs_witness();

                REQUIRE(!pb.is_satisfied());
            }

            // 99, 100
            {
                pb.val(a) = 99;
                pb.val(b) = 100;
                requireAccuracyGadget.generate_r1cs_witness();

                REQUIRE(pb.is_satisfied());
            }

            // max + 1, max
            {
                pb.val(a) = getMaxFieldElement(n) + 1;
                pb.val(b) = getMaxFieldElement(n);
                requireAccuracyGadget.generate_r1cs_witness();

                REQUIRE(!pb.is_satisfied());
            }

            // max, 3000
            {
                pb.val(a) = getMaxFieldElement(n);
                pb.val(b) = 3000;
                requireAccuracyGadget.generate_r1cs_witness();

                REQUIRE(!pb.is_satisfied());
            }

            // Exhaustive checks against a single value
            unsigned int originalValue = 3000;
            for(unsigned int i = 0; i < originalValue * 3; i++)
            {
                pb.val(a) = i;
                pb.val(b) = originalValue;
                requireAccuracyGadget.generate_r1cs_witness();
                bool expectedValue = (i >= 2970 && i <= 3000);

                REQUIRE(pb.is_satisfied() == expectedValue);
            }
        }
    }
}