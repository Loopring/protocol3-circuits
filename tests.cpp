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

TEST_CASE("SignatureVerifier", "[SignatureVerifier]")
{
    protoboard<FieldT> pb;

    jubjub::Params params;
    jubjub::VariablePointT publicKey(pb, "publicKey");
    pb_variable<FieldT> message = make_variable(pb, "message");
    SignatureVerifier signatureVerifier(pb, params, publicKey, message, "signatureVerifier");
    signatureVerifier.generate_r1cs_constraints();

    FieldT pubKeyX = FieldT("21607074953141243618425427250695537464636088817373528162920186615872448542319");
    FieldT pubKeyY = FieldT("3328786100751313619819855397819808730287075038642729822829479432223775713775");
    FieldT msg = FieldT("18996832849579325290301086811580112302791300834635590497072390271656077158490");
    FieldT Rx = FieldT("20401810397006237293387786382094924349489854205086853036638326738826249727385");
    FieldT Ry = FieldT("3339178343289311394427480868578479091766919601142009911922211138735585687725");
    FieldT s = FieldT("219593190015660463654216479865253652653333952251250676996482368461290160677");

    // All data valid
    {
        pb.val(publicKey.x) = pubKeyX;
        pb.val(publicKey.y) = pubKeyY;
        pb.val(message) = msg;
        Loopring::Signature signature(EdwardsPoint(Rx, Ry), s);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(pb.is_satisfied());
    }

    // All zeros
    {
        pb.val(publicKey.x) = 0;
        pb.val(publicKey.y) = 0;
        pb.val(message) = 0;
        Loopring::Signature signature(EdwardsPoint(0, 0), 0);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(!pb.is_satisfied());
    }

    // Different publicKey
    {
        pb.val(publicKey.x) = pubKeyX + 1;
        pb.val(publicKey.y) = pubKeyY;
        pb.val(message) = msg;
        Loopring::Signature signature(EdwardsPoint(Rx, Ry), s);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(!pb.is_satisfied());
    }
    {
        pb.val(publicKey.x) = pubKeyX;
        pb.val(publicKey.y) = pubKeyY + 1;
        pb.val(message) = msg;
        Loopring::Signature signature(EdwardsPoint(Rx, Ry), s);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(!pb.is_satisfied());
    }
    {
        // Different, valid public key
        pb.val(publicKey.x) = FieldT("19818098172422229289422284899436629503222263750727977198150374245991932884258");
        pb.val(publicKey.y) = FieldT("5951877988471485350710444403782724110196846988892201970720985561004735218817");
        pb.val(message) = msg;
        Loopring::Signature signature(EdwardsPoint(Rx, Ry), s);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(!pb.is_satisfied());
    }

    // Different message
    {
        pb.val(publicKey.x) = pubKeyX;
        pb.val(publicKey.y) = pubKeyY;
        pb.val(message) = msg + 1;
        Loopring::Signature signature(EdwardsPoint(Rx, Ry), s);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(!pb.is_satisfied());
    }
    {
        pb.val(publicKey.x) = pubKeyX;
        pb.val(publicKey.y) = pubKeyY;
        pb.val(message) = FieldT::zero();
        Loopring::Signature signature(EdwardsPoint(Rx, Ry), s);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(!pb.is_satisfied());
    }
    {
        pb.val(publicKey.x) = pubKeyX;
        pb.val(publicKey.y) = pubKeyY;
        pb.val(message) = getMaxFieldElement();
        Loopring::Signature signature(EdwardsPoint(Rx, Ry), s);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(!pb.is_satisfied());
    }

    // Different signature
    {
        pb.val(publicKey.x) = pubKeyX;
        pb.val(publicKey.y) = pubKeyY;
        pb.val(message) = msg;
        Loopring::Signature signature(EdwardsPoint(Rx + 1, Ry), s);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(!pb.is_satisfied());
    }
    {
        pb.val(publicKey.x) = pubKeyX;
        pb.val(publicKey.y) = pubKeyY;
        pb.val(message) = msg;
        Loopring::Signature signature(EdwardsPoint(Rx, Ry + 1), s);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(!pb.is_satisfied());
    }
    {
        pb.val(publicKey.x) = pubKeyX;
        pb.val(publicKey.y) = pubKeyY;
        pb.val(message) = msg;
        Loopring::Signature signature(EdwardsPoint(Rx, Ry), s + 1);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(!pb.is_satisfied());
    }
    {
        // Valid signature for a different public key (same message)
        FieldT Rx2 = FieldT("11724635741659369482608508002194555510423986519388485904857477054244428273528");
        FieldT Ry2 = FieldT("1141584024686665974825800506178016776173372699473828623261155117285910293572");
        FieldT s2 = FieldT("48808226556453260593782345205957224790810379817643725430561166968302957481");
        pb.val(publicKey.x) = pubKeyX;
        pb.val(publicKey.y) = pubKeyY;
        pb.val(message) = msg;
        Loopring::Signature signature(EdwardsPoint(Rx2, Ry2), s2);
        signatureVerifier.generate_r1cs_witness(signature);

        REQUIRE(!pb.is_satisfied());
    }
}

TEST_CASE("Float", "[FloatGadget]")
{
    FloatEncoding encoding = Float24Encoding;
    unsigned int numBitsFloat = encoding.numBitsExponent + encoding.numBitsMantissa;

    unsigned int maxLength = 127;
    unsigned int numIterations = 8;
    for (unsigned int n = 1; n <= maxLength; n++)
    {
        protoboard<FieldT> pb;

        Constants constants(pb, "constants");
        FloatGadget floatGadget(pb, constants, encoding, "floatGadget");
        floatGadget.generate_r1cs_constraints();

        // 0
        {
            FieldT value = FieldT::zero();
            floatGadget.generate_r1cs_witness(toFloat(value, encoding));

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(floatGadget.value()) == value));
            REQUIRE(compareBits(floatGadget.bits().get_bits(pb), toBits(value, numBitsFloat)));
        }

        // 1
        {
            FieldT value = FieldT::one();
            floatGadget.generate_r1cs_witness(toFloat(value, encoding));

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(floatGadget.value()) == value));
            REQUIRE(compareBits(floatGadget.bits().get_bits(pb), toBits(value, numBitsFloat)));
        }

        // Random
        for (unsigned int j = 0; j < numIterations; j++)
        {
            FieldT value = getRandomFieldElement(n);
            unsigned int f = toFloat(value, encoding);
            floatGadget.generate_r1cs_witness(FieldT(f));
            FieldT rValue = toFieldElement(fromFloat(f, encoding));

            REQUIRE(pb.is_satisfied());
            REQUIRE((pb.val(floatGadget.value()) == rValue));
            REQUIRE(compareBits(floatGadget.bits().get_bits(pb), toBits(FieldT(f), numBitsFloat)));
        }
    }
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

    // Random
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

TEST_CASE("LabelHasher", "[LabelHasher]")
{
    unsigned int maxLength = 1024;
    for (unsigned int n = 1; n <= maxLength; n = n * 2 + 1)
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
    }
}

TEST_CASE("subadd", "[subadd_gadget]")
{
    unsigned int maxLength = 252;
    for (unsigned int n = 1; n <= maxLength; n++)
    {
        protoboard<FieldT> pb;

        pb_variable<FieldT> from = make_variable(pb, "from");
        pb_variable<FieldT> to = make_variable(pb, "to");
        pb_variable<FieldT> amount = make_variable(pb, "to");

        subadd_gadget subAddGadget(pb, n, from, to, amount, "subAddGadget");
        subAddGadget.generate_r1cs_constraints();

        FieldT max = getMaxFieldElement(n);
        FieldT halfMax = getMaxFieldElement(n - 1);

        // (0, 0) -+ 0
        {
            pb.val(from) = 0;
            pb.val(to) = 0;
            pb.val(amount) = 0;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE(((pb.val(subAddGadget.X)) == FieldT::zero()));
            REQUIRE(((pb.val(subAddGadget.Y)) == FieldT::zero()));
        }

        // (1, 0) -+ 1
        {
            pb.val(from) = 1;
            pb.val(to) = 0;
            pb.val(amount) = 1;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE(((pb.val(subAddGadget.X)) == FieldT::zero()));
            REQUIRE(((pb.val(subAddGadget.Y)) == FieldT::one()));
        }

        // (max, 0) -+ 0
        {
            pb.val(from) = max;
            pb.val(to) = 0;
            pb.val(amount) = 0;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE(((pb.val(subAddGadget.X)) == max));
            REQUIRE(((pb.val(subAddGadget.Y)) == FieldT::zero()));
        }

        // (max, 0) -+ max
        {
            pb.val(from) = max;
            pb.val(to) = 0;
            pb.val(amount) = max;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE(((pb.val(subAddGadget.X)) == FieldT::zero()));
            REQUIRE(((pb.val(subAddGadget.Y)) == max));
        }

        // (halfMax, halfMax + 1) -+ halfMax
        {
            pb.val(from) = halfMax;
            pb.val(to) = halfMax + 1;
            pb.val(amount) = halfMax;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(pb.is_satisfied());
            REQUIRE(((pb.val(subAddGadget.X)) == FieldT::zero()));
            REQUIRE(((pb.val(subAddGadget.Y)) == max));
        }

        // (max, max) -+ max  (overflow)
        {
            pb.val(from) = max;
            pb.val(to) = max;
            pb.val(amount) = max;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // (halfMax, halfMax + 2) -+ halfMax  (overflow)
        {
            pb.val(from) = halfMax;
            pb.val(to) = halfMax + 2;
            pb.val(amount) = halfMax;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // (halfMax - 1, halfMax + 1) -+ halfMax (underflow)
        {
            pb.val(from) = halfMax - 1;
            pb.val(to) = halfMax + 1;
            pb.val(amount) = halfMax;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // (0, 0) -+ 1 (underflow)
        {
            pb.val(from) = 0;
            pb.val(to) = 0;
            pb.val(amount) = 1;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // (0, 0) -+ max (underflow)
        {
            pb.val(from) = 0;
            pb.val(to) = 0;
            pb.val(amount) = max;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // (max - 1, 0) -+ max  (underflow)
        {
            pb.val(from) = max - 1;
            pb.val(to) = 0;
            pb.val(amount) = max;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }

        // (max, 1) -+ max  (overflow)
        {
            pb.val(from) = max;
            pb.val(to) = 1;
            pb.val(amount) = max;
            subAddGadget.generate_r1cs_witness();

            REQUIRE(!pb.is_satisfied());
        }
    }
}
