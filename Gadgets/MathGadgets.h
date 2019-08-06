#ifndef _MATHGADGETS_H_
#define _MATHGADGETS_H_

#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "jubjub/point.hpp"
#include "jubjub/eddsa.hpp"
#include "gadgets/subadd.hpp"
#include "gadgets/poseidon.hpp"

using namespace ethsnarks;
using namespace jubjub;

namespace Loopring
{

void forceEqual(ProtoboardT& pb, const VariableT& A, const VariableT& B, const std::string& annotation_prefix)
{
    pb.add_r1cs_constraint(ConstraintT(A, FieldT::one(), B), FMT(annotation_prefix, ".forceEqual"));
}

class Constants : public GadgetT
{
public:

    const VariableT zero;
    const VariableT one;
    const VariableT _100;
    const VariableT _10000;
    const VariableT _100000;
    const VariableT emptyTradeHistory;
    const VariableT maxAmount;
    const VariableArrayT zeroAccount;

    const VariableArrayT padding_0000;

    Constants(
        ProtoboardT& pb,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        zero(make_variable(pb, FieldT::zero(), FMT(prefix, ".zero"))),
        one(make_variable(pb, FieldT::one(), FMT(prefix, ".one"))),
        _100(make_variable(pb, ethsnarks::FieldT(100), FMT(prefix, "._100"))),
        _10000(make_variable(pb, ethsnarks::FieldT(10000), FMT(prefix, "._10000"))),
        _100000(make_variable(pb, ethsnarks::FieldT(100000), FMT(prefix, "._100000"))),
        emptyTradeHistory(make_variable(pb, ethsnarks::FieldT(EMPTY_TRADE_HISTORY), FMT(prefix, ".emptyTradeHistory"))),
        maxAmount(make_variable(pb, ethsnarks::FieldT(MAX_AMOUNT), FMT(prefix, ".maxAmount"))),
        zeroAccount(NUM_BITS_ACCOUNT, zero),
        padding_0000(4, zero)
    {
        assert(NUM_BITS_MAX_VALUE == FieldT::size_in_bits());
        assert(NUM_BITS_FIELD_CAPACITY == FieldT::capacity());
    }

    void generate_r1cs_witness()
    {

    }

    void generate_r1cs_constraints()
    {
        pb.add_r1cs_constraint(ConstraintT(FieldT::one() + zero, FieldT::one(), FieldT::one()), ".zero");
        pb.add_r1cs_constraint(ConstraintT(one, FieldT::one(), FieldT::one()), ".one");
        pb.add_r1cs_constraint(ConstraintT(_100, FieldT::one(), ethsnarks::FieldT(100)), "._100");
        pb.add_r1cs_constraint(ConstraintT(_10000, FieldT::one(), ethsnarks::FieldT(10000)), "._10000");
        pb.add_r1cs_constraint(ConstraintT(_100000, FieldT::one(), ethsnarks::FieldT(100000)), "._100000");
        pb.add_r1cs_constraint(ConstraintT(emptyTradeHistory, FieldT::one(), ethsnarks::FieldT(EMPTY_TRADE_HISTORY)), ".emptyTradeHistory");
        pb.add_r1cs_constraint(ConstraintT(maxAmount, FieldT::one(), ethsnarks::FieldT(MAX_AMOUNT)), ".maxAmount");
    }
};

class DynamicVariableGadget : public GadgetT
{
public:

    std::vector<VariableT> variables;

    DynamicVariableGadget(
        ProtoboardT& pb,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix)
    {
        add(make_variable(pb, FMT(prefix, ".frontValue")));
    }

    const VariableT& front() const
    {
        return variables.front();
    }

    const VariableT& back() const
    {
        return variables.back();
    }

    void add(const VariableT& variable)
    {
        variables.push_back(variable);
    }

    void generate_r1cs_witness(ethsnarks::FieldT value)
    {
        pb.val(variables.front()) = value;
    }
};


class TransferGadget : public GadgetT
{
public:

    subadd_gadget subadd;

    TransferGadget(
        ProtoboardT& pb,
        DynamicVariableGadget& from,
        DynamicVariableGadget& to,
        const VariableT& value,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        subadd(pb, NUM_BITS_AMOUNT, from.back(), to.back(), value, FMT(prefix, ".subadd"))
    {
        from.add(subadd.X);
        to.add(subadd.Y);
    }

    void generate_r1cs_witness()
    {
        subadd.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        subadd.generate_r1cs_constraints();
    }
};

class UnsafeSubGadget : public GadgetT
{
public:

    VariableT value;
    VariableT sub;
    VariableT sum;

    UnsafeSubGadget(
        ProtoboardT& pb,
        const VariableT& _value,
        const VariableT& _sub,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        value(_value),
        sub(_sub),
        sum(make_variable(pb, FMT(prefix, ".sum")))
    {

    }

    const VariableT& result() const
    {
        return sum;
    }

    void generate_r1cs_witness()
    {
        pb.val(sum) = pb.val(value) - pb.val(sub);
    }

    void generate_r1cs_constraints()
    {
        pb.add_r1cs_constraint(ConstraintT(value - sub, FieldT::one(), sum), ".value - sub = sum");
    }
};

class UnsafeAddGadget : public GadgetT
{
public:

    VariableT value;
    VariableT add;
    VariableT sum;

    UnsafeAddGadget(
        ProtoboardT& pb,
        const VariableT& _value,
        const VariableT& _add,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        value(_value),
        add(_add),
        sum(make_variable(pb, FMT(prefix, ".sum")))
    {

    }

    const VariableT& result() const
    {
        return sum;
    }

    void generate_r1cs_witness()
    {
        pb.val(sum) = pb.val(value) + pb.val(add);
    }

    void generate_r1cs_constraints()
    {
        pb.add_r1cs_constraint(ConstraintT(value + add, FieldT::one(), sum), ".value + add = sum");
    }
};

class TernaryGadget : public GadgetT
{
public:
    VariableT b;
    VariableT x;
    VariableT y;

    VariableT z;

    TernaryGadget(
        ProtoboardT& pb,
        const VariableT& _b,
        const VariableT& _x,
        const VariableT& _y,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        b(_b),
        x(_x),
        y(_y),

        z(make_variable(pb, FMT(prefix, ".z")))
    {

    }

    const VariableT& result() const
    {
        return z;
    }

    void generate_r1cs_witness()
    {
        pb.val(z) = (pb.val(b) == FieldT::one()) ? pb.val(x) : pb.val(y);
    }

    void generate_r1cs_constraints(bool enforceBitness = true)
    {
        if (enforceBitness)
        {
            libsnark::generate_boolean_r1cs_constraint<ethsnarks::FieldT>(pb, b, FMT(annotation_prefix, ".bitness"));
        }
        pb.add_r1cs_constraint(ConstraintT(b, y - x, y - z), FMT(annotation_prefix, ".b * (y - x) == (y - z)"));
    }
};

class LeqGadget : public GadgetT
{
public:
    VariableT _lt;
    VariableT _leq;
    libsnark::comparison_gadget<ethsnarks::FieldT> comparison;

    LeqGadget(
        ProtoboardT& pb,
        const VariableT& A,
        const VariableT& B,
        const size_t n,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        _lt(make_variable(pb, 1, FMT(prefix, ".lt"))),
        _leq(make_variable(pb, 1, FMT(prefix, ".leq"))),
        comparison(pb, n, A, B, _lt, _leq, FMT(prefix, ".A <(=) B"))
    {
        // The comparison gadget is only guaranteed to work correctly on values in the field capacity - 1
        assert(n <= NUM_BITS_FIELD_CAPACITY - 1);
    }

    const VariableT& lt() const
    {
        return _lt;
    }

    const VariableT& leq() const
    {
        return _leq;
    }

    void generate_r1cs_witness()
    {
        comparison.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        comparison.generate_r1cs_constraints();
    }
};


class AndGadget : public GadgetT
{
public:
    std::vector<VariableT> inputs;
    std::vector<VariableT> results;

    AndGadget(
        ProtoboardT& pb,
        const std::vector<VariableT>& _inputs,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        inputs(_inputs)
    {
        assert(inputs.size() > 1);
        for (unsigned int i = 1; i < inputs.size(); i++)
        {
            results.emplace_back(make_variable(pb, FMT(prefix, ".results")));
        }
    }

    const VariableT& result() const
    {
        return results.back();
    }

    void generate_r1cs_witness()
    {
        pb.val(results[0]) = pb.val(inputs[0]) * pb.val(inputs[1]);
        for (unsigned int i = 2; i < inputs.size(); i++)
        {
            pb.val(results[i - 1]) = pb.val(results[i - 2]) * pb.val(inputs[i]);
        }
    }

    void generate_r1cs_constraints()
    {
        // This can be done more efficiently but we never have any long inputs so no need
        pb.add_r1cs_constraint(ConstraintT(inputs[0], inputs[1], results[0]), FMT(annotation_prefix, ".A && B"));
        for (unsigned int i = 2; i < inputs.size(); i++)
        {
            pb.add_r1cs_constraint(ConstraintT(inputs[i], results[i - 2], results[i - 1]), FMT(annotation_prefix, ".A && B"));
        }
    }
};

class OrGadget : public GadgetT
{
public:
    std::vector<VariableT> inputs;
    std::vector<VariableT> results;

    OrGadget(
        ProtoboardT& pb,
        const std::vector<VariableT>& _inputs,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        inputs(_inputs)
    {
        assert(inputs.size() > 1);
        for (unsigned int i = 1; i < inputs.size(); i++)
        {
            results.emplace_back(make_variable(pb, FMT(prefix, ".results")));
        }
    }

    const VariableT& result() const
    {
        return results.back();
    }

    void generate_r1cs_witness()
    {
        pb.val(results[0]) = FieldT::one() - (FieldT::one() - pb.val(inputs[0])) * (FieldT::one() - pb.val(inputs[1]));
        for (unsigned int i = 2; i < inputs.size(); i++)
        {
            pb.val(results[i - 1]) = FieldT::one() - (FieldT::one() - pb.val(results[i - 2])) * (FieldT::one() - pb.val(inputs[i]));
        }
    }

    void generate_r1cs_constraints()
    {
        pb.add_r1cs_constraint(ConstraintT(FieldT::one() - inputs[0], FieldT::one() - inputs[1], FieldT::one() - results[0]), FMT(annotation_prefix, ".A || B == _or"));
        for (unsigned int i = 2; i < inputs.size(); i++)
        {
            pb.add_r1cs_constraint(ConstraintT(FieldT::one() - inputs[i], FieldT::one() - results[i - 2], FieldT::one() - results[i - 1]), FMT(annotation_prefix, ".A || B == _or"));
        }
    }
};

class NotGadget : public GadgetT
{
public:
    VariableT A;
    VariableT _not;

    NotGadget(
        ProtoboardT& pb,
        const VariableT& _A,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        A(_A),
        _not(make_variable(pb, FMT(prefix, "._not")))
    {

    }

    const VariableT& result() const
    {
        return _not;
    }

    void generate_r1cs_witness()
    {
        pb.val(_not) = FieldT::one() - pb.val(A);
    }

    void generate_r1cs_constraints()
    {
        pb.add_r1cs_constraint(ConstraintT(FieldT::one() - A, FieldT::one(), _not), FMT(annotation_prefix, ".!A == _not"));
    }
};

class XorArrayGadget : public GadgetT
{
public:
    VariableArrayT A;
    VariableArrayT B;
    VariableArrayT C;

    XorArrayGadget(
        ProtoboardT& pb,
        VariableArrayT _A,
        VariableArrayT _B,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        A(_A),
        B(_B),

        C(make_var_array(pb, A.size(), FMT(prefix, ".C")))
    {
        assert(A.size() == B.size());
    }

    const VariableArrayT& result() const
    {
        return C;
    }

    void generate_r1cs_witness()
    {
        for (unsigned int i = 0; i < C.size(); i++)
        {
            pb.val(C[i]) = pb.val(A[i]) + pb.val(B[i]) - ((pb.val(A[i]) == FieldT::one() && pb.val(B[i]) == FieldT::one()) ? 2 : 0);
        }
    }

    void generate_r1cs_constraints()
    {
        for (unsigned int i = 0; i < C.size(); i++)
        {
            pb.add_r1cs_constraint(ConstraintT(2 * A[i], B[i], A[i] + B[i] - C[i]), FMT(annotation_prefix, ".A ^ B == C"));
        }
    }
};

class EqualGadget : public GadgetT
{
public:
    LeqGadget leq;
    NotGadget NOTLt;
    AndGadget NOTltANDleq;

    EqualGadget(
        ProtoboardT& pb,
        const VariableT& A,
        const VariableT& B,
        const size_t n,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        leq(pb, A, B, n, FMT(prefix, ".A <(=) B")),
        NOTLt(pb, leq.lt(), FMT(prefix, ".!(A<B)")),
        NOTltANDleq(pb, {NOTLt.result(), leq.leq()}, FMT(prefix, ".!(A<B) && (A<=B)"))
    {

    }

    const VariableT& result() const
    {
        return NOTltANDleq.result();
    }

    void generate_r1cs_witness()
    {
        leq.generate_r1cs_witness();
        NOTLt.generate_r1cs_witness();
        NOTltANDleq.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        leq.generate_r1cs_constraints();
        NOTLt.generate_r1cs_constraints();
        NOTltANDleq.generate_r1cs_constraints();
    }
};

class RequireEqualGadget : public GadgetT
{
public:
    VariableT A;
    VariableT B;

    RequireEqualGadget(
        ProtoboardT& pb,
        const VariableT& _A,
        const VariableT& _B,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        A(_A),
        B(_B)
    {

    }

    void generate_r1cs_witness()
    {

    }

    void generate_r1cs_constraints()
    {
        forceEqual(pb, A, B, FMT(annotation_prefix, ".forceEqual"));
    }
};

class RequireZeroAorBGadget : public GadgetT
{
public:
    VariableT A;
    VariableT B;

    RequireZeroAorBGadget(
        ProtoboardT& pb,
        const VariableT& _A,
        const VariableT& _B,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        A(_A),
        B(_B)
    {

    }

    void generate_r1cs_witness()
    {

    }

    void generate_r1cs_constraints()
    {
        pb.add_r1cs_constraint(ConstraintT(A, B, FieldT::zero()), FMT(annotation_prefix, ".A == 0 || B == 0"));
    }
};

class RequireNotZeroGadget : public GadgetT
{
public:
    VariableT A;
    VariableT A_inv;

    RequireNotZeroGadget(
        ProtoboardT& pb,
        const VariableT& _A,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        A(_A),
        A_inv(make_variable(pb, FMT(prefix, ".A_inv")))
    {

    }

    void generate_r1cs_witness()
    {
        pb.val(A_inv) = pb.val(A).inverse();
    }

    void generate_r1cs_constraints()
    {
        pb.add_r1cs_constraint(ConstraintT(A, A_inv, FieldT::one()), FMT(annotation_prefix, ".A * A_inv == 1"));
    }
};

class RequireNotEqualGadget : public GadgetT
{
public:
    VariableT A;
    VariableT B;

    VariableT diff;
    RequireNotZeroGadget notZero;

    RequireNotEqualGadget(
        ProtoboardT& pb,
        const VariableT& _A,
        const VariableT& _B,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        A(_A),
        B(_B),
        diff(make_variable(pb, FMT(prefix, ".diff"))),
        notZero(pb, diff, FMT(prefix, ".diff != 0"))
    {

    }

    void generate_r1cs_witness()
    {
        pb.val(diff) = pb.val(A) - pb.val(B);
        notZero.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        pb.add_r1cs_constraint(ConstraintT(A - B, FieldT::one(), diff), FMT(annotation_prefix, ".A - B == diff"));
        notZero.generate_r1cs_constraints();
    }
};

class MinGadget : public GadgetT
{
public:
    LeqGadget A_lt_B;
    TernaryGadget minimum;

    MinGadget(
        ProtoboardT& pb,
        const VariableT& A,
        const VariableT& B,
        const size_t n,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        A_lt_B(pb, A, B, n, FMT(prefix, ".(A < B)")),
        minimum(pb, A_lt_B.lt(), A, B, FMT(prefix, ".minimum = (A < B) ? A : B"))
    {

    }

    const VariableT& result() const
    {
        return minimum.result();
    }

    void generate_r1cs_witness()
    {
        A_lt_B.generate_r1cs_witness();
        minimum.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        A_lt_B.generate_r1cs_constraints();
        minimum.generate_r1cs_constraints();
    }
};

class RequireLeqGadget : public GadgetT
{
public:
    LeqGadget leqGadget;

    RequireLeqGadget(
        ProtoboardT& pb,
        const VariableT& A,
        const VariableT& B,
        const size_t n,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        leqGadget(pb, A, B, n, FMT(prefix, ".leq"))
    {

    }

    void generate_r1cs_witness()
    {
        leqGadget.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        leqGadget.generate_r1cs_constraints();
        pb.add_r1cs_constraint(ConstraintT(leqGadget.leq(), FieldT::one(), FieldT::one()), FMT(annotation_prefix, ".leq == 1"));
    }
};

class RequireLtGadget : public GadgetT
{
public:
    LeqGadget leqGadget;

    RequireLtGadget(
        ProtoboardT& pb,
        const VariableT& A,
        const VariableT& B,
        const size_t n,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        leqGadget(pb, A, B, n, FMT(prefix, ".leq"))
    {

    }

    void generate_r1cs_witness()
    {
        leqGadget.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        leqGadget.generate_r1cs_constraints();
        pb.add_r1cs_constraint(ConstraintT(leqGadget.lt(), FieldT::one(), FieldT::one()), FMT(annotation_prefix, ".lt == 1"));
    }
};

class MulDivGadget : public GadgetT
{
public:
    const VariableT A;
    const VariableT B;
    const VariableT C;
    const VariableT _result;

    RequireNotZeroGadget C_notZero;

    const VariableT X;
    libsnark::dual_variable_gadget<FieldT> remainder;

    RequireLtGadget remainder_lt_C;

    // (A * B) / C = D
    // A and B need to be less than <= 126bits
    // C cannot be 0
    MulDivGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const VariableT& _A,
        const VariableT& _B,
        const VariableT& _C,
        unsigned int numBitsDenominator,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        A(_A),
        B(_B),
        C(_C),

        C_notZero(pb, C, FMT(prefix, ".C_notZero")),

        _result(make_variable(pb, FMT(prefix, "._result"))),

        X(make_variable(pb, FMT(prefix, ".X"))),
        remainder(pb, numBitsDenominator, FMT(prefix, ".remainder")),

        remainder_lt_C(pb, remainder.packed, C, numBitsDenominator, FMT(prefix, ".remainder < C"))
    {

    }

    const VariableT& result() const
    {
        return _result;
    }

    const VariableT& getRemainder() const
    {
        return remainder.packed;
    }

    const VariableT& multiplied() const
    {
        return X;
    }

    void generate_r1cs_witness()
    {
        C_notZero.generate_r1cs_witness();

        pb.val(X) = pb.val(A) * pb.val(B);
        if (pb.val(C) != FieldT::zero())
        {
            pb.val(_result) = ethsnarks::FieldT((toBigInt(pb.val(X)) / toBigInt(pb.val(C))).to_string().c_str());
        }
        else
        {
            pb.val(_result) = FieldT::zero();
        }
        pb.val(remainder.packed) = pb.val(X) - (pb.val(C) * pb.val(_result));
        remainder.generate_r1cs_witness_from_packed();

        remainder_lt_C.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        C_notZero.generate_r1cs_constraints();

        pb.add_r1cs_constraint(ConstraintT(A, B, X), FMT(annotation_prefix, ".A * B == X"));
        pb.add_r1cs_constraint(ConstraintT(C, _result, X - remainder.packed), FMT(annotation_prefix, "._result * C == X - remainder"));

        remainder.generate_r1cs_constraints(true);
        remainder_lt_C.generate_r1cs_constraints();
    }
};

class RequireAccuracyGadget : public GadgetT
{
public:
    libsnark::dual_variable_gadget<FieldT> value;
    VariableT original;
    Accuracy accuracy;

    RequireLeqGadget value_leq_original;

    VariableT originalXaccuracyN;
    VariableT valueXaccuracyD;

    RequireLeqGadget originalXaccuracyN_leq_valueXaccuracyD;

    // _accuracy.numerator / _accuracy.denominator <=  value / original
    // original * _accuracy.numerator <= value * _accuracy.denominator
    // We have to make sure there are no overflows and the value is <= the original value (so a user never spends more) so we also check:
    // - value <= original
    // - value < 2^maxNumBits
    RequireAccuracyGadget(
        ProtoboardT& pb,
        const VariableT& _value,
        const VariableT& _original,
        const Accuracy& _accuracy,
        unsigned int maxNumBits,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        value(pb, _value, maxNumBits, FMT(prefix, ".value")),
        original(_original),
        accuracy(_accuracy),

        value_leq_original(pb, value.packed, original, maxNumBits, FMT(prefix, ".value_lt_original")),

        originalXaccuracyN(make_variable(pb, FMT(prefix, ".originalXaccuracyN"))),
        valueXaccuracyD(make_variable(pb, FMT(prefix, ".valueXaccuracyD"))),

        originalXaccuracyN_leq_valueXaccuracyD(pb, originalXaccuracyN, valueXaccuracyD, maxNumBits + 32, FMT(prefix, ".originalXaccuracyN_leq_valueXaccuracyD"))
    {

    }

    void generate_r1cs_witness()
    {
        value.generate_r1cs_witness_from_packed();

        value_leq_original.generate_r1cs_witness();

        pb.val(originalXaccuracyN) = pb.val(original) * accuracy.numerator;
        pb.val(valueXaccuracyD) = pb.val(value.packed) * accuracy.denominator;
        originalXaccuracyN_leq_valueXaccuracyD.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        value.generate_r1cs_constraints(true);

        value_leq_original.generate_r1cs_constraints();

        pb.add_r1cs_constraint(ConstraintT(original, accuracy.numerator, originalXaccuracyN), FMT(annotation_prefix, ".original * accuracy.numerator == originalXaccuracyN"));
        pb.add_r1cs_constraint(ConstraintT(value.packed, accuracy.denominator, valueXaccuracyD), FMT(annotation_prefix, ".value * accuracy.denominator == valueXaccuracyD"));
        originalXaccuracyN_leq_valueXaccuracyD.generate_r1cs_constraints();
    }
};

class EdDSA_HashRAM_Poseidon_gadget : public GadgetT
{
public:
    Poseidon_gadget_T<6, 1, 6, 52, 5, 1> m_hash_RAM;      // hash_RAM = H(R, A, M)
    libsnark::dual_variable_gadget<FieldT> hash;

    EdDSA_HashRAM_Poseidon_gadget(
        ProtoboardT& in_pb,
        const Params& in_params,
        const VariablePointT& in_R,
        const VariablePointT& in_A,
        const VariableT& in_M,
        const std::string& annotation_prefix
    ) :
        GadgetT(in_pb, annotation_prefix),
        // Prefix the message with R and A.
        m_hash_RAM(in_pb, var_array({in_R.x, in_R.y, in_A.x, in_A.y, in_M}), FMT(annotation_prefix, ".hash_RAM")),
        hash(pb, NUM_BITS_MAX_VALUE, FMT(annotation_prefix, ".hash"))
    {

    }

    void generate_r1cs_constraints()
    {
        m_hash_RAM.generate_r1cs_constraints();
        hash.generate_r1cs_constraints(true);
    }

    void generate_r1cs_witness()
    {
        m_hash_RAM.generate_r1cs_witness();
        hash.bits.fill_with_bits_of_field_element(pb, pb.val(m_hash_RAM.result()));
        hash.generate_r1cs_witness_from_bits();
    }

    const VariableArrayT& result()
    {
        return hash.bits;
    }
};

class EdDSA_Poseidon: public GadgetT
{
public:
    PointValidator m_validator_R;                       // IsValid(R)
    fixed_base_mul m_lhs;                               // lhs = B*s
    EdDSA_HashRAM_Poseidon_gadget m_hash_RAM;           // hash_RAM = H(R,A,M)
    ScalarMult m_At;                                    // A*hash_RAM
    PointAdder m_rhs;                                   // rhs = R + (A*hash_RAM)

    EdDSA_Poseidon(
        ProtoboardT& in_pb,
        const Params& in_params,
        const EdwardsPoint& in_base,     // B
        const VariablePointT& in_A,      // A
        const VariablePointT& in_R,      // R
        const VariableArrayT& in_s,      // s
        const VariableT& in_msg,         // m
        const std::string& annotation_prefix
    ) :
        GadgetT(in_pb, annotation_prefix),
        // IsValid(R)
        m_validator_R(in_pb, in_params, in_R.x, in_R.y, FMT(this->annotation_prefix, ".validator_R")),

        // lhs = ScalarMult(B, s)
        m_lhs(in_pb, in_params, in_base.x, in_base.y, in_s, FMT(this->annotation_prefix, ".lhs")),

        // hash_RAM = H(R, A, M)
        m_hash_RAM(in_pb, in_params, in_R, in_A, in_msg, FMT(this->annotation_prefix, ".hash_RAM")),

        // At = ScalarMult(A,hash_RAM)
        m_At(in_pb, in_params, in_A.x, in_A.y, m_hash_RAM.result(), FMT(this->annotation_prefix, ".At = A * hash_RAM")),

        // rhs = PointAdd(R, At)
        m_rhs(in_pb, in_params, in_R.x, in_R.y, m_At.result_x(), m_At.result_y(), FMT(this->annotation_prefix, ".rhs"))
    {

    }

    void generate_r1cs_constraints()
    {
        m_validator_R.generate_r1cs_constraints();
        m_lhs.generate_r1cs_constraints();
        m_hash_RAM.generate_r1cs_constraints();
        m_At.generate_r1cs_constraints();
        m_rhs.generate_r1cs_constraints();

        // Verify the two points are equal
        this->pb.add_r1cs_constraint(
            ConstraintT(m_lhs.result_x(), FieldT::one(), m_rhs.result_x()),
            FMT(this->annotation_prefix, " lhs.x == rhs.x"));

        this->pb.add_r1cs_constraint(
            ConstraintT(m_lhs.result_y(), FieldT::one(), m_rhs.result_y()),
            FMT(this->annotation_prefix, " lhs.y == rhs.y"));
    }

    void generate_r1cs_witness()
    {
        m_validator_R.generate_r1cs_witness();
        m_lhs.generate_r1cs_witness();
        m_hash_RAM.generate_r1cs_witness();
        m_At.generate_r1cs_witness();
        m_rhs.generate_r1cs_witness();
    }
};

class SignatureVerifier : public GadgetT
{
public:

    const jubjub::VariablePointT sig_R;
    const VariableArrayT sig_s;
    const VariableT sig_m;
    EdDSA_Poseidon signatureVerifier;

    SignatureVerifier(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const jubjub::VariablePointT& publicKey,
        const VariableT& _message,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        sig_R(pb, FMT(prefix, ".R")),
        sig_s(make_var_array(pb, FieldT::size_in_bits(), FMT(prefix, ".s"))),
        sig_m(_message),
        signatureVerifier(pb, params, jubjub::EdwardsPoint(params.Gx, params.Gy), publicKey, sig_R, sig_s, sig_m, FMT(prefix, ".signatureVerifier"))
    {

    }

    const VariableArrayT& getHash()
    {
        return signatureVerifier.m_hash_RAM.result();
    }

    void generate_r1cs_witness(Signature sig)
    {
        pb.val(sig_R.x) = sig.R.x;
        pb.val(sig_R.y) = sig.R.y;
        sig_s.fill_with_bits_of_field_element(pb, sig.s);
        signatureVerifier.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        signatureVerifier.generate_r1cs_constraints();
    }
};

class Bitstream
{
public:

    std::vector<VariableArrayT> data;

    void add(const VariableArrayT& bits)
    {
        data.push_back(bits);
    }

    void add(const std::vector<VariableArrayT>& bits)
    {
        data.insert(data.end(), bits.begin(), bits.end());
    }
};

class PublicDataGadget : public GadgetT
{
public:

    const VariableT publicInput;
    std::vector<VariableArrayT> publicDataBits;

    std::unique_ptr<sha256_many> hasher;
    std::unique_ptr<libsnark::dual_variable_gadget<FieldT>> calculatedHash;

    PublicDataGadget(
        ProtoboardT& pb,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        publicInput(make_variable(pb, FMT(prefix, ".publicInput")))
    {
        pb.set_input_sizes(1);
    }

    void add(const VariableArrayT& bits)
    {
        publicDataBits.push_back(bits);
    }

    void add(const std::vector<VariableArrayT>& bits)
    {
        publicDataBits.insert(publicDataBits.end(), bits.begin(), bits.end());
    }

    void generate_r1cs_witness()
    {
        // Calculate the hash
        hasher->generate_r1cs_witness();

        // Calculate the expected public input
        calculatedHash->generate_r1cs_witness_from_bits();
        pb.val(publicInput) = pb.val(calculatedHash->packed);

        printBits("[ZKS]publicData: 0x", flattenReverse(publicDataBits).get_bits(pb), false);
        printBits("[ZKS]publicDataHash: 0x", hasher->result().bits.get_bits(pb));
        print(pb, "[ZKS]publicInput", calculatedHash->packed);
    }

    void generate_r1cs_constraints()
    {
        // Calculate the hash
        hasher.reset(new sha256_many(pb, flattenReverse(publicDataBits), ".hasher"));
        hasher->generate_r1cs_constraints();

        // Check that the hash matches the public input
        calculatedHash.reset(new libsnark::dual_variable_gadget<FieldT>(
            pb, reverse(subArray(hasher->result().bits, 0, FieldT::capacity())), ".packCalculatedHash")
        );
        calculatedHash->generate_r1cs_constraints(false);
        forceEqual(pb, calculatedHash->packed, publicInput, ".publicDataCheck");
    }
};

// Decodes a float with the specified encoding
class FloatGadget : public GadgetT
{
public:
    const Constants& constants;

    const FloatEncoding& floatEncoding;

    VariableArrayT f;

    std::vector<VariableT> values;
    std::vector<VariableT> baseMultipliers;
    std::vector<TernaryGadget> multipliers;

    VariableT _or;

    FloatGadget(
        ProtoboardT& pb,
        const Constants& _constants,
        const FloatEncoding& _floatEncoding,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        constants(_constants),
        floatEncoding(_floatEncoding),

        f(make_var_array(pb, floatEncoding.numBitsExponent + floatEncoding.numBitsMantissa, FMT(prefix, ".f")))
    {
        for (unsigned int i = 0; i < f.size(); i++)
        {
            values.emplace_back(make_variable(pb, FMT(prefix, ".FloatToUintGadgetVariable")));
        }

        for (unsigned int i = 0; i < floatEncoding.numBitsExponent; i++)
        {
            baseMultipliers.emplace_back(make_variable(pb, FMT(prefix, ".baseMultipliers")));
            multipliers.emplace_back(TernaryGadget(pb, f[floatEncoding.numBitsMantissa + i], baseMultipliers[i], constants.one, FMT(prefix, ".multipliers")));
        }
    }

    const VariableT& value() const
    {
        return values.back();
    }

    const VariableArrayT& bits() const
    {
        return f;
    }

    void generate_r1cs_witness(ethsnarks::FieldT floatValue)
    {
        f.fill_with_bits_of_field_element(pb, floatValue);

        // Decodes the mantissa
        for (unsigned int i = 0; i < floatEncoding.numBitsMantissa; i++)
        {
            unsigned j = floatEncoding.numBitsMantissa - 1 - i;
            pb.val(values[i]) = (i == 0) ? pb.val(f[j]) : (pb.val(values[i-1]) * 2 + pb.val(f[j]));
        }

        // Decodes the exponent and shifts the mantissa
        for (unsigned int i = floatEncoding.numBitsMantissa; i < f.size(); i++)
        {
            // Decode the exponent
            unsigned int j = i - floatEncoding.numBitsMantissa;
            pb.val(baseMultipliers[j]) = (j == 0) ? floatEncoding.exponentBase : pb.val(baseMultipliers[j - 1]) * pb.val(baseMultipliers[j - 1]);
            multipliers[j].generate_r1cs_witness();

            // Shift the value with the partial exponent
            pb.val(values[i]) = pb.val(values[i-1]) * pb.val(multipliers[j].result());
        }
    }

    void generate_r1cs_constraints()
    {
        // Make sure all the bits of the float or 0s and 1s
        for (unsigned int i = 0; i < f.size(); i++)
        {
            libsnark::generate_boolean_r1cs_constraint<ethsnarks::FieldT>(pb, f[i], FMT(annotation_prefix, ".bitness"));
        }

         // Decodes the mantissa
        for (unsigned int i = 0; i < floatEncoding.numBitsMantissa; i++)
        {
            unsigned j = floatEncoding.numBitsMantissa - 1 - i;
            if (i == 0)
            {
                pb.add_r1cs_constraint(ConstraintT(f[j], FieldT::one(), values[i]), FMT(annotation_prefix, (std::string(".value_") + std::to_string(i)).c_str()));
            }
            else
            {
                pb.add_r1cs_constraint(ConstraintT(values[i-1] * 2 + f[j], FieldT::one(), values[i]), FMT(annotation_prefix, (std::string(".value_") + std::to_string(i)).c_str()));
            }
        }

        // Decodes the exponent and shifts the mantissa
        for (unsigned int i = floatEncoding.numBitsMantissa; i < f.size(); i++)
        {
            // Decode the exponent
            unsigned int j = i - floatEncoding.numBitsMantissa;
            if (j == 0)
            {
                pb.add_r1cs_constraint(ConstraintT(floatEncoding.exponentBase, FieldT::one(), baseMultipliers[j]), ".baseMultipliers");
            }
            else
            {
                pb.add_r1cs_constraint(ConstraintT(baseMultipliers[j - 1], baseMultipliers[j - 1], baseMultipliers[j]), ".baseMultipliers");
            }
            multipliers[j].generate_r1cs_constraints();

            // Shift the value with the partial exponent
            pb.add_r1cs_constraint(ConstraintT(values[i - 1], multipliers[j].result(), values[i]), ".valuesExp");
        }
    }
};

 // Hashes the labels in different stages so we only need a single Poseidon permutation.
 // Currently hashes 64 labels + the hash of the previous stage in a single stage.
 // There is no particular reason 64 labels are hashed together at once
 // (and depending on our understanding of Poseidon this could still change).
 // This doesn't need to be very secure, the only requirement is that it shouldn't be completely
 // trivial to find a different set of labels with the same hash.
class LabelHasher : public GadgetT
{
public:
    static const unsigned numInputs = 64;
    std::vector<Poseidon_gadget_T<numInputs + 2, 1, 6, 56, numInputs + 1, 1>> stageHashers;

    std::unique_ptr<libsnark::dual_variable_gadget<FieldT>> hash;

    LabelHasher(
        ProtoboardT& pb,
        const Constants& constants,
        const std::vector<VariableT>& labels,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix)
    {
        unsigned int numStages = (labels.size() + numInputs - 1) / numInputs;
        for (unsigned int i = 0; i < numStages; i++)
        {
            std::vector<VariableT> inputs;
            inputs.push_back(i == 0 ? constants.zero : stageHashers.back().result());
            for (unsigned int j = 0; j < numInputs; j++)
            {
                const unsigned int labelIdx = i * numInputs + j;
                inputs.push_back((labelIdx < labels.size()) ? labels[labelIdx] : constants.zero);
            }
            stageHashers.emplace_back(pb, var_array(inputs), FMT(this->annotation_prefix, ".stage1"));
        }

        hash.reset(new libsnark::dual_variable_gadget<FieldT>(
            pb, stageHashers.back().result(), 256, ".labelHashToBits")
        );
    }

    const std::unique_ptr<libsnark::dual_variable_gadget<FieldT>>& result() const
    {
        return hash;
    }

    void generate_r1cs_witness()
    {
        for (auto hasher : stageHashers)
        {
            hasher.generate_r1cs_witness();
        }
        hash->generate_r1cs_witness_from_packed();
        print(pb, "[ZKS]labelHash", hash->packed);
    }

    void generate_r1cs_constraints()
    {
        for (auto hasher : stageHashers)
        {
            hasher.generate_r1cs_constraints();
        }
        hash->generate_r1cs_constraints(true);
    }
};


}

#endif
