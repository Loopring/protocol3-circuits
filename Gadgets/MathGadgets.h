#ifndef _MATHGADGETS_H_
#define _MATHGADGETS_H_

#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "jubjub/point.hpp"
#include "jubjub/eddsa.hpp"
#include "gadgets/subadd.hpp"

using namespace ethsnarks;

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

    const VariableArrayT padding_0;
    const VariableArrayT padding_00;
    const VariableArrayT accountPadding;

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
        padding_0(1, zero),
        padding_00(2, zero),
        accountPadding(4, zero)
    {
        assert(NUM_BITS_MAX_VALUE == FieldT::capacity());
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

class SubGadget : public GadgetT
{
public:

    subadd_gadget subadd;

    SubGadget(
        ProtoboardT& pb,
        const VariableT& _value,
        const VariableT& _sub,
        const size_t n,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        subadd(pb, n, _value, _value, _sub, FMT(prefix, ".subadd"))
    {

    }

    const VariableT& result() const
    {
        return subadd.X;
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

class AddGadget : public GadgetT
{
public:

    subadd_gadget subadd;

    AddGadget(
        ProtoboardT& pb,
        const VariableT& _value,
        const VariableT& _add,
        const size_t n,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        subadd(pb, n, _value, _add, _add, FMT(prefix, ".subadd"))
    {

    }

    const VariableT& result() const
    {
        return subadd.Y;
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

    void generate_r1cs_constraints(bool enforeBitness = true)
    {
        if (enforeBitness)
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
        const std::vector<VariableT> _inputs,
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
    VariableT A;
    VariableT B;
    VariableT _or;

    OrGadget(
        ProtoboardT& pb,
        const VariableT& _A,
        const VariableT& _B,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        A(_A),
        B(_B),

        _or(make_variable(pb, FMT(prefix, "._or")))
    {

    }

    const VariableT& result() const
    {
        return _or;
    }

    void generate_r1cs_witness()
    {
        pb.val(_or) = FieldT::one() - (FieldT::one() - pb.val(A)) * (FieldT::one() - pb.val(B));
    }

    void generate_r1cs_constraints()
    {
        pb.add_r1cs_constraint(ConstraintT(FieldT::one() - A, FieldT::one() - B, FieldT::one() - _or), FMT(annotation_prefix, ".A || B == _or"));
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

class XorGadget : public GadgetT
{
public:
    VariableT A;
    VariableT B;
    VariableT C;

    XorGadget(
        ProtoboardT& pb,
        const VariableT& _A,
        const VariableT& _B,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        A(_A),
        B(_B),

        C(make_variable(pb, FMT(prefix, ".C")))
    {

    }

    const VariableT& result() const
    {
        return C;
    }

    void generate_r1cs_witness()
    {
        pb.val(C) = pb.val(A) + pb.val(B) - ((pb.val(A) == FieldT::one() && pb.val(B) == FieldT::one()) ? 2 : 0);
    }

    void generate_r1cs_constraints()
    {
        pb.add_r1cs_constraint(ConstraintT(2 * A, B, A + B - C), FMT(annotation_prefix, ".A ^ B == C"));
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
        // printBits("A: ", A.get_bits(pb));
        // printBits("B: ", B.get_bits(pb));
        // printBits("C: ", C.get_bits(pb));
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

    const VariableT& eq() const
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

class ForceEqualGadget : public GadgetT
{
public:
    VariableT A;
    VariableT B;

    ForceEqualGadget(
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

class ForceZeroAorBGadget : public GadgetT
{
public:
    VariableT A;
    VariableT B;

    ForceZeroAorBGadget(
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

class ForceNotZeroGadget : public GadgetT
{
public:
    VariableT A;
    VariableT A_inv;

    ForceNotZeroGadget(
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

class ForceNotEqualGadget : public GadgetT
{
public:
    VariableT A;
    VariableT B;

    VariableT diff;
    ForceNotZeroGadget notZero;

    ForceNotEqualGadget(
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

class ForceLeqGadget : public GadgetT
{
public:
    LeqGadget leqGadget;

    ForceLeqGadget(
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

class ForceLtGadget : public GadgetT
{
public:
    LeqGadget leqGadget;

    ForceLtGadget(
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
        pb.add_r1cs_constraint(ConstraintT(leqGadget.lt(), FieldT::one(), FieldT::one()), FMT(annotation_prefix, ".leq == 1"));
    }
};

class PercentageGadget : public GadgetT
{
public:
    libsnark::dual_variable_gadget<FieldT> value;
    LeqGadget leq100Gadget;

    PercentageGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        value(pb, NUM_BITS_PERCENTAGE, FMT(prefix, ".value")),
        leq100Gadget(pb, value.packed, constants._100, NUM_BITS_PERCENTAGE, FMT(prefix, ".percentage <= 100"))
    {

    }

    void generate_r1cs_witness(ethsnarks::FieldT percentage)
    {
        value.bits.fill_with_bits_of_field_element(pb, percentage);
        value.generate_r1cs_witness_from_bits();
        leq100Gadget.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        value.generate_r1cs_constraints(true);
        leq100Gadget.generate_r1cs_constraints();
    }
};

class MulDivGadget : public GadgetT
{
public:
    const VariableT A;
    const VariableT B;
    const VariableT C;
    const VariableT D;

    ForceNotZeroGadget C_notZero;

    const VariableT X;
    const VariableT remainder;

    ForceLtGadget remainder_lt_C;

    // (A * B) / C = D
    MulDivGadget(
        ProtoboardT& pb,
        const Constants& constants,
        const VariableT& _A,
        const VariableT& _B,
        const VariableT& _C,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        A(_A),
        B(_B),
        C(_C),

        C_notZero(pb, C, FMT(prefix, ".C_notZero")),

        D(make_variable(pb, FMT(prefix, ".D"))),

        X(make_variable(pb, FMT(prefix, ".X"))),
        remainder(make_variable(pb, FMT(prefix, ".remainder"))),

        remainder_lt_C(pb, remainder, C, NUM_BITS_MAX_VALUE, FMT(prefix, ".remainder <(=) C"))
    {

    }

    const VariableT& result() const
    {
        return D;
    }

    const VariableT& getRemainder() const
    {
        return remainder;
    }

    const VariableT& multiplied() const
    {
        return X;
    }

    void generate_r1cs_witness()
    {
        C_notZero.generate_r1cs_witness();

        pb.val(X) = pb.val(A) * pb.val(B);
        pb.val(D) = ethsnarks::FieldT((toBigInt(pb.val(X)) / toBigInt(pb.val(C))).to_string().c_str());
        pb.val(remainder) = pb.val(X) - (pb.val(C) * pb.val(D));

        remainder_lt_C.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        C_notZero.generate_r1cs_constraints();

        pb.add_r1cs_constraint(ConstraintT(A, B, X), FMT(annotation_prefix, ".A * B == X"));
        pb.add_r1cs_constraint(ConstraintT(C, D, X - remainder), FMT(annotation_prefix, ".D * C == X - remainder"));

        remainder_lt_C.generate_r1cs_constraints();
    }
};

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
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        mulDiv(pb, constants, _value, _numerator, _denominator, FMT(prefix, ".multiplied")),
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

class EnsureAccuracyGadget : public GadgetT
{
public:
    VariableT value;
    VariableT original;
    Accuracy accuracy;

    ForceLeqGadget value_lt_original;

    VariableT difference;
    VariableT originalXaccuracyN;
    VariableT differenceXaccuracyD;

    ForceLeqGadget originalXaccuracyN_lt_differenceXaccuracyD;

    EnsureAccuracyGadget(
        ProtoboardT& pb,
        const VariableT& _value,
        const VariableT& _original,
        const Accuracy& _accuracy,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),

        value(_value),
        original(_original),
        accuracy(_accuracy),

        value_lt_original(pb, value, original, NUM_BITS_MAX_VALUE, FMT(prefix, ".value_lt_original")),

        difference(make_variable(pb, FMT(prefix, ".difference"))),
        originalXaccuracyN(make_variable(pb, FMT(prefix, ".originalXaccuracyN"))),
        differenceXaccuracyD(make_variable(pb, FMT(prefix, ".differenceXaccuracyD"))),

        originalXaccuracyN_lt_differenceXaccuracyD(pb, originalXaccuracyN, differenceXaccuracyD, NUM_BITS_MAX_VALUE, FMT(prefix, ".originalXaccuracyN_lt_differenceXaccuracyD"))
    {

    }

    void generate_r1cs_witness()
    {
        value_lt_original.generate_r1cs_witness();
        pb.val(difference) = pb.val(original) - pb.val(value);
        pb.val(originalXaccuracyN) = pb.val(original) * accuracy.numerator;
        pb.val(differenceXaccuracyD) = pb.val(value) * accuracy.denominator;
        originalXaccuracyN_lt_differenceXaccuracyD.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        value_lt_original.generate_r1cs_constraints();
        pb.add_r1cs_constraint(ConstraintT(value + difference, FieldT::one(), original), FMT(annotation_prefix, ".value + difference == original"));
        pb.add_r1cs_constraint(ConstraintT(original, accuracy.numerator, originalXaccuracyN), FMT(annotation_prefix, ".original * accuracy.numerator == originalXaccuracyN"));
        pb.add_r1cs_constraint(ConstraintT(value, accuracy.denominator, differenceXaccuracyD), FMT(annotation_prefix, ".value * accuracy.denominator == differenceXaccuracyD"));
        originalXaccuracyN_lt_differenceXaccuracyD.generate_r1cs_constraints();
    }
};

class SignatureVerifier : public GadgetT
{
public:

    const jubjub::VariablePointT sig_R;
    const VariableArrayT sig_s;
    const VariableArrayT sig_m;
    jubjub::PureEdDSA signatureVerifier;

    SignatureVerifier(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const jubjub::VariablePointT& publicKey,
        const VariableArrayT& _message,
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

    libsnark::dual_variable_gadget<FieldT>& inputHash;
    std::vector<VariableArrayT> publicDataBits;

    sha256_many* hasher;

    PublicDataGadget(
        ProtoboardT& pb,
        libsnark::dual_variable_gadget<FieldT>& _inputHash,
        const std::string& prefix
    ) :
        GadgetT(pb, prefix),
        inputHash(_inputHash)
    {
        this->hasher = nullptr;
    }

    ~PublicDataGadget()
    {
        if (hasher)
        {
            delete hasher;
        }
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
        hasher->generate_r1cs_witness();

         // Get the calculated hash in bits
        auto full_output_bits = hasher->result().get_digest();
        BigInt publicDataHashDec = 0;
        for (unsigned int i = 0; i < full_output_bits.size(); i++)
        {
            publicDataHashDec = publicDataHashDec * 2 + (full_output_bits[i] ? 1 : 0);
        }
        libff::bigint<libff::alt_bn128_r_limbs> bn = libff::bigint<libff::alt_bn128_r_limbs>(publicDataHashDec.to_string().c_str());
        printBits("[ZKS]publicData: 0x", flattenReverse(publicDataBits).get_bits(pb), false);
        printBits("[ZKS]publicDataHash: 0x", flattenReverse({hasher->result().bits}).get_bits(pb), true);

        // Store the input hash
        for (unsigned int i = 0; i < 256; i++)
        {
            pb.val(inputHash.bits[i]) = bn.test_bit(i);
        }
        inputHash.generate_r1cs_witness_from_bits();
    }

    void generate_r1cs_constraints()
    {
        hasher = new sha256_many(pb, flattenReverse(publicDataBits), ".hasher");
        hasher->generate_r1cs_constraints();

        // Check that the hash matches the public input
        for (unsigned int i = 0; i < 256; i++)
        {
            pb.add_r1cs_constraint(ConstraintT(hasher->result().bits[255-i], 1, inputHash.bits[i]), "publicData.check()");
        }
    }
};

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

        for (unsigned int i = 0; i < floatEncoding.numBitsMantissa; i++)
        {
            unsigned j = floatEncoding.numBitsMantissa - 1 - i;
            pb.val(values[i]) = (i == 0) ? pb.val(f[j]) : (pb.val(values[i-1]) * 2 + pb.val(f[j]));
        }

        for (unsigned int i = floatEncoding.numBitsMantissa; i < f.size(); i++)
        {
            unsigned int j = i - floatEncoding.numBitsMantissa;
            pb.val(baseMultipliers[j]) = (j == 0) ? floatEncoding.exponentBase : pb.val(baseMultipliers[j - 1]) * pb.val(baseMultipliers[j - 1]);
            multipliers[j].generate_r1cs_witness();
            pb.val(values[i]) = pb.val(values[i-1]) * pb.val(multipliers[j].result());
        }
    }

    void generate_r1cs_constraints()
    {
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

        for (unsigned int i = floatEncoding.numBitsMantissa; i < f.size(); i++)
        {
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
            pb.add_r1cs_constraint(ConstraintT(values[i - 1], multipliers[j].result(), values[i]), ".valuesExp");
        }
    }
};

}

#endif
