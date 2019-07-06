#ifndef _MERKLE_TREE_H_
#define _MERKLE_TREE_H_

#include "ethsnarks.hpp"
#include "gadgets/poseidon.hpp"
#include "MathGadgets.h"

namespace Loopring {

class merkle_path_selector_4 : public GadgetT
{
public:
    OrGadget bit0_or_bit1;
    AndGadget bit0_and_bit1;

    TernaryGadget child0;
    TernaryGadget child1p;
    TernaryGadget child1;
    TernaryGadget child2p;
    TernaryGadget child2;
    TernaryGadget child3;

    VariableT m_input;
    const std::vector<VariableT> m_sideNodes;
    VariableT m_bit0;
    VariableT m_bit1;

    // 00   x  y0  y1 y2
    // 01   y0 x   y1 y2
    // 10   y0 y1   x y2
    // 11   y0 y1  y2  x
    merkle_path_selector_4(
        ProtoboardT &pb,
        const VariableT& input,
        std::vector<VariableT> sideNodes,
        const VariableT& bit0,
        const VariableT& bit1,
        const std::string &prefix
    ) :
        GadgetT(pb, prefix),

        m_input(input),
        m_sideNodes(sideNodes),
        m_bit0(bit0),
        m_bit1(bit1),

        bit0_or_bit1(pb, bit0, bit1, FMT(prefix, ".bit0_or_bit1")),
        bit0_and_bit1(pb, {bit0, bit1}, FMT(prefix, ".bit0_and_bit1")),

        child0(pb, bit0_or_bit1.result(), sideNodes[0], input, FMT(prefix, ".child0")),
        child1p(pb, bit0, input, sideNodes[0], FMT(prefix, ".child1p")),
        child1(pb, bit1, sideNodes[1], child1p.result(), FMT(prefix, ".child1p")),
        child2p(pb, bit0, sideNodes[2], input, FMT(prefix, ".child2p")),
        child2(pb, bit1, child2p.result(), sideNodes[1], FMT(prefix, ".child2")),
        child3(pb, bit0_and_bit1.result(), input, sideNodes[2], FMT(prefix, ".child3"))
    {
        assert(sideNodes.size() == 3);
    }

    void generate_r1cs_constraints()
    {
        bit0_or_bit1.generate_r1cs_constraints();
        bit0_and_bit1.generate_r1cs_constraints();

        child0.generate_r1cs_constraints(false);
        child1p.generate_r1cs_constraints(false);
        child1.generate_r1cs_constraints(false);
        child2p.generate_r1cs_constraints(false);
        child2.generate_r1cs_constraints(false);
        child3.generate_r1cs_constraints(false);
    }

    void generate_r1cs_witness()
    {
        bit0_or_bit1.generate_r1cs_witness();
        bit0_and_bit1.generate_r1cs_witness();

        child0.generate_r1cs_witness();
        child1p.generate_r1cs_witness();
        child1.generate_r1cs_witness();
        child2p.generate_r1cs_witness();
        child2.generate_r1cs_witness();
        child3.generate_r1cs_witness();
    }

    std::vector<VariableT> getChildren() const
    {
        return {child0.result(), child1.result(), child2.result(), child3.result()};
    }
};

template<typename HashT>
class markle_path_compute_4 : public GadgetT
{
public:
    const size_t m_depth;
    const VariableArrayT m_address_bits;
    const VariableT m_leaf;
    const VariableArrayT m_path;

    std::vector<merkle_path_selector_4> m_selectors;
    std::vector<HashT> m_hashers;

    markle_path_compute_4(
        ProtoboardT &in_pb,
        const size_t in_depth,
        const VariableArrayT& in_address_bits,
        const VariableT in_leaf,
        const VariableArrayT& in_path,
        const std::string &in_annotation_prefix
    ) :
        GadgetT(in_pb, in_annotation_prefix),
        m_depth(in_depth),
        m_address_bits(in_address_bits),
        m_leaf(in_leaf),
        m_path(in_path)
    {
        assert( in_depth > 0 );
        assert( in_address_bits.size() == in_depth * 2 );

        for( size_t i = 0; i < m_depth; i++ )
        {
            m_selectors.push_back(
                merkle_path_selector_4(
                    in_pb, (i == 0) ? in_leaf : m_hashers[i-1].result(),
                    {in_path[i*3 + 0], in_path[i*3 + 1], in_path[i*3 + 2]},
                    in_address_bits[i*2 + 0], in_address_bits[i*2 + 1],
                    FMT(this->annotation_prefix, ".selector[%zu]", i)));

            auto t = HashT(
                    in_pb,
                    m_selectors[i].getChildren(),
                    FMT(this->annotation_prefix, ".hasher[%zu]", i));
            m_hashers.push_back(t);
        }
    }

    const VariableT result() const
    {
        assert( m_hashers.size() > 0 );
        return m_hashers.back().result();
    }

    void generate_r1cs_constraints()
    {
        for (size_t i = 0; i < m_hashers.size(); i++)
        {
            m_selectors[i].generate_r1cs_constraints();
            m_hashers[i].generate_r1cs_constraints();
        }
    }

    void generate_r1cs_witness()
    {
        for (size_t i = 0; i < m_hashers.size(); i++)
        {
            m_selectors[i].generate_r1cs_witness();
            m_hashers[i].generate_r1cs_witness();
        }
    }
};


/**
* Merkle path authenticator, verifies computed root matches expected result
*/
template<typename HashT>
class merkle_path_authenticator_4 : public markle_path_compute_4<HashT>
{
public:
    const VariableT m_expected_root;

    merkle_path_authenticator_4(
        ProtoboardT &in_pb,
        const size_t in_depth,
        const VariableArrayT in_address_bits,
        const VariableT in_leaf,
        const VariableT in_expected_root,
        const VariableArrayT in_path,
        const std::string &in_annotation_prefix
    ) :
        markle_path_compute_4<HashT>::markle_path_compute_4(in_pb, in_depth, in_address_bits, in_leaf, in_path, in_annotation_prefix),
        m_expected_root(in_expected_root)
    { }

    bool is_valid() const
    {
        return this->pb.val(this->result()) == this->pb.val(m_expected_root);
    }

    void generate_r1cs_constraints()
    {
        markle_path_compute_4<HashT>::generate_r1cs_constraints();

        // Ensure root matches calculated path hash
        this->pb.add_r1cs_constraint(
            ConstraintT(this->result(), 1, m_expected_root),
            FMT(this->annotation_prefix, ".expected_root authenticator"));
    }
};

template<unsigned param_t, unsigned param_c, unsigned param_F, unsigned param_P, unsigned nInputs, unsigned nOutputs>
class Poseidon: public Poseidon_gadget_T<param_t, param_c, param_F, param_P, nInputs, nOutputs>
{
public:

    const VariableT res;

    Poseidon(
		ProtoboardT &in_pb,
		const std::vector<VariableT>& in_messages,
		const std::string &prefix
	) :
		Poseidon_gadget_T<param_t, param_c, param_F, param_P, nInputs, nOutputs>(in_pb, VariableArrayT(in_messages.begin(), in_messages.end()), prefix),
        res(make_variable(this->pb, FMT(prefix, ".res")))
	{

	}

    void generate_r1cs_witness() const
    {
        Poseidon_gadget_T<param_t, param_c, param_F, param_P, nInputs, nOutputs>::generate_r1cs_witness();
        this->pb.val(res) = lc_vals(this->pb, this->outputs())[0];
    }

    void generate_r1cs_constraints()
    {
        Poseidon_gadget_T<param_t, param_c, param_F, param_P, nInputs, nOutputs>::generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(ConstraintT(res, FieldT::one(), this->outputs()[0]), FMT(this->annotation_prefix, ".res == output"));
    }

	const VariableT& result() const
    {
        return res;
	}
};

using HashMerkleTree = Poseidon<5, 1, 8, 57, 4, 1>;
using HashAccountLeaf = Poseidon<5, 1, 8, 57, 4, 1>;
using HashBalanceLeaf = Poseidon<3, 1, 8, 57, 2, 1>;
using HashTradingHistoryLeaf = Poseidon<4, 1, 8, 57, 3, 1>;

// Optimal parameters:
//using HashMerkleTree = Poseidon<5, 1, 6, 52, 4, 1>;
//using HashAccountLeaf = Poseidon<5, 1, 6, 52, 4, 1>;
//using HashBalanceLeaf = Poseidon<3, 1, 6, 51, 2, 1>;
//using HashTradingHistoryLeaf = Poseidon<4, 1, 6, 52, 3, 1>;

typedef Loopring::merkle_path_authenticator_4<HashMerkleTree> MerklePathCheckT;
typedef Loopring::markle_path_compute_4<HashMerkleTree> MerklePathT;

}

#endif
