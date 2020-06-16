#ifndef _DEPOSITCIRCUIT_H_
#define _DEPOSITCIRCUIT_H_

#include "Circuit.h"
#include "../Utils/Constants.h"
#include "../Utils/Data.h"

#include "ethsnarks.hpp"
#include "utils.hpp"

using namespace ethsnarks;

namespace Loopring
{

class DepositCircuit : public BaseTransactionCircuit
{
public:

    // Inputs
    DualVariableGadget owner;
    DualVariableGadget accountID;
    DualVariableGadget tokenID;
    DualVariableGadget amount;

    OwnerValidGadget ownerValid;

    UnsafeAddGadget numConditionalTransactionsAfter;

    // Calculate the new balance
    AddGadget balance_after;

    DepositCircuit(
        ProtoboardT& pb,
        const TransactionState& state,
        const std::string& prefix
    ) :
        BaseTransactionCircuit(pb, state, prefix),

        // Inputs
        owner(pb, NUM_BITS_OWNER, FMT(prefix, ".owner")),
        accountID(pb, NUM_BITS_ACCOUNT, FMT(prefix, ".accountID")),
        tokenID(pb, NUM_BITS_TOKEN, FMT(prefix, ".tokenID")),
        amount(pb, NUM_BITS_AMOUNT, FMT(prefix, ".amount")),

        ownerValid(pb, state.constants, state.accountA.account.owner, owner.packed, FMT(prefix, ".ownerValid")),

        numConditionalTransactionsAfter(pb, state.numConditionalTransactions, state.constants.one, ".numConditionalTransactionsAfter"),

        // Calculate the new balance
        balance_after(pb, state.accountA.balanceS.balance, amount.packed, NUM_BITS_AMOUNT, FMT(prefix, ".balance_after"))
    {
        setArrayOutput(accountA_Address, accountID.bits);
        setOutput(accountA_Owner, owner.packed);
        setArrayOutput(balanceA_S_Address, tokenID.bits);
        setOutput(balanceA_S_Balance, balance_after.result());

        setOutput(signatureRequired_A, state.constants.zero);
        setOutput(signatureRequired_B, state.constants.zero);

        setOutput(misc_NumConditionalTransactions, numConditionalTransactionsAfter.result());
    }

    void generate_r1cs_witness(const Deposit& deposit)
    {
        // Inputs
        owner.generate_r1cs_witness(pb, deposit.owner);
        accountID.generate_r1cs_witness(pb, deposit.accountID);
        tokenID.generate_r1cs_witness(pb, deposit.tokenID);
        amount.generate_r1cs_witness(pb, deposit.amount);

        ownerValid.generate_r1cs_witness();

        numConditionalTransactionsAfter.generate_r1cs_witness();

        // Calculate the new balance
        balance_after.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        // Inputs
        owner.generate_r1cs_constraints(true);
        accountID.generate_r1cs_constraints(true);
        tokenID.generate_r1cs_constraints(true);
        amount.generate_r1cs_constraints(true);

        ownerValid.generate_r1cs_constraints();

        numConditionalTransactionsAfter.generate_r1cs_constraints();

        // Calculate the new balance
        balance_after.generate_r1cs_constraints();
    }

    const VariableArrayT getPublicData() const
    {
        return flattenReverse({
            owner.bits,
            accountID.bits,
            VariableArrayT(4, state.constants.zero), tokenID.bits,
            amount.bits
        });
    }
};

}

#endif
