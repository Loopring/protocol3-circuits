
#include "ThirdParty/BigInt.hpp"
#include "Utils/Data.h"
#include "Circuits/RingSettlementCircuit.h"
#include "Circuits/DepositCircuit.h"
#include "Circuits/OnchainWithdrawalCircuit.h"
#include "Circuits/OffchainWithdrawalCircuit.h"
#include "Circuits/OrderCancellationCircuit.h"
#include "Circuits/InternalTransferCircuit.h"

#include "ThirdParty/json.hpp"
#include "ethsnarks.hpp"
#include "stubs.hpp"
#include <fstream>
#include <chrono>

#ifdef MULTICORE
#include <omp.h>
#endif

using json = nlohmann::json;

enum class Mode
{
    CreateKeys = 0,
    Validate,
    Prove,
    ExportCircuit,
    ExportWitness,
    CreatePk
};

static inline auto now() -> decltype(std::chrono::high_resolution_clock::now()) {
    return std::chrono::high_resolution_clock::now();
}

template<typename T>
void
print_time(T &t1, const char *str) {
    auto t2 = std::chrono::high_resolution_clock::now();
    auto tim = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    printf("%s: %lld ms\n", str, tim);
    t1 = t2;
}

timespec diff(timespec start, timespec end)
{
    timespec temp;
    if ((end.tv_nsec-start.tv_nsec) < 0)
    {
        temp.tv_sec = end.tv_sec - start.tv_sec - 1;
        temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
    }
    else
    {
        temp.tv_sec = end.tv_sec - start.tv_sec;
        temp.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
    return temp;
}

bool fileExists(const char *fileName)
{
    std::ifstream infile(fileName);
    return infile.good();
}

bool generateKeyPair(ethsnarks::ProtoboardT& pb, std::string& baseFilename)
{
    std::string provingKeyFilename = baseFilename + "_pk.raw";
    std::string verificationKeyFilename = baseFilename + "_vk.json";
#ifdef GPU_PROVE
    std::string paramsFilename = baseFilename + "_params.raw";
#endif
    if (fileExists(provingKeyFilename.c_str()) && fileExists(verificationKeyFilename.c_str())
#ifdef GPU_PROVE
        && fileExists(paramsFilename.c_str())
#endif
    )
    {
        return true;
    }
#ifdef GPU_PROVE
    std::cout << "Generating keys and params..." << std::endl;
    int result = stub_genkeys_params_from_pb(pb, provingKeyFilename.c_str(), verificationKeyFilename.c_str(), paramsFilename.c_str());
#else
    std::cout << "Generating keys..." << std::endl;
    int result = stub_genkeys_from_pb(pb, provingKeyFilename.c_str(), verificationKeyFilename.c_str());
#endif
    return (result == 0);
}

bool generateProof(ethsnarks::ProtoboardT& pb, const char *provingKeyFilename, const char* proofFilename)
{
    std::cout << "Generating proof..." << std::endl;
    timespec time1, time2;
    clock_gettime(CLOCK_MONOTONIC, &time1);

    auto begin = now();
    std::string jProof = stub_prove_from_pb(pb, provingKeyFilename);
    print_time(begin, "Generated proof");

    clock_gettime(CLOCK_MONOTONIC, &time2);
    timespec duration = diff(time1,time2);
    std::cout << "Generated proof in " << duration.tv_sec << " seconds (" << pb.num_constraints() / (duration.tv_sec + 1) << " constraints/second)" << std::endl;

    std::ofstream fproof(proofFilename);
    if (!fproof.is_open())
    {
        std::cerr << "Cannot create proof file: " << proofFilename << std::endl;
        return 1;
    }
    fproof << jProof;
    fproof.close();

    return true;
}

bool trade(Mode mode, bool onchainDataAvailability, unsigned int numRings,
           const json& input, ethsnarks::ProtoboardT& outPb)
{
    // Build the circuit
    Loopring::RingSettlementCircuit circuit(outPb, "circuit");
    circuit.generate_r1cs_constraints(onchainDataAvailability, numRings);
    circuit.printInfo();

    if (mode == Mode::Validate || mode == Mode::Prove)
    {
        json jRingSettlements = input["ringSettlements"];
        if (jRingSettlements.size() != numRings)
        {
            std::cerr << "Invalid number of rings in input file: " << jRingSettlements.size() << std::endl;
            return false;
        }

        Loopring::RingSettlementBlock block = input.get<Loopring::RingSettlementBlock>();

        // Generate witness values for the given input values
        if (!circuit.generateWitness(block))
        {
            std::cerr << "Could not generate witness!" << std::endl;
            return false;
        }
    }
    return true;
}

bool deposit(Mode mode, unsigned int numDeposits, const json& input, ethsnarks::ProtoboardT& outPb)
{
    // Build the circuit
    Loopring::DepositCircuit circuit(outPb, "circuit");
    circuit.generate_r1cs_constraints(numDeposits);
    circuit.printInfo();

    if (mode == Mode::Validate || mode == Mode::Prove)
    {
        json jDeposits = input["deposits"];
        if (jDeposits.size() != numDeposits)
        {
            std::cerr << "Invalid number of deposits in input file: " << jDeposits.size() << std::endl;
            return false;
        }

        Loopring::DepositBlock block = input.get<Loopring::DepositBlock>();

        // Generate witness values for the given input values
        if (!circuit.generateWitness(block))
        {
            std::cerr << "Could not generate witness!" << std::endl;
            return false;
        }
    }
    return true;
}

bool onchainWithdraw(Mode mode, unsigned int numWithdrawals, const json& input, ethsnarks::ProtoboardT& outPb)
{
    // Build the circuit
    Loopring::OnchainWithdrawalCircuit circuit(outPb, "circuit");
    circuit.generate_r1cs_constraints(numWithdrawals);
    circuit.printInfo();

    if (mode == Mode::Validate || mode == Mode::Prove)
    {
        json jWithdrawals = input["withdrawals"];
        if (jWithdrawals.size() != numWithdrawals)
        {
            std::cerr << "Invalid number of withdrawals in input file: " << jWithdrawals.size() << std::endl;
            return false;
        }

        Loopring::OnchainWithdrawalBlock block = input.get<Loopring::OnchainWithdrawalBlock>();

        // Generate witness values for the given input values
        if (!circuit.generateWitness(block))
        {
            std::cerr << "Could not generate witness!" << std::endl;
            return false;
        }
    }
    return true;
}

bool offchainWithdraw(Mode mode, bool onchainDataAvailability, unsigned int numWithdrawals, const json& input, ethsnarks::ProtoboardT& outPb)
{
    // Build the circuit
    Loopring::OffchainWithdrawalCircuit circuit(outPb, "circuit");
    circuit.generate_r1cs_constraints(onchainDataAvailability, numWithdrawals);
    circuit.printInfo();

    if (mode == Mode::Validate || mode == Mode::Prove)
    {
        json jWithdrawals = input["withdrawals"];
        if (jWithdrawals.size() != numWithdrawals)
        {
            std::cerr << "Invalid number of withdrawals in input file: " << jWithdrawals.size() << std::endl;
            return false;
        }

        Loopring::OffchainWithdrawalBlock block = input.get<Loopring::OffchainWithdrawalBlock>();

        // Generate witness values for the given input values
        if (!circuit.generateWitness(block))
        {
            std::cerr << "Could not generate witness!" << std::endl;
            return false;
        }
    }
    return true;
}

bool cancel(Mode mode, bool onchainDataAvailability, unsigned int numCancels, const json& input, ethsnarks::ProtoboardT& outPb)
{
    // Build the circuit
    Loopring::OrderCancellationCircuit circuit(outPb, "circuit");
    circuit.generate_r1cs_constraints(onchainDataAvailability, numCancels);
    circuit.printInfo();

    if (mode == Mode::Validate || mode == Mode::Prove)
    {
        json jCancels = input["cancels"];
        if (jCancels.size() != numCancels)
        {
            std::cerr << "Invalid number of cancels in input file: " << jCancels.size() << std::endl;
            return false;
        }

        Loopring::OrderCancellationBlock block = input.get<Loopring::OrderCancellationBlock>();

        // Generate witness values for the given input values
        if (!circuit.generateWitness(block))
        {
            std::cerr << "Could not generate witness!" << std::endl;
            return false;
        }
    }
    return true;
}

bool internalTransfer(Mode mode, bool onchainDataAvailability, unsigned int numTransfers, const json& input, ethsnarks::ProtoboardT& outPb)
{
    // Build the circuit
    Loopring::InternalTransferCircuit circuit(outPb, "circuit");
    circuit.generate_r1cs_constraints(onchainDataAvailability, numTransfers);
    circuit.printInfo();

    if (mode == Mode::Validate || mode == Mode::Prove)
    {
        json jTransfers = input["transfers"];
        if (jTransfers.size() != numTransfers)
        {
            std::cerr << "Invalid number of transfers in input file: " << jTransfers.size() << std::endl;
            return false;
        }

        Loopring::InternalTransferBlock block = input.get<Loopring::InternalTransferBlock>();

        // Generate witness values for the given input values
        if (!circuit.generateWitness(block))
        {
            std::cerr << "Could not generate witness!" << std::endl;
            return false;
        }
    }
    return true;
}

int main (int argc, char **argv)
{
    ethsnarks::ppT::init_public_params();

    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << std::endl;
        std::cerr << "-validate <block.json>: Validates a block" << std::endl;
        std::cerr << "-prove <block.json> <out_proof.json>: Proves a block" << std::endl;
        std::cerr << "-createkeys <protoBlock.json>: Creates prover/verifier keys" << std::endl;
        std::cerr << "-verify <vk.json> <proof.json>: Verify a proof" << std::endl;
        std::cerr << "-exportcircuit <block.json> <circuit.json>: Exports the rc1s circuit to json (circom - not all fields)" << std::endl;
        std::cerr << "-exportwitness <block.json> <witness.json>: Exports the witness to json (circom)" << std::endl;
        std::cerr << "-createpk <block.json> <pk.json> <pk.raw>: Creates the proving key using a bellman pk" << std::endl;
        return 1;
    }

#ifdef MULTICORE
    const int max_threads = omp_get_max_threads();
    std::cout << "Num threads: " << max_threads << std::endl;
#endif

    const char* proofFilename = NULL;
    Mode mode = Mode::Validate;
    std::string baseFilename = "keys/";
    if (strcmp(argv[1], "-validate") == 0)
    {
        mode = Mode::Validate;
        std::cout << "Validating " << argv[2] << "..." << std::endl;
    }
    else if (strcmp(argv[1], "-prove") == 0)
    {
        if (argc != 4)
        {
            std::cout << "Invalid number of arguments!"<< std::endl;
            return 1;
        }
        mode = Mode::Prove;
        proofFilename = argv[3];
        std::cout << "Proving " << argv[2] << "..." << std::endl;
    }
    else if (strcmp(argv[1], "-createkeys") == 0)
    {
        if (argc != 3)
        {
            std::cout << "Invalid number of arguments!"<< std::endl;
            return 1;
        }
        mode = Mode::CreateKeys;
        std::cout << "Creating keys for " << argv[2] << "..." << std::endl;
    }
    else if (strcmp(argv[1], "-verify") == 0)
    {
        if (argc != 4)
        {
            std::cout << "Invalid number of arguments!"<< std::endl;
            return 1;
        }
        std::cout << "Verify for " << argv[3] << " ..." << std::endl;
        if (stub_main_verify(argv[0], argc - 1, (const char **)(argv + 1)))
        {
            return 1;
        }
        std::cout << "Proof is valid" << std::endl;
        return 0;
    }
    else if (strcmp(argv[1], "-exportcircuit") == 0)
    {
        if (argc != 4)
        {
            std::cout << "Invalid number of arguments!"<< std::endl;
            return 1;
        }
        mode = Mode::ExportCircuit;
        std::cout << "Exporting circuit for " << argv[2] << "..." << std::endl;
    }
    else if (strcmp(argv[1], "-exportwitness") == 0)
    {
        if (argc != 4)
        {
            std::cout << "Invalid number of arguments!"<< std::endl;
            return 1;
        }
        mode = Mode::ExportWitness;
        std::cout << "Exporting witness for " << argv[2] << "..." << std::endl;
    }
    else if (strcmp(argv[1], "-createpk") == 0)
    {
        if (argc != 5)
        {
            std::cout << "Invalid number of arguments!"<< std::endl;
            return 1;
        }
        mode = Mode::CreatePk;
        std::cout << "Creating pk for " << argv[2] << " using " << argv[3] << " ..." << std::endl;
    }
    else
    {
        std::cerr << "Unknown option: " << argv[1] << std::endl;
        return 1;
    }

    // Read the JSON file
    const char* filename = argv[2];
    std::ifstream file(filename);
    if (!file.is_open())
    {
        std::cerr << "Cannot open input file: " << filename << std::endl;
        return 1;
    }
    json input;
    file >> input;
    file.close();

    // Read meta data
    int blockType = input["blockType"].get<int>();
    unsigned int blockSize = input["blockSize"].get<int>();
    bool onchainDataAvailability = input["onchainDataAvailability"].get<bool>();
    std::string strOnchainDataAvailability = onchainDataAvailability ? "_DA_" : "_";
    std::string postFix = strOnchainDataAvailability + std::to_string(blockSize);

    switch(blockType)
    {
        case 0:
        {
            baseFilename += "trade" + postFix;
            break;
        }
        case 1:
        {
            baseFilename += "deposit" + postFix;
            break;
        }
        case 2:
        {
            baseFilename += "withdraw_onchain" + postFix;
            break;
        }
        case 3:
        {
            baseFilename += "withdraw_offchain" + postFix;
            break;
        }
        case 4:
        {
            baseFilename += "cancel" + postFix;
            break;
        }
        case 5:
        {
            baseFilename += "internal_transfer" + postFix;
            break;
        }
        default:
        {
            std::cerr << "Unknown block type: " << blockType << std::endl;
            return 1;
        }
    }

    if (mode == Mode::Prove)
    {
        std::string pkFileName = baseFilename + "_pk.raw";
        if (!fileExists(pkFileName.c_str())) {
            std::cerr << "Failed to find pk!" << std::endl;
            return 1;
        }
    }

    std::cout << "Building circuit... " << std::endl;

    ethsnarks::ProtoboardT pb;
    switch(blockType)
    {
        case 0:
        {
            if (!trade(mode, onchainDataAvailability, blockSize, input, pb))
            {
                return 1;
            }
            break;
        }
        case 1:
        {
            if (!deposit(mode, blockSize, input, pb))
            {
                return 1;
            }
            break;
        }
        case 2:
        {
            if (!onchainWithdraw(mode, blockSize, input, pb))
            {
                return 1;
            }
            break;
        }
        case 3:
        {
            if (!offchainWithdraw(mode, onchainDataAvailability, blockSize, input, pb))
            {
                return 1;
            }
            break;
        }
        case 4:
        {
            if (!cancel(mode, onchainDataAvailability, blockSize, input, pb))
            {
                return 1;
            }
            break;
        }
        case 5:
        {
            if (!internalTransfer(mode, onchainDataAvailability, blockSize, input, pb))
            {
                return 1;
            }
            break;
        }
        default:
        {
            std::cerr << "Unknown block type: " << blockType << std::endl;
            return 1;
        }
    }

    if (mode == Mode::Validate)
    {
        // Check if the inputs are valid for the circuit
        if (!pb.is_satisfied())
        {
            std::cerr << "Block is not valid!" << std::endl;
            return 1;
        }
        std::cout << "Block is valid." << std::endl;
    }

    if (mode == Mode::CreateKeys)
    {
        if (!generateKeyPair(pb, baseFilename))
        {
            std::cerr << "Failed to generate keys!" << std::endl;
            return 1;
        }
    }

    if (mode == Mode::Prove)
    {
#ifdef GPU_PROVE
        std::cout << "GPU Prove: Generate inputsFile." << std::endl;
        std::string inputsFilename = baseFilename + "_inputs.raw";
        auto begin = now();
        stub_write_input_from_pb(pb,  (baseFilename + "_pk.raw").c_str(), inputsFilename.c_str());
        print_time(begin, "write input");
#else
        if (!generateProof(pb, (baseFilename + "_pk.raw").c_str(), proofFilename))
        {
            return 1;
        }
#endif

    }

    if (mode == Mode::ExportCircuit)
    {
        if (!r1cs2json(pb, argv[3]))
        {
            std::cerr << "Failed to export circuit!" << std::endl;
            return 1;
        }
    }

    if (mode == Mode::ExportWitness)
    {
        if (!witness2json(pb, argv[3]))
        {
            std::cerr << "Failed to export witness!" << std::endl;
            return 1;
        }
    }

    if (mode == Mode::CreatePk)
    {
        if (!pk_bellman2ethsnarks(pb, argv[3], argv[4]))
        {
            return 1;
        }
        std::cout << "pk file created: " << argv[4] << std::endl;
    }

    return 0;
}
