
#include "ThirdParty/BigInt.hpp"
#include "Utils/Data.h"
#include "Circuits/RingSettlementCircuit.h"
#include "Circuits/DepositCircuit.h"
#include "Circuits/OnchainWithdrawalCircuit.h"
#include "Circuits/OffchainWithdrawalCircuit.h"
#include "Circuits/OrderCancellationCircuit.h"
#include "Circuits/InternalTransferCircuit.h"

#include "ThirdParty/httplib.h"
#include "ThirdParty/json.hpp"
#include "ethsnarks.hpp"
#include "stubs.hpp"
#include <fstream>
#include <chrono>
#include <mutex>

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
    CreatePk,
    Pk_alt2mcl,
    Server
};

static inline auto now() -> decltype(std::chrono::high_resolution_clock::now()) {
    return std::chrono::high_resolution_clock::now();
}

template<typename T>
unsigned int elapsed_time_ms(const T& t1)
{
    auto t2 = std::chrono::high_resolution_clock::now();
    auto time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    return time_ms;
}

template<typename T>
void print_time(const T& t1, const char* str)
{
    printf("%s (%dms)\n", str, elapsed_time_ms(t1));
}

bool fileExists(const std::string& fileName)
{
    std::ifstream infile(fileName.c_str());
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

json loadBlock(const std::string& filename)
{
    // Read the JSON file
    std::ifstream file(filename.c_str());
    if (!file.is_open())
    {
        std::cerr << "Cannot open block file: " << filename << std::endl;
        return json();
    }
    json input;
    file >> input;
    file.close();
    return input;
}

ethsnarks::ProvingKeyT loadProvingKey(const std::string& pk_file)
{
    std::cout << "Loading proving key " << pk_file << "..." << std::endl;
    auto begin = now();
    auto proving_key = ethsnarks::load_proving_key(pk_file.c_str());
    print_time(begin, "Proving key loaded");
    return proving_key;
}

std::string proveCircuit(Loopring::Circuit* circuit, const ethsnarks::ProvingKeyT& proving_key)
{
    std::cout << "Generating proof..." << std::endl;
    auto begin = now();
    std::string jProof = ethsnarks::prove(circuit->getPb(), proving_key);
    unsigned int elapsed_ms = elapsed_time_ms(begin);
    elapsed_ms = elapsed_ms == 0 ? 1 : elapsed_ms;
    std::cout << "Proof generated in " << float(elapsed_ms) / 1000.0f << " seconds ("
        << (circuit->getPb().num_constraints() * 10) / (elapsed_ms / 100) << " constraints/second)" << std::endl;
    return jProof;
}

bool writeProof(const std::string& jProof, const std::string& proofFilename)
{
    std::ofstream fproof(proofFilename);
    if (!fproof.is_open())
    {
        std::cerr << "Cannot create proof file: " << proofFilename << std::endl;
        return false;
    }
    fproof << jProof;
    fproof.close();
    std::cout << "Proof written to: " << proofFilename << std::endl;
    return true;
}

Loopring::Circuit* newCircuit(Loopring::BlockType blockType, ethsnarks::ProtoboardT& outPb)
{
    switch(blockType)
    {
        case Loopring::BlockType::RingSettlement: return new Loopring::RingSettlementCircuit(outPb, "circuit");
        case Loopring::BlockType::Deposit: return new Loopring::DepositCircuit(outPb, "circuit");
        case Loopring::BlockType::OnchainWithdrawal: return new Loopring::OnchainWithdrawalCircuit(outPb, "circuit");
        case Loopring::BlockType::OffchainWithdrawal: return new Loopring::OffchainWithdrawalCircuit(outPb, "circuit");
        case Loopring::BlockType::OrderCancellation: return new Loopring::OrderCancellationCircuit(outPb, "circuit");
        case Loopring::BlockType::InternalTransfer: return new Loopring::InternalTransferCircuit(outPb, "circuit");
        default:
        {
            std::cerr << "Cannot create circuit for unknown block type: " << int(blockType) << std::endl;
            return nullptr;
        }
    }
}

Loopring::Circuit* createCircuit(Loopring::BlockType blockType, unsigned int blockSize, bool onchainDataAvailability, ethsnarks::ProtoboardT& outPb)
{
    std::cout << "Creating circuit... " << std::endl;
    auto begin = now();
    Loopring::Circuit* circuit = newCircuit(blockType, outPb);
    circuit->generateConstraints(onchainDataAvailability, blockSize);
    circuit->printInfo();
    print_time(begin, "Circuit created");
    return circuit;
}

bool generateWitness(Loopring::Circuit* circuit, const json& input)
{
    std::cout << "Generating witness... " << std::endl;
    auto begin = now();
    if (!circuit->generateWitness(input))
    {
        std::cerr << "Could not generate witness!" << std::endl;
        return false;
    }
    print_time(begin, "Witness generated");
    return true;
}

bool validateCircuit(Loopring::Circuit* circuit)
{
    std::cout << "Validating block..."<< std::endl;
    auto begin = now();
    // Check if the inputs are valid for the circuit
    if (!circuit->getPb().is_satisfied())
    {
        std::cerr << "Block is not valid!" << std::endl;
        return false;
    }
    print_time(begin, "Block is valid");
    return true;
}

std::string getBaseName(Loopring::BlockType blockType)
{
    switch(blockType)
    {
        case Loopring::BlockType::RingSettlement: return "trade";
        case Loopring::BlockType::Deposit: return "deposit";
        case Loopring::BlockType::OnchainWithdrawal: return "withdraw_onchain";
        case Loopring::BlockType::OffchainWithdrawal: return "withdraw_offchain";
        case Loopring::BlockType::OrderCancellation: return "cancel";
        case Loopring::BlockType::InternalTransfer: return "internal_transfer";
        default: return "unknown";
    }
}

std::string getProvingKeyFilename(const std::string& baseFilename)
{
    return baseFilename + "_pk.raw";
}

void runServer(Loopring::Circuit* circuit, const std::string& provingKeyFilename, unsigned int port)
{
    using namespace httplib;

    struct ProverStatus
    {
        bool proving = false;
        std::string blockFilename;
        std::string proofFilename;
    };

    struct ProverStatusRAII
    {
        ProverStatus& proverStatus;
        ProverStatusRAII(ProverStatus& _proverStatus, const std::string& blockFilename, const std::string& proofFilename) : proverStatus(_proverStatus)
        {
            proverStatus.proving = true;
            proverStatus.blockFilename = blockFilename;
            proverStatus.proofFilename = proofFilename;
        }

        ~ProverStatusRAII()
        {
            proverStatus.proving = false;
        }
    };

    // Load the proving key a single time
    auto proving_key = loadProvingKey(provingKeyFilename);

    // Prover status info
    ProverStatus proverStatus;
    // Lock for the prover
    std::mutex mtx;
    // Setup the server
    Server svr;
    // Called to prove blocks
    svr.Get("/prove", [&](const Request& req, Response& res) {
        const std::lock_guard<std::mutex> lock(mtx);

        // Parse the parameters
        std::string blockFilename = req.get_param_value("block_filename");
        std::string proofFilename = req.get_param_value("proof_filename");
        std::string strValidate = req.get_param_value("validate");
        bool validate = (strValidate.compare("true") == 0) ? true : false;
        if (blockFilename.length() == 0)
        {
            res.set_content("Error: block_filename missing!\n", "text/plain");
            return;
        }

        // Set the prover status for this session
        ProverStatusRAII statusRAII(proverStatus, blockFilename, proofFilename);

        // Prove the block
        json input = loadBlock(blockFilename);
        if (input == json())
        {
            res.set_content("Error: Failed to load block!\n", "text/plain");
            return;
        }

        // Some checks to see if this block is compatible with the loaded circuit
        int iBlockType = input["blockType"].get<int>();
        unsigned int blockSize = input["blockSize"].get<int>();
        if (Loopring::BlockType(iBlockType) != circuit->getBlockType() || blockSize != circuit->getBlockSize())
        {
            res.set_content("Error: Incompatible block requested! Use /info to check which blocks can be proven.\n", "text/plain");
            return;
        }

        if (!generateWitness(circuit, input))
        {
            res.set_content("Error: Failed to generate witness for block!\n", "text/plain");
            return;
        }
        if (validate)
        {
            if (!validateCircuit(circuit))
            {
                res.set_content("Error: Block is invalid!\n", "text/plain");
                return;
            }
        }
        std::string jProof = proveCircuit(circuit, proving_key);
        if (jProof.length() == 0)
        {
            res.set_content("Error: Failed to prove block!\n", "text/plain");
            return;
        }
        if (proofFilename.length() != 0)
        {
            if(!writeProof(jProof, proofFilename))
            {
                res.set_content("Error: Failed to write proof!\n", "text/plain");
                return;
            }
        }
        // Return the proof
        res.set_content(jProof + "\n", "text/plain");
    });
    // Retuns the status of the server
    svr.Get("/status", [&](const Request& req, Response& res) {
        if (proverStatus.proving)
        {
            std::string status = std::string("Proving ") + proverStatus.blockFilename;
            res.set_content(status + "\n", "text/plain");
        }
        else
        {
            res.set_content("Idle\n", "text/plain");
        }
    });
    // Info of this prover server
    svr.Get("/info", [&](const Request& req, Response& res) {
        std::string info = std::string("BlockType: ") + std::to_string(int(circuit->getBlockType())) +
            std::string("; BlockSize: ") + std::to_string(circuit->getBlockSize()) + "\n";
        res.set_content(info, "text/plain");
    });
    // Stops the prover server
    svr.Get("/stop", [&](const Request& req, Response& res) {
        const std::lock_guard<std::mutex> lock(mtx);
        svr.stop();
    });
    // Default page contains help
    svr.Get("/", [&](const Request& req, Response& res) {
        std::string content;
        content += "Prover server:\n";
        content += "- Prove a block: /prove?block_filename=<block.json>&proof_filename=<proof.json>&validate=true (proof_filename and validate are optional)\n";
        content += "- Status of the server: /status (busy proving a block or not)\n";
        content += "- Info of the server: /info (which blocks can be proven)\n";
        content += "- Shut down the server: /stop (will first finish generating the proof if busy)\n";
        res.set_content(content, "text/plain");
    });

    std::cout << "Running server on 'localhost' on port " << port << std::endl;
    svr.listen("localhost", port);
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
        std::cerr << "-pk_alt2mcl <block.json> <pk_alt.raw> <pk_mlc.raw>: Converts the proving key from the alt format to the mcl format" << std::endl;
        std::cerr << "-server <block.json> <port>: Keeps the program running as an HTTP server to prove blocks on demand" << std::endl;
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
    else if (strcmp(argv[1], "-pk_alt2mcl") == 0)
    {
        if (argc != 5)
        {
            std::cout << "Invalid number of arguments!"<< std::endl;
            return 1;
        }
        mode = Mode::Pk_alt2mcl;
        std::cout << "Converting pk for " << argv[2] << " from " << argv[3] << " to " << argv[4] << " ..." << std::endl;
    }
    else if (strcmp(argv[1], "-server") == 0)
    {
        if (argc != 4)
        {
            std::cout << "Invalid number of arguments!"<< std::endl;
            return 1;
        }
        mode = Mode::Server;
        std::cout << "Starting proving server for " << argv[2] << " on port " << argv[3] << "..." << std::endl;
    }
    else
    {
        std::cerr << "Unknown option: " << argv[1] << std::endl;
        return 1;
    }

    // Read the block file
    json input = loadBlock(argv[2]);
    if (input == json())
    {
        return 1;
    }

    // Read meta data
    int iBlockType = input["blockType"].get<int>();
    unsigned int blockSize = input["blockSize"].get<int>();
    bool onchainDataAvailability = input["onchainDataAvailability"].get<bool>();
    std::string strOnchainDataAvailability = onchainDataAvailability ? "_DA_" : "_";
    std::string postFix = strOnchainDataAvailability + std::to_string(blockSize);

    if (iBlockType >= int(Loopring::BlockType::COUNT))
    {
        std::cerr << "Invalid block type: " << iBlockType << std::endl;
        return 1;
    }
    Loopring::BlockType blockType = Loopring::BlockType(iBlockType);
    baseFilename += getBaseName(blockType) + postFix;
    std::string provingKeyFilename = getProvingKeyFilename(baseFilename);

    if (mode == Mode::Prove || mode == Mode::Server)
    {
        if (!fileExists(provingKeyFilename))
        {
            std::cerr << "Failed to find pk!" << std::endl;
            return 1;
        }
    }

    ethsnarks::ProtoboardT pb;
    Loopring::Circuit* circuit = createCircuit(blockType, blockSize, onchainDataAvailability, pb);

    if (mode == Mode::Server)
    {
        runServer(circuit, provingKeyFilename, std::stoi(argv[3]));
    }

    if (mode == Mode::Validate || mode == Mode::Prove)
    {
        if (!generateWitness(circuit, input))
        {
            return 1;
        }
    }

    if (mode == Mode::Validate || mode == Mode::Prove)
    {
        if (!validateCircuit(circuit))
        {
            return 1;
        }
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
        stub_write_input_from_pb(pb, provingKeyFilename.c_str(), inputsFilename.c_str());
        print_time(begin, "write input");
#else
        auto proving_key = loadProvingKey(provingKeyFilename);
        std::string jProof = proveCircuit(circuit, proving_key);
        if (jProof.length() == 0)
        {
            return 1;
        }
        if(!writeProof(jProof, proofFilename))
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

    if (mode == Mode::Pk_alt2mcl)
    {
        if (!pk_alt2mcl(pb, argv[3], argv[4]))
        {
            std::cout << "Could not convert pk. Incorrect active curve?" << std::endl;
            return 1;
        }
        std::cout << "pk file created: " << argv[4] << std::endl;
    }

    return 0;
}
