#ifndef _SERVICE_H_
#define _SERVICE_H_
#endif

#include <string>

class ProofResult {
 public:
    int costSeconds;
    bool success;
    std::string errorMessage;
    std::string proofJsonStr;
};

bool validateBlock(char* inputJson);
bool createKeyPair(char* inputJson);
ProofResult generateProof(char* inputJson, char* proofFilename);
