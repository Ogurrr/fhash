#include <iostream>

#include "sha.h"
#include "md.h"
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file path>" << std::endl;
        return 1;
    }

    std::string filePath = argv[1];
    computeFileMD5(filePath);
    computeFileSHA256(filePath);
    computeFileKeccak256(filePath);
    computeFileSHA384(filePath);
    computeFileSHA512(filePath);

    return 0;
}
