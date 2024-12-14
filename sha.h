#ifndef __SHA__
#define __SHA__

#include <iostream>

void computeFileSHA256(const std::string& filePath);
void computeFileSHA384(const std::string& filePath);
void computeFileSHA512(const std::string& filePath);
void computeFileKeccak256(const std::string& filePath);

#endif //__SHA__