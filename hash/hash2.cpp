#include <iostream>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
std::string calculateSHA256(const std::string& input) {
    CryptoPP::SHA256 hash;
    std::string hashString;
    CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashString))));
    return hashString;
}
int main() {
    std::string userInput = "Проверка хеширования";
    std::string hashResult = calculateSHA256(userInput);
    std::cout << "SHA-256 Hash: " << hashResult << std::endl;
    return 0;
}
