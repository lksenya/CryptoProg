#include <iostream>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

int main() {
    CryptoPP::SHA256 hash;
    std::string message = "Проверка хеширования";
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(hash, new CryptoPP::ArraySink(digest, sizeof(digest))));
    std::string hashString;
    CryptoPP::StringSource(digest, sizeof(digest), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashString)));
    std::cout<<"Исходная строка: "+message<<std::endl;
    std::cout << "SHA-256 Hash: " << hashString << std::endl;
    return 0;
}
