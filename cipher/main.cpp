#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>

using namespace CryptoPP;

// Функция для вычисления ключа из пароля
SecByteBlock DeriveKey(const std::string& password)
{
    SecByteBlock derived(AES::DEFAULT_KEYLENGTH);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    const byte* salt = (const byte*)"somesalt"; // Уникальная соль (лучше генерировать случайным образом)
    size_t saltLen = 8; // Длина соли в байтах
    pbkdf.DeriveKey(derived, derived.size(), 0, reinterpret_cast<const byte*>(password.data()), password.size(), salt, saltLen, 1000, 0.0);
    return derived;
}

// Функция для обработки файла
void ProcessFile(const std::string& inputFile, const std::string& outputFile, const std::string& password, bool encrypt)
{
    try {
        std::ifstream in(inputFile, std::ios::binary);
        std::ofstream out(outputFile, std::ios::binary);

        SecByteBlock key = DeriveKey(password);
        byte iv[AES::BLOCKSIZE];
        memset(iv, 0x00, AES::BLOCKSIZE);

        // Выбор режима шифрования или расшифрования
        if (encrypt) {
            CBC_Mode<AES>::Encryption enc;
            enc.SetKeyWithIV(key, key.size(), iv);

            // Шифрование файла
            FileSource fileSrc(in, true, new StreamTransformationFilter(enc, new FileSink(out)));
            fileSrc.PumpAll();
            fileSrc.Flush(true);
            std::cout << "Файл зашифрован" << std::endl;
        }
        else {
            CBC_Mode<AES>::Decryption dec;
            dec.SetKeyWithIV(key, key.size(), iv);

            // Расшифрование файла
            FileSource fileSrc(in, true, new StreamTransformationFilter(dec, new FileSink(out)));
            fileSrc.PumpAll();
            fileSrc.Flush(true);
            std::cout << "Файл расшифрован" << std::endl;
        }
    }
    catch (const Exception& ex) {
        std::cerr << "Crypto++ исключение: " << ex.what() << std::endl;
    }
}

int main()
{
    std::string inputFile, outputFile, password;
    int sw;

    // Выбор режима работы
    std::cout << "Выберите тип оперцации: 1 - шифрование, 2 - расшифрование:   ";
    std::cin >> sw;

    // Ввод путей к файлам и пароля
    std::cout << "Введите путь к входному файлу: ";
    std::cin >> inputFile;

    std::cout << "Введите путь к выходному файлу: ";
    std::cin >> outputFile;

    std::cout << "Введите пароль: ";
    std::cin >> password;

    bool encrypt = (sw == 1);
    ProcessFile(inputFile, outputFile, password, encrypt);

    return 0;
}
