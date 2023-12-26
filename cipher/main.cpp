#include <iostream>
#include <cctype>
#include <locale>
#include "modalphacipher.h"
#include <codecvt>
#include <typeinfo>

using namespace std;

void check(const wstring& Text, const wstring& key, const bool destructCipherText=false)
{
    try {
        wstring cipherText;
        wstring decryptedText;
        modalphacipher cipher(key);
        cipherText = cipher.encrypt(Text); // зашифровывание
        if (destructCipherText) // надо "портить"?
            cipherText.front() = tolower(cipherText.front()); // "портим"
        decryptedText = cipher.decrypt(cipherText); // расшифровывание
        wcout<<L"key="<<key<<endl;
        wcout<<Text<<endl;
        wcout<<cipherText<<endl;
        wcout<<decryptedText<<endl;
    } catch (const cipher_error & e) {
        wcerr<<"Error: "<<e.what()<<endl;
    }
}

// проверка, чтобы строка состояла только из прописных букв
bool isValid(const wstring& s)
{
    for(auto c:s)
        if (!iswalpha(c) || !iswupper(c))
            return false;
    return true;
}
int main()
{
    locale loc("ru_RU.UTF-8");
    locale::global(loc);
    check(L"ПРИВЕТ",L"ПРОЩАЙ");
    check(L"ПРОЩАЙ",L"");
    check(L"ПРОЩАЙ",L"ПРИВЕТ321");
    check(L"П Р О Щ А Й",L"ПРИВЕТ");
    check(L"321",L"ПРИВЕТ");
}
