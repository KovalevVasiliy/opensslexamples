//
// Created by Witcher on 23.04.2023.
//

#ifndef UNTITLED2_CERTTOOLS_H
#define UNTITLED2_CERTTOOLS_H

#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <memory>
#include <string>

using X509UPtr = std::unique_ptr<X509, decltype(&::X509_free)>;
using EVP_KEYUPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;

bool setSerialNumber(X509* cert, int32_t serial);

bool setVersion(X509* cert, long version);

bool updateSubjectName(X509* cert, const char* key, const char* value);

bool setNotAfter(X509* cert, uint32_t y, uint32_t m, uint32_t d, int32_t offset_days);

bool setNotBefore(X509* cert, uint32_t y, uint32_t m, uint32_t d, int32_t offset_days);

bool setPublicKey(X509* cert, EVP_PKEY* key);

bool signCert(X509* cert, EVP_PKEY* key, const EVP_MD* algo);

bool saveCertToPemFile(X509* cert, const std::string& file);

EVP_KEYUPtr generateKeyPair(int32_t bits);

bool addCustomExtension(X509* cert, const char* key, const char* value, bool critical);

bool addStandardExtension(X509* cert, X509* issuer, int nid, const char* value);

bool setIssuer(X509* cert, X509* issuer);

bool addIssuerInfo(X509* cert, const char* key, const char* value);

std::pair<X509UPtr, EVP_KEYUPtr> generateRootCertificate();

std::pair<X509UPtr, EVP_KEYUPtr> generateCertificate(X509* rootCert, EVP_PKEY* keyPair);

#endif //UNTITLED2_CERTTOOLS_H
