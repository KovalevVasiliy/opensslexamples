//
// Created by Witcher on 23.04.2023.
//

#include <iostream>
#include "certtools.h"

#include <openssl/rand.h>


bool setSerialNumber(X509* cert, uint32_t bytes) {
    bool result = false;
    ASN1_STRING* serialNumber = X509_get_serialNumber(cert);
    if (serialNumber != nullptr && bytes != 0) {
       std::vector<unsigned char> serial(bytes);
        RAND_bytes(serial.data(), static_cast<int>(serial.size()));
        if (ASN1_STRING_set(serialNumber, serial.data(), static_cast<int>(serial.size())) == 1) {
            result = true;
        }
    }
    return result;
}

bool setVersion(X509* cert, long version) {
    return X509_set_version(cert, version) == 1;
}

bool updateSubjectName(X509* cert, const char* key, const char* value) {
    bool result = false;
    X509_NAME* subjectName = X509_get_subject_name(cert);
    if (subjectName != nullptr) {
        const int res = X509_NAME_add_entry_by_txt(subjectName, key, MBSTRING_ASC, (unsigned char*)value, -1, -1, 0);
        result = res == 1;
    }
    return result;
}

bool setNotAfter(X509* cert, uint32_t y, uint32_t m, uint32_t d, int32_t offset_days) {
    struct tm base;
    memset(&base, 0, sizeof(base));
    base.tm_year = y - 1900;
    base.tm_mon = m - 1;
    base.tm_mday = d;
    time_t tm = mktime(&base);

    bool result = false;
    ASN1_STRING* notAfter = X509_getm_notAfter(cert);
    if (notAfter != nullptr) {
        X509_time_adj(notAfter, 86400L * offset_days, &tm);
        result = true;
    }
    return result;
}

bool setNotBefore(X509* cert, uint32_t y, uint32_t m, uint32_t d, int32_t offset_days) {
    struct tm base;
    memset(&base, 0, sizeof(base));
    base.tm_year = y - 1900;
    base.tm_mon = m - 1;
    base.tm_mday = d;
    time_t tm = mktime(&base);

    bool result = false;
    ASN1_STRING* notBefore = X509_getm_notBefore(cert);
    if (notBefore != nullptr) {
        X509_time_adj(notBefore, 86400L * offset_days, &tm);
        result = true;
    }
    return result;
}

bool setPublicKey(X509* cert, EVP_PKEY* key) {
    return X509_set_pubkey(cert, key) == 1;
}

bool signCert(X509* cert, EVP_PKEY* key, const EVP_MD* algo) {
    return X509_sign(cert, key, algo) != 0;
}

bool saveCertToPemFile(X509* cert, const std::string& file) {
    bool result = false;
    std::unique_ptr<BIO, decltype(&::BIO_free)> bio(BIO_new(BIO_s_file()), ::BIO_free);
    if (bio != nullptr) {
        if (BIO_write_filename(bio.get(), const_cast<char*>(file.c_str())) > 0) {
            result = PEM_write_bio_X509(bio.get(), cert) == 1;
        }
    }
    return result;
}

EVP_KEYUPtr generateKeyPair(int32_t bits) {
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> key(EVP_RSA_gen(bits), ::EVP_PKEY_free);
    return std::move(key);
}

bool addCustomExtension(X509* cert, const char* key, const char* value, bool critical) {
    const int nid = OBJ_create(key, value, nullptr);

    std::unique_ptr<ASN1_OCTET_STRING, decltype(&::ASN1_OCTET_STRING_free)> data(ASN1_OCTET_STRING_new(), ::ASN1_OCTET_STRING_free);
    int ret = ASN1_OCTET_STRING_set(data.get(), reinterpret_cast<unsigned const char*>(value), static_cast<int>(strlen(value)));
    if (ret != 1) {
        return false;
    }

    std::unique_ptr<X509_EXTENSION, decltype(&::X509_EXTENSION_free)> ex(X509_EXTENSION_create_by_NID(nullptr, nid, critical, data.get()), ::X509_EXTENSION_free);
    return X509_add_ext(cert, ex.get(), -1) == 1;
}

bool addStandardExtension(X509* cert, X509* issuer, int nid, const char* value) {
    X509V3_CTX ctx; // create context
    X509V3_set_ctx_nodb(&ctx); // init context
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0); // set context

    std::unique_ptr<X509_EXTENSION, decltype(&::X509_EXTENSION_free)> ex(X509V3_EXT_conf_nid(nullptr, &ctx, nid, value), ::X509_EXTENSION_free);
    if (ex != nullptr) {
        return X509_add_ext(cert, ex.get(), -1) == 1;
    }
    return false;
}

bool setIssuer(X509* cert, X509* issuer) {
    bool result = false;
    X509_NAME* subjectName = X509_get_subject_name(issuer);
    if (subjectName != nullptr) {
        result = X509_set_issuer_name(cert, subjectName) == 1;
    }
    return result;
}

bool addIssuerInfo(X509* cert, const char* key, const char* value) {
    bool result = false;
    X509_NAME* issuerName = X509_get_issuer_name(cert);
    if (issuerName != nullptr) {
        result = X509_NAME_add_entry_by_txt(issuerName, key, MBSTRING_ASC, (unsigned char*)value, -1, -1, 0) == 1;
    }
    return result;
}

std::pair<X509UPtr, EVP_KEYUPtr> generateRootCertificate() {
    std::pair<X509UPtr, EVP_KEYUPtr> result = std::make_pair(X509UPtr(nullptr, ::X509_free), EVP_KEYUPtr(nullptr, ::EVP_PKEY_free));

    X509UPtr certificate(X509_new(), ::X509_free);
    if (certificate == nullptr) {
        return result;
    }

    const uint32_t bytes = 20;
    bool res = setSerialNumber(certificate.get(), bytes);
    if (!res) {
        std::cerr << "Failed to setSerialNumber" << std::endl;
        return result;
    }

    const long ver = 0x2; // version 3
    res = setVersion(certificate.get(), ver);
    if (!res) {
        std::cerr << "Failed to setVersion" << std::endl;
        return result;
    }

    static constexpr const char* key = "CN";
    static constexpr const char* value = "Common Name";
    res = updateSubjectName(certificate.get(), key, value);
    if (!res) {
        std::cerr << "Failed to updateSubjectName" << std::endl;
        return result;
    }

    uint32_t y = 2025;
    uint32_t m = 12;
    uint32_t d = 25;
    int32_t offset_days = 0;
    res = setNotAfter(certificate.get(), y, m, d, offset_days);
    if (!res) {
        std::cerr << "Failed to setNotAfter" << std::endl;
        return result;
    }

    y = 2022;
    m = 12;
    d = 25;
    offset_days = 0;
    res = setNotBefore(certificate.get(), y, m, d, offset_days);
    if (!res) {
        std::cerr << "Failed to setNotBefore" << std::endl;
        return result;
    }

    const int32_t bits = 2048;
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> keyPair = generateKeyPair(bits);
    res = setPublicKey(certificate.get(), keyPair.get());
    if (!res) {
        std::cerr << "Failed to setPublicKey" << std::endl;
        return result;
    }

    std::unordered_map<int , const char*> extensions {
            {NID_basic_constraints, "critical,CA:TRUE"},
            {NID_subject_key_identifier, "hash"},
            {NID_key_usage, "keyCertSign,cRLSign"},
    };

    for (const auto& ex : extensions) {
        res = addStandardExtension(certificate.get(), nullptr, ex.first, ex.second);
        if (!res) {
            std::cerr << "Failed to addStandardExtension: " << ex.second << std::endl;
            return result;
        }
    }

    res = setIssuer(certificate.get(), certificate.get());
    if (!res) {
        std::cerr << "Failed to setIssuer" << std::endl;
        return result;
    }

    res = signCert(certificate.get(), keyPair.get(), EVP_sha256());
    if (!res) {
        std::cerr << "Failed to signCert" << std::endl;
        return result;
    }
    return std::make_pair(std::move(certificate), std::move(keyPair));
}

std::pair<X509UPtr, EVP_KEYUPtr> generateCertificate(X509* rootCert, EVP_PKEY* rootKeyPair) {
    std::pair<X509UPtr, EVP_KEYUPtr> result = std::make_pair(X509UPtr(nullptr, ::X509_free), EVP_KEYUPtr(nullptr, ::EVP_PKEY_free));

    X509UPtr certificate(X509_new(), ::X509_free);
    if (certificate == nullptr) {
        return result;
    }

    const uint32_t bytes = 20;
    bool res = setSerialNumber(certificate.get(), bytes);
    if (!res) {
        return result;
    }

    const long ver = 0x2; // version 3
    res = setVersion(certificate.get(), ver);
    if (!res) {
        return result;
    }

    static constexpr const char* key = "CN";
    static constexpr const char* value = "Common Name";
    res = updateSubjectName(certificate.get(), key, value);
    if (!res) {
        return result;
    }

    uint32_t y = 2025;
    uint32_t m = 12;
    uint32_t d = 25;
    int32_t offset_days = 0;
    res = setNotAfter(certificate.get(), y, m, d, offset_days);
    if (!res) {
        return result;
    }

    y = 2022;
    m = 12;
    d = 25;
    offset_days = 0;
    res = setNotBefore(certificate.get(), y, m, d, offset_days);
    if (!res) {
        return result;
    }

    const int32_t bits = 2048;
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> keyPair = generateKeyPair(bits);
    res = setPublicKey(certificate.get(), keyPair.get());
    if (!res) {
        return result;
    }

    std::unordered_map<int , const char*> extensions {
            {NID_basic_constraints, "critical,CA:TRUE"},
            {NID_subject_key_identifier, "hash"},
            {NID_key_usage, "keyCertSign,cRLSign"},
    };

    for (const auto& ex : extensions) {
        res = addStandardExtension(certificate.get(), nullptr, ex.first, ex.second);
        if (!res) {
            return result;
        }
    }

    res = setIssuer(certificate.get(), rootCert);
    if (!res) {
        return result;
    }

    res = signCert(certificate.get(), rootKeyPair, EVP_sha256());
    if (!res) {
        return result;
    }
    return std::make_pair(std::move(certificate), std::move(keyPair));
}