#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <memory>
#include <iostream>

bool setSerialNumber(X509* cert, int32_t serial) {
    bool result = false;
    ASN1_INTEGER* serialNumber = X509_get_serialNumber(cert);
    if (serialNumber != nullptr) {
        const int res = ASN1_INTEGER_set(serialNumber, serial);
        result = res == 1;
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

std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> generateKeyPair(int32_t bits) {
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> key(EVP_RSA_gen(bits), ::EVP_PKEY_free);
    return std::move(key);
}

bool addCustomExtension(X509* cert, const char* key, const char* value, bool critical) {
    const int nid = OBJ_create(key, value, nullptr);

    std::unique_ptr<ASN1_OCTET_STRING, decltype(&::ASN1_OCTET_STRING_free)> data(ASN1_OCTET_STRING_new(), ::ASN1_OCTET_STRING_free);
    int ret = ASN1_OCTET_STRING_set(data.get(), reinterpret_cast<unsigned const char*>(value), strlen(value));
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

int main() {
    std::unique_ptr<X509, decltype(&::X509_free)> certificate(X509_new(), ::X509_free);
    if (certificate == nullptr) {
        std::cerr << "Failed to create certificate" << std::endl;
        return -1;
    }

    const int32_t serialNum = 1;
    bool res = setSerialNumber(certificate.get(), serialNum);
    if (!res) {
        std::cerr << "Failed to setSerialNumber" << std::endl;
        return -1;
    }

    const long ver = 0x0; // version 1
    res = setVersion(certificate.get(), ver);
    if (!res) {
        std::cerr << "Failed to setVersion" << std::endl;
        return -1;
    }

    static constexpr const char* key = "CN";
    static constexpr const char* value = "Common Name";
    res = updateSubjectName(certificate.get(), key, value);
    if (!res) {
        std::cerr << "Failed to updateSubjectName" << std::endl;
        return -1;
    }

    const uint32_t y = 2022;
    const uint32_t m = 12;
    const uint32_t d = 25;
    const int32_t offset_days = 0;
    res = setNotAfter(certificate.get(), y, m, d, offset_days);
    if (!res) {
        std::cerr << "Failed to setNotAfter" << std::endl;
        return -1;
    }

    res = setNotBefore(certificate.get(), y, m, d, offset_days);
    if (!res) {
        std::cerr << "Failed to setNotBefore" << std::endl;
        return -1;
    }

    const int32_t bits = 2048;
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> keyPair = generateKeyPair(bits);
    res = setPublicKey(certificate.get(), keyPair.get());
    if (!res) {
        std::cerr << "Failed to setPublicKey" << std::endl;
        return -1;
    }

    const int nid = NID_basic_constraints;
    static const char* extensionValue = "critical,CA:TRUE";

    res = addStandardExtension(certificate.get(), nullptr, nid, extensionValue);
    if (!res) {
        std::cerr << "Failed to addStandardExtension" << std::endl;
        return -1;
    }

    res = addCustomExtension(certificate.get(), "1.2.3", "myvalue", false);
    if (!res) {
        std::cerr << "Failed to addCustomExtension" << std::endl;
        return -1;
    }

    res = signCert(certificate.get(), keyPair.get(), EVP_sha256());
    if (!res) {
        std::cerr << "Failed to signCert" << std::endl;
        return -1;
    }

    std::unique_ptr<X509, decltype(&::X509_free)> duplicate(X509_dup(certificate.get()), ::X509_free);
    if (duplicate == nullptr) {
        std::cerr << "Failed to duplicate certificate" << std::endl;
        return -1;
    }

    res = setIssuer(certificate.get(), duplicate.get());
    if (!res) {
        std::cerr << "Failed to setIssuer" << std::endl;
        return -1;
    }

    res = addIssuerInfo(certificate.get(), key, value);
    if (!res) {
        std::cerr << "Failed to addIssuerInfo" << std::endl;
        return -1;
    }

    res = signCert(certificate.get(), keyPair.get(), EVP_sha256());
    if (!res) {
        std::cerr << "Failed to signCert" << std::endl;
        return -1;
    }

    static const std::string filename = "certificate.pem";
    res = saveCertToPemFile(certificate.get(), filename);
    if (!res) {
        std::cerr << "Failed to saveCertToPemFile" << std::endl;
        return -1;
    }
}