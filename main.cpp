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
    static constexpr const char* value = "US";
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