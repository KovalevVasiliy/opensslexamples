#include <memory>
#include <iostream>
#include "certtools.h"

int main() {
    std::pair<X509UPtr, EVP_KEYUPtr> rootCert = generateRootCertificate();
    if (rootCert.first == nullptr || rootCert.second == nullptr) {
        std::cerr << "Failed to generate rootCert" << std::endl;
        return -1;
    }
    std::pair<X509UPtr, EVP_KEYUPtr> cert = generateCertificate(rootCert.first.get(), rootCert.second.get());
    if (cert.first == nullptr || cert.second == nullptr) {
        std::cerr << "Failed to generate cert" << std::endl;
        return -1;
    }

    saveCertToPemFile(cert.first.get(), "cert.pem");
    saveCertToPemFile(rootCert.first.get(), "rootcert.pem");
}