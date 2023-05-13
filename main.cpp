#include <memory>
#include <iostream>
#include "certtools.h"

static int certVerifyCallback(int ok, X509_STORE_CTX *ctx) {
    const int err = X509_STORE_CTX_get_error(ctx);
    if (err != 0) {
        std::cerr << "Failed to verify cert " << err << std::endl;
    }
    return ok;
}

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

    std::unique_ptr<X509_STORE, decltype(&::X509_STORE_free)> store(X509_STORE_new(), &::X509_STORE_free);

    if (!addCert(store.get(), rootCert.first.get())) {
        std::cerr << "Failed to add cert" << std::endl;
        return -1;
    }
    auto storeContextDeleter = [](X509_STORE_CTX* ctx) {
        X509_STORE_CTX_cleanup(ctx);
        X509_STORE_CTX_free(ctx);
    };
    std::unique_ptr<X509_STORE_CTX, decltype(storeContextDeleter)>
            storeCtx(X509_STORE_CTX_new(), storeContextDeleter);
    if (storeCtx == nullptr) {
        std::cerr << "Failed to X509_STORE_CTX_new" << std::endl;
        return -1;
    }

    X509_STORE_set_verify_cb_func(store.get(), certVerifyCallback);
    if (X509_STORE_CTX_init(storeCtx.get(), store.get(), cert.first.get(), nullptr) == 0) {
        std::cerr << "Failed to X509_STORE_CTX_init" << std::endl;
        return -1;
    }

    if (X509_verify_cert(storeCtx.get()) != 1) {
        std::cerr << "Failed to X509_verify_cert" << std::endl;
        return -1;
    }
    return 0;
}