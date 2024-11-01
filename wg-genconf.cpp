/**
 * wg-genconf.cpp - Generate WireGuard client configuration file
 * Copyright (c) 2024 Tomoatsu Shimada/Walbrix Corporation
 * SPDX-License-Identifier: MIT
 */

#include <unistd.h>

#include <iostream>
#include <memory>

#include <openssl/evp.h>
#include <argparse/argparse.hpp>

static const std::string progname = "wg-genconf";
static const std::string version = "0.1";
static const size_t WG_KEY_LEN = 32;

std::string base64_encode(const uint8_t* bytes, size_t len)
{
    char encoded[4*((len+2)/3)];
    if (!EVP_EncodeBlock((unsigned char*)encoded, bytes, len))
        throw std::runtime_error("EVP_EncodeBlock() failed");
    //else
    return encoded;
}

std::pair<std::string,std::string> create_new_keypair()
{
    std::shared_ptr<uint8_t[]> privkey_bytes(new uint8_t[WG_KEY_LEN]);
    if (getentropy(privkey_bytes.get(), WG_KEY_LEN) != 0)
        throw std::runtime_error("getentropy() failed");
    // https://github.com/torvalds/linux/blob/master/include/crypto/curve25519.h#L61
    privkey_bytes[0] &= 248;
    privkey_bytes[31] = (privkey_bytes[31] & 127) | 64;
    std::shared_ptr<EVP_PKEY> privkey(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, privkey_bytes.get(), WG_KEY_LEN), 
        EVP_PKEY_free);

    std::shared_ptr<uint8_t[]> pubkey_bytes(new uint8_t[WG_KEY_LEN]);
    size_t pubkey_len = WG_KEY_LEN;
    if (!EVP_PKEY_get_raw_public_key(privkey.get(), pubkey_bytes.get(), &pubkey_len)) {
        throw std::runtime_error("EVP_PKEY_get_raw_public_key() failed");
    }

    return {base64_encode(privkey_bytes.get(), WG_KEY_LEN), base64_encode(pubkey_bytes.get(), WG_KEY_LEN)};
}

int main(int argc, char* argv[])
{
    argparse::ArgumentParser program(progname, version);
    program.add_description("Generate WireGuard client configuration file");
    program.add_argument("--address").help("IPv4 and/or IPv6 address with CIDR mask");
    program.add_argument("--privkey").help("Base64-encoded private key(Newly generated if not specified)");
    program.add_argument("--mtu").help("Maximum Transmission Unit (MTU)");
    program.add_argument("--peer-pubkey").help("Base64-encoded peer public key");
    program.add_argument("--allowed-ips").help("IPv4 and/or IPv6 address with CIDR mask");
    program.add_argument("--endpoint").help("Hostname or IP address with port");
    program.add_argument("--persistent-keepalive").help("Interval in seconds to send keepalive packets");

    try {
        program.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return EXIT_FAILURE;
    }

    //else
    std::cout << "[Interface]" << std::endl;

    if (program.present("--address")) {
        std::cout << "Address = " << program.get<std::string>("--address") << std::endl;
    } else {
        std::cout << "#Address = " << std::endl;
    }

    std::string privkey;
    std::optional<std::string> pubkey;

    if (program.present("--privkey")) {
        privkey = program.get<std::string>("--privkey");
    } else {
        try {
            auto [privkey_, pubkey_] = create_new_keypair();
            privkey = privkey_;
            pubkey = pubkey_;
        }
        catch (const std::runtime_error& err) {
            std::cerr << err.what() << std::endl;
            return EXIT_FAILURE;
        }
    }

    std::cout << "PrivateKey = " << privkey << std::endl;
    if (pubkey) {
        std::cout << "#PublicKey = " << *pubkey << std::endl;
    }

    if (program.present("--mtu")) {
        std::cout << "MTU = " << program.get<std::string>("--mtu") << std::endl;
    } else {
        std::cout << "#MTU = 1420" << std::endl;
    }

    std::cout << std::endl;
    std::cout << "[Peer]" << std::endl;

    if (program.present("--peer-pubkey")) {
        std::cout << "PublicKey = " << program.get<std::string>("--peer-pubkey") << std::endl;
    } else {
        std::cout << "#PublicKey = " << std::endl;
    }   

    if (program.present("--allowed-ips")) {
        std::cout << "AllowedIPs = " << program.get<std::string>("--allowed-ips") << std::endl;
    } else {
        std::cout << "#AllowedIPs = " << std::endl;
    }

    if (program.present("--endpoint")) {
        std::cout << "Endpoint = " << program.get<std::string>("--endpoint") << std::endl;
    } else {
        std::cout << "#Endpoint = " << std::endl;
    }

    if (program.present("--persistent-keepalive")) {
        std::cout << "PersistentKeepalive = " << program.get<std::string>("--persistent-keepalive") << std::endl;
    } else {
        std::cout << "#PersistentKeepalive = 25" << std::endl;
    }

    return EXIT_SUCCESS;
}