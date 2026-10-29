#include "chat_client.hpp"
#include "../shared/crypto.hpp"
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

ChatClient::ChatClient() : client_socket(-1), is_running(false) {}

ChatClient::~ChatClient() {
    is_running = false;
    if (client_socket != -1) {
        close(client_socket);
    }

    if (receiver_thread.joinable()) {
        receiver_thread.join();
    }
}

bool ChatClient::connect_to_server(const std::string& ip, int port) {
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        std::cerr << "[CHYBA] Pri vytvareni socketu!\n";
        return false;
    }

    sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &server_address.sin_addr);

    if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "[CHYBA] Pripojeni selhalo! Bezi server?\n";
        return false;
    }

    return true;
}

bool ChatClient::perform_handshake() {
    std::cout << "[INFO] Uspesne pripojeno k serveru.\n";

    char handshake_buffer[2048] = {0};
    int bytes_read = read(client_socket, handshake_buffer, sizeof(handshake_buffer) - 1);

    if (bytes_read > 0) {
        std::string received_data(handshake_buffer);

        if (received_data.find("-----BEGIN PUBLIC KEY-----") != std::string::npos) {
            std::cout << "[HANDSHAKE] Prijat verejny klic od serveru.\n";

            EVP_PKEY* server_pub_key = load_public_key_from_string(received_data);
            if (server_pub_key) {
                std::cout << "[HANDSHAKE] Klic uspesne nacten do pameti a overen.\n";

                std::cout << "[HANDSHAKE] Generuji symetricky klic.\n";
                sym_key = generate_symmetric_key(32);

                std::cout << "[HANDSHAKE] Sifruji symetricky klic RSA klicem serveru.\n";
                std::vector<unsigned char> encrypted_sym_key = rsa_encrypt(server_pub_key, sym_key);

                EVP_PKEY_free(server_pub_key);

                if (encrypted_sym_key.empty()) {
                    std::cerr << "[CHYBA] Sifrovani selhalo.\n";
                    return false;
                }

                send(client_socket, encrypted_sym_key.data(), encrypted_sym_key.size(), 0);
                std::cout << "[HANDSHAKE] Siffrovani odeslano serveru.\n";
                return true;
            }
        }
    }

    std::cerr << "[CHYBA] Handshake selhal.\n";
    return false;
}

void ChatClient::receive_messages_loop() {
    unsigned char buffer[2048];
    while (is_running) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = read(client_socket, buffer, sizeof(buffer));

        if (bytes_read > 0) {
            std::vector<unsigned char> encrypted_data(buffer, buffer + bytes_read);
            std::string decrypted_msg = aes_decrypt(encrypted_data, sym_key);

            // Osetreni aby kdyz prijde zprava, tak to nevypsalo prazdny radek s "Ty: "
            if (!decrypted_msg.empty()) {
                std::cout << "\r\033[2K";

                std::cout << decrypted_msg;
                if (decrypted_msg.back() != '\n') std::cout << "\n";

                std::cout << "Ty: " << std::flush;
            }
        } else if (bytes_read == 0 || (bytes_read < 0 && is_running)) {
            std::cout << "\n[INFO] Server ukoncil spojeni.\n";
            is_running = false;
            exit(0);
        }
    }
}

void ChatClient::start(const std::string& ip, int port) {
    if (!connect_to_server(ip, port)) return;
    if (!perform_handshake()) return;

    std::cout << "[INFO] Handshake dokoncen! Muzes zacit psat (pro ukonceni napis /quit).\n";

    // Hlavni beh a spusteni poslechoveho vlakna
    is_running = true;
    receiver_thread = std::thread(&ChatClient::receive_messages_loop, this);

    std::string user_input;
    while (is_running) {
        std::cout << "Ty: ";
        std::getline(std::cin, user_input);

        if (user_input == "/quit") {
            is_running = false;
            break;
        }

        if (!user_input.empty()) {
            user_input += "\n";
            std::vector<unsigned char> encrypted_msg = aes_encrypt(user_input, sym_key);
            send(client_socket, encrypted_msg.data(), encrypted_msg.size(), 0);
        }
    }
}
