#include "chat_server.hpp"
#include "../shared/crypto.hpp"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <algorithm>
#include <sys/epoll.h>

ChatServer::ChatServer(int port) {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        std::cerr << "[CHYBA] Nepodarilo se vytvorit socket!\n";
        exit(1);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) == -1) {
        std::cerr << "[CHYBA] Nepodarilo se nabindovat port!\n";
        exit(1);
    }

    if (listen(server_fd, 10) == -1) {
        std::cerr << "[CHYBA] Nepodarilo se spustit listen!\n";
        exit(1);
    }

    set_nonblocking(server_fd);
    epoll_fd = epoll_create1(0);

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event);

    server_keypair = generate_rsa_keypair();
    if (!server_keypair) {
        std::cerr << "[CHYBA] Nepodarilo se vygenerovat RSA klice.\n";
        exit(1);
    }
}

ChatServer::~ChatServer() {
    close(server_fd);
    close(epoll_fd);
    if (server_keypair) EVP_PKEY_free(server_keypair);
}

bool ChatServer::set_nonblocking(int socket_fd) {
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1) return false;
    flags |= O_NONBLOCK;
    return fcntl(socket_fd, F_SETFL, flags) != -1;
}

void ChatServer::handle_new_connection() {
    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd != -1) {
        set_nonblocking(client_fd);

        struct epoll_event client_event;
        client_event.events = EPOLLIN | EPOLLET;
        client_event.data.fd = client_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_event);

        // Zalozeni noveho klienta
        clients[client_fd] = ClientNode{client_fd, "", {}, false};
        std::cout << "[SERVER] Novy klient pripojen! (FD: " << client_fd << ")\n";

        // Odeslani verejneho klice
        std::string pub_key_pem = get_public_key_pem(server_keypair);
        send(client_fd, pub_key_pem.c_str(), pub_key_pem.length(), 0);
    }
}

void ChatServer::remove_client(int client_fd) {
    auto& client = clients[client_fd];
    if (client.has_nickname) {
        std::string msg = "*** " + client.nickname + " se odpojil(a) ***\n";
        std::cout << msg;
        broadcast_message(client_fd, msg);
    } else {
        std::cout << "[SERVER] Klient odpojen! (FD: " << client_fd << ")\n";
    }

    close(client_fd);
    clients.erase(client_fd);
}

void ChatServer::broadcast_message(int sender_fd, const std::string& message) {
    for (const auto& [id, client] : clients) {
        if (id != sender_fd && client.has_nickname && !client.sym_key.empty()) {
            std::vector<unsigned char> encrypted_out = aes_encrypt(message, client.sym_key);
            send(id, encrypted_out.data(), encrypted_out.size(), 0);
        }
    }
}

void ChatServer::handle_client_data(int client_fd) {
    unsigned char buffer[2048] = {0};
    int bytes_read = read(client_fd, buffer, sizeof(buffer));

    if (bytes_read > 0) {
        auto& client = clients[client_fd];

        if (client.sym_key.empty()) {
            // Prijeti symetrickeho klice
            std::vector<unsigned char> encrypted_sym_key(buffer, buffer + bytes_read);
            std::vector<unsigned char> decrypted_key = rsa_decrypt(server_keypair, encrypted_sym_key);

            if (!decrypted_key.empty()) {
                client.sym_key = decrypted_key;
                std::cout << "[SERVER] Handshake s FD " << client_fd << " uspesny.\n";

                // Vyzva k zadani prezdivky
                std::string prompt = "Zadej svou prezdivku:\n";
                std::vector<unsigned char> enc_prompt = aes_encrypt(prompt, client.sym_key);
                send(client_fd, enc_prompt.data(), enc_prompt.size(), 0);
            } else {
                std::cerr << "[CHYBA] Nepodarilo se desifrovat klic od klienta.\n";
                remove_client(client_fd);
            }
        }
        else if (!client.has_nickname) {
            // Ulozeni prezdivky
            std::vector<unsigned char> encrypted_msg(buffer, buffer + bytes_read);
            std::string name_input = aes_decrypt(encrypted_msg, client.sym_key);

            name_input.erase(std::remove(name_input.begin(), name_input.end(), '\n'), name_input.end());
            name_input.erase(std::remove(name_input.begin(), name_input.end(), '\r'), name_input.end());

            if (!name_input.empty()) {
                client.nickname = name_input;
                client.has_nickname = true;
                std::cout << "[SERVER] FD " << client_fd << " si nastavil prezdivku: " << client.nickname << "\n";

                // Oznameni o pripojeni uzivatele do chatu
                broadcast_message(client_fd, "*** " + client.nickname + " se pripojil(a) do chatu ***\n");
            }
        }
        else {
            // Zprava
            std::vector<unsigned char> encrypted_msg(buffer, buffer + bytes_read);
            std::string msg = aes_decrypt(encrypted_msg, client.sym_key);

            if (!msg.empty()) {
                std::string formatted_msg = "[" + client.nickname + "]: " + msg;
                std::cout << formatted_msg;
                broadcast_message(client_fd, formatted_msg);
            }
        }
    } else if (bytes_read == 0 || (bytes_read < 0 && errno != EAGAIN)) {
        remove_client(client_fd);
    }
}

void ChatServer::run() {
    const int MAX_EVENTS = 10;
    struct epoll_event events[MAX_EVENTS];

    std::cout << "[SERVER] Bezi asynchronne a ceka na portu 8080...\n";

    while (true) {
        int pocet_udalosti = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        for (int i = 0; i < pocet_udalosti; i++) {
            int aktivni_fd = events[i].data.fd;

            if (aktivni_fd == server_fd) {
                handle_new_connection();
            } else {
                handle_client_data(aktivni_fd);
            }
        }
    }
}
