#pragma once
#include <unordered_map>
#include <string>
#include <vector>
#include <openssl/evp.h>

//Uzivatel
struct ClientNode {
    int fd;
    std::string nickname;
    std::vector<unsigned char> sym_key;
    bool has_nickname = false;
};

class ChatServer {
private:
    int server_fd;
    int epoll_fd;
    EVP_PKEY* server_keypair;

    // Pamet na klienty
    std::unordered_map<int, ClientNode> clients;

    // Privatni mody
    bool set_nonblocking(int socket_fd);
    void handle_new_connection();
    void handle_client_data(int client_fd);
    void remove_client(int client_fd);
    void broadcast_message(int sender_fd, const std::string& message);

public:
    ChatServer(int port);
    ~ChatServer();

    void run();
};
