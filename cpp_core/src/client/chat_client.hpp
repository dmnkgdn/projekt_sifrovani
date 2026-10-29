#pragma once
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <openssl/evp.h>

class ChatClient {
private:
    int client_socket;
    std::vector<unsigned char> sym_key;

    std::atomic<bool> is_running;
    std::thread receiver_thread;

    // Privátní pomocné metody
    bool connect_to_server(const std::string& ip, int port);
    bool perform_handshake();
    void receive_messages_loop();

public:
    ChatClient();
    ~ChatClient();

    void start(const std::string& ip, int port);
};
