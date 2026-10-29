#include "chat_client.hpp"

int main() {
    ChatClient client;
    client.start("127.0.0.1", 8080);
    return 0;
}
