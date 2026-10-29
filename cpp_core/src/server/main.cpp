#include "chat_server.hpp"

int main() {
    ChatServer server(8080);
    server.run();

    return 0;
}
