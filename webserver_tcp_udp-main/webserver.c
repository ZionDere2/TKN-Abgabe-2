#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "data.h"
#include "http.h"
#include "util.h"

#define MAX_RESOURCES 100

struct tuple resources[MAX_RESOURCES] = {
    {"/static/foo", "Foo", sizeof "Foo" - 1},
    {"/static/bar", "Bar", sizeof "Bar" - 1},
    {"/static/baz", "Baz", sizeof "Baz" - 1}};

struct node_info {
    uint16_t id;
    const char *ip;
    const char *port;
};

struct dht_message {
    uint8_t flags;
    uint16_t id;
    struct node_info peer;
};

static struct sockaddr_in derive_sockaddr(const char *host, const char *port);

static struct node_info self_node;
static struct node_info pred_node;
static struct node_info succ_node;
static char succ_ip_buf[INET_ADDRSTRLEN];
static char succ_port_buf[6];
static char pred_ip_buf[INET_ADDRSTRLEN];
static char pred_port_buf[6];
static int server_socket_udp = -1;

static void init_neighbor(struct node_info *node, const char *id_env,
                          const char *ip_env, const char *port_env) {
    const char *id_value = getenv(id_env);
    const char *ip_value = getenv(ip_env);
    const char *port_value = getenv(port_env);

    // If no environment is provided, fall back to self (single-node setup).
    if (!id_value || !ip_value || !port_value) {
        node->id = self_node.id;
        node->ip = self_node.ip;
        node->port = self_node.port;
        return;
    }

    char message[64];
    snprintf(message, sizeof message, "Error parsing %s", id_env);

    node->id = safe_strtoul(id_value, NULL, 10, message);
    node->ip = ip_value;
    node->port = port_value;
}

static bool in_range(uint16_t start, uint16_t end, uint16_t value) {
    if (start < end) {
        return value > start && value <= end;
    }
    return value > start || value <= end;
}

static bool is_responsible(uint16_t hash) {
    if (self_node.id == pred_node.id) {
        return true;
    }

    return in_range(pred_node.id, self_node.id, hash);
}

static bool successor_responsible(uint16_t hash) {
    return in_range(self_node.id, succ_node.id, hash);
}

static bool minimal_lookup_configuration(void) {
    return self_node.id == 0 && pred_node.id == 0xffff && succ_node.id == 1;
}

static void serialize_dht(const struct dht_message *msg, unsigned char *buffer) {
    uint8_t flags = msg->flags;
    uint16_t id = htons(msg->id);
    uint16_t peer_id = htons(msg->peer.id);
    uint16_t peer_port = htons((uint16_t)safe_strtoul(msg->peer.port, NULL, 10,
                                                     "Error parsing peer port"));

    struct in_addr addr = {0};
    inet_aton(msg->peer.ip, &addr);

    buffer[0] = flags;
    memcpy(buffer + 1, &id, sizeof(id));
    memcpy(buffer + 3, &peer_id, sizeof(peer_id));
    memcpy(buffer + 5, &addr, sizeof(addr));
    memcpy(buffer + 9, &peer_port, sizeof(peer_port));
}

static struct dht_message deserialize_dht(const unsigned char *buffer) {
    struct dht_message msg = {0};
    uint16_t id;
    uint16_t peer_id;
    uint16_t peer_port;
    struct in_addr addr;

    msg.flags = buffer[0];
    memcpy(&id, buffer + 1, sizeof(id));
    memcpy(&peer_id, buffer + 3, sizeof(peer_id));
    memcpy(&addr, buffer + 5, sizeof(addr));
    memcpy(&peer_port, buffer + 9, sizeof(peer_port));

    msg.id = ntohs(id);
    msg.peer.id = ntohs(peer_id);
    msg.peer.ip = inet_ntoa(addr);

    static char port_buf[6];
    snprintf(port_buf, sizeof port_buf, "%u", ntohs(peer_port));
    msg.peer.port = port_buf;

    return msg;
}

static void send_dht_message(int sock, const struct dht_message *msg,
                             const struct sockaddr_in *target) {
    unsigned char buffer[11] = {0};
    serialize_dht(msg, buffer);
    sendto(sock, buffer, sizeof(buffer), 0, (const struct sockaddr *)target,
           sizeof(*target));
}

static void handle_dht_message(const struct dht_message *msg,
                               const struct sockaddr_in *sender) {
    if (msg->flags == 0) { // lookup
        if (successor_responsible(msg->id)) {
            struct dht_message reply = {.flags = 1,
                                       .id = self_node.id,
                                       .peer = succ_node};
            unsigned char buffer[11] = {0};
            serialize_dht(&reply, buffer);
            sendto(server_socket_udp, buffer, sizeof(buffer), 0,
                   (const struct sockaddr *)sender, sizeof(*sender));
        } else if (is_responsible(msg->id)) {
            struct dht_message reply = {.flags = 1,
                                       .id = pred_node.id,
                                       .peer = self_node};
            unsigned char buffer[11] = {0};
            serialize_dht(&reply, buffer);
            sendto(server_socket_udp, buffer, sizeof(buffer), 0,
                   (const struct sockaddr *)sender, sizeof(*sender));
        } else {
            struct sockaddr_in succ_addr =
                derive_sockaddr(succ_node.ip, succ_node.port);
            send_dht_message(server_socket_udp, msg, &succ_addr);
        }
    } else if (msg->flags == 1) { // reply
        // Update routing hints: treat replied peer as both predecessor and successor
        succ_node.id = msg->peer.id;
        strncpy(succ_ip_buf, msg->peer.ip, sizeof(succ_ip_buf) - 1);
        succ_ip_buf[sizeof(succ_ip_buf) - 1] = '\0';
        strncpy(succ_port_buf, msg->peer.port, sizeof(succ_port_buf) - 1);
        succ_port_buf[sizeof(succ_port_buf) - 1] = '\0';
        succ_node.ip = succ_ip_buf;
        succ_node.port = succ_port_buf;

        pred_node.id = msg->peer.id;
        strncpy(pred_ip_buf, msg->peer.ip, sizeof(pred_ip_buf) - 1);
        pred_ip_buf[sizeof(pred_ip_buf) - 1] = '\0';
        strncpy(pred_port_buf, msg->peer.port, sizeof(pred_port_buf) - 1);
        pred_port_buf[sizeof(pred_port_buf) - 1] = '\0';
        pred_node.ip = pred_ip_buf;
        pred_node.port = pred_port_buf;
    }
}

/**
 * Sends an HTTP reply to the client based on the received request.
 *
 * @param conn      The file descriptor of the client connection socket.
 * @param request   A pointer to the struct containing the parsed request
 * information.
 */
void send_reply(int conn, struct request *request) {

    // Create a buffer to hold the HTTP reply
    char buffer[HTTP_MAX_SIZE];
    char *reply = buffer;
    size_t offset = 0;

    uint16_t resource_hash =
        pseudo_hash((const unsigned char *)request->uri, strlen(request->uri));

    fprintf(stderr, "Handling %s request for %s (%lu byte payload)\n",
            request->method, request->uri, request->payload_length);

    if (!is_responsible(resource_hash)) {
        if (minimal_lookup_configuration()) {
            struct sockaddr_in succ_addr =
                derive_sockaddr(succ_node.ip, succ_node.port);

            struct dht_message lookup = {0};
            lookup.flags = 0; // lookup
            lookup.id = resource_hash;
            lookup.peer = self_node;

            send_dht_message(server_socket_udp, &lookup, &succ_addr);

            offset = sprintf(reply,
                             "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n");
        } else {
            offset = sprintf(
                reply,
                "HTTP/1.1 303 See Other\r\nLocation: http://%s:%s%s\r\nContent-Length: 0\r\n\r\n",
                succ_node.ip, succ_node.port, request->uri);
        }
    } else if (strcmp(request->method, "GET") == 0) {
        // Find the resource with the given URI in the 'resources' array.
        size_t resource_length;
        const char *resource =
            get(request->uri, resources, MAX_RESOURCES, &resource_length);

        if (resource) {
            size_t payload_offset =
                sprintf(reply, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n",
                        resource_length);
            memcpy(reply + payload_offset, resource, resource_length);
            offset = payload_offset + resource_length;
        } else {
            reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            offset = strlen(reply);
        }
    } else if (strcmp(request->method, "PUT") == 0) {
        // Try to set the requested resource with the given payload in the
        // 'resources' array.
        if (set(request->uri, request->payload, request->payload_length,
                resources, MAX_RESOURCES)) {
            reply = "HTTP/1.1 204 No Content\r\n\r\n";
        } else {
            reply = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
        }
        offset = strlen(reply);
    } else if (strcmp(request->method, "DELETE") == 0) {
        // Try to delete the requested resource from the 'resources' array
        if (delete (request->uri, resources, MAX_RESOURCES)) {
            reply = "HTTP/1.1 204 No Content\r\n\r\n";
        } else {
            reply = "HTTP/1.1 404 Not Found\r\n\r\n";
        }
        offset = strlen(reply);
    } else {
        reply = "HTTP/1.1 501 Method Not Supported\r\n\r\n";
        offset = strlen(reply);
    }

    // Send the reply back to the client
    if (send(conn, reply, offset, 0) == -1) {
        perror("send");
        close(conn);
    }
}

/**
 * Processes an incoming packet from the client.
 *
 * @param conn The socket descriptor representing the connection to the client.
 * @param buffer A pointer to the incoming packet's buffer.
 * @param n The size of the incoming packet.
 *
 * @return Returns the number of bytes processed from the packet.
 *         If the packet is successfully processed and a reply is sent, the
 * return value indicates the number of bytes processed. If the packet is
 * malformed or an error occurs during processing, the return value is -1.
 *
 */
ssize_t process_packet(int conn, char *buffer, size_t n) {
    struct request request = {
        .method = NULL, .uri = NULL, .payload = NULL, .payload_length = -1};
    ssize_t bytes_processed = parse_request(buffer, n, &request);

    if (bytes_processed > 0) {
        send_reply(conn, &request);

        // Check the "Connection" header in the request to determine if the
        // connection should be kept alive or closed.
        const string connection_header = get_header(&request, "Connection");
        if (connection_header && strcmp(connection_header, "close")) {
            return -1;
        }
    } else if (bytes_processed == -1) {
        // If the request is malformed or an error occurs during processing,
        // send a 400 Bad Request response to the client.
        const string bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(conn, bad_request, strlen(bad_request), 0);
        printf("Received malformed request, terminating connection.\n");
        close(conn);
        return -1;
    }

    return bytes_processed;
}

/**
 * Sets up the connection state for a new socket connection.
 *
 * @param state A pointer to the connection_state structure to be initialized.
 * @param sock The socket descriptor representing the new connection.
 *
 */
static void connection_setup(struct connection_state *state, int sock) {
    // Set the socket descriptor for the new connection in the connection_state
    // structure.
    state->sock = sock;

    // Set the 'end' pointer of the state to the beginning of the buffer.
    state->end = state->buffer;

    // Clear the buffer by filling it with zeros to avoid any stale data.
    memset(state->buffer, 0, HTTP_MAX_SIZE);
}

/**
 * Discards the front of a buffer
 *
 * @param buffer A pointer to the buffer to be modified.
 * @param discard The number of bytes to drop from the front of the buffer.
 * @param keep The number of bytes that should be kept after the discarded
 * bytes.
 *
 * @return Returns a pointer to the first unused byte in the buffer after the
 * discard.
 * @example buffer_discard(ABCDEF0000, 4, 2):
 *          ABCDEF0000 ->  EFCDEF0000 -> EF00000000, returns pointer to first 0.
 */
char *buffer_discard(char *buffer, size_t discard, size_t keep) {
    memmove(buffer, buffer + discard, keep);
    memset(buffer + keep, 0, discard); // invalidate buffer
    return buffer + keep;
}

/**
 * Handles incoming connections and processes data received over the socket.
 *
 * @param state A pointer to the connection_state structure containing the
 * connection state.
 * @return Returns true if the connection and data processing were successful,
 * false otherwise. If an error occurs while receiving data from the socket, the
 * function exits the program.
 */
bool handle_connection(struct connection_state *state) {
    // Calculate the pointer to the end of the buffer to avoid buffer overflow
    const char *buffer_end = state->buffer + HTTP_MAX_SIZE;

    // Check if an error occurred while receiving data from the socket
    ssize_t bytes_read =
        recv(state->sock, state->end, buffer_end - state->end, 0);
    if (bytes_read == -1) {
        perror("recv");
        close(state->sock);
        exit(EXIT_FAILURE);
    } else if (bytes_read == 0) {
        return false;
    }

    char *window_start = state->buffer;
    char *window_end = state->end + bytes_read;

    ssize_t bytes_processed = 0;
    while ((bytes_processed = process_packet(state->sock, window_start,
                                             window_end - window_start)) > 0) {
        window_start += bytes_processed;
    }
    if (bytes_processed == -1) {
        return false;
    }

    state->end = buffer_discard(state->buffer, window_start - state->buffer,
                                window_end - window_start);
    return true;
}

/**
 * Derives a sockaddr_in structure from the provided host and port information.
 *
 * @param host The host (IP address or hostname) to be resolved into a network
 * address.
 * @param port The port number to be converted into network byte order.
 *
 * @return A sockaddr_in structure representing the network address derived from
 * the host and port.
 */
static struct sockaddr_in derive_sockaddr(const char *host, const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
    };
    struct addrinfo *result_info;

    // Resolve the host (IP address or hostname) into a list of possible
    // addresses.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode) {
        fprintf(stderr, "Error parsing host/port");
        exit(EXIT_FAILURE);
    }

    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in *)result_info->ai_addr);

    // Free the allocated memory for the result_info
    freeaddrinfo(result_info);
    return result;
}

/**
 * Sets up a TCP server socket and binds it to the provided sockaddr_in address.
 *
 * @param addr The sockaddr_in structure representing the IP address and port of
 * the server.
 *
 * @return The file descriptor of the created TCP server socket.
 */
static int setup_server_socket(struct sockaddr_in addr) {
    const int enable = 1;
    const int backlog = 1;

    // Create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Avoid dead lock on connections that are dropped after poll returns but
    // before accept is called
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    // Set the SO_REUSEADDR socket option to allow reuse of local addresses
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) ==
        -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind socket to the provided address
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Start listening on the socket with maximum backlog of 1 pending
    // connection
    if (listen(sock, backlog)) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return sock;
}
static int setup_udp_server_socket(struct sockaddr_in addr) {
    // Create a socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Avoid dead lock on connections that are dropped after poll returns but
    // before accept is called
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    // Bind socket to the provided address
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Start listening on the socket with maximum backlog of 1 pending
    // connection
    /*if (listen(sock, backlog)) {
        perror("listen");
        exit(EXIT_FAILURE);
    }*/

    return sock;
}   //Aufgabe 1.1


/**
 *  The program expects 2 or 3 parameters; otherwise, it returns EXIT_FAILURE.
 *
 *  Call as:
 *
 *  ./build/webserver self.ip self.port [self.id]
 */
int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) {
        return EXIT_FAILURE;
    }

    self_node.ip = argv[1];
    self_node.port = argv[2];

    const char *self_id_value = argc == 4 ? argv[3] : "0";
    self_node.id = safe_strtoul(self_id_value, NULL, 10,
                                "Error parsing own node id");

    init_neighbor(&pred_node, "PRED_ID", "PRED_IP", "PRED_PORT");
    init_neighbor(&succ_node, "SUCC_ID", "SUCC_IP", "SUCC_PORT");

    strncpy(pred_ip_buf, pred_node.ip, sizeof(pred_ip_buf) - 1);
    pred_ip_buf[sizeof(pred_ip_buf) - 1] = '\0';
    strncpy(pred_port_buf, pred_node.port, sizeof(pred_port_buf) - 1);
    pred_port_buf[sizeof(pred_port_buf) - 1] = '\0';
    pred_node.ip = pred_ip_buf;
    pred_node.port = pred_port_buf;

    strncpy(succ_ip_buf, succ_node.ip, sizeof(succ_ip_buf) - 1);
    succ_ip_buf[sizeof(succ_ip_buf) - 1] = '\0';
    strncpy(succ_port_buf, succ_node.port, sizeof(succ_port_buf) - 1);
    succ_port_buf[sizeof(succ_port_buf) - 1] = '\0';
    succ_node.ip = succ_ip_buf;
    succ_node.port = succ_port_buf;

    struct sockaddr_in addr = derive_sockaddr(self_node.ip, self_node.port);

    // Set up a server socket.
    int server_socket = setup_server_socket(addr);
    server_socket_udp = setup_udp_server_socket(addr);  //Aufgabe 1.1

    struct pollfd sockets[3] = {
        {.fd = server_socket, .events = POLLIN},
        {.fd = server_socket_udp, .events = POLLIN},
        {.fd = -1, .events = POLLIN},
    };

    struct connection_state state = {0};
    while (true) {
        int ready = poll(sockets, sizeof(sockets) / sizeof(sockets[0]), -1);
        if (ready == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        for (size_t i = 0; i < sizeof(sockets) / sizeof(sockets[0]); i += 1) {
            if (sockets[i].revents != POLLIN) {
                continue;
            }

            int s = sockets[i].fd;

            if (s == server_socket) {
                int connection = accept(server_socket, NULL, NULL);
                if (connection == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(server_socket);
                    perror("accept");
                    exit(EXIT_FAILURE);
                }

                connection_setup(&state, connection);
                sockets[2].fd = connection;
                sockets[2].events = POLLIN;
            } else if (s == server_socket_udp) {
                unsigned char RecvBuf[HTTP_MAX_SIZE];
                struct sockaddr_in SenderAddr;
                socklen_t sender_addrlen = sizeof(SenderAddr);

                ssize_t received = recvfrom(server_socket_udp, RecvBuf, HTTP_MAX_SIZE, 0,
                                            (struct sockaddr *)&SenderAddr, &sender_addrlen);
                if (received >= 11) {
                    struct dht_message msg = deserialize_dht(RecvBuf);
                    handle_dht_message(&msg, &SenderAddr);
                }
            } else if (s == sockets[2].fd) {
                assert(s == state.sock);
                bool cont = handle_connection(&state);
                if (!cont) {
                    sockets[2].fd = -1;
                    sockets[2].events = POLLIN;
                }
            }
        }
    }
    return EXIT_SUCCESS;
}
