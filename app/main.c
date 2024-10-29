#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PEER_ID "-PC0001-123456789012"
#define DEFAULT_PORT 6881

// Error handling macro
#define HANDLE_ERROR(condition, msg)                           \
    do {                                                       \
        if(condition) {                                        \
            fprintf(stderr, "%s: %s\n", msg, strerror(errno)); \
            exit(1);                                           \
        }                                                      \
    } while(0)

typedef struct {
    unsigned char* name;
    int length;
    int piece_length;
    unsigned char* pieces;
    int pieces_size;
} TorrentInfoDict;

typedef struct {
    unsigned char* announce;
    unsigned char* created_by;
    TorrentInfoDict info;
    unsigned char infohash[SHA_DIGEST_LENGTH];
    int uploaded;
    int downloaded;
} TorrentMetadata;

typedef struct {
    int interval;
    int min_interval;
    int complete;
    int incomplete;
    unsigned char* peers;
    int peer_count;
} TrackerResponse;

typedef union {
    unsigned char raw[48 + SHA_DIGEST_LENGTH];
    struct {
        unsigned char protocol_length;
        char protocol[19];
        unsigned char reserved[8];
        unsigned char infohash[SHA_DIGEST_LENGTH];
        char peer_id[20];
    } parts;
} Handshake;

typedef struct {
    uint32_t length;  // 4 bytes
    uint8_t id;       // 1 byte
    unsigned char* payload;
} PeerMessage;


typedef struct {
    unsigned char* data;
    size_t length;
    bool* received;
    int num_blocks;
} PieceData;

void* safe_malloc(size_t size, const char* context);
bool is_digit(char c);
char* decode_string(const char* data, int* index, int length);
char* decode_integer(const char* data, int* index);
char* decode_list(const char* data, int* index);
char* decode_dictionary(const char* data, int* index);
char* decode_bencode(const char* data, int* index);
int extract_int(const char* encoded_str, const char* key);
TorrentMetadata decode_torrent(const char* encoded_str);
char* read_file(const char* filename);
static size_t tracker_callback(void* contents, size_t size, size_t nmemb, void* userp);
TrackerResponse contact_tracker(const TorrentMetadata* torrent);
unsigned char* byte_to_ip(const unsigned char* peers);
void hex(const char* header, const unsigned char* src, const int size);
PeerMessage receive_peer_message(int sockfd);
void send_peer_message(int sockfd, uint8_t id, const unsigned char* payload, uint32_t payload_length);
void download_piece(const char* output_file, const TorrentMetadata* torrent, int piece_index, const char* peer_addr);
PieceData* init_piece_data(int piece_length);
void free_piece_data(PieceData* piece);
bool verify_piece(const unsigned char* piece_data, size_t piece_length, const unsigned char* expected_hash);

void* safe_malloc(size_t size, const char* context) {
    void* ptr = malloc(size);
    if(!ptr) {
        fprintf(stderr, "Memory allocation failed for %s: %s\n",
        context, strerror(errno));
        exit(2);
    }
    return ptr;
}

bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

char* decode_string(const char* data, int* index, int length) {
    char* decoded_str = (char*)safe_malloc(length + 3, "decode_string");

    decoded_str[0] = '"';
    memcpy(decoded_str + 1, data + *index, length);
    decoded_str[length + 1] = '"';
    decoded_str[length + 2] = '\0';

    *index += length;
    return decoded_str;
}

char* decode_integer(const char* data, int* index) {
    (*index)++;  // Skip 'i'
    int start = *index;
    while(data[*index] != 'e' && (is_digit(data[*index]) || data[*index] == '-')) (*index)++;
    int length        = *index - start;
    char* decoded_str = (char*)safe_malloc(length + 1, "decode_integer");
    memcpy(decoded_str, data + start, length);
    decoded_str[length] = '\0';
    (*index)++;  // Skip 'e'
    return decoded_str;
}

char* decode_list(const char* data, int* index) {
    (*index)++;  // // Skip 'l'
    size_t buffer_size = strlen(data) + 3;
    char* decoded_str  = safe_malloc(buffer_size, "decoder string for list");
    strcpy(decoded_str, "[");

    bool first_element = true;
    while(data[*index] != 'e') {
        if(!first_element) strcat(decoded_str, ",");
        first_element = false;

        char* element = decode_bencode(data, index);
        strcat(decoded_str, element);
        free(element);
    }
    (*index)++;  // Skip 'e'
    strcat(decoded_str, "]");
    return decoded_str;
}

char* decode_dictionary(const char* data, int* index) {
    (*index)++;  // Skip 'd'
    size_t buffer_size = strlen(data) + 3;
    char* decoded_str  = safe_malloc(buffer_size, "decoder string for dictionary");
    strcpy(decoded_str, "{");

    bool first_element = true;
    while(data[*index] != 'e') {
        if(!first_element) strcat(decoded_str, ",");
        first_element = false;

        char* key = decode_bencode(data, index);
        strcat(decoded_str, key);

        strcat(decoded_str, ":");

        char* value = decode_bencode(data, index);
        strcat(decoded_str, value);

        free(key);
        free(value);
    }
    (*index)++;  // Skip 'e'
    strcat(decoded_str, "}");
    return decoded_str;
}

char* decode_bencode(const char* data, int* index) {
    char type = data[*index];
    if(is_digit(type)) {
        int length = atoi(data + *index);
        while(is_digit(data[*index])) (*index)++;
        (*index)++;  // Skip ':'
        return decode_string(data, index, length);
    }
    switch(type) {
    case 'i': return decode_integer(data, index);
    case 'l': return decode_list(data, index);
    case 'd': return decode_dictionary(data, index);
    default:
        fprintf(stderr, "Unsupported bencoded type: %c\n", type);
        exit(3);
    }
}

int extract_int(const char* encoded_str, const char* key) {
    int index = 0;
    char* tmp = decode_integer(strstr(encoded_str, key) + strlen(key), &index);
    int ret   = atoi(tmp);

    free(tmp);
    return ret;
}

void extract_str(const char* encoded_str, const char* key, int* len, unsigned char** bin) {
    if(strstr(encoded_str, key) >= 0) {
        const char* val_start = strstr(encoded_str, key) + strlen(key);
        char* start           = strstr(val_start, ":") + 1;
        *len                  = atoi(val_start);
        *bin                  = safe_malloc(*len + 1, "extract_str");
        memcpy(*bin, start, *len);
        (*bin)[*len] = '\0';
    } else {
        *len      = 1;
        *bin      = safe_malloc(*len, "null extract_str");
        (*bin)[0] = '\0';
    }
}

TorrentMetadata decode_torrent(const char* encoded_str) {
    TorrentMetadata torrent;
    int tmp_len;

    // printf("%s\n", encoded_str);

    extract_str(encoded_str, "4:name", &tmp_len, &torrent.info.name);
    extract_str(encoded_str, "10:created by", &tmp_len, &torrent.created_by);
    extract_str(encoded_str, "8:announce", &tmp_len, &torrent.announce);
    torrent.info.length       = extract_int(encoded_str, "6:length");
    torrent.info.piece_length = extract_int(encoded_str, "12:piece length");
    extract_str(encoded_str, "6:pieces", &torrent.info.pieces_size, &torrent.info.pieces);

    torrent.uploaded   = 0;
    torrent.downloaded = 0;

    // reencode bencode
    int info_bencoded_len        = snprintf(NULL, 0, "d6:lengthi%de4:name%d:%s12:piece lengthi%de6:pieces%d:", torrent.info.length, strlen(torrent.info.name), torrent.info.name, torrent.info.piece_length, torrent.info.pieces_size);
    unsigned char* info_bencoded = safe_malloc(info_bencoded_len + torrent.info.pieces_size + 2, "for calculating infohash");  // +2 for 'e' + null
    sprintf(info_bencoded, "d6:lengthi%de4:name%d:%s12:piece lengthi%de6:pieces%d:", torrent.info.length, strlen(torrent.info.name), torrent.info.name, torrent.info.piece_length, torrent.info.pieces_size);
    memcpy(info_bencoded + info_bencoded_len, torrent.info.pieces, torrent.info.pieces_size);
    info_bencoded[info_bencoded_len + torrent.info.pieces_size]     = 'e';
    info_bencoded[info_bencoded_len + torrent.info.pieces_size + 1] = '\0';

    SHA1(info_bencoded, info_bencoded_len + torrent.info.pieces_size + 1, torrent.infohash);

    free(info_bencoded);
    return torrent;
}

char* read_file(const char* filename) {
    FILE* file = fopen(filename, "rb");
    HANDLE_ERROR(!file, "Failed to open file");

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = safe_malloc(file_size + 1, "file -> buffer");

    size_t bytes_read = fread(buffer, 1, file_size, file);
    HANDLE_ERROR(bytes_read != file_size, "File read failed");

    buffer[bytes_read] = '\0';
    fclose(file);
    return buffer;
}

static size_t tracker_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    TrackerResponse* response = (TrackerResponse*)userp;

    response->interval     = extract_int(contents, "8:interval");
    response->min_interval = extract_int(contents, "12:min interval");
    response->complete     = extract_int(contents, "8:complete");
    response->incomplete   = extract_int(contents, "10:incomplete");

    extract_str(contents, "5:peers", &response->peer_count, &response->peers);

    return size * nmemb;
}

TrackerResponse contact_tracker(const TorrentMetadata* torrent) {
    CURL* curl = curl_easy_init();
    HANDLE_ERROR(!curl, "CURL initialization failed");

    // Build tracker URL with proper escaping
    char* escaped_infohash = curl_easy_escape(curl, (char*)torrent->infohash, 20);
    char* escaped_peer_id  = curl_easy_escape(curl, PEER_ID, 20);

    char url[512];
    snprintf(url, sizeof(url),
    "%s?info_hash=%s&peer_id=%s&port=%d&uploaded=%d&downloaded=%d&left=%d&compact=1",
    torrent->announce, escaped_infohash, escaped_peer_id, DEFAULT_PORT, torrent->uploaded, torrent->downloaded, (torrent->info.length - torrent->downloaded));

    TrackerResponse response = { 0 };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tracker_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    HANDLE_ERROR(res != CURLE_OK, curl_easy_strerror(res));

    curl_free(escaped_infohash);
    curl_free(escaped_peer_id);
    curl_easy_cleanup(curl);

    return response;
}

unsigned char* byte_to_ip(const unsigned char* peers) {
    static unsigned char ip[22];

    unsigned char ip1 = peers[0];
    unsigned char ip2 = peers[1];
    unsigned char ip3 = peers[2];
    unsigned char ip4 = peers[3];
    uint16_t port     = (peers[4] << 8) | peers[5];  // 2 bytes for port

    snprintf((char*)ip, sizeof(ip), "%d.%d.%d.%d:%d", ip1, ip2, ip3, ip4, port);

    return ip;
}

void hex(const char* header, const unsigned char* src, const int size) {
    printf("%s: ", header);
    for(size_t i = 0; i < size; i++) {
        printf("%02x", src[i]);
    }
    printf("\n");
}

// Implementation of peer message functions
PeerMessage receive_peer_message(int sockfd) {
    printf("<");

    PeerMessage msg = { 0 };

    // Read message length (4 bytes)
    uint32_t length_n;
    if(recv(sockfd, &length_n, 4, MSG_WAITALL) != 4) {
        perror("Failed to receive message length");
        exit(4);
    }
    msg.length = ntohl(length_n);

    if(msg.length > 0) {
        // Read message id (1 byte)
        if(recv(sockfd, &msg.id, 1, MSG_WAITALL) != 1) {
            perror("Failed to receive message id");
            exit(5);
        }

        // Read payload if present
        if(msg.length > 1) {
            msg.payload = safe_malloc(msg.length - 1, "peer message payload");
            if(recv(sockfd, msg.payload, msg.length - 1, MSG_WAITALL) != msg.length - 1) {
                perror("Failed to receive message payload");
                exit(6);
            }
        }
    }

    return msg;
}

void send_peer_message(int sockfd, uint8_t id, const unsigned char* payload, uint32_t payload_length) {
    printf(">");

    // Total message length = id (1 byte) + payload length
    uint32_t length   = payload_length + 1;
    uint32_t length_n = htonl(length);

    // Send length prefix
    if(send(sockfd, &length_n, 4, 0) != 4) {
        perror("Failed to send message length");
        exit(7);
    }

    // Send message id
    if(send(sockfd, &id, 1, 0) != 1) {
        perror("Failed to send message id");
        exit(8);
    }

    // Send payload if present
    if(payload_length > 0) {
        if(send(sockfd, payload, payload_length, 0) != payload_length) {
            perror("Failed to send message payload");
            exit(9);
        }
    }
}

void download_piece(const char* output_file, const TorrentMetadata* torrent, int piece_index, const char* peer_addr) {
    // Parse peer address
    char* colon_pos = strchr(peer_addr, ':');
    if(!colon_pos) {
        fprintf(stderr, "Invalid peer address format\n");
        exit(15);
    }

    char ip[16];
    strncpy(ip, peer_addr, colon_pos - peer_addr);
    ip[colon_pos - peer_addr] = '\0';
    int port                  = atoi(colon_pos + 1);

    // Connect and perform handshake
    int sockfd                     = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port)
    };

    if(inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(16);
    }

    if(connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(17);
    }

    // Send handshake
    Handshake handshake             = { 0 };
    handshake.parts.protocol_length = 19;
    strncpy(handshake.parts.protocol, "BitTorrent protocol", 19);
    memcpy(handshake.parts.infohash, torrent->infohash, SHA_DIGEST_LENGTH);
    strncpy(handshake.parts.peer_id, PEER_ID, 20);

    hex("Handshake Message", handshake.raw, sizeof(handshake.raw));

    if(send(sockfd, handshake.raw, sizeof(handshake.raw), 0) != sizeof(handshake.raw)) {
        perror("Failed to send handshake");
        exit(18);
    }

    // Receive handshake
    Handshake response;
    if(recv(sockfd, response.raw, sizeof(response.raw), MSG_WAITALL) != sizeof(response.raw)) {
        perror("Failed to receive handshake");
        exit(19);
    }
    hex("Response Message", response.raw, sizeof(response.raw));

    // Wait for bitfield
    PeerMessage msg = receive_peer_message(sockfd);
    if(msg.id != 5) {  // bitfield
        fprintf(stderr, "Expected bitfield message\n");
        exit(20);
    }
    free(msg.payload);

    // Send interested message
    send_peer_message(sockfd, 2, NULL, 0);

    // Wait for unchoke
    msg = receive_peer_message(sockfd);
    if(msg.id != 1) {  // unchoke
        fprintf(stderr, "Expected unchoke message\n");
        exit(21);
    }

    // Calculate piece length and number of blocks
    int piece_length = (piece_index == torrent->info.length / torrent->info.piece_length) ? (torrent->info.length % torrent->info.piece_length) : torrent->info.piece_length;

    int num_blocks   = (piece_length + 16383) / 16384;  // ceil(piece_length / 16384)
    PieceData* piece = init_piece_data(piece_length);

    // Request each block
    for(int block = 0; block < num_blocks; block++) {
        int block_length = (block == num_blocks - 1) ? (piece_length - block * 16384) : 16384;

        // Prepare request message payload
        unsigned char request_payload[12];
        uint32_t index_n  = htonl(piece_index);
        uint32_t begin_n  = htonl(block * 16384);
        uint32_t length_n = htonl(block_length);

        memcpy(request_payload, &index_n, 4);
        memcpy(request_payload + 4, &begin_n, 4);
        memcpy(request_payload + 8, &length_n, 4);

        // Send request
        send_peer_message(sockfd, 6, request_payload, 12);

        // Receive piece
        msg = receive_peer_message(sockfd);
        if(msg.id != 7) {  // piece
            fprintf(stderr, "Expected piece message\n");
            exit(22);
        }

        // Copy block data to piece buffer
        uint32_t block_index = ntohl(*(uint32_t*)(msg.payload + 4));
        memcpy(piece->data + block_index, msg.payload + 8, block_length);
        piece->received[block] = true;
        free(msg.payload);
    }
    printf("\n\n");

    // Verify piece hash
    if(!verify_piece(piece->data, piece_length,
       torrent->info.pieces + (piece_index * SHA_DIGEST_LENGTH))) {
        fprintf(stderr, "Piece verification failed\n");
        free_piece_data(piece);
        exit(23);
    }

    // Save piece to file
    FILE* output = fopen(output_file, "wb");
    if(!output) {
        perror("Failed to open output file");
        free_piece_data(piece);
        exit(24);
    }

    fwrite(piece->data, 1, piece_length, output);
    fclose(output);
    printf("Piece %d downloaded to %s\n", piece_index, output_file);

    free_piece_data(piece);
    close(sockfd);
}

PieceData* init_piece_data(int piece_length) {
    PieceData* piece  = safe_malloc(sizeof(PieceData), "piece data struct");
    piece->data       = safe_malloc(piece_length, "piece data buffer");
    piece->length     = piece_length;
    piece->num_blocks = (piece_length + 16383) / 16384;
    piece->received   = safe_malloc(piece->num_blocks * sizeof(bool), "block received flags");
    memset(piece->received, 0, piece->num_blocks * sizeof(bool));
    return piece;
}

void free_piece_data(PieceData* piece) {
    free(piece->data);
    free(piece->received);
    free(piece);
}

bool verify_piece(const unsigned char* piece_data, size_t piece_length, const unsigned char* expected_hash) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(piece_data, piece_length, hash);
    hex("expeced", expected_hash, SHA_DIGEST_LENGTH);
    hex("got", hash, SHA_DIGEST_LENGTH);

    return memcmp(hash, expected_hash, SHA_DIGEST_LENGTH) == 0;
}

int main(int argc, char* argv[]) {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // help menu
    if(argc < 3) {
        fprintf(stderr, "Usage: your_bittorrent.sh <command> <args>\n");
        return 25;
    }

    int index           = 0;
    const char* command = argv[1];
    const char* encoded_str;

    // switch
    if(strcmp(command, "decode") == 0) {
        encoded_str = argv[2];

        char* decoded_str = decode_bencode(encoded_str, &index);
        printf("%s\n", decoded_str);

        free(decoded_str);
    } else if(strcmp(command, "info") == 0) {
        encoded_str             = read_file(argv[2]);
        TorrentMetadata torrent = decode_torrent(encoded_str);

        printf("Name: %s\n", torrent.info.name);
        printf("Created By: %s\n", torrent.created_by);
        printf("Tracker URL: %s\n", torrent.announce);
        printf("Length: %d\n", torrent.info.length);
        printf("Info Hash: ");
        for(int i = 0; i < SHA_DIGEST_LENGTH; i++) printf("%02x", torrent.infohash[i]);
        printf("\n");
        printf("Piece Length: %d\n", torrent.info.piece_length);
        printf("Piece Hashes:");
        for(int i = 0; i < torrent.info.pieces_size; i++) {
            if(i % SHA_DIGEST_LENGTH == 0) printf("\n");
            printf("%02x", torrent.info.pieces[i]);
        }
        printf("\n");

        free(torrent.announce);
        free(torrent.info.name);
        free(torrent.info.pieces);
    } else if(strcmp(command, "peers") == 0) {
        encoded_str             = read_file(argv[2]);
        TorrentMetadata torrent = decode_torrent(encoded_str);
        TrackerResponse tres    = contact_tracker(&torrent);

        for(size_t i = 0; i < tres.peer_count; i += 6) {
            printf("%s\n", byte_to_ip(tres.peers + i));
        }

        free(torrent.announce);
        free(torrent.info.name);
        free(torrent.info.pieces);
        free(tres.peers);
    } else if(strcmp(command, "handshake") == 0) {
        encoded_str             = read_file(argv[2]);
        TorrentMetadata torrent = decode_torrent(encoded_str);

        unsigned char* ip_port = argv[3];

        if(argc < 4) {
            TrackerResponse tres = contact_tracker(&torrent);
            if(tres.peer_count < 6) {
                fprintf(stderr, "No peers available\n");
                return 26;
            }
            ip_port = byte_to_ip(tres.peers);
            free(tres.peers);
        }

        if(!ip_port) {
            fprintf(stderr, "No <ip>:<port>\n");
            exit(10);
        }

        unsigned char* colon_pos = strstr(ip_port, ":");
        if(!colon_pos) {
            fprintf(stderr, "Invalid format. Expected <peer_ip>:<peer_port>\n");
            exit(11);
        }

        size_t ip_len = colon_pos - ip_port;
        char ip[16];  // Buffer for the IP address
        strncpy(ip, ip_port, ip_len);
        ip[ip_len] = '\0';

        int port = atoi(colon_pos + 1);

        printf("peer: %s:%d\n", ip, port);

        Handshake handshake;
        // 1. length of the protocol string (BitTorrent protocol) which is 19 (1 byte)
        handshake.parts.protocol_length = 19;
        // 2. the string BitTorrent protocol (19 bytes)
        strncpy(handshake.parts.protocol, "BitTorrent protocol", 19);
        // 3. eight reserved bytes, which are all set to zero (8 bytes)
        memset(handshake.parts.reserved, 0, 8);
        // 4. sha1 infohash (20 bytes) (NOT the hexadecimal representation, which is 40 bytes long)
        memcpy(handshake.parts.infohash, torrent.infohash, SHA_DIGEST_LENGTH);
        // 5. peer id (20 bytes) (generate 20 random byte values)
        strncpy(handshake.parts.peer_id, PEER_ID, 20);

        hex("Handshake Message", handshake.raw, sizeof(handshake.raw));

        int sockfd;
        struct sockaddr_in server_addr;

        // Create TCP socket
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(sockfd < 0) {
            perror("Socket creation failed");
            exit(12);
        }

        // Set server information
        server_addr.sin_family = AF_INET;
        server_addr.sin_port   = htons(port);
        if(inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
            perror("Invalid address or address not supported");
            exit(13);
        }

        // Connect to the server
        if(connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Connection failed");
            exit(14);
        }

        // Send binary data
        ssize_t sent_bytes = send(sockfd, handshake.raw, sizeof(handshake.raw), 0);
        if(sent_bytes < 0) {
            perror("Failed to send data");
        } else {
            printf("Sent %ld bytes of binary data\n", sent_bytes);
        }

        // Buffer to receive the handshake response
        Handshake response;
        ssize_t received_bytes = recv(sockfd, response.raw, sizeof(response.raw), 0);
        if(received_bytes < 0) {
            perror("Failed to receive data");
        } else {
            printf("Received %ld bytes of binary data\n", received_bytes);

            // Check if we received a complete handshake
            if(received_bytes == sizeof(response.raw)) {
                hex("Peer ID", response.parts.peer_id, sizeof(response.parts.peer_id));  // print peerid
            } else {
                printf("Received incomplete handshake\n");
            }
        }
        hex("Response Message", response.raw, sizeof(response.raw));

        close(sockfd);
        free(torrent.announce);
        free(torrent.info.name);
        free(torrent.info.pieces);
    } else if(strcmp(command, "download_piece") == 0) {
        if(argc < 6 || strcmp(argv[2], "-o") != 0) {
            fprintf(stderr, "Usage: your_bittorrent.sh download_piece -o <output_file> <torrent_file> <piece_index>\n");
            return 27;
        }

        const char* output_file  = argv[3];
        const char* torrent_file = argv[4];
        int piece_index          = atoi(argv[5]);

        char* encoded_str       = read_file(torrent_file);
        TorrentMetadata torrent = decode_torrent(encoded_str);
        printf("%s\n", torrent.announce);

        TrackerResponse tres = contact_tracker(&torrent);
        for(size_t i = 0; i < tres.peer_count; i += 6) printf("%s\n", byte_to_ip(tres.peers + i));
        if(tres.peer_count < 6) {
            fprintf(stderr, "No peers available\n");
            return 28;
        }

        unsigned char* peer = byte_to_ip(tres.peers);
        download_piece(output_file, &torrent, piece_index, (char*)peer);

        // Cleanup
        free(encoded_str);
        free(torrent.announce);
        free(torrent.info.name);
        free(torrent.info.pieces);
        free(tres.peers);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return 29;
    }

    return 0;
}
