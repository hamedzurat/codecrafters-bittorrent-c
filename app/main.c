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
            exit(EXIT_FAILURE);                                \
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

void* safe_malloc(size_t size, const char* context);
bool is_digit(char c);
char* decode_string(const char* data, int* index, int length);
char* decode_integer(const char* data, int* index);
char* decode_list(const char* data, int* index);
char* decode_dictionary(const char* data, int* index);
char* decode_bencode(const char* data, int* index);
int extract_int(const char* encoded_str, const char* key);
TorrentMetadata decode_torrent(const char* encoded_str, const char* decoded_str);
char* read_file(const char* filename);
static size_t tracker_callback(void* contents, size_t size, size_t nmemb, void* userp);
TrackerResponse contact_tracker(const TorrentMetadata* torrent);
unsigned char* byte_to_ip(const unsigned char* peers);
void hex(const char* header, const unsigned char* src, const int size);

void* safe_malloc(size_t size, const char* context) {
    void* ptr = malloc(size);
    if(!ptr) {
        fprintf(stderr, "Memory allocation failed for %s: %s\n",
        context, strerror(errno));
        exit(EXIT_FAILURE);
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
        exit(1);
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
    const char* val_start = strstr(encoded_str, key) + strlen(key);
    char* start           = strstr(val_start, ":") + 1;
    *len                  = atoi(val_start);
    *bin                  = safe_malloc(*len, "extract_str");
    memcpy(*bin, start, *len);
}

TorrentMetadata decode_torrent(const char* encoded_str, const char* decoded_str) {
    TorrentMetadata torrent;
    int tmp_len;

    printf("%s\n", encoded_str);
    printf("%s\n", decoded_str);

    extract_str(encoded_str, "8:announce", &tmp_len, &torrent.announce);
    extract_str(encoded_str, "10:created by", &tmp_len, &torrent.created_by);
    extract_str(encoded_str, "4:name", &tmp_len, &torrent.info.name);
    extract_str(encoded_str, "6:pieces", &torrent.info.pieces_size, &torrent.info.pieces);
    torrent.info.length       = extract_int(encoded_str, "6:length");
    torrent.info.piece_length = extract_int(encoded_str, "12:piece length");
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

int main(int argc, char* argv[]) {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // help menu
    if(argc < 3) {
        fprintf(stderr, "Usage: your_bittorrent.sh <command> <args>\n");
        return 1;
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
        encoded_str = read_file(argv[2]);

        char* decoded_str       = decode_bencode(encoded_str, &index);  // decode
        TorrentMetadata torrent = decode_torrent(encoded_str, decoded_str);

        printf("Name: %s\n", torrent.info.name);
        // printf("Created By: %s\n", torrent.created_by);
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

        // printf("%s\n", decoded_str);

        free(torrent.announce);
        free(torrent.info.name);
        free(torrent.info.pieces);
        free(decoded_str);
    } else if(strcmp(command, "peers") == 0) {
        encoded_str             = read_file(argv[2]);
        char* decoded_str       = decode_bencode(encoded_str, &index);  // decode
        TorrentMetadata torrent = decode_torrent(encoded_str, decoded_str);
        TrackerResponse tres    = contact_tracker(&torrent);

        for(size_t i = 0; i < tres.peer_count; i += 6) {
            printf("%s\n", byte_to_ip(tres.peers + i));
        }

        free(torrent.announce);
        free(torrent.info.name);
        free(torrent.info.pieces);
        free(tres.peers);
        free(decoded_str);
    } else if(strcmp(command, "handshake") == 0) {
        encoded_str             = read_file(argv[2]);
        char* decoded_str       = decode_bencode(encoded_str, &index);  // decode
        TorrentMetadata torrent = decode_torrent(encoded_str, decoded_str);

        unsigned char* ip_port = argv[3];

        if(argc < 4) {
            TrackerResponse tres = contact_tracker(&torrent);
            ip_port              = byte_to_ip(tres.peers);
            free(tres.peers);
        }

        if(!ip_port) {
            fprintf(stderr, "No <ip>:<port>\n");
            exit(1);
        }

        unsigned char* colon_pos = strstr(ip_port, ":");
        if(!colon_pos) {
            fprintf(stderr, "Invalid format. Expected <peer_ip>:<peer_port>\n");
            exit(1);
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
        strncpy(handshake.parts.peer_id, "-PC0001-123456789012", 20);

        hex("Handshake Message", handshake.raw, sizeof(handshake.raw));

        int sockfd;
        struct sockaddr_in server_addr;

        // Create TCP socket
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(sockfd < 0) {
            perror("Socket creation failed");
            exit(EXIT_FAILURE);
        }

        // Set server information
        server_addr.sin_family = AF_INET;
        server_addr.sin_port   = htons(port);
        if(inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
            perror("Invalid address or address not supported");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // Connect to the server
        if(connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Connection failed");
            close(sockfd);
            exit(EXIT_FAILURE);
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
        free(decoded_str);
    } else if(strcmp(command, "download_piece") == 0) {
        char *output_filename, *torrentfile;
        int pieces_index;

        if(strcmp(argv[2], "-o") == 0) {
            output_filename = argv[3];
            torrentfile     = argv[4];
            pieces_index    = atoi(argv[5]);
        } else {
            fprintf(stderr, "brah\n");
            return 1;
        }

        printf("%s -- %s -- %d\n", output_filename, torrentfile, pieces_index);

    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return 1;
    }

    return 0;
}
