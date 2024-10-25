#include <arpa/inet.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char* announce;
    struct {
        int length;
        char* name;
        int piece_length;
        unsigned char* pieces;
        int encoded_pieces_len;
    } info;
    unsigned char infohash[SHA_DIGEST_LENGTH];
} TorrentInfo;

typedef struct {
    int interval;
    int min_interval;
    int complete;
    int incomplete;
    unsigned char* peers;
    int peer_numer;
} TrackerRes;

bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

char* decode_bencode(const char* bencoded_value, int* index) {
    char first_char = bencoded_value[*index];

    if(is_digit(first_char)) {                           // Decoding a string (format: <len>:<string>)
        int src_length = atoi(bencoded_value + *index);  // Decode string length

        while(is_digit(bencoded_value[*index])) (*index)++;  // Move to the ':'
        (*index)++;                                          // Skip the ':'

        char* decoded_str = (char*)malloc(src_length + 3);  // lenght + quotes + string + null

        decoded_str[0] = '"';
        strncpy(decoded_str + 1, bencoded_value + *index, src_length);  // Copy the string
        decoded_str[src_length + 1] = '"';
        decoded_str[src_length + 2] = '\0';

        *index += src_length;  // Move index forward by string length

        return decoded_str;
    } else if(first_char == 'i') {  // Decoding an integer (format: i<integer>e)
        (*index)++;                 // Skip 'i'

        int start = *index;
        while(bencoded_value[*index] != 'e') (*index)++;  // Find 'e'

        int length = *index - start;

        char* decoded_str = (char*)malloc(length + 1);  // integer string + null
        strncpy(decoded_str, bencoded_value + start, length);
        decoded_str[length] = '\0';

        (*index)++;  // Skip 'e'

        return decoded_str;
    } else if(first_char == 'l') {  // Decoding a list (format: l<values>e)
        (*index)++;                 // Skip 'l'

        char* decoded_str = (char*)malloc(strlen(bencoded_value) + 3);  // lenght of list + brackets + null
        strcpy(decoded_str, "[");
        bool first_element = true;

        while(bencoded_value[*index] != 'e') {  // Until end of list
            if(!first_element) strcat(decoded_str, ",");

            char* decoded_part_str = decode_bencode(bencoded_value, index);
            strcat(decoded_str, decoded_part_str);
            free(decoded_part_str);

            first_element = false;
        }

        (*index)++;  // Skip 'e'
        strcat(decoded_str, "]");

        return decoded_str;
    } else if(first_char == 'd') {  // Decoding a dictionary (format: d<key1><value1>...<keyN><valueN>e)
        (*index)++;                 // Skip 'd'

        char* decoded_str = (char*)malloc(strlen(bencoded_value) + 3);  // lenght of dictionary + brackets + null
        strcpy(decoded_str, "{");
        bool first_element = true;

        int key_or_val = 0;  // if key its odd number, or when its val its even

        while(bencoded_value[*index] != 'e') {  // Until end of list
            if(key_or_val % 2 == 0) {
                if(!first_element) strcat(decoded_str, ",");
            } else {
                strcat(decoded_str, ":");
            }

            char* decoded_part_str = decode_bencode(bencoded_value, index);
            strcat(decoded_str, decoded_part_str);
            free(decoded_part_str);

            first_element = false;
            key_or_val++;
        }

        (*index)++;  // Skip 'e'
        strcat(decoded_str, "}");

        return decoded_str;

    } else {
        fprintf(stderr, "Unsupported bencoded value: %s\n", bencoded_value);
        exit(1);
    }

    fprintf(stderr, "decoder returned nothing\n");
    exit(1);
}

char* extract_value(const char* decoded_str, const char* key, const char* end_marker) {
    char* start = strstr(decoded_str, key) + strlen(key);
    if(start - strlen(key) == NULL) {
        fprintf(stderr, "value extraction failed for: %s,%s,%s\n", decoded_str, key, end_marker);
        exit(1);
    }

    char* end = strstr(start, end_marker);
    if(end == NULL) {
        fprintf(stderr, "value extraction failed for: %s,%s,%s\n", decoded_str, key, end_marker);
        exit(1);
    }

    return strndup(start, end - start);
}

int extract_int(const char* encoded_str, const char* key) {
    int index = 0;
    char* tmp = decode_bencode(strstr(encoded_str, key) + strlen(key), &index);
    int ret   = atoi(tmp);

    free(tmp);
    return ret;
}

TorrentInfo decode_torrent(const char* encoded_str, const char* decoded_str) {
    TorrentInfo torrent;
    torrent.announce          = extract_value(decoded_str, "\"announce\":\"", "\"");
    torrent.info.length       = atoi(extract_value(decoded_str, "\"length\":", ","));
    torrent.info.name         = extract_value(decoded_str, "\"name\":\"", "\"");
    torrent.info.piece_length = atoi(extract_value(decoded_str, "\"piece length\":", ","));

    char* piece_val_start           = strstr(encoded_str, "6:pieces") + strlen("6:pieces");
    char* pieces_start              = strstr(piece_val_start, ":") + 1;
    torrent.info.encoded_pieces_len = atoi(piece_val_start);
    torrent.info.pieces             = malloc(torrent.info.encoded_pieces_len);
    memcpy(torrent.info.pieces, pieces_start, torrent.info.encoded_pieces_len);

    // reencode bencode
    int info_bencoded_len        = snprintf(NULL, 0, "d6:lengthi%de4:name%d:%s12:piece lengthi%de6:pieces%d:", torrent.info.length, strlen(torrent.info.name), torrent.info.name, torrent.info.piece_length, torrent.info.encoded_pieces_len);
    unsigned char* info_bencoded = malloc(info_bencoded_len + torrent.info.encoded_pieces_len + 2);  // +2 for 'e' + null
    sprintf(info_bencoded, "d6:lengthi%de4:name%d:%s12:piece lengthi%de6:pieces%d:", torrent.info.length, strlen(torrent.info.name), torrent.info.name, torrent.info.piece_length, torrent.info.encoded_pieces_len);
    memcpy(info_bencoded + info_bencoded_len, torrent.info.pieces, torrent.info.encoded_pieces_len);
    info_bencoded[info_bencoded_len + torrent.info.encoded_pieces_len]     = 'e';
    info_bencoded[info_bencoded_len + torrent.info.encoded_pieces_len + 1] = '\0';

    SHA1(info_bencoded, info_bencoded_len + torrent.info.encoded_pieces_len + 1, torrent.infohash);

    free(info_bencoded);
    return torrent;
}

char* open_file(char* filename) {
    FILE* file = fopen(filename, "rb");
    if(!file) {
        fprintf(stderr, "Failed to open file\n");
        exit(1);
    }

    fseek(file, 0, SEEK_END);      // go to end of file
    long file_size = ftell(file);  // get position of the file pointer
    fseek(file, 0, SEEK_SET);      // go to start of file

    char* buffer = (char*)malloc(file_size + 1);

    size_t bytes_read  = fread(buffer, 1, file_size, file);  // copy into buffer
    buffer[bytes_read] = '\0';

    fclose(file);

    return buffer;
}

size_t callback(void* ptr, size_t size, size_t nmemb, void* stream) {
    int index         = 0;
    char* decoded_str = decode_bencode(ptr, &index);  // decode
    TrackerRes* tres  = (TrackerRes*)stream;

    tres->interval     = extract_int(ptr, "8:interval");
    tres->min_interval = extract_int(ptr, "12:min interval");
    tres->complete     = extract_int(ptr, "8:complete");
    tres->incomplete   = extract_int(ptr, "10:incomplete");

    char* peers_val_start = strstr(ptr, "5:peers") + strlen("5:peers");
    char* peers_start     = strstr(peers_val_start, ":") + 1;
    tres->peer_numer      = atoi(peers_val_start);
    tres->peers           = malloc(tres->peer_numer);
    memcpy(tres->peers, peers_start, tres->peer_numer);

    free(decoded_str);
    return size * nmemb;
}

TrackerRes call_tracker(TorrentInfo torrent) {
    CURL* curl;
    CURLcode res;
    TrackerRes tres;

    char* announce = torrent.announce;
    char* infohash = curl_easy_escape(NULL, torrent.infohash, 20);
    char* peer_id  = curl_easy_escape(NULL, "-PC0001-123456789012", 20);
    int port       = 6881;
    int uploaded   = 0;
    int downloaded = 0;
    int left       = torrent.info.length;
    int compact    = 1;

    char url[512];
    snprintf(url, sizeof(url), "%s?info_hash=%s&peer_id=%s&port=%d&uploaded=%d&downloaded=%d&left=%d&compact=%d", announce, infohash, peer_id, port, uploaded, downloaded, left, compact);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&tres);

        res = curl_easy_perform(curl);

        if(res != CURLE_OK) fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return tres;
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
        encoded_str = open_file(argv[2]);

        char* decoded_str   = decode_bencode(encoded_str, &index);  // decode
        TorrentInfo torrent = decode_torrent(encoded_str, decoded_str);

        printf("Tracker URL: %s\n", torrent.announce);
        printf("Length: %d\n", torrent.info.length);
        printf("Info Hash: ");
        for(int i = 0; i < SHA_DIGEST_LENGTH; i++) printf("%02x", torrent.infohash[i]);
        printf("\n");
        printf("Piece Length: %d\n", torrent.info.piece_length);
        printf("Piece Hashes:");
        for(int i = 0; i < torrent.info.encoded_pieces_len; i++) {
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
        encoded_str         = open_file(argv[2]);
        char* decoded_str   = decode_bencode(encoded_str, &index);  // decode
        TorrentInfo torrent = decode_torrent(encoded_str, decoded_str);

        TrackerRes tres = call_tracker(torrent);

        for(size_t i = 0; i < tres.peer_numer; i += 6) {
            printf("%s\n", byte_to_ip(tres.peers + i));
        }

        free(torrent.announce);
        free(torrent.info.name);
        free(torrent.info.pieces);
        free(tres.peers);
        free(decoded_str);
    } else if(strcmp(command, "handshake") == 0) {
        encoded_str         = open_file(argv[2]);
        char* decoded_str   = decode_bencode(encoded_str, &index);  // decode
        TorrentInfo torrent = decode_torrent(encoded_str, decoded_str);

        unsigned char* ip_port = argv[3];

        if(argc < 4) {
            TrackerRes tres = call_tracker(torrent);
            ip_port         = byte_to_ip(tres.peers);
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

        // printf("IP: %s\n", ip);
        // printf("Port: %d\n", port);

        unsigned char handshake[48 + SHA_DIGEST_LENGTH];
        size_t offset = 0;

        // 1. length of the protocol string (BitTorrent protocol) which is 19 (1 byte)
        handshake[offset] = 19;
        offset++;
        // 2. the string BitTorrent protocol (19 bytes)
        memcpy(handshake + offset, "BitTorrent protocol", 19);
        offset += 19;
        // 3. eight reserved bytes, which are all set to zero (8 bytes)
        memset(handshake + offset, 0, 8);
        offset += 8;
        // 4. sha1 infohash (20 bytes) (NOT the hexadecimal representation, which is 40 bytes long)
        memcpy(handshake + offset, torrent.infohash, SHA_DIGEST_LENGTH);
        offset += SHA_DIGEST_LENGTH;
        // 5. peer id (20 bytes) (generate 20 random byte values)
        memcpy(handshake + offset, "-PC0001-123456789012", 20);

        // hex("Handshake Message", handshake, sizeof(handshake));

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
        ssize_t sent_bytes = send(sockfd, handshake, sizeof(handshake), 0);
        if(sent_bytes < 0) {
            perror("Failed to send data");
        } else {
            // printf("Sent %ld bytes of binary data\n", sent_bytes);
        }

        // Buffer to receive the handshake response
        unsigned char response[48 + SHA_DIGEST_LENGTH];
        ssize_t received_bytes = recv(sockfd, response, sizeof(response), 0);
        if(received_bytes < 0) {
            perror("Failed to receive data");
        } else {
            // printf("Received %ld bytes of binary data\n", received_bytes);

            // Check if we received a complete handshake
            if(received_bytes == sizeof(response)) {
                unsigned char peer_id[20];
                memcpy(peer_id, response + 48, 20);  // peerid starts 48

                hex("Peer ID", peer_id, sizeof(peer_id));  // print peerid
            } else {
                printf("Received incomplete handshake\n");
            }
        }
        // hex("Response Message", response, sizeof(response));

        close(sockfd);
        free(torrent.announce);
        free(torrent.info.name);
        free(torrent.info.pieces);
        free(decoded_str);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return 1;
    }

    return 0;
}
