#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    char* end   = strstr(start, end_marker);
    int size    = end - start;

    return strndup(start, size);
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
        const char* filename = argv[2];

        FILE* file = fopen(filename, "rb");
        if(!file) {
            fprintf(stderr, "Failed to open file\n", command);
            return 1;
        }

        fseek(file, 0, SEEK_END);      // go to end of file
        long file_size = ftell(file);  // get position of the file pointer
        fseek(file, 0, SEEK_SET);      // go to start of file

        char* buffer = (char*)malloc(file_size + 1);

        size_t bytes_read  = fread(buffer, 1, file_size, file);  // copy into buffer
        buffer[bytes_read] = '\0';

        fclose(file);

        encoded_str = buffer;

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
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return 1;
    }

    return 0;
}
