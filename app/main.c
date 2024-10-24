#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

char* decode_bencode(const char* bencoded_value, int* index) {
    char first_char = bencoded_value[*index];

    // Decoding a string (format: <len>:<string>)
    if(is_digit(first_char)) {
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
    }
    // Decoding an integer (format: i<integer>e)
    else if(first_char == 'i') {
        (*index)++;  // Skip 'i'

        int start = *index;
        while(bencoded_value[*index] != 'e') (*index)++;  // Find 'e'

        int length = *index - start;

        char* decoded_str = (char*)malloc(length + 1);  // integer string + null
        strncpy(decoded_str, bencoded_value + start, length);
        decoded_str[length] = '\0';

        (*index)++;  // Skip 'e'

        return decoded_str;
    }
    // Decoding a list (format: l<values>e)
    else if(first_char == 'l') {
        (*index)++;  // Skip 'l'

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
    }
    // Decoding a dictionary (format: d<key1><value1>...<keyN><valueN>e)
    else if(first_char == 'd') {
        (*index)++;  // Skip 'd'

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

    return NULL;  // by default
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

    const char* command     = argv[1];
    const char* encoded_str = argv[2];

    // switch
    if(strcmp(command, "decode") == 0) {
        int index         = 0;
        char* decoded_str = decode_bencode(encoded_str, &index);

        if(decoded_str != NULL) {  // error checking
            printf("%s\n", decoded_str);
            free(decoded_str);  // free memory
        } else {
            fprintf(stderr, "decoder returned NULL\n", command);
            return 1;
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return 1;
    }

    return 0;
}
