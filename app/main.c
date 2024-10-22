#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

char* decode_bencode(const char* bencoded_value) {
    char first_char = bencoded_value[0];

    if(is_digit(first_char)) {
        int src_length          = atoi(bencoded_value);         // decodes string to integer as long as possible
        const char* colon_index = strchr(bencoded_value, ':');  // finds the index of :

        if(colon_index != NULL) {
            char* decoded_str = (char*)malloc(src_length + 1);  // as lenght is string lenght, it knows how much to allocate

            decoded_str[0] = '"';
            strncpy(decoded_str + 1, colon_index + 1, src_length);  // copies
            decoded_str[src_length + 1] = '"';

            return decoded_str;
        } else {
            fprintf(stderr, "Invalid encoded value: %s\n", bencoded_value);
            exit(1);
        }
    } else if(first_char == 'i') {
        bool is_invelid = false;

        int i = 1;                         // to skip i
        if(bencoded_value[1] == '-') i++;  // for negative number

        for(; bencoded_value[i] != '\0'; i++) {
            if(!is_digit(bencoded_value[i]) && bencoded_value[i] == 'e') {  // check if there is a 'e' or not and only 'e' not anyother later
                i--;                                                        // discard bc 'i' and 'e' will count 2 extra

                char* decoded_str = (char*)malloc(i);
                strncpy(decoded_str, bencoded_value + 1, i);
                decoded_str[i] = '\0';

                return decoded_str;
            } else {
                is_invelid = true;
            }
        }
        if(is_invelid) {
            fprintf(stderr, "Invalid encoded value: %s\n", bencoded_value);
            exit(1);
        }
    } else if(first_char == 'l') {
        int index         = 1;
        char* decoded_str = (char*)malloc(strlen(bencoded_value));

        strcpy(decoded_str, "[");

        while(bencoded_value[index] != 'e' && index <= strlen(bencoded_value)) {
            char* decoded_part_str = decode_bencode(bencoded_value + index);
            int size               = strlen(decoded_part_str);

            if(decoded_part_str[0] == '"') {
                int actual_size = size - 2;
                index += actual_size + 1;  // offseting string size + ':'

                while(actual_size != 0) {  // adding string size in as string
                    actual_size /= 10;
                    index++;
                }
            } else if(is_digit(decoded_part_str[0])) {
                index += size + 2;
            } else if(decoded_part_str[0] == '[') {
                index += size + 2;
            }

            strcat(decoded_str, decoded_part_str);
            strcat(decoded_str, ",");

            free(decoded_part_str);
        }

        if(decoded_str[strlen(decoded_str) - 1] == ',') {
            decoded_str[strlen(decoded_str) - 1] = ']';  // replace last , with ]
        } else {
            strcat(decoded_str, "]");
        }

        return decoded_str;
    } else {
        fprintf(stderr, "Only strings are supported at the moment\n");
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
        char* decoded_str = decode_bencode(encoded_str);

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
