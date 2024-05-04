#include <stdio.h>
#include <string.h>
#include <time.h>

# define MAX_CHARS 100

struct password_details {
    char pass[MAX_CHARS];
    // than 100 chars
    double time_taken;
    long int attempts;
    int bf_cracked; // cracked with the brute force algorithm
    int nbf_cracked; // cracked with the pre brute force algorithm
    short int identifier;
};

int main(void) {

    int PASSWORDS_CRACKED = 0;
    int PRE_BRUTEFORCE_CRACKED = 0;
    int size;

    printf("How many passwords would you like to test?\n");
    scanf("%d", &size);

    printf("Please enter %d passwords\n", size);

    struct password_details pass_list[size];
    for (int i = 0; i < size; i++) {
        struct password_details curr_pass;
        scanf("%s", curr_pass.pass);
        curr_pass.attempts = 0;
        curr_pass.bf_cracked = 0;
        curr_pass.nbf_cracked = 0;
        curr_pass.identifier = i + 1;
        pass_list[i] = curr_pass;
    }

    long int attempts = 0;

    // pre brute force algorithm
    char file_pass[MAX_CHARS];
    FILE *fp;
    int password_found = 0;
    int len;
    int pre_bruteforce_attempts = 0;

    fp = fopen("more_common_pass.txt", "r");
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }

    time_t start, end;
    double time_taken;
    start = clock();

    // struct password_details pass_list[] = {pass1, pass2, pass3};

    while (fgets(file_pass, MAX_CHARS, fp) != NULL) {
        pre_bruteforce_attempts++;
        len = strlen(file_pass);
        if (len > 0 && file_pass[len - 1] == '\n') file_pass[len-1] = '\0';

        for (int curr = 0; curr < size; curr++) {
            if (pass_list[curr].nbf_cracked != 1) {
                if (strcmp(pass_list[curr].pass, file_pass) == 0) {
                    end = clock();
                    end = end - start;
                    pass_list[curr].time_taken = ((double)end)/CLOCKS_PER_SEC;
                    printf("password %d found\n", pass_list[curr].identifier);
                    pass_list[curr].nbf_cracked = 1;
                    pass_list[curr].attempts = pre_bruteforce_attempts;
                    PASSWORDS_CRACKED++;
                    PRE_BRUTEFORCE_CRACKED++;
                }
            }
        }
        if (PRE_BRUTEFORCE_CRACKED == size) break;
    }

    fclose(fp);

    for (int curr = 0; curr < size; curr++) {
        if (pass_list[curr].nbf_cracked == 1) {
            printf("password %d took %ld attempts\n", pass_list[curr].identifier, pass_list[curr].attempts);
            printf("took %f seconds to compute\n", pass_list[curr].time_taken);
            if (pass_list[curr].attempts <= 10) {
                printf("Your password is in the top 10 most popular passwords!\n");
            } else if (pass_list[curr].attempts > 10 && pass_list[curr].attempts <= 100) {
                printf("Your password is in the top 100 most popular passwords!\n");
            } else if (pass_list[curr].attempts > 100 && pass_list[curr].attempts <= 1000) {
                printf("Your password is in the top 1000 most popular passwords!\n");
            } else if (pass_list[curr].attempts > 100 && pass_list[curr].attempts <= 10000) {
                printf("Your password is in the top 10000 most popular passwords!\n");
            } else if (pass_list[curr].attempts > 10000 && pass_list[curr].attempts <= 100000) {
                printf("Your password is in the top 10000 most popular passwords!\n");
            } else {
                printf("Your password is in the top 1000000 most popular passwords!\n");
            }
        }
    }

    if (PRE_BRUTEFORCE_CRACKED == size) return 0;

    printf("Entering brute force algorithm\n");

    char password_guesser[MAX_CHARS]; // assuming someones password cannot be greater
    // than 100 characters
    password_guesser[0] = '0';
    password_guesser[1] = '\0';
    attempts = 0;
    int curr_length = 1;
    int curr_array_elem = 0;
    int m = 0;
    int j = 0;
    int x = 0;

    while (1) {
        for (int curr = 0; curr < size; curr++) {
            if (strcmp(pass_list[curr].pass, password_guesser) == 0) {
                if (pass_list[curr].bf_cracked != 1 && pass_list[curr].nbf_cracked != 1) {
                    printf("password %d found\n", pass_list[curr].identifier);
                    end = clock();
                    end = end - start;
                    pass_list[curr].time_taken = ((double)end)/CLOCKS_PER_SEC;
                    pass_list[curr].bf_cracked = 1;
                    pass_list[curr].attempts = attempts;
                    PASSWORDS_CRACKED++;
                    printf("Password %d took %ld attempts\n", pass_list[curr].identifier, pass_list[curr].attempts);
                    printf("Password $d took %f seconds to compute\n\n", pass_list[curr].identifier, pass_list[curr].time_taken);
                }
            }
        }

        if (PASSWORDS_CRACKED == size) {
            printf("All passwords found\n");
            break;
        }

        if (password_guesser[curr_array_elem] == '9') {
            password_guesser[curr_array_elem] = 'A';
            if (curr_array_elem > 0) { // resetting
                for (m = 0; m < curr_array_elem; m++) {
                    password_guesser[m] = '0';
                }
            }
            curr_array_elem = 0;
        } else if (password_guesser[curr_array_elem] == 'Z') {
            password_guesser[curr_array_elem] = 'a';
            if (curr_array_elem > 0) { // resetting
                for (m = 0; m < curr_array_elem; m++) {
                    password_guesser[m] = '0';
                }
            }
            curr_array_elem = 0;
        } else if (password_guesser[curr_array_elem] == 'z') {
            curr_array_elem++;
            if (curr_array_elem == curr_length) {
                password_guesser[curr_length] = '0';
                curr_length++;
                password_guesser[curr_length] = '\0';
                for (x = 0; x < curr_length-1; x++) {
                    password_guesser[x] = '0';
                }
                curr_array_elem = 0;
            } else {
                for (m = 0; m < curr_array_elem; m++) {
                    password_guesser[m] = '0';
                }
            }
        } else {
            password_guesser[curr_array_elem]++;
            if (curr_array_elem > 0) { // resetting
                for (m = 0; m < curr_array_elem; m++) {
                    password_guesser[m] = '0';
                }
            curr_array_elem = 0;
            }
        }

        attempts++;
    }

    printf("Finished\n");

    return 0;
}
