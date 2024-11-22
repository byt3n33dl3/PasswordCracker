#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include <pthread.h>

static const char passchars[] = //"ABCD";
    "abcdefghikjlmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+\"#&/()=?!@$|[]|{}";
static int ALPHABET_SIZE;
static int MAX_SIZE;
static int pw_found = 0;
static char salt[13], hash[50], correct_password[25], password[12];

void setSalt()
{
    strncpy(salt, hash, 12);
}

// ‘A’,’B’,‘C’,‘D’
// ‘AA’,’BA’,‘CA’,
// ‘AB’,’BB’,‘CB’,
// ‘AD’,’DD’,‘CC’
// ‘DB’,’DC’,‘DA’,

void brute_force(char password[12], int x, int index)
{
    if(x > MAX_SIZE){return;}
    for(int i = 0; i < ALPHABET_SIZE; i++){
        if(pw_found == 1 || index < 0){return;}
        password[index]=passchars[i];

        if(index == 0){

            // printf("%s\n", password);

            char* encrypted = crypt(password, salt);

            if (strcmp(hash, encrypted) == 0){
                printf("\nFound: Password is %s\n", password);
                strncpy(correct_password, password, 40);
                pw_found = 1;
                return;
            }

        }else{brute_force(password, x, index-1);}
    }
    
    if(x == index && pw_found == 0){
        x++;
        brute_force(password, x, x);
    }
}

int main(int argc, char const *argv[])
{
    ALPHABET_SIZE = strlen(passchars);
    MAX_SIZE = ALPHABET_SIZE-1;
    strncpy(hash, argv[1], sizeof(hash));

    setSalt();
    brute_force(password, 0, 0);
    printf("THE ANSEWER IS: %s\n", correct_password);
    
    return 0;
}
//p3xsouger@github
