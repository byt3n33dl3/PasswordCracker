#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include <pthread.h>
#include <sys/time.h>

static int pw_found = 0;
static char salt[13], hash[50], correct_password[25];
static pthread_mutex_t lock;
static unsigned long start, end = 0;

void logo()
{
    printf("                     _             \n");
    printf("                    | |            \n");
    printf("  ___ _ __ __ _  ___| | _____ _ __ \n");
    printf(" / __| '__/ _` |/ __| |/ / _ \\ '__|\n");
    printf("| (__| | | (_| | (__|   <  __/ |   \n");
    printf(" \\___|_|  \\__,_|\\___|_|\\_\\___|_|   \n");
    printf("\n");
}

void found()
{
    printf("\n");
    printf(" ********   *******   **     ** ****     ** *******  \n");
    printf("/**/////   **/////** /**    /**/**/**   /**/**////** \n");
    printf("/**       **     //**/**    /**/**//**  /**/**    /**\n");
    printf("/******* /**      /**/**    /**/** //** /**/**    /**\n");
    printf("/**////  /**      /**/**    /**/**  //**/**/**    /**\n");
    printf("/**      //**     ** /**    /**/**   //****/**    ** \n");
    printf("/**       //*******  //******* /**    //***/*******  \n");
    printf("//         ///////    ///////  //      /// ///////   \n");
    printf("\n");
}

int set_threads(char* arg)
{
    if (arg)
        return atoi(arg);

    int user_input = 1;
    printf("Please type in how many threads you would like to start: ");
    scanf("%d", &user_input);

    return user_input;
}

int set_hash(char* arg)
{
    if(arg)
    {
        strncpy(hash, arg, 50);
        strncpy(salt, hash, 12);
        return 1;
    }
    
    printf("Pleas enter a valid hash.\n");
    printf("It should look somthing like this:\n");
    printf("'$1$9779ofJE$c.p.EwsI57yV2xjeorQbs1'\n");
    return 0;
}

int found_password()
{
    return pw_found;
}

unsigned long get_time()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * (unsigned long) 1000000 + tv.tv_usec;
}

void activate_timer()
{
    start = get_time();
}

void print_time()
{
    if(end)
    {
        int ms = ((end - start) / 1000 / 1000);
        int s = ms % 60;
        int m = ms / 60;
        int h = m / 60;
      
        if (h > 0)
            printf("It took %dh %dm %ds before the \n", h, m, s);
        
        else if (m > 0)
            printf("It took %dm %ds before the \n", m, s);
        
        else
            printf("The program run for %ds\n", s);
    }
    else
        printf("You execuded before the code\n");
}

void print_answer()
{
    if(found_password())
    {
        found();
        printf("Password is %s\n", correct_password);
    }
    else 
        printf("Did not find the correct answer\nI'm sorry to disappoint you\n");

    print_time();
}

void check(char* password)
{
    struct crypt_data data;
    data.initialized = 0;

    // printf("%s\r", password);
    char* encrypt = crypt_r(password, salt, &data);

    if (!strcmp(hash, encrypt))
    {
        pthread_mutex_lock(&lock);
        end = get_time();
        strncpy(correct_password, password, 40);
        pw_found = 1;
        pthread_mutex_unlock(&lock);
    }
}
//HenrikSandburg@github
//p3xsouger@github
