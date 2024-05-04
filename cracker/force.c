#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "controller.h"
#include "brute_force.h"

static const char passchars[] = "abcdefghikjlmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+\"#&/()=?!@$|[]|{}";
static int ALPHABET_SIZE, WAIT;

void brute_force(char *password, int length, int index, int start, int end)
{
    if(length == 1)
        check(password);


    for(int i = 0; i < ALPHABET_SIZE; i++)
    {
        if(found_password())
            break;

        password[index] = passchars[i];

        if(index == 1)
        {
            for (int j = start; j < end; j++)
            {
                password[0] = passchars[j];
                check(password);

                if(found_password())
                    break;
            }
        }
        else
            brute_force(password, length, index - 1, start, end);
    }
}

void* brute_force_runner(void *arg)
{
    struct data *arg_struct = (struct data*) arg;
    
    for ( int i = arg_struct->length; !found_password(); i++)
        brute_force( arg_struct->password, i, i, arg_struct->start, arg_struct->end);

    free(arg_struct->password);
    WAIT--;
    return NULL;
}

void waiting()
{
    while(WAIT)
    {
        printf("\r      \r");
        for(int i = 0; i < 3; i++)
        {
            printf(".");
            fflush(stdout);
            sleep(1);
        }
    }
}

void activate_brute_force(int num_thread)
{
    ALPHABET_SIZE = strlen(passchars);

    pthread_t tids[ALPHABET_SIZE];
    struct data arg[ALPHABET_SIZE];
    
    num_thread = 3;
    WAIT = num_thread;
    int chunk = ALPHABET_SIZE / num_thread;

    printf("Activate Brute Forcen Attack!\n");
    
    for(int i = 0; i < num_thread; i++)
    {
        arg[i].length = 1;
        arg[i].password = calloc(50, sizeof(char));
        arg[i].start = chunk * i;
        arg[i].password[0] = passchars[arg[i].start];
        arg[i].end = (i == num_thread - 1) ?((chunk * ( i + 1 )) + ALPHABET_SIZE % num_thread) : chunk * (i + 1) ;
        
        pthread_create(&tids[i], NULL, brute_force_runner, &arg[i]);
    }

    printf("This might take awhile\n");      
    waiting();
    printf("\n");
    

    for (int i = 0; i < num_thread; i++)
        pthread_join(tids[i], NULL);
}
//p3xsouger@github
