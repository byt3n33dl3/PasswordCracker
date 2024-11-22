void brute_force(char* password, int x, int index, int start, int end);
void* brute_force_runner(void* arg);
void waiting();
void activate_brute_force(int num_thread);

typedef struct data
{
    char* password;
    int length, start, end;

}data_to_brute;

//p3xsouger@github
//HenrikSanberg@github
