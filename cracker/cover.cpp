#include <iostream>
#include <string>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

using namespace std;

bool stop = false;
long long amount = 0;
string password;
clock_t start;

const char Alphabet[62] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U','V', 'W', 'X', 'Y', 'Z'
};

string separateWithCommas(long long num) {
    string s = to_string(num);
    int thousands = s.length() - 3;

    while (thousands > 0) {
        s.insert(thousands, ",");
        thousands -= 3;
    }

    return s;
}

void inline crack(unsigned int length, string current) {
    if (length == 0 && stop == false) {
        amount++;

        if (amount % 10000000 == 0) {
            cout << '\r' << separateWithCommas(amount) << " - " << current << " - " << separateWithCommas(amount / ((float)(clock() - start) / CLOCKS_PER_SEC)) << " p/sec";
            cout.flush();
        }
        if (current == password) {
            stop = true;
        }
        return;
    }
    if (stop == false) {
        for (unsigned int i = 0; i < 62; i++) {
            crack(length - 1, current + Alphabet[i]);
        }
    }
}

int main() {
    // Greet the user
    cout << "Welcome to CyanCoding's Brute Force Password Cracker!" << endl << endl;
    cout << "What do you want your password to be? > ";
    cin >> password;

    cout << "\rAttempting to crack " << password << "..." << endl;

    start = clock();

    while (stop == false) {
        static unsigned int pwLength = 1;
        crack(pwLength, "");
        pwLength++;
        if (stop == true) {
            break;
        }
    }
    cout << "\rCyanCoding's C++ BFPC cracked the password \"" << password << "\" in " <<
        separateWithCommas(amount) << " attempts and " << setprecision(2) << fixed <<
        (float)(clock() - start) / CLOCKS_PER_SEC << " seconds." << endl << endl <<
        "That's about " << setprecision(0) <<
        separateWithCommas(amount / ((float)(clock() - start) / CLOCKS_PER_SEC)) <<
        " passwords per second!" << endl << endl;

    return 0;
}
