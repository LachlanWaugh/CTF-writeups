#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char str[4] = "Bye";
    char str2[14] = "Your so leet";
    int input;

    scanf("%d", &input);
    if (input == 0x539)
        puts(str);

    else 
        puts(str2);

    return 1;
}