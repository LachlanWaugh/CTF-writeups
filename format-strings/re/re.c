#include <stdio.h>
#include <stdlib.h>

int main(void) {
    for (int i = 0; i < 10; i++) {
        if (i % 2)
            printf("%d", i);
    }

    return 1;
}