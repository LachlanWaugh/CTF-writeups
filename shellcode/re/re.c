#include <stdio.h>
#include <stdlib.h>

int re_this(int arg1, int arg2) {
    return (arg1 + arg2) % 6;
}

int main(void) {
    re_this(1, 2);
}