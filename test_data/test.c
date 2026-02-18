#include <stdio.h>

int global_var = 42;

typedef struct {
    int x;
    int y;
    char name[32];
} Point;

int add(int a, int b) {
    int result = a + b;
    return result;
}

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int main() {
    Point p = {10, 20, "origin"};
    int sum = add(p.x, p.y);
    int fact = factorial(5);
    printf("Sum: %d, Factorial: %d\n", sum, fact);
    return 0;
}
