#include <iostream>

int global_var = 42;

int add(int a, int b) {
    int result = a + b;
    return result;
}

int main() {
    int local_var = 10;
    int sum = add(global_var, local_var);
    std::cout << "Sum: " << sum << std::endl;
    return 0;
}
