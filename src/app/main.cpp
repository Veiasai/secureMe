#include <iostream>
#include "seccomp.h"

int main() {
    std::cout << seccomp_api_get();
}