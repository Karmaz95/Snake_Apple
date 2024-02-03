//g++ -std=c++11 lambda_capture_example.cpp -o lambda_capture_example

/*
This example demonstrates how lambda capture by reference [&] allows the lambda function to access and modify variables from the outer scope directly.

1. We have a function withWritableMemory that simulates the process of making memory writable, executing some work, and then restoring memory protection.
2. In the main function, we have variables x and y.
3. We define a lambda function lambda capturing all variables by reference [&]().
4. Inside the lambda, we modify the values of x and y.
5. We call withWritableMemory and pass the lambda as an argument.
6. The lambda is executed within the withWritableMemory function.
7. After the lambda execution, we print the values of x and y to see the changes made inside the lambda.
*/
#include <iostream>

void withWritableMemory(std::function<void()> work) {
    std::cout << "Entering withWritableMemory function" << std::endl;
    // Simulating the setup before making memory writable
    std::cout << "Setting up memory..." << std::endl;

    // Make memory writable

    // Execute the provided work function
    work();

    // Restore memory protection
    std::cout << "Restoring memory protection..." << std::endl;

    std::cout << "Exiting withWritableMemory function" << std::endl;
}

int main() {
    int x = 5;
    int y = 3;

    // Lambda function capturing all variables by reference
    auto lambda = [&]() {
        // Access and modify variables from the outer scope
        x = x + 10;
        y = y * 2;

        std::cout << "Inside lambda: x = " << x << ", y = " << y << std::endl;
    };

    // Call the function with the lambda as an argument
    withWritableMemory(lambda);

    // After the lambda is executed
    std::cout << "After lambda: x = " << x << ", y = " << y << std::endl;

    return 0;
}

/*
./lambda_capture_example

Entering withWritableMemory function
Setting up memory...
Inside lambda: x = 15, y = 6
Restoring memory protection...
Exiting withWritableMemory function
After lambda: x = 15, y = 6
*/