#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <array>
#include <cmath>
#include <cstdlib>

// Global variables
int global_int = 42;
const char* global_string = "Hello, DWARF!";
static double global_double = 3.14159;

// Enums
enum class Color {
    RED = 1,
    GREEN = 2,
    BLUE = 3
};

enum Status {
    PENDING = 0,
    RUNNING = 1,
    COMPLETED = 2,
    FAILED = 3
};

// Forward declarations
class BaseClass;
class DerivedClass;
struct Point3D;

// Simple structures
struct Point {
    int x;
    int y;
    
    Point(int x = 0, int y = 0) : x(x), y(y) {}
    
    double distance() const {
        return sqrt(x*x + y*y);
    }
};

struct Point3D {
    int x, y, z;
    
    Point3D(int x = 0, int y = 0, int z = 0) : x(x), y(y), z(z) {}
    
    double magnitude() const {
        return sqrt(x*x + y*y + z*z);
    }
};

// Template class
template<typename T>
class Container {
private:
    std::vector<T> data_;
    size_t capacity_;
    
public:
    Container(size_t capacity = 10) : capacity_(capacity) {
        data_.reserve(capacity_);
    }
    
    void add(const T& item) {
        if (data_.size() < capacity_) {
            data_.push_back(item);
        }
    }
    
    size_t size() const {
        return data_.size();
    }
    
    T& operator[](size_t index) {
        return data_[index];
    }
};

// Base class with virtual functions
class BaseClass {
protected:
    int id_;
    std::string name_;
    
public:
    BaseClass(int id, const std::string& name) : id_(id), name_(name) {}
    virtual ~BaseClass() = default;
    
    virtual void display() const {
        std::cout << "BaseClass: " << name_ << " (ID: " << id_ << ")" << std::endl;
    }
    
    virtual int calculate() const {
        return id_ * 2;
    }
    
    int getId() const { return id_; }
    const std::string& getName() const { return name_; }
};

// Derived class
class DerivedClass : public BaseClass {
private:
    double value_;
    std::vector<int> data_;
    
public:
    DerivedClass(int id, const std::string& name, double value) 
        : BaseClass(id, name), value_(value) {
        data_.resize(5);
        for (int i = 0; i < 5; ++i) {
            data_[i] = i * id;
        }
    }
    
    void display() const override {
        std::cout << "DerivedClass: " << name_ << " (ID: " << id_ 
                  << ", Value: " << value_ << ")" << std::endl;
    }
    
    int calculate() const override {
        return static_cast<int>(id_ * value_);
    }
    
    void processData() {
        for (auto& item : data_) {
            item *= 2;
        }
    }
    
    double getValue() const { return value_; }
};

// Union example
union DataUnion {
    int int_value;
    float float_value;
    char char_array[4];
    
    DataUnion() : int_value(0) {}
};

// Function with various parameter types
int complexFunction(int a, int b, const std::string& str, 
                   const Point& p, Color color, 
                   const std::vector<int>& vec) {
    int result = a + b;
    
    std::cout << "Processing: " << str << std::endl;
    std::cout << "Point: (" << p.x << ", " << p.y << ")" << std::endl;
    std::cout << "Color: " << static_cast<int>(color) << std::endl;
    std::cout << "Vector size: " << vec.size() << std::endl;
    
    for (size_t i = 0; i < vec.size(); ++i) {
        result += vec[i];
    }
    
    return result;
}

// Template function
template<typename T>
T processValue(T value, int multiplier) {
    return value * multiplier;
}

// Function with local variables and control flow
void demonstrateControlFlow(int iterations) {
    int counter = 0;
    std::vector<int> results;
    results.reserve(iterations);
    
    for (int i = 0; i < iterations; ++i) {
        if (i % 2 == 0) {
            counter += i;
            results.push_back(counter);
        } else {
            counter -= i;
            results.push_back(counter);
        }
        
        switch (i % 4) {
            case 0:
                std::cout << "Case 0: " << counter << std::endl;
                break;
            case 1:
                std::cout << "Case 1: " << counter << std::endl;
                break;
            case 2:
                std::cout << "Case 2: " << counter << std::endl;
                break;
            default:
                std::cout << "Default: " << counter << std::endl;
                break;
        }
    }
    
    std::cout << "Final counter: " << counter << std::endl;
    std::cout << "Results size: " << results.size() << std::endl;
}

// Function with exception handling
void demonstrateExceptions() {
    try {
        int* ptr = new int[1000];
        
        for (int i = 0; i < 1000; ++i) {
            ptr[i] = i * i;
        }
        
        // Simulate some processing
        int sum = 0;
        for (int i = 0; i < 1000; ++i) {
            sum += ptr[i];
        }
        
        std::cout << "Sum: " << sum << std::endl;
        
        delete[] ptr;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
    }
}

// Static function
static int staticHelper(int x) {
    return x * x + 1;
}

// Inline function
inline int inlineFunction(int a, int b) {
    return a + b;
}

// Main function
int main(int argc, char* argv[]) {
    std::cout << "=== Comprehensive DWARF Example ===" << std::endl;
    std::cout << "Arguments: " << argc << std::endl;
    if (argv[0]) std::cout << "Program: " << argv[0] << std::endl;
    
    // Local variables
    int local_int = 100;
    double local_double = 2.71828;
    std::string local_string = "Local string";
    
    std::cout << "Local values: " << local_int << ", " << local_double << ", " << local_string << std::endl;
    std::cout << "Global values: " << global_int << ", " << global_string << ", " << global_double << std::endl;
    
    // Create objects
    Point p1(3, 4);
    Point3D p3d(1, 2, 3);
    DataUnion data;
    data.int_value = 0x12345678;
    
    // Create containers
    Container<int> int_container(20);
    Container<std::string> string_container(10);
    
    for (int i = 0; i < 10; ++i) {
        int_container.add(i * i);
        string_container.add("Item " + std::to_string(i));
    }
    
    // Create class instances
    BaseClass* base = new BaseClass(1, "Base Instance");
    DerivedClass* derived = new DerivedClass(2, "Derived Instance", 3.14);
    
    // Demonstrate polymorphism
    base->display();
    derived->display();
    
    std::cout << "Base calculation: " << base->calculate() << std::endl;
    std::cout << "Derived calculation: " << derived->calculate() << std::endl;
    
    // Call complex function
    std::vector<int> test_vector = {1, 2, 3, 4, 5};
    int result = complexFunction(10, 20, "Test string", p1, Color::BLUE, test_vector);
    std::cout << "Complex function result: " << result << std::endl;
    
    // Demonstrate control flow
    demonstrateControlFlow(8);
    
    // Demonstrate exceptions
    demonstrateExceptions();
    
    // Template function calls
    int template_result1 = processValue(5, 3);
    double template_result2 = processValue(2.5, 4);
    std::cout << "Template results: " << template_result1 << ", " << template_result2 << std::endl;
    
    // Static and inline function calls
    int static_result = staticHelper(5);
    int inline_result = inlineFunction(10, 15);
    std::cout << "Static result: " << static_result << std::endl;
    std::cout << "Inline result: " << inline_result << std::endl;
    
    // Clean up
    delete base;
    delete derived;
    
    std::cout << "=== Program completed successfully ===" << std::endl;
    return 0;
}
