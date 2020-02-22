#include "obl_primitives.h"

#include <iostream>

// #define SIMULATED_OBL_ASSIGN
// #define SIMULATED_OBL_ASSIGN_HELPER

namespace obl {

// TODO: define this as inline cause segment fault. Need to know why. Is it due
// to |inline| does not work well with |assembly| impl?
bool LessImplDouble(double x, double y) {
  bool result;
  __asm__ volatile(
      "movsd %1, %%xmm0;"
      "movsd %2, %%xmm1;"
      "comisd %%xmm1, %%xmm0;"
      "setb %0;"
      : "=r"(result)
      : "m"(x), "m"(y)
      : "cc");
  return result;
}

}  // namespace obl

/***************************************************************************************
 * Testing
 **************************************************************************************/
struct Generic {
    double x;
    short y;
    double z;

    Generic() = default;

    Generic(double x, short y, double z)
        : x(x), y(y), z(z) {}

    inline bool operator<(const Generic &b) const {
        return (x < b.x);
    }
    inline bool operator<=(const Generic &b) const {
        return (x <= b.x);
    }
    
    static inline bool ogreater(Generic a, Generic b) {
        return ObliviousGreater(a.x, b.x);
    }
};

namespace obl {

template <>
struct less<Generic> {
  bool operator()(const Generic& a, const Generic& b) {
    return a.x < b.x;
  }
};

}

struct Generic_16B {
    double x;
    uint64_t y;

    Generic_16B() = default;

    Generic_16B(double x, uint64_t y)
        : x(x), y(y) {}
};

struct Foo {
    char a;
    char b;
    char c;
};

void test(const char* name, bool cond) {
    printf("%s : ", name);
    if (cond)
        printf("pass\n");
    else
        printf("fail\n");
}

void test_ObliviousGreater() {
    // Test generic cases
    test("4 > 5", ObliviousGreater(4,5) == 4 > 5);
    test("5 > 4", ObliviousGreater(5,4) == 5 > 4);
    test("4 > 4", ObliviousGreater(4,4) == 4 > 4);

    // Test negative cases
    test("-4 > 4", ObliviousGreater(-4,4) == -4 > 4);
    test("4 > -4", ObliviousGreater(4, -4) == 4 > -4);
    test("-4 > -5", ObliviousGreater(-4, -5) == -4 > -5);
    test("-5 > -4", ObliviousGreater(-5, -4) == -5 > -4);

    // Test floating point
    test("-4. > -3.", ObliviousGreater(-4., -3.) == -4. > -3.);
    test("-4.1 > -4.2", ObliviousGreater(-4.1, -4.2) == -4.1 > -4.2);
    test("-4.2 > -4.1", ObliviousGreater(-4.2, -4.1) == -4.2 > -4.1);
    test("-4. > -4.", ObliviousGreater(-4., -4.) == -4. > -4.);
    test(".4 > .3", ObliviousGreater(.4, .3) == .4 > .3);
    test(".4 > .5", ObliviousGreater(.4, .5) == .4 > .5);

    // Test integer overflow
    test("(int32_t) 2147483648 > 42", !ObliviousGreater((int32_t)2147483648, 42));
    test("2147483648 > 42", ObliviousGreater(2147483648, (int64_t) 42));
}

void test_ObliviousLess() {
    // Test generic cases
    test("4 < 5", ObliviousLess(4,5) == 4 < 5);
    test("5 < 4", ObliviousLess(5,4) == 5 < 4);
    test("4 < 4", ObliviousLess(4,4) == 4 < 4);

    // Test negative cases
    test("-4 < 4", ObliviousLess(-4,4) == -4 < 4);
    test("4 < -4", ObliviousLess(4, -4) == 4 < -4);
    test("-4 < -5", ObliviousLess(-4, -5) == -4 < -5);
    test("-5 < -4", ObliviousLess(-5, -4) == -5 < -4);

    // Test floating point
    test("-4. < -3.", ObliviousLess(-4., -3.) == -4. < -3.);
    test("-4.1 < -4.2", ObliviousLess(-4.1, -4.2) == -4.1 < -4.2);
    test("-4.2 < -4.1", ObliviousLess(-4.2, -4.1) == -4.2 < -4.1);
    test("-4. < -4.", ObliviousLess(-4., -4.) == -4. < -4.);
    test(".4 < .3", ObliviousLess(.4, .3) == .4 < .3);
    test(".4 < .5", ObliviousLess(.4, .5) == .4 < .5);

    // Test integer overflow
    test("(int32_t) 2147483648 < 42", ObliviousLess((int32_t)2147483648, 42));
    test("2147483648 < 42", !ObliviousLess(2147483648, (int64_t) 42));
}

void test_ObliviousEqual() {
    // Test generic cases
    test("4 == 5", ObliviousEqual(4,5) == (4==5));
    test("5 == 4", ObliviousEqual(5,4) == (5==4));
    test("4 == 4", ObliviousEqual(4,4) == (4==4));

    // Test negative cases
    test("-4 == 4", ObliviousEqual(-4,4) == (-4==4));
    test("4 == -4", ObliviousEqual(4, -4) == (4==-4));
    test("-4 == -5", ObliviousEqual(-4, -5) == (-4==-5));
    test("-5 == -4", ObliviousEqual(-5, -4) == (-5==-4));
    test("-4 == -4", ObliviousEqual(-4,-4) == (-4==-4));

    // Test floating point
    test("-4. == -3.", ObliviousEqual(-4., -3.) == (-4.==-3.));
    test("-4.1 == -4.2", ObliviousEqual(-4.1, -4.2) == (-4.1==-4.2));
    test("-4.2 == -4.1", ObliviousEqual(-4.2, -4.1) == (-4.2==-4.1));
    test(".4 == .3", ObliviousEqual(.4, .3) == (.4==.3));
    test(".4 == .5", ObliviousEqual(.4, .5) == (.4==.5));
    test(".4 == .400001", ObliviousEqual(.4, .400001) == (.4==.4000001));
    test("-4. == -4.", ObliviousEqual(-4., -4.) == (-4.==-4.));
    test("4. == 4.", ObliviousEqual(4., 4.) == (4.==4.));
}

void test_ObliviousAssign() {
    test(" (true, 4, 5) ", ObliviousChoose(true, 4, 5) == 4);
    test(" (false, 4, 5)", ObliviousChoose(false, 4, 5) == 5);
    test(" (true, -4, 5) ", ObliviousChoose(true, -4, 5) == -4);
    test(" (false, 4, -5)", ObliviousChoose(false, 4, -5) == -5);
    test(" (true, -4.2, 5.) ", ObliviousChoose(true, -4.2, 5.4) == -4.2);
    test(" (false, 4.23, 5.34)", ObliviousChoose(false, 4.23, 5.34) == 5.34);
    test(" (false, -4.23, -5.34)", ObliviousChoose(false, -4.23, -5.34) == -5.34);
    test(" (false, 4.23, -5.34)", ObliviousChoose(false, 4.23, -5.34) == -5.34);
    test(" (true, 4.23, -5.34)", ObliviousChoose(true, 4.23, -5.34) == 4.23);

    Generic g_a = Generic(-1.35, 2, 3.21);
    Generic g_b = Generic(4.123, 5, 6.432);
    Generic g_c = ObliviousChoose(true, g_a, g_b);
    test(" (true, (-1.35, 2, 3.21), (4.123, 5, 6.432)) ",
        (g_c.x == -1.35 && g_c.y == 2 && g_c.z == 3.21));
    g_c = ObliviousChoose(false, g_a, g_b);
    test(" (false, (-1.35, 2, 3.21), (4.123, 5, 6.432)) ",
        (g_c.x == 4.123 && g_c.y == 5 && g_c.z == 6.432));
    
    test(" (false, (uint8_t) 1, (uint8_t) 2) ", ObliviousChoose(false, (uint8_t) 1, (uint8_t) 2) == 2);

    struct Foo foo;
    foo.a = (char) 1;
    foo.b = (char) 2;
    foo.c = (char) 3;

    struct Foo bar;
    bar.a = (char) 4;
    bar.b = (char) 5;
    bar.c = (char) 6;

    struct Foo baz = ObliviousChoose(false, foo, bar);
    test(" (false, (1,2,3), (4,5,6) ) ",
            baz.a == (char) 4 && baz.b == (char) 5 && baz.c == (char) 6);
}

void test_ObliviousSort() {
    double d_arr[5] = {2.123456789, 3.123456789, 1.123456789, -2.123456789, -1.123456789};
    bool pass = true;
    ObliviousSort(d_arr, d_arr + 5);

    for (int i = 0; i < 5; i++) {
        printf("%f ", d_arr[i]);
        if (i < 4) pass = (pass && (d_arr[i] <= d_arr[i+1]));
    }
    if (pass) 
        printf(" : pass");
    else
        printf(" : fail");
    printf("\n");

    int int_arr[5] = {2, 3, 1, -2, -1};
    ObliviousSort(int_arr, int_arr + 5);
    pass = true;
    for (int i = 0; i < 5; i++) {
        printf("%d ", int_arr[i]);
        if (i < 4) pass = (pass && (d_arr[i] <= d_arr[i+1]));
    }
    if (pass) 
        printf(" : pass");
    else
        printf(" : fail");
    printf("\n");
    
    Generic g_arr[5] = {Generic(-1.35, 2, 3.21), Generic(4.123, 5, 6.432), Generic(-5.123, 3, 7.432), Generic(6.123, 1, 1.432), Generic(-3.123, 4, 0.432)};
    ObliviousSort(g_arr, g_arr + 5);
    pass = true;
    for (int i = 0; i < 5; i++) {
        printf("%f,%d,%f -- ", g_arr[i].x, g_arr[i].y, g_arr[i].z);
        if (i < 4) pass = (pass && (g_arr[i] <= g_arr[i+1]));
    }
    if (pass) 
        printf(" : pass");
    else
        printf(" : fail");
    printf("\n");
}

void test_ObliviousArrayAccess() {
    double d_arr[100]; 
    for (int i = 0; i < 100; i++) {
        d_arr[i] = i + 0.5;
    }
    bool pass = true;
    for (int i = 0; i < 100; i++) {
        double val = ObliviousArrayAccess(d_arr, i, 100);
        if (i % 10 == 0)
            printf("%f ", val);
        pass = pass && (val == d_arr[i]);
    }
    if (pass) 
        printf(" : pass");
    else
        printf(" : fail");
    printf("\n");

    int i_arr[100]; 
    for (int i = 0; i < 100; i++) {
        i_arr[i] = i;
    }
    pass = true;
    for (int i = 0; i < 100; i++) {
        int val = ObliviousArrayAccess(i_arr, i, 100);
        if (i % 10 == 0)
            printf("%d ", val);
        pass = pass && (val == i_arr[i]);
    }
    if (pass) 
        printf(" : pass");
    else
        printf(" : fail");
    printf("\n");

    Generic_16B g_arr[100]; 
    for (int i = 0; i < 100; i++) {
        g_arr[i] = Generic_16B(i+0.5, i);
    }
    pass = true;
    for (int i = 0; i < 100; i++) {
        Generic_16B val = ObliviousArrayAccess(g_arr, i, 100);
        if (i % 10 == 0)
            printf("%f,%llu ", val.x, val.y);
        pass = pass && (val.x == g_arr[i].x) && (val.y == g_arr[i].y);
    }
    if (pass) 
        printf(" : pass");
    else
        printf(" : fail");
    printf("\n");
}

void test_ObliviousArrayAssign() {
    bool pass = true;
    for (int i = 0; i < 100; i++) {
        double d_arr[100]; 
        for (int i = 0; i < 100; i++) {
            d_arr[i] = i + 0.5;
        }
        ObliviousArrayAssign(d_arr, i, 100, 999.0);
        if (i % 10 == 0)
            printf("%f ", d_arr[i]);
        for (int j = 0; j < 100; j++) {
            if (i == j)
                pass = pass && (d_arr[j] == 999);
            else
                pass = pass && (d_arr[j] == j + 0.5);
        }
    }
    if (pass) 
        printf(" : pass");
    else
        printf(" : fail");
    printf("\n");

    pass = true;
    for (int i = 0; i < 100; i++) {
        Generic_16B g_arr[100]; 
        for (int i = 0; i < 100; i++) {
            g_arr[i] = Generic_16B(i+0.5, i);
        }
        ObliviousArrayAssign(g_arr, i, 100, Generic_16B(999.0, 999));
        if (i % 10 == 0)
            printf("%f,%llu ", g_arr[i].x, g_arr[i].y);
        for (int j = 0; j < 100; j++) {
            if (i == j)
                pass = pass && (g_arr[j].x == 999.0) && (g_arr[j].y == 999);
            else
                pass = pass && (g_arr[j].x == j + 0.5) && (g_arr[j].y == j);
        }
    }
    if (pass) 
        printf(" : pass");
    else
        printf(" : fail");
    printf("\n");
}

/***************************************************************************************
 * Main
 **************************************************************************************/

// int main() {
//     test_ObliviousGreater();
//     test_ObliviousLess();
//     test_ObliviousEqual();
//     test_ObliviousAssign();
//     test_ObliviousSort();
//     test_ObliviousArrayAccess();
//     test_ObliviousArrayAssign(); 
//     return 0;
// }
