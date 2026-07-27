/* WlStckD.h */
/*Includes*/
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// #include <netinet/in.h>
// #include <sys/socket.h>
// #include <arpa/inet.h>
// #include <fcntl.h>
/*Includes*/

/* Typedefinations */
typedef unsigned char i8;
typedef unsigned short i16;
typedef unsigned int i32;
typedef unsigned long i64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
typedef float f32;
typedef double f64;
typedef char byte;
/* Typedefinations */

/* MACROS */
#define alloc(x) malloc((i64)x)
#define dealloc(x)                                                             \
  do {                                                                         \
    free(x);                                                                   \
    x = NULL;                                                                  \
  } while (0)
#define true 1
#define True 1
#define false 0
#define False 0
#define public __attribute__((visibility("default")))
#define private static
#define internal __attribute__((visibility = "hidden"))
#define packed __attribute__((packed))
/* MACROS */

/* Definations */
#define ERR_STR "Error %d : %s"
/* Definations */

/* Function Signatures */
int main(int, char **);
/* Function Signatures */
