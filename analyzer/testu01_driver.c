/* TestU01 battery driver.
 *
 * Runs SmallCrush / Crush / BigCrush / Rabbit / Alphabit on a text file of
 * 32-bit unsigned decimal integers (one per line). Compile under WSL:
 *
 *   gcc -O2 -o testu01_driver testu01_driver.c -ltestu01 -ltestu01mylib -ltestu01probdist -lm
 *
 * Usage: testu01_driver <smallcrush|crush|bigcrush|rabbit|alphabit> <textfile>
 */
#include <stdio.h>
#include <string.h>
#include <testu01/bbattery.h>
#include <testu01/ufile.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <battery> <textfile>\n", argv[0]);
        return 1;
    }
    unif01_Gen *gen = ufile_CreateReadText(argv[2], 100000);
    if (gen == NULL) {
        fprintf(stderr, "failed to open %s\n", argv[2]);
        return 1;
    }
    if (strcmp(argv[1], "smallcrush") == 0) {
        bbattery_SmallCrush(gen);
    } else if (strcmp(argv[1], "crush") == 0) {
        bbattery_Crush(gen);
    } else if (strcmp(argv[1], "bigcrush") == 0) {
        bbattery_BigCrush(gen);
    } else if (strcmp(argv[1], "rabbit") == 0) {
        bbattery_Rabbit(gen, 1000000.0);
    } else if (strcmp(argv[1], "alphabit") == 0) {
        bbattery_Alphabit(gen, 1000000.0, 0, 32);
    } else {
        fprintf(stderr, "unknown battery: %s\n", argv[1]);
        return 1;
    }
    return 0;
}
