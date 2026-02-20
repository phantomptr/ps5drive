#include "ps4_compat.h"

int main(void);

int _main(void) {
    ps4_sdk_init();
    return main();
}
