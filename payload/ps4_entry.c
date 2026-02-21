#include "ps4_compat.h"

int main(void);
void ps4_sdk_init(void);

int _main(void) {
    ps4_sdk_init();
    return main();
}
