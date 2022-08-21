#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <regex.h>

#include "hmac-bcrypt.h"

void assert_matches(char *title, char *input, char *expected) {
    char    msgbuf[BUFSIZ];
    regex_t regex;

    printf("%-48s", title);

    int ret = regcomp(&regex, expected, REG_EXTENDED | REG_NEWLINE);

    if (ret) {
        regerror(ret, &regex, msgbuf, sizeof(msgbuf));
        printf("%s\n", msgbuf);
        return;
    }

    ret = regexec(&regex, input, 0, NULL, 0);
       
    if (ret) {
        regerror(ret, &regex, msgbuf, sizeof(msgbuf));
        printf("%s!\n", msgbuf);
    } else {
        printf("Passed\n");
    }
}

void assert_true(char *title, int ret) {
    printf(
        "%-48s%s\n", 
        title, 
        ret ? "Passed" : "Failed"
    );
}

int main() {
    char *password  = "test-pass";
    char *pepper    = "test-pepper";
    char *expected  = "$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ";

    assert_matches(
        "Supply password only",
        hmac_bcrypt_hash(password, NULL, NULL),
        "^\\$2a\\$[0-9]{2}\\$[.\\/+A-Za-z0-9]{108}$"
    );

    assert_matches(
        "Supply password and cost",
        hmac_bcrypt_hash(password, "$2a$10$", NULL),
        "^\\$2a\\$10\\$[.\\/+A-Za-z0-9]{108}$"
    );

    assert_matches(
        "Supply password and cost + salt",
        hmac_bcrypt_hash(password, "$2a$10$v.vnO5oVlX/5zJM9TTXSz.", NULL),
        "^\\$2a\\$10\\$v\\.vnO5oVlX/5zJM9TTXSz\\.[.\\/+A-Za-z0-9]{86}$"
    );

    assert_true(
        "Supply password and cost + salt + pepper",
        hmac_bcrypt_verify(password, expected, pepper)
    );

    return 0;
}
