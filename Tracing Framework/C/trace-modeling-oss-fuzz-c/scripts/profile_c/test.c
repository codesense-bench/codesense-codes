int a = 5;

int foo() {
    return 0;
}

int main(int argc, char **argv)
{
    int x = 0, y = 10;
    int z;
    char b;
    char c = y;
    if (x > 10) {
        return y;
    }
    while (x < 10) {
        x ++;
    }
    do {
        x --;
    } while (x > 0);
    for (int z = 0; z < 5; z ++) {
        y ++;
    }
    for (; z < 5; z ++) {
        y ++;
    }
    switch (y) {
        case 10:
        break;
        default:
        foo();
    }
    return 0;
}