extern int main(int argsc, char **argsv);
extern int LLVMFuzzerRunDriver(int *argc, char ***argv,
                  int (*UserCb)(const uint8_t *Data, size_t Size));

static void setup() __attribute__ ((constructor));
static void cleanup() __attribute__ ((destructor));

void setup()
{
    printf("Hello OpenIKED.\n");
}

void cleanup()
{
}