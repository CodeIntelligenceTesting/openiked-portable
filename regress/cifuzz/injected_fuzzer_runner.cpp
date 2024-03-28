

int main(int _argsc, char **_argsv)
{
    injected_fuzzer_send_arguments(_argsc, _argsv);

    int argsc; char **argsv;
    injected_fuzzer_recv_arguments(&argsc, &argsv);

    for(int i=0; i<argsc; ++i) {
        printf("%d: %s\n", i, argsv[i]);
    }

    return 0;
}