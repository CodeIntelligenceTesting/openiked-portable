

int main(int _argsc, char **_argsv)
{
    write(_argsc, _argsv);

    int argsc, char **argsv
    read(&argsc, &argsv);

    for(int i=0; i<argsc; ++i) {
        printf("%d: %s\n", i, argsv[i]);
    }

    return 0;
}