#include <openssl/bn.h>

int _tmain(int argc, _TCHAR* argv[])
{
	BIGNUM *bn = BN_generate_prime(NULL, 32, true, NULL, NULL, NULL, NULL);
	free(bn);
	return 0;
}

