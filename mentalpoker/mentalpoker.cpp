#include <tchar.h>
#include <cstdio>
#include <cstdlib>
#include <time.h>

#include <openssl/bn.h>

void bn_print(BIGNUM *n)
{
	int len = BN_num_bytes(n);
	unsigned char *data = (unsigned char*)malloc(len);
	BN_bn2bin(n, data);
	for(int i = 0; i < len; i++)
		printf("%02x", data[i]);
	free(data);
}

BIGNUM *bn_gen_prime()
{
	BIGNUM *ret = BN_new();
	if(ret == NULL)
		return NULL;
	if(BN_generate_prime_ex(ret, 32, true, NULL, NULL, NULL) != 1) {
		BN_free(ret);
		ret = NULL;
	}
	return ret;
}

int _tmain(int argc, _TCHAR* argv[])
{
	BIGNUM *bn;

	srand((unsigned int)time(NULL));
	bn = bn_gen_prime();
	bn_print(bn);
	printf("\n");

	BN_free(bn);
	printf("Press Enter to continue\n");
	getchar();
	return 0;
}

