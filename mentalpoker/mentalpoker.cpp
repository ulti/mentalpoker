#include <cstdio>
#include <cstdlib>
#include <time.h>
#ifdef _MSC_VER
# include <tchar.h>
#endif

#include <openssl/bn.h>

#define BITS 32

void bn_print(const BIGNUM *a)
{
	int i,j,v,z=0;

	if (a->neg)
		printf("-");
	if (BN_is_zero(a))
		printf("0");

	for (i=a->top-1; i >=0; i--) {
		for (j=BN_BITS2-4; j >= 0; j-=4) {
			/* strip leading zeros */
			v=((int)(a->d[i]>>(long)j))&0x0f;
			if (z || (v != 0)) {
				printf("%x", v);
				z=1;
			}
		}
	}
	return;
}

BIGNUM *bn_gen_prime()
{
	BIGNUM *ret = BN_new();
	if(ret == NULL)
		return NULL;
	if(BN_generate_prime_ex(ret, BITS, true, NULL, NULL, NULL) != 1) {
		BN_free(ret);
		ret = NULL;
	}
	return ret;
}

#ifdef _MSC_VER
int _tmain(int argc, _TCHAR* argv[])
#else
int main(int argc, char *argv[])
#endif
{
	BIGNUM *rangemax,*gcd,*p,*q,*n,*phi,*e1,*e2,*d1,*d2;
	BIGNUM *data,*enc1,*enc2,*dec1,*dec2;
	BN_CTX *cntx = BN_CTX_new();

	srand((unsigned int)time(NULL));

	rangemax = BN_new();
	BN_set_word(rangemax, 1<<(BITS-1));

	p = bn_gen_prime();
	q = bn_gen_prime();

	// n = p*q
	n = BN_new();
	BN_mul(n,p,q,cntx);

	// phi = (p-1)(q-1)
	phi = BN_new();
	BN_mul(phi,p,q,cntx);
	BN_sub(phi,phi,p);
	BN_sub(phi,phi,q);
	BN_add(phi,phi,BN_value_one());

	// choose e so it is relatively prime to phi
	e1 = BN_new();
	gcd = BN_new();
	while(1) {
		BN_rand_range(e1,rangemax);
		BN_gcd(gcd,e1,phi,cntx);
		if(BN_is_one(gcd))
			break;
	}
	BN_free(gcd);

	// d = e^(-1) mod phi
	d1 = BN_new();
	BN_mod_inverse(d1,e1,phi,cntx);

	// choose a different e that is also relatively prime
	// to phi for the second party
	e2 = BN_new();
	gcd = BN_new();
	while(1) {
		BN_rand_range(e2,rangemax);
		BN_gcd(gcd,e2,phi,cntx);
		if(BN_is_one(gcd))
			break;
	}
	BN_free(gcd);

	// calculate d for second party
	d2 = BN_new();
	BN_mod_inverse(d2,e2,phi,cntx);

	printf("p: "); bn_print(p); printf("\n");
	printf("q: "); bn_print(q); printf("\n");
	printf("phi: "); bn_print(phi); printf("\n");
	printf("n: "); bn_print(n); printf("\n");
	printf("e1: "); bn_print(e1); printf("\n");
	printf("d1: "); bn_print(d1); printf("\n");
	printf("e2: "); bn_print(e2); printf("\n");
	printf("d2: "); bn_print(d2); printf("\n");

	// now to see if encrypting/decrypting works
	data = BN_new();
	enc1 = BN_new();
	enc2 = BN_new();
	dec1 = BN_new();
	dec2 = BN_new();
	BN_set_word(data, 0x42);
	BN_mod_exp(enc1,data,e1,n,cntx);
	BN_mod_exp(enc2,enc1,e2,n,cntx);
	BN_mod_exp(dec1,enc2,d1,n,cntx);
	BN_mod_exp(dec2,dec1,d2,n,cntx);

	printf("data: "); bn_print(data); printf("\n");
	printf("enc1: "); bn_print(enc1); printf("\n");
	printf("enc2: "); bn_print(enc2); printf("\n");
	printf("dec1: "); bn_print(dec1); printf("\n");
	printf("dec2: "); bn_print(dec2); printf("\n");

	BN_free(rangemax);
	BN_free(p);
	BN_free(q);
	BN_free(phi);
	BN_free(n);
	BN_free(e1);
	BN_free(d1);
	BN_free(e2);
	BN_free(d2);
	BN_CTX_free(cntx);

	printf("Press Enter to continue\n");
	getchar();
	return 0;
}
