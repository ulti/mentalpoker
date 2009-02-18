#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <time.h>
#ifdef _MSC_VER
# include <tchar.h>
#endif

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <vector>

using std::vector;


#define BITS 128

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


typedef struct key_st
{
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
} KEY;

KEY *KEY_new()
{
	KEY *key = (KEY*)malloc(sizeof KEY);
	key->p = key->q = key->n = key->e = key->d = NULL;
	return key;
}

void KEY_free(KEY *key)
{
	BN_clear_free(key->p);
	BN_clear_free(key->q);
	BN_clear_free(key->n);
	BN_clear_free(key->e);
	BN_clear_free(key->d);
	free(key);
}

void KEY_generate_keys(KEY *key, BIGNUM *p, BIGNUM *q)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *phi;
	BIGNUM *gcd = BN_new();

	key->p = BN_dup(p);
	key->q = BN_dup(q);

	key->n = BN_new();
	BN_mul(key->n, key->p, key->q, ctx);

	phi = BN_dup(key->n);
	BN_sub(phi, phi, key->p);
	BN_sub(phi, phi, key->q);
	BN_add(phi, phi, BN_value_one());

	key->e = BN_new();
	while(1) {
		BN_rand_range(key->e,phi);
		BN_gcd(gcd,key->e,phi,ctx);
		if(BN_is_one(gcd))
			break;
	}

	key->d = BN_new();
	BN_mod_inverse(key->d, key->e, phi, ctx);

	BN_clear_free(gcd);
	BN_clear_free(phi);
	BN_CTX_free(ctx);
}

void KEY_encrypt(KEY *key, const unsigned char *msg, unsigned int mlen, unsigned char **sig, unsigned int *slen)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *bnmsg = BN_bin2bn(msg, mlen, NULL);
	BIGNUM *bnsig = BN_new();
	int len;

	BN_mod_exp(bnsig, bnmsg, key->e, key->n, ctx);
	len = BN_num_bytes(bnsig);
	if(slen)
		*slen = len;
	if(sig) {
		*sig = (unsigned char *)malloc(len);
		BN_bn2bin(bnsig, *sig);
	}
	BN_clear_free(bnmsg);
	BN_clear_free(bnsig);
	BN_CTX_free(ctx);
}

void KEY_decrypt(KEY *key, unsigned char **msg, unsigned int *mlen, const unsigned char *sig, unsigned int slen)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *bnmsg = BN_new();
	BIGNUM *bnsig = BN_bin2bn(sig, slen, NULL);
	int len;

	BN_mod_exp(bnmsg, bnsig, key->d, key->n, ctx);
	len = BN_num_bytes(bnmsg);
	if(mlen)
		*mlen = len;
	if(msg) {
		*msg = (unsigned char *)malloc(len);
		BN_bn2bin(bnmsg, *msg);
	}
	BN_clear_free(bnmsg);
	BN_clear_free(bnsig);
	BN_CTX_free(ctx);
}


// bits 0-4: rank
// bits 5-6: suit
// bit 7: always set
typedef unsigned char CARD;

CARD CardFSuitRank(char suit, char rank)
{
	return 1<<7 | suit<<5 | rank;
}

char SuitFCard(CARD card)
{
	return (card & 0x60)>>5;
}

char RankFCard(CARD card)
{
	return card & 0x1f;
}

void SuitRankFCard(CARD card, char *suit, char *rank)
{
	if(suit)
		*suit = (card & 0x60)>>5;
	if(rank)
		*rank = card & 0x1f;
}

template <class T>
class Shuffleable : public vector<T>
{
public:
	void shuffle();
};

template <class T>
void Shuffleable<T>::shuffle()
{
	int max = this->size();
	for(int i = 0; i < max; i++) {
		int swapidx = i+rand()%(max-i);
		T temp = this->at(i);
		this->at(i) = this->at(swapidx);
		this->at(swapidx) = temp;
	}
}

typedef struct edata_st
{
	unsigned char *msg;
	unsigned int mlen;
} EDATA;

template class Shuffleable<EDATA>;


void show_deck(Shuffleable<EDATA> &deck)
{
	for(unsigned int i = 0; i < deck.size(); i++) {
		printf("Card %d:", i+1, deck[i].mlen);
		for(unsigned int j = 0; j < deck[i].mlen; j++)
			printf("%02x", deck[i].msg[j]);
		printf("\n");
	}
	printf("===\n");
}


#ifdef _MSC_VER
int _tmain(int argc, _TCHAR* argv[])
#else
int main(int argc, char *argv[])
#endif
{
	KEY *key1,*key2;
	vector<KEY *> p1keys,p2keys;
	BIGNUM *p,*q;
	Shuffleable<EDATA> deck;

	unsigned char *msg;
	unsigned char *msg2;
	unsigned int mlen;
	unsigned int mlen2;

	time_t curtime = time(NULL);
	RAND_seed(&curtime, sizeof time_t);

	// These primes are shared between both players, since they
	// both must generate keys from the same primes or else the
	// encryption won't be commutative.
	p = bn_gen_prime();
	q = bn_gen_prime();

	// Player 1 creates the deck.  Both players must have agreed
	// in advance what the deck should look like.
	for(int i = 0; i < 4; i++) {
		for(int j = 1; j <= 13; j++) {
			deck.push_back(EDATA());
			deck.back().msg = (unsigned char *)malloc(1);
			*(deck.back().msg) = CardFSuitRank(i,j);
			deck.back().mlen = 1;
		}
	}
	show_deck(deck);

	// Player 1 encrypts each card in the deck with the same key,
	// then shuffles and passes the deck to Player 2.  The key
	// used to encrypt the deck is not shared.
	key1 = KEY_new();
	KEY_generate_keys(key1,p,q);
	for(unsigned int i = 0; i < deck.size(); i++) {
		KEY_encrypt(key1, deck[i].msg, deck[i].mlen, &msg, &mlen);
		free(deck[i].msg);
		deck[i].msg = msg;
		deck[i].mlen = mlen;
	}
	deck.shuffle();
	show_deck(deck);

	// Player 2 encrypts each card in the deck with his own key,
	// then shuffles and passes the deck back to Player 1.
	key2 = KEY_new();
	KEY_generate_keys(key2,p,q);
	for(unsigned int i = 0; i < deck.size(); i++) {
		KEY_encrypt(key2, deck[i].msg, deck[i].mlen, &msg, &mlen);
		free(deck[i].msg);
		deck[i].msg = msg;
		deck[i].mlen = mlen;
	}
	deck.shuffle();
	show_deck(deck);

	// Player 1 decrypts each card with his key, then re-encrypts
	// the cards with a different key for each card.  He remembers
	// these keys but they are not shared.
	for(unsigned int i = 0; i < deck.size(); i++) {
		p1keys.push_back(KEY_new());
		KEY_generate_keys(p1keys[i], p, q);
		KEY_decrypt(key1, &msg, &mlen, deck[i].msg, deck[i].mlen);
		free(deck[i].msg);
		KEY_encrypt(p1keys[i], msg, mlen, &(deck[i].msg), &(deck[i].mlen));
	}
	KEY_free(key1);
	show_deck(deck);

	// Player 2 also decrypts each card and re-encrypts with
	// a different key for each card.  After this is done, he shares
	// the deck with Player 1.
	for(unsigned int i = 0; i < deck.size(); i++) {
		p2keys.push_back(KEY_new());
		KEY_generate_keys(p2keys[i], p, q);
		KEY_decrypt(key2, &msg, &mlen, deck[i].msg, deck[i].mlen);
		free(deck[i].msg);
		KEY_encrypt(p2keys[i], msg, mlen, &(deck[i].msg), &(deck[i].mlen));
	}
	KEY_free(key2);
	show_deck(deck);

	// Player 1 selects the card to draw, then passes its index to Player 2.
	// Player 2 sends his key for that card to Player 1, who uses both keys to
	// decrypt the card.  If the card should be revealed to both players,
	// Player 1 sends the revealed card value to Player 2.
	for(unsigned int i = 0; i < deck.size(); i++) {
		CARD c = 0;
		KEY_decrypt(p1keys[i], &msg, &mlen, deck[i].msg, deck[i].mlen);
		KEY_decrypt(p2keys[i], &msg2, &mlen2, msg, mlen);
		if(mlen2 == 1)
			c = *msg2;
		free(msg);
		free(msg2);
		if(c)
			printf("Drew card: %d/%d (index %d)\n", SuitFCard(c), RankFCard(c), i);
		else
			printf("Couldn't find top card\n");
	}

	// Cleanup
	for(unsigned int i = 0; i < deck.size(); i++)
		free(deck[i].msg);
	deck.clear();
	for(unsigned int i = 0; i < p1keys.size(); i++)
		KEY_free(p1keys[i]);
	p1keys.clear();
	for(unsigned int i = 0; i < p2keys.size(); i++)
		KEY_free(p2keys[i]);
	p2keys.clear();
	BN_clear_free(p);
	BN_clear_free(q);

	printf("Press Enter to continue\n");
	getchar();
	return 0;
}
