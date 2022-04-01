
/* Crash routine. */
void xerr(const char* msg);

void printerr(int err, char *str);

/* Initialize libgcrypt. */
void gcrypt_init();

/* Estimate the size of the encrypted key pair. */
size_t get_keypair_size(int nbits);

/* Create an AES context out of a user's password. */
void get_aes_ctx(gcry_cipher_hd_t* aes_hd);

void print_sexp(gcry_sexp_t rsa_keypair);

void dump_mem(const char *ptr, int len);


