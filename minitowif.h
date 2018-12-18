#ifndef minitowif_H
#define minitowif_H

int is_valid_minikey(char *minikey);
int base58encode(char **base58str, unsigned char *data, int datalen);
int minikey_to_private_key(char *minikey, unsigned char *privkey);
int private_key_to_wif(char **wifkey, unsigned char *privkey, int keylen);
int ecdsa_get_pubkey(unsigned char **pubkey, unsigned char *rawprivkey, int keylen);
int pubkey_to_address(char **address, unsigned char *pubkey, int keylen);

#endif