#include <stdio.h> 
#include <stdlib.h> 
#include <openssl/crypto.h> 
#include <openssl/err.h> 
#include <openssl/pem.h> 
#include <openssl/rand.h>
#include <string.h>

//gcc 2xmp.c -lssl -lcrypt && cat req.pem | ./a.out cacert.pem key.pem cert.pem

int seed_prng(int bytes) 
{ 
 if (!RAND_load_file("/dev/random", bytes)) 
 return 0; 
 return 1; 
}

int main(int argc, char *argv[]) 
{ 
 PKCS7 *pkcs7; 
 const EVP_CIPHER *cipher; 
 STACK_OF(X509) *certs; 
 X509 *cert;  
 FILE *fp; 
 BIO *pkcs7_bio, *in, *out; 
 PKCS7_SIGNER_INFO *si;
 
 OpenSSL_add_all_algorithms(); 
 ERR_load_crypto_strings(); 
 seed_prng(16); 
 BIO *out2 = BIO_new_file("foo.txt", "w");
 if(!out)
 printf("errorerror");
 --argc, ++argv; 
 
 
 /* setup the BIO objects for stdin and stdout */ 
 if (!(in = BIO_new_fp(stdin, BIO_NOCLOSE)) || 
 !(out = BIO_new_fp(stdout, BIO_NOCLOSE))) 
 { 
 fprintf(stderr, "Error creating BIO objects\n"); 
 goto err; 
 } 
  
 /* choose cipher and read in all certificates as encryption 
targets */ 
 cipher = EVP_des_ede3_cbc(); 
 certs = sk_X509_new_null(); 
  
 X509 *tmp; 
 
 if (!(fp = fopen(*argv, "r")) || 
 !(tmp = PEM_read_X509(fp, NULL, NULL, NULL))) 
 { 
 fprintf(stderr, "Error reading encryption certificate in %s\n", *argv);
 goto err; 
 } 
 sk_X509_push(certs, tmp); 
 fclose(fp); 
 --argc, ++argv; 
 
 if (!(pkcs7 = PKCS7_encrypt(certs, in, cipher, PKCS7_BINARY))) 
 { 
 ERR_print_errors_fp(stderr); 
 fprintf(stderr, "Error making the PKCS#7 object\n"); 
 goto err; 
 } 

 if (i2d_PKCS7_bio(out2, pkcs7) != 1)  //something with i2d in order to get DER
 { 
 fprintf(stderr, "Error writing the S/MIME data\n"); 
 goto err; 
 } 
 BIO_free(out2);
 //now we need signing
out2 = BIO_new_file("foo.txt", "r");

 EVP_PKEY *pkey; 
 
 /* read the signer private key */ 
 if (!(fp = fopen(*argv, "r")) || 
 !(pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL))) 
 { 
 fprintf(stderr, "Error reading signer private key in %s\n", *argv); 
 goto err; 
 } 
 fclose(fp); 
 --argc, ++argv; 
 
  /* read the signer certificate */ 
 if (!(fp = fopen(*argv, "r")) || 
 !(cert = PEM_read_X509(fp, NULL, NULL, NULL))) 
 { 
 ERR_print_errors_fp(stderr); 
 fprintf(stderr, "Error reading signer certificate in %s\n", 
*argv); 

goto err; 
 } 
 fclose(fp); 
 --argc, ++argv;
 
 
 if (argc) 
 printf("To much in argc!");

 if (!(pkcs7 = PKCS7_sign(NULL, NULL, NULL, out2, PKCS7_PARTIAL|PKCS7_REUSE_DIGEST))) 
 { 
 fprintf(stderr, "Error making the PKCS#7 object\n"); 
 goto err; 
 }
 if (!(si = PKCS7_sign_add_signer(pkcs7, cert, pkey, EVP_md5(), PKCS7_NOSMIMECAP))) 
 { 
 fprintf(stderr, "Error adding Signer\n"); 
 goto err; 
 }
 //pkcs7->d.sign->signer_info = sk_PKCS7_SIGNER_INFO_new_null();
 
 
 //example attribute
ASN1_OCTET_STRING *os;
int signed_string_nid = OBJ_create("2.16.840.1.113733.1.9.5","OID_example1","Our example OID1");
os=ASN1_OCTET_STRING_new();
char *str = "2DF86DA80CBA75AA03AA7949916C7108";
ASN1_OCTET_STRING_set(os,(unsigned char*)str,strlen(str));
PKCS7_add_signed_attribute(si,signed_string_nid,V_ASN1_OCTET_STRING,(char *)os);

ASN1_OCTET_STRING *os2;
signed_string_nid = OBJ_create("2.16.840.1.113733.1.9.6","OID_example3","Our example OID3");
os2=ASN1_OCTET_STRING_new();
char *str3 = "4E18EB679C9A75A3FB3A55D927174CF7";
ASN1_OCTET_STRING_set(os2,(unsigned char*)str3,strlen(str3));
PKCS7_add_signed_attribute(si,signed_string_nid,V_ASN1_OCTET_STRING,(char *)os2);

ASN1_PRINTABLESTRING *ps;
signed_string_nid = OBJ_create("2.16.840.1.113733.1.9.2","OID_example2","Our example OID2");
ps=ASN1_PRINTABLESTRING_new();
char *str2 = "19";
ASN1_STRING_set(ps,(unsigned char*)str2,strlen(str2));
PKCS7_add_signed_attribute(si,signed_string_nid,V_ASN1_PRINTABLESTRING,(char *)ps);

ASN1_PRINTABLESTRING *ps2;
signed_string_nid = OBJ_create("2.16.840.1.113733.1.9.7","OID_example4","Our example OID4");
ps2=ASN1_PRINTABLESTRING_new();
char *str4 = "12341234";
ASN1_STRING_set(ps2,(unsigned char*)str4,strlen(str4));
PKCS7_add_signed_attribute(si,signed_string_nid,V_ASN1_PRINTABLESTRING,(char *)ps2);



//pkcs7_copy_existing_digest(pkcs7, si);
PKCS7_SIGNER_INFO_sign(si);
//if(!PKCS7_add_signer(pkcs7, si))
//	printf("foo");
 //STACK_OF(PKCS7_SIGNER_INFO) *signer_sk;
 //signer_sk = sk_PKCS7_SIGNER_INFO_new_null();
 //sk_PKCS7_SIGNER_INFO_push(signer_sk,si);
//pkcs7->d.sign->signer_info = signer_sk;

STACK_OF(PKCS7_SIGNER_INFO) *signer_sk;
signer_sk=	pkcs7->d.sign->signer_info;
//sk_PKCS7_SIGNER_INFO_push(signer_sk,si);
sk_PKCS7_SIGNER_INFO_pop(signer_sk); //get rid of the original one
sk_PKCS7_SIGNER_INFO_push(signer_sk,si); //add the modified one

 if (!PKCS7_final(pkcs7, out2, PKCS7_BINARY)) 
 { 
 fprintf(stderr, "Error while finalizing\n"); 
 goto err; 
 }
 
 if (PEM_write_PKCS7(stdout, pkcs7) != 1) 
 { 
 fprintf(stderr, "Error writing the S/MIME data\n"); 
 goto err; 
 } 
 
 return 0; 
err: 
 return -1; 
} 
