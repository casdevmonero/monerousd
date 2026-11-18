#include <cstdio>
#include <oqs/oqs.h>
int main(int argc, char** argv){
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
  if (!kem) { fprintf(stderr,"no ML-KEM\n"); return 1; }
  std::vector<uint8_t> pk(kem->length_public_key), sk(kem->length_secret_key);
  OQS_KEM_keypair(kem, pk.data(), sk.data());
  // print pubkey hex (for the daemon env) to stdout
  for (size_t i=0;i<pk.size();++i) printf("%02x", pk[i]);
  printf("\n");
  OQS_KEM_free(kem);
  return 0;
}
