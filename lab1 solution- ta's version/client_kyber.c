#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#include "kyber512/api.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>

AES_KEY *expanded;

uint8_t secret[16] = {
    0xb2, 0x01, 0x12, 0x93,
    0xe9, 0x55, 0x26, 0xa7,
    0xea, 0x69, 0x3a, 0xcb,
    0xfc, 0x7d, 0x0e, 0x1f};

/**
 * Configuration.
 */
struct Config
{
  char ip[15];
  uint16_t port_;
};

int kyber_keypair(uint8_t *pk, uint8_t* sk){
  int result = PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk);
  return result;
}

int kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk){
  int result = PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss, ct, sk);
  return result;
}

void printHelp(char *argv[])
{
  fprintf(
      stderr,
      "Usage: %s [-p port number] "
      "\n",
      argv[0]);
  exit(EXIT_FAILURE);
}

void parseOpt(int argc, char *argv[], struct Config *config)
{
  int opt;
  while ((opt = getopt(argc, argv, "p:")) != -1)
  {
    switch (opt)
    {
    case 'p':
      config->port_ = atoi(optarg);
      break;
    default:
      printHelp(argv);
    }
  }
}

/**
 * Set a read timeout.
 *
 * @param sk Socket.
 * @return True if successful.
 */
static bool SetReadTimeout(const int sk)
{
  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  if (setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
  {
    printf("unable to set read timeout\n");
    return false;
  }

  return true;
}

/**
 * Read n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to read.
 * @return True if successful.
 */
static bool ReadBytes(const int sk, char *buf, const size_t n)
{
  char *ptr = buf;
  while (ptr < buf + n)
  {
    if (!SetReadTimeout(sk))
    {
      return false;
    }

    int ret = recv(sk, ptr, ptr - buf + n, 0);
    if (ret <= 0)
    {
      //LOG(ERROR) << "unable to receive on socket";
      return false;
    }

    ptr += ret;
  }

  return true;
}

/**
 * Write n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to write.
 * @return True if successful.
 */
static bool WriteBytes(const int sk, const char *buf, const size_t n)
{
  char *ptr = buf;
  while (ptr < buf + n)
  {
    int ret = send(sk, ptr, n - (ptr - buf), 0);
    if (ret <= 0)
    {
      printf("unable to send on socket\n");
      return false;
    }

    ptr += ret;
  }

  return true;
}

bool send_kyber_public_key(const int socket_fd, const uint8_t *public_key, size_t key_length) {
    // Cast the uint8_t array to const char* and send
    return WriteBytes(socket_fd, (const char *)public_key, key_length);
}

bool read_kyber_ciphertext(const int socket_fd, uint8_t *ct, size_t ct_length) {
    // Cast the uint8_t array to char* and read into it
    return ReadBytes(socket_fd, (char *)ct, ct_length);
}

static void RunClient(struct Config *conf)
{
  int client_fd, messageSize, i;
  struct sockaddr_in serv_addr;
  uint8_t aes_key[PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES];
  char buffer[8192]={0};
  uint8_t pk[PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES];
  uint8_t ct[PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
  uint8_t plain[16];
  memset(&serv_addr, 0, sizeof(serv_addr));

  // Setup the socket connection
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
  {
    printf("unable to create client socket\n");
    return -1;
  }

  //printf("connecting to port: %i\n", conf->port_);

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(conf->port_);

  if (inet_pton(AF_INET, conf->ip, &serv_addr.sin_addr) <= 0) {
    printf("\nInvalid address/ Address not supported \n");
    return -1;
  }
 
  if ((client_fd = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
    printf("\nConnection Failed \n");
    return -1;
  }

  //Generate kyber keypair and send it to the server
  kyber_keypair(pk, sk);
  messageSize = PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES;
  WriteBytes(sock, &messageSize, sizeof(messageSize));
  send_kyber_public_key(sock, pk, sizeof(pk));

  //Get ciphertext from server
  if (!ReadBytes(sock, &messageSize, sizeof(messageSize)))
  {
    printf("unable to read server's ciphertext size\n");
    return;
  }
  //  printf("server's ct size: %i\n", messageSize);
 
  if (!read_kyber_ciphertext(sock, ct, messageSize))
  {
    printf("unable to read server's ciphertext\n");
    return;
  }
  //printf("server's ciphertext: \n%s\n", buffer);
  
  if (!ReadBytes(sock, buffer, 16))
  {
    printf("unable to read server's secret\n");
    return;
  }

  kyber_decapsulate(aes_key, ct, sk);

  // for (i = 0; i < 16; i++)
  //   printf("%02x ", (char) aes_key[i]);
  // printf("\n");

  expanded = (AES_KEY *)malloc(sizeof(AES_KEY));
  AES_set_decrypt_key((unsigned char *) aes_key, 128, expanded);
  AES_decrypt(buffer, plain, expanded);
  plain[16] = '\0';
  printf("Server's secret:\n");
  for(i = 0; i < 16; i++){
    printf("%c", (unsigned char) plain[i]);
  }
  printf("\n");

  free(expanded);
  close(client_fd);
}

int main(int argc, char **argv)
{
  struct Config conf;
  conf.port_ = 13000;
  //strcpy(conf.ip, "127.0.0.1");
  strcpy(conf.ip, "10.75.12.66");
  parseOpt(argc, argv, &conf);
  RunClient(&conf);
  return 0;
}
