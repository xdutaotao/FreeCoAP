#ifndef M_CLIENT_H
#define M_CLIENT_H

#include <stddef.h>
#include "coap_client.h"

typedef struct
{
    coap_client_t coap_client;
}
m_client_t;

int m_client_init(void);
void m_client_deinit(void);
int m_client_create(m_client_t *client,
                      const char *host,
                      const char *port,
                      const char *key_file_name,
                      const char *cert_file_name,
                      const char *trust_file_name,
                      const char *crl_file_name,
                      const char *common_name);
void m_client_destroy(m_client_t *client);
int m_client_register(m_client_t *client, char *buf, size_t len);

#endif
