#include <string.h>
#include <errno.h>
#ifdef COAP_DTLS_EN
#include <gnutls/gnutls.h>
#endif
#include "m_client.h"
#include "coap_msg.h"
#include "coap_mem.h"
#include "coap_log.h"

#define M_CLIENT_URI_PATH_BUF_LEN  32
#define M_CLIENT_BIG_BUF_NUM       128
#define M_CLIENT_BIG_BUF_LEN       1024
#define M_CLIENT_SMALL_BUF_NUM     128
#define M_CLIENT_SMALL_BUF_LEN     256

/* one-time initialisation */
int m_client_init(void)
{
#ifdef COAP_DTLS_EN
    const char *gnutls_ver = NULL;
#endif
    int ret = 0;

    coap_log_set_level(COAP_LOG_DEBUG);
    ret = coap_mem_big_create(M_CLIENT_BIG_BUF_NUM, M_CLIENT_BIG_BUF_LEN);
    if (ret != 0)
    {
        coap_log_error("%s", strerror(-ret));
        return -1;
    }
    ret = coap_mem_small_create(M_CLIENT_SMALL_BUF_NUM, M_CLIENT_SMALL_BUF_LEN);
    if (ret != 0)
    {
        coap_log_error("%s", strerror(-ret));
        coap_mem_big_destroy();
        return -1;
    }
#ifdef COAP_DTLS_EN
    gnutls_ver = gnutls_check_version(NULL);
    if (gnutls_ver == NULL)
    {
        coap_log_error("Unable to determine GnuTLS version");
        coap_mem_small_destroy();
        coap_mem_big_destroy();
        return -1;
    }
    coap_log_info("GnuTLS version: %s", gnutls_ver);
#endif
    return 0;
}

void m_client_deinit(void)
{
    coap_mem_small_destroy();
    coap_mem_big_destroy();
}

int m_client_create(m_client_t *client,
                      const char *host,
                      const char *port,
                      const char *key_file_name,
                      const char *cert_file_name,
                      const char *trust_file_name,
                      const char *crl_file_name,
                      const char *common_name)
{
    int ret = 0;

    memset(client, 0, sizeof(m_client_t));
#ifdef COAP_DTLS_EN
    ret = coap_client_create(&client->coap_client,
                             host,
                             port,
                             key_file_name,
                             cert_file_name,
                             trust_file_name,
                             crl_file_name,
                             common_name);
#else
    ret = coap_client_create(&client->coap_client,
                             host,
                             port);
#endif
    if (ret < 0)
    {
        coap_log_error("%s", strerror(-ret));
        memset(client, 0, sizeof(m_client_t));
        return ret;
    }
    return 0;
}

void m_client_destroy(m_client_t *client)
{
    coap_client_destroy(&client->coap_client);
    memset(client, 0, sizeof(m_client_t));
}

int m_client_register(m_client_t *client, char *buf, size_t len)
{
    coap_msg_t resp = {0};
    coap_msg_t req = {0};
    size_t n = 0;
    char *p = NULL;
    char uri_path[M_CLIENT_URI_PATH_BUF_LEN] = {0};
    int created = 0;
    int ret = 0;

    /* generate request */
    coap_msg_create(&req);
    coap_msg_set_type(&req, COAP_MSG_CON);
    coap_msg_set_code(&req, COAP_MSG_REQ, COAP_MSG_POST);
    coap_log_info("Sending POST /client/id request with payload: '%s'", buf);
    ret = coap_msg_add_op(&req, COAP_MSG_URI_PATH, 6, "client");
    if (ret < 0)
    {
        coap_log_error("Failed to set URI path in request message");
        coap_msg_destroy(&req);
        return ret;
    }
    ret = coap_msg_add_op(&req, COAP_MSG_URI_PATH, 2, "id");
    if (ret < 0)
    {
        coap_log_error("Failed to set URI path in request message");
        coap_msg_destroy(&req);
        return ret;
    }
    ret = coap_msg_set_payload(&req, buf, strlen(buf));
    if (ret < 0)
    {
        coap_log_error("Failed to set payload in request message");
        coap_msg_destroy(&req);
        return ret;
    }

    /* exchange */
    coap_msg_create(&resp);
    ret = coap_client_exchange(&client->coap_client, &req, &resp);
    if (ret < 0)
    {
        if (ret != -1)
        {
            /* a return value of -1 indicates a DTLS failure which has already been logged */
            coap_log_error("%s", strerror(-ret));
        }
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return ret;
    }

    /* process response */
    if (coap_msg_get_ver(&req) != coap_msg_get_ver(&resp))
    {
        coap_log_error("Received response message with invalid version: %d", coap_msg_get_ver(&resp));
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -EBADMSG;
    }
    if ((coap_msg_get_code_class(&resp) != COAP_MSG_SUCCESS)
     || ((coap_msg_get_code_detail(&resp) != COAP_MSG_CREATED) && (coap_msg_get_code_detail(&resp) != COAP_MSG_CHANGED)))
    {
        coap_log_error("Received response message with invalid code class: %d, code detail: %d",
                       coap_msg_get_code_class(&resp), coap_msg_get_code_detail(&resp));
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -EBADMSG;
    }
    created = coap_msg_get_code_detail(&resp) == COAP_MSG_CREATED;
    n = coap_msg_uri_path_to_str(&resp, uri_path, sizeof(uri_path));
    if ((n + 1) > sizeof(uri_path))
    {
        coap_log_error("URI path buffer too small by %zd bytes", (n + 1) - sizeof(uri_path));
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -ENOSPC;
    }
    if (strcmp(uri_path, "/client/id") != 0)
    {
        coap_log_error("Received response message with invalid URI path: '%s'", uri_path);
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -EBADMSG;
    }
    p = coap_msg_get_payload(&resp);
    n = coap_msg_get_payload_len(&resp);
    if ((p == NULL) || (n == 0))
    {
        coap_log_error("Received response message with invalid payload");
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -EBADMSG;
    }
    if ((n + 1) > len)
    {
        coap_log_error("Payload buffer too small by %zd bytes", (n + 1) - len);
        coap_msg_destroy(&resp);
        coap_msg_destroy(&req);
        return -ENOSPC;
    }
    memcpy(buf, p, n);
    memset(buf + n, 0, len - n);
    coap_msg_destroy(&resp);
    coap_msg_destroy(&req);
    if (strcmp(buf, "OK") != 0)
    {
        coap_log_error("Received response message with unexpected payload: '%s'", buf);
        return -EBADMSG;
    }
    coap_log_info("Received %s %s response with payload: '%s'",
                  created ? "CREATED" : "CHANGED", uri_path, buf);
    return n;
}
