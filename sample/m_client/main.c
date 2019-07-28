#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "m_client.h"

#define KEY_FILE_NAME    "../../certs/client_privkey.pem"
#define CERT_FILE_NAME   "../../certs/client_cert.pem"
#define TRUST_FILE_NAME  "../../certs/root_server_cert.pem"
#define CRL_FILE_NAME    ""
#define COMMON_NAME      "dummy/server"
#define BUF_LEN          32

int main(int argc, char **argv)
{
    m_client_t client = {0};
    size_t len = 0;
    char buf[BUF_LEN] = {0};
    int ret = 0;

    if (argc != 4)
    {
        fprintf(stderr, "usage: m_client host port client id\n");
        fprintf(stderr, "    host: IP address or host name to connect to\n");
        fprintf(stderr, "    port: port number to connect to\n");
        fprintf(stderr, "    id: any opaque identifier to be sent to the server\n");
        return EXIT_FAILURE;
    }
    len = strlen(argv[3]);
    if ((len + 1) > sizeof(buf))
    {
        fprintf(stderr, "error: id value too long (max %zd)\n", sizeof(buf) - 1);
        return EXIT_FAILURE;
    }
    ret = m_client_init();
    if (ret < 0)
    {
        return EXIT_FAILURE;
    }
    ret = m_client_create(&client,
                            argv[1],
                            argv[2],
                            KEY_FILE_NAME,
                            CERT_FILE_NAME,
                            TRUST_FILE_NAME,
                            CRL_FILE_NAME,
                            COMMON_NAME);
    if (ret < 0)
    {
        m_client_deinit();
        return EXIT_FAILURE;
    }
    memcpy(buf, argv[3], len);
    buf[len] = '\0';
    ret = m_client_register(&client, buf, sizeof(buf));
    if (ret < 0)
    {
        m_client_destroy(&client);
        m_client_deinit();
        return EXIT_FAILURE;
    }
    m_client_destroy(&client);
    m_client_deinit();
    return EXIT_SUCCESS;
}
