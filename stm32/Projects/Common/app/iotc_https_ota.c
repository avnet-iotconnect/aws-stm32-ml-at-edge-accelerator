#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "logging_levels.h"
/* define LOG_LEVEL here if you want to modify the logging level from the default */

#define LOG_LEVEL LOG_INFO

#include "logging.h"

#include "FreeRTOS.h"
#include "mbedtls_transport.h"
#include "core_http_client.h"


#define IOTCONNECT_DIGICERT_GLOBAL_ROOT_G2 (\
"-----BEGIN CERTIFICATE-----\n"\
"MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh\n"\
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"\
"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\n"\
"MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT\n"\
"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n"\
"b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG\n"\
"9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI\n"\
"2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx\n"\
"1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ\n"\
"q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz\n"\
"tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ\n"\
"vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP\n"\
"BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV\n"\
"5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY\n"\
"1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4\n"\
"NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG\n"\
"Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91\n"\
"8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe\n"\
"pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl\n"\
"MrY=\n"\
"-----END CERTIFICATE-----\n"

// CN = Go Daddy Root Certificate Authority - G2
#define GODADDY_ROOT_CERTIFICATE_AUTHORITY_G2 (\
"-----BEGIN CERTIFICATE-----\n"\
"MIIDxTCCAq2gAwIBAgIBADANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVVMx\n"\
"EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT\n"\
"EUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRp\n"\
"ZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5MDkwMTAwMDAwMFoXDTM3MTIzMTIz\n"\
"NTk1OVowgYMxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQH\n"\
"EwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjExMC8GA1UE\n"\
"AxMoR28gRGFkZHkgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIw\n"\
"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9xYgjx+lk09xvJGKP3gElY6SKD\n"\
"E6bFIEMBO4Tx5oVJnyfq9oQbTqC023CYxzIBsQU+B07u9PpPL1kwIuerGVZr4oAH\n"\
"/PMWdYA5UXvl+TW2dE6pjYIT5LY/qQOD+qK+ihVqf94Lw7YZFAXK6sOoBJQ7Rnwy\n"\
"DfMAZiLIjWltNowRGLfTshxgtDj6AozO091GB94KPutdfMh8+7ArU6SSYmlRJQVh\n"\
"GkSBjCypQ5Yj36w6gZoOKcUcqeldHraenjAKOc7xiID7S13MMuyFYkMlNAJWJwGR\n"\
"tDtwKj9useiciAF9n9T521NtYJ2/LOdYq7hfRvzOxBsDPAnrSTFcaUaz4EcCAwEA\n"\
"AaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE\n"\
"FDqahQcQZyi27/a9BUFuIMGU2g/eMA0GCSqGSIb3DQEBCwUAA4IBAQCZ21151fmX\n"\
"WWcDYfF+OwYxdS2hII5PZYe096acvNjpL9DbWu7PdIxztDhC2gV7+AJ1uP2lsdeu\n"\
"9tfeE8tTEH6KRtGX+rcuKxGrkLAngPnon1rpN5+r5N9ss4UXnT3ZJE95kTXWXwTr\n"\
"gIOrmgIttRD02JDHBHNA7XIloKmf7J6raBKZV8aPEjoJpL1E/QYVN8Gb5DKj7Tjo\n"\
"2GTzLH4U/ALqn83/B2gX2yKQOC16jdFU8WnjXzPKej17CuPKf1855eJ1usV2GDPO\n"\
"LPAvTK33sefOT6jEm0pUBsV/fdUID+Ic/n4XuKxe9tQWskMJDE32p2u0mYRlynqI\n"\
"4uJEvlz36hz1\n"\
"-----END CERTIFICATE-----\n")


/* Template HTTP request for a GET request. */
#define HTTPS_TEST_GET_HEADERS         \
    "GET / HTTP/1.1\r\n" \
    "Content-Type: application/json\r\n"      \
    "Connection: close\r\n"      \
    "\r\n"

#define HTTPS_TEST_GET_HEADERS_LENGTH               ( sizeof( HTTPS_TEST_GET_HEADERS ) - 1U )

#define HEADER_BUFFER_LENGTH 512
static uint8_t buff_headers[HEADER_BUFFER_LENGTH];

#define RESPONSE_BUFFER_LENGTH 6000
static uint8_t buff_response[RESPONSE_BUFFER_LENGTH];

//PkiObject_t ca_certificates[] = { PKI_OBJ_PEM(IOTCONNECT_DIGICERT_GLOBAL_ROOT_G2) };
static PkiObject_t ca_certificates[] = { PKI_OBJ_PEM((const unsigned char *)GODADDY_ROOT_CERTIFICATE_AUTHORITY_G2, sizeof(GODADDY_ROOT_CERTIFICATE_AUTHORITY_G2)) };

static void https_test(const char* host, const char* path) {
	TlsTransportStatus_t tls_transport_status;
	HTTPStatus_t http_status;

	const char * alpn_protocols[] = {  NULL };

    NetworkContext_t* network_conext = mbedtls_transport_allocate();
    if (NULL == network_conext) {
        LogError("Failed to allocate network context!");
        return;
    }

    /* ALPN protocols must be a NULL-terminated list of strings. */
    tls_transport_status = mbedtls_transport_configure(
        network_conext,
		alpn_protocols,
        NULL,
        NULL,
        ca_certificates,
        1
    );
    if( TLS_TRANSPORT_SUCCESS != tls_transport_status) {
        LogError("Failed to configure mbedtls transport! Error: %d", tls_transport_status);
        return;
    }

    vTaskDelay( 10000 );

    tls_transport_status = mbedtls_transport_connect( network_conext,
    	host,
        443,
        5000,
		5000
    );
    if (TLS_TRANSPORT_SUCCESS != tls_transport_status) {
        LogError("HTTPS: Failed to connect! Error: %d", tls_transport_status);
        return;
    }

    TransportInterface_t transport_if = {0};
	transport_if.pNetworkContext = network_conext;
	transport_if.send = mbedtls_transport_send;
	transport_if.recv = mbedtls_transport_recv;

	HTTPRequestHeaders_t headers = {0};
    headers.pBuffer = buff_headers;
	headers.bufferLen = sizeof(buff_headers);

    static HTTPResponse_t response = {0};
    response.pBuffer = buff_response;
    response.bufferLen = sizeof(buff_response);

    HTTPRequestInfo_t request = { 0 };
    request.pMethod = HTTP_METHOD_GET;
    request.methodLen = sizeof( HTTP_METHOD_GET ) - 1;
    request.pPath = path;
    request.pathLen = strlen(path);
    request.pHost = host;
    request.hostLen = strlen(path);

    http_status = HTTPClient_InitializeRequestHeaders( &headers, &request );
	if (0 != http_status) {
    	LogError("HTTP failed to initialize headers! Error: %s", HTTPClient_strerror(http_status));
    	return;
	}

	http_status = HTTPClient_Send(
		&transport_if,
		&headers, /* HTTPRequestHeaders_t  pRequestHeaders*/
		NULL, /*const uint8_t * pRequestBodyBuf*/
		0, /* size_t reqBodyBufLen*/
		&response,
		HTTP_RESPONSE_CONNECTION_CLOSE_FLAG /* uint32_t sendFlags*/
	);
	if (0 != http_status) {
    	LogError("HTTP Error: %s", HTTPClient_strerror(http_status));
	}

	LogInfo("Response: %.*s", response.bodyLen, response.pBody);


	// wait for network
    vTaskDelay(10000);

    mbedtls_transport_disconnect(network_conext);

/*

    HTTPStatus_t HTTPClient_Send( const TransportInterface_t * pTransport,
                              HTTPRequestHeaders_t * pRequestHeaders,
                              const uint8_t * pRequestBodyBuf,
                              size_t reqBodyBufLen,
                              HTTPResponse_t * pResponse,
                              uint32_t sendFlags );
}
*/
}

void vHTTPSTestTask( void * parameters) {
    (void) parameters;

    https_test("discovery.iotconnect.io", "/");
	LogInfo("HTTPS Test Done.");

    while (true) {
    	vTaskDelay(10000);
    }


}

