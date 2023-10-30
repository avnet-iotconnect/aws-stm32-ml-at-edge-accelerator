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
#include "ota_pal.h"

#define IOTCONNECT_BALTIMORE_CYBER_TRUST_ROOT \
"-----BEGIN CERTIFICATE-----\n"\
"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\n"\
"-----END CERTIFICATE-----\n"

#define IOTCONNECT_DIGICERT_GLOBAL_ROOT_G2 \
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
#define GODADDY_ROOT_CERTIFICATE_AUTHORITY_G2 \
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
"-----END CERTIFICATE-----\n"

 // 9 megabytes will be 7 digits
#define DATA_BYTE_SIZE_CHAR_MAX 7

// NOTE: If this chunk size is 4k or more, this error happens during initial chunk download:
// Failed to read data: Error: SSL - Bad input parameters to function : <No-Low-Level-Code>. (mbedtls_transport.c:1649)
#define DATA_CHUNK_SIZE (1024 * 2)
/*
static buff_data_chunk[DATA_CHUNK_SIZE];
*/

#define HEADER_BUFFER_LENGTH 2048
static uint8_t buff_headers[HEADER_BUFFER_LENGTH];

#define RESPONSE_BUFFER_LENGTH (DATA_CHUNK_SIZE + 1024) /* base response buffer on chunk size and add a little extra */
static uint8_t buff_response[RESPONSE_BUFFER_LENGTH];

//PkiObject_t ca_certificates[] = { PKI_OBJ_PEM(IOTCONNECT_DIGICERT_GLOBAL_ROOT_G2) };
//static PkiObject_t ca_certificates[] = { PKI_OBJ_PEM((const unsigned char *)GODADDY_ROOT_CERTIFICATE_AUTHORITY_G2, sizeof(GODADDY_ROOT_CERTIFICATE_AUTHORITY_G2)) };
static PkiObject_t ca_certificates[] = {PKI_OBJ_PEM((const unsigned char *)IOTCONNECT_BALTIMORE_CYBER_TRUST_ROOT, sizeof(IOTCONNECT_BALTIMORE_CYBER_TRUST_ROOT))};

static void setup_request(HTTPRequestInfo_t* request, const char* method, const char* host, const char* path) {
    request->pMethod = method;
    request->methodLen = strlen(method);
    request->pPath = path;
    request->pathLen = strlen(path);
    request->pHost = host;
    request->hostLen = strlen(path);
    request->reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;
}

static void https_test(const char* host, const char* path) {
	TlsTransportStatus_t tls_transport_status;
	HTTPStatus_t http_status;
	OtaPalStatus_t pal_status;
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

    tls_transport_status = mbedtls_transport_connect(
    	network_conext,
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
    setup_request(&request, HTTP_METHOD_HEAD, host, path);

    http_status = HTTPClient_InitializeRequestHeaders( &headers, &request );
	if (0 != http_status) {
    	LogError("HTTP failed to initialize headers! Error: %s", HTTPClient_strerror(http_status));
    	return;
	}
/*
	// Here we get the total length.
	http_status = HTTPClient_AddRangeHeader(&headers, 0, 0);
	if (0 != http_status) {
	    	LogError("HTTP failed to add headers! Error: %s", HTTPClient_strerror(http_status));
	    	return;
		}
*/
    http_status = HTTPClient_Send(
		&transport_if,
		&headers, /* HTTPRequestHeaders_t  pRequestHeaders*/
		NULL, /*const uint8_t * pRequestBodyBuf*/
		0, /* size_t reqBodyBufLen*/
		&response,
		0 /* uint32_t sendFlags*/
	);
	if (0 != http_status) {
    	LogError("HTTP Send Error: %s", HTTPClient_strerror(http_status));
	}

	// NOTE: AWS S3 may be returning Content-Range
	const char* data_length_str = NULL;
	size_t data_length_str_len = 0;
	http_status = HTTPClient_ReadHeader( &response,
		"Content-Length",
		sizeof("Content-Length") - 1,
		&data_length_str,
		&data_length_str_len
	);
	if (0 != http_status) {
    	LogError("HTTP Error while obtaining headers: %s", HTTPClient_strerror(http_status));
	}

	if (response.statusCode != 200) {
		LogInfo("Response status code is: %u", response.statusCode);
	}

	if (NULL != data_length_str) {
		LogInfo("Response data length: %.*s", data_length_str_len, data_length_str);
	}

	if (data_length_str_len > DATA_BYTE_SIZE_CHAR_MAX) {
		LogInfo("Unsupported data length: %lu", data_length_str_len);
		return;
	}

	//LogInfo("Response body: %.*s", response.bodyLen, response.pBody);

	int data_length = 0;
	char data_length_buffer[DATA_BYTE_SIZE_CHAR_MAX + 1]; // for scanf to deal with a null terminated string
	strncpy(data_length_buffer, data_length_str, data_length_str_len);
	if (1 != sscanf(data_length_buffer, "%d", &data_length)) {
		LogInfo("Could not convert data length to number");
		return;
	}

	LogInfo("Response data length (number) is %d", data_length);

	OtaFileContext_t file_context;
	file_context.fileSize = (uint32_t)data_length;
	file_context.pFilePath = (uint8_t)"b_u585i_iot02a_ntz.bin";
	file_context.filePathMaxSize = (uint16_t)strlen(file_context.pFilePath);

	pal_status = otaPal_CreateFileForRx(&file_context);
	if (OtaPalSuccess != pal_status) {
		LogError("Ota failed to create file. Error: %u", pal_status);
	}
	// OtaPalImageState_t image_state = otaPal_GetPlatformImageState( OtaFileContext_t * const pFileContext );

	for (int data_start = 0; data_start < data_length; data_start += DATA_CHUNK_SIZE) {
		int data_end = data_start + DATA_CHUNK_SIZE;
		if (data_end > data_length) {
			data_end = data_length;
		}

	    http_status = HTTPClient_InitializeRequestHeaders(&headers, &request);
		if (0 != http_status) {
	    	LogError("HTTP failed to initialize headers! Error: %s", HTTPClient_strerror(http_status));
	    	return;
		}
		http_status = HTTPClient_AddRangeHeader(&headers, data_start, data_end - 1);
		if (0 != http_status) {
			LogError("HTTP failed to add range header! Error: %s", HTTPClient_strerror(http_status));
			return;
		}

		// TODO: not sure if we need to reset here
		memset(&request, 0, sizeof(request));
	    setup_request(&request, HTTP_METHOD_GET, host, path);

	    http_status = HTTPClient_Send(
			&transport_if,
			&headers, /* HTTPRequestHeaders_t  pRequestHeaders*/
			NULL, /*const uint8_t * pRequestBodyBuf*/
			0, /* size_t reqBodyBufLen*/
			&response,
			0 /* uint32_t sendFlags*/
		);
		if (0 != http_status) {
	    	LogError("HTTP Send Error: %s", HTTPClient_strerror(http_status));
	    	return;
		}
	    LogInfo("%d-%d(%d) ", data_start, data_end - 1, (int)response.bodyLen);
/*
	    uint16_t bytes_written = otaPal_WriteBlock(
	    	&file_context,
			data_start,
			response.pBody,
			response.bodyLen
	    );
	    if (bytes_written != response.bodyLen) {
	    	LogError("Expected to write %d bytes, but wrote %u!", response.bodyLen, bytes_written);
	    	return;
	    }
	    */
	}

	pal_status = otaPal_ActivateNewImage(&file_context);
	if (OtaPalSuccess != pal_status) {
		LogError("OTA failed activate the downloaded firwmare. Error: %u", pal_status);
	}
    vTaskDelay(100);
    mbedtls_transport_disconnect(network_conext);

}

void vHTTPSTestTask( void * parameters) {
    (void) parameters;

    vTaskDelay( 15000 );


    //https_test("discovery.iotconnect.io", "/");
    https_test("saleshosted.z13.web.core.windows.net", "/demo/st/b_u585i_iot02a_ntz-orig.bin");

	LogInfo("HTTPS Test Done.");

    while (true) {
    	vTaskDelay(10000);
    }


}

