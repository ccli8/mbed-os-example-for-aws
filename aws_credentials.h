/*
 * AWS Certificates
 * Copyright (c) 2020 Arm Limited
 * SPDX-License-Identifier: Apache-2.0
 */


#ifndef AWS_CREDENTIALS_H
#define AWS_CREDENTIALS_H

namespace aws {
namespace credentials {
/*
 * PEM-encoded root CA certificate
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN CERTIFICATE-----\n"
 * "...base64 data...\n"
 * "-----END CERTIFICATE-----";
 */
const char rootCACrt[] = "-----BEGIN CERTIFICATE-----\n"
"...\n"
"...\n"
"...\n"
"-----END CERTIFICATE-----";

/*
 * PEM-encoded device certificate
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN CERTIFICATE-----\n"
 * "...base64 data...\n"
 * "-----END CERTIFICATE-----";
 */
const char deviceCrt[] = "-----BEGIN CERTIFICATE-----\n"
"...\n"
"...\n"
"...\n"
"-----END CERTIFICATE-----";

/*
 * PEM-encoded device public key
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN PUBLIC KEY-----\n"
 * "...base64 data...\n"
 * "-----END PUBLIC KEY-----\n"
 */
const char devicePubKey[] = "-----BEGIN PUBLIC KEY-----\n"
"...\n"
"...\n"
"...\n"
"-----END PUBLIC KEY-----\n";

/*
 * PEM-encoded device private key
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN RSA PRIVATE KEY-----\n"
 * "...base64 data...\n"
 * "-----END RSA PRIVATE KEY-----";
 */
const char devicePvtKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"
"...\n"
"...\n"
"...\n"
"-----END RSA PRIVATE KEY-----";

/*
 * PEM-encoded code verification certificate
 *
 * Must include the PEM header and footer,
 * and every line of the body needs to be quoted and end with \n:
 * "-----BEGIN CERTIFICATE-----\n"
 * "...base64 data...\n"
 * "-----END CERTIFICATE-----";
 */
const char codeVerCrt[] = "-----BEGIN CERTIFICATE-----\n"
"...\n"
"...\n"
"...\n"
"-----END CERTIFICATE-----";

}
}

#endif
