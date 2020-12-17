/*
 * Copyright (c) 2020 Arm Limited
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mbed.h"
#include "mbed_trace.h"
#include "mbedtls/debug.h"
#include "aws_credentials.h"

/* Upgraded MQTT library since 202009.00 */
extern "C" {
#include "core_mqtt.h"
#include "core_mqtt_state.h"
}
/* Include clock for timer. */
extern "C" {
#include "aws-iot-device-sdk-embedded-C/platform/include/clock.h"
}

/* Transport layer with Mbed TLS */
extern "C" {
#include "transport_mbed_tls.h"
}

// debugging facilities
#define TRACE_GROUP "Main"
static Mutex trace_mutex;
static void trace_mutex_lock()
{
    trace_mutex.lock();
}
static void trace_mutex_unlock()
{
    trace_mutex.unlock();
}
extern "C" void aws_iot_log_printf(const char * format, ...) {
    trace_mutex_lock();
    va_list args;
    va_start (args, format);
    vprintf(format, args);
    va_end (args);
    trace_mutex_unlock();
}

/* Size of the network buffer for MQTT packets. */
#define NETWORK_BUFFER_SIZE                     ( 1024U )

/* Transport timeout in milliseconds for transport send and receive. */
#define TRANSPORT_SEND_RECV_TIMEOUT_MS          ( 200U )

/* Timeout for receiving CONNACK packet in milli seconds. */
#define CONNACK_RECV_TIMEOUT_MS                 ( 5000U )

/* Time interval in seconds at which an MQTT PINGREQ need to be sent to broker. */
#define MQTT_KEEP_ALIVE_INTERVAL_SECONDS        ( 5U )

/* Timeout for MQTT_ProcessLoop() function in milliseconds.
 *
 * The timeout value is appropriately chosen for receiving an incoming
 * PUBLISH message and ack responses for QoS 1 and QoS 2 communications
 * with the broker.
 *
 * NOTE: To match one publish message sent by ourselves every 1 sec, we
 *       configure to 1000 ms.
 */
#define MQTT_PROCESS_LOOP_TIMEOUT_MS            ( 1000U )

/* Interval for PUBLISH packet resend when QoS > 0
 *
 * When publish resend is enabled, we may meet MQTTBadResponse error during MQTT_ProcessLoop:
 * No matching record found for publish: PacketId=xxx
 * This is caused by duplicate, drifting e.g. PUBACK packet for QoS 1, caused by resending duplicate PUBLISH packet.
 * The error actually can be ignored. To avoid confusion, disable publish resend.
 */
#define MATT_PUBLISH_RESEND_INTERVAL_MS         ( -1 )

/* Timeout for waiting publish/subscribe/unsubscribe ack when QoS > 0
 *
 * Note: only publish supports resend+timeout because coreMQTT doesn't maintain states for subscribe/unsubscribe.
 */
#define MQTT_TIMEOUT_MS                         ( 15000U )

/* Represents the Mbed TLS context used for TLS session with the broker for tests. */
TlsNetworkContext_t tlsNetworkContext;

/* Synchronization for notifying on receipt of message not published by ourselves */
Semaphore wait_sem {/* count */ 0, /* max_count */ 1};

// debugging facilities
#define TRACE_GROUP "Main"

static void handleIncomingPublish( MQTTPublishInfo_t * pPublishInfo,
                                   uint16_t packetIdentifier )
{
    assert( pPublishInfo != NULL );

    ( void ) packetIdentifier;

    /* Process incoming Publish. */
    tr_info("Incoming QOS : %d.", pPublishInfo->qos);

    /* Verify the received publish is for the topic we have subscribed to. */
    if( ( pPublishInfo->topicNameLength == strlen(MBED_CONF_APP_AWS_MQTT_TOPIC) ) &&
        ( 0 == strncmp( MBED_CONF_APP_AWS_MQTT_TOPIC,
                        pPublishInfo->pTopicName,
                        pPublishInfo->topicNameLength ) ) )
    {
        tr_info("Incoming Publish Topic Name: %.*s matches subscribed topic.\n"
                "Incoming Publish message Packet Id is %u.\n"
                "Incoming Publish Message : %.*s.\n\n",
                pPublishInfo->topicNameLength,
                pPublishInfo->pTopicName,
                packetIdentifier,
                ( int ) pPublishInfo->payloadLength,
                ( const char * ) pPublishInfo->pPayload);
        /* On receipt of a message not published by ourselves, exit */
        if (strncmp("Warning", (const char *) pPublishInfo->pPayload, 7) != 0) {
            tr_info("Hello %.*s !", pPublishInfo->payloadLength, pPublishInfo->pPayload);
            wait_sem.release();
        }
    }
    else
    {
        tr_info("Incoming Publish Topic Name: %.*s does not match subscribed topic.",
                pPublishInfo->topicNameLength,
                pPublishInfo->pTopicName);
    }
}

static void eventCallback( MQTTContext_t * pMqttContext,
                           MQTTPacketInfo_t * pPacketInfo,
                           MQTTDeserializedInfo_t * pDeserializedInfo )
{
    uint16_t packetIdentifier;

    assert( pMqttContext != NULL );
    assert( pPacketInfo != NULL );
    assert( pDeserializedInfo != NULL );

    /* Suppress unused parameter warning when asserts are disabled in build. */
    ( void ) pMqttContext;

    packetIdentifier = pDeserializedInfo->packetIdentifier;

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        assert( pDeserializedInfo->pPublishInfo != NULL );
        /* Handle incoming publish. */
        handleIncomingPublish( pDeserializedInfo->pPublishInfo, packetIdentifier );
    }
    else
    {
        /* Handle other packets. */
        switch( pPacketInfo->type )
        {
            case MQTT_PACKET_TYPE_PUBACK:
                tr_info("Published to the topic %.*s.\n\n",
                        strlen(MBED_CONF_APP_AWS_MQTT_TOPIC),
                        MBED_CONF_APP_AWS_MQTT_TOPIC);
                break;

            case MQTT_PACKET_TYPE_SUBACK:
                tr_info("Subscribed to the topic %.*s.\n\n",
                        strlen(MBED_CONF_APP_AWS_MQTT_TOPIC),
                        MBED_CONF_APP_AWS_MQTT_TOPIC);
                break;

            case MQTT_PACKET_TYPE_UNSUBACK:
                tr_info("Unsubscribed from the topic %.*s.\n\n",
                        strlen(MBED_CONF_APP_AWS_MQTT_TOPIC),
                        MBED_CONF_APP_AWS_MQTT_TOPIC);
                break;

            case MQTT_PACKET_TYPE_PINGRESP:
                /* Nothing to be done from application as library handles
                 * PINGRESP. */
                tr_warning("PINGRESP should not be handled by the application "
                           "callback when using MQTT_ProcessLoop.\n\n");
                break;

            case MQTT_PACKET_TYPE_PUBREC:
                tr_info("PUBREC received for packet id %u.\n\n",
                        packetIdentifier);
                break;

            case MQTT_PACKET_TYPE_PUBREL:
                /* Nothing to be done from application as library handles
                 * PUBREL. */
                tr_info("PUBREL received for packet id %u.\n\n",
                        packetIdentifier);
                break;

            case MQTT_PACKET_TYPE_PUBCOMP:
                /* Nothing to be done from application as library handles
                 * PUBCOMP. */
                tr_info("PUBCOMP received for packet id %u.\n\n",
                        packetIdentifier);
                break;

            /* Any other packet type is invalid. */
            default:
                tr_error("Unknown packet type received:(%02x).\n\n",
                         pPacketInfo->type);
        }
    }
}

/* Calculate elapsed time with wrap-around */
static uint32_t calculateElapsedTime( uint32_t start, uint32_t later )
{
    if (later >= start) {
        return (later - start);
    } else {
        return (uint32_t) ((uint64_t) later + (uint64_t) 0x100000000 - start); 
    }
}

/* Check if PUBLISH packet is not yet acknowledged */
static MQTTStatus_t mqttPublishPending( MQTTContext_t * pContext,
                                        uint16_t packetId,
                                        bool *pPending)
{
    assert(pContext != NULL);
    assert(pPending != NULL);

    *pPending = false;

    uint16_t packetIdToResend = MQTT_PACKET_ID_INVALID;
    MQTTStateCursor_t cursor = MQTT_STATE_CURSOR_INITIALIZER;

    do {
        packetIdToResend = MQTT_PublishToResend(pContext, &cursor);
        if (packetIdToResend == packetId) {
            *pPending = true;
            return MQTTSuccess;
        }
    } while (packetIdToResend != MQTT_PACKET_ID_INVALID);
    
    return MQTTSuccess;
}

/* Helper routine for MQTT_Publish plus resend
 *
 * resendIntervalMs > 0: resend every specified interval
 *                  = 0: resend instantly
 *                  < 0: no resend
 * timeoutMs        > 0: wait for specified time or until pending resolved
 *                  = 0: no wait
 *                  < 0: wait indefinitely
 */
static MQTTStatus_t mqttPublishWithResend( MQTTContext_t * pContext,
                                           MQTTPublishInfo_t * pPublishInfo,
                                           uint16_t packetId,
                                           int32_t resendIntervalMs,
                                           int32_t timeoutMs )
{
    assert(pContext != NULL);
    assert(pPublishInfo != NULL);

    MQTTStatus_t mqtt_status = MQTTSuccess;

    /* First send PUBLISH packet without DUP set */
    mqtt_status = MQTT_Publish(pContext, pPublishInfo, packetId);
    if (mqtt_status != MQTTSuccess) {
        tr_error("AWS Sdk: first send PUBLISH packet failed: %s.", MQTT_Status_strerror(mqtt_status));
        return mqtt_status;
    }
    /* Keep first send time */
    uint32_t firstSendTimeMs = Clock_GetTimeMs();
    uint32_t lastSendTimeMs = firstSendTimeMs;

    /* Needn't resend for QoS 0 */
    if (pPublishInfo->qos == MQTTQoS0) {
        return MQTTSuccess;
    }

    /* Non-blocking */
    if (timeoutMs == 0) {
        return MQTTSuccess;
    }

    /* Keep elapsed time since first send */
    uint32_t timeSinceFirstSendMs = 0;

    do {
        /* Poll for ack just one iteration */
        mqtt_status = MQTT_ProcessLoop(pContext, 0);
        if (mqtt_status != MQTTSuccess) {
            tr_error("AWS Sdk: poll for publish ack failed: %s.", MQTT_Status_strerror(mqtt_status));
            return mqtt_status;
        }

        /* Pending resolved? */
        bool pending = true;
        mqtt_status = mqttPublishPending(pContext, packetId, &pending);
        if (mqtt_status != MQTTSuccess) {
            tr_error("AWS Sdk: query publish pending failed: %s.", MQTT_Status_strerror(mqtt_status));
            return mqtt_status;
        }
        
        if (pending) {
            /* Resend PUBLISH packet with DUP set every resend interval */
            uint32_t timeSinceLastSendMs = calculateElapsedTime(lastSendTimeMs, Clock_GetTimeMs());
            if (resendIntervalMs < 0) {
                // No resend
            } else if (timeSinceLastSendMs >= resendIntervalMs) {
                pPublishInfo->dup = true;
                tr_info("AWS Sdk: resend PUBLISH packet every %u ms", resendIntervalMs);
                mqtt_status = MQTT_Publish(pContext, pPublishInfo, packetId);                
                if (mqtt_status != MQTTSuccess) {
                    tr_error("AWS Sdk: resend PUBLISH packet failed: %s.", MQTT_Status_strerror(mqtt_status));
                    return mqtt_status;
                }
                /* Keep resend time */
                lastSendTimeMs = Clock_GetTimeMs();
            }
        } else {
            /* Pending resolved */
            return MQTTSuccess;
        }

        timeSinceFirstSendMs = calculateElapsedTime(firstSendTimeMs, Clock_GetTimeMs());
    } while (timeoutMs < 0 || timeSinceFirstSendMs <= timeoutMs);

    /* No good error code for timeout. Pick a similar one. */
    tr_warning("AWS Sdk: publish ack timeout(%u ms), packetId(%u).", timeoutMs, packetId);
    return MQTTKeepAliveTimeout;
}

                           
int main()
{
    mbed_trace_mutex_wait_function_set( trace_mutex_lock ); // only if thread safety is needed
    mbed_trace_mutex_release_function_set( trace_mutex_unlock ); // only if thread safety is needed
    mbed_trace_init();

    tr_info("Connecting to the network...");
    auto eth = NetworkInterface::get_default_instance();
    if (eth == NULL) {
        tr_error("No Network interface found.");
        return -1;
    }
    auto ret = eth->connect();
    if (ret != 0) {
        tr_error("Connection error: %x", ret);
        return -1;
    }
    tr_info("MAC: %s", eth->get_mac_address());
    tr_info("Connection Success");

    // demo :
    /* Setup the transport interface object for the library. */
    TransportInterface_t transport = {
        .recv               = Mbed_Tls_Recv,
        .send               = Mbed_Tls_Send,
        .pNetworkContext    = &tlsNetworkContext
    };

    /* Network buffer for MQTT context */
    /* The network buffer must remain valid for the lifetime of the MQTT context. */
    static uint8_t buffer[NETWORK_BUFFER_SIZE];
    MQTTFixedBuffer_t networkBuffer = {    
        .pBuffer            = buffer,
        .size               = NETWORK_BUFFER_SIZE
    };

    MQTTContext_t mqttContext = {};
    auto init_status = MQTT_Init(&mqttContext,
                                 &transport,
                                 Clock_GetTimeMs,
                                 eventCallback,
                                 &networkBuffer);
    if (init_status != MQTTSuccess) {
        tr_error("Failed to initialize coreMQTT with %s", MQTT_Status_strerror(init_status));
        return -1;
    }

    // - Connect to mqtt broker

    // create network connection
    /* Server information */
    ServerInfo_t serverInfo = {
        .hostname           = MBED_CONF_APP_AWS_ENDPOINT,
        .port               = 8883
    };
    /* Credential information */
    CredentialInfo_t credentialInfo = {
        .rootCA             = aws::credentials::rootCACrt,
        .clientCrt          = aws::credentials::deviceCrt,
        .clientKey          = aws::credentials::devicePvtKey
    };
    auto tls_conn_status = Mbed_Tls_Connect(&tlsNetworkContext,
                                            &serverInfo,
                                            &credentialInfo,
                                            TRANSPORT_SEND_RECV_TIMEOUT_MS,
                                            TRANSPORT_SEND_RECV_TIMEOUT_MS);
    if (tls_conn_status != 0) {
        tr_error("AMbed_Tls_Connect failed with %d", tls_conn_status);
        return -1;
    }

    MQTTConnectInfo_t connect_info = {};
    connect_info.cleanSession = 1;
    connect_info.pClientIdentifier = MBED_CONF_APP_AWS_CLIENT_IDENTIFIER;
    connect_info.clientIdentifierLength = strlen(MBED_CONF_APP_AWS_CLIENT_IDENTIFIER);
    /* The interval at which an MQTT PINGREQ needs to be sent out to broker. */
    connect_info.keepAliveSeconds = MQTT_KEEP_ALIVE_INTERVAL_SECONDS;
    /* Username and password for authentication. Not used in this test. */
    connect_info.pUserName = NULL;
    connect_info.userNameLength = 0U;
    connect_info.pPassword = NULL;
    connect_info.passwordLength = 0U;

    /* Send MQTT CONNECT packet to broker. */
    bool sessionPresent;
    auto connect_status = MQTT_Connect(&mqttContext,
                                       &connect_info,
                                       NULL,
                                       CONNACK_RECV_TIMEOUT_MS,
                                       &sessionPresent);
    if (connect_status != MQTTSuccess) {
        tr_error("AWS Sdk: Connection to the MQTT broker failed with %s", MQTT_Status_strerror(connect_status));
        return -1;
    }
                                                  
    // - Subscribe to sdkTest/sub
    //   On message
    //   - Display on the console: "Hello %s", message
    /* Set the members of the subscription. */
    static const char topic[] = MBED_CONF_APP_AWS_MQTT_TOPIC;

    MQTTSubscribeInfo_t subscription = {};
    subscription.qos = MQTTQoS1;
    subscription.pTopicFilter = topic;
    subscription.topicFilterLength = strlen(topic);

    /* Generate packet identifier for the SUBSCRIBE packet. */
    auto packetId = MQTT_GetPacketId(&mqttContext);

    /* Send SUBSCRIBE packet. */
    auto sub_status = MQTT_Subscribe(&mqttContext,
                                     &subscription,
                                     1,
                                     packetId);
    if (sub_status != MQTTSuccess) {
        tr_error("AWS Sdk: Subscribe failed with : %s", MQTT_Status_strerror(sub_status));
        return -1;
    }

    /* Set the members of the publish info. */
    MQTTPublishInfo_t publishInfo = {};
    publishInfo.retain = false,
    publishInfo.qos = MQTTQoS1;
    publishInfo.dup = false;
    publishInfo.pTopicName = topic;
    publishInfo.topicNameLength = strlen(topic);
    for (uint32_t i = 0; i < 10; i++) {
        // - for i in 0..9
        //  - wait up to 1 sec
        //  - if no message received Publish: "You have %d sec remaining to say hello...", 10-i
        //  - other wise, exit
        if (wait_sem.try_acquire()) {
            break;
        }

        /* prepare the message */
        static char message[64];
        snprintf(message, 64, "Warning: Only %u second(s) left to say your name !", 10 - i);
        publishInfo.pPayload = message;
        publishInfo.payloadLength = strlen(message);
        /* Resend mechanism may change it. Reset it */
        publishInfo.dup = false;

        /* Get a new packet id. */
        auto packetId = MQTT_GetPacketId(&mqttContext);

        /* Send PUBLISH packet. */
        tr_info("sending warning message: %s", message);
        auto pub_status = mqttPublishWithResend(&mqttContext, &publishInfo, packetId, MATT_PUBLISH_RESEND_INTERVAL_MS, MQTT_TIMEOUT_MS);
        if (pub_status != MQTTSuccess) {
            tr_warning("AWS Sdk: failed to publish message with %s.", MQTT_Status_strerror(pub_status));
        }
        
        /* Process keep alive and other incoming packets */
        auto poll_status = MQTT_ProcessLoop(&mqttContext, MQTT_PROCESS_LOOP_TIMEOUT_MS);
        if (poll_status != MQTTSuccess) {
            tr_error("AWS Sdk: failed to run MQTT message pump with %s.", MQTT_Status_strerror(poll_status));
            return -1;
        }
    }

    /* Unubscribe to the topic. */
    /* Generate packet identifier for the UNSUBSCRIBE packet. */
    packetId = MQTT_GetPacketId(&mqttContext);

    /* Send UNSUBSCRIBE packet. */
    auto unsub_status = MQTT_Unsubscribe(&mqttContext,
                                         &subscription,
                                         1,
                                         packetId);
    if (unsub_status != MQTTSuccess) {
        tr_error("AWS Sdk: Unsubscribe failed with : %s", MQTT_Status_strerror(unsub_status));
        return -1;
    }

    /* Close the MQTT connection. */
    MQTT_Disconnect(&mqttContext);

    /* Close network connection. */
    Mbed_Tls_Disconnect(&tlsNetworkContext);

    tr_info("Done");

    return 0;
}
