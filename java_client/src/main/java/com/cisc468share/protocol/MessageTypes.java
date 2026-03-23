package com.cisc468share.protocol;

import java.util.Set;

public final class MessageTypes {
    private MessageTypes() {}

    public static final String PROTOCOL_VERSION = "1.0";

    public static final String CLIENT_HELLO = "CLIENT_HELLO";
    public static final String SERVER_HELLO = "SERVER_HELLO";
    public static final String HANDSHAKE_FINISH = "HANDSHAKE_FINISH";

    public static final String PING = "PING";
    public static final String PONG = "PONG";
    public static final String ERROR = "ERROR";

    public static final String LIST_FILES_REQUEST = "LIST_FILES_REQUEST";
    public static final String LIST_FILES_RESPONSE = "LIST_FILES_RESPONSE";
    public static final String GET_FILE_REQUEST = "GET_FILE_REQUEST";
    public static final String GET_FILE_RESPONSE = "GET_FILE_RESPONSE";

    public static final String SEND_FILE_OFFER = "SEND_FILE_OFFER";
    public static final String SEND_FILE_ACCEPT = "SEND_FILE_ACCEPT";
    public static final String SEND_FILE_DENY = "SEND_FILE_DENY";

    public static final String FILE_CHUNK = "FILE_CHUNK";
    public static final String FILE_TRANSFER_COMPLETE = "FILE_TRANSFER_COMPLETE";

    public static final String KEY_UPDATE_NOTICE = "KEY_UPDATE_NOTICE";

    // Consent protocol
    public static final String FILE_REQUEST = "FILE_REQUEST";
    public static final String FILE_REQUEST_ACCEPT = "FILE_REQUEST_ACCEPT";
    public static final String FILE_REQUEST_DENY = "FILE_REQUEST_DENY";

    // Key migration
    public static final String KEY_MIGRATION = "KEY_MIGRATION";

    // Manifest exchange
    public static final String MANIFEST_REQUEST = "MANIFEST_REQUEST";
    public static final String MANIFEST_RESPONSE = "MANIFEST_RESPONSE";

    public static final Set<String> ALL_MESSAGE_TYPES = Set.of(
            CLIENT_HELLO,
            SERVER_HELLO,
            HANDSHAKE_FINISH,
            PING,
            PONG,
            ERROR,
            LIST_FILES_REQUEST,
            LIST_FILES_RESPONSE,
            GET_FILE_REQUEST,
            GET_FILE_RESPONSE,
            SEND_FILE_OFFER,
            SEND_FILE_ACCEPT,
            SEND_FILE_DENY,
            FILE_CHUNK,
            FILE_TRANSFER_COMPLETE,
            KEY_UPDATE_NOTICE,
            FILE_REQUEST,
            FILE_REQUEST_ACCEPT,
            FILE_REQUEST_DENY,
            KEY_MIGRATION,
            MANIFEST_REQUEST,
            MANIFEST_RESPONSE
    );
}
