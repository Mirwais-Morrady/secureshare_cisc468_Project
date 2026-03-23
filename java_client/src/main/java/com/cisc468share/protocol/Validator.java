package com.cisc468share.protocol;

import java.util.List;
import java.util.Map;

public final class Validator {
    private Validator() {}

    public static void requireFields(Map<String, Object> message, List<String> requiredFields) {
        for (String field : requiredFields) {
            if (!message.containsKey(field)) {
                throw new IllegalArgumentException("Missing required field: " + field);
            }
        }
    }

    public static void validateProtocolVersion(Map<String, Object> message) {
        Object version = message.containsKey("proto_ver") ? message.get("proto_ver") : message.get("version");
        if (!MessageTypes.PROTOCOL_VERSION.equals(version)) {
            throw new IllegalArgumentException("Unsupported protocol version: " + version);
        }
    }

    public static void validateMessageType(Map<String, Object> message) {
        Object msgType = message.containsKey("type") ? message.get("type") : message.get("msg_type");
        if (!(msgType instanceof String) || !MessageTypes.ALL_MESSAGE_TYPES.contains(msgType)) {
            throw new IllegalArgumentException("Unsupported message type: " + msgType);
        }
    }
}
