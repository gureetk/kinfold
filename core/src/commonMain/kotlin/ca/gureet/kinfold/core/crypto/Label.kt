// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core.crypto

import ca.gureet.kinfold.core.wire.encode

/** The domain-separation labels of PROTOCOL.md §16.4, each `kinfold/v0/` and a purpose. */
enum class Label(purpose: String) {
    ACCOUNT_ID("account-id"),
    DEVICE_ID("device-id"),
    KEY_ID("key-id"),
    DEVICE_CERT("device-cert"),
    IDENTITY_ROTATE("identity-rotate"),
    KEY_BUNDLE("key-bundle"),
    LOG_ENTRY("log-entry"),
    LOG_HASH("log-hash"),
    CIRCLE_ID("circle-id"),
    LOG_KEY("log-key"),
    MEMBER_TERMS("member-terms"),
    EPOCH_COMMIT("epoch-commit"),
    EPOCH_WRAP("epoch-wrap"),
    STATE_HASH("state-hash"),
    WRAP("wrap"),
    ENV_AAD("env-aad"),
    PAYLOAD_KEY("payload-key"),
    PAYLOAD_NONCE("payload-nonce"),
    ENVELOPE("envelope"),
    PLACE_ID("place-id"),
    OBJECT_KEY("object-key"),
    OBJECT("object"),
    INVITE_ID("invite-id"),
    JOIN_KEY("join-key"),
    JOIN_RESULT_KEY("join-result-key"),
    JOIN_CONSENT("join-consent"),
    LINK_ID("link-id"),
    LINK_COMMIT("link-commit"),
    LINK_CODE("link-code"),
    LINK_INFO("link-info"),
    LINK_KEY("link-key"),
    LINK_CONFIRM("link-confirm"),
    LINK_RESPONSE("link-response"),
    SAFETY("safety"),
    SERVER_FINGERPRINT("server-fingerprint"),
    SHARE_ID("share-id"),
    SHARE_KEY("share-key"),
    SERVER_INFO("server-info"),
    AUTH_CHALLENGE("auth-challenge"),
    AUTH("auth"),
    SERVER_MOVE("server-move"),
    WATCH_GRANT("watch-grant"),
    PUSH("push"),
    PUSH_SIG("push-sig"),
    RELAY_PUSH("relay-push"),
    TEST("test"),
    ;

    /** The full label, such as `kinfold/v0/log-hash`. */
    val text: String = "kinfold/v0/$purpose"

    /** `vec16(label)`, the form every hash, signature and key derivation starts with (§3.3). */
    internal val prefix: ByteArray = encode { vec16(text.encodeToByteArray()) }

    companion object {
        fun ofText(text: String): Label? = entries.firstOrNull { it.text == text }
    }
}
