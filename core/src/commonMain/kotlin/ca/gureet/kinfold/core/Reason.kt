// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.core

/** The reason codes of PROTOCOL.md §16.5, by the strings the spec and the vectors use. */
enum class Reason(val code: String) {
    // The member log (§6)
    TOO_LARGE("too_large"),
    MALFORMED("malformed"),
    BAD_VERSION("bad_version"),
    UNKNOWN_ENTRY_TYPE("unknown_entry_type"),
    BAD_SEQ("bad_seq"),
    BAD_PREV_HASH("bad_prev_hash"),
    BAD_CIRCLE_ID("bad_circle_id"),
    BAD_EPOCH("bad_epoch"),
    UNEXPECTED_GENESIS("unexpected_genesis"),
    BAD_AUTHOR("bad_author"),
    AUTHOR_NOT_ACTIVE("author_not_active"),
    BAD_SIGNATURE("bad_signature"),
    KIND_NOT_ALLOWED("kind_not_allowed"),
    BAD_CERT("bad_cert"),
    BAD_BUNDLE("bad_bundle"),
    NOT_ADMIN("not_admin"),
    ALREADY_MEMBER("already_member"),
    DEVICE_ACTIVE("device_active"),
    INVITE_REUSED("invite_reused"),
    BAD_CONSENT("bad_consent"),
    NOT_MEMBER("not_member"),
    LAST_ADMIN("last_admin"),
    BAD_WRAPS("bad_wraps"),
    WRONG_ACCOUNT("wrong_account"),
    UNKNOWN_DEVICE("unknown_device"),
    LAST_DEVICE("last_device"),
    REKEY_PENDING("rekey_pending"),
    TOO_MANY_MEMBERS("too_many_members"),
    TOO_MANY_DEVICES("too_many_devices"),
    BAD_OPTIONS("bad_options"),
    BAD_ROTATION("bad_rotation"),
    BAD_TIME("bad_time"),
    BAD_DETAILS("bad_details"),
    UNKNOWN_POLICY("unknown_policy"),
    NOT_TEEN("not_teen"),
    NOT_GUARDIAN("not_guardian"),
    TEEN_UNTIL_NOT_REACHED("teen_until_not_reached"),
    BAD_RULES("bad_rules"),
    BAD_GUARDIANS("bad_guardians"),
    BAD_PAUSE("bad_pause"),
    UNKNOWN_PAUSE("unknown_pause"),

    // Envelopes (§7)
    BAD_KIND("bad_kind"),
    WRONG_CIRCLE("wrong_circle"),
    SENDER_NOT_ACTIVE("sender_not_active"),
    UNKNOWN_LOG_HEAD("unknown_log_head"),
    EXPIRED("expired"),
    REPLAY("replay"),
    NOT_A_RECIPIENT("not_a_recipient"),
    UNKNOWN_KEY("unknown_key"),
    BAD_WRAP("bad_wrap"),
    BAD_CIPHERTEXT("bad_ciphertext"),
    BAD_PADDING("bad_padding"),
    BAD_PAYLOAD("bad_payload"),
    NOT_ALLOWED("not_allowed"),
    BAD_TTL("bad_ttl"),
    STALE_HEAD("stale_head"),
    ;

    companion object {
        fun ofCode(code: String): Reason? = entries.firstOrNull { it.code == code }
    }
}

/** A protocol object was refused, for [reason]. */
class ProtocolException(val reason: Reason) : Exception(reason.code)
