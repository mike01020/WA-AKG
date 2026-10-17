/**
 * MINIMAL STORAGE MODE (MINIMAL_STORAGE="true").
 *
 * For integrations that only need to send messages and receive replies by
 * webhook (e.g. appointment confirmations), the gateway does not need to keep
 * the conversations. In this mode:
 *   - messages are NOT saved in the database (not even history sync);
 *   - media is NOT downloaded to disk;
 *   - webhooks still fire for new messages (with text content, no file).
 * Contacts are still kept, because they map WhatsApp LIDs to phone numbers
 * (without it, replies may arrive with an id that cannot be matched to a phone).
 */
export const MINIMAL_STORAGE = process.env.MINIMAL_STORAGE === "true";
