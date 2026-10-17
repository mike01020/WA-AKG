import crypto from "crypto";
import { logger } from "./logger";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // Standard 96-bit IV for GCM
const PREFIX = "enc:v1:";

/**
 * Derives a 32-byte encryption key from environment secrets.
 */
const derive = (secret: string) => crypto.createHash("sha256").update(secret).digest();

/**
 * The key that encrypts the WhatsApp credentials. It should be ENCRYPTION_KEY,
 * kept apart from AUTH_SECRET: whoever leaks the login secret should not also
 * get the WhatsApp sessions. (In production the server refuses to start
 * without ENCRYPTION_KEY — see src/server/index.ts.)
 */
function getDerivedKey(): Buffer {
    const secret = process.env.ENCRYPTION_KEY || process.env.AUTH_SECRET;
    if (!secret) {
        throw new Error("ENCRYPTION_KEY or AUTH_SECRET must be defined in environment variables");
    }
    return derive(secret);
}

/** Keys to try when decrypting: the current one, then the legacy AUTH_SECRET one. */
function decryptionKeys(): Buffer[] {
    const keys = [getDerivedKey()];
    if (process.env.ENCRYPTION_KEY && process.env.AUTH_SECRET) keys.push(derive(process.env.AUTH_SECRET));
    return keys;
}

/**
 * Encrypts a plaintext string using AES-256-GCM.
 * Output format: enc:v1:<iv_hex>:<tag_hex>:<ciphertext_hex>
 */
export function encryptData(plaintext: string): string {
    if (!plaintext) return plaintext;

    const key = getDerivedKey();
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    let encrypted = cipher.update(plaintext, "utf8", "hex");
    encrypted += cipher.final("hex");
    const tag = cipher.getAuthTag().toString("hex");

    return `${PREFIX}${iv.toString("hex")}:${tag}:${encrypted}`;
}

/**
 * Decrypts a ciphertext string produced by encryptData.
 * If the data does not start with the prefix, it is returned as-is (backward compatibility for unencrypted data).
 */
export function decryptData(data: string): string {
    if (!data || typeof data !== "string") return data;

    // Backward compatibility: If not encrypted, return as-is
    if (!data.startsWith(PREFIX)) {
        return data;
    }

    try {
        const raw = data.substring(PREFIX.length);
        const parts = raw.split(":");
        if (parts.length !== 3) {
            throw new Error("Invalid encrypted payload structure");
        }

        const [ivHex, tagHex, encryptedHex] = parts;
        const iv = Buffer.from(ivHex, "hex");
        const tag = Buffer.from(tagHex, "hex");

        // Data encrypted before ENCRYPTION_KEY was set used the AUTH_SECRET key;
        // it is re-encrypted with the new key on the next write.
        let lastErr: any = null;
        for (const key of decryptionKeys()) {
            try {
                const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
                decipher.setAuthTag(tag);
                let decrypted = decipher.update(encryptedHex, "hex", "utf8");
                decrypted += decipher.final("utf8");
                return decrypted;
            } catch (e) {
                lastErr = e;
            }
        }
        throw lastErr || new Error("Decryption failed");
    } catch (err: any) {
        logger.error("Crypto", "Decryption failed:", err.message);
        throw new Error("Failed to decrypt data payload");
    }
}
