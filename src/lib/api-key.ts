import crypto from "crypto";
import { prisma } from "./prisma";
import { logger } from "./logger";

/**
 * API KEYS ARE STORED ONLY AS A HASH.
 *
 * The `apiKey` column keeps `sha256:<hex>` of the key; the plain key is shown
 * to the user once, when it is generated. `apiKeyHint` keeps the first
 * characters so the dashboard can show which key is active.
 *
 * Keys created before this change were stored in plain text. They still work:
 * on the first successful use they are converted to the hashed form.
 */
const HASH_PREFIX = "sha256:";

export function hashApiKey(rawKey: string): string {
    return HASH_PREFIX + crypto.createHash("sha256").update(rawKey, "utf8").digest("hex");
}

export function generateApiKey(): string {
    return `wag_${crypto.randomBytes(24).toString("base64url")}`;
}

export const apiKeyHint = (rawKey: string) => `${rawKey.slice(0, 10)}…`;

const SELECT_USER = { id: true, email: true, name: true, role: true } as const;

/** The user that owns this API key, or null. */
export async function findUserByApiKey(rawKey: string | null | undefined) {
    if (!rawKey || typeof rawKey !== "string" || rawKey.length < 20 || rawKey.length > 200) {
        return null;
    }
    try {
        const hashed = hashApiKey(rawKey);
        const user = await prisma.user.findUnique({ where: { apiKey: hashed }, select: SELECT_USER });
        if (user) return user;

        // Legacy: key stored in plain text. Convert it to the hashed form.
        const legacy = await prisma.user.findUnique({ where: { apiKey: rawKey }, select: SELECT_USER });
        if (legacy) {
            await prisma.user.update({
                where: { id: legacy.id },
                data: { apiKey: hashed, apiKeyHint: apiKeyHint(rawKey) },
            });
            logger.info("Auth", `Legacy plain-text API key of user ${legacy.id} converted to hash`);
        }
        return legacy;
    } catch (error) {
        logger.error("Auth", "API key validation error:", error);
        return null;
    }
}
