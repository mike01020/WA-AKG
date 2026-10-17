import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { generateApiKey, hashApiKey, apiKeyHint } from "@/lib/api-key";

/*
 * The API key is stored only as a hash. GET says whether there is a key and
 * shows its first characters; the full key is returned only once, by POST,
 * right after it is generated.
 */

// Current user's API key (hint only)
export async function GET() {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 401 });

    try {
        const user = await prisma.user.findUnique({
            where: { id: session.user.id },
            select: { apiKey: true, apiKeyHint: true }
        });
        const hasKey = Boolean(user?.apiKey);
        return NextResponse.json({
            status: true,
            message: "API key fetched",
            data: { apiKey: null, hasKey, hint: hasKey ? (user?.apiKeyHint || "wag_…") : null }
        });
    } catch (error) {
        return NextResponse.json({ status: false, message: "Failed to fetch API key", error: "Failed to fetch API key" }, { status: 500 });
    }
}

// Generate a new API key (replaces the old one). The full key is shown only now.
export async function POST() {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 401 });

    try {
        const newApiKey = generateApiKey();

        await prisma.user.update({
            where: { id: session.user.id },
            data: { apiKey: hashApiKey(newApiKey), apiKeyHint: apiKeyHint(newApiKey) }
        });

        return NextResponse.json({
            status: true,
            message: "API key generated. Copy it now: it will not be shown again.",
            data: { apiKey: newApiKey, hasKey: true, hint: apiKeyHint(newApiKey) }
        });
    } catch (error) {
        console.error("Generate API key error:", error);
        return NextResponse.json({ status: false, message: "Failed to generate API key", error: "Failed to generate API key" }, { status: 500 });
    }
}

// Delete/revoke API key
export async function DELETE() {
    const session = await auth();
    if (!session?.user?.id) return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 401 });

    try {
        await prisma.user.update({
            where: { id: session.user.id },
            data: { apiKey: null, apiKeyHint: null }
        });

        return NextResponse.json({ status: true, message: "API key revoked" });
    } catch (error) {
        return NextResponse.json({ status: false, message: "Failed to revoke API key", error: "Failed to revoke API key" }, { status: 500 });
    }
}
