import { auth } from "@/lib/auth";
import { validateApiKey } from "@/lib/api-auth";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { hit, ipDe, LIMITES } from "@/lib/rate-limit";

const muitas = (segundos: number) => NextResponse.json(
    { status: false, message: "Too many requests. Try again later.", error: "Too many requests" },
    { status: 429, headers: { "Retry-After": String(segundos) } }
);

export async function proxy(request: NextRequest) {
    const { pathname } = request.nextUrl;

    // Public routes that don't require authentication
    const publicRoutes = ["/auth/login", "/auth/register", "/api/auth", "/terms", "/privacy"];

    // Check if it's a public route
    const isPublicRoute = publicRoutes.some(route => pathname.startsWith(route));

    // Allow Next.js internals and favicon only
    if (
        pathname.startsWith("/_next") ||
        pathname === "/favicon.ico"
    ) {
        return NextResponse.next();
    }

    // Allow known static asset extensions in root path only (e.g. /vercel.svg)
    const staticExtensions = [".svg", ".ico", ".png", ".jpg", ".jpeg", ".webp", ".woff", ".woff2", ".ttf"];
    if (pathname.lastIndexOf("/") === 0 && staticExtensions.some(ext => pathname.endsWith(ext))) {
        return NextResponse.next();
    }

    // API routes: Check for valid API key or session
    if (pathname.startsWith("/api/")) {
        const ip = ipDe(request.headers);

        // Login attempts (NextAuth credentials callback) and registration
        if (request.method === "POST" && pathname.startsWith("/api/auth/callback/credentials")) {
            const espera = hit(`login:ip:${ip}`, LIMITES.loginIp.limite, LIMITES.loginIp.janela);
            if (espera) return muitas(espera);
        }
        if (request.method === "POST" && pathname === "/api/auth/register") {
            const espera = hit(`cadastro:ip:${ip}`, LIMITES.cadastro.limite, LIMITES.cadastro.janela);
            if (espera) return muitas(espera);
        }

        // General API limit, per IP
        const geral = LIMITES.api();
        if (geral.ativo && !pathname.startsWith("/api/auth")) {
            const espera = hit(`api:ip:${ip}`, geral.limite, geral.janela);
            if (espera) return muitas(espera);
        }

        // Skip auth endpoints
        if (pathname.startsWith("/api/auth")) {
            return NextResponse.next();
        }

        // Check for API key in header
        const apiKey = request.headers.get("x-api-key");
        if (apiKey) {
            // Defense-in-depth: validate API key immediately
            const user = await validateApiKey(request);
            if (!user) {
                return NextResponse.json({ error: "Invalid API key" }, { status: 401 });
            }
            return NextResponse.next();
        }

        // Check for session auth
        const session = await auth();
        if (!session?.user) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        return NextResponse.next();
    }

    // Dashboard routes: Require login
    if (pathname.startsWith("/dashboard")) {
        const session = await auth();

        if (!session?.user) {
            const loginUrl = new URL("/auth/login", request.url);
            loginUrl.searchParams.set("callbackUrl", pathname);
            return NextResponse.redirect(loginUrl);
        }

        return NextResponse.next();
    }

    // Root path — redirect to dashboard if logged in
    if (pathname === "/") {
        const session = await auth();
        if (session?.user) {
            return NextResponse.redirect(new URL("/dashboard", request.url));
        }
        return NextResponse.next();
    }

    // Public routes
    if (isPublicRoute) {
        const session = await auth();
        if (session?.user && (pathname.startsWith("/auth/login") || pathname.startsWith("/auth/register"))) {
            return NextResponse.redirect(new URL("/dashboard", request.url));
        }
        return NextResponse.next();
    }

    // Default: require auth for everything else
    const session = await auth();
    if (!session?.user) {
        const loginUrl = new URL("/auth/login", request.url);
        loginUrl.searchParams.set("callbackUrl", pathname);
        return NextResponse.redirect(loginUrl);
    }

    return NextResponse.next();
}

export const config = {
    matcher: [
        "/((?!_next/static|_next/image|favicon.ico).*)",
    ],
};
