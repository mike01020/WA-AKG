/**
 * RATE LIMITING (in memory, per process).
 *
 * Fixed window counters kept on globalThis, so the proxy and the route
 * handlers share them. Enough for one instance; with several instances behind
 * a load balancer, each instance counts on its own.
 *
 *   ENABLE_RATE_LIMITING   "false" turns the general API limit off (login and
 *                          registration limits always apply)
 *   RATE_LIMIT_PER_MINUTE  requests per minute per IP on /api (default 120)
 */
type Janela = { inicio: number; total: number };
const g = globalThis as unknown as { __waRateLimit?: Map<string, Janela> };
const contadores: Map<string, Janela> = g.__waRateLimit || (g.__waRateLimit = new Map());

let ultimaLimpeza = Date.now();
function limpar(agora: number) {
    if (agora - ultimaLimpeza < 60_000) return;
    ultimaLimpeza = agora;
    for (const [k, v] of contadores) if (agora - v.inicio > 60 * 60_000) contadores.delete(k);
}

/** Counts one hit. Returns how many seconds to wait, or 0 if allowed. */
export function hit(chave: string, limite: number, janelaMs: number): number {
    const agora = Date.now();
    limpar(agora);
    const j = contadores.get(chave);
    if (!j || agora - j.inicio >= janelaMs) {
        contadores.set(chave, { inicio: agora, total: 1 });
        return 0;
    }
    j.total += 1;
    if (j.total > limite) return Math.ceil((j.inicio + janelaMs - agora) / 1000);
    return 0;
}

/** Only reads (does not count). */
export function bloqueado(chave: string, limite: number, janelaMs: number): number {
    const agora = Date.now();
    const j = contadores.get(chave);
    if (!j || agora - j.inicio >= janelaMs) return 0;
    return j.total >= limite ? Math.ceil((j.inicio + janelaMs - agora) / 1000) : 0;
}

export function zerar(chave: string) {
    contadores.delete(chave);
}

/** Client IP: first X-Forwarded-For hop (set by the reverse proxy), else X-Real-IP. */
export function ipDe(headers: Headers): string {
    const xff = headers.get("x-forwarded-for");
    if (xff) return xff.split(",")[0].trim();
    return headers.get("x-real-ip")?.trim() || "unknown";
}

export const LIMITES = {
    // Login: per IP and per e-mail
    loginIp: { limite: 20, janela: 15 * 60_000 },
    loginEmail: { limite: 8, janela: 15 * 60_000 },
    // Registration: per IP
    cadastro: { limite: 5, janela: 60 * 60_000 },
    // General API: per IP
    api: () => ({
        ativo: process.env.ENABLE_RATE_LIMITING !== "false",
        limite: Math.max(10, Number(process.env.RATE_LIMIT_PER_MINUTE) || 120),
        janela: 60_000,
    }),
};
