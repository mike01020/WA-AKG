# Correções de segurança (base: branch `beta`, v1.7.0-beta.1)

Já corrigido na `beta` do autor (conferido no código):

| Ponto | Situação na `beta` |
|---|---|
| Socket.IO sem autenticação | Exige sessão (JWT do NextAuth) ou chave de API; `join-session` confere o dono da sessão; `join-user-room` só a própria sala |
| Credenciais do WhatsApp em texto puro | Criptografadas com AES-256-GCM antes de gravar |
| SSRF em webhooks e mídia | `validateSafeUrl` / `safeFetchBuffer`: bloqueia IP privado, loopback, link-local (metadados) e confere cada redirecionamento |
| Chave de API com `Math.random` | Gerada com `crypto.randomBytes` |
| Mídia sem dono conferido | Arquivo sem sessão no nome só para SUPERADMIN |
| Cadastro aberto | `enableRegistration` agora começa desligado |

Corrigido neste fork:

1. **Chave de API guardada só como hash** (`src/lib/api-key.ts`). O banco guarda `sha256:<hex>` e os primeiros caracteres (`apiKeyHint`). A chave completa aparece uma única vez, ao gerar. Chaves antigas em texto puro continuam valendo e são convertidas no primeiro uso. A chave deixou de ser aceita na query string do Socket.IO, porque URLs ficam registradas em logs.
2. **Limite de tentativas** (`src/lib/rate-limit.ts`, aplicado em `src/proxy.ts` e `src/lib/auth.ts`):
   - login: 8 senhas erradas por e-mail e 20 tentativas por IP em 15 minutos;
   - cadastro: 5 por IP por hora;
   - API: `RATE_LIMIT_PER_MINUTE` por IP. Antes, a variável existia no `.env.example`, mas nada a usava.
3. **Senha mínima de 8 caracteres** no cadastro.
4. **ID de sessão aleatório criptográfico** (`randomBytes`). Um ID escolhido manualmente só aceita `A-Z a-z 0-9 - _` (3 a 64 caracteres).
5. **Chave de criptografia separada.** Em produção o servidor não sobe sem `ENCRYPTION_KEY` (32+ caracteres e diferente de `AUTH_SECRET`). Dados gravados antes com a chave derivada do `AUTH_SECRET` continuam abrindo e são regravados com a nova chave.
6. **Segredo do webhook não vaza.** As listagens de sessão não trazem mais o `secret`. Na lista de webhooks, o segredo só aparece para quem criou o webhook ou para o SUPERADMIN.
7. **CORS do Socket.IO.** Origens `localhost` só são aceitas em desenvolvimento.
8. **Telemetria desligada por padrão.** O ping para o servidor do autor só sai com `ENABLE_TELEMETRY="true"`.
9. **ffmpeg sem shell.** Usa `execFile` com argumentos, com tempo limite de 60 segundos.
10. **Modo de armazenamento mínimo** (`MINIMAL_STORAGE="true"`). Não grava conversas nem baixa mídia; os webhooks continuam saindo. Os contatos são mantidos porque traduzem o LID do WhatsApp para o número de telefone.

Variáveis novas ou alteradas: `ENCRYPTION_KEY` (obrigatória em produção), `MINIMAL_STORAGE`, `ENABLE_TELEMETRY` (padrão `false`).
Depois de atualizar, rode `npm run db:push`: o campo `User.apiKeyHint` é novo.

Riscos que continuam:
- Baileys é **não oficial**: o número pode sofrer restrição ou banimento pelo WhatsApp.
- O limite de tentativas fica em memória: vale por instância, e reiniciar o servidor zera a contagem.
- Rode o gateway em **rede privada** (por exemplo, a rede interna do Railway), sem expor o painel nem o Socket.IO na internet.
