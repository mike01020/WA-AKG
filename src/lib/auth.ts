import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { prisma } from "@/lib/prisma";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { authConfig } from "@/auth.config";
import { bloqueado, hit, zerar, LIMITES } from "@/lib/rate-limit";

export const { handlers, signIn, signOut, auth } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      authorize: async (credentials) => {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          // Too many wrong passwords for this e-mail: refuse for a while,
          // even with the right password (stops password guessing).
          const chave = `login:email:${email.toLowerCase()}`;
          if (bloqueado(chave, LIMITES.loginEmail.limite, LIMITES.loginEmail.janela)) return null;

          const user = await prisma.user.findUnique({ where: { email } });
          if (!user) {
            hit(chave, LIMITES.loginEmail.limite, LIMITES.loginEmail.janela);
            return null;
          }

          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (passwordsMatch) {
             zerar(chave);
             return user;
          }
          hit(chave, LIMITES.loginEmail.limite, LIMITES.loginEmail.janela);
        }
        return null;
      },
    }),
  ],
  secret: process.env.AUTH_SECRET,
});
