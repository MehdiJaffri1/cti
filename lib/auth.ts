import jwt from "jsonwebtoken"
import { cookies } from "next/headers"

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-in-production"

export interface DecodedToken {
  userId: string
  email: string
  iat: number
  exp: number
}

export function createToken(userId: string, email: string): string {
  return jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: "7d" })
}

export async function verifyToken(token: string): Promise<DecodedToken | null> {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as DecodedToken
    return decoded
  } catch (error) {
    return null
  }
}

export async function getAuthTokenFromCookies(): Promise<string | null> {
  const cookieStore = await cookies()
  return cookieStore.get("authToken")?.value || null
}

export async function setAuthTokenCookie(token: string): Promise<void> {
  const cookieStore = await cookies()
  cookieStore.set("authToken", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60, // 7 days
    path: "/",
  })
}

export async function clearAuthTokenCookie(): Promise<void> {
  const cookieStore = await cookies()
  cookieStore.delete("authToken")
}
