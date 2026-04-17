import { type NextRequest, NextResponse } from "next/server"
import { getUserByEmail, createUser } from "@/lib/db"
import { hashPassword } from "@/lib/password"
import { createToken, setAuthTokenCookie } from "@/lib/auth"

export async function POST(request: NextRequest) {
  try {
    const { email, password, confirmPassword } = await request.json()

    // Validation
    if (!email || !password || !confirmPassword) {
      return NextResponse.json({ error: "Email and password are required" }, { status: 400 })
    }

    if (password !== confirmPassword) {
      return NextResponse.json({ error: "Passwords do not match" }, { status: 400 })
    }

    if (password.length < 6) {
      return NextResponse.json({ error: "Password must be at least 6 characters" }, { status: 400 })
    }

    // Check if user already exists
    const existingUser = await getUserByEmail(email)
    if (existingUser) {
      return NextResponse.json({ error: "Email already registered" }, { status: 409 })
    }

    // Hash password and create user
    const hashedPassword = await hashPassword(password)
    const userId = await createUser(email, hashedPassword)

    // Create JWT token
    const token = createToken(userId, email)

    // Create response
    const response = NextResponse.json({ success: true, user: { id: userId, email } }, { status: 201 })

    // Set auth cookie
    await setAuthTokenCookie(token)

    return response
  } catch (error) {
    console.error("Signup error:", error)
    return NextResponse.json({ error: "An error occurred during signup" }, { status: 500 })
  }
}
