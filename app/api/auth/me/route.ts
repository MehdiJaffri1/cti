import { type NextRequest, NextResponse } from "next/server"
import { getAuthTokenFromCookies, verifyToken } from "@/lib/auth"
import { getUserById } from "@/lib/db"

export async function GET(request: NextRequest) {
  try {
    const token = await getAuthTokenFromCookies()

    if (!token) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 })
    }

    const decoded = await verifyToken(token)
    if (!decoded) {
      return NextResponse.json({ error: "Invalid token" }, { status: 401 })
    }

    const user = await getUserById(decoded.userId)
    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 })
    }

    return NextResponse.json({ user: { id: user._id.toString(), email: user.email } }, { status: 200 })
  } catch (error) {
    console.error("Me error:", error)
    return NextResponse.json({ error: "An error occurred" }, { status: 500 })
  }
}
