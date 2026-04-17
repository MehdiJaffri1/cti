import { NextResponse } from "next/server"
import { clearAuthTokenCookie } from "@/lib/auth"

export async function POST() {
  try {
    await clearAuthTokenCookie()
    return NextResponse.json({ success: true }, { status: 200 })
  } catch (error) {
    console.error("Logout error:", error)
    return NextResponse.json({ error: "An error occurred during logout" }, { status: 500 })
  }
}
