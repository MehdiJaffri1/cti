import { NextRequest, NextResponse } from "next/server";
import { getRecentSearches } from "@/lib/db";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const email = searchParams.get("email");

    if (!email) {
      return NextResponse.json({ error: "Email is required" }, { status: 400 });
    }

    const searches = await getRecentSearches(email, 10);

    return NextResponse.json(searches);
  } catch (err) {
    console.error("Error fetching recent searches:", err);
    return NextResponse.json({ error: "Failed to fetch recent searches" }, { status: 500 });
  }
}
