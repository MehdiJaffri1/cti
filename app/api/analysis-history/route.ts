import { type NextRequest, NextResponse } from "next/server"
import { connectToDatabase } from "@/lib/db"

export async function GET(request: NextRequest) {
  try {
    const email = request.nextUrl.searchParams.get("email")

    if (!email) {
      return NextResponse.json({ error: "Email parameter is required" }, { status: 400 })
    }

    const { db } = await connectToDatabase()
    const collection = db.collection("analysisReports")

    const reports = await collection.find({ email }).sort({ createdAt: -1 }).limit(50).toArray()

    const analysisHistory = reports.map((report: any) => ({
      id: report._id.toString(),
      input: report.userInput,
      confidence: report.confidence,
      threatLevel: report.threatLevel,
      createdAt: report.createdAt,
      report: report.report,
    }))

    return NextResponse.json(analysisHistory)
  } catch (error) {
    console.error("[v0] Error fetching analysis history:", error)
    return NextResponse.json({ error: "Failed to fetch analysis history" }, { status: 500 })
  }
}
