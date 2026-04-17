// app/api/analyze/route.ts
import { NextRequest, NextResponse } from "next/server";
import { Client } from "@gradio/client";
import { saveAnalysisReport } from "@/lib/db";

type GraphData = {
  data: any[];
  layout: Record<string, any>;
};

// ----------------- Helper Functions -----------------
function parseReport(report: string) {
  const get = (key: string) => {
    const re = new RegExp(`${key}:\\s*([^\\n\\r]*)`, "i");
    const match = report.match(re);
    return match ? match[1].trim() : null;
  };

  const confidenceRaw = get("Confidence Score") ?? "0";
  const confidence = parseFloat(confidenceRaw) || 0;

  return {
    confidence,
    firstSeen: get("First Seen"),
    lastSeen: get("Last Seen"),
    tags: (get("Tags") || "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean),
    predictedThreat: get("Predicted Threat Level") || "Unknown",
    inputType: get("Input Type"),
    value: get("Value / Name"),
    source: get("Source / Reference"),
    tlp: get("TLP"),
    description: get("Description"),
  };
}

function buildGauge(confidence: number, predictedThreat: string): GraphData {
  const gaugeColors: [number, number, string][] = [
    [0, 0.4, "#16a34a"], // green
    [0.4, 0.75, "#f59e0b"], // yellow/orange
    [0.75, 1, "#dc2626"], // red
  ];

  return {
    data: [
      {
        type: "indicator",
        mode: "gauge+number+delta",
        value: confidence,
        title: {
          text: `<b>Confidence</b><br><span style="font-size:12px;color:#cbd5e1">Threat: ${predictedThreat}</span>`,
          font: { size: 16 },
        },
        number: { suffix: "%" },
        gauge: {
          axis: { range: [0, 100], tickwidth: 1, tickcolor: "#94a3b8" },
          bar: { color: "#0ea5a6" },
          steps: gaugeColors.map(([s, e, color]) => ({
            range: [s * 100, e * 100],
            color,
          })),
          threshold: {
            line: { color: "#111827", width: 4 },
            thickness: 0.8,
            value: confidence,
          },
        },
      },
    ],
    layout: {
      title: { text: "Threat Confidence Gauge", font: { color: "#e2e8f0" } },
      margin: { t: 40, b: 20, l: 10, r: 10 },
      paper_bgcolor: "#0b1220",
      plot_bgcolor: "#0b1220",
      font: { color: "#e2e8f0" },
      height: 360,
      width: 360,
    },
  };
}

function buildTimeline(firstSeen: string | null, lastSeen: string | null): GraphData {
  const fsDate = firstSeen ? new Date(firstSeen) : new Date();
  const lsDate = lastSeen ? new Date(lastSeen) : new Date();

  // friendly labels
  const fmt = (d: Date) =>
    d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric" });

  const fsLabel = fmt(fsDate);
  const lsLabel = fmt(lsDate);

  return {
    data: [
      // invisible baseline (helps with the fill polygon)
      {
        x: [fsDate, lsDate],
        y: [1, 1],
        mode: "lines",
        line: { color: "transparent" },
        hoverinfo: "skip",
        showlegend: false,
      },
      // filled rectangular band between first and last seen
      {
        type: "scatter",
        x: [fsDate, lsDate, lsDate, fsDate, fsDate],
        y: [0.6, 0.6, 1.4, 1.4, 0.6],
        fill: "toself",
        fillcolor: "rgba(14,116,144,0.18)",
        line: { color: "rgba(14,116,144,0)" },
        hoverinfo: "skip",
        showlegend: false,
      },
      // First Seen marker + label
      {
        x: [fsDate],
        y: [1],
        mode: "markers+text",
        marker: { size: 14, color: "#06b6d4", line: { width: 2, color: "#0f172a" } },
        text: [`First: ${fsLabel}`],
        textposition: "bottom center",
        textfont: { color: "#06b6d4", size: 12 },
        hovertemplate: `First Seen: ${fsLabel}<extra></extra>`,
      },
      // Last Seen marker + label
      {
        x: [lsDate],
        y: [1],
        mode: "markers+text",
        marker: { size: 14, color: "#60a5fa", line: { width: 2, color: "#0f172a" } },
        text: [`Last: ${lsLabel}`],
        textposition: "bottom center",
        textfont: { color: "#60a5fa", size: 12 },
        hovertemplate: `Last Seen: ${lsLabel}<extra></extra>`,
      },
    ],
    layout: {
      title: { text: "Threat Levels Over Time", font: { size: 18 } },
      xaxis: {
        title: "Last Seen",
        showgrid: true,
        gridcolor: "#1f2937",
        tickangle: -45,
        tickfont: { color: "#cbd5e1" },
      },
      yaxis: { visible: false, range: [0, 2] },
      margin: { t: 60, b: 80, l: 40, r: 40 },
      paper_bgcolor: "#0b1220",
      plot_bgcolor: "#0b1220",
      font: { color: "#e2e8f0" },
      height: 360,
      width: 720, // wider to make it look like your screenshot
    },
  };
}

// ----------------- API Route -----------------
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { user_input, email } = body;

    if (!user_input) {
      return NextResponse.json({ error: "Input is required" }, { status: 400 });
    }

    const client = await Client.connect("Bha19/cyber_project");
    const result = await client.predict("/predict", { user_input });

    const dataArray = result.data as [string, string | null];
    const [report] = dataArray;

    const parsedData = parseReport(report);
    const { confidence, firstSeen, lastSeen, predictedThreat, inputType, value, source, tlp, description, tags } = parsedData;

    const graphs: GraphData[] = [buildGauge(confidence, predictedThreat)];

    if (email) {
      try {
        await saveAnalysisReport(email, user_input, report, {
          confidence,
          threatLevel: predictedThreat,
          firstSeen,
          lastSeen,
          inputType,
          value,
          source,
          tlp,
          description,
          tags,
        });
      } catch (dbError) {
        console.error("[v0] Failed to save analysis report:", dbError);
      }
    }

    return NextResponse.json({ 
      report, 
      graph: graphs,
      parsedData: {
        confidence,
        threatLevel: predictedThreat,
        firstSeen,
        lastSeen,
        inputType,
        value,
        source,
        tlp,
        description,
        tags,
      }
    });
  } catch (err) {
    console.error("Error calling Gradio API:", err);
    return NextResponse.json({ error: "Failed to call Gradio API" }, { status: 500 });
  }
}
