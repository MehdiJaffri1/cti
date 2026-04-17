"use client"

import { Network, AlertCircle, Share2, Zap } from "lucide-react"

const features = [
  {
    icon: Network,
    title: "Real-Time Threat Intelligence",
    description:
      "Instantly detect and track emerging cyber threats with live intelligence feeds.",
  },
  {
    icon: AlertCircle,
    title: "Advanced Attack Surface Monitoring",
    description:
      "Continuously map, monitor, and secure your digital footprint.",
  },
  {
    icon: Share2,
    title: "AI-Driven Threat Analysis",
    description: "Leverage machine learning to identify, prioritize, and neutralize risks faster.",
  },
  {
    icon: Zap,
    title: "Actionable Security Insights",
    description: "Get clear, data-driven alerts and reports that empower rapid response.",
  },
]

export default function Features() {
  return (
    <section className="bg-gradient-to-b from-black via-slate-900 to-blue-900 py-44 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        <div className="grid md:grid-cols-2 gap-2 items-start">
          {/* Left Column */}
          <div className="mr-32">
            <h2 className="text-4xl sm:text-5xl font-bold text-white mb-6 leading-tight">
              Collect, correlate and leverage
            </h2>
            <p className="text-md text-slate-300 mb-8">
              Operationalize threat intelligence like never before. Share it timely across your security teams and build
              threat-informed defense.
            </p>
          </div>

          {/* Right Column - Features Grid */}
          <div className="grid grid-cols-2 gap-10 -ml-24">
            {features.map((feature, index) => {
              const Icon = feature.icon
              return (
                <div
                  key={index}
                  //className="bg-slate-800/30 border border-slate-700 rounded-lg p-6 hover:border-slate-600 transition"
                >
                  <div className="w-12 h-12 ">
                    <Icon className="text-cyan-400" size={36} />
                  </div>
                  <h2 className="text-2xl font-bold text-white mb-3">{feature.title}</h2>
                  <p className="text-md text-slate-300 mb-8">{feature.description}</p>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </section>
  )
}
