"use client"

import { ArrowRight } from "lucide-react"

const platformSections = [
  {
    title: "GUI built for Threat Intelligence Practitioners",
    description:
      "Modern & Intuitive dashboards with STIX-structured knowledge hypergraph to allow analysts pivot across threat actors, malware, TTPs, and indicators with visual graphs, timelines, and ATT&CK mappings.",
    position: "left",
  },
  {
    title: "Adapt the Platform to your Requirement",
    description:
      "Customize your dashboard depending on your use case – threat monitoring, threat hunting, incident response and investigation, disinformation etc. Benefit from Filigran and community-built dashboards library.",
    position: "right",
  },
  {
    title: "Work Faster and Analyze Better with AI",
    description:
      "Make AI your companion at every step of your activities (threat feeds import, search, insights and generating summaries) as well as your output (finished with template and tone based on your targeted audience).",
    position: "left",
  },
]

export default function Platform() {
  return (
    <section className="py-20 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <h2 className="text-4xl sm:text-5xl font-bold text-white mb-4">Cyber Threat Intelligence Platform</h2>
          <p className="text-lg text-slate-300">
            Manage and operationalize your cyber threat intelligence efficiently and effectively.
          </p>
        </div>

        <div className="space-y-12">
          {platformSections.map((section, index) => (
            <div
              key={index}
              className="bg-slate-800/30 border border-slate-700 rounded-2xl p-8 sm:p-12 hover:border-slate-600 transition"
            >
              <div className="grid md:grid-cols-2 gap-8 items-center">
                {section.position === "left" ? (
                  <>
                    <div>
                      <h3 className="text-2xl sm:text-3xl font-bold text-white mb-4">{section.title}</h3>
                      <p className="text-slate-300 mb-6 leading-relaxed">{section.description}</p>
                      <button className="px-6 py-3 bg-cyan-400 text-black font-semibold rounded-full hover:bg-cyan-300 transition flex items-center gap-2">
                        Take a tour of product
                        <ArrowRight size={18} />
                      </button>
                    </div>
                    <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-6 h-64 flex items-center justify-center">
                      <img
                        src="/threat-intelligence-dashboard-interface.jpg"
                        alt="Platform preview"
                        className="w-full h-full object-cover rounded"
                      />
                    </div>
                  </>
                ) : (
                  <>
                    <div className="bg-slate-900/50 border border-slate-700 rounded-lg p-6 h-64 flex items-center justify-center">
                      <img
                        src="/interactive-threat-intelligence-demo.jpg"
                        alt="Platform preview"
                        className="w-full h-full object-cover rounded"
                      />
                    </div>
                    <div>
                      <h3 className="text-2xl sm:text-3xl font-bold text-white mb-4">{section.title}</h3>
                      <p className="text-slate-300 mb-6 leading-relaxed">{section.description}</p>
                      <button className="px-6 py-3 bg-cyan-400 text-black font-semibold rounded-full hover:bg-cyan-300 transition flex items-center gap-2">
                        Take a tour of product
                        <ArrowRight size={18} />
                      </button>
                    </div>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
