export default function DeploymentOptions() {
  return (
    <section className="bg-gradient-to-b from-black via-slate-900 to-blue-900 py-32 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-16">
          <h2 className="text-4xl sm:text-5xl font-bold text-white mb-4">What are features of our CTI Platform</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Open Source */}
          <div className="p-8 bg-slate-800/30 border border-slate-700 rounded-lg p-6 hover:border-slate-600 transition">
            <h3 className="text-2xl font-bold text-white mb-4">⁠GUI built for threat intelligence</h3>
            <p className="text-gray-300 mb-6">
              Modern & Intuitive dashboards with STIX-structured knowledge hypergraph to allow analysts pivot across actors,
               malware, TTPs, and indicators with visual graphs, timelines, and ATT&CK mappings
            </p>
          </div>

          {/* SaaS */}
          <div className="p-8 bg-slate-800/30 border border-slate-700 rounded-lg p-6 hover:border-slate-600 transition">
            <h3 className="text-2xl font-bold text-white mb-4">Work Faster And Analyze better with AI</h3>
            <p className="text-gray-300 mb-6">
              Make AI your companion at every step of your activities (threat feeds import, search, insights and generating summaries) as well as your output (finished with template and tone based on your targeted audience).
            </p>        
          </div>

          {/* Enterprise Edition */}
          <div className="p-8 bg-slate-800/30 border border-slate-700 rounded-lg p-6 hover:border-slate-600 transition">
            <h3 className="text-2xl font-bold text-white mb-4">Actionable Insights Dashboard</h3>
            <p className="text-gray-300 mb-6">
              Visualize critical threats with intuitive analytics that highlight risk severity, trends, and real-time impact — so you can make data-driven decisions and focus resources where they matter most.
            </p>            
          </div>
        </div>
      </div>
    </section>
  )
}
