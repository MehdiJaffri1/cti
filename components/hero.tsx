"use client"

import { ArrowRight } from "lucide-react"
import Link from "next/link"

export default function Hero() {
  return (
    <section className="bg-gradient-to-b from-black via-slate-900 to-blue-900 pt-32 pb-20 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto text-center">
        {/* CTI Badge */}
        <div className="flex justify-center mb-8">
          <div className="flex items-center gap-2 px-11 py-2 bg-slate-800/50 rounded-full border border-slate-600">
            <span className="text-slate-200 text-md">CTI PLATFORM</span>
          </div>
        </div>

        {/* Main Heading */}
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-white mb-6 leading-tight">
          Trace The Threat
          <br />
          Secure The Future
        </h1>

        {/* Subheading */}
        <p className="text-lg sm:text-lg text-slate-300 mb-12 max-w-2xl mx-auto">
          Organize your cyber threat intelligence to enhance and disseminate actionable
          <br />
          insights with our open-source threat intelligence platform.
        </p>

        <div className="flex justify-center mb-16">
          <Link href="/signup">
            <button className="px-8 py-3 bg-cyan-400 text-black font-semibold rounded-full hover:bg-cyan-300 transition flex items-center justify-center gap-2">
              <span>Get Started</span>
              <ArrowRight size={18} />
            </button>
          </Link>
        </div>

        {/* Dashboard Preview */}
        <div className="relative">
          <div className="absolute inset-0 bg-gradient-to-b from-cyan-400/20 to-transparent rounded-2xl blur-3xl"></div>
          <div className="relative bg-slate-900/50 border border-slate-700 rounded-2xl p-4 sm:p-8 overflow-hidden">
            <img
              src="/front_dashboard.png"
              alt="OpenCTI Dashboard"
              className="w-full h-[800px] rounded-lg"
            />
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mt-20">
          <div>
            <div className="text-3xl sm:text-4xl font-bold text-white mb-2">70%</div>
            <p className="text-slate-400 text-sm">faster threat detection and response</p>
          </div>
          <div>
            <div className="text-3xl sm:text-4xl font-bold text-white mb-2">25%</div>
            <p className="text-slate-400 text-sm">reduction in false positives</p>
          </div>
          <div>
            <div className="text-3xl sm:text-4xl font-bold text-white mb-2">300+</div>
            <p className="text-slate-400 text-sm">connectors</p>
          </div>
          <div>
            <div className="text-3xl sm:text-4xl font-bold text-white mb-2">6K</div>
            <p className="text-slate-400 text-sm">deployments by practitioners</p>
          </div>
        </div>
      </div>
    </section>
  )
}
