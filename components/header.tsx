"use client"

import { useState } from "react"
import Link from "next/link"
import { Menu, X, ChevronDown } from "lucide-react"

export default function Header() {
  const [isOpen, setIsOpen] = useState(false)
  const [openDropdown, setOpenDropdown] = useState<string | null>(null)

  const dropdownContent = {
    platforms: [
      "Proactive Threat Hunting",
      "Incident Response Acceleration",
      "Attack Surface Monitoring",
      "Threat Actor & IOC Tracking",
      "Security Operations Enrichment (SOC)",
      "Brand & Infrastructure Protection",
    ],
    CTI: [
      "What is CTI?",
      "Cyber Threat Intelligence (CTI) is the collection, analysis, and sharing of data about potential and active cyber threats. It helps organizations understand attackers, anticipate risks, and take proactive security measures to protect their digital assets.",
    ],
    About_us:
      "At Trace X, we empower organizations with cutting-edge Cyber Threat Intelligence to stay ahead of evolving digital threats. Our platform combines real-time data collection, AI-driven analysis, and advanced monitoring to deliver actionable insights with unmatched speed and accuracy. Unlike traditional security tools, Trace X offers proactive detection, deep visibility, and automated threat correlation, enabling faster and smarter responses. Whether you're protecting a business, brand, or infrastructure, Trace X provides a secure, scalable, and efficient solution designed to outpace cyber adversaries and give you a strategic security advantage",
    Contant_us: "Tracexcti@gmail.com",
}

return (
  <header className="fixed top-0 w-full z-50 bg-black/50 backdrop-blur-md border-b border-slate-800">
    <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-4 py-2">
      <div className="flex justify-between items-center">
        {/* Logo */}
        <div className="flex items-center gap-2">
          <div className="w-16 h-16 bg-black rounded-full flex items-center justify-center">
            <img src="/logo.png" alt="" className=""></img>
          </div>
          <span className="text-white font-semibold text-3xl hidden sm:inline">TRACE X</span>
        </div>

        {/* Desktop Navigation */}
        <div className="hidden md:flex items-center gap-8">
          <div className="flex gap-8 ">
            {/* Platforms Dropdown */}
            <div className="relative group hover:bg-slate-700/95 rounded-2xl">
              <button className="text-slate-300 hover:text-white transition flex items-center gap-1">
                Platforms
                <ChevronDown size={16} />
              </button>
              <div className="absolute -left-12 mt-0 w-48 bg-slate-900/95 border border-slate-700 rounded-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 py-2">
                {(dropdownContent.platforms as string[]).map((item) => (
                  <Link
                    key={item}
                    href="#"
                    className="block px-4 py-2 text-slate-300 hover:text-cyan-400 hover:bg-slate-800/50 transition text-sm"
                  >
                    {item}
                  </Link>
                ))}
              </div>
            </div>

            {/* CTI Dropdown */}
            <div className="relative group hover:bg-slate-700/95 rounded-2xl">
              <button className="text-slate-300 hover:text-white transition flex items-center gap-1">
                CTI
                <ChevronDown size={16} />
              </button>
              <div className="absolute -left-18 mt-0 w-56 bg-slate-900/95 border border-slate-700 rounded-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 py-2">
                {(dropdownContent.CTI as string[]).map((item) => (
                  <Link
                    key={item}
                    href="#"
                    className="block px-4 py-2 text-slate-300 hover:text-cyan-400 hover:bg-slate-800/50 transition text-sm"
                  >
                    {item}
                  </Link>
                ))}
              </div>
            </div>

            {/* About Us Dropdown */}
            <div className="relative group hover:bg-slate-700/95 rounded-2xl">
              <button className="text-slate-300 hover:text-white transition flex items-center gap-1">
                About Us
                <ChevronDown size={16} />
              </button>
              <div className="absolute -left-18 mt-0 w-64 bg-slate-900/95 border border-slate-700 rounded-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 p-4">
                <p className="text-slate-300 text-sm leading-relaxed">{dropdownContent.About_us}</p>
              </div>
            </div>

            {/* Contact Us Dropdown */}
            <div className="relative group hover:bg-slate-700/95 rounded-2xl">
              <button className="text-slate-300 hover:text-white transition flex items-center gap-1">
                Contact Us
                <ChevronDown size={16} />
              </button>
              <div className="absolute -left-14 mt-0 w-52 bg-slate-900/95 border border-slate-700 rounded-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 p-4">
                <p className="text-slate-300 text-center text-sm leading-relaxed">{dropdownContent.Contant_us}</p>
              </div>
            </div>
          </div>
          <div className="flex gap-3">
            <Link href="/login">
              <button className="px-6 py-2 text-cyan-400 hover:text-cyan-300 transition">Login</button>
            </Link>
            <Link href="/signup">
              <button className="px-6 py-2 bg-cyan-400 text-black font-semibold rounded-full hover:bg-cyan-300 transition">
                Sign Up
              </button>
            </Link>
          </div>
        </div>

        {/* Mobile Menu Button */}
        <button className="md:hidden text-white" onClick={() => setIsOpen(!isOpen)}>
          {isOpen ? <X size={24} /> : <Menu size={24} />}
        </button>
      </div>

      {/* Mobile Navigation */}
      {isOpen && (
        <div className="md:hidden mt-4 pb-4 space-y-4">
          <Link href="#" className="block text-slate-300 hover:text-white transition">
            Platforms
          </Link>
          <Link href="#" className="block text-slate-300 hover:text-white transition">
            Offerings
          </Link>
          <Link href="#" className="block text-slate-300 hover:text-white transition">
            CTI
          </Link>
          <Link href="#" className="block text-slate-300 hover:text-white transition">
            Resources
          </Link>
          <Link href="#" className="block text-slate-300 hover:text-white transition">
            Company
          </Link>
          <Link href="#" className="block text-slate-300 hover:text-white transition">
            About Us
          </Link>
          <Link href="#" className="block text-slate-300 hover:text-white transition">
            Contact Us
          </Link>
          <div className="flex gap-3 pt-4">
            <Link href="/login" className="flex-1">
              <button className="w-full px-6 py-2 text-cyan-400 hover:text-cyan-950 transition border border-slate-600 rounded-full">
                Login
              </button>
            </Link>
            <Link href="/signup" className="flex-1">
              <button className="w-full px-6 py-2 bg-cyan-400 text-black font-semibold rounded-full hover:bg-cyan-300 transition">
                Sign Up
              </button>
            </Link>
          </div>
        </div>
      )}
    </nav>
  </header>
)
}
