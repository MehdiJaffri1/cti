"use client"

import Link from "next/link"
import { useRouter } from 'next/navigation'
import { LogOut } from 'lucide-react'

interface DashboardHeaderProps {
  email: string
}

export default function DashboardHeader({ email }: DashboardHeaderProps) {
  const router = useRouter()

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" })
      router.push("/")
    } catch (error) {
      console.error("Logout failed:", error)
    }
  }

  return (
    <header className="bg-black border-b border-slate-800 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 bg-cyan-400/10 border border-cyan-400/30 rounded-lg flex items-center justify-center flex-shrink-0">
            <img src="/logo.png" alt="Trace X" className="w-8 h-8" />
          </div>
          <Link href="/" className="text-white font-semibold text-2xl hover:text-cyan-400 transition">
            TRACE X
          </Link>
        </div>
        <div className="flex items-center gap-6">
          <div className="text-right">
            <p className="text-slate-300 text-sm">Welcome back</p>
            <p className="text-white font-medium">{email}</p>
          </div>
          <button
            onClick={handleLogout}
            className="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-800/50 rounded-lg transition flex items-center gap-2"
            title="Logout"
          >
            <LogOut size={20} />
          </button>
        </div>
      </div>
    </header>
  )
}
