import AuthForm from "@/components/auth-form"

export default function LoginPage() {
  return (
    <main className="min-h-screen bg-gradient-to-b from-black to-slate-900 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3">Welcome Back</h1>
          <p className="text-slate-400">Login to access your Trace X dashboard and threat analysis</p>
        </div>

        {/* Auth Form */}
        <AuthForm type="login" />

        {/* Footer */}
        <div className="mt-12 pt-8 border-t border-slate-700 text-center">
          <p className="text-slate-400 text-xs">Secure authentication powered by JWT</p>
        </div>
      </div>
    </main>
  )
}
