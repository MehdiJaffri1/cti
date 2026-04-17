import AuthForm from "@/components/auth-form"

export default function SignUpPage() {
  return (
    <main className="min-h-screen bg-gradient-to-b from-black to-slate-900 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-3xl sm:text-4xl font-bold text-white mb-3">Create Your Account</h1>
          <p className="text-slate-400">Join Trace X to start analyzing threats and securing your infrastructure</p>
        </div>

        {/* Auth Form */}
        <AuthForm type="signup" />

        {/* Footer */}
        <div className="mt-12 pt-8 border-t border-slate-700 text-center">
          <p className="text-slate-400 text-xs">By signing up, you agree to our Terms of Service and Privacy Policy</p>
        </div>
      </div>
    </main>
  )
}
