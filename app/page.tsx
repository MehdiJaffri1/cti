import Header from "@/components/header"
import Hero from "@/components/hero"
import Features from "@/components/features"
import DeploymentOptions from "@/components/deployment-options"
import Footer from "@/components/footer"

export default function Home() {
  return (
    <main className="min-h-screen bg-linear-to-b from-black to-blue-900">
      <Header />
      <Hero />
      <Features />
      <DeploymentOptions />
      <Footer />
    </main>
  )
}
