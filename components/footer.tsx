"use client"

import Link from "next/link"

const footerLinks = {
  Contact: [
    "Tracexcti@gmail.com",
  ],
}

export default function Footer() {
  return (
    <footer className="bg-black border-t border-slate-800 py-4 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        {/* Main Footer Content */}
        <div className="flex justify-between items-center mb-8"> 
          {/* Left: Logo + Brand */}
          <div className="flex items-center gap-2">
            <div className="w-10 h-10 bg-black rounded-full flex items-center justify-center">
              <img src="/logo.png" alt="Logo" className="w-8 h-8" />
            </div>
            <span className="text-white font-semibold text-lg">Trace X</span>
          </div>

          {/* Right: Contact Info */}
          <div className="text-md text-slate-400 flex items-center">
            <span className="text-white font-semibold mr-3">Contact:</span>
            <Link
              href="mailto:Tracexcti@gmail.com"
              className="hover:text-white transition text-md"
            >
              Tracexcti@gmail.com
            </Link>
          </div>
        </div>
      </div>
    </footer>
  )
}




// "use client"

// import Link from "next/link"

// const footerLinks = {
//   //Solutions: ["XTM Suite", "OpenCTI", "OpenBAS", "Agentic AI", "What is XTM Hub?"],
//   Contact: [
//     "CTI@gmail.com",
//   ],
//   // Resources: [
//   //   "XTM Hub",
//   //   "Filigran Academy",
//   //   "Filigran Blog",
//   //   "Events & Webinars",
//   //   "Use Case Library",
//   //   "Content Library",
//   //   "OpenCTI Documentation",
//   //   "OpenBAS Documentation",
//   // ],
//   // Company: [
//   //   "Our Story",
//   //   "Leadership",
//   //   "Careers",
//   //   "Our Investors",
//   //   "Newsroom",
//   //   "Our Brand",
//   //   "Become a Partner",
//   //   "MSSP Partners",
//   //   "Technology Alliances",
//   //   "Solutions Providers",
//   //   "Marketplaces",
//   // ],
// }

// export default function Footer() {
//   return (
//     <footer className="bg-black border-t border-slate-800">
//       <div className="max-w-7xl mx-auto">
//         {/* Main Footer Content */}
//         <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-6">
//           {/* Company Info */}
//           <div className="lg:col-span-1">
//             <div className="flex items-center gap-2 mb-4 mt-5">
//               <div className="w-8 h-8 bg-gradient-to-br from-slate-300 to-slate-400 rounded-full flex items-center justify-center">
//                 <span className="text-black font-bold text-sm">F</span>
//               </div>
//               <span className="text-white font-semibold">Filigran</span>
//             </div>
//             {/* <p className="text-slate-400 text-sm leading-relaxed">
//               Filigran provides open-source cybersecurity solutions covering threat intelligence management, breach and
//               attack simulation, and cyber risk management.
//             </p> */}
//             {/* <div className="flex gap-4 mt-4">
//               <div className="w-12 h-12 bg-slate-800 rounded flex items-center justify-center">
//                 <span className="text-xs text-slate-400">ISO</span>
//               </div>
//               <div className="w-12 h-12 bg-slate-800 rounded flex items-center justify-center">
//                 <span className="text-xs text-slate-400">G2</span>
//               </div>
//             </div> */}
//           </div>

//           {/* Footer Links           */}
//           {Object.entries(footerLinks).map(([category, links]) => (
//             <div key={category} className="text-md mt-5 text-slate-400 px-148">
//               <span className="text-white font-semibold mr-3">{category}:</span>
//               {links.map((link, index) => (
//                 <Link
//                   key={index}
//                   href="#"
//                   className="hover:text-white transition text-md mr-2"
//                 >
//                   {link}
//                 </Link>
//               ))}
//             </div>
//           ))}
          

//         </div>

//         {/* Bottom Footer
//         <div className="border-t border-slate-800 pt-4 flex flex-col sm:flex-row justify-between items-center gap-4">
//           <p className="text-slate-400 text-xs">© 2025 Filigran. All rights reserved</p>
//           <div className="flex gap-6">
//             <Link href="#" className="text-slate-400 hover:text-white transition text-xs">
//               Privacy Policy
//             </Link>
//             <Link href="#" className="text-slate-400 hover:text-white transition text-xs">
//               Terms of Services
//             </Link>
//             <Link href="#" className="text-slate-400 hover:text-white transition text-xs">
//               Licenses
//             </Link>
//             <Link href="#" className="text-slate-400 hover:text-white transition text-xs">
//               Contact
//             </Link>
//           </div>
//         </div> */}
//       </div>
//     </footer>
//   )
// }
