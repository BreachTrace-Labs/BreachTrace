import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import IncidentDetail from "./pages/IncidentDetail";
import Research from "./pages/Research";

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-zinc-950 text-zinc-100">
        {/* Top nav */}
        <header className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-sm sticky top-0 z-50">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
            <NavLink to="/" className="flex items-center gap-2 group">
              <span className="text-base font-bold tracking-tight text-zinc-100 group-hover:text-white transition-colors">
                BreachTrace
              </span>
              <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-400 border border-indigo-500/25">
                v0.1
              </span>
            </NavLink>

            <nav className="flex items-center gap-6 text-sm">
              <NavLink
                to="/"
                end
                className={({ isActive }) =>
                  isActive
                    ? "text-zinc-100 font-medium"
                    : "text-zinc-500 hover:text-zinc-300 transition-colors"
                }
              >
                Dashboard
              </NavLink>
              <NavLink
                to="/research"
                className={({ isActive }) =>
                  isActive
                    ? "text-zinc-100 font-medium"
                    : "text-zinc-500 hover:text-zinc-300 transition-colors"
                }
              >
                Research
              </NavLink>
            </nav>
          </div>
        </header>

        {/* Page content */}
        <main className="max-w-6xl mx-auto px-4 sm:px-6 py-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/incident/:id" element={<IncidentDetail />} />
            <Route path="/research" element={<Research />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}