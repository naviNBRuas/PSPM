import { NavLink, Outlet } from "react-router-dom";

const navItems = [
  { to: "/", label: "Dashboard", icon: "📊" },
  { to: "/import", label: "Import", icon: "📥" },
  { to: "/vault", label: "Vault", icon: "🔐" },
  { to: "/analysis", label: "Analysis", icon: "📋" },
  { to: "/generator", label: "Generator", icon: "⚡" },
];

export default function App() {
  return (
    <div className="flex h-screen">
      <aside className="w-64 bg-gray-900 border-r border-gray-800 p-4 flex flex-col">
        <div className="mb-8">
          <h1 className="text-xl font-bold text-emerald-400">PSPM</h1>
          <p className="text-xs text-gray-500 mt-1">
            Password Security Posture Management
          </p>
        </div>
        <nav className="flex flex-col gap-1 flex-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive
                    ? "bg-emerald-500/10 text-emerald-400"
                    : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
                }`
              }
            >
              <span>{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="text-xs text-gray-600 mt-4">
          v0.1.0 &middot; Local-first
        </div>
      </aside>
      <main className="flex-1 overflow-auto p-6">
        <Outlet />
      </main>
    </div>
  );
}
