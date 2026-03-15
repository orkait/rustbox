import type { ReactNode } from "react";
import { Terminal } from "lucide-react";

interface LayoutProps {
  children: ReactNode;
}

export function Layout({ children }: LayoutProps) {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <header className="border-b border-gray-800">
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center gap-3">
          <Terminal className="w-6 h-6 text-emerald-500" />
          <h1 className="text-xl font-bold tracking-tight">Rustbox Judge</h1>
        </div>
      </header>
      <main className="max-w-4xl mx-auto px-6 py-6">{children}</main>
    </div>
  );
}
