import { Code2 } from "lucide-react";

interface LanguageSelectProps {
  value: string;
  onChange: (value: string) => void;
}

const LANGUAGES = [
  { value: "python", label: "Python" },
  { value: "cpp", label: "C++" },
  { value: "java", label: "Java" },
];

export function LanguageSelect({ value, onChange }: LanguageSelectProps) {
  return (
    <div className="flex items-center gap-2">
      <Code2 className="w-5 h-5 text-gray-400" />
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="bg-gray-800 text-white rounded-lg px-3 py-2 border border-gray-700 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 cursor-pointer"
      >
        {LANGUAGES.map((lang) => (
          <option key={lang.value} value={lang.value}>
            {lang.label}
          </option>
        ))}
      </select>
    </div>
  );
}
