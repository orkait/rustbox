import { useState, useEffect } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Layout } from "./components/Layout.tsx";
import { CodeEditor } from "./components/CodeEditor.tsx";
import { LanguageSelect } from "./components/LanguageSelect.tsx";
import { SubmitButton } from "./components/SubmitButton.tsx";
import { ResultPanel } from "./components/ResultPanel.tsx";
import { useSubmission } from "./hooks/useSubmission.ts";

const EXAMPLES: Record<string, string> = {
  python: `# Python — Hello World
import sys

def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

n = 10
print(f"Fibonacci({n}) = {fibonacci(n)}")
print(f"Python {sys.version.split()[0]}")
`,
  cpp: `// C++ — Hello World
#include <bits/stdc++.h>
using namespace std;

int main() {
    vector<int> nums = {5, 3, 8, 1, 9, 2, 7};
    sort(nums.begin(), nums.end());

    cout << "Sorted: ";
    for (int n : nums) cout << n << " ";
    cout << endl;

    cout << "Sum: " << accumulate(nums.begin(), nums.end(), 0) << endl;
    return 0;
}
`,
  java: `// Java — Hello World
public class Main {
    public static void main(String[] args) {
        int[] nums = {5, 3, 8, 1, 9, 2, 7};
        java.util.Arrays.sort(nums);

        System.out.print("Sorted: ");
        for (int n : nums) System.out.print(n + " ");
        System.out.println();

        int sum = java.util.Arrays.stream(nums).sum();
        System.out.println("Sum: " + sum);
    }
}
`,
};

function App() {
  const [language, setLanguage] = useState("python");
  const [code, setCode] = useState(EXAMPLES.python);
  const [stdin, setStdin] = useState("");
  const [stdinOpen, setStdinOpen] = useState(false);
  const { submit, result, loading, error } = useSubmission();

  // Update code example when language changes
  useEffect(() => {
    setCode(EXAMPLES[language] ?? EXAMPLES.python);
  }, [language]);

  const handleSubmit = () => {
    submit({ language, code, stdin });
  };

  return (
    <Layout>
      <div className="space-y-4">
        {/* Toolbar */}
        <div className="flex items-center justify-between">
          <LanguageSelect value={language} onChange={setLanguage} />
          <SubmitButton onClick={handleSubmit} loading={loading} />
        </div>

        {/* Code editor */}
        <CodeEditor
          value={code}
          onChange={setCode}
          language={language}
        />

        {/* Stdin (collapsible) */}
        <div>
          <button
            onClick={() => setStdinOpen(!stdinOpen)}
            className="flex items-center gap-1 text-sm text-gray-400 hover:text-gray-200 transition-colors cursor-pointer"
          >
            {stdinOpen ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
            Standard Input
          </button>
          {stdinOpen && (
            <textarea
              value={stdin}
              onChange={(e) => setStdin(e.target.value)}
              placeholder="Input data for your program..."
              spellCheck={false}
              className="mt-2 w-full min-h-[100px] resize-y rounded-xl bg-gray-900 text-gray-100 font-mono text-sm p-4 border border-gray-700 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500 placeholder-gray-500"
            />
          )}
        </div>

        {/* Results */}
        <ResultPanel result={result} loading={loading} error={error} />
      </div>
    </Layout>
  );
}

export default App;
