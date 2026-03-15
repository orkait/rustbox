import CodeMirror from '@uiw/react-codemirror';
import { python } from '@codemirror/lang-python';
import { cpp } from '@codemirror/lang-cpp';
import { java } from '@codemirror/lang-java';
import { oneDark } from '@codemirror/theme-one-dark';
import { useMemo } from 'react';

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  language: string;
}

function getLanguageExtension(language: string) {
  switch (language) {
    case 'python':
    case 'py':
      return python();
    case 'cpp':
    case 'c++':
    case 'cxx':
      return cpp();
    case 'java':
      return java();
    default:
      return python();
  }
}

export function CodeEditor({ value, onChange, language }: CodeEditorProps) {
  const extensions = useMemo(() => [getLanguageExtension(language)], [language]);

  return (
    <div className="rounded-xl overflow-hidden border border-gray-700">
      <CodeMirror
        value={value}
        onChange={onChange}
        extensions={extensions}
        theme={oneDark}
        height="350px"
        basicSetup={{
          lineNumbers: true,
          highlightActiveLineGutter: true,
          foldGutter: true,
          bracketMatching: true,
          autocompletion: true,
          tabSize: 4,
        }}
      />
    </div>
  );
}
