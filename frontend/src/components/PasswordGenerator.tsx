import { useState } from "react";
import { generatePassword, checkPassword, checkBreach } from "../api";

interface PasswordStrength {
  entropy: number;
  length: number;
  grade: string;
}

export default function PasswordGenerator() {
  const [length, setLength] = useState(32);
  const [includeLower, setIncludeLower] = useState(true);
  const [includeUpper, setIncludeUpper] = useState(true);
  const [includeDigits, setIncludeDigits] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [noAmbiguous, setNoAmbiguous] = useState(false);
  const [style, setStyle] = useState("random");

  const [password, setPassword] = useState("");
  const [strength, setStrength] = useState<PasswordStrength | null>(null);
  const [breachCount, setBreachCount] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);

  async function handleGenerate() {
    const gen = await generatePassword({
      length,
      style,
      include_lowercase: includeLower,
      include_uppercase: includeUpper,
      include_digits: includeDigits,
      include_symbols: includeSymbols,
      no_ambiguous: noAmbiguous,
    });

    setPassword(gen.password);

    const str = await checkPassword(gen.password);
    setStrength(str);

    const br = await checkBreach(gen.password);
    setBreachCount(br.breach_count);
    setCopied(false);
  }

  async function handleCopy() {
    await navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Password Generator</h2>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">
                Style
              </label>
              <select
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm"
                value={style}
                onChange={(e) => setStyle(e.target.value)}
              >
                <option value="random">Random</option>
                <option value="diceware">Diceware</option>
                <option value="pin">PIN</option>
                <option value="memorable">Memorable</option>
              </select>
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-1">
                Length: {length}
              </label>
              <input
                type="range"
                min={4}
                max={128}
                value={length}
                onChange={(e) => setLength(Number(e.target.value))}
                className="w-full"
              />
            </div>

            <div className="space-y-2">
              {[
                [includeLower, setIncludeLower, "Lowercase (a-z)"] as const,
                [includeUpper, setIncludeUpper, "Uppercase (A-Z)"] as const,
                [includeDigits, setIncludeDigits, "Digits (0-9)"] as const,
                [includeSymbols, setIncludeSymbols, "Symbols (!@#$)"] as const,
                [
                  noAmbiguous,
                  setNoAmbiguous,
                  "No ambiguous (1lI0O)",
                ] as const,
              ].map(([checked, setter, label]) => (
                <label key={label} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => setter(!checked)}
                    className="rounded"
                  />
                  {label}
                </label>
              ))}
            </div>

            <button
              onClick={handleGenerate}
              className="w-full px-4 py-2 bg-emerald-500 text-black rounded-lg font-medium hover:bg-emerald-400 transition-colors"
            >
              Generate
            </button>
          </div>
        </div>

        <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
          <h3 className="text-sm text-gray-400 mb-2">Generated Password</h3>

          {password ? (
            <>
              <div className="bg-gray-800 rounded-lg p-4 mb-4 font-mono text-lg break-all select-all">
                {password}
              </div>

              <button
                onClick={handleCopy}
                className="px-3 py-1.5 bg-gray-800 rounded-lg text-sm hover:bg-gray-700 transition-colors mb-4"
              >
                {copied ? "Copied!" : "Copy to Clipboard"}
              </button>

              {strength && (
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Strength</span>
                    <span
                      className={`font-semibold ${
                        strength.grade.startsWith("A")
                          ? "text-emerald-400"
                          : strength.grade === "B"
                            ? "text-lime-400"
                            : strength.grade === "C"
                              ? "text-yellow-400"
                              : "text-red-400"
                      }`}
                    >
                      {strength.grade}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Entropy</span>
                    <span>{strength.entropy.toFixed(1)} bits</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Length</span>
                    <span>{strength.length} chars</span>
                  </div>
                  {breachCount !== null && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Known Breaches</span>
                      <span
                        className={
                          breachCount === 0
                            ? "text-emerald-400"
                            : "text-red-400"
                        }
                      >
                        {breachCount === 0
                          ? "None"
                          : `${breachCount} breaches`}
                      </span>
                    </div>
                  )}
                </div>
              )}
            </>
          ) : (
            <p className="text-gray-500 text-sm">
              Configure options and click Generate.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
