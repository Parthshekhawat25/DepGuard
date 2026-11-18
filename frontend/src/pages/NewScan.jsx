import { useRef, useState } from "react";
import { AlertCircle, FileText, LoaderCircle, UploadCloud, X } from "lucide-react";

const MAX_FILE_SIZE = 1024 * 1024;

async function validateFile(file) {
  if (!file) return "Choose a requirements.txt file.";
  if (!file.name.toLowerCase().endsWith(".txt")) return "Only .txt files are supported.";
  if (file.size > MAX_FILE_SIZE) return "The file must be 1 MB or smaller.";
  if (file.size === 0) return "The selected file is empty.";
  const content = await file.text();
  if (!content.trim()) return "The selected requirements file is empty.";
  return null;
}

export default function NewScan({ onScan, loading, error }) {
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [localError, setLocalError] = useState("");
  const [dragging, setDragging] = useState(false);

  async function selectFile(nextFile) {
    const validationError = await validateFile(nextFile);
    if (validationError) {
      setFile(null);
      setLocalError(validationError);
      return;
    }
    setLocalError("");
    setFile(nextFile);
  }

  function onDrop(event) {
    event.preventDefault();
    setDragging(false);
    void selectFile(event.dataTransfer.files?.[0]);
  }

  return (
    <div className="mx-auto max-w-3xl space-y-7">
      <div>
        <p className="eyebrow text-cyan-300/80">New scan</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Upload dependency evidence</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          DepGuard reads requirements.txt as text. It never executes or installs uploaded packages.
        </p>
      </div>

      <div className="panel p-6 md:p-8">
        <input
          ref={inputRef}
          type="file"
          accept=".txt,text/plain"
          className="hidden"
          onChange={(event) => void selectFile(event.target.files?.[0])}
        />
        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          onDragEnter={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragOver={(event) => event.preventDefault()}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`flex min-h-72 w-full flex-col items-center justify-center rounded-2xl border border-dashed px-6 text-center transition ${
            dragging
              ? "border-cyan-300 bg-cyan-300/10"
              : "border-slate-600 bg-slate-900/30 hover:border-blue-400/70 hover:bg-blue-400/5"
          }`}
        >
          <div className="rounded-2xl bg-blue-400/10 p-4 text-blue-200">
            <UploadCloud size={30} />
          </div>
          <p className="mt-5 text-base font-semibold text-white">Drop requirements.txt here</p>
          <p className="mt-2 text-sm text-slate-500">or click to browse · UTF-8 text · maximum 1 MB</p>
          <span className="mt-5 rounded-lg border border-slate-600 px-3 py-2 text-sm font-semibold text-slate-200">
            Browse file
          </span>
        </button>

        {file && (
          <div className="mt-5 flex items-center justify-between gap-3 rounded-xl border border-slate-700 bg-slate-900/60 p-4">
            <div className="flex min-w-0 items-center gap-3">
              <FileText className="shrink-0 text-cyan-300" size={20} />
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-slate-100">{file.name}</p>
                <p className="text-xs text-slate-500">{(file.size / 1024).toFixed(1)} KB selected</p>
              </div>
            </div>
            <button type="button" onClick={() => setFile(null)} className="rounded-lg p-2 text-slate-500 hover:bg-slate-800 hover:text-white">
              <X size={17} />
            </button>
          </div>
        )}

        {(localError || error) && (
          <div className="mt-5 flex gap-3 rounded-xl border border-rose-400/30 bg-rose-400/10 p-4 text-sm text-rose-200">
            <AlertCircle className="shrink-0" size={18} />
            <span>{localError || error}</span>
          </div>
        )}

        <button
          type="button"
          disabled={!file || loading}
          onClick={() => onScan(file)}
          className="mt-6 flex w-full items-center justify-center gap-2 rounded-xl bg-blue-500 px-4 py-3 text-sm font-semibold text-white transition hover:bg-blue-400 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? <LoaderCircle className="animate-spin" size={18} /> : <UploadCloud size={18} />}
          {loading ? "Scanning dependencies…" : "Scan dependencies"}
        </button>
      </div>
    </div>
  );
}
