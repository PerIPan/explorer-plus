import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

export function SearchBar() {
  const [value, setValue] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  /** Cleanup debounce on unmount */
  useEffect(() => {
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, []);

  /** Focus on `/` keypress anywhere outside an input/textarea */
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement).tagName.toLowerCase();
      if (e.key === '/' && tag !== 'input' && tag !== 'textarea') {
        e.preventDefault();
        inputRef.current?.focus();
      }
      if (e.key === 'Escape') {
        inputRef.current?.blur();
      }
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  const triggerSearch = useCallback(
    (q: string) => {
      const trimmed = q.trim();
      if (trimmed.length >= 3) {
        navigate(`/search?q=${encodeURIComponent(trimmed)}`);
      }
    },
    [navigate]
  );

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    const newVal = e.target.value;
    setValue(newVal);

    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      triggerSearch(newVal);
    }, 300);
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (debounceRef.current) clearTimeout(debounceRef.current);
    triggerSearch(value);
  }

  return (
    <form onSubmit={handleSubmit} role="search" className="relative w-full max-w-xl">
      {/* Search icon */}
      <span
        aria-hidden="true"
        className="absolute left-3 top-1/2 -translate-y-1/2 text-[#8892b0] pointer-events-none"
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <circle cx="11" cy="11" r="8" />
          <path d="m21 21-4.35-4.35" />
        </svg>
      </span>

      <input
        ref={inputRef}
        type="search"
        value={value}
        onChange={handleChange}
        placeholder="Search techniques, groups, software..."
        aria-label="Search MITRE ATT&CK entities"
        className="
          w-full pl-9 pr-16 py-2 rounded-md text-sm
          bg-[#16213e] border border-[#2a2a4a]
          text-[#ccd6f6] placeholder-[#8892b0]
          focus:outline-none focus:border-[#64ffda] focus:ring-1 focus:ring-[#64ffda33]
          transition-colors duration-150
        "
      />

      {/* Keyboard hint */}
      <span
        aria-hidden="true"
        className="absolute right-3 top-1/2 -translate-y-1/2 text-[#8892b0] text-xs border border-[#2a2a4a] rounded px-1 py-0.5 font-mono"
      >
        /
      </span>
    </form>
  );
}
