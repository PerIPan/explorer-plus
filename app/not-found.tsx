import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="text-[var(--accent-teal)] text-4xl font-light mb-2">404 - Not Found</div>
        <div className="text-[var(--text-secondary)] text-sm mb-4">The page you are looking for does not exist.</div>
        <Link href="/" className="text-sm text-[var(--accent-teal)] hover:underline">
          Go to 360 Views
        </Link>
      </div>
    </div>
  );
}
