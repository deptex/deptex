export default function DataProcessingAgreementPage() {
  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <h1 className="text-3xl font-bold text-foreground mb-2">Data Processing Agreement</h1>
        <p className="text-sm text-foreground-secondary mb-8">Last updated: March 2026</p>

        <div className="prose prose-invert prose-sm max-w-none space-y-6 text-foreground-secondary">
          <p className="text-yellow-400 text-xs font-medium uppercase tracking-wider border border-yellow-500/30 rounded px-3 py-2 bg-yellow-500/5">
            Draft — Requires legal review before production use
          </p>

          <h2 className="text-lg font-semibold text-foreground">1. Definitions</h2>
          <p>"Data Controller" means the Customer (the organization using Deptex). "Data Processor" means Deptex Pty Ltd. "Personal Data" means any information relating to an identified or identifiable natural person as defined by GDPR.</p>

          <h2 className="text-lg font-semibold text-foreground">2. Scope and Nature of Processing</h2>
          <p>Deptex processes the following categories of personal data on behalf of the Customer:</p>
          <ul className="list-disc pl-6 space-y-1">
            <li>User account data (email addresses, names, profile pictures)</li>
            <li>Source code metadata (repository names, commit hashes, author names, file paths)</li>
            <li>Dependency metadata (package names, versions, license information)</li>
            <li>Security findings metadata (vulnerability IDs, severity scores, affected components)</li>
          </ul>
          <p>Deptex does not store or process source code itself beyond temporary cloning during extraction. All cloned repositories are deleted after analysis.</p>

          <h2 className="text-lg font-semibold text-foreground">3. Sub-processors</h2>
          <ul className="list-disc pl-6 space-y-1">
            <li>Supabase Inc. (PostgreSQL database, authentication, file storage) — US/EU regions</li>
            <li>Fly.io Inc. (compute workers for extraction and analysis) — configurable region</li>
            <li>Upstash Inc. (Redis caching, job queuing) — EU region</li>
            <li>Stripe Inc. (payment processing) — US/EU</li>
            <li>Google LLC (Gemini AI for platform features) — global</li>
          </ul>

          <h2 className="text-lg font-semibold text-foreground">4. Data Subject Rights</h2>
          <p>Deptex assists the Customer in fulfilling data subject requests (access, rectification, erasure, portability) within 30 days of written request.</p>

          <h2 className="text-lg font-semibold text-foreground">5. Security Measures</h2>
          <ul className="list-disc pl-6 space-y-1">
            <li>Encryption at rest (AES-256) and in transit (TLS 1.2+)</li>
            <li>Row-level security on all database tables</li>
            <li>BYOK API keys encrypted with AES-256-GCM</li>
            <li>Automated vulnerability scanning of our own dependencies</li>
            <li>Access controls with role-based permissions</li>
          </ul>

          <h2 className="text-lg font-semibold text-foreground">6. Data Retention</h2>
          <p>Customer data is retained for the duration of the subscription. Upon termination, all Customer data is deleted within 30 days, except as required by applicable law.</p>

          <h2 className="text-lg font-semibold text-foreground">7. Contact</h2>
          <p>For data processing inquiries: <a href="mailto:privacy@deptex.io" className="text-primary hover:underline">privacy@deptex.io</a></p>
        </div>
      </div>
    </div>
  );
}
