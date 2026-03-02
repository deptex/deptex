export default function TransferImpactAssessmentPage() {
  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <h1 className="text-3xl font-bold text-foreground mb-2">Transfer Impact Assessment</h1>
        <p className="text-sm text-foreground-secondary mb-8">Last updated: March 2026</p>

        <div className="prose prose-invert prose-sm max-w-none space-y-6 text-foreground-secondary">
          <p className="text-yellow-400 text-xs font-medium uppercase tracking-wider border border-yellow-500/30 rounded px-3 py-2 bg-yellow-500/5">
            Draft — Requires legal review before production use
          </p>

          <h2 className="text-lg font-semibold text-foreground">1. Purpose</h2>
          <p>This Transfer Impact Assessment (TIA) evaluates the risks associated with international transfers of personal data by Deptex, in compliance with Chapter V of the GDPR and the EU Standard Contractual Clauses (SCCs).</p>

          <h2 className="text-lg font-semibold text-foreground">2. Data Transfers</h2>
          <p>Deptex transfers personal data from the EU/EEA to:</p>
          <ul className="list-disc pl-6 space-y-1">
            <li>United States (Supabase, Fly.io, Stripe, Google AI)</li>
          </ul>
          <p>All transfers are protected by EU Standard Contractual Clauses (Module 2: Controller to Processor) and, where available, the EU-US Data Privacy Framework.</p>

          <h2 className="text-lg font-semibold text-foreground">3. Risk Assessment</h2>
          <p>The data processed by Deptex consists primarily of:</p>
          <ul className="list-disc pl-6 space-y-1">
            <li>Business email addresses and names (low sensitivity)</li>
            <li>Open-source dependency metadata (publicly available)</li>
            <li>Repository structure metadata (moderate sensitivity for private repos)</li>
          </ul>
          <p>Source code is NOT stored beyond temporary processing. The risk of surveillance or government access to this metadata is assessed as LOW given the non-sensitive nature of the data categories.</p>

          <h2 className="text-lg font-semibold text-foreground">4. Supplementary Measures</h2>
          <ul className="list-disc pl-6 space-y-1">
            <li>Encryption at rest and in transit for all data</li>
            <li>Pseudonymization of identifiers where feasible</li>
            <li>Contractual commitments from sub-processors</li>
            <li>Data minimization — only metadata required for security analysis is retained</li>
            <li>Configurable deployment regions for Enterprise customers</li>
          </ul>

          <h2 className="text-lg font-semibold text-foreground">5. Contact</h2>
          <p>For transfer-related inquiries: <a href="mailto:privacy@deptex.io" className="text-primary hover:underline">privacy@deptex.io</a></p>
        </div>
      </div>
    </div>
  );
}
