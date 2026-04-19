export default function CookiePolicyPage() {
  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <h1 className="text-3xl font-bold text-foreground mb-2">Cookie Policy</h1>
        <p className="text-sm text-foreground-secondary mb-8">Last updated: March 2026</p>

        <div className="prose prose-invert prose-sm max-w-none space-y-6 text-foreground-secondary">
          <h2 className="text-lg font-semibold text-foreground">1. What are cookies?</h2>
          <p>Cookies are small text files stored on your device when you visit a website. They help the site remember your preferences and improve your experience.</p>

          <h2 className="text-lg font-semibold text-foreground">2. Cookies we use</h2>
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 pr-4 font-medium text-foreground">Cookie</th>
                <th className="text-left py-2 pr-4 font-medium text-foreground">Purpose</th>
                <th className="text-left py-2 font-medium text-foreground">Duration</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border">
                <td className="py-2 pr-4">sb-*-auth-token</td>
                <td className="py-2 pr-4">Authentication (Supabase session)</td>
                <td className="py-2">Session / 1 week</td>
              </tr>
              <tr className="border-b border-border">
                <td className="py-2 pr-4">sb-*-auth-token-code-verifier</td>
                <td className="py-2 pr-4">OAuth PKCE flow</td>
                <td className="py-2">Session</td>
              </tr>
            </tbody>
          </table>

          <h2 className="text-lg font-semibold text-foreground">3. Essential cookies only</h2>
          <p>Deptex currently uses only strictly necessary cookies for authentication. We do not use analytics, advertising, or tracking cookies. If this changes, we will update this policy and request your consent.</p>

          <h2 className="text-lg font-semibold text-foreground">4. Managing cookies</h2>
          <p>You can manage cookies through your browser settings. Note that disabling authentication cookies will prevent you from using the platform.</p>

          <h2 className="text-lg font-semibold text-foreground">5. Contact</h2>
          <p>Questions about our cookie practices: <a href="mailto:privacy@deptex.io" className="text-primary hover:underline">privacy@deptex.io</a></p>
        </div>
      </div>
    </div>
  );
}
