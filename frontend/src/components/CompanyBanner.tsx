const companies = [
  "GitHub",
  "Microsoft",
  "Google",
  "Amazon",
  "Netflix",
  "Uber",
  "Stripe",
  "Shopify",
  "Atlassian",
  "Vercel",
  "Linear",
  "Notion",
];

export default function CompanyBanner() {
  return (
    <div className="relative overflow-hidden bg-background py-12">
      {/* Left fade gradient */}
      <div className="absolute left-0 top-0 bottom-0 w-32 bg-gradient-to-r from-background to-transparent z-10 pointer-events-none" />
      
      {/* Right fade gradient */}
      <div className="absolute right-0 top-0 bottom-0 w-32 bg-gradient-to-l from-background to-transparent z-10 pointer-events-none" />
      
      <div className="flex">
        <div className="flex animate-scroll gap-16 whitespace-nowrap">
          {/* First set */}
          {companies.map((company, index) => (
            <div
              key={`first-${company}-${index}`}
              className="text-foreground-secondary text-lg font-medium shrink-0"
            >
              {company}
            </div>
          ))}
          {/* Duplicate for seamless loop */}
          {companies.map((company, index) => (
            <div
              key={`second-${company}-${index}`}
              className="text-foreground-secondary text-lg font-medium shrink-0"
            >
              {company}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

