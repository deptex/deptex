import { ChevronDown, ChevronRight, Menu, ScanSearch, Scale, Bell, Telescope, Plug, HelpCircle, Settings, LogOut } from "lucide-react";
import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { cn } from "../../lib/utils";
import { Button } from "../ui/button";
import { useAuth } from "../../contexts/AuthContext";
import { useUserProfile } from "../../hooks/useUserProfile";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu";

interface NavItem {
  name: string;
  to?: string;
  items?: { name: string; to: string; description?: string; icon?: React.ReactNode }[];
}

const navigationItems: NavItem[] = [
  {
    name: "Product",
    items: [
      { 
        name: "AI Security Agent", 
        to: "/platform-features/ai-security-agent", 
        description: "50+ tools, automations & PR review",
        icon: (
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" className="h-5 w-5 shrink-0 transition-colors duration-150" aria-hidden>
            <path d="M12 2L4 6v5c0 5 4 8 8 10 4-2 8-5 8-10V6l-8-4z" />
            <path d="M12 9l1 2 2 1-1 2-2 1-1-2-2-1 1-2 2-1z" fill="currentColor" stroke="none" />
          </svg>
        )
      },
      { 
        name: "Vulnerability Intelligence", 
        to: "/platform-features/vulnerability-intelligence", 
        description: "Depscore, reachability & version recommendations",
        icon: <ScanSearch className="h-5 w-5" />
      },
      { 
        name: "Customizable Compliance", 
        to: "/platform-features/customizable-compliance", 
        description: "Policy-as-code, SBOM & license compliance",
        icon: <Scale className="h-5 w-5" />
      },
      { 
        name: "Customizable Notifications", 
        to: "/platform-features/customizable-notifications", 
        description: "Define notifications as code",
        icon: <Bell className="h-5 w-5" />
      },
      { 
        name: "Advanced Upstream Insights", 
        to: "/platform-features/advanced-upstream-insights", 
        description: "Supply-chain forensics & contributor anomalies",
        icon: <Telescope className="h-5 w-5" />
      },
    ],
  },
  {
    name: "Resources",
    items: [
      { 
        name: "Open Source", 
        to: "/open-source", 
        description: "Core platform — one repo",
        icon: <img src="/images/integrations/github.png" alt="" className="h-5 w-5 rounded-full" aria-hidden />
      },
      { 
        name: "Integrations", 
        to: "/integrations", 
        description: "GitHub, Slack, Jira & more",
        icon: <Plug className="h-5 w-5" />
      },
      { 
        name: "Docs", 
        to: "/docs", 
        description: "Documentation & guides",
        icon: (
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" className="h-5 w-5 shrink-0" aria-hidden>
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <path d="M14 2v6h6" />
            <path d="M16 13H8" />
            <path d="M16 17H8" />
            <path d="M10 9H8" />
          </svg>
        )
      },
      { 
        name: "Help", 
        to: "/support", 
        description: "Support center",
        icon: <HelpCircle className="h-5 w-5" />
      },
    ],
  },
  { name: "Pricing", to: "/pricing" },
];

const GITHUB_REPO_URL = "https://github.com/deptex/deptex";
const GITHUB_API_REPO = "https://api.github.com/repos/deptex/deptex";

function formatStars(count: number): string {
  if (count >= 1000) return `${(count / 1000).toFixed(1)}k`;
  return count.toLocaleString();
}

export default function NavBar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const [githubStars, setGithubStars] = useState<number | null>(null);
  const { user, signOut } = useAuth();
  const { avatarUrl } = useUserProfile();
  const navigate = useNavigate();
  const [dropdownTimeout, setDropdownTimeout] = useState<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(GITHUB_API_REPO)
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error("Failed to fetch"))))
      .then((data) => {
        if (!cancelled && typeof data.stargazers_count === "number") {
          setGithubStars(data.stargazers_count);
        }
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  return (
    <header className="h-14 fixed left-0 right-0 top-0 z-50 flex items-center border-b border-border bg-background px-6">
      <div className="flex-1 min-w-0">
        <nav
          className="flex items-center justify-between w-full"
          aria-label="Global"
        >
          <div className="flex items-center gap-6">
            <Link
              to="/"
              className="flex items-center hover:opacity-80 transition-opacity shrink-0"
            >
              <img
                src="/images/logo_with_text.png"
                alt="Deptex"
                className="h-7 object-contain"
              />
            </Link>

            <ul className="ml-4 hidden items-center gap-6 lg:flex">
              {navigationItems.map((item) => (
                <li key={item.name} className="relative">
                  {item.items ? (
                    <div
                      className="group relative"
                      onMouseEnter={() => {
                        if (dropdownTimeout) {
                          clearTimeout(dropdownTimeout);
                          setDropdownTimeout(null);
                        }
                        setOpenDropdown(item.name);
                      }}
                      onMouseLeave={() => {
                        const timeout = setTimeout(() => {
                          setOpenDropdown(null);
                        }, 150);
                        setDropdownTimeout(timeout);
                      }}
                    >
                      <button
                        className={cn(
                          "text-sm font-normal leading-6 text-foreground rounded-md px-2 py-1.5 -mx-2 -my-1.5 flex items-center gap-1",
                          "hover:bg-white/5 transition-colors duration-150",
                          openDropdown === item.name && "bg-white/5"
                        )}
                      >
                        {item.name}
                        <ChevronDown
                          className={cn(
                            "h-4 w-4 transition-transform duration-200",
                            openDropdown === item.name && "rotate-180"
                          )}
                        />
                      </button>
                      {openDropdown === item.name && (
                        <div 
                          className="absolute top-full left-0 pt-2 w-80 z-50"
                          onMouseEnter={() => {
                            if (dropdownTimeout) {
                              clearTimeout(dropdownTimeout);
                              setDropdownTimeout(null);
                            }
                            setOpenDropdown(item.name);
                          }}
                          onMouseLeave={() => {
                            const timeout = setTimeout(() => {
                              setOpenDropdown(null);
                            }, 200);
                            setDropdownTimeout(timeout);
                          }}
                        >
                          <div className="rounded-lg border border-border/80 bg-[#0a0c0e] shadow-xl ring-1 ring-black/20 p-1.5 min-w-[20rem]">
                              {item.items.map((subItem) => (
                                <Link
                                  key={subItem.name}
                                  to={subItem.to}
                                  className="flex items-center gap-3 rounded-md px-2.5 py-2.5 text-sm text-foreground transition-colors duration-150 group/item hover:bg-[#12141a]"
                                  onClick={() => setOpenDropdown(null)}
                                >
                                  {subItem.icon && (
                                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-[#0a0c0e] border border-border/60 text-foreground-secondary group-hover/item:text-foreground transition-colors duration-150">
                                      {subItem.icon}
                                    </div>
                                  )}
                                  <div className="flex-1 min-w-0">
                                    <div className="font-medium text-foreground flex items-center gap-1.5">
                                      {subItem.name}
                                      <ChevronRight className="h-4 w-4 shrink-0 text-foreground-secondary/70 opacity-0 -translate-x-1 group-hover/item:opacity-100 group-hover/item:translate-x-0 transition-all duration-200" />
                                    </div>
                                    {subItem.description && (
                                      <div className="text-xs text-foreground-secondary/80 mt-0.5 group-hover/item:text-foreground/90 transition-colors duration-150">
                                        {subItem.description}
                                      </div>
                                    )}
                                  </div>
                                </Link>
                              ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <Link
                      to={item.to || "#"}
                      className="text-sm font-normal leading-6 text-foreground rounded-md px-2 py-1.5 -mx-2 -my-1.5 inline-block hover:bg-white/5 transition-colors duration-150"
                    >
                      {item.name}
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          </div>

          {/* Mobile Menu Button */}
          <div className="flex lg:hidden">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="text-foreground-secondary hover:text-foreground inline-flex items-center justify-center rounded-md transition-colors"
            >
              <span className="sr-only">Open main menu</span>
              <Menu
                className="size-8 p-1"
                aria-hidden="true"
              />
            </button>
          </div>

          {/* Desktop Actions */}
          <div className="hidden items-center justify-end gap-4 lg:flex lg:flex-1">
            <a
              href={GITHUB_REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm font-medium text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors"
              aria-label="Deptex on GitHub"
            >
              <img src="/images/integrations/github.png" alt="" className="h-5 w-5 rounded-full" aria-hidden />
              {githubStars !== null ? (
                <span>{formatStars(githubStars)}</span>
              ) : (
                <span className="tabular-nums">—</span>
              )}
            </a>

            {user ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <button className="flex items-center justify-center rounded-full border border-border bg-background-subtle overflow-hidden hover:bg-background-card transition-colors h-9 w-9">
                    <img
                      src={avatarUrl}
                      alt={user?.email || 'User'}
                      className="h-full w-full rounded-full object-cover"
                      onError={(e) => {
                        e.currentTarget.src = '/images/blank_profile_image.png';
                      }}
                    />
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-72">
                  <DropdownMenuLabel className="p-0">
                    <div className="flex items-center gap-3 px-2 py-3">
                      <div className="flex-shrink-0">
                        <img
                          src={avatarUrl}
                          alt={user?.email || 'User'}
                          className="h-10 w-10 rounded-full object-cover border border-border"
                          onError={(e) => {
                            e.currentTarget.src = '/images/blank_profile_image.png';
                          }}
                        />
                      </div>
                      <div className="flex flex-col gap-0.5 min-w-0 flex-1">
                        {user.user_metadata?.full_name && (
                          <span className="text-sm font-medium text-foreground truncate">{user.user_metadata.full_name}</span>
                        )}
                        <span className="text-xs text-foreground-secondary truncate">{user.email}</span>
                      </div>
                    </div>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem asChild>
                    <Link to="/organizations" className="cursor-pointer focus:bg-transparent hover:text-foreground text-foreground-secondary transition-colors">
                      Organizations
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuItem asChild>
                    <Link to="/settings" className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary transition-colors">
                      <Settings className="h-4 w-4" />
                      Settings
                    </Link>
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem 
                    onClick={async () => {
                      await signOut();
                      navigate('/');
                    }}
                    className="cursor-pointer text-foreground-secondary hover:text-foreground focus:bg-transparent focus:text-foreground flex items-center gap-2 transition-colors"
                  >
                    <LogOut className="h-4 w-4" />
                    Sign out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : (
              <Button
                asChild
                size="sm"
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 font-semibold rounded-lg h-8 px-3.5"
              >
                <Link to="/login">Get started</Link>
              </Button>
            )}
          </div>
        </nav>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <div className="lg:hidden fixed inset-0 z-40 bg-background-card/95 backdrop-blur-lg">
          <div className="flex flex-col h-full p-6">
            <div className="flex items-center justify-between mb-8">
              <Link to="/" className="flex items-center gap-2">
                <img src="/images/logo.png" alt="Deptex" className="size-8" />
                <span className="text-foreground font-semibold">Deptex</span>
              </Link>
              <button
                onClick={() => setMobileMenuOpen(false)}
                className="text-foreground-secondary hover:text-foreground"
              >
                <Menu className="size-6" />
              </button>
            </div>
            <ul className="space-y-4">
              {navigationItems.map((item) => (
                <li key={item.name}>
                  {item.items ? (
                    <div>
                      <div className="text-base font-medium text-foreground mb-2">
                        {item.name}
                      </div>
                      <ul className="ml-4 space-y-2">
                        {item.items.map((subItem) => (
                          <li key={subItem.name}>
                            <Link
                              to={subItem.to}
                              onClick={() => setMobileMenuOpen(false)}
                              className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-foreground-secondary hover:bg-background-subtle transition-colors"
                            >
                              {subItem.icon && (
                                <div className="text-foreground-secondary flex-shrink-0">
                                  {subItem.icon}
                                </div>
                              )}
                              <div>
                                <div className="font-medium">{subItem.name}</div>
                                {subItem.description && (
                                  <div className="text-xs text-foreground-secondary/70 mt-0.5">
                                    {subItem.description}
                                  </div>
                                )}
                              </div>
                            </Link>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <Link
                      to={item.to || "#"}
                      onClick={() => setMobileMenuOpen(false)}
                      className="block rounded-lg px-3 py-2 text-base font-medium text-foreground hover:bg-background-subtle transition-colors"
                    >
                      {item.name}
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </header>
  );
}
