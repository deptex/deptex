import { ChevronDown, ChevronRight, Menu, Package, Braces, Layers, Plug, HelpCircle, Settings, LogOut } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { cn } from "../../lib/utils";
import { Button } from "../ui/button";
import { useAuth } from "../../contexts/AuthContext";
import { getAvatarUrl, getDisplayNameOrNull } from "../../lib/userIdentity";
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
        description: "Chat, tasks & draft-PR fixes",
        icon: (
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" className="h-5 w-5 shrink-0 transition-colors duration-150" aria-hidden>
            <path d="M12 2L4 6v5c0 5 4 8 8 10 4-2 8-5 8-10V6l-8-4z" />
            <path d="M12 9l1 2 2 1-1 2-2 1-1-2-2-1 1-2 2-1z" fill="currentColor" stroke="none" />
          </svg>
        )
      },
      {
        name: "Dependency scanning",
        to: "/platform-features/dependency-scanning",
        description: "Reachability-scored CVEs & malicious packages",
        icon: <Package className="h-5 w-5" />
      },
      {
        name: "Code scanning",
        to: "/platform-features/code-scanning",
        description: "SAST & live-verified secrets",
        icon: <Braces className="h-5 w-5" />
      },
      {
        name: "Infrastructure & DAST",
        to: "/platform-features/infrastructure-dast",
        description: "IaC, containers & runtime testing",
        icon: <Layers className="h-5 w-5" />
      },
    ],
  },
  {
    name: "Resources",
    items: [
      { 
        name: "Open source",
        to: "/open-source",
        description: "The whole platform, open source (AGPL-3.0)",
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

export default function NavBar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const { user, signOut } = useAuth();
  const avatarUrl = getAvatarUrl(user);
  const fullName = getDisplayNameOrNull(user);
  const navigate = useNavigate();
  const [dropdownTimeout, setDropdownTimeout] = useState<ReturnType<typeof setTimeout> | null>(null);

  return (
    <header className="h-14 fixed left-0 right-0 top-0 z-50 flex items-center border-b border-border bg-background px-6">
      <div className="flex-1 min-w-0">
        <nav
          className="flex items-center justify-between w-full"
          aria-label="Global"
        >
          <div className="flex items-center gap-6">
            <Link
              to="/landing"
              className="flex items-center hover:opacity-80 transition-opacity shrink-0"
            >
              <img
                src="/images/logo_with_text.png"
                alt="Deptex"
                className="h-7 object-contain"
              />
            </Link>

            <ul className="ml-4 hidden items-center gap-6 md:flex">
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
                          <div className="rounded-lg border border-border bg-background shadow-lg p-1.5 min-w-[20rem]">
                              {item.items.map((subItem) => (
                                <Link
                                  key={subItem.name}
                                  to={subItem.to}
                                  className="flex items-center gap-3 rounded-md px-2.5 py-2.5 text-sm text-foreground transition-colors duration-150 group/item hover:bg-background-subtle"
                                  onClick={() => setOpenDropdown(null)}
                                >
                                  {subItem.icon && (
                                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-background border border-border text-foreground-secondary group-hover/item:text-foreground transition-colors duration-150">
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

          {/* Right side — the avatar (logged in) or Try for free (logged out)
              stays visible at every width; GitHub + Dashboard + nav collapse into
              the burger below md, so the header is never just an empty burger. */}
          <div className="flex items-center justify-end gap-3">
            <a
              href={GITHUB_REPO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="hidden md:flex items-center rounded-md p-1.5 text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors"
              aria-label="Deptex on GitHub"
            >
              <img src="/images/integrations/github.png" alt="" className="h-5 w-5 rounded-full" aria-hidden />
            </a>

            {user ? (
              <>
                <Button asChild variant="outline" className="hidden md:inline-flex !h-8 !rounded-lg !px-3 text-foreground">
                  <Link to="/organizations">Dashboard</Link>
                </Button>
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
                  <DropdownMenuContent align="end" sideOffset={8} className="w-72 p-1.5 rounded-xl">
                    <DropdownMenuLabel className="p-0">
                      <div className="flex items-center gap-3 px-3 py-2">
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
                          {fullName && (
                            <span className="text-sm font-medium text-foreground truncate">{fullName}</span>
                          )}
                          <span className="text-xs text-foreground-secondary truncate">{user.email}</span>
                        </div>
                      </div>
                    </DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem asChild>
                      <Link to="/settings" className="cursor-pointer h-9 px-3 gap-3 rounded-md font-medium text-foreground-secondary hover:bg-background-subtle/85 focus:bg-background-subtle/85 hover:text-foreground">
                        <Settings className="h-5 w-5" />
                        Settings
                      </Link>
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onClick={async () => {
                        await signOut();
                        navigate('/');
                      }}
                      className="cursor-pointer h-9 px-3 gap-3 rounded-md font-medium text-foreground-secondary hover:bg-background-subtle/85 focus:bg-background-subtle/85 hover:text-foreground"
                    >
                      <LogOut className="h-5 w-5" />
                      Sign out
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </>
            ) : (
              <Button asChild variant="green">
                <Link to="/login">Try for free</Link>
              </Button>
            )}

            {/* Burger — mobile only */}
            <button
              type="button"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden text-foreground-secondary hover:text-foreground inline-flex items-center justify-center rounded-md transition-colors"
            >
              <span className="sr-only">Open main menu</span>
              <Menu className="size-8 p-1" aria-hidden="true" />
            </button>
          </div>
        </nav>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden fixed inset-0 z-40 bg-background-card/95 backdrop-blur-lg">
          <div className="flex flex-col h-full p-6 overflow-y-auto">
            <div className="flex items-center justify-between mb-8">
              <Link to="/landing" className="flex items-center gap-2">
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

            {/* Auth actions — mirror the desktop bar so they're reachable on mobile */}
            <div className="mt-auto border-t border-border pt-6">
              {user ? (
                <div className="space-y-1">
                  <div className="flex items-center gap-3 px-3 py-2">
                    <img
                      src={avatarUrl}
                      alt={user?.email || 'User'}
                      className="h-9 w-9 rounded-full object-cover border border-border flex-shrink-0"
                      onError={(e) => {
                        e.currentTarget.src = '/images/blank_profile_image.png';
                      }}
                    />
                    <div className="flex flex-col min-w-0">
                      {fullName && (
                        <span className="text-sm font-medium text-foreground truncate">{fullName}</span>
                      )}
                      <span className="text-xs text-foreground-secondary truncate">{user.email}</span>
                    </div>
                  </div>
                  <Link
                    to="/organizations"
                    onClick={() => setMobileMenuOpen(false)}
                    className="block rounded-lg px-3 py-2 text-base font-medium text-foreground hover:bg-background-subtle transition-colors"
                  >
                    Dashboard
                  </Link>
                  <Link
                    to="/settings"
                    onClick={() => setMobileMenuOpen(false)}
                    className="block rounded-lg px-3 py-2 text-base font-medium text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors"
                  >
                    Settings
                  </Link>
                  <button
                    type="button"
                    onClick={async () => {
                      setMobileMenuOpen(false);
                      await signOut();
                      navigate('/');
                    }}
                    className="block w-full text-left rounded-lg px-3 py-2 text-base font-medium text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors"
                  >
                    Sign out
                  </button>
                </div>
              ) : (
                <Button asChild variant="green" className="w-full">
                  <Link to="/login" onClick={() => setMobileMenuOpen(false)}>
                    Try for free
                  </Link>
                </Button>
              )}
            </div>
          </div>
        </div>
      )}
    </header>
  );
}
