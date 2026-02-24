import { ChevronDown, Github, Menu, User, Bot, FolderGit2, Eye, Radio, FileCheck, HeartPulse, Zap, HelpCircle, Code, Shield, Users, Settings, LogOut } from "lucide-react";
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
        name: "Autonomous Security Agent", 
        to: "/autonomous-agent", 
        description: "AI-driven security engineer",
        icon: <Bot className="h-5 w-5" />
      },
      { 
        name: "Repository Tracking", 
        to: "/repository-tracking", 
        description: "Deep dependency tracking",
        icon: <FolderGit2 className="h-5 w-5" />
      },
      { 
        name: "Anomaly Detection", 
        to: "/anomaly-detection", 
        description: "Detect suspicious behavior",
        icon: <Eye className="h-5 w-5" />
      },
      { 
        name: "Vulnerability Intelligence", 
        to: "/vulnerability-intelligence", 
        description: "CVE monitoring and analysis",
        icon: <Radio className="h-5 w-5" />
      },
      { 
        name: "SBOM & Compliance", 
        to: "/sbom-compliance", 
        description: "SBOM generation and tracking",
        icon: <FileCheck className="h-5 w-5" />
      },
      { 
        name: "Project Health & Insights", 
        to: "/project-health", 
        description: "Health score and analytics",
        icon: <HeartPulse className="h-5 w-5" />
      },
    ],
  },
  {
    name: "Resources",
    items: [
      { 
        name: "Open Source", 
        to: "/open-source", 
        description: "Explore our repositories",
        icon: <Github className="h-5 w-5" />
      },
      { 
        name: "Integrations", 
        to: "/integrations", 
        description: "Connect with your favorite tools",
        icon: <Zap className="h-5 w-5" />
      },
      { 
        name: "Support", 
        to: "/support", 
        description: "Get help from our team",
        icon: <HelpCircle className="h-5 w-5" />
      },
    ],
  },
  {
    name: "Solutions",
    items: [
      { 
        name: "For Engineering Teams", 
        to: "/solutions/engineering-teams", 
        description: "Keep repositories secure and compliant",
        icon: <Code className="h-5 w-5" />
      },
      { 
        name: "For Security Teams", 
        to: "/solutions/security-teams", 
        description: "Deep visibility into supply chain",
        icon: <Shield className="h-5 w-5" />
      },
      { 
        name: "For Platform & DevOps Teams", 
        to: "/solutions/devops-teams", 
        description: "Safe deployments and consistent environments",
        icon: <Zap className="h-5 w-5" />
      },
      { 
        name: "For Open Source Maintainers", 
        to: "/solutions/open-source-maintainers", 
        description: "Maintain project health and track drift",
        icon: <Github className="h-5 w-5" />
      },
      { 
        name: "For CTOs & Engineering Leadership", 
        to: "/solutions/cto-leadership", 
        description: "Improve security posture organization-wide",
        icon: <Users className="h-5 w-5" />
      },
      { 
        name: "For Startups & Scaleups", 
        to: "/solutions/startups-scaleups", 
        description: "Launch fast with built-in security",
        icon: <Zap className="h-5 w-5" />
      },
    ],
  },
  { name: "Pricing", to: "/pricing" },
  { name: "Docs", to: "/docs" },
];

export default function NavBar() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const { user, signOut } = useAuth();
  const { avatarUrl } = useUserProfile();
  const navigate = useNavigate();
  const [dropdownTimeout, setDropdownTimeout] = useState<number | null>(null);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 0);
    };

    window.addEventListener("scroll", handleScroll);
    return () => {
      window.removeEventListener("scroll", handleScroll);
      if (dropdownTimeout) {
        clearTimeout(dropdownTimeout);
      }
    };
  }, [dropdownTimeout]);

  return (
    <header
      className={cn(
        "fixed left-0 right-0 z-50 transition-all duration-300",
        isScrolled ? "top-5" : "top-0"
      )}
    >
      <div
        className={cn("transition-all duration-300", {
          "bg-background-card/90 border-border mx-4 rounded-full border pr-2 shadow-lg backdrop-blur-lg md:mx-20 lg:pr-0":
            isScrolled,
          "bg-background-card/80 border-border mx-0 border-b backdrop-blur-lg":
            !isScrolled,
        })}
      >
        <nav
          className={cn(
            "flex items-center justify-between transition-all duration-300",
            {
              "p-3 lg:px-6": isScrolled,
              "p-6 lg:px-8": !isScrolled,
            }
          )}
          aria-label="Global"
        >
          <div className="flex items-center gap-6">
            <Link
              to="/"
              className="text-foreground hover:text-primary flex items-center transition-colors duration-300 ease-in-out"
            >
              <img
                className={cn("transition-all duration-500", {
                  "size-8": !isScrolled,
                  "size-7": isScrolled,
                })}
                src="/images/logo.png"
                alt="Deptex"
              />
              <span
                className={cn(
                  "text-foreground font-semibold leading-6 transition-all duration-300 ml-2",
                  {
                    "text-sm": !isScrolled,
                    "text-xs": isScrolled,
                  }
                )}
              >
                Deptex
              </span>
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
                          "text-sm font-normal leading-6 text-foreground-secondary hover:text-primary duration-300 ease-in-out transition-colors flex items-center gap-1",
                          openDropdown === item.name && "text-primary"
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
                          className="absolute top-full left-0 pt-2 w-72 z-50"
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
                          <div className="rounded-lg border border-border/50 bg-background-card/95 backdrop-blur-xl p-1.5 shadow-xl">
                          {item.items.map((subItem) => (
                            <Link
                              key={subItem.name}
                              to={subItem.to}
                              className="flex items-start gap-3 rounded-md px-3 py-2.5 text-sm text-foreground transition-all duration-200 group/item"
                              onClick={() => setOpenDropdown(null)}
                            >
                              {subItem.icon && (
                                <div className="text-foreground-secondary group-hover/item:text-foreground transition-colors duration-200 mt-0.5 flex-shrink-0">
                                  {subItem.icon}
                                </div>
                              )}
                              <div className="flex-1 min-w-0">
                                <div className="font-medium group-hover/item:text-foreground transition-colors duration-200">{subItem.name}</div>
                                {subItem.description && (
                                  <div className="text-xs text-foreground-secondary/70 group-hover/item:text-foreground-secondary mt-0.5 transition-colors duration-200">
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
                      className="text-sm font-normal leading-6 text-foreground-secondary hover:text-primary duration-300 ease-in-out transition-colors"
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
                className={cn("transition-all duration-300", {
                  "size-8 p-1": !isScrolled,
                  "size-6 p-0.5": isScrolled,
                })}
                aria-hidden="true"
              />
            </button>
          </div>

          {/* Desktop Actions */}
          <div className="hidden items-center justify-end gap-4 lg:flex lg:flex-1">
            <a
              href="https://github.com/deptex/deptex"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-foreground-secondary hover:text-foreground transition-colors"
            >
              <Github className="h-5 w-5" />
              <span className="text-sm font-medium">12.5K</span>
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
              <Button asChild>
                <Link to="/login">Sign in</Link>
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
