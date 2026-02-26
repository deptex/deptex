import { useState, useEffect, useRef } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { LogOut, Settings, Search, X } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useUserProfile } from "../hooks/useUserProfile";
import { Button } from "./ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
} from "./ui/dialog";
import { docNavGroups } from "../app/pages/docsConfig";

const HEADER_HEIGHT = "h-14";

const docTabs = [
  { label: "Docs", path: "/docs", slug: null },
  { label: "API", path: "/docs/api", slug: "api" },
  { label: "Learn", path: "/docs/learn", slug: "learn" },
  { label: "Help", path: "/docs/help", slug: "help" },
];

export default function DocsHeader() {
  const { user, signOut } = useAuth();
  const location = useLocation();
  const { avatarUrl } = useUserProfile();
  const navigate = useNavigate();
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const searchInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const filteredItems = searchQuery.trim()
    ? docNavGroups.flatMap((g) =>
        g.items.filter(
          (item) =>
            item.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
            item.slug.toLowerCase().includes(searchQuery.toLowerCase())
        )
      )
    : docNavGroups.flatMap((g) => g.items);

  return (
    <>
      <header
        className={`${HEADER_HEIGHT} fixed left-0 right-0 top-0 z-50 flex items-center justify-between border-b border-border bg-background px-6`}
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

          <nav className="flex items-center gap-1">
            {docTabs.map((tab) => {
              const path = location.pathname;
              const isDocsTab = tab.path === "/docs";
              const isTopLevelSection = ["api", "learn", "help"].includes(path.split("/")[2] || "");
              const isActive = isDocsTab
                ? path === "/docs" || (path.startsWith("/docs/") && !isTopLevelSection)
                : path === tab.path;
              return (
                <Link
                  key={tab.label}
                  to={tab.path}
                  className={`relative flex items-center px-3 py-2 text-sm font-medium transition-colors rounded-md ${
                    isActive
                      ? "text-foreground"
                      : "text-foreground-secondary hover:text-foreground"
                  }`}
                >
                  {tab.label}
                  {isActive && (
                    <span className="absolute left-2 right-2 h-[2px] bg-foreground rounded-full -bottom-[10px]" aria-hidden />
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        <div className="flex items-center gap-4 flex-1 justify-center max-w-xl mx-4">
          <button
            onClick={() => setSearchOpen(true)}
            className="w-full flex items-center gap-3 px-4 py-2 rounded-md bg-background-card border border-border text-foreground-secondary hover:border-foreground-secondary/50 hover:text-foreground transition-colors text-sm min-h-9"
          >
            <Search className="h-4 w-4 shrink-0" />
            <span className="flex-1 text-left">Search docs...</span>
            <kbd className="hidden sm:inline-flex items-center justify-center gap-0.5 h-4 min-w-[1.75rem] px-1.5 rounded bg-white/[0.06] border border-white/10 font-mono font-medium text-foreground-secondary">
              <span className="text-[9.5px] leading-none" aria-hidden>⌘</span>
              <span className="text-[11px] leading-none">K</span>
            </kbd>
          </button>
        </div>

        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" asChild>
            <Link to="/organizations">Dashboard</Link>
          </Button>
          {user ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="flex items-center justify-center rounded-full border border-border bg-background-subtle overflow-hidden hover:bg-background-card transition-colors h-9 w-9">
                  <img
                    src={avatarUrl}
                    alt={user?.email || "User"}
                    className="h-full w-full rounded-full object-cover"
                    onError={(e) => {
                      e.currentTarget.src = "/images/blank_profile_image.png";
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
                        alt={user?.email || "User"}
                        className="h-10 w-10 rounded-full object-cover border border-border"
                        onError={(e) => {
                          e.currentTarget.src = "/images/blank_profile_image.png";
                        }}
                      />
                    </div>
                    <div className="flex flex-col gap-0.5 min-w-0 flex-1">
                      {user.user_metadata?.full_name && (
                        <span className="text-sm font-medium text-foreground truncate">
                          {user.user_metadata.full_name}
                        </span>
                      )}
                      <span className="text-xs text-foreground-secondary truncate">{user.email}</span>
                    </div>
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <Link
                    to="/settings"
                    className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground-secondary transition-colors"
                  >
                    <Settings className="h-4 w-4" />
                    Settings
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={async () => {
                    await signOut();
                    navigate("/");
                  }}
                  className="cursor-pointer text-foreground-secondary hover:text-foreground focus:bg-transparent focus:text-foreground flex items-center gap-2 transition-colors"
                >
                  <LogOut className="h-4 w-4" />
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : (
            <Button asChild size="sm">
              <Link to="/login">Sign in</Link>
            </Button>
          )}
        </div>
      </header>

      <Dialog open={searchOpen} onOpenChange={setSearchOpen}>
        <DialogContent
          hideClose
          className="max-w-xl w-[90vw] p-0 gap-0 bg-background-card border-border overflow-hidden"
        >
          <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
            <Search className="h-4 w-4 text-foreground-secondary shrink-0" />
            <input
              ref={searchInputRef}
              type="text"
              placeholder="Search docs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1 bg-transparent text-sm text-foreground placeholder:text-foreground-secondary border-0 min-h-8 outline-none focus:outline-none focus:ring-0 focus:ring-offset-0 focus-visible:outline-none focus-visible:ring-0 focus-visible:ring-offset-0"
              autoFocus
            />
            <button
              onClick={() => setSearchOpen(false)}
              className="flex items-center justify-center w-8 h-8 rounded-md text-foreground-muted hover:text-foreground hover:bg-white/[0.04] transition-colors shrink-0"
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="max-h-[60vh] overflow-y-auto custom-scrollbar py-3">
            {filteredItems.map((item) => (
              <Link
                key={item.slug}
                to={`/docs/${item.slug}`}
                onClick={() => setSearchOpen(false)}
                className="flex flex-col gap-0.5 px-4 py-2.5 mx-2 rounded-md hover:bg-table-hover transition-colors text-left"
              >
                <span className="text-sm font-medium text-foreground">{item.label}</span>
                {item.description && (
                  <span className="text-xs text-foreground-secondary">{item.description}</span>
                )}
              </Link>
            ))}
            {filteredItems.length === 0 && (
              <p className="px-4 py-4 text-sm text-foreground-secondary">No results found.</p>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

export { HEADER_HEIGHT };
