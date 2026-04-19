import { Link, useNavigate, useLocation } from "react-router-dom";
import { LogOut, Settings } from "lucide-react";
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

const HEADER_HEIGHT = "h-14";

const docTabs = [
  { label: "Docs", path: "/docs", slug: null },
  { label: "Help", path: "/docs/help", slug: "help" },
];

export default function DocsHeader() {
  const { user, signOut } = useAuth();
  const location = useLocation();
  const { avatarUrl } = useUserProfile();
  const navigate = useNavigate();

  return (
    <>
      <header
        className={`${HEADER_HEIGHT} fixed left-0 right-0 top-0 z-50 flex items-center border-b border-border bg-background px-6`}
      >
        {/* Left: logo + nav */}
        <div className="flex items-center gap-6 flex-1 min-w-0">
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
              const isTopLevelSection = ["help"].includes(path.split("/")[2] || "");
              const isActive = isDocsTab
                ? path === "/docs" || (path.startsWith("/docs/") && !isTopLevelSection)
                : path.startsWith(tab.path);
              return (
                <Link
                  key={tab.label}
                  to={tab.path}
                  className={`relative flex items-center px-3 py-2 text-sm font-medium transition-colors rounded-md ${
                    isActive
                      ? "text-foreground"
                      : "text-foreground/80 hover:text-foreground"
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

        {/* Right: sign in / user */}
        <div className="flex items-center gap-3 flex-1 justify-end min-w-0">
          {user && (
            <Button
              asChild
              size="default"
              variant="outline"
              className="font-semibold text-sm px-5 py-2.5 rounded-lg h-9"
            >
              <Link to="/organizations">Dashboard</Link>
            </Button>
          )}
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
                      <span className="text-xs text-foreground/80 truncate">{user.email}</span>
                    </div>
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <Link
                    to="/settings"
                    className="cursor-pointer flex items-center gap-2 focus:bg-transparent hover:text-foreground text-foreground/80 transition-colors"
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
                  className="cursor-pointer text-foreground/80 hover:text-foreground focus:bg-transparent focus:text-foreground flex items-center gap-2 transition-colors"
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
      </header>
    </>
  );
}

export { HEADER_HEIGHT };
