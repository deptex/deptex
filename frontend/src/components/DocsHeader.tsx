import { Link, useNavigate } from "react-router-dom";
import { LogOut, Settings } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { getAvatarUrl, getDisplayNameOrNull } from "../lib/userIdentity";
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

export default function DocsHeader() {
  const { user, signOut } = useAuth();
  const avatarUrl = getAvatarUrl(user);
  const fullName = getDisplayNameOrNull(user);
  const navigate = useNavigate();

  return (
    <>
      <header
        className={`${HEADER_HEIGHT} fixed left-0 right-0 top-0 z-50 flex items-center justify-between border-b border-border bg-background px-6`}
      >
        {/* Left: logo + Docs wordmark */}
        <div className="flex items-center gap-3 min-w-0">
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
          <span className="text-sm font-medium text-foreground border-l border-border pl-3">
            Docs
          </span>
        </div>

        {/* Right: sign in / user — matches the landing NavBar */}
        <div className="flex items-center gap-3 min-w-0">
          {user && (
            <Button asChild variant="outline" className="!h-8 !rounded-lg !px-3 text-foreground">
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
              <DropdownMenuContent align="end" sideOffset={8} className="w-72 p-1.5 rounded-xl">
                <DropdownMenuLabel className="p-0">
                  <div className="flex items-center gap-3 px-3 py-2">
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
                      {fullName && (
                        <span className="text-sm font-medium text-foreground truncate">
                          {fullName}
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
                    className="cursor-pointer h-9 px-3 gap-3 rounded-md font-medium text-foreground-secondary hover:bg-background-subtle/85 focus:bg-background-subtle/85 hover:text-foreground"
                  >
                    <Settings className="h-5 w-5" />
                    Settings
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={async () => {
                    await signOut();
                    navigate("/");
                  }}
                  className="cursor-pointer h-9 px-3 gap-3 rounded-md font-medium text-foreground-secondary hover:bg-background-subtle/85 focus:bg-background-subtle/85 hover:text-foreground"
                >
                  <LogOut className="h-5 w-5" />
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : (
            <Button asChild variant="green">
              <Link to="/login">Try for free</Link>
            </Button>
          )}
        </div>
      </header>
    </>
  );
}

export { HEADER_HEIGHT };
