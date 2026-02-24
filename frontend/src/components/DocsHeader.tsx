import { Link, useNavigate } from "react-router-dom";
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

export default function DocsHeader() {
  const { user, signOut } = useAuth();
  const { avatarUrl } = useUserProfile();
  const navigate = useNavigate();

  return (
    <header
      className={`${HEADER_HEIGHT} fixed left-0 right-0 top-0 z-50 flex items-center justify-between border-b border-border bg-background-card px-6`}
    >
      <div className="flex items-center gap-3">
        <Link
          to="/"
          className="text-foreground hover:text-primary flex items-center gap-2 transition-colors"
        >
          <img src="/images/logo.png" alt="Deptex" className="size-7" />
          <span className="text-sm font-semibold">Deptex</span>
        </Link>
        <span className="text-foreground-muted text-sm">Docs</span>
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
  );
}

export { HEADER_HEIGHT };
