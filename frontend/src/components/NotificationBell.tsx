import { useState, useEffect, useCallback, useRef } from 'react';
import { Bell, Check, BellOff } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { supabase } from '../lib/supabase';
import { Popover, PopoverTrigger, PopoverContent } from './ui/popover';
import { Tooltip, TooltipTrigger, TooltipContent } from './ui/tooltip';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

interface Notification {
  id: string;
  title: string;
  body?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  deptex_url?: string;
  is_read: boolean;
  created_at: string;
}

interface NotificationBellProps {
  organizationId?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#2563eb',
  info: '#71717a',
};

function formatRelativeTime(dateStr: string): string {
  const diff = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
  return `${Math.floor(diff / 604800)}w ago`;
}

export default function NotificationBell({ organizationId }: NotificationBellProps) {
  const { session, user } = useAuth();
  const navigate = useNavigate();
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchHeaders = useCallback((): HeadersInit | null => {
    if (!session?.access_token) return null;
    return {
      'Authorization': `Bearer ${session.access_token}`,
      'Content-Type': 'application/json',
    };
  }, [session?.access_token]);

  const fetchUnreadCount = useCallback(async () => {
    const headers = fetchHeaders();
    if (!headers) return;
    try {
      const params = organizationId ? `?org_id=${organizationId}` : '';
      const res = await fetch(
        `${API_BASE_URL}/api/user-notifications/unread-count${params}`,
        { headers },
      );
      if (res.ok) {
        const data = await res.json();
        setUnreadCount(data.count ?? 0);
      }
    } catch {
      // Network failure — keep stale count
    }
  }, [fetchHeaders, organizationId]);

  const fetchNotifications = useCallback(async () => {
    const headers = fetchHeaders();
    if (!headers) return;
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: '1', per_page: '20' });
      if (organizationId) params.set('org_id', organizationId);
      const res = await fetch(
        `${API_BASE_URL}/api/user-notifications?${params}`,
        { headers },
      );
      if (res.ok) {
        const data = await res.json();
        setNotifications(data.notifications ?? data ?? []);
      }
    } catch {
      // Network failure — keep stale list
    } finally {
      setLoading(false);
    }
  }, [fetchHeaders, organizationId]);

  const markAsRead = useCallback(async (id: string) => {
    const headers = fetchHeaders();
    if (!headers) return;
    setNotifications(prev => prev.map(n => (n.id === id ? { ...n, is_read: true } : n)));
    setUnreadCount(prev => Math.max(0, prev - 1));
    try {
      await fetch(`${API_BASE_URL}/api/user-notifications/${id}/read`, {
        method: 'PATCH',
        headers,
      });
    } catch {
      // Optimistic update already applied
    }
  }, [fetchHeaders]);

  const markAllAsRead = useCallback(async () => {
    const headers = fetchHeaders();
    if (!headers) return;
    setNotifications(prev => prev.map(n => ({ ...n, is_read: true })));
    setUnreadCount(0);
    try {
      await fetch(`${API_BASE_URL}/api/user-notifications/mark-all-read`, {
        method: 'POST',
        headers,
      });
    } catch {
      // Optimistic update already applied
    }
  }, [fetchHeaders]);

  // Poll unread count every 30s
  useEffect(() => {
    fetchUnreadCount();
    pollRef.current = setInterval(fetchUnreadCount, 30_000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [fetchUnreadCount]);

  // Fetch full list when popover opens
  useEffect(() => {
    if (open) fetchNotifications();
  }, [open, fetchNotifications]);

  // Supabase Realtime: live inserts into user_notifications
  useEffect(() => {
    if (!user?.id) return;

    const channel = supabase
      .channel('user-notifications')
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'user_notifications',
          filter: `user_id=eq.${user.id}`,
        },
        (payload) => {
          const incoming = payload.new as Notification;
          setNotifications(prev => [incoming, ...prev]);
          setUnreadCount(prev => prev + 1);
        },
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [user?.id]);

  const handleNotificationClick = (notification: Notification) => {
    if (!notification.is_read) markAsRead(notification.id);
    if (notification.deptex_url) {
      setOpen(false);
      navigate(notification.deptex_url);
    }
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <Tooltip>
        <TooltipTrigger asChild>
          <PopoverTrigger asChild>
            <button className="relative flex items-center justify-center rounded-md p-2 text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors">
              <Bell className="h-5 w-5" />
              {unreadCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-red-600 px-1 text-[10px] font-medium text-white leading-none">
                  {unreadCount > 99 ? '99+' : unreadCount}
                </span>
              )}
            </button>
          </PopoverTrigger>
        </TooltipTrigger>
        <TooltipContent side="bottom">Notifications</TooltipContent>
      </Tooltip>

      <PopoverContent align="end" className="w-[340px] p-0">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <span className="text-sm font-medium text-foreground">Notifications</span>
          {unreadCount > 0 && (
            <button
              onClick={markAllAsRead}
              className="flex items-center gap-1 text-xs text-foreground-secondary hover:text-foreground transition-colors"
            >
              <Check className="h-3 w-3" />
              Mark all as read
            </button>
          )}
        </div>

        <div className="max-h-[400px] overflow-y-auto">
          {loading && notifications.length === 0 ? (
            <div className="flex items-center justify-center py-10">
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-foreground-secondary border-t-transparent" />
            </div>
          ) : notifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 gap-2">
              <BellOff className="h-8 w-8 text-foreground-secondary/50" />
              <span className="text-sm text-foreground-secondary">No new notifications</span>
            </div>
          ) : (
            notifications.map(notification => (
              <button
                key={notification.id}
                onClick={() => handleNotificationClick(notification)}
                className={`w-full flex items-start gap-3 px-4 py-3 text-left border-b border-border last:border-b-0 transition-colors ${
                  notification.is_read
                    ? 'opacity-50 hover:opacity-70'
                    : 'hover:bg-background-subtle'
                }`}
              >
                <span
                  className="mt-1.5 h-2 w-2 flex-shrink-0 rounded-full"
                  style={{ backgroundColor: SEVERITY_COLORS[notification.severity] ?? SEVERITY_COLORS.info }}
                />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-foreground truncate">{notification.title}</p>
                  <p className="text-xs text-foreground-secondary mt-0.5">
                    {formatRelativeTime(notification.created_at)}
                  </p>
                </div>
                {notification.deptex_url && (
                  <span className="text-xs text-primary flex-shrink-0 mt-0.5">View</span>
                )}
              </button>
            ))
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}
