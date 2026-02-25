import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { useParams, useOutletContext } from 'react-router-dom';
import { Calendar, Clock, ChevronDown, ChevronRight, ChevronLeft, Filter, Search, Users, Loader2 } from 'lucide-react';
import { api, Activity, Organization, Team } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
    DropdownMenuCheckboxItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuRadioGroup,
    DropdownMenuRadioItem,
} from '../../components/ui/dropdown-menu';
import { Button } from '../../components/ui/button';
import { useAuth } from '../../contexts/AuthContext';
import { RolePermissions } from '../../lib/api';

interface OrganizationContextType {
    organization: Organization | null;
    reloadOrganization: () => Promise<void>;
}

// Activity type definitions (Categorized in the UI)
type DatePreset = 'all_time' | 'last_day' | 'last_week' | 'last_month' | 'custom';

// Format permission name for display (e.g., "view_settings" -> "View Settings")
const formatPermissionName = (permission: string): string => {
    return permission
        .replace(/_/g, ' ')
        .replace(/\b\w/g, (l: string) => l.toUpperCase());
};

// Format date for display
const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;

    // Format as "Nov 30", "Nov 29", etc.
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
};

// Format date for month header
const formatMonthHeader = (dateString: string): string => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
};

// Get date range for preset with offset
const getDateRangeForPreset = (preset: DatePreset, offset: number = 0): { start_date?: string; end_date?: string } => {
    const now = new Date();
    const endDate = new Date(now);
    const startDate = new Date(now);

    switch (preset) {
        case 'last_day':
            // Move end date back by offset days
            endDate.setDate(endDate.getDate() + offset);
            endDate.setHours(23, 59, 59, 999);

            // Start date is 1 day before end date
            startDate.setDate(endDate.getDate() - 1);
            startDate.setHours(0, 0, 0, 0);

            return {
                start_date: startDate.toISOString(),
                end_date: endDate.toISOString()
            };

        case 'last_week':
            // Move end date back by (offset * 7) days
            endDate.setDate(endDate.getDate() + (offset * 7));
            endDate.setHours(23, 59, 59, 999);

            // Start date is 7 days before end date
            startDate.setDate(endDate.getDate() - 7);
            startDate.setHours(0, 0, 0, 0);

            return {
                start_date: startDate.toISOString(),
                end_date: endDate.toISOString()
            };

        case 'last_month':
            // Move end date back by offset months
            endDate.setMonth(endDate.getMonth() + offset);
            endDate.setHours(23, 59, 59, 999);

            // Start date is 1 month before end date
            startDate.setMonth(endDate.getMonth() - 1);
            startDate.setHours(0, 0, 0, 0);

            return {
                start_date: startDate.toISOString(),
                end_date: endDate.toISOString()
            };

        case 'custom':
        case 'all_time':
        default:
            return {};
    }
};

const ITEMS_PER_PAGE = 30;

export default function AuditLogsSection() {
    const { id } = useParams<{ id: string }>();
    const { user } = useAuth();
    const { organization } = useOutletContext<OrganizationContextType>();

    // We can use context if available, but organizationId is most important
    const [activities, setActivities] = useState<Activity[]>([]);
    const [teams, setTeams] = useState<Team[]>([]);
    const [loading, setLoading] = useState(true);
    const [loadingMore, setLoadingMore] = useState(false);
    const [datePreset, setDatePreset] = useState<DatePreset>('all_time');
    const [dateOffset, setDateOffset] = useState(0);
    const [customStartDate, setCustomStartDate] = useState<string>('');
    const [customEndDate, setCustomEndDate] = useState<string>('');
    const [selectedTypes, setSelectedTypes] = useState<string[]>([]);
    const [selectedTeamId, setSelectedTeamId] = useState<string | null>(null);
    const [searchQuery, setSearchQuery] = useState('');

    // Pagination state
    const [page, setPage] = useState(0);
    const [hasMore, setHasMore] = useState(true);
    const observerTarget = useRef<HTMLDivElement>(null);

    const { toast } = useToast();

    useEffect(() => {
        if (id && user && organization) {
            loadTeams();
        }
    }, [id, user, organization]);

    // Get cached permissions
    const getCachedPermissions = (): RolePermissions | null => {
        if (organization?.permissions) return organization.permissions;
        if (id) {
            const cachedStr = localStorage.getItem(`org_permissions_${id}`);
            if (cachedStr) {
                try { return JSON.parse(cachedStr); } catch { return null; }
            }
        }
        return null;
    };

    const loadTeams = async () => {
        if (!id || !user || !organization) return;
        try {
            // Get user permissions from cache or organization
            const permissions = getCachedPermissions();

            // Fetch all teams
            const allTeams = await api.getTeams(id);

            if (permissions?.manage_teams_and_projects) {
                // If user can view all teams, show all
                setTeams(allTeams);
            } else {
                // Otherwise, fetch user's membership details to find their teams
                const members = await api.getOrganizationMembers(id);
                const me = members.find(m => m.user_id === user.id);
                const myTeamIds = me?.teams?.map(t => t.id) || [];

                // Filter teams to only those the user is a member of
                const myTeams = allTeams.filter(team => myTeamIds.includes(team.id));
                setTeams(myTeams);
            }
        } catch (error) {
            console.error('Failed to load teams:', error);
        }
    };

    // Reset pagination when filters change
    useEffect(() => {
        setPage(0);
        setHasMore(true);
        // We don't clear activities immediately to avoid flash, loadActivities will handle replacement
    }, [id, datePreset, dateOffset, customStartDate, customEndDate, selectedTypes, selectedTeamId]);

    // Load activities when page or filters change
    useEffect(() => {
        if (id) {
            loadActivities(page);
        }
    }, [id, datePreset, dateOffset, customStartDate, customEndDate, selectedTypes, selectedTeamId, page]);

    const loadActivities = async (currentPage: number) => {
        if (!id) return;

        try {
            if (currentPage === 0) {
                setLoading(true);
            } else {
                setLoadingMore(true);
            }

            let filters: { start_date?: string; end_date?: string; activity_type?: string[]; team_id?: string; limit: number; offset: number } = {
                limit: ITEMS_PER_PAGE,
                offset: currentPage * ITEMS_PER_PAGE
            };

            if (datePreset === 'custom') {
                if (customStartDate) {
                    const start = new Date(customStartDate);
                    start.setHours(0, 0, 0, 0);
                    filters.start_date = start.toISOString();
                }
                if (customEndDate) {
                    const end = new Date(customEndDate);
                    end.setHours(23, 59, 59, 999);
                    filters.end_date = end.toISOString();
                }
            } else {
                const dateRange = getDateRangeForPreset(datePreset, dateOffset);
                filters = { ...filters, ...dateRange };
            }

            if (selectedTypes.length > 0) {
                filters.activity_type = selectedTypes;
            }

            if (selectedTeamId) {
                filters.team_id = selectedTeamId;
            }

            const data = await api.getActivities(id, filters);

            if (data.length < ITEMS_PER_PAGE) {
                setHasMore(false);
            }

            if (currentPage === 0) {
                setActivities(data);
            } else {
                setActivities(prev => [...prev, ...data]);
            }

        } catch (error: any) {
            console.error('Failed to load activities:', error);
            toast({
                title: 'Error',
                description: error.message || 'Failed to load activities',
            });
        } finally {
            setLoading(false);
            setLoadingMore(false);
        }
    };

    // Infinite scroll observer
    useEffect(() => {
        const observer = new IntersectionObserver(
            entries => {
                if (entries[0].isIntersecting && hasMore && !loading && !loadingMore) {
                    setPage(prev => prev + 1);
                }
            },
            { threshold: 0.5 }
        );

        if (observerTarget.current) {
            observer.observe(observerTarget.current);
        }

        return () => {
            if (observerTarget.current) {
                observer.unobserve(observerTarget.current);
            }
        };
    }, [hasMore, loading, loadingMore]);

    // Group activities by month
    const groupedActivities = useMemo(() => {
        const groups: Record<string, Activity[]> = {};

        activities.forEach(activity => {
            // Filter by search query if present
            if (searchQuery) {
                const query = searchQuery.toLowerCase();
                const matches =
                    activity.description.toLowerCase().includes(query) ||
                    activity.user?.full_name?.toLowerCase().includes(query) ||
                    activity.user?.email.toLowerCase().includes(query) ||
                    false;

                if (!matches) return;
            }

            const date = new Date(activity.created_at);
            const monthKey = `${date.getFullYear()}-${date.getMonth()}`;

            if (!groups[monthKey]) {
                groups[monthKey] = [];
            }
            groups[monthKey].push(activity);
        });

        // Sort groups by date (newest first)
        const sortedGroups = Object.entries(groups).sort(([a], [b]) => {
            return b.localeCompare(a);
        });

        return sortedGroups.map(([monthKey, items]) => ({
            month: formatMonthHeader(items[0].created_at),
            activities: items,
        }));
    }, [activities, searchQuery]);

    const handleTypeToggle = (type: string) => {
        setSelectedTypes(prev =>
            prev.includes(type)
                ? prev.filter(t => t !== type)
                : [...prev, type]
        );
    };

    const getDateFilterDisplay = () => {
        if (datePreset === 'custom') {
            if (customStartDate && customEndDate) {
                const start = new Date(customStartDate);
                const end = new Date(customEndDate);
                return `${start.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} - ${end.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`;
            }
            if (customStartDate) {
                return 'Select end date';
            }
            return 'Select date range';
        }

        if (datePreset === 'all_time') return 'All time';

        const { start_date, end_date } = getDateRangeForPreset(datePreset, dateOffset);
        if (!start_date || !end_date) return '';

        const start = new Date(start_date);
        const end = new Date(end_date);

        // If showing "Last Day" (1 day range)
        if (datePreset === 'last_day') {
            const today = new Date();
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);

            // Reset hours for comparison
            today.setHours(0, 0, 0, 0);
            yesterday.setHours(0, 0, 0, 0);
            const checkDate = new Date(start);
            checkDate.setHours(0, 0, 0, 0);

            if (checkDate.getTime() === yesterday.getTime()) return 'Last 24 Hours';
            if (checkDate.getTime() === today.getTime()) return 'Today';

            return `${start.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} - ${end.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`;
        }

        return `${start.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} - ${end.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`;
    };

    const handlePrevious = (e: React.MouseEvent) => {
        e.stopPropagation();
        setDateOffset(prev => prev - 1);
    };

    const handleNext = (e: React.MouseEvent) => {
        e.stopPropagation();
        if (dateOffset < 0) {
            setDateOffset(prev => prev + 1);
        }
    };

    const getTeamLabel = () => {
        if (!selectedTeamId) return 'Filter by team...';
        const team = teams.find(t => t.id === selectedTeamId);
        return team ? team.name : 'Unknown Team';
    };

    const filterCategories = [
        {
            title: 'Organization', items: [
                { value: 'created_org', label: 'Created Org' },
                { value: 'updated_org_name', label: 'Updated Org Name' },
                { value: 'changed_org_profile_image', label: 'Changed Org Profile Image' },
                { value: 'transferred_ownership', label: 'Transferred Ownership' },
                { value: 'updated_policy', label: 'Updated Policy' },
                { value: 'left_org', label: 'Left Org' },
            ]
        },
        {
            title: 'Members', items: [
                { value: 'invited_member', label: 'Invited Member' },
                { value: 'cancelled_invite', label: 'Cancelled Invite' },
                { value: 'new_member_joined', label: 'New Member Joined' },
                { value: 'removed_member', label: 'Removed Member' },
                { value: 'changed_member_role', label: 'Changed Member Role' },
            ]
        },
        {
            title: 'Roles', items: [
                { value: 'created_role', label: 'Created Role' },
                { value: 'changed_role_settings', label: 'Changed Role Settings' },
                { value: 'changed_role_rank', label: 'Changed Role Rank' },
                { value: 'deleted_role', label: 'Deleted Role' },
            ]
        },
        {
            title: 'Teams', items: [
                { value: 'team_created', label: 'Created Team' },
                { value: 'updated_team_name', label: 'Updated Team Name' },
                { value: 'updated_team_description', label: 'Updated Team Description' },
                { value: 'changed_team_avatar', label: 'Changed Team Avatar' },
                { value: 'deleted_team', label: 'Deleted Team' },
                { value: 'added_member_to_team', label: 'Added Member to Team' },
                { value: 'removed_member_from_team', label: 'Removed Member from Team' },
                { value: 'left_team', label: 'Left Team' },
                { value: 'changed_team_member_role', label: 'Changed Team Member Role' },
                { value: 'created_team_role', label: 'Created Team Role' },
                { value: 'updated_team_role', label: 'Updated Team Role' },
                { value: 'deleted_team_role', label: 'Deleted Team Role' },
                { value: 'changed_team_role_rank', label: 'Changed Team Role Rank' },
            ]
        },
        {
            title: 'Projects', items: [
                { value: 'project_created', label: 'Created Project' },
                { value: 'updated_project_name', label: 'Updated Project Name' },
                { value: 'changed_project_profile_image', label: 'Changed Project Profile Image' },
            ]
        },
    ];

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold text-foreground">Audit Logs</h2>
            </div>

            {/* Original audit logs UI — commented out (free plan restriction)
            <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-1">
                    <DropdownMenu>...</DropdownMenu>
                    {datePreset !== 'all_time' && (...)}
                </div>
                <div className="flex items-center gap-3">
                    <DropdownMenu>... Team Filter ...</DropdownMenu>
                    <DropdownMenu>... Events Filter ...</DropdownMenu>
                </div>
            </div>
            {loading ? (skeleton) : activities.length === 0 ? (empty) : (activity list + infinite scroll)}
            */}

            <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <div className="px-5 py-3.5 rounded-t-lg bg-background-card-header border-b border-border">
                    <span className="text-sm font-semibold text-foreground">Audit Logs</span>
                </div>
                <div className="p-6">
                    <p className="text-sm text-foreground-secondary">Audit logs not available on free plan.</p>
                </div>
            </div>
        </div>
    );
}
