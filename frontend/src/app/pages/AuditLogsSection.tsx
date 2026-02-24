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

            <div className="flex items-center justify-between gap-4">
                {/* Date Filter - Remains on Left */}
                <div className="flex items-center gap-1">
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="outline" className="flex items-center gap-2 h-9 px-3 text-sm font-medium">
                                <Clock className="h-4 w-4 text-foreground-secondary" />
                                <span>{getDateFilterDisplay()}</span>
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="start" className="w-56">
                            <DropdownMenuLabel>Date Range</DropdownMenuLabel>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem onClick={() => { setDatePreset('all_time'); setDateOffset(0); }}>
                                All Time
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => { setDatePreset('last_day'); setDateOffset(0); }}>
                                Last 24 Hours
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => { setDatePreset('last_week'); setDateOffset(0); }}>
                                Last 7 Days
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => { setDatePreset('last_month'); setDateOffset(0); }}>
                                Last 30 Days
                            </DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>

                    {datePreset !== 'all_time' && (
                        <div className="flex items-center -space-x-px">
                            <Button
                                variant="outline"
                                size="icon"
                                className="h-9 w-9 rounded-r-none border-r-0"
                                onClick={handlePrevious}
                            >
                                <ChevronLeft className="h-4 w-4" />
                            </Button>
                            <Button
                                variant="outline"
                                size="icon"
                                className="h-9 w-9 rounded-l-none"
                                onClick={handleNext}
                                disabled={dateOffset >= 0}
                            >
                                <ChevronRight className="h-4 w-4" />
                            </Button>
                        </div>
                    )}
                </div>

                {/* Other Filters - Moved to Right */}
                <div className="flex items-center gap-3">
                    {/* Team Filter */}
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="outline" className="flex items-center gap-2 h-9 px-3 text-sm font-medium text-foreground-secondary hover:text-foreground">
                                <Users className="h-4 w-4" />
                                <span>{getTeamLabel()}</span>
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-56">
                            <DropdownMenuLabel>Filter by Team</DropdownMenuLabel>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem onClick={() => setSelectedTeamId(null)}>
                                All Teams
                            </DropdownMenuItem>
                            {teams.map(team => (
                                <DropdownMenuItem key={team.id} onClick={() => setSelectedTeamId(team.id)}>
                                    <div className="flex items-center justify-between w-full">
                                        <span>{team.name}</span>
                                        {selectedTeamId === team.id && <ChevronDown className="h-3 w-3 rotate-[-90deg]" />}
                                    </div>
                                </DropdownMenuItem>
                            ))}
                            {teams.length === 0 && (
                                <div className="p-2 text-xs text-foreground-secondary text-center">
                                    No teams found
                                </div>
                            )}
                        </DropdownMenuContent>
                    </DropdownMenu>

                    {/* Events Filter */}
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="outline" className="flex items-center gap-2 h-9 px-3 text-sm font-medium">
                                <Filter className="h-4 w-4" />
                                <span>Events</span>
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-64 max-h-[400px] overflow-y-auto">
                            {filterCategories.map((category, idx) => (
                                <div key={idx}>
                                    <DropdownMenuLabel className="text-xs text-foreground-secondary uppercase tracking-wider mt-2">{category.title}</DropdownMenuLabel>
                                    {category.items.map(item => (
                                        <DropdownMenuCheckboxItem
                                            key={item.value}
                                            checked={selectedTypes.includes(item.value)}
                                            onCheckedChange={() => handleTypeToggle(item.value)}
                                        >
                                            {item.label}
                                        </DropdownMenuCheckboxItem>
                                    ))}
                                    {idx < filterCategories.length - 1 && <DropdownMenuSeparator className="mt-2" />}
                                </div>
                            ))}
                            {selectedTypes.length > 0 && (
                                <>
                                    <DropdownMenuSeparator />
                                    <DropdownMenuItem
                                        className="justify-center text-primary font-medium"
                                        onClick={() => setSelectedTypes([])}
                                    >
                                        Clear Filters
                                    </DropdownMenuItem>
                                </>
                            )}
                        </DropdownMenuContent>
                    </DropdownMenu>
                </div>
            </div>

            {loading ? (
                <div className="space-y-4">
                    {/* Loading skeleton for month header using same structure as ActivityPage */}
                    <div>
                        <div className="h-5 w-32 bg-muted rounded animate-pulse mb-4" />
                        <div className="space-y-4">
                            {[...Array(5)].map((_, i) => (
                                <div key={i} className="flex items-start gap-4 p-4 bg-background-card border border-border rounded-lg">
                                    <div className="w-8 h-8 rounded-full bg-muted animate-pulse flex-shrink-0" />
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-start justify-between gap-4">
                                            <div className="flex-1 min-w-0 space-y-2">
                                                <div className="h-4 bg-muted rounded animate-pulse w-3/4" />
                                                <div className="h-3 bg-muted rounded animate-pulse w-1/2" />
                                            </div>
                                            <div className="h-3 bg-muted rounded animate-pulse w-16" />
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            ) : activities.length === 0 ? (
                <div className="flex items-center justify-center py-12">
                    <div className="text-center">
                        <p className="text-foreground-secondary mb-2">No activities found</p>
                        <p className="text-sm text-foreground-secondary/70">
                            Try adjusting your filters to see more results
                        </p>
                    </div>
                </div>
            ) : (
                <div className="space-y-8 pb-8">
                    {groupedActivities.map(({ month, activities: monthActivities }) => (
                        <div key={month}>
                            <h3 className="text-sm font-semibold text-foreground mb-4">{month}</h3>
                            <div className="space-y-4">
                                {monthActivities.map(activity => {
                                    const hasDisplayableMetadata = activity.metadata && (
                                        (activity.metadata.project_name && activity.activity_type !== 'project_created') ||
                                        (activity.metadata.team_name && activity.activity_type !== 'member_joined_team' && activity.activity_type !== 'team_created') ||
                                        (activity.metadata.role_name && activity.activity_type !== 'created_role' && activity.activity_type !== 'changed_role_settings' && activity.activity_type !== 'deleted_role') ||
                                        (activity.activity_type === 'changed_role_settings' && (activity.metadata.name_changed || activity.metadata.permissions_changed)) ||
                                        (activity.metadata.added_licenses && activity.metadata.added_licenses.length > 0) ||
                                        (activity.metadata.removed_licenses && activity.metadata.removed_licenses.length > 0) ||
                                        activity.metadata.slsa_enforcement_changed ||
                                        activity.metadata.slsa_level_changed
                                    );
                                    return (
                                        <div
                                            key={activity.id}
                                            className={`flex gap-3 p-4 bg-background-card border border-border rounded-lg hover:bg-background-card/50 transition-colors ${hasDisplayableMetadata ? 'items-start' : 'items-center'}`}
                                        >
                                            <div className="flex-shrink-0">
                                                {activity.user?.avatar_url ? (
                                                    <img
                                                        src={activity.user.avatar_url}
                                                        alt={activity.user.full_name || activity.user.email || 'User'}
                                                        className="w-8 h-8 rounded-full object-cover border border-border"
                                                        onError={(e) => {
                                                            e.currentTarget.src = '/images/blank_profile_image.png';
                                                        }}
                                                    />
                                                ) : (
                                                    <div className="w-8 h-8 rounded-full bg-background-subtle border border-border flex items-center justify-center">
                                                        <span className="text-xs text-foreground-secondary">
                                                            {(activity.user?.full_name || activity.user?.email || '?')[0].toUpperCase()}
                                                        </span>
                                                    </div>
                                                )}
                                            </div>

                                            <div className={`flex-1 min-w-0 flex justify-between gap-4 ${hasDisplayableMetadata ? 'items-start' : 'items-center'}`}>
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-sm text-foreground leading-5">
                                                        {activity.user ? (
                                                            <>
                                                                <span className="font-medium text-foreground">{activity.user.full_name || activity.user.email}</span>
                                                                {' '}
                                                                <span className="text-foreground-secondary">{activity.description}</span>
                                                            </>
                                                        ) : (
                                                            <span className="text-foreground-secondary">{activity.description}</span>
                                                        )}
                                                    </p>

                                                    {hasDisplayableMetadata && (
                                                        <div className="mt-1.5 text-xs text-foreground-secondary/70 space-y-0.5">
                                                            {activity.metadata!.project_name && activity.activity_type !== 'project_created' && (
                                                                <div>Project: <span className="text-foreground-secondary">{activity.metadata!.project_name}</span></div>
                                                            )}
                                                            {activity.metadata!.team_name && activity.activity_type !== 'member_joined_team' && activity.activity_type !== 'team_created' && (
                                                                <div>Team: <span className="text-foreground-secondary">{activity.metadata!.team_name}</span></div>
                                                            )}
                                                            {activity.activity_type === 'changed_role_settings' && activity.metadata!.name_changed && (
                                                                <div className="text-foreground-secondary">
                                                                    Changed name from <span className="text-foreground-secondary">{activity.metadata!.old_name}</span> to <span className="text-foreground-secondary">{activity.metadata!.new_name}</span>
                                                                </div>
                                                            )}
                                                            {activity.activity_type === 'changed_role_settings' && activity.metadata!.permissions_changed && (
                                                                <>
                                                                    {activity.metadata!.added_permissions && activity.metadata!.added_permissions.length > 0 && (
                                                                        <div className="text-foreground-secondary">
                                                                            Added permissions: {activity.metadata!.added_permissions.map((p: string) => formatPermissionName(p)).join(', ')}
                                                                        </div>
                                                                    )}
                                                                    {activity.metadata!.removed_permissions && activity.metadata!.removed_permissions.length > 0 && (
                                                                        <div className="text-foreground-secondary">
                                                                            Removed permissions: {activity.metadata!.removed_permissions.map((p: string) => formatPermissionName(p)).join(', ')}
                                                                        </div>
                                                                    )}
                                                                </>
                                                            )}
                                                            {activity.metadata!.role_name && activity.activity_type !== 'created_role' && activity.activity_type !== 'changed_role_settings' && activity.activity_type !== 'deleted_role' && (
                                                                <div>Role: <span className="text-foreground-secondary">{activity.metadata!.role_name}</span></div>
                                                            )}
                                                        </div>
                                                    )}
                                                </div>

                                                <span className="text-xs text-foreground-secondary whitespace-nowrap self-start mt-1">
                                                    {formatDate(activity.created_at)}
                                                </span>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    ))}

                    {/* Infinite Scroll Sensor */}
                    <div ref={observerTarget} className="flex justify-center py-4">
                        {loadingMore && (
                            <Loader2 className="h-6 w-6 animate-spin text-foreground-secondary" />
                        )}
                        {!hasMore && activities.length > 0 && (
                            <span className="text-xs text-foreground-secondary">No more activities to load</span>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
