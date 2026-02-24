import { useState, useEffect, useMemo } from 'react';
import { useParams, useOutletContext } from 'react-router-dom';
import { Calendar, Clock, ChevronDown, ChevronRight, Filter } from 'lucide-react';
import { api, Activity, Organization } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuCheckboxItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from '../../components/ui/dropdown-menu';
import { ChevronLeft, ChevronRight as ChevronRightIcon } from 'lucide-react';


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

// Get activity icon color based on type
const getActivityIconColor = (activityType: string): string => {
  if (activityType.includes('created') || activityType.includes('joined')) {
    return 'bg-gradient-to-br from-green-500 to-yellow-500';
  }
  if (activityType.includes('updated') || activityType.includes('changed')) {
    return 'bg-purple-500';
  }
  if (activityType.includes('removed') || activityType.includes('left') || activityType.includes('cancelled')) {
    return 'bg-red-500';
  }
  return 'bg-blue-500';
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

const FilterSection = ({
  title,
  items,
  selectedValues,
  onToggle
}: {
  title: string;
  items: { value: string; label: string }[];
  selectedValues: string[];
  onToggle: (value: string) => void;
}) => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="pb-1">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center w-full py-2 text-sm font-medium text-foreground-secondary hover:text-foreground transition-colors group"
      >
        <ChevronRight className={`h-4 w-4 mr-2 transition-transform duration-200 ${isOpen ? 'rotate-90 text-foreground' : 'text-foreground-secondary group-hover:text-foreground'}`} />
        <span className={isOpen ? 'text-foreground' : ''}>{title}</span>
      </button>

      {isOpen && (
        <div className="mt-0.5 space-y-0.5 pl-6">
          {items.map((type) => (
            <label
              key={type.value}
              className="flex items-center gap-2 py-1.5 text-sm text-foreground-secondary hover:text-foreground cursor-pointer transition-colors"
            >
              <input
                type="checkbox"
                checked={selectedValues.includes(type.value)}
                onChange={() => onToggle(type.value)}
                className="rounded border-border text-primary focus:ring-primary h-3.5 w-3.5"
              />
              <span>{type.label}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
};

export default function ActivityPage() {
  const { id } = useParams<{ id: string }>();
  const { organization } = useOutletContext<OrganizationContextType>();
  const [activities, setActivities] = useState<Activity[]>([]);
  const [loading, setLoading] = useState(true);
  const [datePreset, setDatePreset] = useState<DatePreset>('all_time');
  const [dateOffset, setDateOffset] = useState(0);
  const [customStartDate, setCustomStartDate] = useState<string>('');
  const [customEndDate, setCustomEndDate] = useState<string>('');
  const [selectedTypes, setSelectedTypes] = useState<string[]>([]);
  const { toast } = useToast();

  // Load activities when filters change
  useEffect(() => {
    if (id) {
      loadActivities();
    }
  }, [id, datePreset, dateOffset, customStartDate, customEndDate, selectedTypes]);

  const loadActivities = async () => {
    if (!id) return;

    try {
      setLoading(true);

      let filters: { start_date?: string; end_date?: string; activity_type?: string[] } = {};

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

      const data = await api.getActivities(id, filters);
      setActivities(data);
    } catch (error: any) {
      console.error('Failed to load activities:', error);
      toast({
        title: 'Error',
        description: error.message || 'Failed to load activities',
      });
    } finally {
      setLoading(false);
    }
  };

  // Group activities by month
  const groupedActivities = useMemo(() => {
    const groups: Record<string, Activity[]> = {};

    activities.forEach(activity => {
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
  }, [activities]);

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

    if (datePreset === 'all_time') return 'All Time';

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

  return (
    <div className="min-h-screen bg-background">
      <div className="mx-auto w-full max-w-7xl px-6 py-8">
        <div className="flex gap-8">
          {/* Filters Sidebar */}
          <div className="w-64 flex-shrink-0">
            <div className="sticky top-8">
              <h2 className="text-sm font-semibold text-foreground mb-4">Filters</h2>

              {/* Date Filter */}
              <div className="mb-6 flex gap-1 w-full">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <button className="flex-1 flex items-center justify-between px-3 py-2 text-sm bg-background-card border border-border rounded-md hover:bg-background-card/50 transition-colors text-left min-w-0">
                      <div className="flex items-center gap-2 truncate">
                        <Calendar className="h-4 w-4 text-foreground-secondary flex-shrink-0" />
                        <span className="text-foreground truncate">{getDateFilterDisplay()}</span>
                      </div>
                      <ChevronDown className="h-4 w-4 text-foreground-secondary flex-shrink-0 ml-2" />
                    </button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start" className="w-64">
                    <DropdownMenuItem
                      onClick={() => {
                        setDatePreset('all_time');
                        setDateOffset(0);
                      }}
                      className={`hover:bg-background-subtle/50 focus:bg-background-subtle/50 ${datePreset === 'all_time' ? 'bg-background-subtle' : ''}`}
                    >
                      <Calendar className="h-4 w-4 mr-2" />
                      All Time
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onClick={() => {
                        setDatePreset('last_day');
                        setDateOffset(0);
                      }}
                      className={`hover:bg-background-subtle/50 focus:bg-background-subtle/50 ${datePreset === 'last_day' ? 'bg-background-subtle' : ''}`}
                    >
                      <Clock className="h-4 w-4 mr-2" />
                      Last Day
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onClick={() => {
                        setDatePreset('last_week');
                        setDateOffset(0);
                      }}
                      className={`hover:bg-background-subtle/50 focus:bg-background-subtle/50 ${datePreset === 'last_week' ? 'bg-background-subtle' : ''}`}
                    >
                      <Clock className="h-4 w-4 mr-2" />
                      Last Week
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onClick={() => {
                        setDatePreset('last_month');
                        setDateOffset(0);
                      }}
                      className={`hover:bg-background-subtle/50 focus:bg-background-subtle/50 ${datePreset === 'last_month' ? 'bg-background-subtle' : ''}`}
                    >
                      <Clock className="h-4 w-4 mr-2" />
                      Last Month
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>

                {datePreset !== 'all_time' && (
                  <div className="flex gap-1">
                    <button
                      onClick={handlePrevious}
                      className="p-2 bg-background-card border border-border rounded-md hover:bg-background-card/50 transition-colors text-foreground-secondary hover:text-foreground"
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </button>
                    <button
                      onClick={handleNext}
                      disabled={dateOffset >= 0}
                      className={`p-2 bg-background-card border border-border rounded-md transition-colors ${dateOffset >= 0 ? 'opacity-50 cursor-not-allowed text-foreground-secondary' : 'hover:bg-background-card/50 text-foreground-secondary hover:text-foreground'}`}
                    >
                      <ChevronRightIcon className="h-4 w-4" />
                    </button>
                  </div>
                )}
              </div>

              {/* Activity Type Filters */}
              <div className="space-y-1">
                <h3 className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider mb-2">
                  Activity Type
                </h3>

                <FilterSection
                  title="Organization"
                  selectedValues={selectedTypes}
                  onToggle={handleTypeToggle}
                  items={[
                    { value: 'created_org', label: 'Created Org' },
                    { value: 'updated_org_name', label: 'Updated Org Name' },
                    { value: 'changed_org_profile_image', label: 'Changed Org Profile Image' },
                    { value: 'transferred_ownership', label: 'Transferred Ownership' },
                    { value: 'updated_policy', label: 'Updated Policy' },
                    { value: 'left_org', label: 'Left Org' },
                  ]}
                />

                <FilterSection
                  title="Members"
                  selectedValues={selectedTypes}
                  onToggle={handleTypeToggle}
                  items={[
                    { value: 'invited_member', label: 'Invited Member' },
                    { value: 'cancelled_invite', label: 'Cancelled Invite' },
                    { value: 'new_member_joined', label: 'New Member Joined' },
                    { value: 'removed_member', label: 'Removed Member' },
                    { value: 'changed_member_role', label: 'Changed Member Role' },
                  ]}
                />

                <FilterSection
                  title="Roles"
                  selectedValues={selectedTypes}
                  onToggle={handleTypeToggle}
                  items={[
                    { value: 'created_role', label: 'Created Role' },
                    { value: 'changed_role_settings', label: 'Changed Role Settings' },
                    { value: 'deleted_role', label: 'Deleted Role' },
                  ]}
                />

                <FilterSection
                  title="Teams"
                  selectedValues={selectedTypes}
                  onToggle={handleTypeToggle}
                  items={[
                    { value: 'team_created', label: 'Created Team' },
                    { value: 'member_joined_team', label: 'Member Joined Team' },
                  ]}
                />

                <FilterSection
                  title="Projects"
                  selectedValues={selectedTypes}
                  onToggle={handleTypeToggle}
                  items={[
                    { value: 'project_created', label: 'Created Project' },
                    { value: 'updated_project_name', label: 'Updated Project Name' },
                    { value: 'changed_project_profile_image', label: 'Changed Project Profile Image' },
                  ]}
                />
              </div>
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1 min-w-0">
            {loading ? (
              <div className="space-y-8">
                {/* Loading skeleton for month header */}
                <div>
                  <div className="h-5 w-32 bg-muted rounded animate-pulse mb-4" />
                  <div className="space-y-4">
                    {[...Array(5)].map((_, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-4 p-4 bg-background-card border border-border rounded-lg"
                      >
                        {/* Activity Icon Skeleton */}
                        <div className="w-8 h-8 rounded-full bg-muted animate-pulse flex-shrink-0" />

                        {/* Activity Content Skeleton */}
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
              <div className="space-y-8">
                {groupedActivities.map(({ month, activities: monthActivities }) => (
                  <div key={month}>
                    <h3 className="text-sm font-semibold text-foreground mb-4">{month}</h3>
                    <div className="space-y-4">
                      {monthActivities.map(activity => {
                        // Check if there's any metadata that will actually be displayed
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
                            {/* User Avatar */}
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

                            {/* Activity Content */}
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
                                    {activity.metadata!.added_licenses && activity.metadata!.added_licenses.length > 0 && (
                                      <div className="text-foreground-secondary">
                                        Added: {activity.metadata!.added_licenses.slice(0, 5).join(', ')}
                                        {activity.metadata!.added_licenses.length > 5 && ` +${activity.metadata!.added_licenses.length - 5} more`}
                                      </div>
                                    )}
                                    {activity.metadata!.removed_licenses && activity.metadata!.removed_licenses.length > 0 && (
                                      <div className="text-foreground-secondary">
                                        Removed: {activity.metadata!.removed_licenses.slice(0, 5).join(', ')}
                                        {activity.metadata!.removed_licenses.length > 5 && ` +${activity.metadata!.removed_licenses.length - 5} more`}
                                      </div>
                                    )}
                                    {activity.metadata!.slsa_enforcement_changed && (
                                      <div className="text-foreground-secondary">
                                        SLSA Enforcement: {activity.metadata!.old_slsa_enforcement || 'None'} → {activity.metadata!.new_slsa_enforcement || 'None'}
                                      </div>
                                    )}
                                    {activity.metadata!.slsa_level_changed && activity.metadata!.new_slsa_level !== null && (
                                      <div className="text-foreground-secondary">
                                        SLSA Level: {activity.metadata!.old_slsa_level || 'Not set'} → {activity.metadata!.new_slsa_level}
                                      </div>
                                    )}
                                    {activity.metadata!.slsa_level_changed && activity.metadata!.new_slsa_level === null && activity.metadata!.old_slsa_level !== null && (
                                      <div className="text-foreground-secondary">
                                        SLSA Level: {activity.metadata!.old_slsa_level} → removed
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                              <span className="text-xs text-foreground-secondary flex-shrink-0">
                                {formatDate(activity.created_at)}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
