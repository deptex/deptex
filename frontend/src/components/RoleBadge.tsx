import { cn } from '../lib/utils';

interface RoleBadgeProps {
    role: string;
    roleDisplayName?: string | null;
    roleColor?: string | null;
    className?: string;
}

// Helper to convert hex to rgba
const hexToRgba = (hex: string, alpha: number) => {
    let r = 0, g = 0, b = 0;
    // Handle 3 char hex
    if (hex.length === 4) {
        r = parseInt(hex[1] + hex[1], 16);
        g = parseInt(hex[2] + hex[2], 16);
        b = parseInt(hex[3] + hex[3], 16);
    }
    // Handle 6 char hex
    else if (hex.length === 7) {
        r = parseInt(hex.substring(1, 3), 16);
        g = parseInt(hex.substring(3, 5), 16);
        b = parseInt(hex.substring(5, 7), 16);
    }
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
};

export function RoleBadge({ role, roleDisplayName, roleColor, className }: RoleBadgeProps) {
    const normalizedRole = role.toLowerCase();
    let badgeStyles = '';
    let customStyle = {};

    // Check if roleColor is truthy and not an empty string
    if (roleColor && roleColor.trim() !== '') {
        customStyle = {
            backgroundColor: hexToRgba(roleColor, 0.1),
            color: roleColor,
            borderColor: hexToRgba(roleColor, 0.2),
        };
    } else {
        // No color set - transparent with subtle border for a plain, neutral look
        badgeStyles = 'bg-transparent text-foreground-secondary border border-foreground/20';
    }

    // Determine display name
    let displayName = roleDisplayName;
    if (!displayName) {
        if (normalizedRole === 'owner') {
            displayName = 'Owner';
        } else {
            displayName = role.charAt(0).toUpperCase() + role.slice(1);
        }
    }

    return (
        <span
            className={cn(`px-2 py-0.5 rounded text-xs font-medium border flex-shrink-0 transition-colors`, badgeStyles, className)}
            style={customStyle}
        >
            {displayName}
        </span>
    );
}
