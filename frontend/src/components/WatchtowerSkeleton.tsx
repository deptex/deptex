
import { Shield } from 'lucide-react';
import { Button } from './ui/button';

export function WatchtowerSkeleton() {
    return (
        <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-6">
            {/* Header Skeleton */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                    {/* Icon skeleton */}
                    <div className="w-10 h-10 rounded-full bg-muted animate-pulse" />
                    <div>
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                            {/* Title skeleton */}
                            <div className="h-6 w-32 bg-muted rounded animate-pulse" />
                            {/* Badge skeleton */}
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-muted/80 text-transparent text-xs font-medium animate-pulse">
                                <Shield className="h-3 w-3 opacity-0" />
                                Watching
                            </span>
                        </div>
                        {/* Version skeleton */}
                        <div className="h-4 w-16 bg-muted rounded animate-pulse" />
                    </div>
                </div>
                {/* Button skeleton */}
                <div className="h-9 w-24 bg-muted rounded animate-pulse" />
            </div>

            {/* Status Banner Skeleton */}
            <div className="rounded-xl p-5 mb-6 bg-background-card border border-border animate-pulse">
                <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-xl bg-muted flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                        <div className="h-6 w-1/3 bg-muted rounded mb-2" />
                        <div className="h-4 w-2/3 bg-muted rounded" />
                    </div>
                </div>
            </div>

            {/* Three Status Cards Skeleton — bottom strip matches status cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
                {[1, 2, 3].map((i) => (
                    <div key={i} className="bg-background-card border border-border rounded-lg pt-4 px-4 pb-0 flex flex-col h-full animate-pulse">
                        <div className="flex items-start justify-between mb-3">
                            <div className="w-10 h-10 rounded bg-muted" />
                            <div className="h-4 w-16 bg-muted rounded" />
                        </div>
                        <div className="h-5 w-3/4 bg-muted rounded mb-2" />
                        <div className="h-16 w-full bg-muted rounded flex-1" />
                        <div className="mt-3 -mx-4 px-4 pt-3 pb-3 border-t border-border bg-background-card-header rounded-b-lg">
                            <div className="h-1 w-full bg-muted/50 rounded-full overflow-hidden">
                                <div className="h-full bg-muted w-1/3" />
                            </div>
                        </div>
                    </div>
                ))}
            </div>

            {/* Commits Section Skeleton */}
            <div className="mt-8">
                {/* Header */}
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                        <div className="h-5 w-5 rounded bg-muted animate-pulse" />
                        <div className="h-6 w-40 bg-muted rounded animate-pulse" />
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="h-8 w-32 bg-muted rounded animate-pulse" />
                        <div className="h-8 w-32 bg-muted rounded animate-pulse" />
                    </div>
                </div>

                {/* Commits Table Skeleton - matches per-day table styling */}
                <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                    <table className="w-full">
                        <thead className="bg-background-card-header">
                            <tr className="border-b border-border">
                                <th className="text-left px-4 py-3"><div className="h-3 w-14 bg-muted rounded animate-pulse" /></th>
                                <th className="text-left px-4 py-3"><div className="h-3 w-20 bg-muted rounded animate-pulse" /></th>
                                <th className="text-left px-4 py-3"><div className="h-3 w-10 bg-muted rounded animate-pulse" /></th>
                                <th className="text-left px-4 py-3"><div className="h-3 w-12 bg-muted rounded animate-pulse" /></th>
                                <th className="text-left px-4 py-3"><div className="h-3 w-14 bg-muted rounded animate-pulse" /></th>
                                <th className="text-left px-4 py-3"><div className="h-3 w-28 bg-muted rounded animate-pulse" /></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                            {[1, 2, 3, 4, 5].map((i) => (
                                <tr key={i} className="animate-pulse">
                                    <td className="px-4 py-3"><div className="h-4 w-24 bg-muted rounded" /></td>
                                    <td className="px-4 py-3"><div className="h-4 max-w-md bg-muted rounded" /></td>
                                    <td className="px-4 py-3"><div className="h-3 w-16 bg-muted rounded" /></td>
                                    <td className="px-4 py-3"><div className="h-3 w-12 bg-muted rounded" /></td>
                                    <td className="px-4 py-3"><div className="h-3 w-8 bg-muted rounded" /></td>
                                    <td className="px-4 py-3"><div className="h-3 w-32 bg-muted rounded" /></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
    );
}
