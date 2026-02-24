import { Eye } from 'lucide-react';

export default function ProjectWatchListPage() {
    return (
        <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
            <div className="flex flex-col items-center justify-center py-16 px-4">
                <div className="text-center">
                    <Eye className="mx-auto h-12 w-12 text-foreground-secondary mb-4" />
                    <h3 className="text-lg font-semibold text-foreground mb-2">Watch List</h3>
                    <p className="text-foreground-secondary">
                        Watch list coming soon.
                    </p>
                </div>
            </div>
        </main>
    );
}
