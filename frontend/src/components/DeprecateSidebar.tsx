import { useState } from 'react';
import { Ban, Loader2, Save } from 'lucide-react';
import { Button } from './ui/button';

interface DeprecateSidebarProps {
    dependencyName: string;
    onClose: () => void;
    onDeprecate: (alternativeName: string) => Promise<void>;
}

export function DeprecateSidebar({ dependencyName, onClose, onDeprecate }: DeprecateSidebarProps) {
    const [alternative, setAlternative] = useState('');
    const [saving, setSaving] = useState(false);

    const handleSave = async () => {
        if (!alternative.trim()) return;

        setSaving(true);
        try {
            await onDeprecate(alternative.trim());
            onClose();
        } catch (error) {
            // Error handling is done in the parent component via toast
            setSaving(false);
        }
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && alternative.trim()) {
            handleSave();
        } else if (e.key === 'Escape') {
            onClose();
        }
    };

    return (
        <div className="fixed inset-0 z-50">
            {/* Backdrop */}
            <div
                className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
                onClick={onClose}
            />

            {/* Side Panel */}
            <div
                className="fixed right-0 top-0 h-full w-full max-w-md bg-background border-l border-border shadow-2xl transform transition-transform duration-300 translate-x-0 flex flex-col"
                onClick={(e) => e.stopPropagation()}
            >
                {/* Header — distinct strip like other sidebars */}
                <div className="px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-8 h-8 rounded-lg bg-warning/10 border border-warning/20 flex items-center justify-center">
                            <Ban className="h-4 w-4 text-warning" />
                        </div>
                        <h2 className="text-lg font-semibold text-foreground">
                            Deprecate Package
                        </h2>
                    </div>
                    <p className="text-sm text-foreground-secondary">
                        Mark <span className="font-medium text-foreground">{dependencyName}</span> as deprecated across your organization
                    </p>
                </div>

                {/* Content — form scrolls; actions pinned to bottom, same background */}
                <div className="flex-1 flex flex-col min-h-0">
                    <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
                        <div>
                            <label htmlFor="alternative" className="block text-sm font-medium text-foreground mb-2">
                                Alternative
                            </label>
                            <input
                                id="alternative"
                                type="text"
                                value={alternative}
                                onChange={(e) => setAlternative(e.target.value)}
                                onKeyDown={handleKeyDown}
                                placeholder="e.g. axios, lodash-es"
                                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary"
                                autoFocus
                            />
                            <p className="text-xs text-foreground-secondary mt-1.5">
                                Enter the recommended alternative package name
                            </p>
                        </div>
                    </div>
                    <div className="flex-shrink-0 px-6 py-4 flex items-center justify-end gap-2">
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={onClose}
                            disabled={saving}
                        >
                            Cancel
                        </Button>
                        <Button
                            variant="default"
                            size="sm"
                            onClick={handleSave}
                            disabled={saving || !alternative.trim()}
                            className="gap-1.5"
                        >
                            {saving ? (
                                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                                <Save className="h-3.5 w-3.5" />
                            )}
                            Save
                        </Button>
                    </div>
                </div>
            </div>
        </div>
    );
}
