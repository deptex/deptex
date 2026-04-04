import { useState } from 'react';
import { Ban, Loader2 } from 'lucide-react';
import { Button } from './ui/button';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogFooter,
    DialogTitle,
    DialogDescription,
} from './ui/dialog';

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
        }
    };

    return (
        <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
            <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden">
                <div className="px-6 pt-6 pb-4 border-b border-border">
                    <DialogTitle>Deprecate package</DialogTitle>
                    <DialogDescription className="mt-1">
                        Mark <span className="font-medium text-foreground">{dependencyName}</span> as deprecated across your organization.
                    </DialogDescription>
                </div>

                <div className="px-6 py-4 grid gap-4 bg-background">
                    <div className="grid gap-2">
                        <label htmlFor="alternative" className="text-sm font-medium text-foreground">
                            Recommended alternative
                        </label>
                        <input
                            id="alternative"
                            type="text"
                            value={alternative}
                            onChange={(e) => setAlternative(e.target.value)}
                            onKeyDown={handleKeyDown}
                            className="flex h-9 w-full rounded-md border border-border bg-background-card px-3 py-2.5 text-sm text-foreground shadow-sm transition-colors placeholder:text-foreground-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:border-primary"
                            autoFocus
                        />
                    </div>
                </div>

                <DialogFooter className="px-6 py-4 bg-background">
                    <Button
                        variant="outline"
                        onClick={onClose}
                        disabled={saving}
                    >
                        Cancel
                    </Button>
                    <Button
                        className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                        onClick={handleSave}
                        disabled={saving || !alternative.trim()}
                    >
                        {saving ? (
                            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        ) : (
                            <Ban className="h-4 w-4 mr-2" />
                        )}
                        Deprecate
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
