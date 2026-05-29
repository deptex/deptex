import { useEffect, useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './ui/dialog';
import { Button } from './ui/button';
import { RepoTreePicker } from './RepoTreePicker';

interface RepoPathPickerDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  organizationId: string;
  repoFullName: string;
  defaultBranch: string;
  integrationId: string;
  /** Currently committed path. Used as the dialog's starting selection. */
  initialPath: string;
  /** Ecosystem committed for `initialPath`, if known. Seeds `draftEcosystem` on open so that
   * clicking "Select" without changing the selection still surfaces a real ecosystem to the
   * parent (instead of `undefined`). */
  initialEcosystem?: string;
  /** Called with the chosen path when the user clicks "Select". */
  onConfirm: (path: string, ecosystem?: string) => void;
  rootName: string;
  rootFramework?: string | null;
  rootEcosystem?: string | null;
  /** True if the repo root contains a Dockerfile / compose file — paints the Docker badge on the root row. */
  rootDockerized?: boolean;
  /** Map of folder path → ecosystem, used to paint framework icons on folder rows. */
  pathHints?: Record<string, string | undefined>;
  /** Folder paths that contain a Dockerfile/Containerfile/docker-compose.yml. */
  dockerizedPaths?: string[];
}

export function RepoPathPickerDialog({
  open,
  onOpenChange,
  organizationId,
  repoFullName,
  defaultBranch,
  integrationId,
  initialPath,
  initialEcosystem,
  onConfirm,
  rootName,
  rootFramework,
  rootEcosystem,
  rootDockerized,
  pathHints,
  dockerizedPaths,
}: RepoPathPickerDialogProps) {
  const [draftPath, setDraftPath] = useState(initialPath);
  const [draftEcosystem, setDraftEcosystem] = useState<string | undefined>(initialEcosystem);

  useEffect(() => {
    if (open) {
      setDraftPath(initialPath);
      // Seed from the parent's committed ecosystem so clicking Select without
      // re-picking a row still surfaces a real ecosystem instead of `undefined`.
      setDraftEcosystem(initialEcosystem);
    }
  }, [open, initialPath, initialEcosystem]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent hideClose className="max-w-2xl gap-0 p-0 overflow-hidden">
        <DialogHeader className="px-7 pt-7 pb-5 gap-2.5">
          <DialogTitle className="text-xl font-bold">Root Directory</DialogTitle>
          <DialogDescription className="text-sm text-foreground/85 leading-relaxed">
            Select the directory containing your project&apos;s package manifest. For monorepos,
            create a separate project for each package you want to track.
          </DialogDescription>
        </DialogHeader>

        <div className="h-[460px] overflow-y-auto custom-scrollbar px-4 pb-4">
          <RepoTreePicker
            organizationId={organizationId}
            repoFullName={repoFullName}
            defaultBranch={defaultBranch}
            integrationId={integrationId}
            selectedPath={draftPath}
            onSelect={(p, e) => {
              setDraftPath(p);
              setDraftEcosystem(e);
            }}
            rootName={rootName}
            rootFramework={rootFramework}
            rootEcosystem={rootEcosystem}
            rootDockerized={rootDockerized}
            pathHints={pathHints}
            dockerizedPaths={dockerizedPaths}
          />
        </div>

        <DialogFooter className="px-6 py-4 bg-background-subtle/30 border-t border-border flex-row sm:justify-between gap-2">
          <Button
            type="button"
            variant="outline"
            className="!h-8 !px-3 !rounded-lg"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="white"
            onClick={() => {
              onConfirm(draftPath, draftEcosystem);
              onOpenChange(false);
            }}
          >
            Select
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
