import { memo } from 'react';
import AppHeader from './AppHeader';
import OrganizationSwitcher from './OrganizationSwitcher';
import { Organization } from '../lib/api';

interface OrganizationHeaderProps {
  organization: Organization | null;
}

function OrganizationHeader({ organization }: OrganizationHeaderProps) {
  if (!organization) {
    return null;
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-background border-b border-border">
      <AppHeader
        breadcrumb={[]}
        showSearch={false}
        showNewOrg={false}
        hideRightActions
        customLeftContent={
          <nav className="flex items-center gap-2 text-sm">
            <img
              src="/images/logo.png"
              alt="Deptex"
              className="h-8 w-8 flex-shrink-0"
            />
            <div className="h-4 w-px bg-border flex-shrink-0 ml-1.5 mr-3" aria-hidden />
            <OrganizationSwitcher
              currentOrganizationId={organization.id}
              currentOrganizationName={organization.name}
              currentOrganizationAvatarUrl={organization.avatar_url}
              triggerVariant="full"
            />
          </nav>
        }
      />
    </div>
  );
}

const areEqual = (prevProps: OrganizationHeaderProps, nextProps: OrganizationHeaderProps) => {
  if (!prevProps.organization || !nextProps.organization) {
    return prevProps.organization === nextProps.organization;
  }
  return (
    prevProps.organization.id === nextProps.organization.id &&
    prevProps.organization.name === nextProps.organization.name &&
    prevProps.organization.avatar_url === nextProps.organization.avatar_url &&
    JSON.stringify(prevProps.organization.permissions) === JSON.stringify(nextProps.organization.permissions)
  );
};

export default memo(OrganizationHeader, areEqual);
