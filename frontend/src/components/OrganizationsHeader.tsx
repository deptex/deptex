import AppHeader from './AppHeader';

export default function OrganizationsHeader() {
  return (
    <AppHeader
      breadcrumb={[{ label: 'Organizations' }]}
      showSearch={false}
      showNewOrg={false}
    />
  );
}
