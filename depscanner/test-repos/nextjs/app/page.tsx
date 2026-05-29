import { echoAction } from './actions/echo';
import { safeAction } from './actions/safe';

export default async function Page({
  searchParams,
}: {
  searchParams: { msg?: string };
}) {
  const fd = new FormData();
  fd.append('msg', searchParams.msg ?? '');
  const { html: echoHtml } = await echoAction(fd);
  const { html: safeHtml } = await safeAction();
  return (
    <main>
      {/* REACHABLE sink: server-action result rendered with dangerouslySetInnerHTML. */}
      <div dangerouslySetInnerHTML={{ __html: echoHtml }} />
      <div dangerouslySetInnerHTML={{ __html: safeHtml }} />
    </main>
  );
}
