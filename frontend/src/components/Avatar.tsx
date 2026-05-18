// Avatar primitives for user and organization profile images.
//
// Two concerns are baked in so no call site has to remember them:
//  1. referrerPolicy="no-referrer" — Google's profile-picture CDN
//     (lh3.googleusercontent.com) rejects requests carrying a cross-origin
//     Referer header, so without this the image 4xxs from our domain.
//  2. onError fallback — if the remote URL fails anyway, swap to a local
//     default image (guarded against an infinite loop if the default 404s).

const USER_FALLBACK = '/images/blank_profile_image.png';
const ORG_FALLBACK = '/images/org_profile.png';

interface AvatarProps {
  src?: string | null;
  alt?: string;
  className?: string;
}

function AvatarImg({ src, alt = '', className, fallback }: AvatarProps & { fallback: string }) {
  return (
    <img
      src={src || fallback}
      alt={alt}
      referrerPolicy="no-referrer"
      onError={(e) => {
        const img = e.currentTarget;
        if (!img.src.endsWith(fallback)) img.src = fallback;
      }}
      className={className}
    />
  );
}

/** User profile image — falls back to the blank-profile silhouette. */
export function UserAvatar(props: AvatarProps) {
  return <AvatarImg {...props} fallback={USER_FALLBACK} />;
}

/** Organization image — falls back to the generic org image. */
export function OrgAvatar(props: AvatarProps) {
  return <AvatarImg {...props} fallback={ORG_FALLBACK} />;
}
