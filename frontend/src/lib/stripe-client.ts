import { loadStripe, type Stripe } from '@stripe/stripe-js';

const PUBLISHABLE_KEY = import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY as string | undefined;

export const stripePromise: Promise<Stripe | null> = PUBLISHABLE_KEY
  ? loadStripe(PUBLISHABLE_KEY)
  : Promise.resolve(null);
