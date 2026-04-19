import { Router, Request, Response, raw } from 'express';

const router = Router();

// Stripe webhooks require the raw body for signature verification.
// The global express.json() middleware with verify stores rawBody on the request.
router.post('/', async (req: Request, res: Response) => {
  try {
    const signature = req.headers['stripe-signature'] as string;
    if (!signature) {
      return res.status(400).json({ error: 'Missing stripe-signature header' });
    }

    const rawBody = (req as any).rawBody;
    if (!rawBody) {
      return res.status(400).json({ error: 'Missing raw body for signature verification' });
    }

    // Lazy-import EE stripe lib to avoid requiring stripe SDK in CE builds
    let stripeLib: any;
    try {
      stripeLib = require('../lib/stripe');
    } catch {
      return res.status(503).json({ error: 'Billing module not available' });
    }

    let event: any;
    try {
      event = stripeLib.constructWebhookEvent(Buffer.from(rawBody), signature);
    } catch (err: any) {
      console.error('[Stripe Webhook] Signature verification failed:', err.message);
      return res.status(400).json({ error: 'Invalid signature' });
    }

    // Idempotency check
    const alreadyProcessed = await stripeLib.isEventProcessed(event.id);
    if (alreadyProcessed) {
      return res.json({ received: true, status: 'already_processed' });
    }

    // Process event by type
    switch (event.type) {
      case 'checkout.session.completed':
        await stripeLib.handleCheckoutCompleted(event.data.object);
        break;
      case 'customer.subscription.updated':
        await stripeLib.handleSubscriptionUpdated(event.data.object);
        break;
      case 'customer.subscription.deleted':
        await stripeLib.handleSubscriptionDeleted(event.data.object);
        break;
      case 'invoice.payment_succeeded':
        await stripeLib.handlePaymentSucceeded(event.data.object);
        break;
      case 'invoice.payment_failed':
        await stripeLib.handlePaymentFailed(event.data.object);
        break;
      default:
        console.log(`[Stripe Webhook] Unhandled event type: ${event.type}`);
    }

    await stripeLib.markEventProcessed(event.id, event.type);
    res.json({ received: true });
  } catch (err: any) {
    console.error('[Stripe Webhook] Error:', err.message);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

export default router;
