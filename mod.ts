import { Buffer } from 'node:buffer';
import { hmacSha256 } from '@frytg/crypto/hmac';
import { timingSafeEqual } from '@std/crypto@1.0.4/timing-safe-equal';
import { WebhookEvent, WebhookEventMap, WebhookEventName } from './types.d.ts';

type Handler<E extends WebhookEventName = WebhookEventName> = {
  event: E;
  handler: (payload: WebhookEventMap[E]) => Response | void | Promise<Response | void>;
};

/**
 * Get HTTP Request object and apply the defined handlers.
 * Used to integrate github webhooks handling with an existing HTTP server.
 */
const handle = async (
  request: Request,
  handlers: Handler[],
  secret: string | undefined,
): Promise<Response | undefined> => {
  const body = await request.text();
  const { event, signature } = parseHeaders(request.headers);
  if (!event || (secret && (!signature || !validateSignature(signature, body, secret, event)))) {
    return new Response(undefined, { status: 403 });
  }
  try {
    const payload = JSON.parse(body) as WebhookEvent;
    for (const { event: target, handler } of handlers) {
      if (target === event) {
        const response = await handler(payload);
        if (response) {
          return response;
        }
      }
    }
  } catch {
    return new Response(undefined, { status: 500 });
  }
};

/**
 * Create a Deno HTTP Web Server and start listening for github webhooks on
 * the specified port and pathname (if there is such), using the passed handlers.
 */
const server = (port: number, pathname: string, handlers: Handler[], secret: string | undefined): void => {
  globalThis.Deno.serve({ port }, async (request) => {
    if (request.method === 'POST') {
      const url = new URL(request.url);
      if ((url.pathname || '/') === (pathname || '/')) {
        const response = await handle(request, handlers, secret);
        if (response) {
          return response;
        }
        return new Response(undefined, { status: 200 });
      }
      return new Response(undefined, { status: 404 });
    }
    return new Response(undefined, { status: 404 });
  });
};

/**
 * Handle GitHub Webhooks with Deno HTTP Web Server or a custom HTTP server with
 * built-in cryptographic timing-safe validation
 */
export const webhook = (secret?: string): ReturnType<typeof webhookBuilder> => {
  return webhookBuilder([], secret);
};

/**
 * Internal utility function used to build webhook handlers object
 */
const webhookBuilder = (
  handlers: Handler[],
  secret: string | undefined,
): {
  /**
   * Define a github webhook event handler that can be either sync or async.\
   * If a Response object is returned, all subsequent handlers will not be called.
   */
  on<E extends WebhookEventName>(event: Handler<E>['event'], handler: Handler<E>['handler']): any;
  /**
   * Create a Deno HTTP Web Server and start listening for github webhooks on
   * the specified port and pathname (if there is such).
   */
  listen(port: number, pathname?: string): void;
  /**
   * Get HTTP Request object and apply the defined handlers.
   * Used to integrate github webhooks handling with an existing HTTP server.
   */
  handle(request: Request): Promise<Response | undefined>;
} => ({
  on(event, handler) {
    return webhookBuilder([...handlers, { event, handler } as Handler], secret);
  },

  listen(port, pathname = '') {
    server(port, pathname, handlers, secret);
  },

  handle(request) {
    return handle(request, handlers, secret);
  },
});

/**
 * Cryptographic timing-safe validation of github webhook
 * @returns whether the webhook is valid or not
 */
const validateSignature = (signature: string, body: string, secret: string, event: WebhookEventName): boolean => {
  const sigHashAlg = 'sha256';
  const sig = new TextEncoder().encode(signature);
  const digest = new TextEncoder().encode(sigHashAlg + '=' + hmacSha256(body, Buffer.from(secret, 'utf8')));
  if (sig.length !== digest.length || !timingSafeEqual(digest, sig)) {
    console.log(`%c[${event}] crypto: fail`, 'color: red');
    return false;
  } else {
    console.log(`%c[${event}] crypto: ok`, 'color: green');
    return true;
  }
};

/**
 * Parse github webhook request headers
 * @returns webhook event and signature
 */
const parseHeaders = (
  headers: Headers,
): { event: keyof import('./types.d.ts').EventPayloadMap | null; signature: string | null } => {
  const event = headers.get('x-github-event') as WebhookEventName | null;
  const signature = headers.get('x-hub-signature-256');
  if (!event) {
    console.warn('Header "x-github-event" not found');
  }
  if (!signature) {
    console.warn('Header "x-hub-signature-256" not found');
  }
  return { event, signature };
};
