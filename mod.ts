import { serve } from 'https://deno.land/std@0.184.0/http/server.ts';
import { hmac } from 'https://deno.land/x/hmac@v2.0.1/mod.ts';
import { timingSafeEqual } from 'https://deno.land/std@0.185.0/crypto/timing_safe_equal.ts';
import {
  WebhookEvent,
  WebhookEventMap,
  WebhookEventName,
} from 'https://cdn.skypack.dev/-/@octokit/webhooks-definitions@v3.67.3-6fIVkCsEAeaghYKNFfKw/dist=es2019,mode=raw/schema.d.ts';

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
const server = (port: number, pathname: string, handlers: Handler[], secret: string | undefined) => {
  serve(
    async (request) => {
      if (request.method === 'POST') {
        const url = new URL(request.url);
        if (url.pathname === pathname) {
          const response = await handle(request, handlers, secret);
          if (response) {
            return response;
          }
          return new Response(undefined, { status: 200 });
        }
        return new Response(undefined, { status: 404 });
      }
      return new Response(undefined, { status: 404 });
    },
    { port },
  );
};

/**
 * Handle GitHub Webhooks with Deno HTTP Web Server or a custom HTTP server with
 * built-in cryptographic timing-safe validation
 */
export const webhook = (secret?: string) => {
  return webhookBuilder([], secret);
};

/**
 * Internal utility function used to build webhook handlers object
 */
const webhookBuilder = (handlers: Handler[], secret: string | undefined) => ({
  /**
   * Define a github webhook event handler that can be either sync or async.\
   * If a Response object is returned, all subsequent handlers will not be called.
   */
  on<E extends WebhookEventName>(
    event: Handler<E>['event'],
    handler: Handler<E>['handler'],
  ) {
    return webhookBuilder([...handlers, { event, handler } as Handler], secret);
  },

  /**
   * Create a Deno HTTP Web Server and start listening for github webhooks on
   * the specified port and pathname (if there is such).
   */
  listen(port: number, pathname = ''): void {
    server(port, pathname, handlers, secret);
  },

  /**
   * Get HTTP Request object and apply the defined handlers.
   * Used to integrate github webhooks handling with an existing HTTP server.
   */
  handle(request: Request): Promise<Response | undefined> {
    return handle(request, handlers, secret);
  },
});

/**
 * Cryptographic timing-safe validation of github webhook
 * @returns whether the webhook is valid or not
 */
const validateSignature = (signature: string, body: string, secret: string, event: WebhookEventName) => {
  const sigHashAlg = 'sha256';
  const sig = new TextEncoder().encode(signature);
  const digest = new TextEncoder().encode(sigHashAlg + '=' + hmac(sigHashAlg, secret, body, 'utf8', 'hex'));
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
const parseHeaders = (headers: Headers) => {
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
