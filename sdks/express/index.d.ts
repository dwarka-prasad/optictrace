import type { RequestHandler } from 'express';

export interface OpticTraceOptions {
  /** Path to optic.yaml (default "optic.yaml"). */
  configPath?: string;
  /** OpticTrace agent base URL, e.g. "http://localhost:9095". Omit to log to stdout. */
  agentUrl?: string;
  /** Override service.name from the config. */
  serviceName?: string;
  /** Also emit records as JSON lines on stdout. */
  consoleLog?: boolean;
  /** Called with telemetry transport errors (default: silent). */
  onError?: (err: unknown) => void;
}

declare function optictrace(options?: OpticTraceOptions): RequestHandler;
export default optictrace;
export { optictrace };

export interface Span {
  traceId: string;
  spanId: string;
  parentSpanId: string;
  sampled: boolean;
}

/** The span being served, or undefined outside a request. */
export function currentSpan(): Span | undefined;

/**
 * Headers for a call this service makes downstream, carrying THIS hop's span
 * so the next service nests under this request rather than beside it.
 */
export function outboundHeaders(extra?: Record<string, string>): Record<string, string>;

/** Ships application log lines correlated to the span serving them. */
export class LogShipper {
  constructor(
    agentUrl: string,
    service: string,
    opts?: { maxQueue?: number; flushMs?: number; batchSize?: number },
  );
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
  flush(): Promise<void>;
  close(): Promise<void>;
  readonly sent: number;
  readonly failed: number;
  readonly dropped: number;
  readonly lastError: string | null;
}
