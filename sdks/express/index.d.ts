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
