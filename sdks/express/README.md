# @optictrace/express

OpticTrace middleware for Express: config-driven API telemetry & governance.
Evaluates your `optic.yaml` **in-process** (restriction + redaction happen
before any byte leaves the app) and ships governed records to the OpticTrace
agent for metrics, storage, and the dashboard.

```js
const express = require('express');
const optictrace = require('@optictrace/express');

const app = express();
app.use(optictrace({
  configPath: 'optic.yaml',
  agentUrl: 'http://localhost:9095',   // omit to log JSON lines to stdout
}));
```

Place it **before** body parsers so the raw request stream can be teed.
Telemetry is fire-and-forget: agent downtime never affects your app.

Hot reload rules with `kill -HUP <pid>`. See the
[main repository](https://github.com/dwarka-prasad/optictrace) for the full
`optic.yaml` reference.
