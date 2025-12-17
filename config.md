## Root configuration object

| Name | Type | Description | |
| --- | --- | --- | --- |
| <a id="config-opt-tsnet-hostname"></a>`tsnet.hostname` | string | Hostname to use for the tsnet node.| Default: _"tsiam"_ |
| <a id="config-opt-tsnet-authkey"></a>`tsnet.authKey` | string | AuthKey can be used to authenticate the tsnet node automatically.<br>If empty, tsnet will rely on existing state in the database.|  |
| <a id="config-opt-tsnet-statedir"></a>`tsnet.stateDir` | string | Directory where tsnet stores its state.<br>If empty, defaults to a folder next to the loaded config file.|  |
| <a id="config-opt-tsnet-ephemeral"></a>`tsnet.ephemeral` | boolean | If true, the tsnet node is ephemeral (not persisted in the tailnet).| Default: _false_ |
| <a id="config-opt-logs-level"></a>`logs.level` | string | Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.| Default: _"info"_ |
| <a id="config-opt-logs-omithealthchecks"></a>`logs.omitHealthChecks` | boolean | If true, calls to the healthcheck endpoint (`/healthz`) are not included in the logs.| Default: _true_ |
| <a id="config-opt-logs-json"></a>`logs.json` | boolean | If true, emits logs formatted as JSON, otherwise uses a text-based structured log format.<br>Defaults to false if a TTY is attached (e.g. when running the binary directly in the terminal or in development); true otherwise.|  |
| <a id="config-opt-signingkey-algorithm"></a>`signingKey.algorithm` | string | Signing algorithm to use. Supported values: RS256, ES256, ES384, ES512, EdDSA.| Default: _"ES256"_ |
| <a id="config-opt-signingkey-curve"></a>`signingKey.curve` | string | Curve for EdDSA algorithm.<br>Currently only Ed25519 is supported.|  |
| <a id="config-opt-signingkey-storagepath"></a>`signingKey.storagePath` | string | Path to store signing key. If empty, key will be ephemeral (not persisted).|  |
