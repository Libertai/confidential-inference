# Models

One directory per model, named after the alias clients send.

| File | |
| --- | --- |
| `model.json` | Build inputs: the vLLM image digest, the checkpoint repository and revision, and the name its volume takes. |
| `model.conf` | Copied verbatim into the workload image and read by `init.sh`: the alias vLLM serves under, and its environment and serving flags. |

`alias` in `model.json` and `MODEL_ALIAS` in `model.conf` have to agree;
`build.sh` refuses to build if they don't. The alias also has to match the key
in libertai-api's `models.json`, since it health-checks `/health/<alias>`.

Adding a model means adding a directory here, then `./deployment/build.sh
--model <alias>`. Both files land in the launch measurement, so a published
deployment is only reproducible at the commit that built it.
