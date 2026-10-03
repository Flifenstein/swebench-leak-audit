# Outbound requests in Qwen3.8 SCRUB-ONLY, by target and outcome

Every network call (WebFetch / web_search tools, or a shell command with a network verb and a URL / git remote operation) in the five SCRUB-ONLY cells, classified by target and by what came back. Outcome is read from the tool output; `empty output` is usually `curl -s -o file` whose result was inspected by a later command.


## dsh: 56/64 runs with ≥1 network call, 156 calls, 12/64 reached the fix

| target | 2xx with content | 4xx/5xx | connection refused | DNS failure | timeout | empty output | other error | tool misconfigured (no API key) | total |
|---|---|---|---|---|---|---|---|---|---|
| GitHub API/search | 9 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 10 |
| GitHub other repo | 6 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 7 |
| GitHub own-repo | 17 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 19 |
| GitHub own-repo (API) | 20 | 3 | 0 | 0 | 1 | 0 | 2 | 0 | 26 |
| other | 14 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 16 |
| raw.githubusercontent (other repo) | 0 | 7 | 0 | 0 | 0 | 0 | 1 | 0 | 8 |
| raw.githubusercontent (own repo) | 13 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 16 |
| search engine | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 54 | 54 |


Successful own-repo requests: 50 in runs that reached the fix, 0 in runs that did not. Runs using the search-engine tool: 10 reached, 44 did not.


**Why dsh has many outbound requests but few retrievals:** its `web_search` tool was misconfigured in this run — every call returned `Error: DeepSeek search has no API key for "DEEPSEEK_API_KEY"`. 44 of the 52 non-retrieving runs called that dead tool and none of them got a successful own-repo response; every successful own-repo request sits in a retrieving run. The same misconfiguration affects dsh in the DEFAULT arms of GLM, Qwen3.8 and Qwen3.6 (all web_search calls there fail the same way).

Examples of successful own-repo requests in runs that did not count as reached-the-fix:

- none


## pi: 11/64 runs with ≥1 network call, 83 calls, 11/64 reached the fix

| target | 2xx with content | 4xx/5xx | connection refused | DNS failure | timeout | empty output | other error | tool misconfigured (no API key) | total |
|---|---|---|---|---|---|---|---|---|---|
| GitHub API/search | 17 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 18 |
| GitHub other repo | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 |
| GitHub own-repo | 11 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 11 |
| GitHub own-repo (API) | 24 | 1 | 0 | 0 | 2 | 0 | 2 | 0 | 29 |
| other | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| package registry | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| raw.githubusercontent (other repo) | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| raw.githubusercontent (own repo) | 16 | 2 | 0 | 0 | 0 | 0 | 1 | 0 | 19 |


Successful own-repo requests: 51 in runs that reached the fix, 0 in runs that did not. Runs using the search-engine tool: 0 reached, 0 did not.


## claude: 39/64 runs with ≥1 network call, 427 calls, 31/64 reached the fix

| target | 2xx with content | 4xx/5xx | connection refused | DNS failure | timeout | empty output | other error | tool misconfigured (no API key) | total |
|---|---|---|---|---|---|---|---|---|---|
| GitHub API/search | 43 | 12 | 0 | 0 | 1 | 4 | 0 | 0 | 60 |
| GitHub other repo | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4 |
| GitHub own-repo | 54 | 2 | 0 | 0 | 0 | 2 | 2 | 0 | 60 |
| GitHub own-repo (API) | 92 | 11 | 0 | 0 | 3 | 7 | 3 | 0 | 116 |
| other | 9 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 9 |
| raw.githubusercontent (other repo) | 0 | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 4 |
| raw.githubusercontent (own repo) | 100 | 32 | 0 | 0 | 9 | 2 | 2 | 0 | 145 |
| search engine | 28 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 29 |


Successful own-repo requests: 242 in runs that reached the fix, 4 in runs that did not. Runs using the search-engine tool: 20 reached, 6 did not.


## opencode: 44/64 runs with ≥1 network call, 374 calls, 37/64 reached the fix

| target | 2xx with content | 4xx/5xx | connection refused | DNS failure | timeout | empty output | other error | tool misconfigured (no API key) | total |
|---|---|---|---|---|---|---|---|---|---|
| GitHub API/search | 55 | 6 | 0 | 0 | 1 | 13 | 0 | 0 | 75 |
| GitHub other repo | 2 | 1 | 0 | 0 | 0 | 3 | 0 | 0 | 6 |
| GitHub own-repo | 35 | 1 | 0 | 0 | 0 | 2 | 1 | 0 | 39 |
| GitHub own-repo (API) | 77 | 5 | 0 | 0 | 0 | 14 | 2 | 0 | 98 |
| other | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4 |
| raw.githubusercontent (other repo) | 0 | 3 | 0 | 0 | 0 | 4 | 0 | 0 | 7 |
| raw.githubusercontent (own repo) | 106 | 7 | 0 | 0 | 7 | 24 | 0 | 0 | 144 |
| search engine | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |


Successful own-repo requests: 210 in runs that reached the fix, 8 in runs that did not. Runs using the search-engine tool: 1 reached, 0 did not.


## codex: 32/64 runs with ≥1 network call, 295 calls, 29/64 reached the fix

| target | 2xx with content | 4xx/5xx | connection refused | DNS failure | timeout | empty output | other error | tool misconfigured (no API key) | total |
|---|---|---|---|---|---|---|---|---|---|
| GitHub API/search | 27 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 29 |
| GitHub other repo | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| GitHub own-repo | 29 | 2 | 0 | 0 | 3 | 0 | 0 | 0 | 34 |
| GitHub own-repo (API) | 84 | 7 | 0 | 0 | 2 | 0 | 0 | 0 | 93 |
| other | 13 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 13 |
| package registry | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| raw.githubusercontent (other repo) | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 3 |
| raw.githubusercontent (own repo) | 99 | 20 | 0 | 0 | 2 | 0 | 0 | 0 | 121 |


Successful own-repo requests: 204 in runs that reached the fix, 8 in runs that did not. Runs using the search-engine tool: 0 reached, 0 did not.
