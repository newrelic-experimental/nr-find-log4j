const https = require('https');
const readline = require("readline");
const fs = require('fs');

const INTRO_TEXT = `
This script will scan your New Relic account(s) for services that
report usage of a library, and generate a manifest containing each
service with the version of said library as reported by New Relic APM.

Note that this script may generate false positives and false negatives.
It is intended to assist your own investigation of supply chain composition,
and does not provide any strong guarantees or proof of
non-vulnerability.

The script requires a New Relic *User* API key. To get your key,
visit https://one.newrelic.com/launcher/api-keys-ui.launcher and either
copy an existing USER key (use the 'Copy key' action in the '...' menu)
or create a new one with the *Create a key* button.

Executing this script may take some time if you have many services.

Command-line options:
    --csv           output findings in CSV format (default)
    --json          output findings in JSON format

Disclaimer

This tool is provided by New Relic AS IS, without warranty of any kind.
New Relic does not guarantee that the tool will: not cause any disruption
to services or systems; provide results that are complete or 100% accurate;
correct or cure any detected vulnerability; or provide specific remediation
advice.

`;

const REGIONS = {
    'us': 'https://api.newrelic.com/graphql',
    'eu': 'https://api.eu.newrelic.com/graphql'
};

let NERDGRAPH_URL = REGIONS['us'];

const CERT_ERROR_HELP = `

Uh oh, I think you're behind an HTTPS proxy with a self-signed or internal
certificate, which can cause Node.js requests to the New Relic API to fail.

CAUTION: Someone could be maliciously intercepting your network traffic.

If you're sure this is a trusted proxy, you can work around this issue
in two ways:

1. Recommended: Set NODE_EXTRA_CA_CERTS environment variable to reference
a PEM file containing your proxy's certificate chain:
\tNODE_EXTRA_CA_CERTS=proxy-ca-root-cert.pem node nr-find-log4j.js

2. Unadvisable: Set NODE_TLS_REJECT_UNAUTHORIZED=0 environment variable to
disable SSL certificate validation.

See the Node.js docs for help: https://nodejs.org/api/cli.html

`;

const STATE = {
    apiKey: undefined,
    accountIds: undefined,
    region: 'us'
};

const QUERIES = {
    accessibleAccounts: `query getAccounts {
        actor {
          accounts {
            id
            name
          }
        }
      }`,
    getServices: `query getServices {
        actor {
          entitySearch(query: "domain = 'APM' AND type = 'APPLICATION' AND reporting IS true") {
            count
            results {
              nextCursor
              entities {
                ... on ApmApplicationEntityOutline {
                  guid
                  name
                  applicationId
                  accountId
                  reporting
                }
              }
            }
          }
        }
      }`,
    getMoreServices: `query getMoreServices($cursor:String!) {
        actor {
          entitySearch(query: "domain = 'APM' AND type = 'APPLICATION' AND reporting IS true") {
            count
            results(cursor: $cursor) {
              nextCursor
              entities {
                ... on ApmApplicationEntityOutline {
                  guid
                  name
                  applicationId
                  accountId
                  reporting
                }
              }
            }
          }
        }
      }`,
    getModulesInEntity: `query getEntity($entityGuid:EntityGuid!, $libraryName:String!) {
        actor {
          entity(guid: $entityGuid) {
            ... on ApmApplicationEntity {
              guid
              name
              applicationInstances {
                modules(filter: {startsWith: $libraryName}) {
                  name
                  version
                  attributes {
                    name
                    value
                  }
                }
              }
              accountId
              applicationId
              runningAgentVersions {
                maxVersion
                minVersion
              }
              language
            }
          }
        }
      }`,
    getModulesInAccount: `query getAccountModules($accountId: Int!, $libraryName:String!) {
        actor {
          account(id: $accountId) {
            agentEnvironment {
              modules(filter: {contains: $libraryName}) {
                nextCursor
                results {
                  details {
                    name
                    host
                  }
                  loadedModules {
                    name
                    version
                    attributes {
                      name
                      value
                    }
                  }
                  applicationGuids
                }
              }
            }
          }
        }
      }`,
      getMoreModulesInAccount: `query getAccountModules($accountId: Int!, $libraryName:String!, $cursor: String!) {
        actor {
          account(id: $accountId) {
            agentEnvironment {
              modules(filter: {contains: $libraryName}, cursor: $cursor) {
                nextCursor
                results {
                  details {
                    name
                    host
                  }
                  loadedModules {
                    name
                    version
                    attributes {
                      name
                      value
                    }
                  }
                  applicationGuids
                }
              }
            }
          }
        }
      }`
};

/**
 * Prompt the user to enter a library name from the console.
 * 
 * This function then executes `requestRegion()`.
 * 
 * @param {out} state - an object whose libraryName property will be populated by this call
 */
 function requestLibraryName(state) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question("\nWhat library shall I search for (default: log4j-core)? ",
        async (key) => {
            rl.close();
            state.libraryName = key || 'log4j-core';
            requestRegion(state);
        }
    );
}

/**
 * Prompt the user to choose a New Relic region from the console, which determines which API domain name.
 * 
 * If a valid region is read, then this function updates the global NERDGRAPH_URL and executes `requestApiKey()`.
 * Otherwise, prints an error and exits.
 * 
 * @param {out} state - an object whose region property will be populated by this call
 */
 function requestRegion(state) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question(`What region shall we examine (options: ${Object.keys(REGIONS).join(' ')}; default: us)? `,
        (region) => {
            rl.close();
            if (region) {
                region = region.toLowerCase();
                if (REGIONS[region]) {
                    state.region = region;
                    NERDGRAPH_URL = REGIONS[region];
                } else {
                    process.stdout.write(`\nPlease enter a valid region name, or just hit 'return' to default to the US region.\nValid options are: ${Object.keys(REGIONS).join(' ')}\n`);
                    process.exit(2);
                }
            }
            process.stdout.write(`API endpoint: ${NERDGRAPH_URL}\n`);

            requestApiKey(state);
        }
    );
}

/**
 * Prompt the user to enter an API key from the console, then test the key by fetching the accessible accounts list.
 * 
 * If ≥ 1 account is successfully read, then this function executes `findServices()`. Otherwise, prints an error and exits.
 * 
 * @param {out} state - an object whose apiKey and accountIds properties will be populated by this call
 */
function requestApiKey(state) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question("\nWhat is your New Relic User API Key? ",
        async (key) => {
            rl.close();
            // Track when we starterd scanning
            state.scanStarted = Date.now();

            process.stdout.write('Checking api key... ');
            state.apiKey = key;
            const accountIds = await fetchAccountIds(state);
            if (accountIds != undefined && accountIds.length > 0) {
                state.accountIds = accountIds;
                process.stdout.write(` OK, found ${accountIds.length} accounts.\n`);
                await findServices(state);
            } else {
                process.stdout.write('ERROR, api key is invalid or I failed to connect to New Relic API.\n');
                process.exit(1);
            }
        }
    );
}

/**
 * Connect to New Relic API and retrieve the list of accessible account IDs for the api key `state.apiKey`
 * 
 * @param {in} state - an object containing an `apiKey` property
 * @returns an array of New Relic accountIds, or undefined on failure
 */
async function fetchAccountIds(state) {
    try {
        const res = await nerdgraphQuery(state.apiKey, QUERIES.accessibleAccounts);
        const accountIds = res['actor']['accounts'].map(a => a['id']);
        return accountIds;
    } catch (err) {
        process.stderr.write(`Error requesting accessible accounts from New Relic api.\n`);
        process.stderr.write(err.toString() + '\n');
        return undefined;
    }
}

/**
 * Fetch all services and populate `state.applications` with summaries of each, using the service guid as a key.
 * 
 * @param state - object containing `apiKey` and `accountIds` and `libraryName` properties; `applications` property will be populated w/ a dictionary of service metadata
 */
async function findServices(state) {
    process.stdout.write('Scanning your accounts, this may take some time...\n');

    state.applications = state.applications || {};

    var resultSet = await nerdgraphQuery(state.apiKey, QUERIES.getServices);
    const entityCount = resultSet['actor']['entitySearch']['count'];
    process.stdout.write(`Checking ${entityCount} services...   `);

    var batch = 1;
    while (resultSet) {
        for (const application of resultSet['actor']['entitySearch']['results']['entities']) {
            if (application['guid']) {
                application['nrUrl'] = `https://rpm.newrelic.com/accounts/${application['accountId']}/applications/${application['applicationId']}/environment`;
                state.applications[application['guid']] = application;
            }
        }

        const cursor = resultSet['actor']['entitySearch']['results']['nextCursor'];
        if (cursor) {
            const glyphs = '|/-\\';
            process.stdout.write(`\b\b\b ${glyphs.charAt(batch % glyphs.length)} `);
            batch += 1;
            resultSet = await nerdgraphQuery(state.apiKey, QUERIES.getMoreServices, {cursor});
        } else {
            break;
        }
    }
    process.stdout.write(`\b\b\b done. Actual service count is ${Object.values(state.applications).length}.\n`);

    // We prefer findModulesByAccount() because it uses a more efficent API, but we've
    //   found some cases where we're not getting complete results.
    // We'll default to an api call per java service until I can figure it out the disparity.
    // Use the `--quick-scan` undocumented command line arg to use the account-level query.
    if (! process.argv.includes('--quick-scan')) {
        await findModulesByEntity(state);
    } else {
        await findModulesByAccount(state);
    }
}

/**
 * Look for the `log4j-core` module in each service in `state.applications`. If found, decorate application metadata with the jar info we have collected.
 * 
 * @param state - object containing `apiKey`, `accountIds`, and `applications` properties; `applications` values will be decorated with log4j-core jar metadata if found
 */
async function findModulesByEntity(state) {
    const entityCount = Object.values(state.applications).length;
    var progress = 0;
    process.stdout.write(`\rScanning modules (service ${progress} of ${entityCount})...      `);

    for (const application of Object.values(state.applications)) {
        try {
            const data = await nerdgraphQuery(state.apiKey, QUERIES.getModulesInEntity, {entityGuid: application['guid'], libraryName: state.libraryName});
            if (data && data['actor'] && data['actor']['entity'] && data['actor']['entity']['applicationInstances']) {
                if (data['actor']['entity']['runningAgentVersions']) {
                    application['agentVersion'] = concatNoneOrMore(data['actor']['entity']['runningAgentVersions']['minVersion'], data['actor']['entity']['runningAgentVersions']['maxVersion']);
                }
                if (data['actor']['entity']['applicationInstances']) {
                    let instanceCount = 0;

                    for (const instance of data['actor']['entity']['applicationInstances']) {
                        if (instance['modules'] && instance['modules'].length > 0) {
                            instanceCount += 1;
                            for (const module of instance['modules']) {
                                application['library'] = module['name'];
                                application['libraryVersion'] = module['version'];
                                if (module['attributes']) {
                                    for (const attribute of module['attributes']) {
                                        if (attribute['name'] === 'sha1Checksum' && attribute['value']) {
                                            application['librarySha1'] = attribute['value'];
                                        }
                                        if (attribute['name'] === 'sha512Checksum' && attribute['value']) {
                                            application['librarySha512'] = attribute['value'];
                                        }
                                    }
                                }
                            }
                        }
                    }

                    application['examinedInstances'] = instanceCount;
                }
            } else {
              process.stderr.write(`\nWarning: failed to get library list for ${application['guid']} - please check this service manually at ${application['nrUrl']}\n`);
            }
        } catch (err) {
            process.stderr.write(`\nError fetching data for ${application['guid']}: ${err.toString()}\n`);
        }

        progress += 1;
        process.stdout.write(`\rScanning modules (service ${progress} of ${entityCount})...      `);
    }

    process.stdout.write(`\rScanning modules (service ${entityCount} of ${entityCount})...  done.\n`);

    writeResults(state);
}

/**
 * Look for the `log4j-core` module in each account in `state.accountIds`. If found, decorate application metadata with the jar info we have collected.
 * 
 * Note: this version does not report the running New Relic agent version.
 * 
 * @param state - object containing `apiKey`, `accountIds`, and `applications` properties; `applications` values will be decorated with log4j-core jar metadata if found
 */
 async function findModulesByAccount(state) {
    const accountCount = state.accountIds.length;
    var progress = 0;

    for (const accountId of state.accountIds) {
        progress += 1;
        process.stdout.write(`\rScanning modules (account ${accountId} - ${progress} of ${accountCount})...        `);
        try {
            var data = await nerdgraphQuery(state.apiKey, QUERIES.getModulesInAccount, {accountId, libraryName: state.libraryName});

            var batch = 1;
            while (data && data['actor'] && data['actor']['account'] && data['actor']['account']['agentEnvironment'] && data['actor']['account']['agentEnvironment']['modules']) {
                const moduleResults = data['actor']['account']['agentEnvironment']['modules']['results'];
                for (const result of moduleResults || []) {
                    if (result['loadedModules'].length > 0) {
                        const {name, host} = result['details'];
                        const appName = name.replace(/^java:/, '').replace(/:\d+$/, '');
                        const entityGuids = result['applicationGuids'];

                        for (const module of result['loadedModules']) {
                            if (!entityGuids || entityGuids.length < 1) {
                                process.stdout.write(`\nWarning: result w/out a guid found:\t${appName}\t${host}\t${module['name']}\t${module['version']}      `);
                            }

                            for (const guid of entityGuids) {
                                if (!state.applications[guid]) {
                                  // There are rare cases where entitySearch doesn't return every application
                                  // If we find one of those, construct an application record from the data we have here
                                  const applicationId = getApplicationIdFromGuid(guid);
                                  state.applications[guid] = {
                                    accountId,
                                    guid,
                                    name: appName,
                                    applicationId,
                                    nrUrl: (applicationId) ? `https://rpm.newrelic.com/accounts/${accountId}/applications/${applicationId}/environment` : ''
                                  }
                                }

                                const application = state.applications[guid];

                                application['library'] = module['name'];
                                application['libraryVersion'] = module['version'];
                                if (module['attributes']) {
                                    for (const attribute of module['attributes']) {
                                        if (attribute['name'] === 'sha1Checksum' && attribute['value']) {
                                            application['librarySha1'] = attribute['value'];
                                        }
                                        if (attribute['name'] === 'sha512Checksum' && attribute['value']) {
                                            application['librarySha512'] = attribute['value'];
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
        
                const cursor = data['actor']['account']['agentEnvironment']['modules']['nextCursor'];
                if (cursor) {
                    const glyphs = '|/-\\';
                    process.stdout.write(`\b\b\b ${glyphs.charAt(batch % glyphs.length)} `);
                    batch += 1;
                    data = await nerdgraphQuery(state.apiKey, QUERIES.getMoreModulesInAccount, {accountId, cursor, libraryName: state.libraryName});
                } else {
                    break;
                }
            }
        } catch (err) {
            process.stderr.write(`\nError fetching data for account ${accountId}: ${err.toString()}\n`);
        }
    }

    process.stdout.write(`\rScanning modules (${accountCount} of ${accountCount})... done.                  \n`);

    writeResults(state);
}

/**
 * Write discovered results to json and/or csv file(s).
 * 
 * Files will be named `log4j_scan_<ISO_timestamp>.[json|csv]`.
 * 
 * Use `--json` and/or `--csv` command line arguments to specify output format(s). Default is CSV.
 * Use `--all-services` command line argument to output all discovered services, regardless of whether they contain log4j-core.
 * 
 * @param state - object containing `scanStarted` timestamp and `applications` dictionary
 */
function writeResults(state) {
    const useJson = process.argv.includes('--json');
    const useCsv = process.argv.includes('--csv') || !useJson;
    const includeAllApplications = process.argv.includes('--all-services');

    const applications = Object.values(state.applications);
    const vulnerableApplications = applications.filter(a => a['library']);

    state.scanCompleted = Date.now();
    state.scanDurationSec = Math.ceil((state.scanCompleted - state.scanStarted) / 1000);

    process.stdout.write(`\nOK, scan took ${state.scanDurationSec} seconds. Found ${vulnerableApplications.length} services with log4j-core.\n`);
    const fileTimestamp = new Date().toISOString().replace(/\:/g, '-');

    if (useJson) {
        const outputFile = `${state.libraryName}_scan_${state.region}_${fileTimestamp}.json`;
        fs.writeFileSync(
            outputFile,
            JSON.stringify((includeAllApplications) ? applications : vulnerableApplications, null, 2)
        );
        process.stdout.write(`Wrote results to ${outputFile}\n`);
    }

    if (useCsv) {
        const columns = ['accountId', 'applicationId', 'name', 'agentVersion', 'examinedInstances', 'library', 'libraryVersion', 'librarySha1', 'librarySha512', 'nrUrl'];
        const outputFile = `${state.libraryName}_scan_${state.region}_${fileTimestamp}.csv`;
        // DIY rather than depend on a csv module
        fs.writeFileSync(
            outputFile,
            toCSV(columns, (includeAllApplications) ? applications : vulnerableApplications)
        );
        process.stdout.write(`Wrote results to ${outputFile}\n`);
    }
}

/**
 * Run a graphQl query against the NewRelic API.
 * 
 * @param {in} apiKey - New Relic API key
 * @param {in} query - GraphQL query
 * @param {in} variables - (optional) an object containing variables for the GraphQL query
 */
async function nerdgraphQuery(apiKey, query, variables={}) {
    const payload = JSON.stringify({query, variables});

    try {
        var prms = buildRequestPromise(apiKey, payload);
        var response = await prms;
        if (response.errors) {
            process.stderr.write(`\nError returned from API: ${JSON.stringify(response.errors)}\n`);
        }
        if (response.data) {
            return response.data;
        }
    } catch (err) {
        handleNetworkError(err);
    }

    // We hit occasional networking issues that lead to timeouts or other transient issues
    // So, if the query failed try it again one time
    try {
      var prms = buildRequestPromise(apiKey, payload);
      var response = await prms;
      if (response.data) {
          return response.data;
      }
    } catch (err) {
        handleNetworkError(err);
    }

  return undefined;
}

/**
 * Figure out what to do with an error thrown by an https request.
 * 
 * If err suggests the issue is a certificate error from a HTTPS proxy, then print troubleshooting info and exit.
 * Otherwise, print the error string and continue.
 * 
 * @param err - the Error thrown by https.request
 */
function handleNetworkError(err) {
  const errString = err.toString();
  // check for signs that Node is rejecting a HTTPS proxy with a self-signed cert
  //   Per https://github.com/nodejs/node/blob/master/deps/openssl/openssl/include/openssl/x509_vfy.h.in#L224-L225
  //   and https://github.com/nodejs/node/blob/master/deps/openssl/openssl/crypto/x509/x509_txt.c#L60-L63
  //   err.code == 18 is X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
  //   err.code == 19 is X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
  if (err.code === 18 || err.code === 19 || errString.includes("self signed certificate")) {
    process.stderr.write(CERT_ERROR_HELP);
    process.exit(5);
  }
  else {
    process.stderr.write(`\nException processing API call: ${errString}\n`);
  }
}

/**
 * Build a promise that will send the provided payload to nerdgraph and resolve to the response body.
 * 
 * @param apiKey - New Relic User API key for executing a nerdgraph query
 * @param payload - string containing the json-encoded graphql payload
 * @returns a Promise that, when resolved, will execute the requests and return the deserialized json response
 */
function buildRequestPromise(apiKey, payload) {
  const options = {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': payload.length,
        'API-Key': apiKey,
        'NewRelic-Requesting-Services': 'nr-find-log4j'
    }
  };

  return new Promise((resolve, reject) => {
    const req = https.request(NERDGRAPH_URL, options, (res) => {
        let body = '';

        res.on('data', (chunk) => {
            body += chunk;
        });

        res.on('end', () => {
            resolve(JSON.parse(body));
        });
    });

    req.on('error', (err) => {
        reject(err);
    });

    req.write(payload)
    req.end();
  });
}

/**
 * Return a comma-separated string of the unique, non-null, non-blank arguments passed in.
 *
 * @returns a string containing 0 or more args, separated by commas
 */
function concatNoneOrMore(a, b, c, d, e, f) {
    const vals = [a, b, c, d, e, f].filter(v => v !== undefined && v !== null && v !== '');
    return [... new Set(vals)].join(',');
}

/**
 * Generate a CSV-formatted string containing one column for each element of `columns` and a row for each object of `data`.
 * 
 * Suitable for generating relatively small (fit in memory) CSVs. Does not handle 100% of CSV formatting edge cases (newlines in strings, e.g.).
 * 
 * @param {in} columns - ordered array of column names to put in the CSV
 * @param {in} data - array of objects that will be rows in the CSV, containing keys from the `columns` param
 * @returns a string containing the CSV contents
 */
function toCSV(columns, data) {
    var output = columns.map(escapeCsv).join(',') + '\n';
    for (const row of data) {
        output += columns.map(c => escapeCsv(row[c])).join(',') + '\n';
    }
    return output;
}

/**
 * Safely escape a value to be included in a CSV file.
 * 
 * Wraps strings that contain commas with " and escapes " chars inside wrapped strings.
 * Also converts undefined and null values to empty strings.
 * 
 * @param {in} s string to escape
 * @returns a string suitable for inclusion in a CSV cell
 */
function escapeCsv(s) {
    if (s === undefined || s === null) {
        return '';
    } else if (typeof(s) === 'string' && s.includes(',')) {
        return `"${s.replace(/"/g, '""')}"`;
    } else {
        return s;
    }
}

/**
 * Extract the APM applicationId from a New Relic entity guid.
 * @param {in} guid 
 * @returns applicationId, or undefined on failure
 */
function getApplicationIdFromGuid(guid) {
  if (!guid) return undefined;

  try {
    const decodedString = atob(guid);
    const splitString = decodedString.split("|");
    return parseInt(splitString[3]);
  } catch (err) {
    return undefined;
  }
};


// Kick off the application
try {
    process.stdout.write(INTRO_TEXT);

    requestLibraryName(STATE);
} catch (err) {
    process.stderr.write(`Uncaught runtime error: ${err.toString()}\n`);
    process.exit(2);
}
