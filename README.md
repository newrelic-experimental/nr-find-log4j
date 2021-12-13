[![New Relic Experimental header](https://github.com/newrelic/opensource-website/raw/master/src/images/categories/Experimental.png)](https://opensource.newrelic.com/oss-category/#new-relic-experimental)

Per [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228), Apache log4j2 versions < 2.15.0 are vulnerable to remote code execution and data exfiltration.

This script will scan your New Relic account(s) for java services that *report* usage of log4j-core, and generate a manifest containing each suspect service with the version of log4j-core reported by New Relic APM.

Note that this script may generate false positives and false negatives. It is intended to assist your own investigation of potentially vulnerable systems, and does not provide any strong guarantees or proof of non-vulnerability.

## Usage

```sh
node nr-find-log4j.js
```

Requirements:

* Node.js (tested on versions 12 and 14)
* A New Relic **User** API Key

To get your New Relic API key, visit the
[New Relic API Key management page](https://one.newrelic.com/launcher/api-keys-ui.launcher) 
and either copy an existing USER key (use the 'Copy key' action in the '...' menu)
or create a new key with the *Create a key* button.

Executing this script will take some time if you have many java services.

Command-line options:

```sh
--csv           output findings in CSV format (default)
--json          output findings in JSON format
--all-services  include services that do NOT report presence of log4j-core
```

## Support

New Relic has open-sourced this project. This project is provided AS-IS WITHOUT WARRANTY OR DEDICATED SUPPORT. Issues and contributions should be reported to the project here on GitHub.

We encourage you to bring your experiences and questions to the [Explorers Hub](https://discuss.newrelic.com) where our community members collaborate on solutions and new ideas.

**A note about vulnerabilities**

As noted in our [security policy](../../security/policy), New Relic is committed to the privacy and security of our customers and their data. We believe that providing coordinated disclosure by security researchers and engaging with the security community are important means to achieve our security goals.

If you believe you have found a security vulnerability in this project or any of New Relic's products or websites, we welcome and greatly appreciate you reporting it to New Relic through [HackerOne](https://hackerone.com/newrelic).

## License

[Project Name] is licensed under the [Apache 2.0](http://apache.org/licenses/LICENSE-2.0.txt) License.
