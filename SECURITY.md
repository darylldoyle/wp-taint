# Security policy

## Reporting a vulnerability in wp-taint itself

If you find a security issue in wp-taint — the analyser — please report it
privately through
[GitHub's security advisories](https://github.com/darylldoyle/wp-taint/security/advisories/new)
rather than a public issue. wp-taint runs on a developer machine and analyses
source without executing it, so its own attack surface is small, but a report is
still welcome.

## You found a vulnerability in a plugin or theme *using* wp-taint

This is the more likely case, and it needs care.

**Do not open a public issue with a working exploit, and do not paste a real
site's code.** A false-negative report that includes a live, unpatched
vulnerability in third-party code is a disclosure, and a public one puts every
site running that code at risk before its maintainer can fix it.

Instead:

- To tell us wp-taint *missed a pattern*, open a
  [false-negative issue](https://github.com/darylldoyle/wp-taint/issues/new?template=false-negative.yml)
  with a **minimal, made-up example** that shows the shape — not the real code.
- To report the actual vulnerability, contact the plugin or theme's maintainer
  through their own security channel, and consider a coordinated disclosure via
  the [WordPress plugin security team](https://make.wordpress.org/plugins/handbook/managing-your-plugin/#reporting-security-issues)
  or a program such as [Patchstack](https://patchstack.com/).

wp-taint helps you find these; disclosing them responsibly is on all of us.
