Contributions to this ASF fork of Vulnogram are welcome.

# Coordination

Submitting a contribution without prior coordination is fine, but for larger
changes first discussing it in a [GitHub issue](https://github.com/apache/security-vulnogram)
or on the [security-discuss@community.apache.org mailinglist](https://www.apache.org/foundation/mailinglists.html)
might be good to avoid disappointment.

# Contributing upstream

We plan to periodically pick up improvements from
https://github.com/Vulnogram/Vulnogram/ here, so if an
improvement is not urgent and would be relevant there as well
it would be good to contribute it there first and let it flow
into our instance via a merge.

# Avoiding merge conflicts

Since we plan to merge updates from upstream periodically,
it'd be good to avoid merge conflicts. For that reason we try
to:

* keep ASF-specific code in `custom` and `customRoutes`
* not copy-paste too much from the default implementations
* clearly mark 'inline' improvements with `// ASF`

# Testing

Try to test your changes locally before submitting your changes,
or add unit tests:

    VULNOGRAM_TLS_CERT=unittest/cert.pem VULNOGRAM_TLS_KEY=unittest/key.pem npm run unittest



# Submitting changes

Submit changes by creating a GitHub PR to the `main` branch.

# Reviewing

Anyone may review changes. After an approval by a Security Team member, the
reviewer may choose to merge the change immediately, or leave the PR to be
merged after the contributor has considered any optional comments.

A reviewer may ask for specific functionality/scenario's to be tested before
promoting the feature from the test to the prod environment. 

# Deploying

Changes are deployed to the test and prod environments manually by the security
team. Generally we try to have a quick pipeline from merging to `main`,
deploying to the test environment and then deploying to the prod environment.

If any problems are identified on the test environment ideally those are fixed
with a quick follow-up PR. If there is no quick solution available and the
change introduces a regression, the feature may be reverted on `main` to
unblock the deployment pipeline.
