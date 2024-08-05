const config = {
  branches: [
    "release/+([0-9])?(.{+([0-9]),x}).x",
    "feat/check-semantic-release",
    "next",
    "next-major",
    {
      name: "prerelease",
      prerelease: "pre",
    },
  ],
  ci: true,
  debug: true,
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset: "ESLint",
        releaseRules: [
          { tag: "breaking", release: "major" },
          { tag: "chore", release: false },
          { tag: "ci", release: false },
          { tag: "docs", release: false },
          { tag: "feat", release: "minor" },
          { tag: "fix", release: "patch" },
          { tag: "refactor", release: "patch" },
          { tag: "security", release: "patch" },
          { tag: "style", release: "patch" },
          { tag: "test", release: false },
        ],
      },
    ],
    [
      "@semantic-release/exec",
      {
        publishCmd:
          'echo "NEXT_RELEASE_VERSION=${nextRelease.version}" >> $GITHUB_OUTPUT',
      },
    ],
    [
      "@semantic-release/release-notes-generator",
      {
        preset: "ESLint",
      },
    ],
    [
      "@semantic-release/github",
      {
        successComment:
          "This ${issue.pull_request ? 'PR is included' : 'issue has been resolved'} in version ${nextRelease.version} :tada:",
        labels: true,
        releasedLabels: true,
      },
    ],
  ],
};

const ref = process.env.GITHUB_REF;
const branch = ref.split("/").pop();

if (
  config.branches.some(
    (it) => it === branch || (it.name === branch && !it.prerelease),
  )
) {
  config.plugins.push("@semantic-release/changelog", [
    "@semantic-release/git",
    {
      assets: ["CHANGELOG.md"],
      message:
        "chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}",
    },
  ]);
}

module.exports = config;
