const config = {
  branches: [
    "release/+([0-9])?(.{+([0-9]),x}).x",
    "main",
    "next",
    "next-major",
    {
      name: "prerelease",
      prerelease: "pre",
    },
  ],
  tagFormat: "${version}",
  ci: true,
  debug: true,
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset: "conventionalcommits",
        releaseRules: [
          { type: "breaking", release: "major" },
          { type: "feat", release: "minor" },
          { type: "fix", release: "patch" },
          { type: "refactor", release: "patch" },
          { type: "security", release: "patch" },
          { type: "style", release: "patch" },
          { type: "test", release: false },
          { type: "docs", release: false },
          { type: "ci", release: false },
          { type: "chore", release: false },
        ],
      },
    ],
    [
      "@semantic-release/exec",
      {
        verifyReleaseCmd:
          'echo "VERIFY_RELEASE_VERSION=${nextRelease.version}" >> $GITHUB_OUTPUT',
        publishCmd:
          'echo "NEXT_RELEASE_VERSION=${nextRelease.version}" >> $GITHUB_OUTPUT',
        prepareCmd: [
          "toml set --toml-path substreams/common/Cargo.toml package.version ${nextRelease.version}",
          "toml set --toml-path tycho-ethereum/Cargo.toml package.version ${nextRelease.version}",
          "toml set --toml-path tycho-client/Cargo.toml package.version ${nextRelease.version}",
          "toml set --toml-path tycho-client-py/pyproject.toml project.version ${nextRelease.version}",
          "toml set --toml-path tycho-core/Cargo.toml package.version ${nextRelease.version}",
          "toml set --toml-path tycho-indexer/Cargo.toml package.version ${nextRelease.version}",
          "toml set --toml-path tycho-storage/Cargo.toml package.version ${nextRelease.version}",
          "cargo update -p tycho-ethereum",
          "cargo update -p tycho-client",
          "cargo update -p tycho-core",
          "cargo update -p tycho-indexer",
          "cargo update -p tycho-storage",
        ].join(" && "),
      },
    ],
    [
      "@semantic-release/release-notes-generator",
      {
        preset: "conventionalcommits",
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
    (it) => it === branch || (it.name === branch && !it.prerelease)
  )
) {
  config.plugins.push("@semantic-release/changelog", [
    "@semantic-release/git",
    {
      assets: ["CHANGELOG.md"],
      assets: [
        "CHANGELOG.md",
        "Cargo.lock",
        "substreams/common/Cargo.toml",
        "tycho-ethereum/Cargo.toml",
        "tycho-client/Cargo.toml",
        "tycho-client-py/pyproject.toml",
        "tycho-core/Cargo.toml",
        "tycho-indexer/Cargo.toml",
        "tycho-storage/Cargo.toml",
      ],
      message:
        "chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}",
    },
  ]);
}

module.exports = config;
