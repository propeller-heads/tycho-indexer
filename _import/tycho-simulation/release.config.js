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
          "toml set --toml-path Cargo.toml package.version ${nextRelease.version}",
          "toml set --toml-path protosim/Cargo.toml package.version ${nextRelease.version}",
          "toml set --toml-path protosim_py/Cargo.toml package.version ${nextRelease.version}",
          "toml set --toml-path protosim_py/pyproject.toml project.version ${nextRelease.version}",
          "cargo update -p protosim",
          "cargo update -p _protosim_py",
          "cargo update -p prop-builder",
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
    (it) => it === branch || (it.name === branch && !it.prerelease),
  )
) {
  config.plugins.push("@semantic-release/changelog", [
    "@semantic-release/git",
    {
      assets: [
        "CHANGELOG.md",
        "Cargo.toml",
        "Cargo.lock",
        "protosim/Cargo.toml",
        "protosim_py/Cargo.toml",
        "protosim_py/pyproject.toml",
      ],
      message:
        "chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}",
    },
  ]);
}

module.exports = config;
