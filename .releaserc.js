module.exports = {
    branches: [
        {name: "2.11.x"},
        {name: "main"},
        {name: "next", prerelease: true},
    ],
    plugins: [
        "@semantic-release/commit-analyzer",
        "@semantic-release/release-notes-generator",
        "@semantic-release/github"
    ]
};
