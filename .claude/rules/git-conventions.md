## Commit messages

- Use conventional commit messages.
- Title: Capture the IMPACT of the change, not the tech details. From the title, we need to understand WHY we did this,
  what we ACHIEVED with the commit. Length-wise, aim for about 50 chars max.
- Body: Use bullets primarily. No word wrap. Don't hard-wrap body lines at 72 chars or any other width. Let the
  terminal/viewer wrap naturally. Enclose entities in ``. No co-author!

## PRs

- Use the PR title to summarize the changes in a casual/informal tone. Be information dense and concise.
- In the desc., write a thorough, organized, but concise, often bulleted list of the changes. Use no headings.
- At the bottom of the PR description, use a single "## Test plan" heading, in which, explain how the changes were
  tested. Assume that the changes were also tested manually if it makes sense for the type of changes.
