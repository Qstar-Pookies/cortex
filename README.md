# Cortex

One HTML file. No build, no server, no npm.

## How it works

`index.html` reads the file list of this repo and pulls every
`.md` / `.txt` / `.prompt` file out of `prompts/<model>/`.

On `https://<you>.github.io/<repo>/` it works out the owner and repo
from the URL by itself. Nothing to configure.

## Adding a prompt

```
prompts/claude/my-thing.md
```

Push, then reload the page. That is the whole workflow.

Optional front matter:

```
---
title: My Thing
---

prompt text
```

No front matter? The first `# Heading` becomes the title. No heading
either? The filename becomes the title.

## Folders

Only these are read:

```
prompts/claude/
prompts/deepseek/
prompts/gemini/
prompts/grok/
prompts/opencode/
```

The folder name has to match exactly.

## Deploy

1. Push this folder to a GitHub repo
2. Settings -> Pages -> Source: Deploy from a branch
3. Branch: `main`, folder: `/ (root)`

No GitHub Action needed.

## Opened from disk

Double-clicking `index.html` still renders, but it can't read a local
folder, so it shows the built-in examples instead. Fill in
`GITHUB_OWNER` / `GITHUB_REPO` at the top of the script to make it pull
from GitHub even then.
