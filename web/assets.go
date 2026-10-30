// Package web contains immutable, locally served terminal lab assets.
package web

import "embed"

//go:embed index.html app.mjs paste.mjs remote.mjs keybash.css schibsted-grotesk.woff2 style.css desktop.html desktop.mjs desktop-workspace.mjs desktop.css auth-login.html auth-workspace.html auth.mjs auth.css custody-login.html custody-workspace.html custody.mjs systems.mjs custody.css vendor/*
var Assets embed.FS

// FontPath is the one typeface every page loads, from this server alone.
const FontPath = "/schibsted-grotesk.woff2"
